/*
 * SPDX-FileCopyrightText: Copyright (c) 2010-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/delay.h>


#include <linux/mlx_sx/kernel_user.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include "sx.h"
#include "dq.h"
#include "health_check.h"
#include "alloc.h"
#include "sx_dbg_dump_proc.h"
#include "dev_db.h"
#include "emad.h"

#define DEV_ID_ALL                                    (0)
#define START_HETT_SESSION                            0
#define STOP_HETT_SEASSON                             1
#define FW_SOS_TEST                                   0x1
#define FW_SOS_LOG_MAX_SIZE                           256
#define HEALTH_CHECK_EVENT_MSG_MAX                    512
#define FW_SOS_IRON_RISC                              1
#define FW_SOS_EXECUTED_EMAD                          1
#define FW_SOS_TEST                                   0x1
#define CAUSE_OFFSET_MASK                             0x1F
#define DEFAULT_ALERT_THRESHOLD                       3
#define DEFAULT_CHECK_INTERVAL                        1
#define MAX_HISTORY_SIZE                              (30)
#define LONG_COMMAND_MAX_COUNTER                      25
#define NUM_OF_HC_CYCLE_ITER_INIT_THREAD_NOT_RESPONSE 3

#define SX_HEALTH_HIGH_SEVERITY(severity) ((severity) <= SXD_HEALTH_SEVERITY_WARN)

enum sx_dev_check {
    SX_HC_DEV_CHECK_TASKLET,
    SX_HC_DEV_CHECK_CATAS,
    SX_HC_DEV_CHECK_SDQ,
    SX_HC_DEV_CHECK_RDQ,
    SX_HC_DEV_CHECK_SDK_THREADS,
    SX_HC_DEV_CHECK_CMD_IFC,
    SX_HC_DEV_CHECK_LAST
};

enum sx_global_check {
    SX_HC_GLOBAL_CHECK_SYSFS_TS,
    SX_HC_GLOBAL_CHECK_KERNEL_THREADS,
    SX_HC_GLOBAL_CHECK_LAST
};

#define SX_HC_BIT(check) (1 << (check))

struct sx_cmd_ifc {
    u64   last_cmd_ifc_counter;           /*last number of cmd that sent */
    void *mailbox_p; /* mailbox function as opaque (void*) */
    void *cmd_ctx;     /* context function as opaque (void*) */
    bool  is_last_pkt_sent_via_health;
};

struct config_sdq {
    struct sx_bitmap sdq_bitmap;
    u64              num_of_check_iter;      /*count number of check iteration that made*/
    u32              max_iter_allowed;                /*maximum time that that go bit should ACK for cmd_ifc ,GO_BIT_TIMEOUT_MSECS/periodic_time +1 */
};

enum health_debug_state {
    HEALTH_DEBUG_NORMAL,
    HEALTH_DEBUG_MUTE,
    HEALTH_DEBUG_DONT_STOP_ON_FATAL
};

struct sx_sdk_thread {
    struct sx_bitmap           running_bitmap; /* Hold all the threads that responded */
    struct sx_bitmap           last_sent_bitmap; /* Hold all the threads that we sent monitor cmd to them*/
    u64                        sdk_main_monitor_counter; /* Will indicate if all sdk thread monitor mechanism is working which means the hc_thread_monitor_init is working */
    u64                        sdk_monitor_last_checked_counter;
    u32                        num_of_iter_without_cnt_increase; /* Number of HC cycles the health check monitor mechanism wasn't initiated by the main thread while it was expected to be. */
    ku_thread_status_changed_t bit_to_thread_status_arr[NUM_OF_SDK_THREADS_MAP_BY_BITS];/* Hold thread info per bit */
    u32                        sdk_thread_monitor_cnt;
    u32                        mult_threshold_time; /* for debug propose in case using slow setup like kernel debug   */
    u32                        new_debug_time_for_thread_monitor; /* for debug verification propose in case to raise the timeout threads fast*/
};

struct sx_health_check_config {
    struct sx_bitmap           rdq_bitmap;
    struct sx_bitmap           last_rdq_bitmap; /* keep state upon config change */
    struct sx_bitmap           ignore_rdq_bitmap; /* will contain all WJH RDQ the need to ignore and not monitor*/
    struct config_sdq          sdq;
    struct sx_cmd_ifc          cmd_ifc;
    struct sx_sdk_thread       sdk_thread_info;
    uint32_t                   periodic_time;
    uint32_t                   failures_num;
    sxd_health_severity_t      min_severity;
    enum health_debug_state    debug_state;
    thread_monitoring_status_e thread_monitoring_status;
};

struct sxd_ecc_counters_info {
    uint32_t ecc_corrected;
    uint32_t ecc_uncorrected;
};

struct sx_health_dev_info {
    struct sx_dev      *dev;
    struct delayed_work main_health_check_dwork;
    struct list_head    dev_list;
    u32 __iomem        *catas_iomap;
    struct mutex        lock;

    /* following fields must be accessed within device information lock */
    struct list_head        issues_list;
    struct list_head        issues_history;       /* history of non-fatal issues */
    u32                     history_size;
    u32                     major_issues_detected;       /* error or higher */
    u32                     minor_issues_detected;       /* warning or lower */
    sxd_health_cause_t      fatal_cause;
    sxd_event_health_data_t event_extra_data;

    /*
     * Currently there is no FW design about device_index and slot_index in MECCC,
     * we don't know the valid ranges for device_index and slot_index.
     * FW always returns the ECC statistics for device_index 0 and slot_index 0, so here we
     * only define a single software cache for device_index 0 and slot_index 0.
     * If FW supports multiple device_index/slot_index in the future, then we need to define
     * the software cache for all possible combinations of device_index/slot_index.
     */
    struct sxd_ecc_counters_info  ecc_stats;
    struct ku_mfgd_reg            active_mfgd;
    bool                          health_check_first_itr_skip_checks_func;
    struct sx_health_check_config config;
    bool                          disabled;
    bool                          fatal_error_mode_active;
    bool                          issu_on;
    bool                          issu_signal_done;
    struct completion            *wq_issu_cyc_completion;
    bool                          long_command_detected;
    u32                           long_command_event_counter;
    u32                           checks_bitmap; /* default: all checks. values from enum sx_dev_check */
};

struct health_check_kernel_thread_t {
    unsigned long             jiffies;       /* time when the failure happened */
    struct list_head          list;
    char                    * name;       /*name of the kernel work queue thread */
    struct workqueue_struct * wq;
    u64                       old_counter;       /* counter status from prev iteration */
    u64                       new_counter;       /* will be increase in case the thread works as expected */
    struct delayed_work       kernel_wq_increase_cnt_dwork;
};

struct issue_info {
    sxd_health_severity_t   severity;
    unsigned long           jiffies;     /* time when the failure happened */
    struct list_head        list;
    sxd_health_cause_t      cause;
    char                    err_msg[HEALTH_CHECK_EVENT_MSG_MAX];
    sxd_event_health_data_t event_data;
    u8                      irisc_id;
};

typedef struct sxd_health_external_report_data {
    struct sxd_ecc_counters_info ecc_stats;
    sxd_event_health_data_t      extra_data_event;
} sxd_health_external_report_data_t;

struct external_cause_work {
    struct work_struct                w;
    u8                                dev_id; /* dev_id == DEV_ID_ALL means all devices */
    u32                               issue_severity;
    u32                               issue_cause;
    u8                                irisc_id;
    char                              err_msg[HEALTH_CHECK_EVENT_MSG_MAX];
    sxd_health_external_report_data_t data;
};

struct mfde_work {
    struct ku_mfde_reg mfde;
    struct sx_dev     *dev;
    struct work_struct w;
};

static ssize_t __health_check_running_cntr_cb(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute __health_check_running_counter_attr = __ATTR(health_check_running_counter,
                                                                          S_IRUGO,
                                                                          __health_check_running_cntr_cb,
                                                                          NULL);

static struct workqueue_struct *__health_check_wq = NULL;
static struct delayed_work      __health_check_ts_work;
static struct delayed_work      __kernel_workqueue_monitor_dwork;
static uint64_t                 __health_check_ts = 0;
unsigned long                   __health_check_ts_jiffies;     /* time when last __health_check_ts increased*/
static bool                     __health_check_ts_trigger = false;
static bool                     __health_check_wq_threads_trigger = false;
static char                     __wq_thread_name_trigger[30] = "";
static bool                     __is_first_iteration_of_kernel_wq_monitor_s = false;
static u32                      __kernel_thread_monitor_cnt = 0;
static u32                      __global_checks_bitmap = SX_HC_BIT(SX_HC_GLOBAL_CHECK_LAST) - 1; /* default: all checks */
static LIST_HEAD(__kernel_thread_list);
static LIST_HEAD(__dev_info_list);
static DEFINE_MUTEX(__health_check_lock);
static DEFINE_MUTEX(__kthreads_monitor_lock);

/************************************************
 *  Local function declarations
 ***********************************************/

static const char * const sxd_health_thread_id_str_s[] = {
    SXD_FOREACH_OBJECT_HEALTH_THREAD_FAILURE_ID(SXD_GENERATE_STRING)
};

static const char * const sxd_cause_type_str_s[] = {
    SXD_FOREACH_OBJECT_HEALTH_CAUSE(SXD_GENERATE_STRING)
};

static const char * sxd_cause_type_str(sxd_health_cause_t idx)
{
    return ((idx > SXD_HEALTH_CAUSE_MAX_E) ?
            "Unknown" : sxd_cause_type_str_s[idx]);
};

static const char* thread_monitor_status_str[] = {
    "thread monitor active",
    "thread monitor disconnect",
    "thread monitor reconnect"
};

static const char * __severity_to_str(sxd_health_severity_t severity)
{
    const char *str;

    switch (severity) {
    case SXD_HEALTH_SEVERITY_FATAL:
        str = "Fatal";
        break;

    case SXD_HEALTH_SEVERITY_WARN:
        str = "Warning";
        break;

    case SXD_HEALTH_SEVERITY_NOTICE:
        str = "Notice";
        break;

    default:
        str = "N/A";
        break;
    }

    return str;
}

static int __get_kernel_crtimeout_print(char *print_message, uint8_t irisc, uint8_t log_id, struct sx_dev *dev)
{
    int                 err = 0;
    enum sxd_chip_types chip_type = SXD_CHIP_TYPE_UNKNOWN;
    struct sx_priv     *priv = sx_priv(dev);
    bool                iron_emad = false;
    bool                sma_access = false;
    bool                pci_tools_api = false;
    bool                regular_iric = false;

    chip_type = priv->dev_info.dev_info_ro.chip_type;
    /*decide which cr master caused  crspace timeout according to chip type */
    switch (chip_type) {
    case SXD_CHIP_TYPE_SPECTRUM2:
    case SXD_CHIP_TYPE_QUANTUM:
    case SXD_CHIP_TYPE_SPECTRUM:
    case SXD_CHIP_TYPE_SPECTRUM_A1:
    case SXD_CHIP_TYPE_SWITCH_IB:
    case SXD_CHIP_TYPE_SWITCH_IB2:
        if ((log_id == 0) || ((log_id >= 2) && (log_id <= 7))) {
            regular_iric = true;
        }
        if (log_id == 9) {
            pci_tools_api = true;
        }
        if (log_id == 11) {
            sma_access = true;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM3:
    case SXD_CHIP_TYPE_SPECTRUM4:
    case SXD_CHIP_TYPE_SPECTRUM5:
    case SXD_CHIP_TYPE_QUANTUM2:
    case SXD_CHIP_TYPE_QUANTUM3:
        if ((log_id == 0) || ((log_id >= 2) && (log_id <= 9))) {
            regular_iric = true;
        }
        if (log_id == 11) {
            pci_tools_api = true;
        }
        if (log_id == 12) {
            sma_access = true;
        }
        break;

    default:
        err = 1;
        sxd_log_err("Health-Check: cr-timeout print failed, unsupported ASIC type:[%d]\n",
                    chip_type);
        goto out;
        break;
    }


    if ((irisc == FW_SOS_IRON_RISC) && (log_id == FW_SOS_IRON_RISC) && (iron_emad == true)) {
        strcpy(print_message, "Crspace timeout is due to EMAD/ICMD execution");
        goto out;
    }

    if ((pci_tools_api == true) || ((irisc == 1) && (iron_emad == false))) {
        strcpy(print_message, "Crspace timeout is due to Tools or FW dump me API");
        goto out;
    }

    if ((regular_iric == true) && (log_id != irisc)) {
        strcpy(print_message, "Crspace timeout is due to internal FW process");
        goto out;
    }

    if (regular_iric == true) {
        strcpy(print_message, "Crspace timeout is due to EMAD/ICMD execution");
        goto out;
    }

    if (sma_access == true) {
        strcpy(print_message, "crspace timeout is sue to external access via HOST");
        goto out;
    }

    strcpy(print_message, "crspace timeout case is unknown. Check FW");
out:
    return err;
}

/* must be called within the health-check lock */
static struct sx_health_dev_info * __info_find(u8 dev_id)
{
    struct sx_dev             *dev = sx_dev_db_get_dev_by_id(dev_id);
    struct sx_health_dev_info *info;

    if (!dev) {
        return NULL;
    }

    list_for_each_entry(info, &__dev_info_list, dev_list) {
        if (info->dev == dev) {
            return info;
        }
    }

    return NULL;
}

static bool __is_qtm_device(struct sx_dev *dev)
{
    enum sxd_chip_types chip_type = SXD_CHIP_TYPE_UNKNOWN;
    struct sx_priv     *priv = sx_priv(dev);

    chip_type = priv->dev_info.dev_info_ro.chip_type;
    switch (chip_type) {
    case SXD_CHIP_TYPE_QUANTUM:
    case SXD_CHIP_TYPE_QUANTUM2:
    case SXD_CHIP_TYPE_QUANTUM3:
        return true;

    default:
        return false;
    }
}

/* Checks whether FW asked for FW dump generation notification, which means long command timeout occurred. */
static bool __is_long_command_detected(struct sx_health_dev_info *info)
{
    fw_dump_completion_state_t state = FW_DUMP_COMPLETION_STATE_IDLE;

    sx_core_cr_dump_notify_dump_completion(info->dev->device_id, true /* query */, &state);

    /* If this is the first time we recognize the long command, mark device with long_command_detected and zero counter */
    if ((FW_DUMP_COMPLETION_STATE_REQUEST_SENT == state) && !info->long_command_detected) {
        sxd_log_notice(KERN_NOTICE "Health-Check - detected long command\n");
        info->long_command_detected = true;
        info->long_command_event_counter = 0;
    }
    /* If this device is marked with long_command_detected but actual state has changed - FW was released and we can un-mark the device*/
    else if ((FW_DUMP_COMPLETION_STATE_REQUEST_SENT != state) && info->long_command_detected) {
        info->long_command_detected = false;
        info->long_command_event_counter = 0;
    }

    return info->long_command_detected;
}

/* must be called within the device information lock */
static void __add_issue(struct sx_health_dev_info *info,
                        u32                        issue_severity,
                        sxd_health_cause_t         cause,
                        uint8_t                    irisc_id,
                        const char                *err_msg,
                        sxd_event_health_data_t   *event_data)
{
    struct issue_info *new_issue = NULL;

    if (SXD_HEALTH_CAUSE_NONE != info->fatal_cause) {
        /* device is already in fatal mode, ignoring any additional issues */
        return;
    }

    sxd_log_notice("Health-Check: new failure (dev=%u, severity='%s', cause=%d ['%s'], irisc=%u, desc='%s')\n",
                   info->dev->device_id,
                   __severity_to_str(issue_severity),
                   cause,
                   sxd_cause_type_str(cause),
                   irisc_id,
                   err_msg);

    if (SXD_HEALTH_SEVERITY_FATAL == issue_severity) {
        info->fatal_cause = cause;
        if (event_data) {
            memcpy(&info->event_extra_data, event_data, sizeof(info->event_extra_data));
        }
    }

    new_issue = kzalloc(sizeof(struct issue_info), GFP_KERNEL);
    if (new_issue == NULL) {
        sxd_log_err("Health-Check: couldn't allocate device %u health-check failure\n", info->dev->device_id);
        return;
    }

    INIT_LIST_HEAD(&new_issue->list);
    new_issue->severity = issue_severity;
    new_issue->jiffies = jiffies;
    new_issue->cause = cause;
    new_issue->irisc_id = irisc_id;

    if (err_msg) {
        strncpy(new_issue->err_msg, err_msg, sizeof(new_issue->err_msg) - 1);
    }
    if (event_data) {
        memcpy(&new_issue->event_data, event_data, sizeof(new_issue->event_data));
    }

    list_add_tail(&new_issue->list, &info->issues_list);
    if (SX_HEALTH_HIGH_SEVERITY(issue_severity)) {
        info->major_issues_detected++;
    } else {
        info->minor_issues_detected++;
    }

    /* Long command FW events are currently handled only on QTM devices */
    if (__is_qtm_device(info->dev) && (cause != SXD_HEALTH_CAUSE_FW_LONG_COMMAND) &&
        __is_long_command_detected(info)) {
        /* In case long command timeout occurred, we don't want to report any event but the long command event,
         * since it might be a direct result of the long command. We simply print the event details and move on. */
        sxd_log_notice("Health-Check: event is not sent due to long command that was detected!\n");
        info->long_command_detected = true;
        return;
    }

    /*
     * send an event if its severity is equal to or higher than the minimum severity the user asked for.
     * Don't care about FATAL event, it will be raised elsewhere.
     * NOTE: higher severity = lower numeric value.
     **/

    if (info->config.debug_state == HEALTH_DEBUG_MUTE) {
        return;
    }

    if ((info->config.min_severity >= issue_severity) && (issue_severity != SXD_HEALTH_SEVERITY_FATAL)) {
        sx_send_health_event(info->dev->device_id, cause, issue_severity, irisc_id, event_data, NULL);
        sxd_log_notice("Health-Check issue found: device=%d, cause=%s cause id=%d, severity=%s irisc_id=0x%x\n",
                       info->dev->device_id,
                       sxd_cause_type_str(cause),
                       cause,
                       __severity_to_str(issue_severity),
                       irisc_id);
    }
}

static void __add_issue_to_all_devices(u32                issue_severity,
                                       sxd_health_cause_t cause,
                                       u8                 irisc_id,
                                       const char        *err_msg)
{
    struct sx_health_dev_info *info;

    list_for_each_entry(info, &__dev_info_list, dev_list) {
        mutex_lock(&info->lock);
        __add_issue(info, issue_severity, cause, irisc_id, err_msg, NULL);
        mutex_unlock(&info->lock);
    }
}

/*This function check if one of the ECC counters raise, if so in case of correction ecc sent  */
static bool __check_and_update_ecc_counters(struct sx_health_dev_info *info, struct external_cause_work *ecw)
{
    bool is_corrected = false;
    bool is_uncorrected = false;

    if (ecw->data.ecc_stats.ecc_corrected + ecw->data.ecc_stats.ecc_uncorrected == 1) {
        /* this condition is true if:
         * 1. this is the first ECC event since chip reset.
         * 2. this is the first ECC event since someone cleared MECCC counters
         */

        is_corrected = (ecw->data.ecc_stats.ecc_corrected > 0);
        is_uncorrected = (ecw->data.ecc_stats.ecc_uncorrected > 0);
    } else if (ecw->data.ecc_stats.ecc_corrected > info->ecc_stats.ecc_corrected) {
        is_corrected = true;
    } else if (ecw->data.ecc_stats.ecc_uncorrected > info->ecc_stats.ecc_uncorrected) {
        is_uncorrected = true;
    }

    if (is_corrected) {
        info->ecc_stats.ecc_corrected = ecw->data.ecc_stats.ecc_corrected;
        ecw->data.extra_data_event.ecc_data.ecc_stats.ecc_corrected = ecw->data.ecc_stats.ecc_corrected;

        sxd_log_notice("Health-Check :Correctable ECC event received from device [%u]\n", info->dev->device_id);
        ecw->issue_severity = SXD_HEALTH_SEVERITY_NOTICE;
    } else if (is_uncorrected) {
        info->ecc_stats.ecc_uncorrected = ecw->data.ecc_stats.ecc_uncorrected;
        ecw->data.extra_data_event.ecc_data.ecc_stats.ecc_uncorrected = ecw->data.ecc_stats.ecc_uncorrected;

        sxd_log_notice("Health-Check: Uncorrectable ECC event received from device [%u]\n", info->dev->device_id);
        ecw->issue_severity = SXD_HEALTH_SEVERITY_FATAL;
    } else {
        sxd_log_notice("Health-Check: ECC event received from device [%u] but no indication for changes.",
                       info->dev->device_id);
    }

    return is_corrected || is_uncorrected;
}

static bool __check_external_report(struct sx_health_dev_info *info, struct external_cause_work *ecw)
{
    bool ret = true;

    switch (ecw->issue_cause) {
    case SXD_HEALTH_CAUSE_ECC_E:
        /* this call may change health-severity in 'ecw' */
        if (!__check_and_update_ecc_counters(info, ecw)) {
            sxd_log_notice("Health-Check: ECC raised on device %u but no indication for uncorrectable events.",
                           info->dev->device_id);
            ret = false;
        }

        break;

    default:
        break;
    }

    return ret;
}

static void __external_report_work(struct work_struct *work)
{
    struct external_cause_work *ecw = NULL;
    struct sx_health_dev_info  *info = NULL;

    ecw = container_of(work, struct external_cause_work, w);

    mutex_lock(&__health_check_lock);

    if (ecw->dev_id == DEV_ID_ALL) {
        __add_issue_to_all_devices(ecw->issue_severity, ecw->issue_cause,  ecw->irisc_id, ecw->err_msg);
    } else {
        info = __info_find(ecw->dev_id);
        if (info) {
            mutex_lock(&info->lock);

            if (__check_external_report(info, ecw)) {
                __add_issue(info, ecw->issue_severity, ecw->issue_cause, ecw->irisc_id, ecw->err_msg,
                            &ecw->data.extra_data_event);
            }

            mutex_unlock(&info->lock);
        }
    }

    mutex_unlock(&__health_check_lock);
    kfree(ecw);
}

static void __sx_health_external_report(u8                                 dev_id,
                                        u32                                issue_severity,
                                        u32                                issue_cause,
                                        u8                                 irisc_id,
                                        sxd_health_external_report_data_t *data,
                                        const char                        *err_msg)
{
    struct external_cause_work *ecw;

    ecw = kzalloc(sizeof(struct external_cause_work), GFP_ATOMIC);
    if (!ecw) {
        sxd_log_err("Health-Check:health report allocation failed: dev_id [%u], severity [%u], error [%s]\n",
                    dev_id,
                    issue_severity,
                    ((err_msg) ? err_msg : "N/A"));
        return;
    }

    INIT_WORK(&ecw->w, __external_report_work);
    ecw->dev_id = dev_id;
    ecw->issue_severity = issue_severity;
    ecw->issue_cause = issue_cause;
    ecw->irisc_id = irisc_id;

    if (data) {
        memcpy(&ecw->data, data, sizeof(ecw->data));
    }

    if (err_msg) {
        strncpy(ecw->err_msg, err_msg, sizeof(ecw->err_msg) - 1);
    }

    queue_work(__health_check_wq, &ecw->w);
}

void sx_health_report_error_fshe(struct sx_dev *dev, struct ku_fshe_reg *fshe_reg)
{
    char error_msg[64] = { 0 };

    snprintf(error_msg, sizeof(error_msg) - 1, "[hw_error_mask = 0x%x]",
             fshe_reg->hw_errors);

    __sx_health_external_report(dev->device_id,
                                SXD_HEALTH_SEVERITY_FATAL,
                                SXD_HEALTH_CAUSE_STATEFUL_DB_ORDERING_E,
                                DBG_ALL_IRISCS,
                                NULL,
                                error_msg);
}

void sx_health_report_error_meccc(struct sx_dev *dev, struct ku_meccc_reg *meccc_reg)
{
    sxd_health_external_report_data_t data;

    memset(&data, 0, sizeof(data));

    data.extra_data_event.ecc_data.device_index = meccc_reg->device_index;
    data.extra_data_event.ecc_data.slot_index = meccc_reg->slot_index;
    data.ecc_stats.ecc_uncorrected = meccc_reg->ecc_ucrt_cnt;
    data.ecc_stats.ecc_corrected = meccc_reg->ecc_crt_cnt;

    /* the severity will be update in a lower level */
    __sx_health_external_report(dev->device_id,
                                SXD_HEALTH_SEVERITY_NOTICE,
                                SXD_HEALTH_CAUSE_ECC_E,
                                DBG_ALL_IRISCS,
                                &data,
                                "MECCC event raised ECC corrected/uncorrected");
}

/* check if bitmap_subset covered by bitmap , bitmap is function as the operational
 * bitmap of all the RDQ/SDQ that got hit(traps/traffic) from HW, bitmap_subset
 *  will functions as requested  RDQ/SDQ that we want to get ACK on them.
 *  if bit_id with value of 1 means we got hit (bitmap) or want to get
 *  trap(subset bitmap) on this RDQ/SDQ.
 *  if case of un match function will return the first bit equal to 1
 *  that bitmap not contain,
 *  in case bitmap contain bitmap_subset return  -1 */
static u32 __bitmaps_covered(struct sx_bitmap *bitmap,
                             struct sx_bitmap *bitmap_subset,
                             struct sx_bitmap *all_missing_bitmap)
{
    u32  bit_id, max, main_bit_id_value, subset_bit_id_value;
    u32  first_miss_bit = (u32) - 1;    /* Default value in case we won't find any miss */
    bool is_first_bit_found = false;

    /* bitmap and bitmap_subset share the same size */
    max = sx_bitmap_num_bits(bitmap_subset);

    for (bit_id = 0; bit_id < max; bit_id++) {
        subset_bit_id_value = sx_bitmap_test(bitmap_subset, bit_id);
        /* only in case this bit id was requested check operation bit map */
        if (subset_bit_id_value) {
            main_bit_id_value = sx_bitmap_test(bitmap, bit_id);
            if (main_bit_id_value != subset_bit_id_value) {
                if (is_first_bit_found == false) {
                    first_miss_bit = bit_id;
                    is_first_bit_found = true;
                }
                sx_bitmap_set(all_missing_bitmap, bit_id);
            }
        }
    }

    return first_miss_bit;
}

static void __update_sdk_thread_last_time_alive(struct sx_bitmap           *running_bitmap,
                                                struct sx_bitmap           *last_bitmap,
                                                u32                         mult_threshold_time,
                                                u32                         new_debug_time_for_all_threads,
                                                ku_thread_status_changed_t *threads_info)
{
    u32           bit_id, max;
    u64           max_expected_thread_duration_sec;
    unsigned long now = jiffies;

    /* bitmap and bitmap_subset share the same size */
    max = sx_bitmap_num_bits(running_bitmap);
    for (bit_id = 0; bit_id < max; bit_id++) {
        if (sx_bitmap_test(running_bitmap, bit_id) && sx_bitmap_test(last_bitmap, bit_id)) {
            threads_info[bit_id].time_passed_from_last_update =
                (jiffies_to_msecs(now - threads_info[bit_id].last_update_time) / 1000);
            if ((long)threads_info[bit_id].time_passed_from_last_update < 0) {
                sxd_log_err("Health-Check: internal error time_passed_from_last_update negative time[%lu] (sec), for thread [%s] bit_id[%d], "
                            " now [%lu] (jiffies unit) is smaller "
                            "them last_update_time [%ld] (jiffies unit).  \n",
                            (long)threads_info[bit_id].time_passed_from_last_update,
                            threads_info[bit_id].name,
                            bit_id,
                            now,
                            threads_info[bit_id].last_update_time);
            }
            threads_info[bit_id].last_update_time = now;
        } else {
            if (sx_bitmap_test(last_bitmap, bit_id)) {   /*last is up but running is down */
                threads_info[bit_id].time_passed_from_last_update =
                    (jiffies_to_msecs(now - threads_info[bit_id].last_update_time) / 1000);
                /* Checks if threshold time should be change for debug propose if new time was set or need to extend time for slow setups*/
                if (new_debug_time_for_all_threads) {
                    max_expected_thread_duration_sec = new_debug_time_for_all_threads;
                } else {
                    max_expected_thread_duration_sec = threads_info[bit_id].max_expected_thread_duration_sec *
                                                       mult_threshold_time;
                }
                if ((long)threads_info[bit_id].time_passed_from_last_update < 0) {
                    sxd_log_err("Health-Check: internal error time_passed_from_last_update negative time[%lu] (sec), for thread [%s] bit_id[%d], "
                                " now [%lu] (jiffies unit) is smaller "
                                "them last_update_time [%ld] (jiffies unit).  \n",
                                (long)threads_info[bit_id].time_passed_from_last_update,
                                threads_info[bit_id].name,
                                bit_id,
                                now,
                                threads_info[bit_id].last_update_time);
                }
                if (threads_info[bit_id].time_passed_from_last_update < max_expected_thread_duration_sec) {
                    sx_bitmap_set(running_bitmap, bit_id);
                }
            }
        }
    }
}

static int __write_hett(struct ku_access_hett_reg *hett, struct sx_dev *dev, const char *op)
{
    int err;

    hett->dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&hett->op_tlv, MLXSW_HETT_ID, EMAD_METHOD_WRITE);
    err = sx_ACCESS_REG_HETT(dev, hett);
    if (err) {
        sxd_log_err("Health-Check:sx_ACCESS_REG_HETT (%s) returned with error %d\n", op, err);
    }

    return err;
}

static int __read_meccc_and_update_ecc_stas(struct ku_access_meccc_reg *meccc,
                                            struct sx_health_dev_info  *info,
                                            const char                 *op)
{
    int err = 0;

    meccc->dev_id = info->dev->device_id;
    sx_cmd_set_op_tlv(&meccc->op_tlv, MLXSW_MECCC_ID, EMAD_METHOD_QUERY);
    err = sx_ACCESS_REG_MECCC(info->dev, meccc);
    if (err) {
        sxd_log_err("Health-Check:sx_ACCESS_REG_MECCC (%s) returned with error %d\n", op, err);
        goto out;
    }
    info->ecc_stats.ecc_corrected = meccc->meccc_reg.ecc_crt_cnt;
    info->ecc_stats.ecc_uncorrected = meccc->meccc_reg.ecc_ucrt_cnt;
out:
    return err;
}

static int __read_write_mfgd(struct ku_access_mfgd_reg *mfgd, struct sx_dev *dev, sx_emad_method_e cmd)
{
    mfgd->dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&mfgd->op_tlv, MLXSW_MFGD_ID, cmd);
    return sx_ACCESS_REG_MFGD(dev, mfgd);
}

/* calculate how many sdq iteration allowed without ACK from HW,
 * every iteration take periodic_time , max time without ACK is
 * 10000 msecs (10 seconds)   */
static u32 __sx_sdq_calc_num_of_check_iter(u32 periodic_time)
{
    return (10000 / (periodic_time * 1000)) + 1;
}

static void __check_tasklet(struct sx_health_dev_info *info)
{
    struct sx_priv *priv = sx_priv(info->dev);
    char            err_msg[HEALTH_CHECK_EVENT_MSG_MAX];

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_TASKLET))) {
        return;
    }

    /* check if PCI device */
    if (info->dev->pdev == NULL) {
        return;
    }

    if (priv->health_check.tasklet_start_cnt == priv->health_check.tasklet_end_cnt) {
        /* tasklet is not running now, so nothing to measure here */
        return;
    }

    /* if last tasklet started more than 2 seconds ago, we're in deep trouble */
    if (time_after(jiffies, priv->health_check.tasklet_last_start + 2 * HZ)) {
        snprintf(err_msg, sizeof(err_msg) - 1, "Interrupt handler is running for a long time! (iteration=%llu)\n",
                 priv->health_check.tasklet_start_cnt);
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_SDK_THREADS, DBG_ALL_IRISCS, err_msg, NULL);
    }
}

/* must be called within the device information lock */
static void __check_catas(struct sx_health_dev_info *info)
{
    struct sx_priv *priv = sx_priv(info->dev);
    char            err_msg[HEALTH_CHECK_EVENT_MSG_MAX];
    u32             catas = 0;

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_CATAS))) {
        return;
    }

    if (!priv->health_check.debug_trigger_state.catas) { /* debug trigger not set */
        if (!info->catas_iomap) { /* device does not support catas */
            catas = 0;
        } else {
            catas = swab32(__raw_readl(info->catas_iomap));
        }
    } else {
        catas = 0xdeadbeaf;
    }

    /* Bit 0 TCAM ECC error is already covered by MECCC trap, here we only check bit 1. */
    if (catas & 0x2) {
        snprintf(err_msg, sizeof(err_msg) - 1, "0x%x", catas);
        __add_issue(info, SXD_HEALTH_SEVERITY_FATAL, SXD_HEALTH_CAUSE_CATAS, DBG_ALL_IRISCS, err_msg, NULL);
    }
}

/* must be called within the device information lock */
static void __start_and_check_cmd_ifc(struct sx_health_dev_info *info)
{
    struct sx_priv *priv = sx_priv(info->dev);
    int             err = 0;
    char            err_msg[HEALTH_CHECK_EVENT_MSG_MAX];
    bool            cntr_advanced = (info->config.cmd_ifc.last_cmd_ifc_counter
                                     < priv->health_check.cmd_ifc_num_of_pck_received);

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_CMD_IFC))) {
        return;
    }

    info->config.cmd_ifc.cmd_ctx = NULL;
    info->config.cmd_ifc.mailbox_p = NULL;

    /* Check if debug trigger turn on*/
    if (priv->health_check.debug_trigger_state.cmd_ifc) {
        snprintf(err_msg, sizeof(err_msg) - 1, "Debug trigger set");
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_GO_BIT, DBG_ALL_IRISCS, err_msg, NULL);
        goto out;
    }

    /* cmd_ifc got new ACK from last cycle */
    if (cntr_advanced) {
        info->config.cmd_ifc.last_cmd_ifc_counter = priv->health_check.cmd_ifc_num_of_pck_received;
        info->config.cmd_ifc.is_last_pkt_sent_via_health = false;
        goto out;
    }
    /* number of cmd_ifc packets not increase from last iteration  */
    /* try to acquire cmd_ifc semaphore*/
    err = sx_cmd_prepare(info->dev, SX_CMD_QUERY_FW_HCR1, &info->config.cmd_ifc.cmd_ctx);
    /*  Acquire semaphore failed ,someone from outside of health check is took it*/
    if (err) {
        /* In the prev iteration we sent cmd_ifc via health check and then
         * external cmd_ifc was taken so its mean the external cmd_ifc
         *  running less then time frame configures (1 sec in default mode) so we will sign that in this iteration packet
         *   did not sent via health check and go out
         **/
        if (info->config.cmd_ifc.is_last_pkt_sent_via_health) {
            info->config.cmd_ifc.is_last_pkt_sent_via_health = false;
            goto out;
        }

        /* packet from outside stuck on the cmd_ifc more then time frame configures*/
        snprintf(err_msg,
                 sizeof(err_msg) - 1,
                 "Health-Mechanism: failed to acquire CmdIfc semaphore [last_packet_sent_from_health=%s]",
                 ((info->config.cmd_ifc.is_last_pkt_sent_via_health) ? "yes" : "no"));
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_GO_BIT, DBG_ALL_IRISCS, err_msg, NULL);
        goto out;
    }

    /* Seceded to acquire cmd_ifc semaphore*/
    /* GO bit not free - Only if sent query_fw via health check in
     * Previous cycles and got timeout  */
    if (sx_cmd_check_go_bit(info->dev, info->dev->device_id)) {
        snprintf(err_msg,
                 sizeof(err_msg) - 1,
                 "Health-Mechanism: go-bit is not cleared from previous command [last_packet_sent_from_health=%s]",
                 ((info->config.cmd_ifc.is_last_pkt_sent_via_health) ? "yes" : "no"));
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_GO_BIT, DBG_ALL_IRISCS, err_msg, NULL);
        goto out_release;
    }

    /* Go bit cleared and cmd-ifc can be send*/
    info->config.cmd_ifc.last_cmd_ifc_counter = priv->health_check.cmd_ifc_num_of_pck_received;
    err = sx_cmd_health_check_send(info->dev, &info->config.cmd_ifc.mailbox_p, info->config.cmd_ifc.cmd_ctx);
    /* Failed to send cmd_ifc*/
    if (err) {
        sxd_log_err("Health-Check:Failed to send cmd_ifc \n");
        info->config.cmd_ifc.is_last_pkt_sent_via_health = false;
        goto out_release;
    }

    /* check if after 100ms cmd_ifc got ACK*/
    msleep(100);

    /* Go bit still busy and did not got ACK  */
    if (sx_cmd_check_go_bit(info->dev, info->dev->device_id)) {
        snprintf(err_msg,
                 sizeof(err_msg) - 1,
                 "Health-Mechanism: go-bit is not cleared after sending probe command");
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_GO_BIT, DBG_ALL_IRISCS, err_msg, NULL);
    } else {  /* In case of got ACK after 100ms*/
        info->config.cmd_ifc.last_cmd_ifc_counter = priv->health_check.cmd_ifc_num_of_pck_received;
    }

    info->config.cmd_ifc.is_last_pkt_sent_via_health = true;

out_release:
    /* Release the semaphore*/
    sx_cmd_health_check_release(info->dev, info->config.cmd_ifc.mailbox_p, info->config.cmd_ifc.cmd_ctx);

out:
    return;
}


static void __check_and_report_sdq_failure(struct sx_health_dev_info *info, u32 first_missing_bit_index)
{
    char err_msg[HEALTH_CHECK_EVENT_MSG_MAX];

    /*failure - exceed the time frame  */
    if (info->config.sdq.num_of_check_iter >= info->config.sdq.max_iter_allowed) {
        sxd_log_notice("Health-Check:Did not receive completion for SDQ dqn (%u) \n",
                       first_missing_bit_index);
        snprintf(err_msg, sizeof(err_msg) - 1, "SDQ #%u", first_missing_bit_index);
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_SDQ, DBG_ALL_IRISCS, err_msg, NULL);
        /* cleaning parameters to start point*/
        info->config.sdq.num_of_check_iter = 0;
    }
}

static int __test_sdq(struct sx_dev *dev)
{
    /*FW return EMAD_STS_OK in case we send on query mode PPAD full of 0 */
    uint8_t         ppad[16] = { 0 };
    int             len = 0;
    struct sk_buff *skb = NULL;
    struct sk_buff *new_skb = NULL;
    int             ret = 0;
    int             sdq_id;
    u32             max_sdq;
    struct isx_meta meta;
    struct sx_dq   *sdq = NULL;
    struct sx_priv *priv = sx_priv(dev);

    memset(&meta, 0, sizeof(meta));
    /* 0xffffffff TID value will sign that this packet is health check packet */

    max_sdq = priv->dev_cap.max_num_sdqs;
    for (sdq_id = 0; sdq_id < max_sdq; sdq_id++) {
        sdq = priv->sdq_table.dq[sdq_id];
        /* if SDQ exist/in use */
        if (sdq) {
            ret = sx_emad_build(dev->device_id, ppad, sizeof(ppad), &skb,
                                &meta, 0xffff, 0xffff,
                                GFP_KERNEL, PPAD_REG_ID, EMAD_METHOD_QUERY);
            if (ret != 0) {
                sxd_log_err("Health-Check:failed to send SDQ test packet (ret=%d)\n", ret);
                goto out;
            }

            /* If there's no place for the ISX header
             * need to alloc a new skb and use it instead */
            if (skb_headroom(skb) < ISX_HDR_SIZE) {
                len = skb->len;
                new_skb = alloc_skb(ISX_HDR_SIZE + len, GFP_KERNEL);
                if (!new_skb) {
                    sxd_log_rl_err("__test_sdq"
                                   "Err: failed allocating "
                                   "SKB\n");
                    /* todo add counters of packets that sent and received under PRIV */

                    kfree_skb(skb); /* drop packet flow, use kfree_skb */

                    return -ENOMEM;
                }

                skb_reserve(new_skb, ISX_HDR_SIZE);
                memcpy(skb_put(new_skb, len), skb->data, len);

                /* free unused clone, use consume_skb */
                consume_skb(skb);
                skb = new_skb;
            }

            ret = __sx_core_post_send(dev, skb, &meta, sdq_id);
            if (ret != 0) {
                sxd_log_warning("Health-Check: failed to send packet to test SDQ %d (ret=%d)\n", sdq_id, ret);

                /* keep iterating the SDQs !!! don't break here! */
            }
        }
    }

out:
    return ret;
}

/* must be called within the device information lock */
static void __start_sdq_for_next_cycle(struct sx_health_dev_info *info)
{
    struct sx_priv *priv = sx_priv(info->dev);

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_SDQ))) {
        return;
    }

    /* we cannot send packets to an SDQ before PCI profile is set */
    if (!priv->profile.pci_profile_set) {
        return;
    }

    /*initialize operational state RDQ bitmap*/
    sx_bitmap_clear_all(&priv->health_check.operational_state.sdq_bitmap);
    __test_sdq(info->dev);
}

/* must be called within the device information lock */
static void __check_sdq_from_last_cycle(struct sx_health_dev_info *info)
{
    struct sx_priv  *priv = sx_priv(info->dev);
    u32              first_missing_bit_index = 0;
    struct sx_bitmap all_missing_bitmap;

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_SDQ))) {
        return;
    }

    /* if PCI profile is not set, no point to check SDQ */
    if (!priv->profile.pci_profile_set) {
        return;
    }

    sx_bitmap_init(&all_missing_bitmap, NUMBER_OF_SDQS);

    info->config.sdq.num_of_check_iter++;

    first_missing_bit_index = __bitmaps_covered(&priv->health_check.operational_state.sdq_bitmap,
                                                &info->config.sdq.sdq_bitmap,
                                                &all_missing_bitmap);
    if (first_missing_bit_index != ((u32) - 1)) {
        __check_and_report_sdq_failure(info, first_missing_bit_index);
    } else {
        info->config.sdq.num_of_check_iter = 0;
    }
}

/* must be called within the device information lock */
static void __start_rdq_for_next_cycle(struct sx_health_dev_info *info)
{
    struct ku_access_hett_reg reg_hett;
    int                       err = 0;
    struct sx_priv           *priv = sx_priv(info->dev);

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_RDQ))) {
        return;
    }

    /* if PCI profile is not set, no point to check RDQ */
    if (!priv->profile.pci_profile_set) {
        return;
    }

    /*initialize operational state RDQ bitmap*/
    sx_bitmap_clear_all(&priv->health_check.operational_state.rdq_bitmap);

    /*rdq_bitmap changed on the fly so last_rdq_bitmap will be static and will represent the HETT requested rdq_bitmap*/
    sx_bitmap_copy(&info->config.last_rdq_bitmap, &info->config.rdq_bitmap);

    /* here we mask all the WJH/ignore RDQ from the RDQ DB (that contain all the
     *  rdq that exist in the chip)*/
    info->config.last_rdq_bitmap.table[0] = (info->config.last_rdq_bitmap.table[0])
                                            & ((~info->config.ignore_rdq_bitmap.table[0]));

    memset(&reg_hett, 0, sizeof(reg_hett));
    reg_hett.hett_reg.opcode = START_HETT_SESSION;
    reg_hett.hett_reg.trap_group_bitmap = info->config.last_rdq_bitmap.table[0];
    err = __write_hett(&reg_hett, info->dev, "send trap group bitmap");

    if (err) {
        __add_issue(info, SXD_HEALTH_SEVERITY_FATAL, SXD_HEALTH_CAUSE_FW_HETT, DBG_ALL_IRISCS, NULL, NULL);
    }
}

/* must be called within the device information lock */
static void __check_rdq_from_last_cycle(struct sx_health_dev_info *info)
{
    uint32_t         first_missing_bit_index = 0;
    char             err_msg[HEALTH_CHECK_EVENT_MSG_MAX];
    struct sx_priv  *priv = sx_priv(info->dev);
    struct sx_bitmap all_missing_bitmap;

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_RDQ))) {
        return;
    }

    /* if PCI profile is not set, no point to check RDQ */
    if (!priv->profile.pci_profile_set) {
        return;
    }

    sx_bitmap_init(&all_missing_bitmap, NUMBER_OF_RDQS);

    first_missing_bit_index =
        __bitmaps_covered(&priv->health_check.operational_state.rdq_bitmap,
                          &info->config.last_rdq_bitmap,
                          &all_missing_bitmap);
    if (first_missing_bit_index != ((u32) - 1)) {
        snprintf(err_msg, sizeof(err_msg) - 1, "RDQ #%u", first_missing_bit_index);
        sxd_log_notice("Health check: all RDQS that missing rdq 0-61 [0x%lx]\n",
                       all_missing_bitmap.table[0]);
        __add_issue(info, SXD_HEALTH_SEVERITY_WARN, SXD_HEALTH_CAUSE_RDQ, DBG_ALL_IRISCS, err_msg, NULL);
    }
    sx_bitmap_clear_all(&info->config.last_rdq_bitmap);
}

/* must be called within the device information lock */
static void __check_sdk_hc_monitor_init_thread(struct sx_health_dev_info *info)
{
    char error_msg[HEALTH_CHECK_EVENT_MSG_MAX] = {0};

    if (!(info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_SDK_THREADS))) {
        return;
    }

    if ((info->config.thread_monitoring_status == THREAD_MONITOR_ACTIVE_E) &&
        (info->config.sdk_thread_info.sdk_monitor_last_checked_counter ==
         info->config.sdk_thread_info.sdk_main_monitor_counter)) {
        info->config.sdk_thread_info.num_of_iter_without_cnt_increase++;
        /* 3 health check cycle iteration sdk td worker did not send any sdk monitor update */
        if (info->config.sdk_thread_info.num_of_iter_without_cnt_increase ==
            NUM_OF_HC_CYCLE_ITER_INIT_THREAD_NOT_RESPONSE) {
            snprintf(error_msg, sizeof(error_msg), "SDK main monitor thread does not respond");
            sxd_log_err("%s\n", error_msg);
            __add_issue(info, SXD_HEALTH_SEVERITY_FATAL, SXD_HEALTH_CAUSE_SDK_THREADS, DBG_ALL_IRISCS, error_msg,
                        NULL);
        }
    } else {
        info->config.sdk_thread_info.sdk_monitor_last_checked_counter =
            info->config.sdk_thread_info.sdk_main_monitor_counter;
        info->config.sdk_thread_info.num_of_iter_without_cnt_increase = 0;
    }
}
static void __check_sysfs_ts_threshold(void)
{
    unsigned long now = jiffies;

    if (!(__global_checks_bitmap & SX_HC_BIT(SX_HC_GLOBAL_CHECK_SYSFS_TS))) {
        return;
    }

    /* check if last sysfs "running counter" did not updated more than 5 seconds ago */
    if (time_after(now, __health_check_ts_jiffies + 5 * HZ)) {
        sxd_log_err("Sysfs running counter is not updated for more than 5 sec! running counter =[%llu],"
                    " last time update = [%d] msec ago"
                    "\n", __health_check_ts, jiffies_to_msecs(now - __health_check_ts_jiffies));
    }
}

static void __set_threads_last_time_update(ku_thread_status_changed_t *thread_status)
{
    u32 thread_index;

    for (thread_index = 0; thread_index < NUM_OF_SDK_THREADS_MAP_BY_BITS; thread_index++) {
        /* if SDK thread exist/in use */
        if (thread_status[thread_index].thread_id) {
            thread_status[thread_index].last_update_time = jiffies;
        }
    }
}

static int __sx_health_update_sdk_thread_monitor(u8 dev_id, const threads_monitor_info_t* threads_info)
{
    struct sx_health_dev_info *info = NULL;
    u32                        first_missing_bit_index = 0;
    char                       error_msg[HEALTH_CHECK_EVENT_MSG_MAX] = {0};
    struct sx_bitmap           all_missing_bitmap;

    sx_bitmap_init(&all_missing_bitmap, SDK_THREAD_MONITOR_BITMAP_SIZE);
    info = __info_find(dev_id);
    if (!info) {
        return 0; /* When health check is disabled, need to return success and not error because the device isn't available*/
    }

    mutex_lock(&info->lock);

    switch (threads_info->thread_monitoring_status) {
    case THREAD_MONITOR_ACTIVE_E:
        sxd_log_debug("Health check:thread monitoring is Active \n");
        break;

    case THREAD_MONITOR_DISCONNECT_E:
        info->config.thread_monitoring_status = THREAD_MONITOR_DISCONNECT_E;
        sxd_log_info("Health check: thread monitoring is disconnect \n");
        goto out;

    case THREAD_MONITOR_RECONNECT_E:
        info->config.thread_monitoring_status = THREAD_MONITOR_ACTIVE_E;
        sxd_log_info("Health check: thread monitoring is reconnect \n");
        __set_threads_last_time_update(info->config.sdk_thread_info.bit_to_thread_status_arr);
        goto out;

    default:
        sxd_log_err("Health check: thread monitoring status=%d is out of range \n",
                    threads_info->thread_monitoring_status);
        goto out;
    }
    info->config.sdk_thread_info.sdk_main_monitor_counter++;
    /* Convert u64 to bitmaps*/
    sx_set_u64_to_bitmap(threads_info->running_threads_status, &info->config.sdk_thread_info.running_bitmap);
    sx_set_u64_to_bitmap(threads_info->last_sent_threads_existing, &info->config.sdk_thread_info.last_sent_bitmap);
    /* Find the missing bit*/
    __update_sdk_thread_last_time_alive(&info->config.sdk_thread_info.running_bitmap,
                                        &info->config.sdk_thread_info.last_sent_bitmap,
                                        info->config.sdk_thread_info.mult_threshold_time,
                                        info->config.sdk_thread_info.new_debug_time_for_thread_monitor,
                                        info->config.sdk_thread_info.bit_to_thread_status_arr);
    first_missing_bit_index = __bitmaps_covered(&info->config.sdk_thread_info.running_bitmap,
                                                &info->config.sdk_thread_info.last_sent_bitmap, &all_missing_bitmap);
    if ((first_missing_bit_index != ((u32) - 1)) &&
        (info->config.thread_monitoring_status == THREAD_MONITOR_ACTIVE_E)) {
        if (info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].thread_id == 0) {
            /* first 32 bits map once we will have more then 64 thread need to print the next 64 bits*/
            sxd_log_err("Health check:all missing threads via bitmap 0x%lx first_missing_bit_index =%d \n",
                        all_missing_bitmap.table[0],
                        first_missing_bit_index);
            sxd_log_err("Health check:sdk monitor -Internal error thread [%s] with bit id [%u] contain invalid thread id [0x%llx] "
                        "cmd [%d] time_passed_from_last_update [%lu] sec, num of threads monitored [%d]\n",
                        info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].name,
                        info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].bit_index,
                        info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].thread_id,
                        info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].cmd,
                        info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].time_passed_from_last_update,
                        info->config.sdk_thread_info.sdk_thread_monitor_cnt);
            goto out;
        }
        snprintf(error_msg,
                 sizeof(error_msg),
                 "Health check: SDK thread [%s] TID [0x%llx] bit [%d] does not respond [%lu] seconds",
                 info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].name,
                 info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].thread_id,
                 info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].bit_index,
                 info->config.sdk_thread_info.bit_to_thread_status_arr[first_missing_bit_index].time_passed_from_last_update);
        sxd_log_err("%s\n", error_msg);
        __add_issue(info, SXD_HEALTH_SEVERITY_FATAL, SXD_HEALTH_CAUSE_SDK_THREADS, DBG_ALL_IRISCS, error_msg, NULL);
    }
out:
    mutex_unlock(&info->lock);
    return 0;
}

static int __sx_health_update_sdk_thread_status_changed(u8 dev_id, const ku_thread_status_changed_t* threads_info)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (!info) {
        return -ENODEV;
    }

    mutex_lock(&info->lock);

    if (SX_HEALTH_CHECK_DELETE_THREAD == threads_info->cmd) {
        if (info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index].thread_id) {
            /* In case this entry/thread was exist (maybe the thread was created and deleted during the time main thread (td worker) slept ) */
            info->config.sdk_thread_info.sdk_thread_monitor_cnt--;
        }
        memset(&info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index],
               0, sizeof(ku_thread_status_changed_t));
    } else { /* Add new thread*/
        /* In case its a new thread that hold a new bit so num of thread will increase
         * ,otherwise we just replace the thread info (because its deleted and new thread created a took this place) */
        if (info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index].thread_id == 0) {
            info->config.sdk_thread_info.sdk_thread_monitor_cnt++;
        }
        memcpy(&info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index],
               threads_info,
               sizeof(ku_thread_status_changed_t));
        info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index].time_passed_from_last_update =
            0;
        info->config.sdk_thread_info.bit_to_thread_status_arr[threads_info->bit_index].last_update_time = jiffies;
    }

    mutex_unlock(&info->lock);
    return 0;
}

static int __sx_health_set_issu_on(u8 dev_id, struct completion *cyc_finish_wq_completion)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (!info) {
        return -ENODEV;
    }

    mutex_lock(&info->lock);
    if (info->issu_on) {
        goto out;
    }

    init_completion(cyc_finish_wq_completion);
    info->issu_on = true;
    info->issu_signal_done = false;
    info->wq_issu_cyc_completion = cyc_finish_wq_completion;

out:
    mutex_unlock(&info->lock);

    return 0;
}


static int __sx_health_set_issu_off(u8 dev_id)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (!info) {
        return -ENODEV;
    }

    mutex_lock(&info->lock);
    if (!info->issu_on) {
        goto out;
    }

    info->issu_on = false;
    info->issu_signal_done = false;
    info->health_check_first_itr_skip_checks_func = true;

out:
    mutex_unlock(&info->lock);

    return 0;
}

/* must be called within the device information lock */
static void __remove_old_issues(struct sx_health_dev_info *info)
{
    struct issue_info *iter, *tmp, *to_remove;
    unsigned long      now = jiffies;

    list_for_each_entry_safe(iter, tmp, &info->issues_list, list) {
        if (time_after(now, iter->jiffies + info->config.failures_num * 10 * HZ)) {
            if (SX_HEALTH_HIGH_SEVERITY(iter->severity)) {
                info->major_issues_detected--;
            } else {
                info->minor_issues_detected--;
            }

            list_del(&iter->list);
            list_add_tail(&iter->list, &info->issues_history);
            if (info->history_size == MAX_HISTORY_SIZE) {
                to_remove = list_first_entry(&info->issues_history, struct issue_info, list);
                list_del(&to_remove->list);
                kfree(to_remove);
            } else {
                info->history_size++;
            }
        } else {
            break; /* failures are in chronological order, if we're here we can stop the iteration */
        }
    }
}

/* MAIN THREAD of health check mechanism , sample all monitors and sent Health check event  */
static void __sx_health_check_cycle(struct work_struct *work)
{
    struct sx_health_dev_info *info = container_of(work, struct sx_health_dev_info, main_health_check_dwork.work);
    struct issue_info         *failure = NULL;
    struct sx_priv            *priv = NULL;

    mutex_lock(&info->lock);

    if (info->disabled) {
        /* user removed device from health-check. */
        goto out;
    }

    /* Long command FW events are currently handled only on QTM devices */
    if (__is_qtm_device(info->dev) && __is_long_command_detected(info)) {
        info->long_command_event_counter++;
        if (info->long_command_event_counter >= LONG_COMMAND_MAX_COUNTER) {
            /* If the long command bit is on and it's been LONG_COMMAND_MAX_COUNTER cycles, it means that either
             * we didn't receive the long command MFDE, or that NOS did not released the interface and re-enable
             * the health monitor. Hence - we send a FATAL event to NOS and stop monitoring. */
            sxd_log_err("Health-Check: long command was not released after %d seconds, "
                        "stopping further device monitoring!\n",
                        LONG_COMMAND_MAX_COUNTER);

            if (info->config.debug_state != HEALTH_DEBUG_MUTE) {
                sx_send_health_event(info->dev->device_id,
                                     SXD_HEALTH_CAUSE_FW_LONG_COMMAND,
                                     SXD_HEALTH_SEVERITY_FATAL,
                                     0xff,
                                     NULL,
                                     NULL);
            }

            goto out;
        }
        goto schedule_next_cycle;
    }

    /* this is an immediate check, no need for 2-step check */
    __check_tasklet(info);

    /* this is an immediate check, no need for 2-step check */
    __check_catas(info);

    if (info->issu_on) {
        if (!info->issu_signal_done) {
            complete(info->wq_issu_cyc_completion);
            info->issu_signal_done = true;
        }
        goto issu_supported_features;
    }

    if (info->health_check_first_itr_skip_checks_func) {
        info->health_check_first_itr_skip_checks_func = false;
        goto health_monitor;
    }
    __check_sdq_from_last_cycle(info);
    __check_rdq_from_last_cycle(info);
    __check_sdk_hc_monitor_init_thread(info);
    __check_sysfs_ts_threshold();

health_monitor:
    __start_rdq_for_next_cycle(info);

    /* start sending packets to SDQ's in case the last SDQ check confirm new
     * season should start */
    if (info->config.sdq.num_of_check_iter == 0) {
        __start_sdq_for_next_cycle(info);
    }

    __start_and_check_cmd_ifc(info);

issu_supported_features:
    failure = list_last_entry(&info->issues_list, struct issue_info, list);

    /* Long command FW events are currently handled only on QTM devices */
    if (__is_qtm_device(info->dev) && __is_long_command_detected(info)) {
        /* In case long command was detected, we don't want to report any event to NOS since is might be caused
         * by the long command process. We start a counter and just move to next cycle, until LONG_COMMAND_MAX_COUNTER
         * achieved or NOS releases FW and re-enable health monitor. */
        info->long_command_event_counter++;
        goto schedule_next_cycle;
    }

    priv = sx_priv(info->dev);

    if (info->fatal_cause != SXD_HEALTH_CAUSE_NONE) {
        /* Fatal failure detect: send SDK health event and stop monitoring this device */

        if (info->config.debug_state != HEALTH_DEBUG_MUTE) {
            sx_send_health_event(info->dev->device_id,
                                 info->fatal_cause,
                                 SXD_HEALTH_SEVERITY_FATAL,
                                 failure->irisc_id,
                                 &info->event_extra_data,
                                 NULL);
        }

        priv->health_check.is_fatal = true;
        sxd_log_err("Health-Check: device=%u, cause=%d ['%s'] - stopping further device monitoring!\n",
                    info->dev->device_id,
                    info->fatal_cause,
                    sxd_cause_type_str(info->fatal_cause));

        if (info->config.debug_state == HEALTH_DEBUG_DONT_STOP_ON_FATAL) {
            goto schedule_next_cycle;
        }

        goto out;
    }

    if (info->major_issues_detected >= info->config.failures_num) {
        /* Too many failures: send SDK health event with SXD_HEALTH_CAUSE_SDK_WD cause and stop monitoring this device */

        info->fatal_cause = SXD_HEALTH_CAUSE_SDK_WD;

        if (info->config.debug_state != HEALTH_DEBUG_MUTE) {
            sx_send_health_event(info->dev->device_id,
                                 SXD_HEALTH_CAUSE_SDK_WD,
                                 SXD_HEALTH_SEVERITY_FATAL,
                                 failure->irisc_id,
                                 NULL,
                                 NULL);
        }

        priv->health_check.is_fatal = true;
        sxd_log_err("Health-Check: device %u is set to FATAL because of too many major issues - "
                    "stopping further device monitoring!\n",
                    info->dev->device_id);

        if (info->config.debug_state == HEALTH_DEBUG_DONT_STOP_ON_FATAL) {
            goto schedule_next_cycle;
        }

        goto out;
    }

schedule_next_cycle:
    __remove_old_issues(info);
    queue_delayed_work(__health_check_wq, &info->main_health_check_dwork, info->config.periodic_time * HZ);

out:
    mutex_unlock(&info->lock);
}

static int __sx_health_send_mfgd(struct sx_dev                 *dev,
                                 bool                           enable,
                                 bool                           fatal_error_mode_active,
                                 sxd_mfgd_fw_fatal_event_test_t fw_fatal_event_test,
                                 struct ku_mfgd_reg            *active_mfgd)
{
    struct ku_access_mfgd_reg reg_mfgd;
    int                       err = 0;

    memset(&reg_mfgd, 0, sizeof(reg_mfgd));
    /*get sdk_fatal_error_mode to determine which state to set fw_fatal_mode*/
    err = __read_write_mfgd(&reg_mfgd, dev, EMAD_METHOD_QUERY);
    if (err) {
        sxd_log_err("Health-Check: Failed to read MFGD %u\n", dev->device_id);
        goto out;
    }
    /*"Get should have handled this, set the "1" defaults or all hell breaks loose */
    /*    reg_mfgd.fw_dci_rif_cache = true; */
    /*    reg_mfgd.fw_dci_en = true; */
    /*    reg_mfgd.fw_kvc_en = true; */
    /*    reg_mfgd.atcam_bf_en = true; */
    /*    reg_mfgd.egress_en = 0xFF; */
    /*  */
    if (enable) {
        reg_mfgd.mfgd_reg.fw_fatal_event_mode =
            (fatal_error_mode_active) ? SXD_MFGD_FW_FATAL_EVENT_MODE_CHECK_FW_FATAL_STOP_FW_E :
            SXD_MFGD_FW_FATAL_EVENT_MODE_CHECK_FW_FATAL_E;
        reg_mfgd.mfgd_reg.en_debug_assert = (fatal_error_mode_active) ? 1 : 0;
    } else {/*disable */
        reg_mfgd.mfgd_reg.fw_fatal_event_mode = SXD_MFGD_FW_FATAL_EVENT_MODE_DONT_CHECK_FW_FATAL_E;
        reg_mfgd.mfgd_reg.en_debug_assert = false;
    }
    reg_mfgd.mfgd_reg.fw_fatal_event_test = fw_fatal_event_test;

    sxd_log_notice("Health-Check: FW long-command timeout setting is %u seconds\n",
                   reg_mfgd.mfgd_reg.long_cmd_timeout_value);

    err = __read_write_mfgd(&reg_mfgd, dev, EMAD_METHOD_WRITE);
    if (err) {
        sxd_log_err("Health-Check: Failed to write MFGD %u\n", dev->device_id);
        goto out;
    }

    if (active_mfgd) {
        memcpy(active_mfgd, &reg_mfgd.mfgd_reg, sizeof(*active_mfgd));
    }

out:
    return err;
}

/* must be called within the health-check lock */
static int __info_alloc(u8                          dev_id,
                        sampling_params_t         * params,
                        struct sx_health_dev_info **ret_info,
                        bool                        fatal_error_mode_active)
{
    struct sx_dev             *dev = NULL;
    struct sx_priv            *priv = NULL;
    struct sx_health_dev_info *info = NULL;
    resource_size_t            catas_start = 0;
    u32 __iomem               *catas_iomap = NULL;
    int                        err = 0;
    uint32_t                   dq_id = 0;
    uint32_t                   thread_index = 0;
    unsigned long              flags;
    unsigned long              hw_groups_curr_status;
    struct ku_access_meccc_reg reg_meccc;


    dev = sx_dev_db_get_dev_by_id(dev_id);
    if (!dev) {
        sxd_log_err("Health-Check:failed to get device from id (id=%u)\n", dev_id);
        err = -ENODEV;
        goto out;
    }

    priv = sx_priv(dev);

    if (priv->fw.catas_size > 0) {
        catas_start = pci_resource_start(dev->pdev, priv->fw.catas_bar) + priv->fw.catas_offset;
        catas_iomap = ioremap(catas_start, priv->fw.catas_size * 4);
        if (!catas_iomap) {
            sxd_log_err("Health-Check:failed to map internal error buffer on device %u at 0x%llx\n",
                        dev->device_id,
                        catas_start);
            err = -ENOMEM;
            goto out;
        }
    }

    info = kzalloc(sizeof(struct sx_health_dev_info), GFP_KERNEL);
    if (!info) {
        sxd_log_err("Health-Check:could not create a new health-check entry for device %u\n", dev->device_id);
        err = -ENOMEM;
        goto out;
    }

    info->dev = dev;
    info->catas_iomap = catas_iomap;
    info->fatal_cause = SXD_HEALTH_CAUSE_NONE;
    info->config.debug_state = HEALTH_DEBUG_NORMAL;
    info->issu_on = params->issu_on;
    if (info->issu_on) {
        info->issu_signal_done = true;
    }

    INIT_DELAYED_WORK(&info->main_health_check_dwork, __sx_health_check_cycle);
    INIT_LIST_HEAD(&info->dev_list);
    INIT_LIST_HEAD(&info->issues_list);
    INIT_LIST_HEAD(&info->issues_history);
    info->history_size = 0;

    mutex_init(&info->lock);
    sx_bitmap_init(&info->config.last_rdq_bitmap, NUMBER_OF_RDQS);
    sx_bitmap_init(&info->config.sdq.sdq_bitmap, NUMBER_OF_SDQS);
    sx_bitmap_init(&info->config.rdq_bitmap, NUMBER_OF_RDQS);
    sx_bitmap_init(&info->config.ignore_rdq_bitmap, NUMBER_OF_RDQS);
    memset(&info->config.sdk_thread_info, 0, sizeof(info->config.sdk_thread_info));

    sx_bitmap_init(&info->config.sdk_thread_info.running_bitmap, SDK_THREAD_MONITOR_BITMAP_SIZE);
    sx_bitmap_init(&info->config.sdk_thread_info.last_sent_bitmap, SDK_THREAD_MONITOR_BITMAP_SIZE);

    /* set SDK threads that was operate in the last iteration of health check . all the changes that occurred during health check
     * was disabled exist in the user space and will update this table */
    for (thread_index = 0; thread_index < NUM_OF_SDK_THREADS_MAP_BY_BITS; thread_index++) {
        /* if SDK thread exist/in use */
        if (priv->prev_sdk_thread_status_arr[thread_index].thread_id) {
            memcpy(&info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index],
                   &priv->prev_sdk_thread_status_arr[thread_index], sizeof(ku_thread_status_changed_t));
            info->config.sdk_thread_info.sdk_thread_monitor_cnt++;
            info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].last_update_time = jiffies;
        }
    }
    info->config.thread_monitoring_status = THREAD_MONITOR_ACTIVE_E;

    /* set SDQ's that are operate */
    for (dq_id = 0; dq_id < priv->dev_cap.max_num_sdqs; dq_id++) {
        /* if SDQ exist/in use */
        if (priv->sdq_table.dq[dq_id]) {
            sx_bitmap_set(&info->config.sdq.sdq_bitmap, dq_id);
        }
    }

    info->config.periodic_time = params->check_interval;
    info->config.failures_num = params->alert_threshold;
    info->config.sdq.max_iter_allowed = __sx_sdq_calc_num_of_check_iter(info->config.periodic_time);
    info->config.min_severity = params->min_severity;
    info->long_command_detected = false;
    info->long_command_event_counter = 0;
#ifdef PD_BU
    info->config.sdk_thread_info.mult_threshold_time = 1000; /*For PLD thread monitor timeout increase */
#else
    info->config.sdk_thread_info.mult_threshold_time = 1; /* Default in case no need to extend the threshold time*/
    info->config.sdk_thread_info.new_debug_time_for_thread_monitor = 0; /* Default in case no need to extend the threshold time*/
    #endif
    hw_groups_curr_status = params->hw_groups_curr_status;
    /* fill the rdq_bitmap with the hw_traps that exist before starting this feature */
    for (dq_id = 0; dq_id < priv->dev_cap.max_num_rdqs; dq_id++) {
        if (test_bit(dq_id, &hw_groups_curr_status)) {
            sx_bitmap_set(&info->config.rdq_bitmap, dq_id);
        }
    }
    info->health_check_first_itr_skip_checks_func = true;
    info->fatal_error_mode_active = fatal_error_mode_active;
    info->checks_bitmap = SX_HC_BIT(SX_HC_DEV_CHECK_LAST) - 1; /* default: all checks */

    switch (priv->dev_info.dev_info_ro.chip_type) {
    case SXD_CHIP_TYPE_SPECTRUM:
    case SXD_CHIP_TYPE_SPECTRUM2:
    case SXD_CHIP_TYPE_SPECTRUM3:
    case SXD_CHIP_TYPE_SPECTRUM4:
    case SXD_CHIP_TYPE_SPECTRUM5:
        memset(&reg_meccc, 0, sizeof(reg_meccc));

        /* Currently only device_index 0 and slot_index 0 is supported for MECCC ,see more details where sxd_mgmt_ecc_stats defined*/
        reg_meccc.meccc_reg.device_index = 0;
        reg_meccc.meccc_reg.slot_index = 0;

        err = __read_meccc_and_update_ecc_stas(&reg_meccc, info, "Read ecc counters");
        if (err) {
            goto out;
        }

        break;

    default:
        break;
    }

    err = __sx_health_send_mfgd(dev,
                                true,
                                fatal_error_mode_active,
                                SXD_MFGD_FW_FATAL_EVENT_TEST_DONT_TEST_E,
                                &info->active_mfgd);
    if (err) {
        goto out;
    }

    /* fill the ignore_bitmap with the WJH hw_traps that exist before starting this feature */
    /* must lock set_monitor_rdq_lock first to avoid update of new RDQ WJH in parallel
     * set_monitor_rdq_lock is locked in higher stage (under fun sx_health_check_configure) */
    spin_lock_irqsave(&priv->rdq_table.lock, flags);
    for (dq_id = 0; dq_id < priv->monitor_rdqs_count; dq_id++) {
        sx_bitmap_set(&info->config.ignore_rdq_bitmap, priv->monitor_rdqs_arr[dq_id]);
    }
    spin_unlock_irqrestore(&priv->rdq_table.lock, flags);

    list_add_tail(&info->dev_list, &__dev_info_list);
    *ret_info = info;

out:
    return err;
}

/* must be called within the health-check lock */
static void __info_dealloc(struct sx_health_dev_info *info)
{
    struct issue_info *iter = NULL, *tmp = NULL;
    int                err = 0;
    uint32_t           thread_index = 0;
    struct sx_priv    *priv = sx_priv(info->dev);

    sxd_log_info("Health-Check: disabling monitoring on device %d\n", info->dev->device_id);

    mutex_lock(&info->lock);
    info->disabled = true;
    err = __sx_health_send_mfgd(info->dev,
                                false,
                                info->fatal_error_mode_active,
                                SXD_MFGD_FW_FATAL_EVENT_TEST_DONT_TEST_E,
                                NULL);
    if (err) {
        sxd_log_info("Health-Check: failed to disable FW event monitoring (MFGD) on device %d\n",
                     info->dev->device_id);
    }

    /*Clear the sdk thread status DB in the priv and save all the threads that was activated
     * under info for next iteration of enabling the health check  */
    memset(&priv->prev_sdk_thread_status_arr, 0,
           sizeof(priv->prev_sdk_thread_status_arr[0]) * NUM_OF_SDK_THREADS_MAP_BY_BITS);

    for (thread_index = 0; thread_index < NUM_OF_SDK_THREADS_MAP_BY_BITS; thread_index++) {
        /* if SDK thread exist/in use */
        if (info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].thread_id) {
            memcpy(&priv->prev_sdk_thread_status_arr[thread_index],
                   &info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index],
                   sizeof(ku_thread_status_changed_t));
        }
    }


    info->config.sdk_thread_info.sdk_thread_monitor_cnt = 0;
    __kernel_thread_monitor_cnt = 0;
    /* clear all debug triggers */
    __health_check_ts_trigger = false;
    priv->health_check.debug_trigger_state.catas = false;
    priv->health_check.debug_trigger_state.cmd_ifc = false;
    sx_bitmap_clear_all(&priv->health_check.debug_trigger_state.sdq_bitmap);
    sx_bitmap_clear_all(&priv->health_check.debug_trigger_state.rdq_bitmap);
    __health_check_wq_threads_trigger = false;

    list_del(&info->dev_list);

    list_for_each_entry_safe(iter, tmp, &info->issues_list, list) {
        list_del(&iter->list);
        kfree(iter);
    }

    list_for_each_entry_safe(iter, tmp, &info->issues_history, list) {
        list_del(&iter->list);
        kfree(iter);
    }

    iounmap(info->catas_iomap);
    info->catas_iomap = NULL;
    mutex_unlock(&info->lock);

    /* the work we're about to cancel only uses 'info->lock' so it is safe to cancel it
     * synchronously inside the '__health_check_lock' lock. */
    cancel_delayed_work_sync(&info->main_health_check_dwork);
    kfree(info);
}

static void __sx_health_check_update_timestamp(struct work_struct *work)
{
    mutex_lock(&__health_check_lock);

    if (!__health_check_ts_trigger) {
        __health_check_ts++;
        __health_check_ts_jiffies = jiffies;
    }

    if (__health_check_wq) {
        queue_delayed_work(__health_check_wq, &__health_check_ts_work, HZ); /* 1 second */
    }

    mutex_unlock(&__health_check_lock);
}

/* Adding Dwork for each work queue that exist in health check kernel list*/
static void __start_kernel_threads_monitor(void)
{
    struct health_check_kernel_thread_t *iter_thread = NULL;

    list_for_each_entry(iter_thread, &__kernel_thread_list, list) {
        iter_thread->old_counter = iter_thread->new_counter;
        queue_delayed_work(iter_thread->wq, &iter_thread->kernel_wq_increase_cnt_dwork, 0); /* now */
    }
}

static void __check_kernel_threads_monitor(void)
{
    struct health_check_kernel_thread_t *iter_thread = NULL;

    if (!(__global_checks_bitmap & SX_HC_BIT(SX_HC_GLOBAL_CHECK_KERNEL_THREADS))) {
        return;
    }

    list_for_each_entry(iter_thread, &__kernel_thread_list, list) {
        if (!(iter_thread->new_counter > iter_thread->old_counter)) {
            /* If we have monitored devices report on the failure to all of them */
            __add_issue_to_all_devices(SXD_HEALTH_SEVERITY_WARN,
                                       SXD_HEALTH_CAUSE_KERNEL_THREADS,
                                       DBG_ALL_IRISCS,
                                       iter_thread->name);
            break;
        }
    }
}

static void __sx_health_kernel_workqueue_monitor(struct work_struct *work)
{
    /*
     * LOCKS must be in this order:
     * health-check lock
     * threads monitor lock
     * dev-info lock
     */

    mutex_lock(&__health_check_lock);
    mutex_lock(&__kthreads_monitor_lock);

    if (!list_empty(&__dev_info_list)) {
        if (__is_first_iteration_of_kernel_wq_monitor_s) {
            __is_first_iteration_of_kernel_wq_monitor_s = false;
            /*Skip the first check because nothing sent to the kernel WQ's*/
        } else {
            __check_kernel_threads_monitor();
        }

        __start_kernel_threads_monitor();
        queue_delayed_work(__health_check_wq, &__kernel_workqueue_monitor_dwork, HZ);/* every second */
    }

    mutex_unlock(&__kthreads_monitor_lock);
    mutex_unlock(&__health_check_lock);
}

static void __sx_health_inc_wq_thread_counter(struct work_struct *work)
{
    struct health_check_kernel_thread_t *iter_thread;

    iter_thread = container_of(work, struct health_check_kernel_thread_t,
                               kernel_wq_increase_cnt_dwork.work);
    mutex_lock(&__kthreads_monitor_lock);

    if (iter_thread == NULL) {
        sxd_log_err("Health-Check: kernel thread %s not existing in the "
                    "kernel threads list anymore and counter didn't change"
                    "new counter = %llu \n", iter_thread->name, iter_thread->new_counter);
    } else {
        if (__health_check_wq_threads_trigger) {
            if (strcmp(iter_thread->name, __wq_thread_name_trigger) == 0) {
                goto out;
            } else {
                iter_thread->new_counter++;
            }
        } else {
            iter_thread->new_counter++;
        }
    }
out:
    mutex_unlock(&__kthreads_monitor_lock);
}

void sx_health_check_destroy_monitored_workqueue(struct workqueue_struct * workqueue)
{
    struct health_check_kernel_thread_t *iter_thread, *tmp = NULL;
    bool                                 wq_found_in_list = false;

    mutex_lock(&__kthreads_monitor_lock);
    list_for_each_entry_safe(iter_thread, tmp, &__kernel_thread_list, list) {
        if (workqueue == iter_thread->wq) {
            kfree(iter_thread->name);
            list_del(&iter_thread->list);
            kfree(iter_thread);
            __kernel_thread_monitor_cnt--;
            wq_found_in_list = true;
            break;
        }
    }
    if (!wq_found_in_list) {
        sxd_log_err("Health-Check: kernel thread %s not existing in the "
                    "kernel threads list anymore so its not removed from the "
                    "list \n", iter_thread->name);
    }

    mutex_unlock(&__kthreads_monitor_lock);
    destroy_workqueue(workqueue);
}

EXPORT_SYMBOL(sx_health_check_destroy_monitored_workqueue); /*to be access to other drivers e.g BFD */

struct workqueue_struct* sx_health_check_create_monitored_workqueue(const char* name)
{
    struct health_check_kernel_thread_t *new_kernel_thread = NULL;

    mutex_lock(&__kthreads_monitor_lock);

    new_kernel_thread = kzalloc(sizeof(struct health_check_kernel_thread_t), GFP_KERNEL);

    if (new_kernel_thread == NULL) {
        sxd_log_err("Health-Check:couldn't allocate new_kernel_thread node\n");
        goto out;
    }
    INIT_LIST_HEAD(&new_kernel_thread->list);
    INIT_DELAYED_WORK(&new_kernel_thread->kernel_wq_increase_cnt_dwork,  __sx_health_inc_wq_thread_counter);

    new_kernel_thread->jiffies = jiffies;
    new_kernel_thread->name = kstrdup(name, GFP_KERNEL);
    if (new_kernel_thread->name == NULL) {
        sxd_log_err("Health-Check:allocate thread name %s for new_kernel_thread failed\n", name);
        kfree(new_kernel_thread);
        new_kernel_thread = NULL;
        goto out;
    }
    new_kernel_thread->wq = create_singlethread_workqueue(name);
    if (!new_kernel_thread->wq) {
        sxd_log_err("Health-Check: Failed to create wq %s. \n", name);
        kfree(new_kernel_thread->name);
        kfree(new_kernel_thread);
        new_kernel_thread = NULL;
        goto out;
    }
    list_add_tail(&new_kernel_thread->list, &__kernel_thread_list);
    __kernel_thread_monitor_cnt++;
out:
    mutex_unlock(&__kthreads_monitor_lock);
    return new_kernel_thread ? new_kernel_thread->wq : NULL;
}
EXPORT_SYMBOL(sx_health_check_create_monitored_workqueue); /*to be access to other drivers e.g BFD */

static int __sx_health_add_device(u8 dev_id, sampling_params_t * params, bool fatal_error_mode_active)
{
    struct sx_health_dev_info *info = NULL;
    int                        err = 0;
    bool                       is_first_time_device_with_health_check = false;

    if (list_empty(&__dev_info_list)) {
        is_first_time_device_with_health_check = true;
    }

    info = __info_find(dev_id);
    if (!info) {
        err = __info_alloc(dev_id,
                           params,
                           &info,
                           fatal_error_mode_active);
    } else {
        err = -EEXIST;
    }

    if (!err) {
        if (is_first_time_device_with_health_check) {
            __is_first_iteration_of_kernel_wq_monitor_s = true;
            queue_delayed_work(__health_check_wq, &__kernel_workqueue_monitor_dwork, 0); /* now */
        }
        queue_delayed_work(__health_check_wq, &info->main_health_check_dwork, 0); /* now */
    }

    return err;
}

static void __sx_health_delete_device(u8 dev_id)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (info) {
        __info_dealloc(info);
    }
}

int __sx_health_update_tg_locked(u8 dev_id, int hw_trap_group, bool is_add, bool is_wjh_rdq_update)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (!info) {
        sxd_log_info("Health-Check: failed to update tg WJH because health "
                     "check not enable yet on device %u\n", dev_id);
        return -ENODEV;
    }

    mutex_lock(&info->lock);

    if (is_add) {
        if (is_wjh_rdq_update) {
            sxd_log_info("Health-Check: Add RDQ WJH %d to ignore list on device %u\n",
                         hw_trap_group,
                         dev_id);
            sx_bitmap_set(&info->config.ignore_rdq_bitmap, hw_trap_group);
            /*in case of create new WJH RDQ must to update the subset bitmap
             *  as well(last_rdq_bitmap) to avoid a race when comparing
             *  to operation rdq bitmap */
            sx_bitmap_free(&info->config.last_rdq_bitmap, hw_trap_group);
        } else {
            sx_bitmap_set(&info->config.rdq_bitmap, hw_trap_group);
        }
    } else {
        if (is_wjh_rdq_update) {
            sxd_log_info("Health-Check: Delete RDQ WJH %d from ignore list on device %u\n",
                         hw_trap_group,
                         dev_id);
            sx_bitmap_free(&info->config.ignore_rdq_bitmap, hw_trap_group);
        } else {
            sx_bitmap_free(&info->config.rdq_bitmap, hw_trap_group);
            /*in case of deletion must to update the subset bitmap
             *  as well(last_rdq_bitmap) to avoid a race when comparing
             *  to operation rdq bitmap */
            sx_bitmap_free(&info->config.last_rdq_bitmap, hw_trap_group);
        }
    }

    mutex_unlock(&info->lock);
    return 0;
}

int sx_health_update_tg(u8 dev_id, int hw_trap_group, bool is_add, bool is_wjh_rdq_update)
{
    int ret = 0;

    mutex_lock(&__health_check_lock);

    if (!__health_check_wq) {
        ret = -ENOENT;
        goto unlock;
    }

    ret = __sx_health_update_tg_locked(dev_id, hw_trap_group, is_add, is_wjh_rdq_update);

unlock:
    mutex_unlock(&__health_check_lock);
    return ret;
}

static int __sx_health_update_sampling_params(u8                    dev_id,
                                              uint32_t              check_interval,
                                              uint32_t              alert_threshold,
                                              sxd_health_severity_t min_severity)
{
    struct sx_health_dev_info *info = NULL;

    info = __info_find(dev_id);
    if (!info) {
        return -ENODEV;
    }

    mutex_lock(&info->lock);

    info->config.periodic_time = check_interval;
    info->config.failures_num = alert_threshold;
    info->config.min_severity = min_severity;
    info->config.sdq.max_iter_allowed = __sx_sdq_calc_num_of_check_iter(info->config.periodic_time);

    mutex_unlock(&info->lock);
    return 0;
}

int sx_health_check_dev_init(struct sx_dev *dev)
{
    struct sx_priv *priv = sx_priv(dev);
    int             ret = 0;

    ret = sx_bitmap_init(&priv->health_check.debug_trigger_state.sdq_bitmap, NUMBER_OF_SDQS);
    if (ret) {
        sxd_log_err("Health-Check: Failed to initialize SDQs debug trigger bitmap, aborting.\n");
        goto out;
    }

    ret = sx_bitmap_init(&priv->health_check.debug_trigger_state.rdq_bitmap, NUMBER_OF_RDQS);
    if (ret) {
        sxd_log_err("Health-Check: Failed to initialize RDQs debug trigger bitmap, aborting.\n");
        goto out;
    }
    ret = sx_bitmap_init(&priv->health_check.operational_state.sdq_bitmap, NUMBER_OF_SDQS);
    if (ret) {
        sxd_log_err("Health-Check: Failed to initialize operational SDQs debug trigger bitmap, aborting.\n");
        goto out;
    }

    ret = sx_bitmap_init(&priv->health_check.operational_state.rdq_bitmap, NUMBER_OF_RDQS);
    if (ret) {
        sxd_log_err("Health-Check: Failed to initialize operational SDQs debug trigger bitmap, aborting.\n");
        goto out;
    }

    priv->health_check.operational_state.catas = false;
    priv->health_check.operational_state.cmd_ifc = false;
    priv->health_check.debug_trigger_state.cmd_ifc = false;
    priv->health_check.debug_trigger_state.catas = false;

out:
    return ret;
}

bool sx_health_check_dev_deinit(struct sx_dev *dev, void *context)
{
    bool cancel_workqueue_monitor = false;

    mutex_lock(&__health_check_lock);

    if (!__health_check_wq) { /* trying to delete a device while feature is disabled ... */
        goto unlock;
    }

    __sx_health_delete_device(dev->device_id);

    /* if no more devices requires health check monitor, delete __kernel_workqueue_monitor_dwork */
    if (list_empty(&__dev_info_list)) {
        cancel_workqueue_monitor = true;
    }

unlock:
    mutex_unlock(&__health_check_lock);

    if (cancel_workqueue_monitor) {
        cancel_delayed_work_sync(&__kernel_workqueue_monitor_dwork);
    }

    return true;
}

static int __health_check_dbg_handle_stop(int argc, const char *argv[], void *context)
{
    struct sx_health_dev_info *info = NULL;
    int                        err = 0;
    int                        dev_id;

    /* argv[2] is dev_id */
    err = kstrtoint(argv[2], 10, &dev_id);
    if (err) {
        sxd_log_notice("Health-Check: debug command 'stop' - invalid device ID\n");
        return -EINVAL;
    }

    mutex_lock(&__health_check_lock);

    info = __info_find(dev_id);
    if (!info) {
        sxd_log_notice("Health-Check: debug command 'stop' - device %d not found\n", dev_id);
        err = -ENODEV;
        goto out;
    }

    sxd_log_notice("Health-Check: debug command 'stop' for device %d\n", dev_id);
    __info_dealloc(info);

out:
    mutex_unlock(&__health_check_lock);
    return err;
}

static int __health_check_dbg_handle_set_debug_state(int                     argc,
                                                     const char             *argv[],
                                                     void                   *context,
                                                     enum health_debug_state ds)
{
    struct sx_health_dev_info *info = NULL;
    int                        err = 0;
    int                        dev_id;

    /* argv[2] is dev_id */
    err = kstrtoint(argv[2], 10, &dev_id);
    if (err) {
        sxd_log_notice("Health-Check: debug command 'set_debug_state' - invalid device ID\n");
        return -EINVAL;
    }

    mutex_lock(&__health_check_lock);

    info = __info_find(dev_id);
    if (!info) {
        sxd_log_notice("Health-Check: debug command 'set_debug_state' - device %d not found\n", dev_id);
        err = -ENODEV;
        goto out;
    }

    mutex_lock(&info->lock);

    switch (ds) {
    case HEALTH_DEBUG_MUTE:
        sxd_log_notice("Health-Check: debug command 'set_debug_state' to MUTE for device %d\n", dev_id);
        break;

    case HEALTH_DEBUG_NORMAL:
        sxd_log_notice("Health-Check: debug command 'set_debug_state' to NORMAL for device %d\n", dev_id);
        break;

    case HEALTH_DEBUG_DONT_STOP_ON_FATAL:
        sxd_log_notice("Health-Check: debug command 'set_debug_state' to DO_NOT_STOP_ON_FATAL for device %d\n",
                       dev_id);
        break;

    default:
        sxd_log_notice("Health-Check: debug command 'set_debug_state' - invalid state\n");
        err = -EINVAL;
        goto out_unlock_info;
    }

    info->config.debug_state = ds;

out_unlock_info:
    mutex_unlock(&info->lock);

out:
    mutex_unlock(&__health_check_lock);
    return err;
}

static int __health_check_dbg_handle_dev_checks(int argc, const char *argv[], void *context, bool is_set)
{
    struct sx_health_dev_info *info = NULL;
    const char                *cmd = (is_set) ? "set_dev_checks" : "unset_dev_checks";
    int                        err = 0;
    int                        dev_id, checks_bitmap;

    /* argv[2] is dev_id */
    err = kstrtoint(argv[2], 10, &dev_id);
    if (err) {
        sxd_log_notice("Health-Check: debug command '%s' - invalid device ID\n", cmd);
        return -EINVAL;
    }

    /* argv[3] is checks_bitmap */
    err = kstrtoint(argv[3], 16, &checks_bitmap);
    if (err) {
        sxd_log_notice("Health-Check: debug command '%s' - failed to parse checks-bitmap\n", cmd);
        return -EINVAL;
    }

    if (checks_bitmap >= SX_HC_BIT(SX_HC_DEV_CHECK_LAST)) {
        sxd_log_notice("Health-Check: debug command '%s' - invalid bitmap\n", cmd);
        return -EINVAL;
    }

    mutex_lock(&__health_check_lock);

    info = __info_find(dev_id);
    if (!info) {
        sxd_log_notice("Health-Check: debug command '%s' - device %d not found\n", cmd, dev_id);
        err = -ENODEV;
        goto out;
    }

    sxd_log_notice("Health-Check: debug command '%s' for device %d with checks bitmap 0x%08x\n",
                   cmd,
                   dev_id,
                   checks_bitmap);
    mutex_lock(&info->lock);

    if (is_set) {
        info->checks_bitmap |= checks_bitmap;
    } else {
        info->checks_bitmap &= ~checks_bitmap;
    }

    mutex_unlock(&info->lock);

out:
    mutex_unlock(&__health_check_lock);
    return err;
}

static int __health_check_dbg_handle_global_checks(int argc, const char *argv[], void *context, bool is_set)
{
    const char *cmd = (is_set) ? "set_global_checks" : "unset_global_checks";
    int         err = 0;
    int         checks_bitmap;

    /* argv[2] is checks_bitmap */
    err = kstrtoint(argv[2], 16, &checks_bitmap);
    if (err) {
        sxd_log_notice("Health-Check: debug command '%s' - failed to parse checks-bitmap\n", cmd);
        return -EINVAL;
    }

    if (checks_bitmap >= SX_HC_BIT(SX_HC_GLOBAL_CHECK_LAST)) {
        sxd_log_notice("Health-Check: debug command '%s' - invalid bitmap\n", cmd);
        return -EINVAL;
    }

    mutex_lock(&__health_check_lock);

    sxd_log_notice("Health-Check: debug command '%s' with checks bitmap 0x%08x\n", cmd, checks_bitmap);
    if (is_set) {
        __global_checks_bitmap |= checks_bitmap;
    } else {
        __global_checks_bitmap &= ~checks_bitmap;
    }

    mutex_unlock(&__health_check_lock);
    return err;
}

int sx_health_check_dbg_cmd_handler(int argc, const char *argv[], void *context)
{
    int err = 0;

    if (argc < 3) {
        sxd_log_notice("Health-Check: debug command - invalid number of arguments\n");
        return -EINVAL;
    }

    /* argv[1] is the command */
    if (strcmp(argv[1], "stop") == 0) {
        err = __health_check_dbg_handle_stop(argc, argv, context);
    } else if (strcmp(argv[1], "mute") == 0) {
        err = __health_check_dbg_handle_set_debug_state(argc, argv, context, HEALTH_DEBUG_MUTE);
    } else if (strcmp(argv[1], "dont_stop_on_fatal") == 0) {
        err = __health_check_dbg_handle_set_debug_state(argc, argv, context, HEALTH_DEBUG_DONT_STOP_ON_FATAL);
    } else if (strcmp(argv[1], "normal") == 0) {
        err = __health_check_dbg_handle_set_debug_state(argc, argv, context, HEALTH_DEBUG_NORMAL);
    } else if (strcmp(argv[1], "set_dev_checks") == 0) {
        err = __health_check_dbg_handle_dev_checks(argc, argv, context, true);
    } else if (strcmp(argv[1], "unset_dev_checks") == 0) {
        err = __health_check_dbg_handle_dev_checks(argc, argv, context, false);
    } else if (strcmp(argv[1], "set_global_checks") == 0) {
        err = __health_check_dbg_handle_global_checks(argc, argv, context, true);
    } else if (strcmp(argv[1], "unset_global_checks") == 0) {
        err = __health_check_dbg_handle_global_checks(argc, argv, context, false);
    } else {
        sxd_log_notice("Health-Check: debug command - invalid command [%s]\n", argv[1]);
        return -EINVAL;
    }

    return err;
}

int sx_health_check_init(void)
{
    int err = 0;

    sxd_log_info("Health-Check: initialization\n");

    mutex_lock(&__health_check_lock);
    if (__health_check_wq) {
        err = -EEXIST;
        goto out;
    }

    __health_check_wq = create_singlethread_workqueue("sx_health_check");
    if (!__health_check_wq) {
        err = -ENOMEM;
        goto out;
    }
    /* Create the sysfs of the running counter under sys/module/sx_core/health_check_running_counter */
    err = sysfs_create_file(&(THIS_MODULE->mkobj.kobj), &(__health_check_running_counter_attr.attr));

    if (err) {
        sxd_log_err("Health-Check: failed to create sysfs entry (err=%d)\n", err);
        goto out;
    }

    INIT_DELAYED_WORK(&__health_check_ts_work, __sx_health_check_update_timestamp);
    INIT_DELAYED_WORK(&__kernel_workqueue_monitor_dwork,  __sx_health_kernel_workqueue_monitor);

    queue_delayed_work(__health_check_wq, &__health_check_ts_work, 0); /* now */
out:
    mutex_unlock(&__health_check_lock);
    return err;
}

int sx_health_check_deinit(void)
{
    struct workqueue_struct *hcwq = NULL;
    int                      err = 0;

    sxd_log_info("Health-Check: cleanup\n");

    mutex_lock(&__health_check_lock);

    if (!__health_check_wq) {
        sxd_log_err("Health-Check has not been started\n");
        err = -ENOENT;
        goto out;
    }

    if (!list_empty(&__dev_info_list)) {
        sxd_log_err("Health-Check: devices are still being monitored\n");
        err = -EBUSY;
        goto out;
    }

    hcwq = __health_check_wq; /* save a temporary copy */
    __health_check_wq = NULL; /* tell everyone that feature is now disabled! */

    sysfs_remove_file(&(THIS_MODULE->mkobj.kobj), &(__health_check_running_counter_attr.attr));

out:
    mutex_unlock(&__health_check_lock);

    if (hcwq) {
        cancel_delayed_work_sync(&__health_check_ts_work);
        destroy_workqueue(hcwq);
    }

    return err;
}

int sx_health_check_configure(ku_dbg_health_check_params_t *params)
{
    int               err = 0;
    struct completion cyc_finish_wq_completion;

    /* the order of locking must be  (from out side to inside)
     * 1)__set_monitor_rdq_lock
     * 2)__health_check_lock
     * 3)info->lock
     * */
    if (SXD_HEALTH_FATAL_FAILURE_ENABLE_E == params->sxd_health_fatal_failure_detect_cmd) {
        sx_set_monitor_rdq_lock();
    }
    mutex_lock(&__health_check_lock);

    if (!__health_check_wq) {
        sxd_log_err("Health-Check: feature is disabled\n");
        err = -ENOENT;
        goto unlock;
    }

    switch (params->sxd_health_fatal_failure_detect_cmd) {
    case SXD_HEALTH_FATAL_FAILURE_ENABLE_E:
        sxd_log_info("Health-Check: Enable device %u, issu_on %d\n",
                     params->dev_id,
                     params->params.sampling_params.issu_on);
        err = __sx_health_add_device(params->dev_id,
                                     &params->params.sampling_params,
                                     params->fatal_error_mode_active);
        break;

    case SXD_HEALTH_FATAL_FAILURE_DISABLE_E:
        sxd_log_info("Health-Check: Disable device %u\n", params->dev_id);
        __sx_health_delete_device(params->dev_id);
        break;

    case SXD_HEALTH_FATAL_FAILURE_ADD_TRAP_GROUP_E:
        sxd_log_debug("Health-Check: Add trap-group %d to device %u\n",
                      params->params.tg_params.hw_trap_group,
                      params->dev_id);
        /* When adding a monitor trap group, we need to first add it to ignore_rdq_bitmap, then add it to rdq_bitmap.
         *  Otherwise there will be a time window in which the HETT trap may arrive at the monitor RDQ. */
        if (params->params.tg_params.is_monitor) {
            err = __sx_health_update_tg_locked(params->dev_id,
                                               params->params.tg_params.hw_trap_group,
                                               true,
                                               true);
            if (err) {
                goto unlock;
            }
        }
        err = __sx_health_update_tg_locked(params->dev_id,
                                           params->params.tg_params.hw_trap_group,
                                           true,
                                           false);
        break;

    case SXD_HEALTH_FATAL_FAILURE_DELETE_TRAP_GROUP_E:
        sxd_log_debug("Health-Check: Delete trap-group %d from device %u\n",
                      params->params.tg_params.hw_trap_group,
                      params->dev_id);
        err = __sx_health_update_tg_locked(params->dev_id,
                                           params->params.tg_params.hw_trap_group,
                                           false,
                                           false);
        break;

    case SXD_HEALTH_FATAL_FAILURE_UPDATE_SAMPLE_PARAMS_E:
        sxd_log_debug(
            "Health-Check: Update sampling parameters for device %u (interval=%u, threshold=%u min_severity=%s)\n",
            params->dev_id,
            params->params.sampling_params.check_interval,
            params->params.sampling_params.alert_threshold,
            __severity_to_str(params->params.sampling_params.min_severity));

        err = __sx_health_update_sampling_params(params->dev_id,
                                                 params->params.sampling_params.check_interval,
                                                 params->params.sampling_params.alert_threshold,
                                                 params->params.sampling_params.min_severity);
        break;

    case SXD_HEALTH_FATAL_FAILURE_UPDATE_SDK_THREAD_MONITOR_E:
        err = __sx_health_update_sdk_thread_monitor(params->dev_id,
                                                    &params->params.sdk_threads_info.threads_monitor_info);
        break;

    case SXD_HEALTH_FATAL_FAILURE_UPDATE_SDK_THREAD_STATUS_CHANGED_E:
        sxd_log_info("Health-Check: Update SDK thread ('%s') status changed to '%s' on bit index %d for device %u \n",
                     params->params.sdk_threads_info.thread_status_changed.name,
                     params->params.sdk_threads_info.thread_status_changed.cmd ? "New thread" : "delete thread",
                     params->params.sdk_threads_info.thread_status_changed.bit_index,
                     params->dev_id);
        err = __sx_health_update_sdk_thread_status_changed(params->dev_id,
                                                           &params->params.sdk_threads_info.thread_status_changed);
        break;

    case SXD_HEALTH_FATAL_FAILURE_ADD_EMAD_TIMEOUT_FAILURE_E:
        sxd_log_info("Health-Check: Add timeout error for device %u \n", params->dev_id);
        sx_health_report_error_emad_timeout(params->dev_id,
                                            params->params.emad_timeout_info.reg_id,
                                            params->params.emad_timeout_info.usecs,
                                            "SXD_libs");
        break;

    case SXD_HEALTH_FATAL_FAILURE_ISSU_ON_E:
        sxd_log_info("Health-Check: Set ISSU on mode for device %u\n",  params->dev_id);
        err = __sx_health_set_issu_on(params->dev_id, &cyc_finish_wq_completion);
        break;

    case SXD_HEALTH_FATAL_FAILURE_ISSU_OFF_E:
        sxd_log_info("Health-Check: Set ISSU off mode for device %u\n",  params->dev_id);
        err = __sx_health_set_issu_off(params->dev_id);
        break;

    default:
        break;
    }

unlock:
    mutex_unlock(&__health_check_lock);
    if (SXD_HEALTH_FATAL_FAILURE_ENABLE_E == params->sxd_health_fatal_failure_detect_cmd) {
        sx_set_monitor_rdq_unlock();
    }
    if (SXD_HEALTH_FATAL_FAILURE_ISSU_ON_E == params->sxd_health_fatal_failure_detect_cmd) {
        /* Wait for check cycle to finish, after the cycle is done SDK can continue with the ISSU process. */
        wait_for_completion_interruptible(&cyc_finish_wq_completion);
    }
    if (err) {
        sxd_log_err("Health-Check: Operation failed (err=%d)\n", err);
    }

    return err;
}

void sx_health_check_report_dq_ok(struct sx_dev *dev, bool is_send, int dqn)
{
    struct sx_priv *priv = sx_priv(dev);

    if (is_send) {
        if (!sx_bitmap_test(&priv->health_check.debug_trigger_state.sdq_bitmap, dqn)) { /* debug trigger not set */
            sx_bitmap_set(&priv->health_check.operational_state.sdq_bitmap, dqn);
        }
    } else {
        if (!sx_bitmap_test(&priv->health_check.debug_trigger_state.rdq_bitmap, dqn)) { /* debug trigger not set */
            sx_bitmap_set(&priv->health_check.operational_state.rdq_bitmap, dqn);
        }
    }
}

static ssize_t __health_check_running_cntr_cb(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int len = 0;

    len = sprintf(buf, "%llu\n", __health_check_ts);
    return len;
}

static void __dump_bitmap(struct seq_file *m, void *v, void *context, struct sx_bitmap *bitmap)
{
    u32  i, max;
    int  rmin = -1, rmax = -1;
    bool found_bit, bit_test;

    max = sx_bitmap_num_bits(bitmap);
    found_bit = false;
    for (i = 0; i < max; i++) {
        bit_test = sx_bitmap_test(bitmap, i);
        if (bit_test) {
            found_bit = true;
            if (rmin == -1) {
                rmin = (int)i;
            }

            rmax = i;
        }

        if ((rmin != -1) && (!bit_test || (i == max - 1))) {
            if (rmin == rmax) {
                seq_printf(m, "%d, ", rmin);
            } else {
                seq_printf(m, "%d-%d, ", rmin, rmax);
            }

            rmin = -1;
            rmax = -1;
        }
    }

    if (!found_bit) {
        seq_printf(m, "None");
    }

    seq_printf(m, "\n");
}

static void __dump_issues_list(struct seq_file *m, struct list_head *list, const char *title, const bool *p_fatal)
{
    struct issue_info *failure;

    seq_printf(m, "    %s\n", title);
    seq_printf(m, "        %-8s    %-7s    %-30s    %s\n",
               "Severity", "Sec-Ago", "Cause", "Description");
    seq_printf(m, "        ==================================================================================\n");

    if (list_empty(list)) {
        seq_printf(m, "        No issues\n");
    } else {
        list_for_each_entry(failure, list, list) {
            seq_printf(m, "        %-8s    %-7u    %-30s    %s\n",
                       __severity_to_str(failure->severity),
                       (jiffies_to_msecs(jiffies - failure->jiffies) / 1000),
                       sxd_cause_type_str(failure->cause),
                       failure->err_msg);
        }
    }

    if (p_fatal && *p_fatal) {
        seq_printf(m, "        ***** Device is in fatal state! *****\n");
    }

    seq_printf(m, "\n");
}

static void __dump_info(struct seq_file *m, void *v, void *context, struct sx_health_dev_info *info)
{
    struct sx_priv                      *priv;
    struct health_check_kernel_thread_t *iter_thread = NULL;
    u32                                  thread_index = 0;
    bool                                 is_fatal = false;
    u32                                  long_cmd_val = 0;

    priv = sx_priv(info->dev);

    mutex_lock(&info->lock);

    is_fatal = (info->fatal_cause != SXD_HEALTH_CAUSE_NONE);

    seq_printf(m, "Device ID: %u\n", info->dev->device_id);
    seq_printf(m, "    Check Interval ................................... %u msec\n",
               (info->config.periodic_time * 1000));
    seq_printf(m, "    Alert Threshold .................................. %u failures\n",
               info->config.failures_num);
    seq_printf(m, "    Minimum Severity ................................. %s (%d)\n",
               __severity_to_str(info->config.min_severity),
               info->config.min_severity);
    seq_printf(m, "    Major issues detected ............................ %u\n", info->major_issues_detected);
    seq_printf(m, "    Minor issues detected ............................ %u\n", info->minor_issues_detected);
    seq_printf(m, "    Fatal detected ................................... %s\n", ((is_fatal) ? "Yes" : "No"));
    seq_printf(m, "    Fatal-Error-Mode enabled ......................... %s\n",
               (info->fatal_error_mode_active) ? "Yes" : "No");
    seq_printf(m, "    Running counter .................................. %llu\n", __health_check_ts);
    seq_printf(m, "    Last time running counter increased .............. %u msecs\n",
               (jiffies_to_msecs(jiffies - __health_check_ts_jiffies)));
    seq_printf(m, "    ISSU On .......................................... %s\n",
               (info->issu_on) ? "Yes" : "No");
    seq_printf(m, "    ISSU signal done ................................. %s\n",
               (info->issu_signal_done) ? "Yes" : "No");
    seq_printf(m, "    Debug state ...................................... %s\n",
               ((info->config.debug_state == HEALTH_DEBUG_NORMAL) ? "Normal" :
                (info->config.debug_state == HEALTH_DEBUG_MUTE) ? "Muting health events" :
                (info->config.debug_state == HEALTH_DEBUG_DONT_STOP_ON_FATAL) ? "Don't stop on fatal" :
                "N/A"));
    seq_printf(m, "    PCI profile set .................................. %s\n",
               ((priv->profile.pci_profile_set) ? "Yes" : "No"));

    seq_printf(m, "    Global checks bitmap ............................. 0x%08x\n", __global_checks_bitmap);
    seq_printf(m, "        [bits: " SX_GLOBAL_CHECKS "]\n");

    seq_printf(m, "    Per-dev checks bitmap ............................ 0x%08x\n", info->checks_bitmap);
    seq_printf(m, "        [bits: " SX_PER_DEV_CHECKS "]\n");
    seq_printf(m, "\n");

    seq_printf(m, "    MFGD\n");
    seq_printf(m, "        en_debug_assert .............................. %u\n",
               info->active_mfgd.en_debug_assert);
    seq_printf(m, "        fw_fatal_event_mode .......................... %u\n",
               info->active_mfgd.fw_fatal_event_mode);
    seq_printf(m, "        fw_fatal_event_test .......................... %u\n",
               info->active_mfgd.fw_fatal_event_test);
    seq_printf(m, "        long_cmd_timeout_value ....................... %u\n",
               info->active_mfgd.long_cmd_timeout_value);
    seq_printf(m, "        packet_state_test_action ..................... %u\n",
               info->active_mfgd.packet_state_test_action);
    seq_printf(m, "        packet_state_test_time_value ................. %u\n",
               info->active_mfgd.packet_state_test_time_value);
    seq_printf(m, "\n");

    seq_printf(m, "    ECC Counters\n");
    seq_printf(m, "        Correctable .................................. %u\n", info->ecc_stats.ecc_corrected);
    seq_printf(m, "        Uncorrectable ................................ %u\n", info->ecc_stats.ecc_uncorrected);
    seq_printf(m, "\n");

    seq_printf(m, "    CR-Space\n");
    if (info->catas_iomap) {
        seq_printf(m, "        CATAS value (@offset 0x%x) ............... 0x%08x (check bit %s)\n",
                   (u32)priv->fw.catas_offset,
                   swab32(__raw_readl(info->catas_iomap)),
                   ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_CATAS)) ? "enabled" : "disabled"));
    } else {
        seq_printf(m, "        CATAS value .............................. Not supported\n");
    }
    if (priv->fw.cr_dump_offset) {
        sx_dpt_cr_space_read(priv->dev.device_id, priv->fw.cr_dump_offset, (u8*)&long_cmd_val, sizeof(long_cmd_val));
        seq_printf(m, "        long-command value (@offset 0x%x) ........ 0x%08x\n",
                   (u32)priv->fw.cr_dump_offset,
                   be32_to_cpu(long_cmd_val));
    } else {
        seq_printf(m, "        long-command value ....................... Not supported\n");
    }
    seq_printf(m, "\n");

    seq_printf(m, "    SDQs (check bit %s)\n",
               ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_SDQ)) ? "enabled" : "disabled"));
    seq_printf(m, "        All .......................................... ");
    __dump_bitmap(m, v, context, &info->config.sdq.sdq_bitmap);
    seq_printf(m, "        Operational .................................. ");
    __dump_bitmap(m, v, context, &priv->health_check.operational_state.sdq_bitmap);
    seq_printf(m, "        Debug trigger ................................ ");
    __dump_bitmap(m, v, context, &priv->health_check.debug_trigger_state.sdq_bitmap);
    seq_printf(m, "        Max iterations allowed ....................... %u\n",
               info->config.sdq.max_iter_allowed);
    seq_printf(m, "        Current iteration ............................ %llu\n",
               info->config.sdq.num_of_check_iter);
    seq_printf(m, "\n");

    seq_printf(m, "    RDQs (check bit %s)\n",
               ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_RDQ)) ? "enabled" : "disabled"));
    seq_printf(m, "        All .......................................... ");
    __dump_bitmap(m, v, context, &info->config.rdq_bitmap);
    seq_printf(m, "        Ignored ...................................... ");
    __dump_bitmap(m, v, context, &info->config.ignore_rdq_bitmap);
    seq_printf(m, "        Monitored last cycle ......................... ");
    __dump_bitmap(m, v, context, &info->config.last_rdq_bitmap);
    seq_printf(m, "        Operational .................................. ");
    __dump_bitmap(m, v, context, &priv->health_check.operational_state.rdq_bitmap);
    seq_printf(m, "        Debug trigger ................................ ");
    __dump_bitmap(m, v, context, &priv->health_check.debug_trigger_state.rdq_bitmap);
    seq_printf(m, "\n");

    seq_printf(m, "    Command Interface (check bit %s)\n",
               ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_CMD_IFC)) ? "enabled" : "disabled"));
    seq_printf(m, "        Packets received ............................. %llu\n",
               priv->health_check.cmd_ifc_num_of_pck_received);
    seq_printf(m, "        Last packet sent via health-check ............ %s\n",
               (info->config.cmd_ifc.is_last_pkt_sent_via_health) ? "Yes" : "No");
    seq_printf(m, "        Previous cycle counter ....................... %llu\n",
               info->config.cmd_ifc.last_cmd_ifc_counter);
    seq_printf(m, "\n");

    seq_printf(m, "    Interrupt Handler (tasklet) (check bit %s)\n",
               ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_TASKLET)) ? "enabled" : "disabled"));
    seq_printf(m, "        start count .................................. %llu\n",
               priv->health_check.tasklet_start_cnt);
    seq_printf(m, "        end count .................................... %llu\n", priv->health_check.tasklet_end_cnt);
    seq_printf(m, "        max duration (msec) .......................... %u\n",
               jiffies_to_msecs(priv->health_check.tasklet_max_duration));
    if (priv->health_check.tasklet_start_cnt > priv->health_check.tasklet_end_cnt) {
        seq_printf(m, "        current duration (msec) ...................... %u\n",
                   jiffies_to_msecs(jiffies - priv->health_check.tasklet_last_start));
    } else {
        seq_printf(m, "        current duration (msec) ...................... Not running\n");
    }
    seq_printf(m, "\n");

    seq_printf(m, "    Kernel Threads (check bit %s)\n",
               ((__global_checks_bitmap & SX_HC_BIT(SX_HC_GLOBAL_CHECK_KERNEL_THREADS)) ? "enabled" : "disabled"));
    seq_printf(m, "        Operational .................................. %u\n",
               __kernel_thread_monitor_cnt);
    list_for_each_entry(iter_thread, &__kernel_thread_list, list) {
        seq_printf(m, "            %s \n", iter_thread->name);
    }
    seq_printf(m, "        Debug trigger ................................ %s\n",
               (__health_check_wq_threads_trigger ? "Yes" : "No"));
    if (__health_check_wq_threads_trigger) {
        seq_printf(m, "        Debug trigger thread ......................... %s\n",
                   __wq_thread_name_trigger);
    }
    seq_printf(m, "\n");

    seq_printf(m, "    SDK Threads (check bit %s)\n",
               ((info->checks_bitmap & SX_HC_BIT(SX_HC_DEV_CHECK_SDK_THREADS)) ? "enabled" : "disabled"));
    seq_printf(m, "       Main thread sdk_main_monitor_counter ...... [%llu]\n",
               info->config.sdk_thread_info.sdk_main_monitor_counter);
    seq_printf(m, "       Multiplied threshold time..................... %u\n",
               info->config.sdk_thread_info.mult_threshold_time);
    if (info->config.sdk_thread_info.new_debug_time_for_thread_monitor > 0) {
        seq_printf(m, "       New debug time is set for all threads monitor.. %u\n",
                   info->config.sdk_thread_info.new_debug_time_for_thread_monitor);
    }
    seq_printf(m, "       Operational .................................. %u\n",
               info->config.sdk_thread_info.sdk_thread_monitor_cnt);
    for (thread_index = 0; thread_index < NUM_OF_SDK_THREADS_MAP_BY_BITS; thread_index++) {
        if (info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].thread_id) {
            seq_printf(m,
                       "            %15s, bit_id [%2d], TID [%4llu], original threshold time [%4lu] sec, last response time [%2lu] sec, MUTED [%3s]\n",
                       info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].name,
                       info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].bit_index,
                       info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].thread_id,
                       info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].max_expected_thread_duration_sec,
                       info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].time_passed_from_last_update,
                       (info->config.sdk_thread_info.bit_to_thread_status_arr[thread_index].
                        max_expected_thread_duration_sec == -1) ? "YES" : "NO");
        }
    }
    seq_printf(m, "       Last sent bitmap .............................. ");
    __dump_bitmap(m, v, context, &info->config.sdk_thread_info.last_sent_bitmap);
    seq_printf(m, "       Running bitmap ................................ ");
    __dump_bitmap(m, v, context, &info->config.sdk_thread_info.running_bitmap);
    seq_printf(m, "\n");
    seq_printf(m, "       Thread monitor status ..........................%s \n",
               thread_monitor_status_str[info->config.thread_monitoring_status]);
    seq_printf(m, "\n");

    seq_printf(m, "\n");

    __dump_issues_list(m, &info->issues_list, "Current Issues", &is_fatal);
    __dump_issues_list(m, &info->issues_history, "History", NULL);

    mutex_unlock(&info->lock);
}

int sx_health_check_dump(struct seq_file *m, void *v, void *context)
{
    struct sx_health_dev_info *info;

    sx_dbg_dump_print_table_header(m, "Health-Check DUMP");

    mutex_lock(&__health_check_lock);

    list_for_each_entry(info, &__dev_info_list, dev_list) {
        __dump_info(m, v, context, info);
    }

    mutex_unlock(&__health_check_lock);
    return 0;
}

void sx_health_check_set_debug_trigger(struct sx_health_check_trigger_params *params)
{
    struct sx_health_dev_info           *info;
    struct sx_priv                      *priv = NULL;
    bool                                 is_wq_thread_name_found = false;
    struct health_check_kernel_thread_t *iter_thread = NULL;
    int                                  err = 0;
    sampling_params_t                    sampling_params;

    mutex_lock(&__health_check_lock);

    memset(&sampling_params, 0, sizeof(sampling_params));

    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_SYSFS) {
        sxd_log_notice("Health-Check: Trigger SYSFS failure\n");
        __health_check_ts_trigger = true;
        goto out;
    }

    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_ADD_DEV) {
        sxd_log_notice("Health-Check: Trigger Add-Device %u\n", params->dev_id);
        sampling_params.alert_threshold = DEFAULT_ALERT_THRESHOLD;
        sampling_params.check_interval = DEFAULT_CHECK_INTERVAL;
        sampling_params.min_severity = SXD_HEALTH_SEVERITY_FATAL;

        __sx_health_add_device(params->dev_id, &sampling_params, params->fatal_error_mode_active);
        goto out;
    }

    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_DEL_DEV) {
        sxd_log_notice("Health-Check: Trigger Del-Device %u\n", params->dev_id);
        __sx_health_delete_device(params->dev_id);
        goto out;
    }

    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_KERNEL_THREADS) {
        mutex_lock(&__kthreads_monitor_lock);
        list_for_each_entry(iter_thread, &__kernel_thread_list, list) {
            if (strcmp(params->params.kthread_params.name, iter_thread->name) == 0) {
                is_wq_thread_name_found = true;
                sxd_log_notice("Health-Check: Trigger kernel thread %s failure \n",
                               params->params.kthread_params.name);
                __health_check_wq_threads_trigger = true;
                strcpy(__wq_thread_name_trigger, params->params.kthread_params.name);
                break;
            }
        }
        mutex_unlock(&__kthreads_monitor_lock);

        if (is_wq_thread_name_found == false) {
            sxd_log_err("Health-Check: Trigger kernel thread %s not "
                        "part of the existing in the list of monitored wq kernel threads \n",
                        params->params.kthread_params.name);
        }
        goto out;
    }
    info = __info_find(params->dev_id);
    if (!info) {
        sxd_log_err("Health-Check: device %u is not monitored\n", params->dev_id);
        goto out;
    }

    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_FATAL_EVENT_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_FATAL_EVENT_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_FW_FATAL_EVENT_E,
                                    &info->active_mfgd);
        goto out;
    }
    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_CAUSE_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_CAUSE_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_FATAL_CAUSE_E,
                                    &info->active_mfgd);

        goto out;
    }
    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_ASSERT_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_ASSERT_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_FWASSERT_E,
                                    &info->active_mfgd);

        goto out;
    }
    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_ASSERT_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_ASSERT_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_TILE_ASSERT_E,
                                    &info->active_mfgd);

        goto out;
    }
    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_FATAL_CAUSE_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_FATAL_CAUSE_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_TILE_FATAL_CAUSE_E,
                                    &info->active_mfgd);
        goto out;
    }
    if (params->op == SX_HEALTH_CHECK_TRIGGER_OP_FW_PLL_FATAL_CAUSE_TEST) {
        sxd_log_notice("Health-Check: Trigger FW Event test with SX_HEALTH_CHECK_TRIGGER_OP_FW_PLL_FATAL_CAUSE_TEST\n");
        err = __sx_health_send_mfgd(info->dev,
                                    true,
                                    info->fatal_error_mode_active,
                                    SXD_MFGD_FW_FATAL_EVENT_TEST_TRIGGER_FW_PLL_LOCK_CAUSE_E,
                                    &info->active_mfgd);
        goto out;
    }

    priv = sx_priv(info->dev);

    mutex_lock(&info->lock);
    switch (params->op) {
    case SX_HEALTH_CHECK_TRIGGER_OP_CATAS:
        sxd_log_notice("Health-Check: Trigger CATAS failure on device %u\n", params->dev_id);
        priv->health_check.debug_trigger_state.catas = true;
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_CMD_IFC:
        sxd_log_notice("Health-Check: Trigger CMD_IFC failure on device %u\n", params->dev_id);
        priv->health_check.debug_trigger_state.cmd_ifc = true;
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_SDQ:
        sxd_log_notice("Health-Check: Trigger SDQ %d failure on device %u\n",
                       params->params.dq_params.dqn, params->dev_id);
        sx_bitmap_set(&priv->health_check.debug_trigger_state.sdq_bitmap, params->params.dq_params.dqn);
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_RDQ:
        sxd_log_notice("Health-Check: Trigger RDQ %d failure on device %u\n",
                       params->params.dq_params.dqn, params->dev_id);
        sx_bitmap_set(&priv->health_check.debug_trigger_state.rdq_bitmap, params->params.dq_params.dqn);
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_CANCEL_ALL:
        sxd_log_notice("Health-Check: Cancel all debug triggers on device %u\n", params->dev_id);
        priv->health_check.debug_trigger_state.catas = false;
        priv->health_check.debug_trigger_state.cmd_ifc = false;
        sx_bitmap_clear_all(&priv->health_check.debug_trigger_state.rdq_bitmap);
        sx_bitmap_clear_all(&priv->health_check.debug_trigger_state.sdq_bitmap);
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_EXTEND_THRESHOLD_THREAD_MONITOR:
        sxd_log_notice("Health-Check: dev id = [%d] multiplied SDK threads threshold time by %u\n",
                       params->dev_id,
                       params->params.sdk_threshold_debug_params.mult_value);
        info->config.sdk_thread_info.mult_threshold_time = params->params.sdk_threshold_debug_params.mult_value;
        break;

    case SX_HEALTH_CHECK_TRIGGER_OP_SET_NEW_THRESHOLD_THREAD_MONITOR:
        sxd_log_notice("Health-Check: dev id = [%d] NEW debug SDK threads threshold time is %u\n",
                       params->dev_id,
                       params->params.sdk_threshold_debug_params.new_debug_threshold_time);
        info->config.sdk_thread_info.new_debug_time_for_thread_monitor =
            params->params.sdk_threshold_debug_params.new_debug_threshold_time;
        break;

    default:
        break;
    }
    mutex_unlock(&info->lock);

out:
    mutex_unlock(&__health_check_lock);
}

enum {
    SXD_MFDE_LOG_NONE,
    SXD_MFDE_LOG_ERROR,
    SXD_MFDE_LOG_NOTICE
};

static void __mfde_work(struct work_struct *work)
{
    struct mfde_work           *mfde_w = container_of(work, struct mfde_work, w);
    struct ku_mfde_reg         *mfde_reg = &mfde_w->mfde;
    struct sx_dev              *dev = mfde_w->dev;
    struct external_cause_work *ecw;
    int                         err, index;
    int                         cause_reg, cause_offset, tile;
    uint64_t                    log_ip = 0;
    char                      * assert_string;
    char                        print_message[FW_SOS_LOG_MAX_SIZE] = {0};
    char                        tile_index_str[32] = {0};
    char                       *error_msg;
    struct sx_health_dev_info  *info = NULL;
    bool                        is_test = false;
    int                         mfde_log_level = SXD_MFDE_LOG_NONE;

    mutex_lock(&__health_check_lock);

    info = __info_find(dev->device_id);
    if (!info) {
        sxd_log_notice("Health-Check: got MFDE event but device %u health-check monitoring is disabled!\n",
                       dev->device_id);
        mutex_unlock(&__health_check_lock);
        goto out;
    }
    mutex_unlock(&__health_check_lock);

    ecw = kzalloc(sizeof(struct external_cause_work), GFP_KERNEL);
    if (ecw == NULL) {
        sxd_log_err("Health-Check: failed to allocate work");
        goto out;
    }

    ecw->irisc_id = mfde_reg->irisc_id;
    ecw->issue_severity = SXD_HEALTH_SEVERITY_FATAL;
    ecw->issue_cause = SXD_HEALTH_CAUSE_FW;
    ecw->dev_id = dev->device_id;

    error_msg = ecw->err_msg;

    switch (mfde_reg->event_id) {
    case SXD_MFDE_EVENT_ID_CRSPACE_TIMEOUT_E:
        log_ip = mfde_reg->event_params.crspace_timeout.log_ip;
        err = __get_kernel_crtimeout_print(print_message, mfde_reg->irisc_id,
                                           mfde_reg->event_params.crspace_timeout.log_id, dev);
        if (err) {
            sxd_log_err("Health-Check: failed to get kernel crspace timeout print err =%d\n",
                        err);
            kfree(ecw);
            goto out;
        }

        if (mfde_reg->event_params.crspace_timeout.tile_v) {
            snprintf(tile_index_str, sizeof(tile_index_str) - 1, "tile_index = [%d], ",
                     mfde_reg->event_params.crspace_timeout.tile_index);
        }

        snprintf(error_msg,
                 HEALTH_CHECK_EVENT_MSG_MAX,
                 "FW CR Space timeout: irisc_id = [%d], log_address = [0x%x], old_event = [%d], "
                 "is_yu = [%d], is_iron = [%d], is_main_farm = [%d], tile_v = [%d], %s"
                 "log_id = [%d], log_ip = [0x%llx] [%s], reg_attr_id = [0x%x], mgmt_class = [%d], "
                 "method = [%d], event_severity=[%d], packet_state = [%d]",
                 mfde_reg->irisc_id,
                 mfde_reg->event_params.crspace_timeout.log_address,
                 mfde_reg->event_params.crspace_timeout.oe,
                 mfde_reg->event_params.crspace_timeout.is_yu,
                 mfde_reg->event_params.crspace_timeout.is_iron,
                 mfde_reg->event_params.crspace_timeout.is_main_farm,
                 mfde_reg->event_params.crspace_timeout.tile_v,
                 tile_index_str,
                 mfde_reg->event_params.crspace_timeout.log_id,
                 log_ip,
                 print_message,
                 mfde_reg->reg_attr_id,
                 mfde_reg->mgmt_class,
                 mfde_reg->method,
                 mfde_reg->severity,
                 mfde_reg->packet_state);
        mfde_log_level = SXD_MFDE_LOG_ERROR;
        break;

    case SXD_MFDE_EVENT_ID_KVD_IM_STOP_E:
        snprintf(error_msg,
                 HEALTH_CHECK_EVENT_MSG_MAX,
                 "FW KVM Stopped: irisc_id = [%d],  old_event = [%d], pipe mask = [%d], "
                 "reg_attr_id = [0x%x], mgmt_class = [%d], method = [%d], event_severity=[%d], "
                 "packet_state = [%d]",
                 mfde_reg->irisc_id,
                 mfde_reg->event_params.kvd_im_stop.oe,
                 mfde_reg->event_params.kvd_im_stop.pipes_mask,
                 mfde_reg->reg_attr_id,
                 mfde_reg->mgmt_class,
                 mfde_reg->method,
                 mfde_reg->severity,
                 mfde_reg->packet_state);
        mfde_log_level = SXD_MFDE_LOG_ERROR;
        break;

    case SXD_MFDE_EVENT_ID_TEST_E:
        snprintf(error_msg, HEALTH_CHECK_EVENT_MSG_MAX, "FW test event\n");
        mfde_log_level = SXD_MFDE_LOG_NOTICE;
        is_test = true;
        break;

    case SXD_MFDE_EVENT_ID_FW_ASSERT_E:
        assert_string = "N/A";
        /* if assert_string from FW is not empty */
        if (mfde_reg->event_params.fw_assert.assert_string[0]) {
            for (index = 0; index < SXD_MFDE_FW_ASSERT_ASSERT_STRING_NUM; index++) {
                mfde_reg->event_params.fw_assert.assert_string[index] =
                    be32_to_cpu(mfde_reg->event_params.fw_assert.assert_string[index]);
            }
            assert_string = (char *)mfde_reg->event_params.fw_assert.assert_string;
            /* make sure string is NULL terminated */
            *(assert_string +
              (SXD_MFDE_FW_ASSERT_ASSERT_STRING_NUM * sizeof(mfde_reg->event_params.fw_assert.assert_string[0]) -
               1)) = '\0';
        }

        snprintf(error_msg,
                 HEALTH_CHECK_EVENT_MSG_MAX,
                 "FW Assert: assert_string = [%s], irisc_id = [%d], assert id = [0x%x], "
                 "assert_var0 = [0x%x], assert_var1 = [0x%x], assert_var2 = [0x%x], assert_var3 = [0x%x], "
                 "assert_var4 = [0x%x], assert_existptr = [0x%x], assert_callra = [0x%x], "
                 "ext_synd = [0x%x], old_event = [0x%x], tile_v = [0x%x], tile_index = [0x%x], "
                 "reg_attr_id = [0x%x], mgmt_class = [%d], method = [%d], event_severity=[%d], "
                 "packet_state = [%d]",
                 assert_string,
                 mfde_reg->irisc_id,
                 mfde_reg->event_params.fw_assert.ext_synd,
                 mfde_reg->event_params.fw_assert.assert_var0,
                 mfde_reg->event_params.fw_assert.assert_var1,
                 mfde_reg->event_params.fw_assert.assert_var2,
                 mfde_reg->event_params.fw_assert.assert_var3,
                 mfde_reg->event_params.fw_assert.assert_var4,
                 mfde_reg->event_params.fw_assert.assert_existptr,
                 mfde_reg->event_params.fw_assert.assert_callra,
                 mfde_reg->event_params.fw_assert.ext_synd,
                 mfde_reg->event_params.fw_assert.oe,
                 mfde_reg->event_params.fw_assert.tile_v,
                 mfde_reg->event_params.fw_assert.tile_index,
                 mfde_reg->reg_attr_id,
                 mfde_reg->mgmt_class,
                 mfde_reg->method,
                 mfde_reg->severity,
                 mfde_reg->packet_state);
        is_test = (mfde_reg->event_params.fw_assert.test == FW_SOS_TEST);
        mfde_log_level = (is_test) ? SXD_MFDE_LOG_NOTICE : SXD_MFDE_LOG_ERROR;
        break;

    case SXD_MFDE_EVENT_ID_FATAL_CAUSE_E:
        cause_reg = mfde_reg->event_params.fatal_cause.cause_id >> 5;
        cause_offset = mfde_reg->event_params.fatal_cause.cause_id & CAUSE_OFFSET_MASK;
        if ((mfde_reg->event_params.fatal_cause.fw_cause) &&
            (mfde_reg->event_params.fatal_cause.cause_id ==
             SXD_MFDE_FW_FATAL_CASUE_ID_CORE_PLL_LOCK_FAILURE_E)) {
            ecw->issue_cause = SXD_HEALTH_CAUSE_PLL_E;
        }

        if (true == mfde_reg->event_params.fatal_cause.tile_v) {
            tile = mfde_reg->event_params.fatal_cause.tile_index;
            snprintf(error_msg,
                     HEALTH_CHECK_EVENT_MSG_MAX,
                     "FW Fatal: fw_cause = [0x%x], cause_id = [0x%x], irisc_id = [%d], tile_index = [0x%x], "
                     "reg_attr_id = [0x%x], mgmt_class = [%d], method = [%d], event_severity=[%d], "
                     "packet_state = [%d]",
                     mfde_reg->event_params.fatal_cause.fw_cause,
                     mfde_reg->event_params.fatal_cause.cause_id,
                     mfde_reg->irisc_id,
                     tile,
                     mfde_reg->reg_attr_id,
                     mfde_reg->mgmt_class,
                     mfde_reg->method,
                     mfde_reg->severity,
                     mfde_reg->packet_state);
        } else {
            /* tile is not valid / no tile */
            snprintf(error_msg,
                     HEALTH_CHECK_EVENT_MSG_MAX,
                     "FW Fatal:fw_cause = [0x%x], cause_id = [0x%x], irisc_id = [%d], reg_attr_id = [0x%x], "
                     "mgmt_class = [%d], method = [%d], event_severity=[%d], packet_state = [%d]",
                     mfde_reg->event_params.fatal_cause.fw_cause,
                     mfde_reg->event_params.fatal_cause.cause_id,
                     mfde_reg->irisc_id,
                     mfde_reg->reg_attr_id,
                     mfde_reg->mgmt_class,
                     mfde_reg->method,
                     mfde_reg->severity,
                     mfde_reg->packet_state);
        }
        is_test = (mfde_reg->event_params.fatal_cause.test == FW_SOS_TEST);
        mfde_log_level = (is_test) ? SXD_MFDE_LOG_NOTICE : SXD_MFDE_LOG_ERROR;
        break;

    case SXD_MFDE_EVENT_ID_LONG_CMD_TIMEOUT_E:
        snprintf(error_msg,
                 HEALTH_CHECK_EVENT_MSG_MAX,
                 "FW Long Command Timeout: irisc_id = [%d],  reg_attr_id = [0x%x], mgmt_class = [%d], "
                 "method = [%d], event_severity=[%d], packet_state = [%d]",
                 mfde_reg->irisc_id,
                 mfde_reg->reg_attr_id,
                 mfde_reg->mgmt_class,
                 mfde_reg->method,
                 mfde_reg->severity,
                 mfde_reg->packet_state);
        ecw->issue_cause = SXD_HEALTH_CAUSE_FW_LONG_COMMAND;
        if (__is_qtm_device(dev)) {
            /* On IB switches this event is a warning to gain resiliency
             * (CR-Space dump will kill the long-command and FW will continue as usual) */
            ecw->issue_severity = SXD_HEALTH_SEVERITY_WARN;
            mfde_log_level = SXD_MFDE_LOG_NOTICE;
        } else {
            /* On Ethernet switches this event is fatal */
            ecw->issue_severity = SXD_HEALTH_SEVERITY_FATAL;
            mfde_log_level = SXD_MFDE_LOG_ERROR;
        }
        break;

    case SXD_MFDE_EVENT_ID_RISCV_EXCEPTION_E:
        snprintf(error_msg,
                 HEALTH_CHECK_EVENT_MSG_MAX,
                 "FW RiscV exception: irisc_id = [%d],  reg_attr_id = [0x%x], mgmt_class = [%d], "
                 "method = [%d], event_severity=[%d], mepc=[0x%llx], mcause=[0x%llx], mtval=[0x%llx]",
                 mfde_reg->irisc_id,
                 mfde_reg->reg_attr_id,
                 mfde_reg->mgmt_class,
                 mfde_reg->method,
                 mfde_reg->severity,
                 mfde_reg->event_params.riscv_exception.mepc,
                 mfde_reg->event_params.riscv_exception.mcause,
                 mfde_reg->event_params.riscv_exception.mtval);
        mfde_log_level = SXD_MFDE_LOG_ERROR;
        break;

    default:
        sxd_log_err("Health-Check: the given event id =%d is out of range", mfde_reg->event_id);
        kfree(ecw);
        goto out;
    }

    ecw->err_msg[HEALTH_CHECK_EVENT_MSG_MAX - 1] = 0;

    if ((mfde_reg->severity == SXD_MFDE_SEVERITY_INTR_E) && !is_test) {
        sxd_log_rl_notice("Health-Check: got an internal FW event - ignoring [%s]\n", error_msg);
        kfree(ecw);
        goto out;
    }

    switch (mfde_log_level) {
    case SXD_MFDE_LOG_ERROR:
        sxd_log_err("Health-Check: %s\n", error_msg);
        break;

    case SXD_MFDE_LOG_NOTICE:
        sxd_log_notice("Health-Check: %s\n", error_msg);
        break;

    default:
        break;
    }

    __external_report_work(&ecw->w);

out:
    kfree(mfde_w);
}

void sx_health_report_error_mfde(struct sx_dev *dev, struct ku_mfde_reg *mfde_reg)
{
    struct mfde_work *mfde_w;

    /*must to allocate mfde_W because we move
     *  to new context from atomic (trap flow) to new work that health check will handle */
    mfde_w = kmalloc(sizeof(struct mfde_work), GFP_ATOMIC);
    if (mfde_w == NULL) {
        sxd_log_err("Health-Check: failed to allocate work");
    }

    INIT_WORK(&mfde_w->w, __mfde_work);
    memcpy(&mfde_w->mfde, mfde_reg, sizeof(struct ku_mfde_reg));
    mfde_w->dev = dev;
    queue_work(__health_check_wq, &mfde_w->w);
}

void sx_health_report_error_emad_timeout(sxd_dev_id_t dev_id, u16 reg_id, u32 usecs, const char *origin)
{
    char error_msg[128];

    snprintf(error_msg, sizeof(error_msg) - 1, "[%s: %d/%s] reg_id=0x%04x, usecs=%u",
             origin,
             current->pid,
             current->comm,
             reg_id,
             usecs);

    __sx_health_external_report(dev_id,
                                SXD_HEALTH_SEVERITY_WARN,
                                SXD_HEALTH_CAUSE_EMAD_TIMEOUT,
                                DBG_ALL_IRISCS,
                                NULL,
                                error_msg);
}

void sx_health_report_error_cmdifc_timeout(sxd_dev_id_t dev_id, sxd_health_cause_t cause, u16 op, u16 reg_id)
{
    char error_msg[128];

    if (op == SX_CMD_ACCESS_REG) {
        snprintf(error_msg, sizeof(error_msg) - 1, "[%d/%s] - op=ACCESS_REG, reg_id=0x%x",
                 current->pid,
                 current->comm,
                 reg_id);
    } else {
        snprintf(error_msg, sizeof(error_msg) - 1, "[%d/%s] - op=0x%x",
                 current->pid,
                 current->comm,
                 op);
    }

    __sx_health_external_report(dev_id,
                                SXD_HEALTH_SEVERITY_WARN,
                                cause,
                                DBG_ALL_IRISCS,
                                NULL,
                                error_msg);
}

void sx_health_report_error_generic(u32 issue_severity, const char *error_msg)
{
    __sx_health_external_report(DEV_ID_ALL,
                                issue_severity,
                                SXD_HEALTH_CAUSE_GENERIC_E,
                                DBG_ALL_IRISCS,
                                NULL,
                                error_msg);
}

/*
 * This function is running under the listeners DB lock, which means that 'listener' pointer
 * is valid in the entire flow of this function
 */
void sx_health_handle_new_listener(struct sx_dev *dev, struct listener_entry *listener)
{
    struct sx_health_dev_info *info = NULL;
    struct issue_info         *failure = NULL;
    sxd_health_severity_t      last_sev = SXD_HEALTH_SEVERITY_NOTICE;

    mutex_lock(&__health_check_lock);

    info = __info_find(dev->device_id);
    if (info) {
        mutex_lock(&info->lock);

        if (info->config.debug_state == HEALTH_DEBUG_MUTE) {
            goto unlock;
        }

        list_for_each_entry(failure, &info->issues_list, list) {
            last_sev = failure->severity;
            if (info->config.min_severity >= failure->severity) {
                sx_send_health_event(dev->device_id,
                                     failure->cause,
                                     failure->severity,
                                     failure->irisc_id,
                                     &failure->event_data,
                                     listener);
            }
        }

        if ((last_sev != SXD_HEALTH_SEVERITY_FATAL) && (info->fatal_cause != SXD_HEALTH_CAUSE_NONE)) {
            failure = list_last_entry(&info->issues_list, struct issue_info, list);
            sx_send_health_event(dev->device_id,
                                 info->fatal_cause,
                                 SXD_HEALTH_SEVERITY_FATAL,
                                 failure->irisc_id,
                                 &info->event_extra_data,
                                 listener);
        }
unlock:
        mutex_unlock(&info->lock);
    }

    mutex_unlock(&__health_check_lock);
}
