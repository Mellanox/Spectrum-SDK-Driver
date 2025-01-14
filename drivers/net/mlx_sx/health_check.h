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

#ifndef __HEALTH_CHECK_H__
#define __HEALTH_CHECK_H__

#include <linux/mlx_sx/kernel_user.h>

enum sx_health_check_trigger_op {
    SX_HEALTH_CHECK_TRIGGER_OP_ADD_DEV,
    SX_HEALTH_CHECK_TRIGGER_OP_DEL_DEV,
    SX_HEALTH_CHECK_TRIGGER_OP_SYSFS,
    SX_HEALTH_CHECK_TRIGGER_OP_CATAS,
    SX_HEALTH_CHECK_TRIGGER_OP_CMD_IFC,
    SX_HEALTH_CHECK_TRIGGER_OP_SDQ,
    SX_HEALTH_CHECK_TRIGGER_OP_RDQ,
    SX_HEALTH_CHECK_TRIGGER_OP_CANCEL_ALL,
    SX_HEALTH_CHECK_TRIGGER_OP_KERNEL_THREADS,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_FATAL_EVENT_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_CAUSE_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_ASSERT_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_ASSERT_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_TILE_FATAL_CAUSE_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_FW_PLL_FATAL_CAUSE_TEST,
    SX_HEALTH_CHECK_TRIGGER_OP_EXTEND_THRESHOLD_THREAD_MONITOR,
    SX_HEALTH_CHECK_TRIGGER_OP_SET_NEW_THRESHOLD_THREAD_MONITOR
};

#define SX_HEALTH_CHECK_ADD_THREAD    1
#define SX_HEALTH_CHECK_DELETE_THREAD 0

#define NUM_OF_SDK_THREADS_MAP_BY_BITS 64

#define SX_PER_DEV_CHECKS "0-tasklet, 1-catas, 2-sdq, 3-rdq, 4-sdk_threads, 5-cmd_ifc"
#define SX_GLOBAL_CHECKS  "0-sysfs_ts, 1-kernel_threads"

struct sx_health_check_trigger_params {
    enum sx_health_check_trigger_op op;
    u8                              dev_id;
    union {
        struct dq_params {
            int dqn;
        } dq_params;
        struct kthread_params {
            char* name;
        } kthread_params;
        /* This filed is for debug purpose for cases we want
         * to increase the thread threshold time (debug kernel setup for example)*/
        struct sdk_thread_threshold_params {
            int mult_value;
            int new_debug_threshold_time;
        } sdk_threshold_debug_params;
    } params;
    bool fatal_error_mode_active;
};

int sx_health_check_dev_init(struct sx_dev *dev);
bool sx_health_check_dev_deinit(struct sx_dev *dev, void *context);
int sx_health_check_init(void);
int sx_health_check_deinit(void);
int sx_health_check_configure(ku_dbg_health_check_params_t *params);
void sx_health_check_report_dq_ok(struct sx_dev *dev, bool is_send, int dqn);
void sx_health_check_report_cmd_ifc_ok(struct sx_dev *dev);

int sx_health_check_dump(struct seq_file *m, void *v, void *context);

void sx_health_check_set_debug_trigger(struct sx_health_check_trigger_params *params);

int sx_health_update_tg(u8 dev_id, int hw_trap_group, bool is_add, bool is_wjh_rdq_update);

void sx_health_report_error_mfde(struct sx_dev *dev, struct ku_mfde_reg *mfde_reg);
void sx_health_report_error_meccc(struct sx_dev *dev, struct ku_meccc_reg *meccc_reg);
void sx_health_report_error_fshe(struct sx_dev *dev, struct ku_fshe_reg *fshe_reg);
void sx_health_report_error_emad_timeout(sxd_dev_id_t dev_id,
                                         u16          reg_id,
                                         u32          usecs,
                                         const char  *origin);
void sx_health_report_error_cmdifc_timeout(sxd_dev_id_t       dev_id,
                                           sxd_health_cause_t cause,
                                           u16                op,
                                           u16                reg_id);
void sx_health_report_error_generic(u32         issue_severity,
                                    const char *error_msg);

int sx_health_check_dbg_cmd_handler(int argc, const char *argv[], void *context);

#endif /* __HEALTH_CHECK_H__ */
