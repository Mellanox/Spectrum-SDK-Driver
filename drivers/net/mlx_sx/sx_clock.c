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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/clocksource.h>
#include <linux/delay.h>
#include <linux/seq_file.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include "sx_clock.h"
#include "sx.h"
#include "dev_db.h"
#include "sx_dbg_dump_proc.h"

int clock_activity_log = 0;
module_param_named(clock_activity_log, clock_activity_log, int, 0644);
MODULE_PARM_DESC(clock_activity_log, "en/dis clock activity log");

struct clock_setter_key {
    /* PID alone is not enough. PID + start_time ==> Unique key */
    u64   start_time;
    pid_t pid;
};
struct clock_setter_info {
    pid_t                   pid;
    char                    name[32];
    u64                     times;
    unsigned long           first_touch;
    unsigned long           last_touch;
    struct sx_core_map_info map;
    struct list_head        lru_list;
};
#define CLOCK_SETTERS_MAX_ENTRIES (64)

static struct workqueue_struct *__clock_wq;

int sx_core_clock_init(void)
{
    __clock_wq = sx_health_check_create_monitored_workqueue("sx_clock_wq");
    if (!__clock_wq) {
        sxd_log_err("Failed to create clock work queue.\n");
        return -ENOMEM;
    }

    return 0;
}

void sx_core_clock_deinit(void)
{
    flush_workqueue(__clock_wq);
    sx_health_check_destroy_monitored_workqueue(__clock_wq);
    __clock_wq = NULL;
}

void sx_clock_fill_hwtstamp_nsec(u64 nsec, struct skb_shared_hwtstamps *hwts)
{
    memset(hwts, 0, sizeof(*hwts));
    hwts->hwtstamp = ns_to_ktime(nsec);
}

static int __clock_setters_compare(const void *key1, const void *key2)
{
    const struct clock_setter_key *csk1 = (struct clock_setter_key*)key1;
    const struct clock_setter_key *csk2 = (struct clock_setter_key*)key2;

    if (csk1->pid != csk2->pid) {
        return ((int)csk1->pid) - ((int)csk2->pid);
    }

    return (int)(((s64)csk1->start_time) - ((s64)csk2->start_time));
}

static int __sx_clock_dev_init(struct sx_priv *priv)
{
    int err = 0;

    sx_internal_log_init(&priv->hw_clock.log_settime,
                         10,
                         SX_INTERNAL_LOG_SEVERITY_INFO_E,
                         "clock_set_time_dev_%u", priv->dev.device_id);
    sx_internal_log_init(&priv->hw_clock.log_adjfreq,
                         10,
                         SX_INTERNAL_LOG_SEVERITY_INFO_E,
                         "clock_adj_freq_dev_%u", priv->dev.device_id);
    sx_internal_log_init(&priv->hw_clock.log_adjtime,
                         10,
                         SX_INTERNAL_LOG_SEVERITY_INFO_E,
                         "clock_adj_time_dev_%u", priv->dev.device_id);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    sx_internal_log_init(&priv->hw_clock.log_adjphase,
                         10,
                         SX_INTERNAL_LOG_SEVERITY_INFO_E,
                         "clock_adj_phase_dev_%u", priv->dev.device_id);
#endif
    sx_internal_log_init(&priv->hw_clock.log_activity,
                         1000,
                         SX_INTERNAL_LOG_SEVERITY_INFO_E,
                         "ptp_and_clock_activity_dev_%u",
                         priv->dev.device_id);

    mutex_init(&priv->hw_clock.clock_setters_lock);
    INIT_LIST_HEAD(&priv->hw_clock.clock_setters_lru);
    err = sx_core_map_init(&priv->hw_clock.clock_setters,
                           __clock_setters_compare,
                           sizeof(struct clock_setter_key));
    if (err) {
        goto out;
    }

    err = SX_CLOCK_DEV_SPECIFIC_CB(&priv->dev, sx_clock_dev_init, priv);
    if (err) {
        sxd_log_err("chip-specific clock init failed (err=%d)\n", err);
        goto out;
    }

    err = SX_CLOCK_DEV_SPECIFIC_CB(&priv->dev, sx_clock_ptp_pps_init, priv);
    if (err) {
        sxd_log_err("chip-specific ptp pps init failed (err=%d)\n", err);
        goto out;
    }

out:
    if (err) {
        priv->hw_clock.clock_info.enable = NULL;
        priv->hw_clock.clock_info.verify = NULL;
        kfree(priv->hw_clock.clock_info.pin_config);
        sx_internal_log_deinit(&priv->hw_clock.log_activity);
        sx_internal_log_deinit(&priv->hw_clock.log_adjtime);
        sx_internal_log_deinit(&priv->hw_clock.log_adjfreq);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
        sx_internal_log_deinit(&priv->hw_clock.log_adjphase);
#endif
        sx_internal_log_deinit(&priv->hw_clock.log_settime);

        if (priv->hw_clock.clock) {
            ptp_clock_unregister(priv->hw_clock.clock);
            priv->hw_clock.clock = NULL;
        }
    } else {
        priv->hw_clock.initialized = true;
    }

    return err;
}

static int __destruct_clock_setter(const void *key, struct sx_core_map_info *info, void *context)
{
    struct clock_setter_info *setter = container_of(info, struct clock_setter_info, map);

    list_del(&setter->lru_list);
    kfree(setter);
    return 0;
}

static int __sx_clock_dev_deinit(struct sx_priv *priv)
{
    int err;

    err = SX_CLOCK_DEV_SPECIFIC_CB(&priv->dev, sx_clock_dev_cleanup, priv);
    if (err) {
        sxd_log_err("chip-specific clock cleanup failed (err=%d)\n", err);
    }

    if (priv->hw_clock.clock) {
        ptp_clock_unregister(priv->hw_clock.clock);
        priv->hw_clock.clock = NULL;
    }

    mutex_lock(&priv->hw_clock.clock_setters_lock);
    sx_core_map_remove_all(&priv->hw_clock.clock_setters, __destruct_clock_setter, NULL);
    mutex_unlock(&priv->hw_clock.clock_setters_lock);

    sx_internal_log_deinit(&priv->hw_clock.log_settime);
    sx_internal_log_deinit(&priv->hw_clock.log_adjfreq);
    sx_internal_log_deinit(&priv->hw_clock.log_adjtime);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    sx_internal_log_deinit(&priv->hw_clock.log_adjphase);
#endif
    sx_internal_log_deinit(&priv->hw_clock.log_activity);
    priv->hw_clock.initialized = false;
    return 0;
}


int sx_clock_register(struct sx_priv *priv, const struct ptp_clock_info *ptp_clock_info)
{
    /* Register PTP clock */
    memcpy(&priv->hw_clock.clock_info, ptp_clock_info, sizeof(struct ptp_clock_info));
    snprintf(priv->hw_clock.clock_info.name, 16, "sx_ptp");

    priv->hw_clock.clock = ptp_clock_register(&priv->hw_clock.clock_info, &priv->dev.pdev->dev);
    if (IS_ERR(priv->hw_clock.clock)) {
        sxd_log_err("Failed to register ptp clock.\n");
        priv->hw_clock.clock = NULL;
        return -EINVAL;
    }

    return 0;
}


int sx_clock_queue_delayed_work(struct delayed_work *dwork, unsigned long delay)
{
    return queue_delayed_work(__clock_wq, dwork, delay);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
int sx_core_clock_cqe_ts_to_utc(struct sx_priv *priv, const struct timespec64 *cqe_ts, struct timespec64 *utc)
#else
int sx_core_clock_cqe_ts_to_utc(struct sx_priv *priv, const struct timespec *cqe_ts, struct timespec *utc)
#endif
{
    int err;

    err = SX_CLOCK_DEV_SPECIFIC_CB(&priv->dev, sx_clock_cqe_ts_to_utc, priv, cqe_ts, utc);
    if (err) {
        sxd_log_err("chip-specific clock cqe_ts_to_utc failed (err=%d)\n", err);
    }

    return err;
}


int sx_core_clock_dev_init(struct sx_priv *priv)
{
    u8  clock_supported = SX_CLOCK_IS_DEV_SPECIFIC_CB_SUPPORTED(&priv->dev, sx_clock_dev_init);
    int err = 0;

    if (clock_supported) {
        err = __sx_clock_dev_init(priv);
    }

    return err;
}


int sx_core_clock_dev_deinit(struct sx_priv *priv)
{
    u8  clock_supported = SX_CLOCK_IS_DEV_SPECIFIC_CB_SUPPORTED(&priv->dev, sx_clock_dev_cleanup);
    int err = 0;

    if (clock_supported) {
        err = __sx_clock_dev_deinit(priv);
    }

    return err;
}

void sx_clock_dbg_add_setter(struct sx_priv *priv)
{
    struct clock_setter_info *info;
    struct sx_core_map_info  *map_info;
    struct clock_setter_key   key = {
        .pid = current->pid,
        .start_time = current->start_time
    };
    unsigned long             now = jiffies;
    int                       err;

    mutex_lock(&priv->hw_clock.clock_setters_lock);

    err = sx_core_map_lookup(&priv->hw_clock.clock_setters, &key, &map_info);
    if (err) {
        /* if list of setters is full, remove the oldest one and use it's allocation for the new one */
        if (priv->hw_clock.clock_setters_num_entries == CLOCK_SETTERS_MAX_ENTRIES) {
            info = list_first_entry(&priv->hw_clock.clock_setters_lru, struct clock_setter_info, lru_list);
            priv->hw_clock.clock_setters_num_entries--;
            list_del(&info->lru_list);
            sx_core_map_remove(&priv->hw_clock.clock_setters, info->map.key, NULL);
            memset(info, 0, sizeof(*info));
        } else {
            info = kzalloc(sizeof(struct clock_setter_info), GFP_KERNEL);
            if (!info) {
                sxd_log_err("failed to allocate clock setter Agent=[%s/%d]\n", current->comm, current->pid);
                goto out;
            }
        }

        info->first_touch = now;
        info->pid = current->pid;
        info->times = 0;
        strncpy(info->name, current->comm, sizeof(info->name) - 1);

        err = sx_core_map_insert(&priv->hw_clock.clock_setters, &key, &info->map, GFP_KERNEL);
        if (err) {
            sxd_log_err("failed to add clock setter Agent=[%s/%d]\n", current->comm, current->pid);
            kfree(info);
            goto out;
        }

        priv->hw_clock.clock_setters_num_entries++;
        list_add_tail(&info->lru_list, &priv->hw_clock.clock_setters_lru);
    } else {
        info = container_of(map_info, struct clock_setter_info, map);
        list_move_tail(&info->lru_list, &priv->hw_clock.clock_setters_lru);
    }

    info->last_touch = now;
    info->times++;

out:
    mutex_unlock(&priv->hw_clock.clock_setters_lock);
}

void sx_clock_log_add_settime(struct sx_priv *priv, s64 value)
{
    sx_int_log_info(&priv->hw_clock.log_settime,
                    "%-18lld [%s/%d]",
                    (long)value, current->comm, current->pid);
    SX_CLOCK_ACTIVITY_LOG(priv, SX_INTERNAL_LOG_SEVERITY_INFO_E, "SET_TIME %lld", value);
}


void sx_clock_log_add_adjtime(struct sx_priv *priv, s64 value)
{
    sx_int_log_info(&priv->hw_clock.log_adjtime,
                    "%-18lld [%s/%d]",
                    (long)value, current->comm, current->pid);
    SX_CLOCK_ACTIVITY_LOG(priv, SX_INTERNAL_LOG_SEVERITY_INFO_E, "ADJ_TIME %lld", value);
}


void sx_clock_log_add_adjfreq(struct sx_priv *priv, s64 value)
{
    sx_int_log_info(&priv->hw_clock.log_adjfreq,
                    "%-18lld ppb        [%s/%d]",
                    (long)value, current->comm, current->pid);
    SX_CLOCK_ACTIVITY_LOG(priv, SX_INTERNAL_LOG_SEVERITY_INFO_E, "ADJ_FREQ %lld", value);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
void sx_clock_log_add_adjfine(struct sx_priv *priv, s64 value)
{
    sx_int_log_info(&priv->hw_clock.log_adjfreq,
                    "%-18lld scaled_ppm [%s/%d]",
                    (long)value, current->comm, current->pid);
    SX_CLOCK_ACTIVITY_LOG(priv, SX_INTERNAL_LOG_SEVERITY_INFO_E, "ADJ_FREQ (scaled_ppm) %lld", value);
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
void sx_clock_log_add_adjphase(struct sx_priv *priv, s64 value)
{
    sx_int_log_info(&priv->hw_clock.log_adjphase,
                    "%-18lld [%s/%d]",
                    (long)value, current->comm, current->pid);
    SX_CLOCK_ACTIVITY_LOG(priv, SX_INTERNAL_LOG_SEVERITY_INFO_E, "ADJ_PHASE %lld", value);
}
#endif

static void __dump_clock_setters(struct sx_priv *priv, struct seq_file *m)
{
    char                      first_touch[32], last_touch[32], agent[32];
    struct clock_setter_info *iter;

    seq_printf(m, "Clock setters\n");
    seq_printf(m, "%-32s   %-10s   %-23s   %-23s\n",
               "Agent", "Times", "First-Set", "Last-Set");
    seq_printf(m, "------------------------------------------------------------------------------------\n");

    mutex_lock(&priv->hw_clock.clock_setters_lock);

    list_for_each_entry(iter, &priv->hw_clock.clock_setters_lru, lru_list) {
        snprintf(agent, sizeof(agent), "%s/%d", iter->name, iter->pid);
        sx_dbg_jiffies_to_time_str(NULL, iter->first_touch, first_touch, sizeof(first_touch));
        sx_dbg_jiffies_to_time_str(NULL, iter->last_touch, last_touch, sizeof(last_touch));
        seq_printf(m, "%-32s   %-10llu   %-20s   %-20s\n", agent, iter->times, first_touch, last_touch);
    }

    mutex_unlock(&priv->hw_clock.clock_setters_lock);
    seq_printf(m, "\n\n");
}

int sx_dbg_clock_dump_proc_show(struct seq_file *m, void *v, void *context)
{
    struct sx_priv *priv = NULL;
    struct sx_dev * dev = sx_dbg_dump_get_device(m);

    if (!dev) {
        return 0;
    }
    priv = sx_priv(dev);
    if (!priv->hw_clock.initialized) {
        return 0;
    }

    seq_printf(m, "HW Clock Dump (device #%u)\n", dev->device_id);
    seq_printf(m, "--------------------------\n");

    SX_CLOCK_DEV_SPECIFIC_CB(dev, sx_clock_dump, priv, m, v, context);

    __dump_clock_setters(priv, m);
    sx_internal_log_dump(&priv->hw_clock.log_settime, m);
    sx_internal_log_dump(&priv->hw_clock.log_adjfreq, m);
    sx_internal_log_dump(&priv->hw_clock.log_adjtime, m);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
    sx_internal_log_dump(&priv->hw_clock.log_adjphase, m);
#endif

    seq_printf(m, "\n\n");
    return 0;
}

int sx_dbg_clock_and_ptp_log_dump_proc_show(struct seq_file *m, void *v, void *context)
{
    struct sx_priv *priv = NULL;
    struct sx_dev * dev = sx_dbg_dump_get_device(m);

    if (!dev) {
        return 0;
    }
    priv = sx_priv(dev);
    if (clock_activity_log) {
        sx_internal_log_dump(&priv->hw_clock.log_activity, m);
    } else {
        seq_printf(m, "clock_activity_log parameter is turned off! activity log is idle now!\n\n");
    }

    seq_printf(m, "\n\n");
    return 0;
}
