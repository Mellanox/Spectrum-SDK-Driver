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

#ifndef SX_CLOCK_H
#define SX_CLOCK_H

#include <linux/version.h>
#include <linux/types.h>

#include "sx.h"
#include "internal_log.h"

extern int clock_activity_log;

/************************************************************************************/
#define SX_CLOCK_SETTIME        settime64
#define SX_CLOCK_GETTIME        gettime64
#define SX_CLOCK_TIMESPEC_TO_NS timespec64_to_ns
#define SX_CLOCK_NS_TO_TIMESPEC ns_to_timespec64
typedef struct timespec64 sx_clock_timespec_t;
/************************************************************************************/

#define SX_CLOCK_IS_DEV_SPECIFIC_CB_SUPPORTED(dev, func_name)           \
    ({                                                                  \
        struct sx_priv *__priv = sx_priv(dev);                          \
        int __err = 0;                                                  \
        u8 __is_supported = 0;                                          \
        do {                                                            \
            __err = __sx_core_dev_specific_cb_get_reference(dev);       \
            if (__err) {                                                \
                sxd_log_err("failed to get " #func_name " callback\n"); \
                break;                                                  \
            }                                                           \
            if (__priv->dev_specific_cb.func_name) {                    \
                __is_supported = 1;                                     \
            }                                                           \
            __sx_core_dev_specific_cb_release_reference(dev);           \
        } while (0);                                                    \
        __is_supported;                                                 \
    })

#define SX_CLOCK_DEV_SPECIFIC_CB(dev, func_name, ...)                   \
    ({                                                                  \
        struct sx_priv *__priv = sx_priv(dev);                          \
        int __err = 0;                                                  \
        do {                                                            \
            __err = __sx_core_dev_specific_cb_get_reference(dev);       \
            if (__err) {                                                \
                sxd_log_err("failed to get " #func_name " callback\n"); \
                break;                                                  \
            }                                                           \
            if (__priv->dev_specific_cb.func_name) {                    \
                __err = __priv->dev_specific_cb.func_name(__VA_ARGS__); \
            }                                                           \
            __sx_core_dev_specific_cb_release_reference(dev);           \
        } while (0);                                                    \
        __err;                                                          \
    })

#define SX_CLOCK_ACTIVITY_LOG(priv, sev, fmt, args ...)                        \
    do {                                                                       \
        if (clock_activity_log) {                                              \
            sx_int_log(&(priv)->hw_clock.log_activity, (sev), (fmt), ## args); \
        }                                                                      \
    } while (0)

struct sx_priv;
struct sx_tstamp;
struct skb_shared_hwtstamps;
struct ptp_clock_info;
struct cyclecounter;
struct sk_buff;

/* external functions */
int sx_core_clock_init(void);
void sx_core_clock_deinit(void);
int sx_core_clock_dev_init(struct sx_priv *priv);
int sx_core_clock_dev_deinit(struct sx_priv *priv);
int sx_core_clock_cqe_ts_to_utc(struct sx_priv *priv,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
                                const struct timespec64 *cqe_ts,
                                struct timespec64       *utc);
#else
                                const struct timespec *cqe_ts,
                                struct timespec       *utc);
#endif

/* common functions */
void sx_clock_log_add_settime(struct sx_priv *priv, s64 value);
void sx_clock_log_add_adjtime(struct sx_priv *priv, s64 value);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
void sx_clock_log_add_adjphase(struct sx_priv *priv, s64 value);
#endif
void sx_clock_log_add_adjfreq(struct sx_priv *priv, s64 value);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0))
void sx_clock_log_add_adjfine(struct sx_priv *priv, s64 value);
#endif
void sx_clock_dbg_add_setter(struct sx_priv *priv);
int sx_clock_register(struct sx_priv              *priv,
                      const struct ptp_clock_info *ptp_clock_info);
int sx_clock_queue_delayed_work(struct delayed_work *dwork,
                                unsigned long        delay);
void sx_clock_fill_hwtstamp_nsec(u64 nsec, struct skb_shared_hwtstamps *hwts);
int sx_dbg_clock_dump_proc_show(struct seq_file *m, void *v, void *context);
int sx_dbg_clock_and_ptp_log_dump_proc_show(struct seq_file *m, void *v, void *context);

/* SPC1 functions */
int sx_clock_dev_init_spc1(struct sx_priv *priv);
int sx_clock_dev_cleanup_spc1(struct sx_priv *priv);
void sx_clock_fill_hwtstamp_spc1(struct sx_priv *priv, u64 frc, struct skb_shared_hwtstamps *hwts);
int sx_clock_dump_spc1(struct sx_priv *priv, struct seq_file *m, void *v, void *context);

/* SPC2 functions */
int sx_clock_dev_init_spc2(struct sx_priv *priv);
int sx_clock_dev_cleanup_spc2(struct sx_priv *priv);
int sx_clock_cqe_ts_to_utc_spc2(struct sx_priv *priv,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
                                const struct timespec64 *cqe_ts,
                                struct timespec64       *utc);
#else
                                const struct timespec *cqe_ts,
                                struct timespec       *utc);
#endif
int sx_clock_dump_spc2(struct sx_priv *priv, struct seq_file *m, void *v, void *context);
void sx_core_ptp_handle_mtppst_event(struct completion_info *ci);
int sx_clock_ptp_pps_init_spc2(struct sx_priv *priv);

#endif  /* SX_CLOCK_H */
