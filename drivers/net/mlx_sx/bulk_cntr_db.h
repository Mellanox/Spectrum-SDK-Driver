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

#ifndef __BULK_CNTR_DB_H__
#define __BULK_CNTR_DB_H__

#include <linux/seq_file.h>
#include <linux/mlx_sx/kernel_user.h>
#include <linux/mlx_sx/device.h>

int bulk_cntr_db_add(struct sx_dev *dev, struct ku_bulk_cntr_transaction_add *bulk_cntr_tr_add);
int bulk_cntr_db_del(struct sx_dev *dev, pid_t client_pid, unsigned long buffer_id);
int bulk_cntr_db_cancel(struct sx_dev *dev, pid_t client_pid, unsigned long buffer_id);

int bulk_cntr_db_ack(unsigned long                    buffer_id,
                     sxd_bulk_cntr_event_id_t        *ev_id,
                     enum sxd_bulk_cntr_done_status_e status);

int bulk_cntr_db_complete(struct sx_dev                    *dev,
                          const sxd_bulk_cntr_event_id_t   *event_id,
                          unsigned long                    *buffer_id,
                          enum sxd_bulk_cntr_done_status_e *status,
                          uint32_t                         *cookie);

int bulk_cntr_db_in_progress_get(struct sx_dev *dev, enum sxd_bulk_cntr_key_type_e type, u8 *in_progress_p);
int bulk_cntr_db_in_progress(struct sx_dev *dev, struct ku_bulk_cntr_transaction *bulk_cntr_tr_in_progress,
                             void *data);

int bulk_cntr_db_event_id_to_buffer(struct sx_dev                              *dev,
                                    sxd_bulk_cntr_event_id_t                   *event_id,
                                    struct sxd_bulk_cntr_buffer_layout_common **layout_common);

int bulk_cntr_db_per_prio_cache_set(struct sx_dev *dev, struct ku_bulk_cntr_per_prio_cache *bulk_cntr_per_prio_cache);

int bulk_cntr_db_per_prio_cache_entry_get(struct sx_dev         *dev,
                                          uint16_t               local_port,
                                          uint16_t               prio,
                                          sxd_port_cntr_prio_t **cache_entry);

int bulk_cntr_db_mocs_session_acquire(struct sx_dev *dev, enum sxd_bulk_cntr_key_type_e type);
int bulk_cntr_db_mocs_session_release(struct sx_dev *dev, enum sxd_bulk_cntr_key_type_e type);
int bulk_cntr_db_buffer_stats_set(struct sx_dev *dev, struct ku_bulk_cntr_buffer_stats *bulk_cntr_buffer_stats_data_p);
int bulk_cntr_db_buffer_info_get(struct sx_dev *dev, struct ku_bulk_cntr_buffer_info *bulk_cntr_buffer_info_p);
int bulk_cntr_db_buffer_info_set(struct sx_dev *dev, struct ku_bulk_cntr_buffer_info *bulk_cntr_buffer_info_p);
int bulk_cntr_db_dump(struct seq_file *m, void *v, void *context);

int sx_core_hft_init(void);
void sx_core_hft_deinit(void);
bool sx_core_hft_queue_work(struct work_struct *w);

#endif /* __BULK_CNTR_DB_H__ */
