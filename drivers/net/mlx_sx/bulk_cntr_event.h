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

#ifndef __BULK_CNTR_EVENT_H__
#define __BULK_CNTR_EVENT_H__

#include <linux/mlx_sx/device.h>
#include <linux/mlx_sx/driver.h>

void sx_bulk_cntr_handle_mocs_done(struct completion_info *ci);
void sx_bulk_cntr_handle_ppcnt(struct completion_info *ci);
void sx_bulk_cntr_handle_mgpcb(struct completion_info *ci);
void sx_bulk_cntr_handle_pbsr(struct completion_info *ci);
void sx_bulk_cntr_handle_sbsrd(struct completion_info *ci);
void sx_bulk_cntr_handle_ceer(struct completion_info *ci);
void sx_bulk_cntr_handle_fsed(struct completion_info *ci);
void sx_bulk_cntr_handle_mofrb(struct completion_info *ci);
void sx_bulk_cntr_handle_upcnt(struct completion_info *ci);
void sx_bulk_cntr_handle_utcc(struct completion_info *ci);
void sx_bulk_cntr_handle_usacn(struct completion_info *ci);
void sx_bulk_cntr_handle_moftd(struct completion_info *ci);

int sx_bulk_cntr_handle_ack(struct sx_dev                  *dev,
                            const sxd_bulk_cntr_event_id_t *ev_id,
                            unsigned long                   buffer_id);
int sx_bulk_cntr_handle_continue_ack(struct sx_dev                  *dev,
                                     const sxd_bulk_cntr_event_id_t *ev_id,
                                     unsigned long                   buffer_id);
int bulk_cntr_stateful_db_entry_write(struct sx_dev *dev, ku_stateful_db_translated_entry_t *entry_p);

#endif /* __BULK_CNTR_EVENT_H__ */
