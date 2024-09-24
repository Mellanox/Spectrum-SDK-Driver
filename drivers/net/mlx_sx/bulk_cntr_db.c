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

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>

#include "mmap.h"
#include "bulk_cntr_db.h"
#include <linux/mlx_sx/device.h>
#include "sx.h"
#include "ioctl_internal.h"


#ifndef BYTES_IN_MB
#define BYTES_IN_MB (1024 * 1204)
#endif
/* HFT is not considered in this max progress limit. */
#define BULK_CNTR_MAX_IN_PROGRESS  (2)
#define BULK_CNTR_HFT_BUF_SIZE_MAX (350)

struct transaction_entry {
    unsigned long                              buffer_id; /* mmap pointer in user process */
    sxd_bulk_cntr_event_id_t                   event_id;
    u8                                         is_canceled; /* is transaction canceled by user */
    struct sxd_bulk_cntr_buffer_layout_common *common_layout; /* pointer to shared-memory from driver's perspective */
};
struct transaction_status {
    pid_t                            client_pid; /* user process ID */
    unsigned long                    buffer_id; /* mmap pointer in user process */
    enum sxd_bulk_cntr_done_status_e status; /* status of the transaction */
};

/* HFT work queue specific information.*/
struct sx_hft_sesssion_ctx {
    struct workqueue_struct *hft_wq_p;
};

static struct transaction_entry *__in_progress[SXD_BULK_CNTR_KEY_TYPE_LAST_E];
static u32                       __in_progress_cnt = 0;
static bool                      __accuflow_reservation = false;
static bool                      __hft_reservation = false;
static DEFINE_SPINLOCK(__bulk_cntr_db_lock);
static sxd_port_per_prio_counter_cache_t *__per_prio_counter_cache = NULL;
static u64                                g_bulk_counter_buffer_hft_utilization = 0;
static u64                                g_bulk_counter_max_buffer_hft_limit = BULK_CNTR_HFT_BUF_SIZE_MAX; /* 350MB default initialization. */
static struct sx_hft_sesssion_ctx         g_hft_session_ctx; /* HFT specific context.*/

/* this function gets user process ID + user shared memory pointer and returns the shared memory pointer
 * from driver's perspective */
struct sxd_bulk_cntr_buffer_layout_common * __get_buffer(pid_t client_pid, unsigned long buffer_id)
{
    return (struct sxd_bulk_cntr_buffer_layout_common*)sx_mmap_user_to_kernel(client_pid, buffer_id);
}

void __bulk_cntr_dec_mmap_ref(pid_t client_pid, unsigned long buffer_id)
{
    sx_mmap_ref_dec(client_pid, buffer_id);
}

void __bulk_cntr_inc_mmap_ref(pid_t client_pid, unsigned long buffer_id)
{
    sx_mmap_ref_inc(client_pid, buffer_id);
}
static void __init_elephant_layout(struct sxd_bulk_cntr_buffer_layout_elephant *layout_elephant_p,
                                   struct sxd_bulk_cntr_params_elephant        *elephant_params_p)
{
    int total_ports = 0, i = 0, j = 0;

    memcpy(&layout_elephant_p->port_mask, &elephant_params_p->port_mask,
           sizeof(layout_elephant_p->port_mask));

    for (i = 0; i < SXD_COS_ELEPHANT_PORT_MASK_NUM; i++) {
        for (j = 0; j < 32; j++) {
            if (layout_elephant_p->port_mask[i] & (1 << j)) {
                total_ports++;
            }
        }
    }

    memset(&layout_elephant_p->port_flows, 0, sizeof(layout_elephant_p->port_flows));
    memset(&layout_elephant_p->data, 0, sizeof(layout_elephant_p->data[0]) * total_ports *
           SXD_COS_ELEPHANT_FLOW_ID_NUM_MAX);
}

/* add a new bulk-counter transaction */
int bulk_cntr_db_add(struct ku_bulk_cntr_transaction_add *bulk_cntr_tr_add)
{
    struct sxd_bulk_cntr_buffer_layout_common          *layout_common;
    struct sxd_bulk_cntr_buffer_layout_flow            *layout_flow;
    struct sxd_bulk_cntr_buffer_layout_shared_buffer   *layout_shared_buffer;
    struct sxd_bulk_cntr_buffer_layout_headroom        *layout_headroom;
    struct sxd_bulk_cntr_buffer_layout_port            *layout_port;
    struct sxd_bulk_cntr_buffer_layout_elephant        *layout_elephant;
    struct sxd_bulk_cntr_buffer_layout_stateful_db     *layout_stateful_db;
    struct sxd_bulk_cntr_buffer_layout_flow_estimator  *layout_flow_estimator;
    struct sxd_bulk_cntr_buffer_layout_macsec_port     *layout_macsec_port;
    struct sxd_bulk_cntr_buffer_layout_macsec_acl_flow *layout_macsec_acl_flow;
    struct sxd_bulk_cntr_buffer_layout_macsec_sa       *layout_macsec_sa;
    struct sxd_bulk_cntr_buffer_layout_hft             *layout_hft;
    struct transaction_entry                           *entry;
    int                                                 i = 0, j = 0;
    int                                                 err = 0;
    enum sxd_bulk_cntr_key_type_e                       type = bulk_cntr_tr_add->event_id.event_id_fields.type;
    sxd_dev_id_t                                        device_id = DEFAULT_DEVICE_ID;
    uint16_t                                            max_packet_size = 0;
    struct sx_dev                                      *dev;


    /* convert from user-process shared memory pointer to driver's pointer */
    layout_common = __get_buffer(bulk_cntr_tr_add->event_id.event_id_fields.client_id,
                                 bulk_cntr_tr_add->buffer_id);
    if (!layout_common) {
        sxd_log_err("Bulk-Counter DB add - invalid buffer_id\n");
        return -EINVAL;
    }

    if (type != SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E) {
        if (type != layout_common->type) {
            sxd_log_err("Bulk-Counter DB add - type mismatch\n");
            return -EINVAL;
        }
    }

    spin_lock_bh(&__bulk_cntr_db_lock);

    /* Only one HFT session is allowed at a time and it should not be accounted for max session in progress.
     * Two different bulk session types along with HFT is allowed to execute at the same time.*/
    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        if (__in_progress[type] != NULL) {
            err = -EBUSY;
            goto out;
        }
    } else if ((__in_progress[type] != NULL) || (__in_progress_cnt == BULK_CNTR_MAX_IN_PROGRESS)) {
        err = -EBUSY;
        goto out;
    }

    entry = kmalloc(sizeof(struct transaction_entry), GFP_ATOMIC);
    if (!entry) {
        err = -ENOMEM;
        goto out;
    }

    layout_common->counters_received_so_far = 0; /* reset the numbers received for the new transaction */
    switch (type) {
    case SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E:
    /* fall-through */
    case SXD_BULK_CNTR_KEY_TYPE_FLOW_E:
        layout_flow = (struct sxd_bulk_cntr_buffer_layout_flow*)layout_common;
        layout_flow->base_counter_id = bulk_cntr_tr_add->params.flow_params.base_counter_id;
        break;

    case SXD_BULK_CNTR_KEY_TYPE_FLOW_ESTIMATOR_E:
        layout_flow_estimator = (struct sxd_bulk_cntr_buffer_layout_flow_estimator*)layout_common;
        layout_flow_estimator->base_counter_id = bulk_cntr_tr_add->params.flow_estimator_params.base_counter_id;
        break;

    case SXD_BULK_CNTR_KEY_TYPE_SHARED_BUFFER_E:
        layout_shared_buffer = (struct sxd_bulk_cntr_buffer_layout_shared_buffer*)layout_common;
        layout_common->num_of_counters = bulk_cntr_tr_add->params.shared_buffer_params.num_of_counters;
        layout_shared_buffer->port_idx = 0;
        layout_shared_buffer->pg_tc_sp_idx = 0;
        layout_shared_buffer->port_pool_idx = 0;
        layout_shared_buffer->pool_idx = 0;
        layout_shared_buffer->last_type = SXD_BULK_CNTR_SB_TYPE_INVALID;
        layout_shared_buffer->mc_pool_id = bulk_cntr_tr_add->params.shared_buffer_params.mc_pool_id;
        memcpy(layout_shared_buffer->port_mask, bulk_cntr_tr_add->params.shared_buffer_params.port_mask,
               sizeof(uint32_t) * SXD_BULK_CNTR_PORT_MASK_NUM);
        memcpy(layout_shared_buffer->sw_pool_id, bulk_cntr_tr_add->params.shared_buffer_params.sw_pool_id,
               sizeof(uint32_t) * SXD_BULK_CNTR_TOTAL_POOL_MAX_NUM);
        memset(layout_shared_buffer->port, 0, sizeof(sxd_bulk_cntr_shared_buffer_port_t) * SXD_BULK_CNTR_PORT_NUM);
        for (i = 0; i < SXD_BULK_CNTR_PORT_NUM; i++) {
            for (j = 0; j < SXD_BULK_CNTR_POOL_NUM; j++) {
                layout_shared_buffer->port[i].rx_per_pool[j].sw_pool_id = SXD_BULK_CNTR_POOL_ID_INVALID;
                layout_shared_buffer->port[i].tx_per_pool[j].sw_pool_id = SXD_BULK_CNTR_POOL_ID_INVALID;
                layout_shared_buffer->port[i].rx_per_pool_desc[j].sw_pool_id = SXD_BULK_CNTR_POOL_ID_INVALID;
                layout_shared_buffer->port[i].tx_per_pool_desc[j].sw_pool_id = SXD_BULK_CNTR_POOL_ID_INVALID;
            }
        }
        memset(layout_shared_buffer->mc_port, 0, sizeof(sxd_bulk_cntr_shared_buffer_mc_port_t) *
               SXD_BULK_CNTR_PORT_NUM);
        memset(&layout_shared_buffer->mc_switch_prio, 0, sizeof(sxd_bulk_cntr_shared_buffer_mc_sp_t));
        memset(&layout_shared_buffer->pool, 0, sizeof(sxd_bulk_cntr_shared_buffer_pool_t));
        for (i = 0; i < SXD_BULK_CNTR_TOTAL_POOL_MAX_NUM; i++) {
            layout_shared_buffer->pool.statistics[i].sw_pool_id = SXD_BULK_CNTR_POOL_ID_INVALID;
        }

        break;

    case SXD_BULK_CNTR_KEY_TYPE_HEADROOM_E:
        layout_headroom = (struct sxd_bulk_cntr_buffer_layout_headroom*)layout_common;
        layout_common->num_of_counters = bulk_cntr_tr_add->params.headroom_params.num_of_counters;
        memcpy(layout_headroom->port_width, bulk_cntr_tr_add->params.headroom_params.port_width,
               sizeof(uint8_t) * SXD_BULK_CNTR_PORT_NUM);
        memcpy(layout_headroom->port_mask, bulk_cntr_tr_add->params.headroom_params.port_mask,
               sizeof(uint32_t) * SXD_BULK_CNTR_PORT_MASK_NUM);
        memset(layout_headroom->headroom, 0, sizeof(sxd_bulk_cntr_headroom_port_t) * SXD_BULK_CNTR_PORT_NUM);
        break;

    case SXD_BULK_CNTR_KEY_TYPE_PORT_E:
        layout_common->num_of_counters = bulk_cntr_tr_add->params.port_params.number_of_counters;
        layout_port = (struct sxd_bulk_cntr_buffer_layout_port*)layout_common;
        memcpy(&(layout_port->mappings),
               &(bulk_cntr_tr_add->params.port_params.mappings),
               sizeof(layout_port->mappings));
        memset(layout_port->counters, 0, sizeof(layout_port->counters[0]) * (layout_port->counters_size));
        break;

    case SXD_BULK_CNTR_KEY_TYPE_ELEPHANT_E:
        layout_elephant = (struct sxd_bulk_cntr_buffer_layout_elephant *)layout_common;
        __init_elephant_layout(layout_elephant, &bulk_cntr_tr_add->params.elephant_params);
        break;

    case SXD_BULK_CNTR_KEY_TYPE_STATEFUL_DB_E:
        layout_stateful_db = (struct sxd_bulk_cntr_buffer_layout_stateful_db *)layout_common;

        layout_stateful_db->meta_layout.number_of_entries = 0;
        layout_stateful_db->meta_layout.number_of_entries_translated = 0;
        memset(layout_stateful_db->data, 0,
               sizeof(layout_stateful_db->data[0]) * (bulk_cntr_tr_add->params.stateful_db_params.entries_num_max));

        break;

    case SXD_BULK_CNTR_KEY_TYPE_MACSEC_PORT_E:
        layout_common->num_of_counters = bulk_cntr_tr_add->params.macsec_port_params.number_of_counters;
        layout_macsec_port = (struct sxd_bulk_cntr_buffer_layout_macsec_port*)layout_common;
        memcpy(&(layout_macsec_port->mappings),
               &(bulk_cntr_tr_add->params.macsec_port_params.mappings),
               sizeof(layout_macsec_port->mappings));
        memset(layout_macsec_port->counters, 0,
               sizeof(layout_macsec_port->counters[0]) * (layout_macsec_port->counters_size));
        break;

    case SXD_BULK_CNTR_KEY_TYPE_MACSEC_ACL_FLOW_E:
        layout_common->num_of_counters = bulk_cntr_tr_add->params.macsec_acl_flow_params.number_of_counters;
        layout_macsec_acl_flow = (struct sxd_bulk_cntr_buffer_layout_macsec_acl_flow*)layout_common;
        layout_macsec_acl_flow->direction = bulk_cntr_tr_add->params.macsec_acl_flow_params.direction;
        layout_macsec_acl_flow->base_entity_id = bulk_cntr_tr_add->params.macsec_acl_flow_params.base_entity_id;
        memcpy(layout_macsec_acl_flow->port_index_map,
               bulk_cntr_tr_add->params.macsec_acl_flow_params.port_index_map,
               sizeof(layout_macsec_acl_flow->port_index_map));
        break;

    case SXD_BULK_CNTR_KEY_TYPE_MACSEC_SA_E:
        layout_common->num_of_counters = bulk_cntr_tr_add->params.macsec_sa_params.number_of_counters;
        layout_macsec_sa = (struct sxd_bulk_cntr_buffer_layout_macsec_sa*)layout_common;
        layout_macsec_sa->direction = bulk_cntr_tr_add->params.macsec_sa_params.direction;
        layout_macsec_sa->base_entity_id = bulk_cntr_tr_add->params.macsec_sa_params.base_entity_id;
        layout_macsec_sa->local_port = bulk_cntr_tr_add->params.macsec_sa_params.local_port;
        layout_macsec_sa->uengine_id = bulk_cntr_tr_add->params.macsec_sa_params.uengine_id;
        break;

    case SXD_BULK_CNTR_KEY_TYPE_HFT_E:
        dev = sx_core_ioctl_get_dev(device_id);
        if (!dev) {
            return -ENODEV;
        }
        err = sx_core_get_rdq_param_max(dev, NULL, &max_packet_size);
        if (err) {
            sxd_log_err("could not get RDQ attributes (err=%d)\n", err);
            goto out;
        }
        layout_hft = (struct sxd_bulk_cntr_buffer_layout_hft*)layout_common;
        layout_hft->samples_expected = bulk_cntr_tr_add->params.hft_params.samples_expected;
        layout_hft->sample_buffer_size = bulk_cntr_tr_add->params.hft_params.sample_buffer_size;
        memcpy(&layout_hft->metadata_map,
               &bulk_cntr_tr_add->params.hft_params.metadata_map,
               sizeof(layout_hft->metadata_map));
        memcpy(&layout_hft->port_map,
               &bulk_cntr_tr_add->params.hft_params.port_map,
               sizeof(layout_hft->port_map));
        memcpy(&layout_hft->global_map,
               &bulk_cntr_tr_add->params.hft_params.global_map,
               sizeof(layout_hft->global_map));
        layout_hft->samples_received = 0;
        layout_hft->buffer_idx = 0;
        layout_hft->moftd_max_entries = SXD_MAX_HFT_ENTRIES_SINGLE_EMAD(max_packet_size);
        layout_hft->moftd_reg_buf = kmalloc(max_packet_size, GFP_ATOMIC);
        if (layout_hft->moftd_reg_buf == NULL) {
            err = -ENOMEM;
            sxd_log_err("%s: failed to allocate memory for MOFTD buffer.\n",
                        __func__);
            goto out;
        }
        break;

    default:
        break;
    }


    /* save transaction data */
    entry->buffer_id = bulk_cntr_tr_add->buffer_id;
    entry->event_id = bulk_cntr_tr_add->event_id;
    entry->is_canceled = 0;
    entry->common_layout = layout_common;

    /* increment reference for shared memory so that memory is not deallocated when application
     * exits, after bulk transaction is triggered.
     */
    __bulk_cntr_inc_mmap_ref(bulk_cntr_tr_add->event_id.event_id_fields.client_id,
                             bulk_cntr_tr_add->buffer_id);

    __in_progress[type] = entry;

    /* hft session doesn't affect other bulk counter session */
    if (type != SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        __in_progress_cnt++;
    }

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}


/* common delete (called from DEL/COMPLETE) of bulk-counter transaction from DB */
static void __bulk_cntr_db_del(uint32_t type, struct transaction_entry *entry)
{
    __in_progress[type] = NULL;

    /* Do it only for non HFT session as firmware support bulk session and hft. */
    if (type != SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        __in_progress_cnt--;
    }

    kfree(entry);
}


/* delete a bulk-counter transaction from DB */
int bulk_cntr_db_del(pid_t client_pid, unsigned long buffer_id)
{
    struct sxd_bulk_cntr_buffer_layout_common *layout_common;
    struct transaction_entry                  *entry;
    int                                        err = 0;
    enum sxd_bulk_cntr_key_type_e              type = SXD_BULK_CNTR_KEY_TYPE_LAST_E;
    sxd_bulk_cntr_buffer_layout_hft_t         *layout_hft_p = NULL;

    /* convert from user-process shared memory pointer to driver's pointer */
    layout_common = __get_buffer(client_pid, buffer_id);
    if (!layout_common) {
        sxd_log_err("Bulk-Counter DB del - invalid buffer_id\n");
        return -EINVAL;
    }
    type = layout_common->type;

    spin_lock_bh(&__bulk_cntr_db_lock);

    /* check if there requested buffer is indeed in progress */
    entry = __in_progress[type];
    if (!entry) {
        err = -ENOENT;
        goto out;
    }

    if (entry->buffer_id != buffer_id) {
        /* If buffer IDs are not equal and the type of buffer is the FLOW COUNTERS type,
         *  we need to check also the ACCUFLOW COUNTERS type as by the design
         *  on the user level there is only the FLOW COUNTERS type. */
        if (type == SXD_BULK_CNTR_KEY_TYPE_FLOW_E) {
            entry = __in_progress[SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E];
            if (!entry || (entry->buffer_id != buffer_id)) {
                err = -ENOENT;
                goto out;
            }

            type = SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E;
        } else {
            err = -ENOENT;
            goto out;
        }
    }

    /* check if the operation was canceled by the user */
    if (entry->is_canceled) { /* transaction is already canceled, waiting for MOCS_DONE to delete it */
        err = -EBUSY;
        goto out;
    }

    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        layout_hft_p = (sxd_bulk_cntr_buffer_layout_hft_t*)layout_common;
        if (layout_hft_p->moftd_reg_buf != NULL) {
            kfree(layout_hft_p->moftd_reg_buf);
            layout_hft_p->moftd_reg_buf = NULL;
        }
    }

    /* delete the transaction from DB */
    __bulk_cntr_db_del(type, entry);

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);

    if (!err) {
        /* Decrement reference to shared memory after lock dependency is removed.
         * so that memory is deallocated if application has exited, after bulk
         * transaction is triggered.
         */
        __bulk_cntr_dec_mmap_ref(client_pid, buffer_id);
    }

    return err;
}


/* cancel an operation that is in progress */
int bulk_cntr_db_cancel(pid_t client_pid, unsigned long buffer_id)
{
    struct sxd_bulk_cntr_buffer_layout_common *layout_common;
    struct transaction_entry                  *entry;
    int                                        err = 0;

    /* convert from user-process shared memory pointer to driver's pointer */
    layout_common = __get_buffer(client_pid, buffer_id);
    if (!layout_common) {
        sxd_log_err("Bulk-Counter DB cancel - invalid buffer_id\n");
        return -EINVAL;
    }

    spin_lock_bh(&__bulk_cntr_db_lock);

    /* check if there requested buffer is indeed in progress */
    entry = __in_progress[layout_common->type];
    if (!entry) {
        err = -ENOENT;
        goto out;
    }

    if (entry->buffer_id != buffer_id) {
        /* If buffer IDs are not equal and the type of buffer is the FLOW COUNTERS type,
         *  we need to check also the ACCUFLOW COUNTERS type as by the design
         *  on the user level there is only the FLOW COUNTERS type. */
        if (layout_common->type == SXD_BULK_CNTR_KEY_TYPE_FLOW_E) {
            entry = __in_progress[SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E];
            if (!entry || (entry->buffer_id != buffer_id)) {
                err = -ENOENT;
                goto out;
            }
        } else {
            err = -ENOENT;
            goto out;
        }
    }

    /* mark the transaction as 'canceled' */
    entry->is_canceled = 1;

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}


/* complete a transaction. called in two cases:
 * 1. MOCS_DONE event handled by the driver and no ack from SDK is required.
 * 2. Ack from SDK upon MOCS_DONE event (in cases when SDK has to do
 *    some cleanups for the transaction, e.g. unlock counter range).
 */
int bulk_cntr_db_complete(const sxd_bulk_cntr_event_id_t   *event_id,
                          unsigned long                    *buffer_id,
                          enum sxd_bulk_cntr_done_status_e *status,
                          uint32_t                         *cookie)
{
    struct transaction_entry                  *entry;
    enum sxd_bulk_cntr_key_type_e              type;
    int                                        err = 0;
    sxd_bulk_cntr_buffer_layout_stateful_db_t *layout_stateful_p = NULL;
    sxd_bulk_cntr_buffer_layout_hft_t         *layout_hft_p = NULL;
    unsigned long                              buffer_id_val = 0;
    pid_t                                      client_id_val = 0;

    type = event_id->event_id_fields.type;

    spin_lock_bh(&__bulk_cntr_db_lock);

    /* check that there is an operation of type 'type' in progress */
    entry = __in_progress[type];
    if (!entry) {
        err = -ENOENT;
        goto out;
    }

    buffer_id_val = entry->buffer_id;
    client_id_val = entry->event_id.event_id_fields.client_id;

    if (buffer_id) {
        *buffer_id = buffer_id_val;
    }

    /* determine the status of the transaction to be reported to the user */
    if (entry->is_canceled) {
        *status = SXD_BULK_CNTR_DONE_STATUS_CANCELED;
    } else if ((entry->common_layout->num_of_counters != entry->common_layout->counters_received_so_far) &&
               (type != SXD_BULK_CNTR_KEY_TYPE_STATEFUL_DB_E)) {
        *status = SXD_BULK_CNTR_DONE_STATUS_ERROR;
    } else if (type == SXD_BULK_CNTR_KEY_TYPE_STATEFUL_DB_E) {
        layout_stateful_p = (struct sxd_bulk_cntr_buffer_layout_stateful_db *)entry->common_layout;
        if (layout_stateful_p->meta_layout.number_of_entries !=
            layout_stateful_p->meta_layout.number_of_entries_translated) {
            *status = SXD_BULK_CNTR_DONE_STATUS_ERROR;
        } else {
            *status = SXD_BULK_CNTR_DONE_STATUS_OK;
        }
    } else {
        *status = SXD_BULK_CNTR_DONE_STATUS_OK;
    }

    if (cookie) {
        *cookie = entry->common_layout->cookie;
    }

    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        layout_hft_p = (sxd_bulk_cntr_buffer_layout_hft_t*)entry->common_layout;
        if (layout_hft_p->moftd_reg_buf != NULL) {
            kfree(layout_hft_p->moftd_reg_buf);
            layout_hft_p->moftd_reg_buf = NULL;
        }
    }

    /* delete the transaction from DB. */
    __bulk_cntr_db_del(event_id->event_id_fields.type, entry);

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);

    if (!err) {
        /* Decrement reference to shared memory after lock dependency is removed.
         * so that memory is deallocated if application has exited, after bulk
         * transaction is triggered.
         */
        __bulk_cntr_dec_mmap_ref(client_id_val, buffer_id_val);
    }
    return err;
}


/* get a buffer from MOCS event_id field (upon MOCS parsing) */
int bulk_cntr_db_event_id_to_buffer(sxd_bulk_cntr_event_id_t                   *event_id,
                                    struct sxd_bulk_cntr_buffer_layout_common **layout_common)
{
    struct transaction_entry *entry;
    int                       err = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);

    /* check that there is an operation of type 'type' in progress */
    entry = __in_progress[event_id->event_id_fields.type];
    if (!entry) {
        err = -ENOENT;
        goto out;
    }

    *layout_common = entry->common_layout;

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}

int bulk_cntr_db_per_prio_cache_set(struct ku_bulk_cntr_per_prio_cache *bulk_cntr_per_prio_cache)
{
    int                                err = 0;
    sxd_port_per_prio_counter_cache_t* temp_per_prio_counter_cache = NULL;

    if (bulk_cntr_per_prio_cache->is_set) {
        temp_per_prio_counter_cache = (sxd_port_per_prio_counter_cache_t*)sx_mmap_user_to_kernel(
            bulk_cntr_per_prio_cache->pid,
            bulk_cntr_per_prio_cache->user_ptr);

        if (!temp_per_prio_counter_cache) {
            sxd_log_err("Bulk-Counter DB per prio cache set - invalid buffer_id\n");
            err = -EINVAL;
            goto out;
        }
    }

    spin_lock_bh(&__bulk_cntr_db_lock);
    __per_prio_counter_cache = temp_per_prio_counter_cache;
    spin_unlock_bh(&__bulk_cntr_db_lock);

out:
    return err;
}

int bulk_cntr_db_per_prio_cache_entry_get(uint16_t local_port, uint16_t prio, sxd_port_cntr_prio_t **cache_entry)
{
    int err = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);

    if (!__per_prio_counter_cache) {
        err = -ENOENT;
        goto out;
    }

    if ((local_port > MAX_PHYPORT_NUM) || (prio > SXD_PORT_PRIO_ID_MAX) || (!cache_entry)) {
        err = -EINVAL;
        goto out;
    }

    *cache_entry = &(__per_prio_counter_cache->counters[local_port][prio]);

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}

int bulk_cntr_db_in_progress(struct ku_bulk_cntr_transaction *bulk_cntr_tr_in_progress, void *data)
{
    int err = 0;

    err = bulk_cntr_db_in_progress_get(bulk_cntr_tr_in_progress->type, &bulk_cntr_tr_in_progress->in_progress);
    if (err) {
        goto out;
    }

    err = copy_to_user((void*)data, bulk_cntr_tr_in_progress, sizeof(*bulk_cntr_tr_in_progress));
    if (err) {
        goto out;
    }

out:
    return err;
}

int bulk_cntr_db_in_progress_get(enum sxd_bulk_cntr_key_type_e type, u8 *in_progress_p)
{
    int err = 0;

    if (type >= SXD_BULK_CNTR_KEY_TYPE_LAST_E) {
        err = -EINVAL;
        sxd_log_err("Bulk-Counter DB in progress - invalid type: %u\n", type);
        goto out;
    }

    spin_lock_bh(&__bulk_cntr_db_lock);

    *in_progress_p = (__in_progress[type] != NULL);

    spin_unlock_bh(&__bulk_cntr_db_lock);

out:
    return err;
}

void bulk_cntr_db_hft_mmap_dtor(unsigned long user_ptr, pid_t pid, unsigned long size)
{
    spin_lock_bh(&__bulk_cntr_db_lock);

    if (g_bulk_counter_buffer_hft_utilization >= size) {
        g_bulk_counter_buffer_hft_utilization -= size;
    } else {
        sxd_log_err("hft memory destructor failure hft total size(%llu), size freed(%lu).\n",
                    g_bulk_counter_buffer_hft_utilization,
                    size);
    }

    spin_unlock_bh(&__bulk_cntr_db_lock);
}

int bulk_cntr_db_buffer_stats_set(struct ku_bulk_cntr_buffer_stats *bulk_cntr_buffer_stats_data_p)
{
    int err = 0;

    /* is_allocated is set to TRUE when NOS maps memory for bulk counters and
     * is set to FALSE when NOS unmaps the memory, but we do accounting when memory
     * is actually freed through the destructor callback.
     */
    if (bulk_cntr_buffer_stats_data_p->is_allocated) {
        /* max buffer limit size 0 is considered as unlimited, so we just need to update utilization.
         * SDK imposes a hard limit on the buffer than can allocated when max buffer limit is non zero
         */
        spin_lock_bh(&__bulk_cntr_db_lock);
        if ((g_bulk_counter_max_buffer_hft_limit == 0) ||
            (g_bulk_counter_buffer_hft_utilization + bulk_cntr_buffer_stats_data_p->size <=
             (g_bulk_counter_max_buffer_hft_limit * BYTES_IN_MB))) {
            g_bulk_counter_buffer_hft_utilization += bulk_cntr_buffer_stats_data_p->size;
        } else {
            err = -ENOMEM;
        }
        spin_unlock_bh(&__bulk_cntr_db_lock);
        if (!err) {
            sx_mmap_set_pfn_dtor(bulk_cntr_buffer_stats_data_p->user_ptr,
                                 bulk_cntr_buffer_stats_data_p->pid,  bulk_cntr_buffer_stats_data_p->size,
                                 bulk_cntr_db_hft_mmap_dtor);
        }
    }

    return err;
}

int bulk_cntr_db_buffer_info_get(struct ku_bulk_cntr_buffer_info *bulk_cntr_buffer_info_p)
{
    spin_lock_bh(&__bulk_cntr_db_lock);
    bulk_cntr_buffer_info_p->current_utilization = g_bulk_counter_buffer_hft_utilization;
    bulk_cntr_buffer_info_p->max_size = g_bulk_counter_max_buffer_hft_limit;
    spin_unlock_bh(&__bulk_cntr_db_lock);

    return 0;
}

int bulk_cntr_db_buffer_info_set(struct ku_bulk_cntr_buffer_info *bulk_cntr_buffer_info_p)
{
    int err = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);
    /* we need to make sure that the current utilization is less than the new max if the size is not unlimited. */
    if (bulk_cntr_buffer_info_p->max_size != 0) {
        if ((bulk_cntr_buffer_info_p->max_size * BYTES_IN_MB) < g_bulk_counter_buffer_hft_utilization) {
            err = -ENOMEM;
            goto out;
        }
    }
    g_bulk_counter_max_buffer_hft_limit = bulk_cntr_buffer_info_p->max_size;

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}

int sx_core_hft_init(void)
{
    g_hft_session_ctx.hft_wq_p = sx_health_check_create_monitored_workqueue("hft_wq");
    if (!g_hft_session_ctx.hft_wq_p) {
        sxd_log_err("Failed to create HFT work queue.\n");
        return -ENOMEM;
    }

    return 0;
}

void sx_core_hft_deinit(void)
{
    flush_workqueue(g_hft_session_ctx.hft_wq_p);
    sx_health_check_destroy_monitored_workqueue(g_hft_session_ctx.hft_wq_p);
    g_hft_session_ctx.hft_wq_p = NULL;
}

bool sx_core_hft_queue_work(struct work_struct *w)
{
    if (__in_progress[SXD_BULK_CNTR_KEY_TYPE_HFT_E] == NULL) {
        sxd_log_rl_warning("sx_core_hft_queue_work"
                           "Err: HFT is not started");
        return -ENOENT;
    }

    return queue_work(g_hft_session_ctx.hft_wq_p, w);
}

int bulk_cntr_db_mocs_session_acquire(enum sxd_bulk_cntr_key_type_e type)
{
    int err = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);

    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        if ((__in_progress[type] != NULL) || (__hft_reservation == true)) {
            sxd_log_err("HFT counters have already reserved a MOCS session.\n");
            err = -EBUSY;
            goto out;
        }
        __hft_reservation = true;
        goto out;
    }

    if (__in_progress_cnt >= BULK_CNTR_MAX_IN_PROGRESS) {
        sxd_log_err("There is no free MOCS session.\n");
        err = -EBUSY;
        goto out;
    }

    if (type == SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E) {
        if (__accuflow_reservation) {
            sxd_log_err("Accumulated counters have already reserved a MOCS session.\n");
            err = -EBUSY;
            goto out;
        }
        __accuflow_reservation = true;
    }

    __in_progress_cnt++;

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}
EXPORT_SYMBOL(bulk_cntr_db_mocs_session_acquire);

int bulk_cntr_db_mocs_session_release(enum sxd_bulk_cntr_key_type_e type)
{
    int err = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);

    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        if (__hft_reservation == false) {
            err = -EINVAL;
            sxd_log_err("Bulk-Counter DB hft session release - nothing to release \n");
            goto out;
        }
        __hft_reservation = false;
        goto out;
    }

    if (__in_progress_cnt == 0) {
        err = -EINVAL;
        sxd_log_err("Bulk-Counter DB session release - nothing to release \n");
        goto out;
    }

    if (type == SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E) {
        if (__accuflow_reservation == false) {
            sxd_log_err("Accumulated counters didn't reserve a MOCS session.\n");
            err = -EINVAL;
            goto out;
        }
        __accuflow_reservation = false;
    }

    __in_progress_cnt--;

out:
    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}
EXPORT_SYMBOL(bulk_cntr_db_mocs_session_release);

int bulk_cntr_db_dump(struct seq_file *m, void *v, void *context)
{
    int err = 0;
    int index = 0;

    spin_lock_bh(&__bulk_cntr_db_lock);

    seq_printf(m, "Bulk counters DB:\n");
    seq_printf(m, "Transactions in progress         : %u \n", __in_progress_cnt);
    seq_printf(m, "Max transactions in parallel     : %u \n", BULK_CNTR_MAX_IN_PROGRESS);
    seq_printf(m, "Accumulated counters reservation : %u \n", __accuflow_reservation);
    seq_printf(m, "HFT bulk buffer max limit : %llu MB\n",         g_bulk_counter_max_buffer_hft_limit);
    seq_printf(m, "HFT bulk buffer current utilization : %llu bytes\n",   g_bulk_counter_buffer_hft_utilization);

    seq_printf(m, "Transactions:\n");
    for (; index < SXD_BULK_CNTR_KEY_TYPE_LAST_E; index++) {
        seq_printf(m, "Transaction type #%d: \n", index);
        if (__in_progress[index] == NULL) {
            seq_printf(m, "\ttransaction is idle.\n");
        } else {
            seq_printf(m, "\tBuffer ID: %lu\n", __in_progress[index]->buffer_id);
            seq_printf(m, "\tEvent ID: %llu\n", __in_progress[index]->event_id.event_id_value);
            seq_printf(m, "\tIs canceled: %u\n", __in_progress[index]->is_canceled);
        }
    }

    spin_unlock_bh(&__bulk_cntr_db_lock);
    return err;
}
