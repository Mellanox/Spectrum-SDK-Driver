/*
 * Copyright (c) 2010-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION & AFFILIATES, Ltd.
 * (the "Company") and all right, title, and interest in and to the software product,
 * including all associated intellectual property rights, are and shall
 * remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <linux/skbuff.h>

#include <linux/mlx_sx/device.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include "bulk_cntr_db.h"
#include "bulk_cntr_event.h"
#include "sx_af_counters.h"

#define EVENT_EMAD_HDR_TID(skb) (be64_to_cpu(((struct emad_operation*)((skb)->data + sizeof(struct sx_eth_hdr)))->tid))
#define EVENT_REG_OFFSET(skb)        \
    ((skb)->data +                   \
     sizeof(struct sx_eth_hdr) +     \
     sizeof(struct emad_operation) + \
     sizeof(struct sxd_emad_tlv_reg))

extern int rx_debug_hft_event;

/* hft mocs done specific information. */
struct hft_mocs_done_info {
    u8 reserved;
};

/* hft moftd event specific information. */
struct hft_moftd_info {
    struct sk_buff *skb_p;
};

/* hft work data. events are pushed in order, all moftd events are pushed before mocs done. */
typedef union sx_hft_sample_work_data {
    union {
        struct hft_mocs_done_info mocs_done_info;
        struct hft_moftd_info     moftd_info;
    } data_info;
} sx_hft_sample_work_data_t;

/* hft work item. */
struct sx_hft_sample_work {
    sx_hft_sample_work_data_t data;
    ktime_t                   ktime;
    struct work_struct        ws;
};

void __enqueue_hft_moftd_event(struct completion_info *comp_info_p);
void __enqueue_hft_mocs_done_event(void);

/* function to parse multi-reg EMAD frame */
void sx_bulk_cntr_multi_emad_parse(const void               *buff,
                                   u32                       buff_len,
                                   sx_bulk_cntr_reg_parser_t reg_parser_cb,
                                   void                     *context)
{
    const struct sx_eth_hdr                   *emad_eth_header = (struct sx_eth_hdr*)buff; /* ethernet header */
    const struct sxd_emad_tlv_reg             *tlv;
    struct sxd_bulk_cntr_buffer_layout_common *layout_common = NULL;
    sxd_bulk_cntr_event_id_t                   event_id;
    u32                                        buff_remain = buff_len;
    u16                                        reg_id, type, len;
    int                                        err;

    /* check that buffer is long enough */
    if (buff_len < sizeof(*emad_eth_header) + sizeof(struct emad_operation)) {
        sxd_log_err("SX_BULK_CNTR: buffer is too small [buff_len=%u]\n", buff_len);
        return;
    }

    /* skip the EMAD ethernet header */
    buff_remain -= sizeof(*emad_eth_header);

    /* check that the first TLV is OPERATION_TLV and then skip it */
    tlv = (struct sxd_emad_tlv_reg*)(((u8*)buff) + sizeof(*emad_eth_header));

    type = sxd_emad_tlv_type(tlv);
    len = sxd_emad_tlv_len(tlv);

    if (type != TLV_TYPE_OPERATION_E) {
        sxd_log_err("SX_BULK_CNTR: operation TLV is missing in buffer\n");
        return;
    }

    if (len != sizeof(struct emad_operation)) {
        sxd_log_err("SX_BULK_CNTR: operation TLV has bad length (len=%u)\n", len);
        return;
    }

    reg_id = cpu_to_be16(((struct emad_operation*)tlv)->register_id);
    event_id.event_id_value = cpu_to_be64(((struct emad_operation*)tlv)->tid);
    /* Accumulated / performance counters are unique:
     *   SDK does MOCS not for a specific group / buffer, but for all Accumulated counters.
     *   Thus, there will be no buffer associated with the received event id. */
    if (((reg_id != MLXSW_MAFTI_ID) && (reg_id != MLXSW_MAFRI_ID) &&
         (event_id.event_id_fields.type != SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E)) &&
        (event_id.event_id_fields.type != SXD_BULK_CNTR_KEY_TYPE_PERFORMANCE_E) &&
        (event_id.event_id_fields.type != SXD_BULK_CNTR_KEY_TYPE_ISSU_E)) {
        err = bulk_cntr_db_event_id_to_buffer(&event_id, &layout_common);
        if (err) {
            sxd_log_warning("SX_BULK_CNTR: unable to find buffer for event_id %llu\n", event_id.event_id_value);
            return;
        }
    }

    buff_remain -= sizeof(struct emad_operation);
    tlv = (struct sxd_emad_tlv_reg*)(((u8*)tlv) + sizeof(struct emad_operation));

    /* time to parse the registers until END_TLV */
    while (buff_remain >= sizeof(*tlv)) {
        type = sxd_emad_tlv_type(tlv);
        len = sxd_emad_tlv_len(tlv);

        if ((type != TLV_TYPE_REG_E) && (type != TLV_TYPE_END_E)) {
            sxd_log_err("SX_BULK_CNTR: unexpected TLV in event (type=%u)\n", type);
            break;
        }

        /* in case of END_TLV, just stop parsing */
        if (type == TLV_TYPE_END_E) {
            break;
        }

        if (len == 0) {
            sxd_log_err("SX_BULK_CNTR: REG-TLV length is 0\n");
            break;
        }

        if (len > buff_remain) {
            sxd_log_err("SX_BULK_CNTR: REG-TLV unexpected length (len=%u, buff_len=%u)\n", len, buff_remain);
            break;
        }

        /* call the reg-parser callback */
        reg_parser_cb(((u8*)tlv) + sizeof(struct sxd_emad_tlv_reg),
                      len - sizeof(struct sxd_emad_tlv_reg),
                      layout_common,
                      context);

        /* go to the next register in the frame */
        tlv = (struct sxd_emad_tlv_reg*)(((u8*)tlv) + len);
        buff_remain -= len;
    }

    if (type != TLV_TYPE_END_E) {
        sxd_log_err("SX_BULK_CNTR: unexpected end of frame (no END_TLV)\n");
    }
}
EXPORT_SYMBOL(sx_bulk_cntr_multi_emad_parse);

static int __send_notification_to_user(const sxd_bulk_cntr_event_id_t  *ev_id,
                                       unsigned long                    buffer_id,
                                       enum sxd_bulk_cntr_done_status_e status,
                                       uint32_t                         cookie,
                                       gfp_t                            gfp_mask)
{
    sxd_bulk_counter_done_notification_t event = {
        .status = status,
        .buffer_id = buffer_id,
        .cookie = cookie,
    };
    int                                  err;

    /* User will use the cookie to identify whether this notification is what he wants. */
    err = send_trap(&event,
                    sizeof(event),
                    SXD_TRAP_ID_BULK_COUNTER_DONE_EVENT,
                    0,
                    1,
                    TARGET_PID_DONT_CARE,
                    gfp_mask);
    if (err) {
        sxd_log_err("failed to send notification for bulk-counter transaction completion\n");
    }

    return err;
}


/* this function is called in cases that the driver needs ack from SDK
 * to complete a bulk-counter transaction. For example, when flow-counter
 * bulk-read is done, SDK has to unlock the range of counters before the user
 * get notified that the transaction is done.
 */
int sx_bulk_cntr_handle_ack(const sxd_bulk_cntr_event_id_t *ev_id, unsigned long buffer_id)
{
    enum sxd_bulk_cntr_done_status_e status;
    uint32_t                         cookie;
    enum sxd_bulk_cntr_key_type_e    type = 0;
    int                              err = 0;

    /* complete the transaction: get status and delete from DB */
    type = ev_id->event_id_fields.type;
    /* when there are no flow counters in HFT, buffer id needs to be retrieved from database. */
    if (type == SXD_BULK_CNTR_KEY_TYPE_HFT_E) {
        __enqueue_hft_mocs_done_event();
        goto out;
    } else {
        err = bulk_cntr_db_complete(ev_id, NULL, &status, &cookie);
    }


    if (err) {
        sxd_log_err("Bulk-Cntr ACK: failed to complete the transaction\n");
        goto out;
    }

    /* send notification to user upon transaction completion */
    err = __send_notification_to_user(ev_id, buffer_id, status, cookie, GFP_KERNEL);
    if (err) {
        sxd_log_err("Bulk-Cntr SDK ack: failed to send notification to user upon transaction completion\n");
    }

out:
    return err;
}

int sx_bulk_cntr_handle_continue_ack(const sxd_bulk_cntr_event_id_t *ev_id, unsigned long buffer_id)
{
    enum sxd_bulk_cntr_done_status_e status;
    uint32_t                         cookie;
    int                              err = 0;

    /* complete the transaction: get status and delete from DB */
    err = bulk_cntr_db_complete(ev_id, NULL, &status, &cookie);
    if (err) {
        sxd_log_err("Bulk-Cntr ACK: failed to complete the transaction\n");
        goto out;
    }

    if (status == SXD_BULK_CNTR_DONE_STATUS_OK) {
        status = SXD_BULK_CNTR_DONE_STATUS_PARTIALLY_COMPLETE;
    }

    /* send notification to user upon transaction completion */
    err = __send_notification_to_user(ev_id, buffer_id, status, cookie, GFP_KERNEL);
    if (err) {
        sxd_log_err("Bulk-Cntr SDK ack: failed to send notification to user upon transaction completion\n");
    }

out:
    return err;
}

/***************************************************************************************
 * MOCS_DONE
 */

static void __mocs_done_parser(const void                                *mocs_reg,
                               u32                                        reg_len,
                               struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                               void                                      *context)
{
    sxd_bulk_cntr_event_id_t         event_id;
    unsigned long                    buffer_id;
    enum sxd_bulk_cntr_done_status_e status;
    uint32_t                         cookie;
    u64                              emad_tid = *((u64*)context);
    int                              err;

    event_id.event_id_value = mlxsw_reg_mocs_event_tid_get(mocs_reg);

    if (emad_tid != event_id.event_id_value) {
        /* according to PRM they should be equal in MOCS_DONE event */
        sxd_log_err("MOCS_DONE event is corrupted: emad_tid=%llu, event_tid=%llu\n",
                    emad_tid,
                    event_id.event_id_value);
        return;
    }

    if ((event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_FLOW_E) ||
        (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_FLOW_ESTIMATOR_E) ||
        (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_STATEFUL_DB_E) ||
        (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_HFT_E)) {
        /* we don't send the notification to user now. First, SDK has to acknowledge that
         * it has unlocked the counters. we're waiting for the ack that will be handled
         * in sx_bulk_cntr_handle_ack() */
        return;
    }

    if (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_ISSU_E) {
        /* we don't send the notification to user now. This internal use only */
        return;
    }

    if (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_ACCUFLOW_E) {
        sx_af_counters_mocs_done();
        return;
    }

    if (event_id.event_id_fields.type == SXD_BULK_CNTR_KEY_TYPE_PERFORMANCE_E) {
        /* Performance counters are supported via spice module, thus we don't send any notification to the user.
         * Mocs session release will be invoked from spice module */
        return;
    }

    /* complete the transaction: get status and delete from DB */
    err = bulk_cntr_db_complete(&event_id, &buffer_id, &status, &cookie);
    if (err) {
        sxd_log_err("failed to get transaction status on bulk-counter completion\n");
        return;
    }

    /* send notification to user upon transaction completion */
    err = __send_notification_to_user(&event_id, buffer_id, status, cookie, GFP_ATOMIC);
    if (err) {
        sxd_log_err("Bulk-Cntr FW done - failed to send notification to user upon transaction completion\n");
    }
}


void sx_bulk_cntr_handle_mocs_done(struct completion_info *ci)
{
    u64 emad_tid;

    emad_tid = EVENT_EMAD_HDR_TID(ci->skb);
    sx_bulk_cntr_multi_emad_parse(ci->skb->data,
                                  ci->skb->len,
                                  __mocs_done_parser,
                                  &emad_tid);
}

/***************************************************************************************
 * PPCNT
 */
#define CHECK_PPCNT_GRP_EXPECTED(bulk_cntr_port_grp)                                        \
    do {                                                                                    \
        if (!(layout_port->mappings.counter_set_bitmap & bulk_cntr_port_grp)) {             \
            sxd_log_err("Bulk-Cntr PPCNT parser - unexpected PPCNT group %u\n", ppcnt.grp); \
            return;                                                                         \
        }                                                                                   \
    } while (0)

#define CHECK_RECEIVED_PPCNT_COUNT()                                                     \
    do {                                                                                 \
        if (layout_common->counters_received_so_far == layout_common->num_of_counters) { \
            sxd_log_err("Bulk-Cntr PPCNT parser - got more counters than required\n");   \
            return;                                                                      \
        }                                                                                \
    } while (0)

#define CHECK_PPCNT_GRP_AND_COUNT(grp) \
    do {                               \
        CHECK_PPCNT_GRP_EXPECTED(grp); \
        CHECK_RECEIVED_PPCNT_COUNT();  \
    } while (0)


#define CHECK_PPCNT_TC_GRP_AND_COUNT()                                                                    \
    do {                                                                                                  \
        CHECK_PPCNT_GRP_EXPECTED(SXD_BULK_CNTR_PORT_GRP_TC_E);                                            \
        if (ppcnt.prio_tc > SXD_PORT_TC_ID_MAX) {                                                         \
            sxd_log_err("Bulk-Cntr PPCNT parser - invalid traffic class %u\n", ppcnt.prio_tc);            \
            return;                                                                                       \
        }                                                                                                 \
        if (!SXD_BULK_CNTR_PORT_BITMAP_GET_TC(layout_port->mappings.counter_set_bitmap, ppcnt.prio_tc)) { \
            sxd_log_err("Bulk-Cntr PPCNT parser - unexpected traffic class %u\n", ppcnt.prio_tc);         \
            return;                                                                                       \
        }                                                                                                 \
        CHECK_RECEIVED_PPCNT_COUNT();                                                                     \
    } while (0)

#define GET_PPCNT_COUNTER_64(dst_struct_name, dst_field_name, src_struct_name, src_field_name)                \
    do {                                                                                                      \
        counter_64 = (((sxd_port_cntr_t)(ppcnt.counter_set.src_struct_name.src_field_name ## _high)) << 32) + \
                     ppcnt.counter_set.src_struct_name.src_field_name ## _low;                                \
        if (port_cntr_index != layout_port->counters_size) {                                                  \
            layout_port->counters[port_cntr_index].dst_struct_name.dst_field_name = counter_64;               \
        }                                                                                                     \
        if (lag_cntr_index != layout_port->counters_size) {                                                   \
            layout_port->counters[lag_cntr_index].dst_struct_name.dst_field_name += counter_64;               \
        }                                                                                                     \
    } while (0)

#define GET_PPCNT_COUNTER_64_PER_PRIO(dst_struct_name, dst_field_name, src_struct_name, src_field_name)        \
    do {                                                                                                       \
        counter_64 = (((sxd_port_cntr_t)(ppcnt.counter_set.src_struct_name.src_field_name ## _high)) << 32) +  \
                     ppcnt.counter_set.src_struct_name.src_field_name ## _low;                                 \
        if (port_cntr_index != layout_port->counters_size) {                                                   \
            layout_port->counters[port_cntr_index].dst_struct_name[ppcnt.prio_tc].dst_field_name = counter_64; \
        }                                                                                                      \
        if (lag_cntr_index != layout_port->counters_size) {                                                    \
            layout_port->counters[lag_cntr_index].dst_struct_name[ppcnt.prio_tc].dst_field_name += counter_64; \
        }                                                                                                      \
    } while (0)

#define GET_PPCNT_COUNTER_32(dst_struct_name, dst_field_name, src_struct_name, src_field_name)  \
    do {                                                                                        \
        counter_32 = ppcnt.counter_set.src_struct_name.src_field_name;                          \
        if (port_cntr_index != layout_port->counters_size) {                                    \
            layout_port->counters[port_cntr_index].dst_struct_name.dst_field_name = counter_32; \
        }                                                                                       \
        if (lag_cntr_index != layout_port->counters_size) {                                     \
            layout_port->counters[lag_cntr_index].dst_struct_name.dst_field_name += counter_32; \
        }                                                                                       \
    } while (0)

static void __ppcnt_parser(const void                                *ppcnt_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    int                                 ret = 0;
    struct ku_ppcnt_reg                 ppcnt;
    uint16_t                            lag_id;
    sxd_bulk_cntr_buffer_layout_port_t *layout_port = (sxd_bulk_cntr_buffer_layout_port_t*)layout_common;
    bool                                is_per_prio_marked;
    bool                                is_per_tc_marked;
    bool                                is_per_pg_marked;
    uint16_t                            port_cntr_index;
    uint16_t                            lag_cntr_index;
    sxd_port_cntr_t                     counter_64;
    sxd_port_cntr32_t                   counter_32;
    int                                 local_port = 0;

    memset(&ppcnt, 0, sizeof(ppcnt));

    if (reg_len < MLXSW_PPCNT_LEN) {
        sxd_log_err("Bulk-Cntr PPCNT parser - reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_PPCNT_LEN);
        return;
    }

    ret = __PPCNT_decode((u8*)ppcnt_reg, &ppcnt, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr PPCNT parser - failed to decode PPCNT\n");
        return;
    }

    SX_PORT_BUILD_PHY_ID_FROM_LSB_MSB(local_port,
                                      ppcnt.local_port,
                                      ppcnt.lp_msb);

    /* local_port range is [1 - MAX_PHYPORT_NUM] */
    if (local_port > MAX_PHYPORT_NUM) {
        sxd_log_err("Bulk-Cntr PPCNT parser - invalid local port %u\n", ppcnt.local_port);
        return;
    }

    port_cntr_index = layout_port->mappings.port_index_map[local_port];
    lag_id = layout_port->mappings.port_to_lag_map[local_port];
    if (lag_id != MAX_LAG_NUM) {
        lag_cntr_index = layout_port->mappings.lag_index_map[lag_id];
    } else {
        lag_cntr_index = layout_port->counters_size;
    }

    if ((port_cntr_index >= layout_port->counters_size) && (lag_cntr_index >= layout_port->counters_size)) {
        sxd_log_err("Bulk-Cntr PPCNT parser - unexpected local port %u\n", ppcnt.local_port);
        return;
    }

    switch (ppcnt.grp) {
    case SXD_PPCNT_GRP_IEEE_802_3_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_IEEE_802_DOT_3_E);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_frames_transmitted_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_frames_transmitted_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_frames_received_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_frames_received_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_frame_check_sequence_errors,
                             eth_802_3_cntrs_grp_data_layout,
                             a_frame_check_sequence_errors);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3, a_alignment_errors, eth_802_3_cntrs_grp_data_layout, a_alignment_errors);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_octets_transmitted_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_octets_transmitted_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_octets_received_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_octets_received_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_multicast_frames_xmitted_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_multicast_frames_xmitted_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_broadcast_frames_xmitted_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_broadcast_frames_xmitted_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_multicast_frames_received_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_multicast_frames_received_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_broadcast_frames_recieved_ok,
                             eth_802_3_cntrs_grp_data_layout,
                             a_broadcast_frames_received_ok);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_in_range_length_errors,
                             eth_802_3_cntrs_grp_data_layout,
                             a_in_range_length_errors);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_out_of_range_length_field,
                             eth_802_3_cntrs_grp_data_layout,
                             a_out_of_range_length_field);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_frame_too_long_errors,
                             eth_802_3_cntrs_grp_data_layout,
                             a_frame_too_long_errors);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_symbol_error_during_carrier,
                             eth_802_3_cntrs_grp_data_layout,
                             a_symbol_error_during_carrier);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_mac_control_frames_transmitted,
                             eth_802_3_cntrs_grp_data_layout,
                             a_mac_control_frames_transmitted);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_mac_control_frames_received,
                             eth_802_3_cntrs_grp_data_layout,
                             a_mac_control_frames_received);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_unsupported_opcodes_received,
                             eth_802_3_cntrs_grp_data_layout,
                             a_unsupported_opcodes_received);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_pause_mac_ctrl_frames_received,
                             eth_802_3_cntrs_grp_data_layout,
                             a_pause_mac_ctrl_frames_received);
        GET_PPCNT_COUNTER_64(ieee_802_dot_3,
                             a_pause_mac_ctrl_frames_transmitted,
                             eth_802_3_cntrs_grp_data_layout,
                             a_pause_mac_ctrl_frames_transmitted);
        break;

    case SXD_PPCNT_GRP_RFC_2863_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_RFC_2863_E);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_octets, eth_2863_cntrs_grp_data_layout, if_in_octets);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_ucast_pkts, eth_2863_cntrs_grp_data_layout, if_in_ucast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_discards, eth_2863_cntrs_grp_data_layout, if_in_discards);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_errors, eth_2863_cntrs_grp_data_layout, if_in_errors);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_unknown_protos, eth_2863_cntrs_grp_data_layout, if_in_unknown_protos);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_octets, eth_2863_cntrs_grp_data_layout, if_out_octets);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_ucast_pkts, eth_2863_cntrs_grp_data_layout, if_out_ucast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_discards, eth_2863_cntrs_grp_data_layout, if_out_discards);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_errors, eth_2863_cntrs_grp_data_layout, if_out_errors);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_multicast_pkts, eth_2863_cntrs_grp_data_layout, if_in_multicast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2863, if_in_broadcast_pkts, eth_2863_cntrs_grp_data_layout, if_in_broadcast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_multicast_pkts, eth_2863_cntrs_grp_data_layout, if_out_multicast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2863, if_out_broadcast_pkts, eth_2863_cntrs_grp_data_layout, if_out_broadcast_pkts);
        break;

    case SXD_PPCNT_GRP_RFC_2819_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_RFC_2819_E);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_drop_events, eth_2819_cntrs_grp_data_layout,
                             ether_stats_drop_events);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_octets, eth_2819_cntrs_grp_data_layout, ether_stats_octets);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_pkts, eth_2819_cntrs_grp_data_layout, ether_stats_pkts);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_broadcast_pkts,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_broadcast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_multicast_pkts,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_multicast_pkts);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_crc_align_errors,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_crc_align_errors);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_undersize_pkts,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_undersize_pkts);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_oversize_pkts,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_oversize_pkts);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_fragments, eth_2819_cntrs_grp_data_layout, ether_stats_fragments);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_jabbers, eth_2819_cntrs_grp_data_layout, ether_stats_jabbers);
        GET_PPCNT_COUNTER_64(rfc_2819, ether_stats_collisions, eth_2819_cntrs_grp_data_layout, ether_stats_collisions);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts64octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts64octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts65to127octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts65to127octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts128to255octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts128to255octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts256to511octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts256to511octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts512to1023octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts512to1023octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts1024to1518octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts1024to1518octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts1519to2047octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts1519to2047octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts2048to4095octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts2048to4095octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts4096to8191octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts4096to8191octets);
        GET_PPCNT_COUNTER_64(rfc_2819,
                             ether_stats_pkts8192to10239octets,
                             eth_2819_cntrs_grp_data_layout,
                             ether_stats_pkts8192to10239octets);
        break;

    case SXD_PPCNT_GRP_RFC_3635_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_RFC_3635_E);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_alignment_errors,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_alignment_errors);
        GET_PPCNT_COUNTER_64(rfc_3635, dot3stats_fcs_errors, eth_3635_cntrs_grp_data_layout, dot3stats_fcs_errors);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_single_collision_frames,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_single_collision_frames);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_multiple_collision_frames,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_multiple_collision_frames);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_sqe_test_errors,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_sqe_test_errors);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_deferred_transmissions,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_deferred_transmissions);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_late_collisions,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_late_collisions);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_excessive_collisions,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_excessive_collisions);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_internal_mac_transmit_errors,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_internal_mac_transmit_errors);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_carrier_sense_errors,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_carrier_sense_errors);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_frame_too_longs,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_frame_too_longs);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3stats_internal_mac_receive_errors,
                             eth_3635_cntrs_grp_data_layout,
                             dot3stats_internal_mac_receive_errors);
        GET_PPCNT_COUNTER_64(rfc_3635, dot3stats_symbol_errors, eth_3635_cntrs_grp_data_layout,
                             dot3stats_symbol_errors);
        GET_PPCNT_COUNTER_64(rfc_3635,
                             dot3control_in_unknown_opcodes,
                             eth_3635_cntrs_grp_data_layout,
                             dot3control_in_unknown_opcodes);
        GET_PPCNT_COUNTER_64(rfc_3635, dot3in_pause_frames, eth_3635_cntrs_grp_data_layout, dot3in_pause_frames);
        GET_PPCNT_COUNTER_64(rfc_3635, dot3out_pause_frames, eth_3635_cntrs_grp_data_layout, dot3out_pause_frames);
        break;

    case SXD_PPCNT_GRP_PER_PRIORITY_COUNTERS_E:
        if (ppcnt.prio_tc > SXD_PORT_PRIO_ID_MAX) {
            sxd_log_err("Bulk-Cntr PPCNT parser - invalid priority %u\n", ppcnt.prio_tc);
            return;
        }
        is_per_prio_marked =
            SXD_BULK_CNTR_PORT_BITMAP_GET_PRIO(layout_port->mappings.counter_set_bitmap, ppcnt.prio_tc);
        is_per_tc_marked = (ppcnt.prio_tc <= SXD_PORT_TC_ID_MAX) && SXD_BULK_CNTR_PORT_BITMAP_GET_TC(
            layout_port->mappings.counter_set_bitmap,
            ppcnt.prio_tc);
        is_per_pg_marked = (ppcnt.prio_tc < SXD_PRIORITY_GROUP_NUM) && SXD_BULK_CNTR_PORT_BITMAP_GET_PG(
            layout_port->mappings.counter_set_bitmap,
            ppcnt.prio_tc);
        if ((!is_per_prio_marked) && (!is_per_tc_marked) && (!is_per_pg_marked)) {
            sxd_log_err("Bulk-Cntr PPCNT parser - unexpected priority %u\n", ppcnt.prio_tc);
            return;
        }
        CHECK_RECEIVED_PPCNT_COUNT();

        if (is_per_prio_marked) {
            GET_PPCNT_COUNTER_64_PER_PRIO(prio, tx_pause, eth_per_prio_grp_data_layout, tx_pause);
            GET_PPCNT_COUNTER_64_PER_PRIO(prio, rx_pause, eth_per_prio_grp_data_layout, rx_pause);
            GET_PPCNT_COUNTER_64_PER_PRIO(prio,
                                          tx_pause_duration,
                                          eth_per_prio_grp_data_layout,
                                          tx_pause_duration);
            GET_PPCNT_COUNTER_64_PER_PRIO(prio,
                                          rx_pause_duration,
                                          eth_per_prio_grp_data_layout,
                                          rx_pause_duration);
        }

        if (is_per_tc_marked) {
            GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_octet, eth_per_prio_grp_data_layout, tx_octets);
            GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_frames, eth_per_prio_grp_data_layout, tx_frames);
        }

        if (is_per_pg_marked) {
            GET_PPCNT_COUNTER_64_PER_PRIO(pg, rx_octet, eth_per_prio_grp_data_layout, rx_octets);
            GET_PPCNT_COUNTER_64_PER_PRIO(pg, rx_frames, eth_per_prio_grp_data_layout, rx_frames);
            GET_PPCNT_COUNTER_64_PER_PRIO(pg, rx_buffer_discard, eth_per_prio_grp_data_layout, rx_discards);
        }

        break;

    case SXD_PPCNT_GRP_PER_TRAFFIC_CLASS_COUNTERS_E:
        CHECK_PPCNT_TC_GRP_AND_COUNT();
        GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_queue, eth_per_traffic_class_layout, transmit_queue);
        GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_no_buffer_discard_uc, eth_per_traffic_class_layout, no_buffer_discard_uc);
        break;

    case SXD_PPCNT_GRP_PER_TRAFFIC_CLASS_CONGESTION_COUNTERS_E:
        CHECK_PPCNT_TC_GRP_AND_COUNT();
        GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_wred_discard, eth_per_traffic_class_cong_layout, wred_discard);
        GET_PPCNT_COUNTER_64_PER_PRIO(tc, tx_ecn_marked_tc, eth_per_traffic_class_cong_layout, ecn_marked_tc);
        break;

    case SXD_PPCNT_GRP_ETHERNET_EXTENDED_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_PERF_E);
        GET_PPCNT_COUNTER_64(perf, tx_wait, eth_extended_cntrs_grp_data_layout, port_transmit_wait);
        GET_PPCNT_COUNTER_64(perf, ecn_marked, eth_extended_cntrs_grp_data_layout, ecn_marked);
        GET_PPCNT_COUNTER_64(perf, no_buffer_discard_mc, eth_extended_cntrs_grp_data_layout, no_buffer_discard_mc);
        GET_PPCNT_COUNTER_64(perf, rx_ebp, eth_extended_cntrs_grp_data_layout, rx_ebp);
        GET_PPCNT_COUNTER_64(perf, tx_ebp, eth_extended_cntrs_grp_data_layout, tx_ebp);
        GET_PPCNT_COUNTER_64(perf, rx_buffer_almost_full, eth_extended_cntrs_grp_data_layout, rx_buffer_almost_full);
        GET_PPCNT_COUNTER_64(perf, rx_buffer_full, eth_extended_cntrs_grp_data_layout, rx_buffer_full);
        GET_PPCNT_COUNTER_64(perf, tx_stats_pkts64octets, eth_extended_cntrs_grp_data_layout, tx_stats_pkts64octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts65to127octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts65to127octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts128to255octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts128to255octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts256to511octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts256to511octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts512to1023octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts512to1023octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts1024to1518octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts1024to1518octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts1519to2047octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts1519to2047octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts2048to4095octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts2048to4095octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts4096to8191octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts4096to8191octets);
        GET_PPCNT_COUNTER_64(perf,
                             tx_stats_pkts8192to10239octets,
                             eth_extended_cntrs_grp_data_layout,
                             tx_stats_pkts8192to10239octets);
        GET_PPCNT_COUNTER_64(perf,
                             ece_marked,
                             eth_extended_cntrs_grp_data_layout,
                             ece_marked);
        GET_PPCNT_COUNTER_64(perf,
                             tx_int_cksm_err,
                             eth_extended_cntrs_grp_data_layout,
                             tx_int_cksm_err);
        break;

    case SXD_PPCNT_GRP_ETHERNET_DISCARD_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_DISCARD_E);
        GET_PPCNT_COUNTER_64(discard, ingress_general, eth_discard_cntrs_grp, ingress_general);
        GET_PPCNT_COUNTER_64(discard, ingress_policy_engine, eth_discard_cntrs_grp, ingress_policy_engine);
        GET_PPCNT_COUNTER_64(discard, ingress_vlan_membership, eth_discard_cntrs_grp, ingress_vlan_membership);
        GET_PPCNT_COUNTER_64(discard, ingress_tag_frame_type, eth_discard_cntrs_grp, ingress_tag_frame_type);
        GET_PPCNT_COUNTER_64(discard, egress_vlan_membership, eth_discard_cntrs_grp, egress_vlan_membership);
        GET_PPCNT_COUNTER_64(discard, loopback_filter, eth_discard_cntrs_grp, loopback_filter);
        GET_PPCNT_COUNTER_64(discard, egress_general, eth_discard_cntrs_grp, egress_general);
        GET_PPCNT_COUNTER_64(discard, egress_hoq, eth_discard_cntrs_grp, egress_hoq);
        GET_PPCNT_COUNTER_64(discard, port_isolation, eth_discard_cntrs_grp, port_isolation);
        GET_PPCNT_COUNTER_64(discard, egress_policy_engine, eth_discard_cntrs_grp, egress_policy_engine);
        GET_PPCNT_COUNTER_64(discard, ingress_tx_link_down, eth_discard_cntrs_grp, ingress_tx_link_down);
        GET_PPCNT_COUNTER_64(discard, egress_stp_filter, eth_discard_cntrs_grp, egress_stp_filter);
        GET_PPCNT_COUNTER_64(discard, egress_hoq_stall, eth_discard_cntrs_grp, egress_hoq_stall);
        GET_PPCNT_COUNTER_64(discard, egress_sll, eth_discard_cntrs_grp, egress_sll);
        GET_PPCNT_COUNTER_64(discard, ingress_discard_all, eth_discard_cntrs_grp, ingress_discard_all);
        break;

    case SXD_PPCNT_GRP_PHYSICAL_LAYER_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_PHY_LAYER_E);
        GET_PPCNT_COUNTER_64(phy_layer, time_since_last_clear, phys_layer_cntrs, time_since_last_clear);
        GET_PPCNT_COUNTER_64(phy_layer, symbol_errors, phys_layer_cntrs, symbol_errors);
        GET_PPCNT_COUNTER_64(phy_layer, sync_headers_errors, phys_layer_cntrs, sync_headers_errors);
        GET_PPCNT_COUNTER_64(phy_layer, edpl_bip_errors_lane0, phys_layer_cntrs, edpl_bip_errors_lane0);
        GET_PPCNT_COUNTER_64(phy_layer, edpl_bip_errors_lane1, phys_layer_cntrs, edpl_bip_errors_lane1);
        GET_PPCNT_COUNTER_64(phy_layer, edpl_bip_errors_lane2, phys_layer_cntrs, edpl_bip_errors_lane2);
        GET_PPCNT_COUNTER_64(phy_layer, edpl_bip_errors_lane3, phys_layer_cntrs, edpl_bip_errors_lane3);
        GET_PPCNT_COUNTER_64(phy_layer, fc_fec_corrected_blocks_lane0, phys_layer_cntrs,
                             fc_fec_corrected_blocks_lane0);
        GET_PPCNT_COUNTER_64(phy_layer, fc_fec_corrected_blocks_lane1, phys_layer_cntrs,
                             fc_fec_corrected_blocks_lane1);
        GET_PPCNT_COUNTER_64(phy_layer, fc_fec_corrected_blocks_lane2, phys_layer_cntrs,
                             fc_fec_corrected_blocks_lane2);
        GET_PPCNT_COUNTER_64(phy_layer, fc_fec_corrected_blocks_lane3, phys_layer_cntrs,
                             fc_fec_corrected_blocks_lane3);
        GET_PPCNT_COUNTER_64(phy_layer,
                             fc_fec_uncorrectable_blocks_lane0,
                             phys_layer_cntrs,
                             fc_fec_uncorrectable_blocks_lane0);
        GET_PPCNT_COUNTER_64(phy_layer,
                             fc_fec_uncorrectable_blocks_lane1,
                             phys_layer_cntrs,
                             fc_fec_uncorrectable_blocks_lane1);
        GET_PPCNT_COUNTER_64(phy_layer,
                             fc_fec_uncorrectable_blocks_lane2,
                             phys_layer_cntrs,
                             fc_fec_uncorrectable_blocks_lane2);
        GET_PPCNT_COUNTER_64(phy_layer,
                             fc_fec_uncorrectable_blocks_lane3,
                             phys_layer_cntrs,
                             fc_fec_uncorrectable_blocks_lane3);
        GET_PPCNT_COUNTER_64(phy_layer, rs_fec_corrected_blocks, phys_layer_cntrs, rs_fec_corrected_blocks);
        GET_PPCNT_COUNTER_64(phy_layer, rs_fec_uncorrectable_blocks, phys_layer_cntrs, rs_fec_uncorrectable_blocks);
        GET_PPCNT_COUNTER_64(phy_layer, rs_fec_no_errors_blocks, phys_layer_cntrs, rs_fec_no_errors_blocks);
        GET_PPCNT_COUNTER_64(phy_layer, rs_fec_single_error_blocks, phys_layer_cntrs, rs_fec_single_error_blocks);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_total,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_total);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane0,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane0);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane1,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane1);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane2,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane2);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane3,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane3);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane4,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane4);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane5,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane5);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane6,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane6);
        GET_PPCNT_COUNTER_64(phy_layer,
                             rs_fec_corrected_symbols_lane7,
                             phys_layer_cntrs,
                             rs_fec_corrected_symbols_lane7);
        GET_PPCNT_COUNTER_32(phy_layer, link_down_events, phys_layer_cntrs, link_down_events);
        GET_PPCNT_COUNTER_32(phy_layer, successful_recovery_events, phys_layer_cntrs, successful_recovery_events);
        break;

    case SXD_PPCNT_GRP_PHYSICAL_LAYER_STATISTICAL_COUNTERS_E:
        CHECK_PPCNT_GRP_AND_COUNT(SXD_BULK_CNTR_PORT_GRP_PHY_LAYER_STATS_E);
        GET_PPCNT_COUNTER_64(phy_layer_stats, time_since_last_clear, phys_layer_stat_cntrs, time_since_last_clear);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_received_bits, phys_layer_stat_cntrs, phy_received_bits);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_symbol_errors, phys_layer_stat_cntrs, phy_symbol_errors);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_corrected_bits, phys_layer_stat_cntrs, phy_corrected_bits);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane0, phys_layer_stat_cntrs, phy_raw_errors_lane0);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane1, phys_layer_stat_cntrs, phy_raw_errors_lane1);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane2, phys_layer_stat_cntrs, phy_raw_errors_lane2);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane3, phys_layer_stat_cntrs, phy_raw_errors_lane3);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane4, phys_layer_stat_cntrs, phy_raw_errors_lane4);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane5, phys_layer_stat_cntrs, phy_raw_errors_lane5);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane6, phys_layer_stat_cntrs, phy_raw_errors_lane6);
        GET_PPCNT_COUNTER_64(phy_layer_stats, phy_raw_errors_lane7, phys_layer_stat_cntrs, phy_raw_errors_lane7);
        GET_PPCNT_COUNTER_32(phy_layer_stats, raw_ber_magnitude, phys_layer_stat_cntrs, raw_ber_magnitude);
        GET_PPCNT_COUNTER_32(phy_layer_stats, raw_ber_coef, phys_layer_stat_cntrs, raw_ber_coef);
        GET_PPCNT_COUNTER_32(phy_layer_stats, effective_ber_magnitude, phys_layer_stat_cntrs, effective_ber_magnitude);
        GET_PPCNT_COUNTER_32(phy_layer_stats, effective_ber_coef, phys_layer_stat_cntrs, effective_ber_coef);
        break;

    default:
        sxd_log_err("Bulk-Cntr PPCNT parser - unexpected PPCNT group %u\n", ppcnt.grp);
        return;
    }

    layout_common->counters_received_so_far++;
}


void sx_bulk_cntr_handle_ppcnt(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __ppcnt_parser, NULL);
}


/***************************************************************************************
 * MGPCB
 *
 *       31                       24                       16                       8                        0
 *       +------------------------+------------------------+------------------------+------------------------+
 * 000h  |                        |                            counter_index_base                            |
 *       +------------------------+------------------------+------------------------+------------------------+
 * 004h  |                                                                          |         num_rec        |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 008h  |                                                                                       |  opcode   |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 00ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 010h  |                                        record[0].byte_counter                                     |
 * 014h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 018h  |                                        record[0].packet_counter                                   |
 * 01ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *       .
 *       .
 *       .
 *       +---------------------------------------------------------------------------------------------------+
 * 400h  |                                        record[63].byte_counter                                    |
 * 404h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 408h  |                                        record[63].packet_counter                                  |
 * 40ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *
 */


static void __mgpcb_parser(const void                                *mgpcb_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    int                                      ret = 0;
    struct ku_mgpcb_reg                      mgpcb;
    struct sxd_bulk_cntr_buffer_layout_flow *layout_flow = (struct sxd_bulk_cntr_buffer_layout_flow*)layout_common;
    u32                                      counter_base_index;
    u32                                      i, index_to_buff;

    if (reg_len < MLXSW_MGPCB_LEN) {
        sxd_log_err("MGPCB parse: reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_MGPCB_LEN);
        return;
    }

    ret = __MGPCB_decode((u8*)mgpcb_reg, &mgpcb, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr MGPCB parser - failed to decode MGPCB\n");
        return;
    }

    counter_base_index = mgpcb.counter_index_base;
    index_to_buff = (counter_base_index - layout_flow->base_counter_id) / 2; /* counter indexes increment by 2 */

    for (i = 0; i < mgpcb.num_rec; i++) {
        layout_flow->counters[index_to_buff + i].flow_counter_bytes = mgpcb.record[i].byte_counter;
        layout_flow->counters[index_to_buff + i].flow_counter_packets = mgpcb.record[i].packet_counter;
        if (layout_common->counters_received_so_far == layout_common->num_of_counters) {
            sxd_log_err("MGPCB parse: got more counters than required\n");
            break;
        }

        layout_common->counters_received_so_far++;
    }
}

void sx_bulk_cntr_handle_mgpcb(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __mgpcb_parser, NULL);
}

/***************************************************************************************
 * MOFRB
 *
 *       31                       24                       16                       8                        0
 *       +------------------------+------------------------+------------------------+------------------------+
 * 000h  |clear                   |                                            |      num_rec                |
 *       +------------------------+------------------------+------------------------+------------------------+
 * 004h  |                                                               counter_index_base                  |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 008h  |                                                                                                   |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 00ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 010h  |  flow_estimator_bin[0]   flow_estimator_bin[1]    flow_estimator_bin[2]   flow_estimator_bin[3]   |
 *       +---------------------------------------------------------------------------------------------------+
 * 014h  |  flow_estimator_bin[4]   flow_estimator_bin[5]    flow_estimator_bin[6]   flow_estimator_bin[7]   |
 *       +---------------------------------------------------------------------------------------------------+
 *       .
 *       .
 *       .
 *       +---------------------------------------------------------------------------------------------------+
 * 20ch  | flow_estimator_bin[508]  flow_estimator_bin[509] flow_estimator_bin[510]  flow_estimator_bin[511] |
 *       +---------------------------------------------------------------------------------------------------+
 *
 */

/*
 *  1) do "layout_common->counters_received_so_far++;"
 *  2) make sure this is flow_estimator_bin, need x/4 or x/2 to match flow counters in sx_api_bulk_counter_transaction_get
 */
struct mofrb_reg {
    u8  clear;
    u8  reserved1;
    u16 num_rec;
    u32 counter_index_base;
    u32 reserved2[2];
    u8  flow_estimator_bin[SXD_MOFRB_FLOW_ESTIMATOR_BIN_NUM];
};
static void __mofrb_parser(const void                                *mofrb_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    struct ku_mofrb_reg                                mofrb;
    struct sxd_bulk_cntr_buffer_layout_flow_estimator *layout_flow =
        (struct sxd_bulk_cntr_buffer_layout_flow_estimator*)layout_common;
    u32 num_rec = 0;
    u32 expected_reg_len = 0;
    u32 counter_base_index = 0;
    u32 i = 0;
    u32 count_set_idx = 0;
    int ret = 0;

    ret = __MOFRB_decode((u8*)mofrb_reg, &mofrb, context);
    if (ret != 0) {
        sxd_log_err("Failed to decode PBSR\n");
        goto out;
    }

    num_rec = mofrb.num_rec & 0x7ff;
    if (num_rec % FLOW_ESTIMATOR_BINS_PER_FLOW_COUNTER != 0) {
        sxd_log_err("%s: mofrb num_rec (%u) is not 4 aligned\n", __func__, num_rec);
        goto out;
    }

    expected_reg_len = sizeof(struct mofrb_reg);
    if (reg_len != expected_reg_len) {
        sxd_log_err("MOFRB parse: reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, expected_reg_len);
        goto out;
    }

    counter_base_index = mofrb.counter_index_base & 0xffffff;
    if (counter_base_index != layout_flow->base_counter_id) {
        sxd_log_err("%s: mofrb base idx (%u) mis-match save base_idx (%u)\n",
                    __func__,
                    counter_base_index,
                    layout_flow->base_counter_id);
        goto out;
    }

    count_set_idx = 0;
    for (i = 0; i < num_rec; i++) {
        layout_flow->counter_sets[count_set_idx].flow_estimator_records[i %
                                                                        FLOW_ESTIMATOR_BINS_PER_FLOW_COUNTER] =
            mofrb.flow_estimator_bin[i];
        if ((i + 1) % FLOW_ESTIMATOR_BINS_PER_FLOW_COUNTER == 0) {
            count_set_idx++;
            if (layout_common->counters_received_so_far == layout_common->num_of_counters) {
                sxd_log_err("MGPCB parse: got more counters than required\n");
                break;
            }
            layout_common->counters_received_so_far++;
        }
    }

out:
    return;
}

void sx_bulk_cntr_handle_mofrb(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __mofrb_parser, NULL);
}

/***************************************************************************************
 * PBSR
 *
 *       31                       24                       16                       8                        0
 *       +------------------------+------------------------+------------------------+------------------------+
 * 000h  |                        |    local_port          |                        |                   |type|
 *       +------------------------+------------------------+------------------------+------------------------+
 * 004h  |                                                                                                   |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 008h  |                                                 |       used_shared_headroom_buffer               |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 00ch  |                                        stat_buffer[0]                                             |
 * 010h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 018h  |                                        stat_buffer[1]                                             |
 * 01ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *       .
 *       .
 *       .
 *       +---------------------------------------------------------------------------------------------------+
 * 054h  |                                        stat_buffer[9]                                             |
 * 058h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 05ch  |                                        shared_buffer_status                                       |
 * 060h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *
 */

static void __calculate_headroom(struct sxd_bulk_cntr_buffer_layout_headroom *layout_headroom,
                                 const struct ku_pbsr_reg                    *pbsr,
                                 u16                                          port_idx,
                                 u8                                           is_8xlane,
                                 u8                                           is_slave)
{
    u8 i = 0, cnt = 0, idx = 0;

    if (is_8xlane) {
        cnt = 2;
    } else {
        cnt = 1;
    }

    if (is_slave) {
        idx = 1;
    } else {
        layout_headroom->headroom[port_idx].shared_headroom_usage.curr_occupancy = be16_to_cpu(
            pbsr->used_shared_headroom_buffer);
        layout_headroom->headroom[port_idx].shared_headroom_usage.watermark = 0;
        idx = 0;
    }

    layout_headroom->headroom[port_idx].shared.statistics.curr_occupancy +=
        pbsr->stat_shared_headroom_pool.used_buffer;
    layout_headroom->headroom[port_idx].shared.statistics.watermark +=
        pbsr->stat_shared_headroom_pool.watermark;
    layout_headroom->headroom[port_idx].shared.occupancy_statistics_lst.cnt = cnt;
    layout_headroom->headroom[port_idx].shared.occupancy_statistics_lst.statistics[idx].curr_occupancy =
        pbsr->stat_shared_headroom_pool.used_buffer;
    layout_headroom->headroom[port_idx].shared.occupancy_statistics_lst.statistics[idx].watermark =
        pbsr->stat_shared_headroom_pool.watermark;

    for (i = 0; i < SXD_BULK_CNTR_PG_NUM; i++) {
        layout_headroom->headroom[port_idx].port_pg[i].statistics.curr_occupancy +=
            pbsr->stat_buffer[i].used_buffer;
        layout_headroom->headroom[port_idx].port_pg[i].statistics.watermark +=
            pbsr->stat_buffer[i].watermark;
        layout_headroom->headroom[port_idx].port_pg[i].occupancy_statistics_lst.cnt = cnt;
        layout_headroom->headroom[port_idx].port_pg[i].occupancy_statistics_lst.statistics[idx].curr_occupancy =
            pbsr->stat_buffer[i].used_buffer;
        layout_headroom->headroom[port_idx].port_pg[i].occupancy_statistics_lst.statistics[idx].watermark =
            pbsr->stat_buffer[i].watermark;
    }

    return;
}

static void __pbsr_parser(const void                                *pbsr_reg,
                          u32                                        reg_len,
                          struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                          void                                      *context)
{
    struct ku_pbsr_reg                           pbsr;
    struct sxd_bulk_cntr_buffer_layout_headroom *layout_headroom =
        (struct sxd_bulk_cntr_buffer_layout_headroom*)layout_common;
    int ret = 0;
    u8  buffer_type;
    u16 local_port, port_idx;

    ret = __PBSR_decode((u8*)pbsr_reg, &pbsr, context);
    if (ret != 0) {
        sxd_log_err("Failed to decode PBSR\n");
        return;
    }

    buffer_type = pbsr.buffer_type;

    SX_PORT_BUILD_PHY_ID_FROM_LSB_MSB(local_port,
                                      pbsr.local_port,
                                      pbsr.lp_msb);

    port_idx = local_port - 1;

    if (layout_headroom->port_width[port_idx] != 8) {
        __calculate_headroom(layout_headroom, &pbsr, port_idx, 0, 0);
    } else {
        if (buffer_type == SXD_BULK_CNTR_HEADROOM_BUFFER_TYPE_MASTER_E) {
            __calculate_headroom(layout_headroom, &pbsr, port_idx, 1, 0);
        }

        if (buffer_type == SXD_BULK_CNTR_HEADROOM_BUFFER_TYPE_SLAVE_E) {
            __calculate_headroom(layout_headroom, &pbsr, port_idx, 1, 1);
        }
    }

    if (layout_common->counters_received_so_far == layout_common->num_of_counters) {
        sxd_log_err("PBSR parse: got more counters than required\n");
        return;
    }

    layout_common->counters_received_so_far++;

    return;
}

void sx_bulk_cntr_handle_pbsr(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __pbsr_parser, NULL);
}


/***************************************************************************************
 * SBSRD
 *
 *       31                       24                       16                       8                        0
 *       +------------------------+------------------------+------------------------+------------------------+
 * 000h  | s|d                                                                      |         type           |
 *       +------------------------+------------------------+------------------------+------------------------+
 * 004h  |                                                                          |         num_rec        |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 008h  |            first_entry_index                    |                       |    first_local_port     |
 *       +------------------------+------------------------+------------------------+------------+-----------+
 * 00ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 010h  |                                        shared_buffer_status[0]                                    |
 * 014h  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 * 018h  |                                        shared_buffer_status[1]                                    |
 * 01ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *       .
 *       .
 *       .
 *       +---------------------------------------------------------------------------------------------------+
 * 408h  |                                        shared_buffer_status[127]                                  |
 * 40ch  |                                                                                                   |
 *       +---------------------------------------------------------------------------------------------------+
 *
 */

static void __sbsrd_parser(const void                                *sbsrd_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    struct ku_sbsrd_reg                               sbsrd;
    struct sxd_bulk_cntr_buffer_layout_shared_buffer *layout_shared_buffer =
        (struct sxd_bulk_cntr_buffer_layout_shared_buffer*)layout_common;
    int ret = 0;
    u32 i = 0, idx = 0, sw_pool_id = 0, num_rec = 0;
    u8  type = 0, desc = 0;
    u32 port_idx = layout_shared_buffer->port_idx;
    u8  pg_tc_sp_idx = layout_shared_buffer->pg_tc_sp_idx;
    u8  port_pool_idx = layout_shared_buffer->port_pool_idx;
    u8  pool_idx = layout_shared_buffer->pool_idx;
    u8  last_type = layout_shared_buffer->last_type;

    ret = __SBSRD_decode((u8*)sbsrd_reg, &sbsrd, context);
    if (ret != 0) {
        sxd_log_err("Failed to decode SBSRD\n");
        return;
    }

    type = sbsrd.type;
    desc = sbsrd.desc;
    num_rec = sbsrd.num_rec;

    if (type != last_type) {
        port_idx = 0;
        pg_tc_sp_idx = 0;
        port_pool_idx = 0;
    }

    for (i = 0; i < num_rec; i++) {
        switch (type) {
        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_RX_PG_E:
            if (port_idx == SXD_BULK_CNTR_PORT_NUM) {
                sxd_log_err("SBSRD parse: got too many number of rx_pg record.\n");
                return;
            }

            if (desc == 0) {
                layout_shared_buffer->port[port_idx].rx_pg[pg_tc_sp_idx].curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->port[port_idx].rx_pg[pg_tc_sp_idx].watermark =
                    sbsrd.shared_buffer_status[i].max_buff_occupancy;
            } else {
                layout_shared_buffer->port[port_idx].rx_pg_desc[pg_tc_sp_idx].curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->port[port_idx].rx_pg_desc[pg_tc_sp_idx].watermark =
                    sbsrd.shared_buffer_status[i].max_buff_occupancy;
            }

            pg_tc_sp_idx++;
            if (pg_tc_sp_idx == SXD_BULK_CNTR_PG_NUM) {
                port_idx++;
                pg_tc_sp_idx = 0;
            }

            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_TX_TC_E:
            if (port_idx == SXD_BULK_CNTR_PORT_NUM) {
                sxd_log_err("SBSRD parse: got too many number of tx_tc record.\n");
                return;
            }

            if (desc == 0) {
                layout_shared_buffer->port[port_idx].tx_tc[pg_tc_sp_idx].curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->port[port_idx].tx_tc[pg_tc_sp_idx].watermark =
                    sbsrd.shared_buffer_status[i].max_buff_occupancy;
            } else {
                layout_shared_buffer->port[port_idx].tx_tc_desc[pg_tc_sp_idx].curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->port[port_idx].tx_tc_desc[pg_tc_sp_idx].watermark =
                    sbsrd.shared_buffer_status[i].max_buff_occupancy;
            }

            pg_tc_sp_idx++;
            if (pg_tc_sp_idx == SXD_BULK_CNTR_TC_NUM) {
                port_idx++;
                pg_tc_sp_idx = 0;
            }

            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_RX_PER_POOL_E:
            if (port_idx == SXD_BULK_CNTR_PORT_NUM) {
                sxd_log_err("SBSRD parse: got too many number of rx_per_pool record.\n");
                return;
            }
            /* The index is in order by direction (ingress/egress) and then by buffer type (data/descriptor),
             * So the first 16 (pool number) are for data ingress, the second 16 are for data egress,
             * the third one are for descriptor ingress, the fourth are for descriptor egress */
            idx = pg_tc_sp_idx + (SXD_BULK_CNTR_POOL_NUM * 2) * desc;
            sw_pool_id = layout_shared_buffer->sw_pool_id[idx];
            if (sw_pool_id != SXD_BULK_CNTR_POOL_ID_INVALID) {
                if (desc == 0) {
                    layout_shared_buffer->port[port_idx].rx_per_pool[port_pool_idx].sw_pool_id = sw_pool_id;
                    layout_shared_buffer->port[port_idx].rx_per_pool[port_pool_idx].occupancy.curr_occupancy =
                        sbsrd.shared_buffer_status[i].buff_occupancy;
                    layout_shared_buffer->port[port_idx].rx_per_pool[port_pool_idx].occupancy.watermark =
                        sbsrd.shared_buffer_status[i].max_buff_occupancy;
                } else {
                    layout_shared_buffer->port[port_idx].rx_per_pool_desc[port_pool_idx].sw_pool_id = sw_pool_id;
                    layout_shared_buffer->port[port_idx].rx_per_pool_desc[port_pool_idx].occupancy.curr_occupancy =
                        sbsrd.shared_buffer_status[i].buff_occupancy;
                    layout_shared_buffer->port[port_idx].rx_per_pool_desc[port_pool_idx].occupancy.watermark =
                        sbsrd.shared_buffer_status[i].max_buff_occupancy;
                }
                port_pool_idx++;
            }

            pg_tc_sp_idx++;
            if (pg_tc_sp_idx == SXD_BULK_CNTR_POOL_NUM) {
                port_idx++;
                pg_tc_sp_idx = 0;
                port_pool_idx = 0;
            }

            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_TX_PER_POOL_E:
            if (port_idx == SXD_BULK_CNTR_PORT_NUM) {
                sxd_log_err("SBSRD parse: got too many number of tx_per_pool record.\n");
                return;
            }
            /* The index is in order by direction (ingress/egress) and then by buffer type (data/descriptor),
             * So the first 16 (pool num) are for data ingress, the second 16 are for data egress,
             * the third one are for descriptor ingress, the fourth are for descriptor egress */
            idx = pg_tc_sp_idx + SXD_BULK_CNTR_POOL_NUM + (SXD_BULK_CNTR_POOL_NUM * 2) * desc;
            sw_pool_id = layout_shared_buffer->sw_pool_id[idx];
            if (sw_pool_id != SXD_BULK_CNTR_POOL_ID_INVALID) {
                if (desc == 0) {
                    if (sw_pool_id == layout_shared_buffer->mc_pool_id) {
                        layout_shared_buffer->mc_port[port_idx].occupancy.curr_occupancy =
                            sbsrd.shared_buffer_status[i].buff_occupancy;
                        layout_shared_buffer->mc_port[port_idx].occupancy.watermark =
                            sbsrd.shared_buffer_status[i].max_buff_occupancy;
                    } else {
                        layout_shared_buffer->port[port_idx].tx_per_pool[port_pool_idx].sw_pool_id = sw_pool_id;
                        layout_shared_buffer->port[port_idx].tx_per_pool[port_pool_idx].occupancy.curr_occupancy =
                            sbsrd.shared_buffer_status[i].buff_occupancy;
                        layout_shared_buffer->port[port_idx].tx_per_pool[port_pool_idx].occupancy.watermark =
                            sbsrd.shared_buffer_status[i].max_buff_occupancy;
                    }
                } else {
                    layout_shared_buffer->port[port_idx].tx_per_pool_desc[port_pool_idx].sw_pool_id = sw_pool_id;
                    layout_shared_buffer->port[port_idx].tx_per_pool_desc[port_pool_idx].occupancy.curr_occupancy =
                        sbsrd.shared_buffer_status[i].buff_occupancy;
                    layout_shared_buffer->port[port_idx].tx_per_pool_desc[port_pool_idx].occupancy.watermark =
                        sbsrd.shared_buffer_status[i].max_buff_occupancy;
                }
                port_pool_idx++;
            }

            pg_tc_sp_idx++;
            if (pg_tc_sp_idx == SXD_BULK_CNTR_POOL_NUM) {
                port_idx++;
                pg_tc_sp_idx = 0;
                port_pool_idx = 0;
            }
            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_MC_SWITH_PRIO_E:
            if (pg_tc_sp_idx == SXD_BULK_CNTR_SP_NUM) {
                sxd_log_err("SBSRD parse: got too many number of mc_switch_prio record.\n");
                return;
            }
            layout_shared_buffer->mc_switch_prio.statistics[pg_tc_sp_idx].curr_occupancy =
                sbsrd.shared_buffer_status[i].buff_occupancy;
            layout_shared_buffer->mc_switch_prio.statistics[pg_tc_sp_idx].watermark =
                sbsrd.shared_buffer_status[i].max_buff_occupancy;
            pg_tc_sp_idx++;
            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_RX_POOL_E:
            if (pg_tc_sp_idx == SXD_BULK_CNTR_POOL_NUM) {
                sxd_log_err("SBSRD parse: got too many number of tc_pool record.\n");
                return;
            }
            /* The index is in order by direction (ingress/egress) and then by buffer type (data/descriptor),
             * So the first 16 (pool num) are for data ingress, the second 16 are for data egress,
             * the third one are for descriptor ingress, the fourth are for descriptor egress */
            idx = pg_tc_sp_idx + (SXD_BULK_CNTR_POOL_NUM * 2) * desc;
            sw_pool_id = layout_shared_buffer->sw_pool_id[idx];
            if (sw_pool_id != SXD_BULK_CNTR_POOL_ID_INVALID) {
                layout_shared_buffer->pool.statistics[pool_idx].sw_pool_id = sw_pool_id;
                layout_shared_buffer->pool.statistics[pool_idx].occupancy.curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->pool.statistics[pool_idx].occupancy.watermark =
                    sbsrd.shared_buffer_status[i].max_buff_occupancy;
                layout_shared_buffer->pool.statistics[pool_idx].ext_occupancy =
                    sbsrd.ext_occupancy_status[i].ext_buff_occupancy;
                pool_idx++;
            }
            pg_tc_sp_idx++;
            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_TX_POOL_E:
            if (pg_tc_sp_idx == SXD_BULK_CNTR_POOL_NUM) {
                sxd_log_err("SBSRD parse: got too many number of tc_pool record.\n");
                return;
            }
            /* The index is in order by direction (ingress/egress) and then by buffer type (data/descriptor),
             * So the first 16 (pool num) are for data ingress, the second 16 are for data egress,
             * the third one are for descriptor ingress, the fourth are for descriptor egress */
            idx = pg_tc_sp_idx + SXD_BULK_CNTR_POOL_NUM + (SXD_BULK_CNTR_POOL_NUM * 2) * desc;
            sw_pool_id = layout_shared_buffer->sw_pool_id[idx];
            if (sw_pool_id != SXD_BULK_CNTR_POOL_ID_INVALID) {
                layout_shared_buffer->pool.statistics[pool_idx].sw_pool_id = sw_pool_id;
                layout_shared_buffer->pool.statistics[pool_idx].occupancy.curr_occupancy =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->pool.statistics[pool_idx].occupancy.watermark =
                    sbsrd.shared_buffer_status[i].buff_occupancy;
                layout_shared_buffer->pool.statistics[pool_idx].ext_occupancy =
                    sbsrd.ext_occupancy_status[i].ext_buff_occupancy;
                pool_idx++;
            }
            pg_tc_sp_idx++;
            break;

        case SXD_BULK_CNTR_SHARED_BUFFER_ATTR_TYPE_CPU_TX_TC_E:
            /* Don't support it for now */
            break;

        default:
            sxd_log_err("SBSRD parse: got unknown SBSRD type\n");
            return;
            break;
        }

        layout_common->counters_received_so_far++;
    }

    layout_shared_buffer->port_idx = port_idx;
    layout_shared_buffer->pg_tc_sp_idx = pg_tc_sp_idx;
    layout_shared_buffer->port_pool_idx = port_pool_idx;
    layout_shared_buffer->pool_idx = pool_idx;
    layout_shared_buffer->last_type = type;
}

void sx_bulk_cntr_handle_sbsrd(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __sbsrd_parser, NULL);
}

/***************************************************************************************
 * CEER
 */

static int __ceer_l2_type_map(sxd_ceer_l2_type_t l2_type, uint32_t *type_p)
{
    int rc = 0;

    switch (l2_type) {
    case SXD_CEER_L2_TYPE_NO_ETH_E:
    case SXD_CEER_L2_TYPE_ETH_E:
        *type_p = l2_type;
        break;

    default:
        sxd_log_err("CEER invalid l2 type (%d).\n", l2_type);
        rc = -1;
        break;
    }

    return rc;
}

static int __ceer_vlan_type_map(sxd_ceer_vlan_type_t vlan_type, uint32_t *type_p)
{
    int rc = 0;

    switch (vlan_type) {
    case SXD_CEER_VLAN_TYPE_NO_TAG_E:
    case SXD_CEER_VLAN_TYPE_PRIO_TAG_E:
    case SXD_CEER_VLAN_TYPE_VLAN_TAG_E:
    case SXD_CEER_VLAN_TYPE_QINQ_E:
        *type_p = vlan_type;
        break;

    default:
        sxd_log_err("CEER invalid vlan type (%d).\n", vlan_type);
        rc = -1;
        break;
    }

    return rc;
}

static int __ceer_l3_type_map(sxd_ceer_l3_type_t l3_type, uint32_t *type_p)
{
    int rc = 0;

    switch (l3_type) {
    case SXD_CEER_L3_TYPE_IPV4_E:
    case SXD_CEER_L3_TYPE_IPV6_E:
    case SXD_CEER_L3_TYPE_GRH_E:
    case SXD_CEER_L3_TYPE_FIBERCHANNEL_E:
        *type_p = l3_type;
        break;

    case SXD_CEER_L3_TYPE_UNKNOWN_E:
        *type_p = SXD_CEER_L3_TYPE_FIBERCHANNEL_E + 1;
        break;

    default:
        sxd_log_err("CEER invalid l3 type (%d).\n", l3_type);
        rc = -1;
        break;
    }

    return rc;
}

static int __ceer_l4_type_map(sxd_ceer_l4_type_t l4_type, uint32_t *type_p)
{
    int rc = 0;

    switch (l4_type) {
    case SXD_CEER_L4_TYPE_TCP_E:
    case SXD_CEER_L4_TYPE_UDP_E:
    case SXD_CEER_L4_TYPE_ICMP_E:
    case SXD_CEER_L4_TYPE_IGMP_E:
    case SXD_CEER_L4_TYPE_BTH_E:
    case SXD_CEER_L4_TYPE_BTH_OVER_UDP_E:
    case SXD_CEER_L4_TYPE_AH_E:
    case SXD_CEER_L4_TYPE_ESP_E:
        *type_p = l4_type;
        break;

    case SXD_CEER_L4_TYPE_UNKNOWN_E:
        *type_p = SXD_CEER_L4_TYPE_ESP_E + 1;
        break;

    default:
        sxd_log_err("CEER invalid l4 type (%d).\n", l4_type);
        rc = -1;
        break;
    }

    return rc;
}

static int __ceer_extra_data_type_map(sxd_ceer_tunnel_type_t tunnel_type, uint32_t *type_p)
{
    int rc = 0;

    switch (tunnel_type) {
    case SXD_CEER_TUNNEL_TYPE_NO_TUNNEL_E:
    case SXD_CEER_TUNNEL_TYPE_VXLAN_E:
    case SXD_CEER_TUNNEL_TYPE_NVGRE_E:
    case SXD_CEER_TUNNEL_TYPE_IP_IN_IP_E:
    case SXD_CEER_TUNNEL_TYPE_IP_IN_GRE_IN_IP_E:
    case SXD_CEER_TUNNEL_TYPE_MPLS_E:
        *type_p = tunnel_type;
        break;

    default:
        sxd_log_err("CEER invalid tunnel type (%d).\n", tunnel_type);
        rc = -1;
        break;
    }

    return rc;
}

static int __ceer_extra_data_mpls_map(ku_elephant_flow_mpls_extra_data_t *mpls_data_p,
                                      sxd_ceer_ceer_extra_fields_mpls_t  *ceer_mpls_p)
{
    int rc = 0;

    mpls_data_p->bos = ceer_mpls_p->mpls_bos;
    mpls_data_p->exp = ceer_mpls_p->mpls_exp;
    mpls_data_p->mpls_labels[0].label_valid = ceer_mpls_p->mpls_lb0_v;
    if (mpls_data_p->mpls_labels[0].label_valid == 1) {
        mpls_data_p->mpls_labels[0].label_id = ceer_mpls_p->mpls_label0_label_id;
        mpls_data_p->mpls_labels[0].ttl = ceer_mpls_p->mpls_label0_ttl;
    }
    mpls_data_p->mpls_labels[1].label_valid = ceer_mpls_p->mpls_lb1_v;
    if (mpls_data_p->mpls_labels[1].label_valid == 1) {
        mpls_data_p->mpls_labels[1].label_id = ceer_mpls_p->mpls_label1_label_id;
        mpls_data_p->mpls_labels[1].ttl = ceer_mpls_p->mpls_label1_ttl;
    }
    mpls_data_p->mpls_labels[2].label_valid = ceer_mpls_p->mpls_lb2_v;
    if (mpls_data_p->mpls_labels[2].label_valid == 1) {
        mpls_data_p->mpls_labels[2].label_id = ceer_mpls_p->mpls_label2_label_id;
        mpls_data_p->mpls_labels[2].ttl = ceer_mpls_p->mpls_label2_ttl;
    }
    mpls_data_p->mpls_labels[3].label_valid = ceer_mpls_p->mpls_lb3_v;
    if (mpls_data_p->mpls_labels[3].label_valid == 1) {
        mpls_data_p->mpls_labels[3].label_id = ceer_mpls_p->mpls_label3_label_id;
        mpls_data_p->mpls_labels[3].ttl = ceer_mpls_p->mpls_label3_ttl;
    }
    mpls_data_p->mpls_labels[4].label_valid = ceer_mpls_p->mpls_lb4_v;
    if (mpls_data_p->mpls_labels[4].label_valid == 1) {
        mpls_data_p->mpls_labels[4].label_id = ceer_mpls_p->mpls_label4_label_id;
        mpls_data_p->mpls_labels[4].ttl = ceer_mpls_p->mpls_label4_ttl;
    }

    return rc;
}

static int __ceer_extra_data_tunnel_map(sxd_ceer_tunnel_type_t                tunnel_type,
                                        ku_elephant_flow_tunnel_extra_data_t *tunnel_data_p,
                                        sxd_ceer_ceer_extra_fields_t         *ceer_tunnel_p)
{
    int rc = 0;

    if ((tunnel_type == SXD_CEER_TUNNEL_TYPE_VXLAN_E) ||
        (tunnel_type == SXD_CEER_TUNNEL_TYPE_NVGRE_E)) {
        tunnel_data_p->vni = ceer_tunnel_p->vni;
        memcpy(&tunnel_data_p->dmac, &ceer_tunnel_p->inner_dmac, sizeof(struct sx_ether_addr));
        memcpy(&tunnel_data_p->smac, &ceer_tunnel_p->inner_smac, sizeof(struct sx_ether_addr));
    }
    if (ceer_tunnel_p->inner_l3_type == SXD_CEER_INNER_L3_TYPE_IPV4_E) {
        tunnel_data_p->inner_l3.l3_type = SXD_CEER_INNER_L3_TYPE_IPV4_E;
        tunnel_data_p->inner_l3.dip.family = 1;
        tunnel_data_p->inner_l3.dip.ipv4 = ceer_tunnel_p->inner_dip[0];
        tunnel_data_p->inner_l3.sip.family = 1;
        tunnel_data_p->inner_l3.sip.ipv4 = ceer_tunnel_p->inner_sip[0];
        tunnel_data_p->inner_l3.dscp = ceer_tunnel_p->inner_dscp;
        tunnel_data_p->inner_l3.ecn = ceer_tunnel_p->inner_ecn;
        tunnel_data_p->inner_l3.ttl = ceer_tunnel_p->inner_ttl;
        tunnel_data_p->inner_l3.dont_frag = ceer_tunnel_p->inner_dont_frag;
    } else if (ceer_tunnel_p->inner_l3_type == SXD_CEER_INNER_L3_TYPE_OTHER_E) {
        tunnel_data_p->inner_l3.l3_type = SXD_CEER_L3_TYPE_FIBERCHANNEL_E + 1;
    } else {
        sxd_log_err("CEER invalid inner l3 type (%d).\n", tunnel_data_p->inner_l3.l3_type);
        rc = -1;
    }

    return rc;
}

static int __get_port_index(struct sxd_bulk_cntr_buffer_layout_elephant *layout, u16 local, int *port_idx_p)
{
    int cnt = 0, i = 0, j = 0;
    int port_idx = local / 32;
    int port_bit = local % 32;

    /* Count number of turn-on bits up to local port bit */
    if (layout->port_mask[port_idx] & (1 << (port_bit))) {
        /* Count number of turn-on bits in dwords before local port dword (port_idx) */
        for (i = 0; i < port_idx; i++) {
            for (j = 0; j < 32; j++) {
                if (layout->port_mask[i] & (1 << j)) {
                    cnt++;
                }
            }
        }
        /* Count number of turn-on bits in local port dword before local port offset bit (port_bit) */
        for (j = 0; j < port_bit; j++) {
            if (layout->port_mask[port_idx] & (1 << j)) {
                cnt++;
            }
        }
    } else {
        sxd_log_err("local port %d was not set in MOCS\n", local);
        return -1;
    }

    *port_idx_p = cnt;
    return 0;
}

static int __ceer_reg_to_data(ku_elephant_flow_data_t *data_p, struct ku_ceer_reg *ceer_p)
{
    int rc = 0;

    /* Set data key */
    data_p->data_key.flow_id = ceer_p->detection_entry;
    data_p->data_key.valid = ceer_p->det;

    /* Set data value */

    /* Hash data */
    data_p->data_value.hash.hash_valid = ceer_p->hash_valid;
    if (ceer_p->hash_valid == 1) {
        data_p->data_value.hash.lag_hash = ceer_p->lag_hash;
        data_p->data_value.hash.router_hash = ceer_p->router_hash;
    }

    /* L2 data */
    rc = __ceer_l2_type_map(ceer_p->l2_type, &data_p->data_value.l2.l2_type);
    if (rc != 0) {
        goto out;
    }
    if (ceer_p->l2_type == SXD_CEER_L2_TYPE_ETH_E) {
        rc = __ceer_vlan_type_map(ceer_p->vlan_type, &data_p->data_value.l2.vlan_type);
        if (rc != 0) {
            goto out;
        }
        memcpy(&data_p->data_value.l2.dmac, &ceer_p->dmac, sizeof(struct sx_ether_addr));
        memcpy(&data_p->data_value.l2.smac, &ceer_p->smac, sizeof(struct sx_ether_addr));
        if ((ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_PRIO_TAG_E)
            || (ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_VLAN_TAG_E)
            || (ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_QINQ_E)) {
            data_p->data_value.l2.pcp_dei.dei = ceer_p->dei;
            data_p->data_value.l2.pcp_dei.pcp = ceer_p->pcp;
        }
        if ((ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_VLAN_TAG_E)
            || (ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_QINQ_E)) {
            data_p->data_value.l2.vid = ceer_p->vid;
        }
        if (ceer_p->vlan_type == SXD_CEER_VLAN_TYPE_QINQ_E) {
            data_p->data_value.l2.inner_pcp_dei.dei = ceer_p->inner_dei;
            data_p->data_value.l2.inner_pcp_dei.pcp = ceer_p->inner_pcp;
            data_p->data_value.l2.inner_vid = ceer_p->inner_vid;
        }
    }

    /* L3 data */
    rc = __ceer_l3_type_map(ceer_p->l3_type, &data_p->data_value.l3.l3_type);
    if (rc != 0) {
        goto out;
    }
    if ((ceer_p->l3_type == SXD_CEER_L3_TYPE_IPV4_E)
        || (ceer_p->l3_type == SXD_CEER_L3_TYPE_IPV6_E)
        || (ceer_p->l3_type == SXD_CEER_L3_TYPE_GRH_E)) {
        data_p->data_value.l3.dont_frag = ceer_p->dont_frag;
        data_p->data_value.l3.ttl = ceer_p->ttl;
        data_p->data_value.l3.ecn = ceer_p->ecn;
        data_p->data_value.l3.dscp = ceer_p->dscp;
        if (ceer_p->l3_type == SXD_CEER_L3_TYPE_IPV4_E) {
            data_p->data_value.l3.sip.family = 1;
            data_p->data_value.l3.sip.ipv4 = ceer_p->sip[0];
            data_p->data_value.l3.dip.family = 1;
            data_p->data_value.l3.dip.ipv4 = ceer_p->dip[0];
        } else {
            data_p->data_value.l3.sip.family = 2;
            memcpy(data_p->data_value.l3.sip.ipv6, ceer_p->sip, SXD_CEER_SIP_NUM * sizeof(uint32_t));
            data_p->data_value.l3.dip.family = 2;
            memcpy(data_p->data_value.l3.dip.ipv6, ceer_p->dip, SXD_CEER_DIP_NUM * sizeof(uint32_t));
        }
    }

    /* Extra data type - needed for L4 */
    rc = __ceer_extra_data_type_map(ceer_p->tunnel_type, &data_p->data_value.extra_data.extra_data_key);
    if (rc != 0) {
        goto out;
    }

    /* L4 data */
    rc = __ceer_l4_type_map(ceer_p->l4_type, &data_p->data_value.l4.l4_type);
    if (rc != 0) {
        goto out;
    }
    if ((ceer_p->l4_type == SXD_CEER_L4_TYPE_TCP_E)
        || (ceer_p->l4_type == SXD_CEER_L4_TYPE_UDP_E)) {
        data_p->data_value.l4.l4_source_port = ceer_p->sport;
        if (ceer_p->tunnel_type != SXD_CEER_TUNNEL_TYPE_VXLAN_E) {
            data_p->data_value.l4.l4_destination_port = ceer_p->dport;
        }
    }

    /* Extra data value */
    if (ceer_p->extra_data_type == SXD_CEER_EXTRA_DATA_TYPE_NONE_E) {
        goto out;
    }

    if (ceer_p->extra_data_type == SXD_CEER_EXTRA_DATA_TYPE_MPLS_E) {
        rc = __ceer_extra_data_mpls_map(&data_p->data_value.extra_data.mpls_extra_data,
                                        &ceer_p->extra_data.ceer_extra_fields_mpls);
        if (rc != 0) {
            goto out;
        }
    } else if (ceer_p->extra_data_type == SXD_CEER_EXTRA_DATA_TYPE_TUNNEL_E) {
        rc = __ceer_extra_data_tunnel_map(data_p->data_value.extra_data.extra_data_key,
                                          &data_p->data_value.extra_data.tunnel_extra_data,
                                          &ceer_p->extra_data.ceer_extra_fields);
        if (rc != 0) {
            goto out;
        }
    } else {
        sxd_log_err("CEER invalid extra data type (%d).\n", ceer_p->extra_data_type);
        rc = -1;
    }

out:
    return rc;
}

static void __ceer_parser(const void                                *ceer_reg,
                          u32                                        reg_len,
                          struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                          void                                      *context)
{
    struct ku_ceer_reg                           ceer;
    struct sxd_bulk_cntr_buffer_layout_elephant *layout = (struct sxd_bulk_cntr_buffer_layout_elephant*)layout_common;
    int                                          ret = 0, local_port = 0, port_idx = 0, data_idx = 0;

    memset(&ceer, 0, sizeof(ceer));

    ret = __CEER_decode((u8*)ceer_reg, &ceer, context);
    if (ret != 0) {
        sxd_log_err("Failed to decode CEER\n");
        return;
    }

    if (ceer.det == 0) {
        sxd_log_err("Local %d flow %d ID not elephant flow\n",
                    ceer.local_port, ceer.detection_entry);
        return;
    }

    SX_PORT_BUILD_PHY_ID_FROM_LSB_MSB(local_port,
                                      ceer.local_port,
                                      ceer.lp_msb);

    ret = __get_port_index(layout, local_port, &port_idx);
    if (ret != 0) {
        sxd_log_err("Failed to get port index\n");
        return;
    }

    layout->port_flows[port_idx].flow_id_list[layout->port_flows[port_idx].flow_cnt] = ceer.detection_entry;
    layout->port_flows[port_idx].flow_cnt++;

    data_idx = SXD_COS_ELEPHANT_FLOW_ID_NUM_MAX * port_idx + ceer.detection_entry;

    ret = __ceer_reg_to_data(&layout->data[data_idx], &ceer);
    if (ret != 0) {
        sxd_log_err("Failed to convert CEER to flow data\n");
        return;
    }
}

void sx_bulk_cntr_handle_ceer(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __ceer_parser, NULL);
}

static int __fsed_reg_to_data(ku_stateful_db_entry_t       *data_p,
                              struct ku_fsed_reg           *fsed_p,
                              ku_stateful_db_meta_layout_t *meta_layout_p,
                              uint32_t                      num_max_entries)
{
    int                      rc = 0;
    uint16_t                 page_ind = 0;
    uint32_t                 entry_ind = meta_layout_p->number_of_entries;
    sxd_fsed_sf_dump_page_t *sf_dump_page_p;
    int                      record_ind = 0;


    for (page_ind = 0; page_ind < fsed_p->num_pages; page_ind++) {
        sf_dump_page_p = &(fsed_p->sf_dump_page[page_ind]);

        if (sf_dump_page_p->mode == SXD_FSED_MODE_MODE_0_E) {  /* 54B key */
            if (!sf_dump_page_p->dump_page.sf_page_dump_mode_0.valid) {
                sxd_log_err("54b key entry not valid, page number %d\n", page_ind);
                rc = -1;
                goto out;
            }

            if (entry_ind == num_max_entries) {
                sxd_log_err("FSED parse: mode (%d): got too many entries. "
                            "Page index (%d), entry_ind (%d), entries num max (%d).\n",
                            sf_dump_page_p->mode, page_ind, entry_ind, num_max_entries);
                rc = -1;
                goto out;
            }

            data_p[entry_ind].partition_id = sf_dump_page_p->dump_page.sf_page_dump_mode_0.partition;
            data_p[entry_ind].db_entry_data.db_entry_value = sf_dump_page_p->dump_page.sf_page_dump_mode_0.data;
            data_p[entry_ind].db_entry_meta.entry_activity = sf_dump_page_p->dump_page.sf_page_dump_mode_0.a;
            data_p[entry_ind].db_entry_meta.entry_sem_status = sf_dump_page_p->dump_page.sf_page_dump_mode_0.sem_s;
            data_p[entry_ind].db_entry_meta.entry_sem_cnt = sf_dump_page_p->dump_page.sf_page_dump_mode_0.sem_count;

            entry_ind++;
        } else if (sf_dump_page_p->mode == SXD_FSED_MODE_MODE_1_E) { /* 18/9B key */
            for (record_ind = 0; record_ind < SXD_FSED_RECORD_NUM; record_ind++) {
                if (!sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].valid) {
                    if (record_ind == 0) {
                        sxd_log_err("First record entry not valid, page number %d\n", page_ind);
                        rc = -1;
                        goto out;
                    } else {
                        /* Non-first record may be invalid */
                        continue;
                    }
                }

                if (entry_ind == num_max_entries) {
                    sxd_log_err("FSED parse: mode (%d): got too many entries. "
                                "Page index (%d), record index (%d), entry_ind (%d), entries num max (%d).\n",
                                sf_dump_page_p->mode, page_ind, record_ind, entry_ind, num_max_entries);
                    rc = -1;
                    goto out;
                }

                data_p[entry_ind].partition_id =
                    sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].partition;
                data_p[entry_ind].db_entry_data.db_entry_value =
                    sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].data;
                data_p[entry_ind].db_entry_meta.entry_activity =
                    sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].a;
                data_p[entry_ind].db_entry_meta.entry_sem_status =
                    sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].sem_s;
                data_p[entry_ind].db_entry_meta.entry_sem_cnt =
                    sf_dump_page_p->dump_page.sf_page_dump_mode_1.record[record_ind].sem_count;

                entry_ind++;
            }
        } else {
            sxd_log_err("Invalid page mode (%d) for page number (%d)\n", sf_dump_page_p->mode, page_ind);
            rc = -1;
            goto out;
        }
    }

out:
    meta_layout_p->number_of_entries = entry_ind;
    return rc;
}


static void __fsed_parser(const void                                *fsed_reg,
                          u32                                        reg_len,
                          struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                          void                                      *context)
{
    struct ku_fsed_reg                              fsed;
    struct sxd_bulk_cntr_buffer_layout_stateful_db *layout =
        (struct sxd_bulk_cntr_buffer_layout_stateful_db*)layout_common;
    int      ret;
    uint32_t prev_number_of_entries = layout->meta_layout.number_of_entries;

    memset(&fsed, 0, sizeof(fsed));

    ret = __FSED_decode((u8*)fsed_reg, &fsed, context);
    if (ret != 0) {
        sxd_log_err("Failed to decode FSED\n");
        return;
    }


    ret = __fsed_reg_to_data(&layout->data[0], &fsed, &layout->meta_layout, layout_common->num_of_counters);
    if (ret != 0) {
        sxd_log_err("Failed to convert FSED to entry data\n");
        return;
    }

    if (layout->meta_layout.number_of_entries != fsed.num_of_entries + prev_number_of_entries) {
        sxd_log_err("Number of entries in FSED field [%d] do not match number of entries extracted from FSED [%d].\n",
                    fsed.num_of_entries,
                    (layout->meta_layout.number_of_entries - prev_number_of_entries));
        return;
    }
}


void sx_bulk_cntr_handle_fsed(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __fsed_parser, NULL);
}

#define GET_UPCNT_COUNTER_64(dst_struct_name, dst_field_name, src_struct_name, src_field_name) \
    do {                                                                                       \
        if (port_cntr_index <= layout_port->counters_size) {                                   \
            layout_port->counters[port_cntr_index].dst_struct_name.dst_field_name =            \
                (uint64_t)(upcnt.counter_set.src_struct_name.src_field_name);                  \
        }                                                                                      \
    } while (0)

static void __upcnt_parser(const void                                *upcnt_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    int                                        ret = 0;
    struct ku_upcnt_reg                        upcnt;
    sxd_bulk_cntr_buffer_layout_macsec_port_t *layout_port = (sxd_bulk_cntr_buffer_layout_macsec_port_t*)layout_common;
    int                                        local_port = 0;
    uint16_t                                   port_cntr_index;

    memset(&upcnt, 0, sizeof(upcnt));

    if (reg_len < MLXSW_UPCNT_LEN) {
        sxd_log_err("Bulk-Cntr UPCNT parser - reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_UPCNT_LEN);
        return;
    }

    ret = __UPCNT_decode((u8*)upcnt_reg, &upcnt, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr UPCNT parser - failed to decode UPCNT\n");
        return;
    }

    SX_PORT_BUILD_PHY_ID_FROM_LSB_MSB(local_port,
                                      upcnt.local_port,
                                      upcnt.lp_msb);

    /* local_port range is [1 - MAX_PHYPORT_NUM] */
    if (local_port > MAX_PHYPORT_NUM) {
        sxd_log_err("Bulk-Cntr UPCNT parser - invalid local port %u\n", upcnt.local_port);
        return;
    }

    port_cntr_index = layout_port->mappings.port_index_map[local_port];

    if (port_cntr_index >= layout_port->counters_size) {
        sxd_log_err("Bulk-Cntr UPCNT parser - unexpected local port %u\n", upcnt.local_port);
        return;
    }

    switch (upcnt.grp) {
    case SXD_UPCNT_GRP_GROUP0_E:
        GET_UPCNT_COUNTER_64(port_group0_stats, in_pkts_mtu, upcnt_group0, in_pkts_mtu);
        GET_UPCNT_COUNTER_64(port_group0_stats, in_pkts_general, upcnt_group0, in_pkts_general);
        GET_UPCNT_COUNTER_64(port_group0_stats, in_pn_overflow, upcnt_group0, in_pn_overflow);
        GET_UPCNT_COUNTER_64(port_group0_stats, in_pause_pfc, upcnt_group0, in_pause_pfc);
        GET_UPCNT_COUNTER_64(port_group0_stats, in_eapol, upcnt_group0, in_eapol);
        GET_UPCNT_COUNTER_64(port_group0_stats, in_buffer_overflow, upcnt_group0, in_buffer_overflow);
        GET_UPCNT_COUNTER_64(port_group0_stats, out_pkts_general, upcnt_group0, out_pkts_general);
        GET_UPCNT_COUNTER_64(port_group0_stats, out_pn_overflow, upcnt_group0, out_pn_overflow);
        GET_UPCNT_COUNTER_64(port_group0_stats, out_pause_pfc, upcnt_group0, out_pause_pfc);
        GET_UPCNT_COUNTER_64(port_group0_stats, out_eapol, upcnt_group0, out_eapol);
        break;

    case SXD_UPCNT_GRP_GROUP1_E:
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_untagged, upcnt_group1, in_pkts_untagged);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_notag, upcnt_group1, in_pkts_no_tag);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_bad_tag, upcnt_group1, in_pkts_bad_tag);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_no_sa_rcv, upcnt_group1, in_pkts_no_sa_rcv);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_no_sa_discard, upcnt_group1, in_pkts_no_sa_discard);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_octets_validated, upcnt_group1, in_octets_validated);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_octets_decrypted, upcnt_group1, in_octets_decrypted);
        GET_UPCNT_COUNTER_64(port_group1_stats, in_pkts_too_long, upcnt_group1, in_pkts_too_long);
        GET_UPCNT_COUNTER_64(port_group1_stats, out_pkts_untagged, upcnt_group1, out_pkts_untagged);
        GET_UPCNT_COUNTER_64(port_group1_stats, out_pkts_too_long, upcnt_group1, out_pkts_too_long);
        GET_UPCNT_COUNTER_64(port_group1_stats, out_octets_protected, upcnt_group1, out_octets_protected);
        GET_UPCNT_COUNTER_64(port_group1_stats, out_octets_encrypted, upcnt_group1, out_octets_encrypted);
        break;

    default:
        sxd_log_err("Bulk-Cntr UPCNT parser - unexpected UPCNT group %u\n", upcnt.grp);
        return;
    }

    layout_common->counters_received_so_far++;
}

void sx_bulk_cntr_handle_upcnt(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __upcnt_parser, NULL);
}


static void __utcc_parser(const void                                *utcc_reg,
                          u32                                        reg_len,
                          struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                          void                                      *context)
{
    int                                            ret = 0;
    struct ku_utcc_reg                             utcc;
    u32                                            i;
    sxd_bulk_cntr_buffer_layout_macsec_acl_flow_t *layout_macsec_acl_flow =
        (sxd_bulk_cntr_buffer_layout_macsec_acl_flow_t*)layout_common;
    int local_port = 0;
    u16 port_cntr_index;
    u16 port_counter_offset_idx = 0;

    memset(&utcc, 0, sizeof(utcc));


    if (reg_len < MLXSW_UTCC_LEN) {
        sxd_log_err("Bulk-Cntr UTCC parser - reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_UTCC_LEN);
        return;
    }

    ret = __UTCC_decode((u8*)utcc_reg, &utcc, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr UTCC parser - failed to decode UTCC\n");
        return;
    }

    SX_PORT_BUILD_PHY_ID_FROM_LSB_MSB(local_port,
                                      utcc.local_port,
                                      utcc.lp_msb);

    /* local_port range is [1 - MAX_PHYPORT_NUM] */
    if (local_port > MAX_PHYPORT_NUM) {
        sxd_log_err("Bulk-Cntr UTCC parser - invalid local port %u\n", utcc.local_port);
        return;
    }

    port_cntr_index = layout_macsec_acl_flow->port_index_map[local_port];
    port_counter_offset_idx = port_cntr_index * layout_common->num_of_counters;

    for (i = 0; i < (layout_macsec_acl_flow->number_of_counters / layout_common->num_of_counters); i++) {
        layout_macsec_acl_flow->counter_sets[port_counter_offset_idx + i].packets_counter =
            utcc.counter[layout_macsec_acl_flow->base_entity_id + i];
    }

    layout_common->counters_received_so_far++;
}

void sx_bulk_cntr_handle_utcc(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __utcc_parser, NULL);
}

static void __usacn_parser(const void                                *usacn_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    int                                      ret = 0;
    struct ku_usacn_reg                      usacn;
    u16                                      sadb_entry_idx = 0;
    sxd_bulk_cntr_buffer_layout_macsec_sa_t *layout_macsec_sa =
        (sxd_bulk_cntr_buffer_layout_macsec_sa_t*)layout_common;

    memset(&usacn, 0, sizeof(usacn));


    if (reg_len < MLXSW_USACN_LEN) {
        sxd_log_err("Bulk-Cntr USACN parser - reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_USACN_LEN);
        return;
    }

    ret = __USACN_decode((u8*)usacn_reg, &usacn, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr USACN parser - failed to decode USACN\n");
        return;
    }

    if (usacn.uengine != layout_macsec_sa->uengine_id) {
        sxd_log_err("Bulk-Cntr USACN parser - invalid uengine %u\n", usacn.uengine);
        return;
    }

    if ((usacn.sadb_entry_index < layout_macsec_sa->base_entity_id) ||
        (usacn.sadb_entry_index > layout_macsec_sa->base_entity_id + layout_macsec_sa->number_of_counters)) {
        sxd_log_err("Bulk-Cntr USACN parser - invalid sadb entry index  %u, base entity id %u, num_counters %llu\n",
                    usacn.sadb_entry_index,
                    layout_macsec_sa->base_entity_id,
                    layout_macsec_sa->number_of_counters);
        return;
    }

    sadb_entry_idx = usacn.sadb_entry_index - layout_macsec_sa->base_entity_id;
    layout_macsec_sa->counter_sets[sadb_entry_idx].in_pkts_unchecked = usacn.in_pkts_unchecked;
    layout_macsec_sa->counter_sets[sadb_entry_idx].in_pkts_late = usacn.in_pkts_late;
    layout_macsec_sa->counter_sets[sadb_entry_idx].in_pkts_ok = usacn.in_pkts_ok;
    layout_macsec_sa->counter_sets[sadb_entry_idx].in_pkts_not_valid = usacn.in_pkts_not_valid;

    layout_common->counters_received_so_far++;
}

void sx_bulk_cntr_handle_usacn(struct completion_info *ci)
{
    sx_bulk_cntr_multi_emad_parse(ci->skb->data, ci->skb->len, __usacn_parser, NULL);
}

int bulk_cntr_stateful_db_entry_write(ku_stateful_db_translated_entry_t *entry_p)
{
    sxd_bulk_cntr_event_id_t                        event_id;
    struct sxd_bulk_cntr_buffer_layout_common      *layout_common = NULL;
    struct sxd_bulk_cntr_buffer_layout_stateful_db *stateful_db_layout = NULL;
    int                                             err = 0;

    event_id.event_id_fields.type = SXD_BULK_CNTR_KEY_TYPE_STATEFUL_DB_E;

    err = bulk_cntr_db_event_id_to_buffer(&event_id, &layout_common);
    if (err != 0) {
        sxd_log_err("Failed to get buffer pointer from event ID\n");
        goto out;
    }

    stateful_db_layout = (struct sxd_bulk_cntr_buffer_layout_stateful_db *)layout_common;

    if (entry_p->entry_num >= layout_common->num_of_counters) {
        sxd_log_err("FSED Entry write: failed to update out of bound entry."
                    "Received entry number (%d), max number of entries (%d).\n",
                    entry_p->entry_num, layout_common->num_of_counters);
        err = -1;
        goto out;
    }

    stateful_db_layout->data[entry_p->entry_num].key_id = entry_p->key_id;

    memcpy((void *)&stateful_db_layout->data[entry_p->entry_num].key_data,
           (void *)&entry_p->key_data, sizeof(ku_stateful_db_key_data_t));
    stateful_db_layout->meta_layout.number_of_entries_translated++;

out:
    return err;
}

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#define MOFTD_FLOW_COUNTER_ENTRIES 4

static uint32_t hft_port_counter_size[SXD_BULK_CNTR_HFT_SAMPLE_PER_INFO_SUBTYPE_COUNT_MAX] = {
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_BYTE_TRANSMIT_OK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_BYTE_RECEIVED_OK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PACKET_TRANSMITTED_OK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PACKET_RECEIVED_OK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_2863_GROUP_IF_IN_DISCARDS_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_802_3_GROUP_PAUSE_MAC_CTRL_FRAMES_TRANSMITTED_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_802_3_GROUP_PAUSE_MAC_CTRL_FRAMES_RECEIVED_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_TX_PAUSE_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_RX_PAUSE_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_RX_OCTETS_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_TRAFFIC_CLASS_TX_OCTETS_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_ETH_TRAFFIC_CLASS_CONG_ECN_MARKED_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_32,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_BUFFER_WATERMARK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_32,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_BUFFER_CURRENT_OCCUPANCY_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_EGRESS_PORT_TRAFFIC_CLASS_BUFFER_WATERMARK_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_32,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_EGRESS_PORT_TRAFFIC_CLASS_BUFFER_CURRENT_OCCUPANCY_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_64,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_BUFFER_WATERMARK_SAMPLE_POS_E  */
    SXD_BULK_CNTR_HFT_SIZE_32,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_BUFFER_OCCUPANCY_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_32,            /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_AR_GRADE_LOW_SAMPLE_POS_E */
    SXD_BULK_CNTR_HFT_SIZE_32             /* SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_AR_GRADE_HIGH_SAMPLE_POS_E */
};

static void __process_port_buffer(sxd_bulk_cntr_buffer_layout_hft_t *layout_hft, u8 *port_buffer, u32 buffer_len)
{
    u32  idx = 0, swap_idx = 0;
    u32  port_counter_type = 0;
    u32 *counter_buffer;
    u32  buffer_idx = 0;
    u32  temp;
    u32  swap_count = 0;

    counter_buffer = (u32*)port_buffer;
    for (idx = 0; idx < layout_hft->port_map.port_counter_list_size; idx++) {
        port_counter_type = layout_hft->port_map.port_counter_list[idx];
        switch (port_counter_type) {
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_BYTE_TRANSMIT_OK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_BYTE_RECEIVED_OK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PACKET_TRANSMITTED_OK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PACKET_RECEIVED_OK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_2863_GROUP_IF_IN_DISCARDS_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_802_3_GROUP_PAUSE_MAC_CTRL_FRAMES_TRANSMITTED_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_RFC_802_3_GROUP_PAUSE_MAC_CTRL_FRAMES_RECEIVED_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_AR_GRADE_LOW_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_AR_GRADE_HIGH_SAMPLE_POS_E:
            swap_count = 1;
            break;

        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_TX_PAUSE_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_RX_PAUSE_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_PRIO_GROUP_RX_OCTETS_SAMPLE_POS_E:
            swap_count = layout_hft->port_map.prio_list_cnt;
            break;

        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_BUFFER_WATERMARK_SAMPLE_POS_E:
        case
            SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_HEADROOM_BUFFER_CURRENT_OCCUPANCY_SAMPLE_POS_E
            :
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_BUFFER_WATERMARK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_INGRESS_PORT_PRIORITY_GROUP_BUFFER_OCCUPANCY_SAMPLE_POS_E:
            swap_count = layout_hft->port_map.pg_list_cnt;
            break;

        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_ETH_TRAFFIC_CLASS_CONG_ECN_MARKED_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_EGRESS_PORT_TRAFFIC_CLASS_BUFFER_CURRENT_OCCUPANCY_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_EGRESS_PORT_TRAFFIC_CLASS_BUFFER_WATERMARK_SAMPLE_POS_E:
        case SXD_BULK_CNTR_HFT_SAMPLE_COUNTER_PORT_PER_TRAFFIC_CLASS_TX_OCTETS_SAMPLE_POS_E:
            swap_count = layout_hft->port_map.tc_list_cnt;
            break;
        }
        if (hft_port_counter_size[port_counter_type] == SXD_BULK_CNTR_HFT_SIZE_64) {
            /* Flip the high and low */
            for (swap_idx = 0; swap_idx < swap_count; swap_idx++) {
                temp = counter_buffer[buffer_idx];
                counter_buffer[buffer_idx] = counter_buffer[buffer_idx + 1];
                counter_buffer[buffer_idx + 1] = temp;
                buffer_idx += 2;
            }
        } else {
            buffer_idx += swap_count;
        }
    }
}

static void __process_flow_counter_buffer(sxd_bulk_cntr_buffer_layout_hft_t *layout_hft,
                                          u32                               *flow_counter_buffer,
                                          u32                                flow_counter_count)
{
    u32 idx = 0;
    u32 buffer_idx = 0;
    u32 temp;

    for (idx = 0; idx < flow_counter_count; idx++) {
        /* Flip the high and low for number of packets. */
        temp = flow_counter_buffer[buffer_idx];
        flow_counter_buffer[buffer_idx] = flow_counter_buffer[buffer_idx + 1];
        flow_counter_buffer[buffer_idx + 1] = temp;
        buffer_idx += 2;
        /* Flip the high and low for number of bytes. */
        temp = flow_counter_buffer[buffer_idx];
        flow_counter_buffer[buffer_idx] = flow_counter_buffer[buffer_idx + 1];
        flow_counter_buffer[buffer_idx + 1] = temp;
        buffer_idx += 2;
    }
}

/* Workaround for #3912933 */
int __MOFTD_decode(u8 *outbox, void *ku_reg, void *context)
{
    struct ku_moftd_reg *moftd_reg = (struct ku_moftd_reg*)ku_reg;
    uint32_t             i = 0;

    moftd_reg->num_rec = mlxsw_reg_moftd_num_rec_get(outbox);
    moftd_reg->itr_index = mlxsw_reg_moftd_itr_index_get(outbox);
    moftd_reg->num_entries_in_itr = mlxsw_reg_moftd_num_entries_in_itr_get(outbox);
    moftd_reg->entry_index = mlxsw_reg_moftd_entry_index_get(outbox);
    moftd_reg->first_port_in_chunk = mlxsw_reg_moftd_first_port_in_chunk_get(outbox);
    moftd_reg->num_entries_per_port = mlxsw_reg_moftd_num_entries_per_port_get(outbox);
    moftd_reg->user_cookie = mlxsw_reg_moftd_user_cookie_get(outbox);
    for (i = 0; i < moftd_reg->num_rec; i++) {
        moftd_reg->entry[i] = mlxsw_reg_moftd_entry_get(outbox, 0, i);
    }


    return 0;
}

static void __moftd_parser(const void                                *moftd_reg,
                           u32                                        reg_len,
                           struct sxd_bulk_cntr_buffer_layout_common *layout_common,
                           void                                      *context)
{
    int                                ret = 0;
    u8                                *moftd_buf;
    struct ku_moftd_reg               *moftd_p;
    sxd_bulk_cntr_buffer_layout_hft_t *layout_hft =
        (sxd_bulk_cntr_buffer_layout_hft_t*)layout_common;
    u32  local_port = 0, idx = 0;
    u32  entry_index = 0;
    u32  metadata_total_expected = 0, metadata_total_received = 0;
    u32  port_total_expected = 0, port_total_received = 0;
    u32  flow_total_expected = 0, flow_total_received = 0;
    u32  remaining_received_entry_32 = 0;
    u32  remaining_expected_entries_32 = 0;
    u32  remaining_min_entries_32 = 0;
    u32 *moftd_entries;
    u32  moftd_num_rec = 0;

    if (rx_debug_hft_event) {
        sxd_log_debug("moftd event received.\n");
    }

    if (layout_hft->samples_received == layout_hft->samples_expected) {
        sxd_log_err("Received more samples than expected=%d\n", layout_hft->samples_expected);
        goto out;
    }
    if (reg_len < MLXSW_MOFTD_LEN) {
        sxd_log_err("Bulk-Cntr MOFTD parser - reg_len is less than expected len (reg_len=%u, expected=%u)\n",
                    reg_len, MLXSW_MOFTD_LEN);
        goto out;
    }

    moftd_num_rec = mlxsw_reg_moftd_num_rec_get((u8*)moftd_reg);
    if (moftd_num_rec > layout_hft->moftd_max_entries) {
        sxd_log_err("Bulk-Cntr MOFTD parser - moftd number of records=%d exceeds max limit=%lld",
                    moftd_num_rec,
                    layout_hft->moftd_max_entries);
        goto out;
    }

    moftd_buf = layout_hft->moftd_reg_buf;
    if (moftd_buf == NULL) {
        sxd_log_err("Bulk-Cntr MOFTD parser - pre-allocated moftd buffer is NULL\n");
        goto out;
    }

    ret = __MOFTD_decode((u8*)moftd_reg, moftd_buf, context);
    if (ret != 0) {
        sxd_log_err("Bulk-Cntr MOFTD parser - failed to decode MOFTD\n");
        goto out;
    }

    moftd_p = (struct ku_moftd_reg *)moftd_buf;

    if (rx_debug_hft_event) {
        sxd_log_debug("RX_MOFTD: number_records=%d, first_port=%d, entries_per_port=%d, metadata_entries_expected=%d, port_expected=%d, flow0_expected=%d, flow1_expected=%d, "
                      "single_port_buffer_size=%d, samples_expected=%d, samples_received=%d, current_iteration=%d\n",
                      moftd_p->num_rec,
                      moftd_p->first_port_in_chunk,
                      moftd_p->num_entries_per_port,
                      layout_hft->metadata_map.metadata_info_expected,
                      layout_hft->port_map.count_port_expected,
                      layout_hft->global_map.flow_info[0].counter_number,
                      layout_hft->global_map.flow_info[1].counter_number,
                      layout_hft->port_map.port_counter_buffer_size,
                      layout_hft->samples_expected,
                      layout_hft->samples_received,
                      moftd_p->itr_index);
    }

    if (moftd_p->num_rec == 0) {
        sxd_log_warning("Bulk-Cntr MOFTD parser - MOFTD entries is 0\n");
        goto out;
    }

    if (layout_hft->samples_received != moftd_p->itr_index) {
        sxd_log_err("Bulk-Cntr MOFTD parser - expected iteration=%d, received iteration=%d\n",
                    layout_hft->samples_received,
                    moftd_p->itr_index);
        goto out;
    }


    moftd_entries = &(moftd_p->entry[0]);
    entry_index = 0;

    /* When iteration is split across multiple events, then total received may be nonzero, but
     * not equal to total expected for metadata, port and global respectively.
     * In a sample the counters always will be in the same order:
     * METADATA information, PORT counters, GLOBAL counters
     */
    /* Parse metadata received */
    metadata_total_expected = layout_hft->metadata_map.metadata_info_expected;
    metadata_total_received = layout_hft->metadata_map.metadata_info_received;
    if ((metadata_total_expected != 0) && (entry_index < moftd_p->num_rec) &&
        (metadata_total_received < metadata_total_expected)) {
        /* Remaining expected entries. */
        remaining_expected_entries_32 = metadata_total_expected - metadata_total_received;
        /* Remaining entries in this event. */
        remaining_received_entry_32 = moftd_p->num_rec - entry_index;
        /* Minimum entries that we can copy based on min expected and min received. */
        remaining_min_entries_32 = MIN(remaining_received_entry_32, remaining_expected_entries_32);
        /* copy meta data info based on entries availability. */
        memcpy((u8*)&layout_hft->buffer[layout_hft->buffer_idx], (u8*)&moftd_entries[entry_index],
               (remaining_min_entries_32 * SXD_MOFTD_ENTRY_SIZE));
        layout_hft->metadata_map.metadata_info_received += remaining_min_entries_32;
        /* Increment the buffer index in the host bulk buffer. */
        layout_hft->buffer_idx += (remaining_min_entries_32 * SXD_MOFTD_ENTRY_SIZE);
        /* Advance index in the eMAD entries array. */
        entry_index += remaining_min_entries_32;
    }

    if (rx_debug_hft_event) {
        sxd_log_debug("metadata entries received=%d, entry_idx=%d\n",
                      layout_hft->metadata_map.metadata_info_received, entry_index);
    }

    /* if all entries are parsed then return. */
    if (entry_index == moftd_p->num_rec) {
        goto record_end;
    }

    /* error if all entries are not exhausted and we are unable to find all meta information. */
    if (metadata_total_expected != layout_hft->metadata_map.metadata_info_received) {
        sxd_log_err("Bulk-Cntr MOFTD parser - failed to decode MOFTD, metadata received=%d, metadata expected=%d\n",
                    metadata_total_received, metadata_total_expected);
        goto out;
    }

    /* verify if firmware and SDK are in sync w.r.t entries per port for one iteration(first). */
    if (moftd_p->num_entries_per_port != 0) {
        if ((layout_hft->port_map.port_counter_buffer_size / 4) != moftd_p->num_entries_per_port) {
            sxd_log_err(
                "Bulk-Cntr MOFTD parser - failed to decode MOFTD, port entries expected=[%d], port entries received=[%d]\n",
                (layout_hft->port_map.port_counter_buffer_size / 4),
                moftd_p->num_entries_per_port);
            goto out;
        }
    }

    /* Parse port counter buffer received */
    port_total_expected = layout_hft->port_map.count_port_expected;
    port_total_received = layout_hft->port_map.count_port_received;
    if ((moftd_p->num_entries_per_port != 0) && (port_total_expected != 0) &&
        (port_total_received < port_total_expected)) {
        /* firmware may send events for more ports than requested by user.
         * sample_port_index_map holds actual ports in moftc whose event will come.
         * port_index_map holds all ports requested by user.
         */
        /* Find the index of local port in the list returned in MOFTC actual bitmask. */
        idx = layout_hft->port_map.sample_port_index_map[moftd_p->first_port_in_chunk];
        /* local port is stored in the port list map at the given index. */
        local_port = layout_hft->port_map.sample_port_list_map[idx];
        /* Continue till end of entries or till all ports are received. */
        while (entry_index < moftd_p->num_rec && port_total_received < port_total_expected) {
            if (rx_debug_hft_event) {
                sxd_log_debug("actual_local_port=%d, entry_index=%d",
                              local_port, entry_index);
            }
            /* Port filtering, ignore ports that are not needed. */
            if (layout_hft->port_map.port_index_map[local_port] != 0) {
                /* copy the MOFTD counter buffer to bulk memory. */
                memcpy((u8*)&layout_hft->buffer[layout_hft->buffer_idx], (u8*)&moftd_entries[entry_index],
                       layout_hft->port_map.port_counter_buffer_size);
                /* process port buffer */
                __process_port_buffer(layout_hft, &layout_hft->buffer[layout_hft->buffer_idx],
                                      layout_hft->port_map.port_counter_buffer_size);
                /* Increment the buffer index in the host bulk buffer. */
                layout_hft->buffer_idx += layout_hft->port_map.port_counter_buffer_size;
            }
            /* Move entry index by number of entries in a port. */
            entry_index += moftd_p->num_entries_per_port;
            /* Increment counter for ports whose counters are retrieved. */
            layout_hft->port_map.count_port_received++;
            port_total_received++;
            /* Increment the index to find the next local port whose counters are present in entries. */
            idx++;
            /* next local port is stored in the port list map at the given index. */
            local_port = layout_hft->port_map.sample_port_list_map[idx];
        }
    }

    if (rx_debug_hft_event) {
        sxd_log_debug("port counter received=%d, entry_idx==%d\n",
                      layout_hft->port_map.count_port_received,
                      entry_index);
    }
    /* if all entries are parsed then return. */
    if (entry_index == moftd_p->num_rec) {
        goto record_end;
    }
    /* error if all entries are not exhausted and we are unable to find all port information. */
    if (port_total_expected != port_total_received) {
        sxd_log_err(
            "Bulk-Cntr MOFTD parser - failed to decode MOFTD, port count received=%d, port count expected=%d\n",
            port_total_received,
            port_total_expected);
        goto out;
    }

    /* check for all flow counter types in global list. */
    for (idx = 0; idx < layout_hft->global_map.flow_counter_type_count; idx++) {
        /* find the number of remaining entries in emad to be retrieved. */
        remaining_received_entry_32 = moftd_p->num_rec - entry_index;
        /* total expected entries of a particular counter type. */
        flow_total_expected = layout_hft->global_map.flow_info[idx].counter_number;
        /* total received entries of a particular counter type. */
        flow_total_received = layout_hft->global_map.flow_info[idx].counter_received;
        /* proceed if we expect some entries and all of them are not received. */
        if ((flow_total_expected != 0) && (flow_total_received < flow_total_expected)) {
            /* find total remaining 32 bit entries. */
            remaining_expected_entries_32 = (flow_total_expected - flow_total_received) * MOFTD_FLOW_COUNTER_ENTRIES;
            /* find the least among available entries from eMAD and expected entries. */
            remaining_min_entries_32 = MIN(remaining_received_entry_32, remaining_expected_entries_32);
            if (rx_debug_hft_event) {
                sxd_log_debug("index=%d, flow counters expected=%d, flow counter received=%d\n",
                              idx, remaining_expected_entries_32, remaining_received_entry_32);
            }
            /*copy flow counters. */
            memcpy((u8*)&layout_hft->buffer[layout_hft->buffer_idx], (u8*)&moftd_entries[entry_index],
                   (remaining_min_entries_32 * SXD_MOFTD_ENTRY_SIZE));
            /* process flow counter buffer */
            __process_flow_counter_buffer(layout_hft, (u32*)&layout_hft->buffer[layout_hft->buffer_idx],
                                          (remaining_min_entries_32 / 4));
            /* update expected counter, each counter is a set of four 32 bit counters. */
            layout_hft->global_map.flow_info[idx].counter_received +=
                (remaining_min_entries_32 / MOFTD_FLOW_COUNTER_ENTRIES);
            flow_total_received = (remaining_min_entries_32 / MOFTD_FLOW_COUNTER_ENTRIES);
            /* Increment the buffer index in the host bulk buffer. */
            layout_hft->buffer_idx += (remaining_min_entries_32 * SXD_MOFTD_ENTRY_SIZE);
            /* Advance index in the eMAD entries array. */
            entry_index += remaining_min_entries_32;
            /* if all entries are parsed then return. */
            if (entry_index == moftd_p->num_rec) {
                goto record_end;
            }
        }
    }


    for (idx = 0; idx < layout_hft->global_map.flow_counter_type_count; idx++) {
        if (layout_hft->global_map.flow_info[idx].counter_number
            != layout_hft->global_map.flow_info[idx].counter_received) {
            sxd_log_err(
                "Bulk-Cntr MOFTD parser - End of entries reached, index=%d, flow counter received=%d, flow counter expected=%d\n",
                idx,
                layout_hft->global_map.flow_info[idx].counter_received,
                layout_hft->global_map.flow_info[idx].counter_number);
            goto out;
        }
    }

    if (entry_index != moftd_p->num_rec) {
        sxd_log_err(
            "Bulk-Cntr MOFTD parser - failed to decode MOFTD, entries parsed=%d, entries left to be parsed=%d\n",
            entry_index,
            (moftd_p->num_rec - entry_index));
        goto out;
    }

record_end:
    if (rx_debug_hft_event) {
        sxd_log_debug(
            "record parsing done - total entries in sample=%d, events parsed in current sample event=%d, starting index=%d\n",
            moftd_p->num_entries_in_itr,
            entry_index,
            moftd_p->entry_index);
    }
    if (moftd_p->num_entries_in_itr == entry_index + moftd_p->entry_index) {
        if (layout_hft->metadata_map.metadata_info_received != layout_hft->metadata_map.metadata_info_expected) {
            sxd_log_err("Bulk-Cntr MOFTD parser - End of entries info info expected=%d, port info received=%d\n",
                        layout_hft->metadata_map.metadata_info_expected,
                        layout_hft->metadata_map.metadata_info_received);
            goto out;
        }

        if (layout_hft->port_map.count_port_received != layout_hft->port_map.count_port_expected) {
            sxd_log_err("Bulk-Cntr MOFTD parser - End of entries port info expected=%d, port info received=%d\n",
                        layout_hft->port_map.count_port_expected, layout_hft->port_map.count_port_received);
            goto out;
        }

        for (idx = 0; idx < layout_hft->global_map.flow_counter_type_count; idx++) {
            if (layout_hft->global_map.flow_info[idx].counter_number
                != layout_hft->global_map.flow_info[idx].counter_received) {
                sxd_log_err(
                    "Bulk-Cntr MOFTD parser - End of entries reached, idx=%d, flow counter received=%d, flow counter expected=%d\n",
                    idx,
                    layout_hft->global_map.flow_info[idx].counter_received,
                    layout_hft->global_map.flow_info[idx].counter_number);
                goto out;
            }
        }
        /* Increment once all information belonging to a sample is received. */
        layout_hft->samples_received++;
        if (rx_debug_hft_event) {
            sxd_log_debug("received all sample entries, total samples received=%d\n", layout_hft->samples_received);
        }
        layout_hft->port_map.count_port_received = 0;
        layout_hft->metadata_map.metadata_info_received = 0;
        for (idx = 0; idx < layout_hft->global_map.flow_counter_type_count; idx++) {
            layout_hft->global_map.flow_info[idx].counter_received = 0;
        }
    }
out:
    return;
}

static void __sx_hft_moftd_handler_cb(struct work_struct *work_p)
{
    struct sx_hft_sample_work *hft_work_p = container_of(work_p, struct sx_hft_sample_work, ws);

    sx_bulk_cntr_multi_emad_parse(hft_work_p->data.data_info.moftd_info.skb_p->data,
                                  hft_work_p->data.data_info.moftd_info.skb_p->len,
                                  __moftd_parser,
                                  NULL);

    consume_skb(hft_work_p->data.data_info.moftd_info.skb_p); /* free unused skb, use consume_skb */
    kfree(hft_work_p);
}

static void __sx_hft_mocs_done_handler_cb(struct work_struct *work_p)
{
    int                              err = 0;
    struct sx_hft_sample_work       *hft_work_p = container_of(work_p, struct sx_hft_sample_work, ws);
    unsigned long                    buffer_id;
    enum sxd_bulk_cntr_done_status_e status;
    uint32_t                         cookie;
    sxd_bulk_cntr_event_id_t         event_id;

    event_id.event_id_fields.type = SXD_BULK_CNTR_KEY_TYPE_HFT_E;

    err = bulk_cntr_db_complete(&event_id, &buffer_id, &status, &cookie);
    if (err) {
        sxd_log_err("failed to complete the transaction for hft ack\n");
        goto out;
    }

    /* send notification to user upon transaction completion */
    err = __send_notification_to_user(&event_id, buffer_id, status, cookie, GFP_KERNEL);
    if (err) {
        sxd_log_err("Bulk-Cntr SDK ack: failed to send notification to user upon transaction completion\n");
        goto out;
    }

out:
    kfree(hft_work_p);
}

void __enqueue_hft_moftd_event(struct completion_info *comp_info_p)
{
    int                        err = 0;
    u8                         skb_got = false;
    struct sx_hft_sample_work *hft_work_p = NULL;
    struct sk_buff            *skb_p = comp_info_p->skb;
    bool                       wq_err = false;

    hft_work_p = kmalloc(sizeof(*hft_work_p), GFP_ATOMIC);
    if (hft_work_p == NULL) {
        err = -ENOMEM;
        sxd_log_warning("Memory allocation for hft moftd data failed, "
                        "dropping a hft moftd event job\n");
        goto out;
    }

    hft_work_p->ktime = ktime_get_real();
    hft_work_p->data.data_info.moftd_info.skb_p = skb_p;

    INIT_WORK(&hft_work_p->ws, __sx_hft_moftd_handler_cb);

    skb_get(skb_p);
    skb_got = true;

    wq_err = sx_core_hft_queue_work(&hft_work_p->ws);
    if (wq_err == false) {
        err = -EAGAIN;
        sxd_log_rl_warning("Failed to schedule a hft moftd event job\n");
        goto out;
    }

out:
    if (err) {
        if (hft_work_p) {
            kfree(hft_work_p);
        }

        if (skb_got) {
            kfree_skb(skb_p);   /* drop packet flow, use kfree_skb */
        }
    }
    return;
}

void __enqueue_hft_mocs_done_event(void)
{
    int                        err = 0;
    struct sx_hft_sample_work *hft_work_p = NULL;
    bool                       wq_err = false;

    hft_work_p = kmalloc(sizeof(*hft_work_p), GFP_ATOMIC);
    if (hft_work_p == NULL) {
        err = -ENOMEM;
        sxd_log_warning("Memory allocation for hft mocs done event data failed, "
                        "dropping mocs done for hft job\n");
        goto out;
    }

    hft_work_p->ktime = ktime_get_real();

    INIT_WORK(&hft_work_p->ws, __sx_hft_mocs_done_handler_cb);

    wq_err = sx_core_hft_queue_work(&hft_work_p->ws);
    if (wq_err == false) {
        err = -EAGAIN;
        sxd_log_warning("Failed to schedule an hft mocs done event job\n");
        goto out;
    }

out:
    if (err) {
        if (hft_work_p) {
            kfree(hft_work_p);
        }
    }
    return;
}

void sx_bulk_cntr_handle_moftd(struct completion_info *comp_info_p)
{
    __enqueue_hft_moftd_event(comp_info_p);
}
