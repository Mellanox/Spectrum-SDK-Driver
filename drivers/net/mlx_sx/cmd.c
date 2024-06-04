/*
 * Copyright (C) 2010-2024 NVIDIA CORPORATION & AFFILIATES, Ltd. ALL RIGHTS RESERVED.
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

/************************************************
 * Includes
 ***********************************************/

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/delay.h>
#include "sx.h"
#include "dq.h"
#include "cq.h"
#include "sx_dpt.h"
#include "sx_proc.h"
#include "sgmii.h"
#include "dev_init.h"
#include "health_check.h"
#include "sx_dbg_dump_proc.h"
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>


/************************************************
 *  Definitions
 ***********************************************/

#define CMD_POLL_TOKEN 0xffff

/************************************************
 *  Globals
 ***********************************************/

extern int i2c_cmd_dump;
extern int i2c_cmd_op;
extern int i2c_cmd_reg_id;
extern int i2c_cmd_dump_cnt;

/* for simulator only */
static int (*cmd_ifc_stub_func)(void *rxbuff, void *txbuf, int size,
                                u8 op_modifier, u16 opcode, u32 input_modifier, u16 token);

/************************************************
 * Functions                            *
 ***********************************************/

void mem_blk_dump(char *name, u8 *data, int len)
{
    int i;
    u8 *buf = (void*)data;
    int cnt = len;

    sxd_log_info("======= %s =========\n", name);
    for (i = 0; i < cnt; i++) {
        if ((i == 0) || (i % 4 == 0)) {
            sxd_log_info("\n");
            sxd_log_info("0x%04x : ", i);
        }
        sxd_log_info(" 0x%02x", buf[i]);
    }

    sxd_log_info("\n");
}

void register_ver_cmd_ifc_stub(int (*func)(void *rxbuff, void *txbuf, int size,
                                           u8 op_modifier, u16 opcode, u32 input_modifier, u16 token))
{
    cmd_ifc_stub_func = func;
}
EXPORT_SYMBOL(register_ver_cmd_ifc_stub);

enum {
    /* command completed successfully: */
    CMD_STAT_OK = 0x00,
    /* Internal error (such as a bus error)
    * occurred while processing command: */
    CMD_STAT_INTERNAL_ERR = 0x01,
    /* Operation/command not supported or opcode modifier not supported: */
    CMD_STAT_BAD_OP = 0x02,
    /* Parameter not supported or parameter out of range: */
    CMD_STAT_BAD_PARAM = 0x03,
    /* System not enabled or bad system state: */
    CMD_STAT_BAD_SYS_STATE = 0x04,
    /* Attempt to access reserved or unallocated resource: */
    CMD_STAT_BAD_RESOURCE = 0x05,
    /* Requested resource is currently executing a command,
     * or is otherwise busy: */
    CMD_STAT_RESOURCE_BUSY = 0x06,
    /* Required capability exceeds device limits: */
    CMD_STAT_EXCEED_LIM = 0x08,
    /* Resource is not in the appropriate state or ownership: */
    CMD_STAT_BAD_RES_STATE = 0x09,
    /* Index out of range: */
    CMD_STAT_BAD_INDEX = 0x0a,
    /* FW image corrupted: */
    CMD_STAT_BAD_NVMEM = 0x0b,
    /* FW is in ISSU */
    CMD_STAT_FW_ISSU = 0x27,
    /* Bad management packet (silently discarded): */
    CMD_STAT_BAD_PKT = 0x30,
};

enum {
    HCR_IN_PARAM_OFFSET    = 0x00,
    HCR_IN_MODIFIER_OFFSET = 0x08,
    HCR_OUT_PARAM_OFFSET   = 0x0c,
    HCR_TOKEN_OFFSET       = 0x14,
    HCR_STATUS_OFFSET      = 0x18,
    HCR_OPMOD_SHIFT        = 12,
    HCR_E_BIT              = 22,
    HCR_GO_BIT             = 23
};

enum {
    I2C_GO_BIT_TIMEOUT_MSECS = 500,
    GO_BIT_TIMEOUT_MSECS     = 500
};

enum {
    SX_HCR1_BASE = 0x71000,
    SX_HCR1_SIZE = 0x0001c,
    SX_HCR2_BASE = 0x72000,         /* for i2c command interface */
    SX_HCR2_SIZE = 0x0001c,
};

struct sx_cmd_context {
    struct completion done;
    int               result;
    int               next;
    u64               out_param;
    u16               token;
    u16               opcode;
};

static const char * cmd_str(u16 opcode)
{
    switch (opcode) {
    case SX_CMD_MAP_FA:
        return "SX_CMD_MAP_FA";

    case SX_CMD_UNMAP_FA:
        return "SX_CMD_UNMAP_FA";

    case SX_CMD_QUERY_FW:
        return "SX_CMD_QUERY_FW";

    case SX_CMD_QUERY_FW_HCR1:
        return "SX_CMD_QUERY_FW_HCR1";

    case SX_CMD_QUERY_RSRC:
        return "SX_CMD_QUERY_RSRC";

    case SX_CMD_QUERY_BOARDINFO:
        return "SX_CMD_QUERY_BOARDINFO";

    case SX_CMD_QUERY_AQ_CAP:
        return "SX_CMD_QUERY_AQ_CAP";

    case SX_CMD_CONFIG_PROFILE:
        return "SX_CMD_CONFIG_PROFILE";

    case SX_CMD_ACCESS_REG:
        return "SX_CMD_ACCESS_REG";

    case SX_CMD_CONF_PORT:
        return "SX_CMD_CONF_PORT";

    case SX_CMD_INIT_PORT:
        return "SX_CMD_INIT_PORT";

    case SX_CMD_CLOSE_PORT:
        return "SX_CMD_CLOSE_PORT";

    case SX_CMD_SW2HW_DQ:
        return "SX_CMD_SW2HW_DQ";

    case SX_CMD_HW2SW_DQ:
        return "SX_CMD_HW2SW_DQ";

    case SX_CMD_2ERR_DQ:
        return "SX_CMD_2ERR_DQ";

    case SX_CMD_QUERY_DQ:
        return "SX_CMD_QUERY_DQ";

    case SX_CMD_SW2HW_CQ:
        return "SX_CMD_SW2HW_CQ";

    case SX_CMD_HW2SW_CQ:
        return "SX_CMD_HW2SW_CQ";

    case SX_CMD_QUERY_CQ:
        return "SX_CMD_QUERY_CQ";

    case SX_CMD_SW2HW_EQ:
        return "SX_CMD_SW2HW_EQ";

    case SX_CMD_HW2SW_EQ:
        return "SX_CMD_HW2SW_EQ";

    case SX_CMD_QUERY_EQ:
        return "SX_CMD_QUERY_EQ";

    case SX_CMD_INIT_MAD_DEMUX:
        return "SX_CMD_INIT_MAD_DEMUX";

    case SX_CMD_MAD_IFC:
        return "SX_CMD_MAD_IFC";

    case SX_CMD_ISSU_FW:
        return "SX_CMD_ISSU_FW";

    default:
        return "Unknown command";
    }
}

static int sx_status_to_errno(u8 status)
{
    static const int trans_table[] = {
        [CMD_STAT_INTERNAL_ERR] = -EIO,
        [CMD_STAT_BAD_OP] = -EPERM,
        [CMD_STAT_BAD_PARAM] = -EINVAL,
        [CMD_STAT_BAD_SYS_STATE] = -ENXIO,
        [CMD_STAT_BAD_RESOURCE] = -EBADF,
        [CMD_STAT_RESOURCE_BUSY] = -EBUSY,
        [CMD_STAT_EXCEED_LIM] = -ENOMEM,
        [CMD_STAT_BAD_RES_STATE] = -EBADF,
        [CMD_STAT_BAD_INDEX] = -EBADF,
        [CMD_STAT_BAD_NVMEM] = -EFAULT,
        [CMD_STAT_FW_ISSU] = -ENODEV,
        [CMD_STAT_BAD_PKT] = -EINVAL,
    };

    if ((status >= ARRAY_SIZE(trans_table)) ||
        ((status != CMD_STAT_OK) && (trans_table[status] == 0))) {
        return -EIO;
    }

    return trans_table[status];
}

static int cmd_get_hcr_pci(struct sx_dev *dev, int offset)
{
    u32 status = 0;

    if (dev->pdev) {
        status = __raw_readl(sx_priv(dev)->cmd.hcr + offset);
    }

    return status;
}

static int cmd_get_hcr_mst(int hcr_base, int offset, int *err)
{
    return sx_dpt_mst_readl(hcr_base + offset, err);
}

static int cmd_get_hcr_i2c(int sx_dev_id, int hcr_base, int offset, int *err)
{
    return sx_dpt_i2c_readl(sx_dev_id, hcr_base + offset, err);
}

static int __cmd_get_hcr_reg(struct sx_dev *dev, int sx_dev_id, int hcr_base, int offset, int cmd_path, u32 *reg)
{
    u32 reg_tmp = 0;
    int err = 0;

    switch (cmd_path) {
    case DPT_PATH_PCI_E:
        reg_tmp = be32_to_cpu((__force __be32)cmd_get_hcr_pci(dev, offset));
        break;

    case DPT_PATH_I2C:
        reg_tmp = be32_to_cpu(cmd_get_hcr_i2c(sx_dev_id, hcr_base, offset, &err));
        break;

    case DPT_PATH_MST:
        reg_tmp = be32_to_cpu(cmd_get_hcr_mst(hcr_base, offset, &err));
        break;

    default:
        sxd_log_err("%s(): Error: unsupported cmd_path %d \n", __func__, cmd_path);
        err = -EINVAL;
        break;
    }

    if (!err) {
        *reg = reg_tmp;
    }

    return err;
}

int sx_cmd_send_mad_sync(struct sx_dev *dev,
                         int            dev_id,
                         u32            in_modifier,
                         u8             op_modifier,
                         void          *in_mad,
                         int            in_size,
                         void          *out_mad,
                         int            out_size)
{
    struct sx_cmd_mailbox *inmailbox, *outmailbox;
    void                  *inbox;
    int                    err;

    if ((in_size > SX_MAILBOX_SIZE) || (out_size > SX_MAILBOX_SIZE)) {
        return -EINVAL;
    }

    inmailbox = sx_alloc_cmd_mailbox(dev, dev_id);
    if (IS_ERR(inmailbox)) {
        return PTR_ERR(inmailbox);
    }

    outmailbox = sx_alloc_cmd_mailbox(dev, dev_id);
    if (IS_ERR(outmailbox)) {
        sx_free_cmd_mailbox(dev, inmailbox);
        return PTR_ERR(outmailbox);
    }

    inbox = inmailbox->buf;
    memcpy(inbox, in_mad, in_size);

    err = sx_cmd_box(dev, dev_id, inmailbox,
                     outmailbox, in_modifier, op_modifier,
                     SX_CMD_MAD_IFC, SX_CMD_TIME_CLASS_C, in_size);

    if (!err) {
        memcpy(out_mad, outmailbox->buf, 256);
    }

    sx_free_cmd_mailbox(dev, inmailbox);
    sx_free_cmd_mailbox(dev, outmailbox);
    return err;
}

static int __cmd_pending(struct sx_dev *dev, int sx_dev_id, u32 hcr_base, int cmd_path, u32 *status)
{
    int err = __cmd_get_hcr_reg(dev, sx_dev_id, hcr_base, HCR_STATUS_OFFSET, cmd_path, status);

    if (!err) {
        *status &= (1 << HCR_GO_BIT);
    }

    return err;
}

static int __wait_for_cmd_pending(struct sx_dev *dev, int sx_dev_id, u32 hcr_base, int cmd_path, u16 op, int timeout)
{
    u32           go_bit;
    unsigned long end = 0;
    unsigned long start = 0;

#ifdef QUANTUM3_BU
    timeout = timeout * 4000 * 5;
#endif

    start = jiffies;
    end = msecs_to_jiffies(timeout * 10) + start;

    while (__cmd_pending(dev, sx_dev_id, hcr_base, cmd_path, &go_bit) != 0 || go_bit) {
        if (time_after_eq(jiffies, end)) {
#if defined(INCREASED_TIMEOUT) && !defined(QUANTUM3_BU)
            end = msecs_to_jiffies(timeout * 4000) + jiffies;
            sx_warn(dev,
                    "INCREASED_TIMEOUT is set, Skipping timeout. op=%d, timeout=%d, start=%lu, end=%lu\n",
                    op,
                    timeout,
                    start,
                    end);
            cond_resched();
            continue;
#else
            sx_warn(dev, "Go bit not cleared, op=%d, timeout=%d\n", op, timeout);
            return -ETIMEDOUT;
#endif
        }
        cond_resched();
    }

    return 0;
}

int sx_cmd_health_check_send(struct sx_dev *dev, void** mailbox_p, void* cmd_ctx)
{
    struct sx_cmd_context *context = (struct sx_cmd_context*)cmd_ctx;
    u16                    token;
    int                    event;
    int                    err = 0;
    struct sx_cmd         *cmd = &sx_priv(dev)->cmd;
    u32 __iomem           *hcr = cmd->hcr;
    dma_addr_t             dma = 0;
    struct sx_cmd_mailbox* cmd_mailbox = NULL;

    mutex_lock(&cmd->hcr_mutex);

    cmd_mailbox = sx_alloc_cmd_mailbox(dev, dev->device_id);
    if (IS_ERR(cmd_mailbox)) {
        err = PTR_ERR(cmd_mailbox);
        goto out;
    }

    dma = cmd_mailbox->dma;
    token = cmd->use_events ? context->token : CMD_POLL_TOKEN;
    event = cmd->use_events ? 1 : 0;
    sx_cmd_write_to_pci(dev, 0, dma, 0, 0, SX_CMD_QUERY_FW,
                        token, event, SXD_HEALTH_CAUSE_NONE, hcr);
    *mailbox_p = cmd_mailbox;
out:
    return err;
}

/* this function is in use by health-check, only on PCI configuration */
bool sx_cmd_check_go_bit(struct sx_dev *dev, int sx_dev_id)
{
    u32 go_bit;

    /* always successful on PCI, no need to check error */
    __cmd_pending(dev, sx_dev_id, SX_HCR1_BASE, DPT_PATH_PCI_E, &go_bit);

    return (go_bit != 0);
}

static int __sx_cmd_prepare_post_events(u16 op, struct sx_cmd *cmd, bool try_lock, void **context)
{
    struct sx_cmd_context *cmd_ctx = NULL;
    int                    rc = 0;

    if (try_lock) {
        rc = down_trylock(&cmd->event_sem);
        if (rc != 0) {
            return rc;
        }
    } else {
        down(&cmd->event_sem);
    }
    spin_lock(&cmd->context_lock);
    BUG_ON(cmd->free_head < 0);
    cmd_ctx = &cmd->context[cmd->free_head];
    cmd_ctx->token += cmd->token_mask + 1;
    if (op == SX_CMD_QUERY_FW_HCR1) {
        op = SX_CMD_QUERY_FW;
    }
    cmd_ctx->opcode = op;
    cmd->free_head = cmd_ctx->next;
    spin_unlock(&cmd->context_lock);
    init_completion(&cmd_ctx->done);

    *context = cmd_ctx;
    return 0;
}

int sx_cmd_prepare(struct sx_dev *dev, u16 op, void **context)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;
    int            rc = 0;

    if (cmd->use_events) {
        rc = __sx_cmd_prepare_post_events(op, cmd, true, context);
    } else {
        /* polling case*/
        rc = down_trylock(&cmd->pci_poll_sem);
    }

    return rc;
}

static void __sx_cmd_release_events(struct sx_cmd *cmd, void *context)
{
    struct sx_cmd_context *cmd_ctx = (struct sx_cmd_context*)context;

    spin_lock(&cmd->context_lock);
    cmd_ctx->next = cmd->free_head;
    cmd->free_head = cmd_ctx - cmd->context;
    spin_unlock(&cmd->context_lock);

    up(&cmd->event_sem);
}

void sx_cmd_health_check_release(struct sx_dev *dev, void* mailbox_p, void * cmd_ctx)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;

    sx_free_cmd_mailbox(dev, (struct sx_cmd_mailbox*)mailbox_p);

    mutex_unlock(&cmd->hcr_mutex);

    if (cmd->use_events) {
        __sx_cmd_release_events(cmd, cmd_ctx);
    } else {
        up(&cmd->pci_poll_sem);
    }
}

void sx_cmd_write_to_pci(struct sx_dev      *dev,
                         u64                 in_param,
                         u64                 out_param,
                         u32                 in_modifier,
                         u8                  op_modifier,
                         u16                 op,
                         u16                 token,
                         int                 event,
                         sxd_health_cause_t *cause,
                         u32 __iomem        *hcr)
{
    /*
     * We use writel (instead of something like memcpy_toio)
     * because writes of less than 32 bits to the HCR don't work
     * (and some architectures such as ia64 implement memcpy_toio
     * in terms of writeb).
     */
    __raw_writel((__force u32)cpu_to_be32(in_param >> 32),
                 hcr + 0);
    __raw_writel((__force u32)cpu_to_be32(in_param & 0xfffffffful),
                 hcr + 1);
    __raw_writel((__force u32)cpu_to_be32(in_modifier),
                 hcr + 2);
    __raw_writel((__force u32)cpu_to_be32(out_param >> 32),
                 hcr + 3);
    __raw_writel((__force u32)cpu_to_be32(out_param & 0xfffffffful),
                 hcr + 4);
    __raw_writel((__force u32)cpu_to_be32(token << 16),
                 hcr + 5);

    /* __raw_writel may not order writes. */
    wmb();

    __raw_writel((__force u32)cpu_to_be32((1 << HCR_GO_BIT) |
                                          (event ? (1 << HCR_E_BIT) : 0) |
                                          (op_modifier << HCR_OPMOD_SHIFT) |
                                          op), hcr + 6);

    MMIOWB();
}

static int sx_cmd_post_pci(struct sx_dev         *dev,
                           struct sx_cmd_mailbox *in_mb,
                           struct sx_cmd_mailbox *out_mb,
                           u32                    in_modifier,
                           u8                     op_modifier,
                           u16                    op,
                           u16                    token,
                           int                    event,
                           sxd_health_cause_t    *cause)
{
    struct sx_priv *priv = sx_priv(dev);
    struct sx_cmd  *cmd = &priv->cmd;
    int             ret = -EAGAIN;
    u64             in_param = in_mb ? (in_mb->is_in_param_imm ? in_mb->imm_data : in_mb->dma) : 0;
    u64             out_param = out_mb ? out_mb->dma : 0;
    u32 __iomem    *hcr = cmd->hcr;
    unsigned long   stuck_time;
    int             err = 0;

    mutex_lock(&cmd->hcr_mutex);

    /*
     * SX_CMD_QUERY_FW_HCR1 is a local CMD used to call SX_CMD_QUERY_FW with SX_HCR1_BASE explicitly
     * We need it because now FW has two different mailboxes: one for PCI (HCR1) and one for I2C (HCR2).
     * Even if we use I2C, there are a few commands that must be sent on HCR1. Thus, we need to get the mailbox of this HCR
     */
    if (op == SX_CMD_QUERY_FW_HCR1) {
        op = SX_CMD_QUERY_FW;
    }

    if (sx_cmd_check_go_bit(dev, dev->device_id)) {
        if (sx_is_dev_stuck(dev, &stuck_time)) {
            sxd_log_rl_err("Device %d is marked as 'stuck' for %u seconds. Aborting command %s.\n",
                           dev->device_id, jiffies_to_msecs(jiffies - stuck_time) / 1000, cmd_str(op));
        } else {
            sxd_log_err("Device %d is stuck from a previous command. Marking it as 'stuck' and aborting command %s.\n",
                        dev->device_id, cmd_str(op));

            sx_set_stuck_dev(dev, true);
        }

        err = -ETIMEDOUT;
        goto out;
    }

    if (sx_is_dev_stuck(dev, NULL)) {
        sxd_log_info("Device %d is no longer stuck on previous command.\n", dev->device_id);

        sx_set_stuck_dev(dev, false);
    }

    sx_cmd_write_to_pci(dev, in_param, out_param, in_modifier, op_modifier, op, token, event, cause, hcr);

    if ((op == SX_CMD_ACCESS_REG) && in_mb && in_mb->buf) {
        /* these line is for debug purposes */
        priv->cmd.last_reg_id = be16_to_cpu(((struct emad_operation*)in_mb->buf)->register_id);
    }

    ret = 0;

out:
    mutex_unlock(&cmd->hcr_mutex);
    return ret;
}

static inline struct sx_cmd_mailbox * sx_mailbox(dma_addr_t *dma_addr)
{
    return container_of(dma_addr, struct sx_cmd_mailbox, dma);
}

static void __fill_hcr(struct sx_cmd_mailbox *in_mb,
                       u32                    hcr_base,
                       u32                    in_modifier,
                       u8                     op_modifier,
                       u16                    op,
                       u16                    token,
                       u32                   *hcr_buf)
{
    u32 tmp_u32;

    /*
     *   When using a local mailbox, software
     *   should specify 0 as the Input/Output parameters.
     */
    if (in_mb && in_mb->is_in_param_imm) {
        tmp_u32 = in_mb->imm_data >> 32;
        hcr_buf[0] = cpu_to_be32(tmp_u32);
        tmp_u32 = in_mb->imm_data & 0xFFFFFFFF;
        hcr_buf[1] = cpu_to_be32(tmp_u32);
    } else {
        hcr_buf[0] = 0;
        hcr_buf[1] = 0;
    }

    hcr_buf[2] = cpu_to_be32(in_modifier);
    hcr_buf[3] = 0;
    hcr_buf[4] = 0;
    hcr_buf[5] = cpu_to_be32(token << 16);
    hcr_buf[6] = cpu_to_be32((op_modifier << HCR_OPMOD_SHIFT) | op);
}

static void __raise_go_bit(u32 *hcr_buf)
{
    hcr_buf[6] |= cpu_to_be32(1 << HCR_GO_BIT);
}

static int sx_cmd_post_mst(struct sx_dev         *dev,
                           int                    sx_dev_id,
                           u8                     hcr_number,
                           u32                    hcr_base,
                           struct sx_cmd_mailbox *in_mb,
                           struct sx_cmd_mailbox *out_mb,
                           u32                    in_modifier,
                           u8                     op_modifier,
                           u16                    op,
                           u16                    token,
                           int                    in_mb_size,
                           sxd_health_cause_t    *cause)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;
    int            ret = -EAGAIN;
    u32            hcr_buf[7];
    int            err = 0;

    mutex_lock(&cmd->hcr_mutex);

    err = __wait_for_cmd_pending(dev, 0 /* reserved in MST */, hcr_base, DPT_PATH_MST, op, 0);
    if (-ETIMEDOUT == err) {
        sx_warn(dev, "MST go bit not cleared from last command\n");
        *cause = SXD_HEALTH_CAUSE_GO_BIT;
        goto out;
    } else if (err) {
        sx_err(dev, "MST client return error %d\n", err);
        goto out;
    }

    if (in_mb) {
        ret = sx_dpt_mst_write_buf(sx_glb.sx_dpt.dpt_info[sx_dev_id].in_mb_offset[hcr_number], in_mb->buf, in_mb_size);
        if (ret) {
            sxd_log_debug("first write_buf failed, err = %d\n", ret);
            goto out;
        }
    }

    __fill_hcr(in_mb, hcr_base, in_modifier, op_modifier, op, token, hcr_buf);
    ret = sx_dpt_mst_write_buf(hcr_base, (void*)hcr_buf,  28);
    if (ret) {
        sxd_log_debug("second write_buf failed, err = %d\n", ret);
        goto out;
    }

    /* We write to go bit after writing all other HCR values */
    __raise_go_bit(hcr_buf);
    ret = sx_dpt_mst_writel(hcr_base + 6 * sizeof(u32), hcr_buf[6]);
    if (ret) {
        sxd_log_debug("first writel failed, err = %d\n", ret);
        goto out;
    }

    ret = 0;

out:
    mutex_unlock(&cmd->hcr_mutex);
    return ret;
}

static int sx_cmd_post_i2c(struct sx_dev         *dev,
                           int                    sx_dev_id,
                           u8                     hcr_number,
                           u32                    hcr_base,
                           struct sx_cmd_mailbox *in_mb,
                           struct sx_cmd_mailbox *out_mb,
                           u32                    in_modifier,
                           u8                     op_modifier,
                           u16                    op,
                           u16                    token,
                           int                    in_mb_size,
                           sxd_health_cause_t    *cause)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;
    int            ret = -EAGAIN;
    u32            hcr_buf[7];
    int            err = 0;

    if ((op != SX_CMD_QUERY_FW) &&
        (op != SX_CMD_MAD_IFC) &&
        (op != SX_CMD_INIT_MAD_DEMUX) &&
        (op != SX_CMD_QUERY_FW_HCR1) &&
        (op != SX_CMD_QUERY_BOARDINFO) &&
        (op != SX_CMD_CONFIG_PROFILE) &&
        (op != SX_CMD_ACCESS_REG) &&
        (op != SX_CMD_QUERY_RSRC) &&
        (op != SX_CMD_INIT_SYSTEM_M_KEY) &&
        (op != SX_CMD_ISSU_FW)) {
        sx_err(dev, "command (0x%x) not supported by I2C ifc\n", op);
        return -EINVAL;
    }

    /*
     * SX_CMD_QUERY_FW_HCR1 is a local CMD used to call SX_CMD_QUERY_FW with SX_HCR1_BASE explicitly
     * We need it because now FW has two different mailboxes: one for PCI (HCR1) and one for I2C (HCR2).
     * Even if we use I2C, there are a few commands that must be sent on HCR1. Thus, we need to get the mailbox of this HCR.
     */
    if ((op == SX_CMD_QUERY_FW_HCR1)) {
        op = SX_CMD_QUERY_FW;
    }

    mutex_lock(&cmd->hcr_mutex);

    err = __wait_for_cmd_pending(dev, sx_dev_id, hcr_base, DPT_PATH_I2C, op, 0);
    if (-EUNATCH == err) {
        sx_err(dev, "client not ready yet for "
               "sx_dev_id %d\n", sx_dev_id);
        goto out;
    } else if (-ETIMEDOUT == err) {
        sx_warn(dev, "I2C go bit not cleared from last command\n");
        *cause = SXD_HEALTH_CAUSE_GO_BIT;
        if (sx_glb.sx_i2c.set_go_bit_stuck) {
            int i2c_dev_id;
            if (sx_dpt_get_i2c_dev_by_id(sx_dev_id, &i2c_dev_id) != 0) {
                sx_err(dev, "sx_dpt_get_i2c_dev_by_id for dev_id: %d failed !\n",
                       sx_dev_id);
            } else {
                sx_glb.sx_i2c.set_go_bit_stuck(i2c_dev_id);
            }
        }
        goto out;
    } else if (err) {
        sx_err(dev, "client return error %d, "
               "sx_dev_id %d\n", err, sx_dev_id);
        goto out;
    }

    /*
     *   Some of the commands use mailboxes. In order to use
     *   mailboxes through the i2c, special area is reserved on
     *   the i2c address space that can be used for input and
     *   output mailboxes. Such mailboxes are called Local
     *   Mailboxes. Copy the pci mailboxes to local mailboxes
     */
    if (in_mb) {
        ret = sx_dpt_i2c_write_buf(sx_dev_id,
                                   sx_glb.sx_dpt.dpt_info[sx_dev_id].in_mb_offset[hcr_number],
                                   in_mb->buf, in_mb_size);
        if (ret) {
            sxd_log_debug("sx_cmd_post_i2c: first write_buf "
                          "failed, err = %d\n", ret);
            goto out;
        }
    }

    __fill_hcr(in_mb, hcr_base, in_modifier, op_modifier, op, token, hcr_buf);
    ret = sx_dpt_i2c_write_buf(sx_dev_id, hcr_base, (void*)hcr_buf,  28);
    if (ret) {
        sxd_log_debug("sx_cmd_post_i2c: second write_buf "
                      "failed, err = %d\n", ret);
        goto out;
    }

    /* We write to go bit after writing all other HCR values */
    __raise_go_bit(hcr_buf);
    ret = sx_dpt_i2c_writel(sx_dev_id, hcr_base + 6 * sizeof(u32), hcr_buf[6]);
    if (ret) {
        sxd_log_debug("sx_cmd_post_i2c: first writel failed, err = %d\n", ret);
        goto out;
    }

    ret = 0;

out:
    mutex_unlock(&cmd->hcr_mutex);
    return ret;
}


static int sx_cmd_post(struct sx_dev         *dev,
                       int                    sx_dev_id,
                       u8                     hcr_number,
                       u32                    hcr_base,
                       struct sx_cmd_mailbox *in_mb,
                       struct sx_cmd_mailbox *out_mb,
                       u32                    in_modifier,
                       u8                     op_modifier,
                       u16                    op,
                       u16                    token,
                       int                    event,
                       int                    cmd_path,
                       int                    in_mb_size,
                       sxd_health_cause_t    *cause)
{
    int err = 0;

    switch (cmd_path) {
    case DPT_PATH_PCI_E:
        if (dev->pdev) {
            err = sx_cmd_post_pci(dev, in_mb, out_mb, in_modifier, op_modifier, op, token, event, cause);
        }
        break;

    case DPT_PATH_I2C:
        err = sx_cmd_post_i2c(dev,
                              sx_dev_id,
                              hcr_number,
                              hcr_base,
                              in_mb,
                              out_mb,
                              in_modifier,
                              op_modifier,
                              op,
                              token,
                              in_mb_size,
                              cause);
        break;

    case DPT_PATH_MST:
        err = sx_cmd_post_mst(dev,
                              sx_dev_id,
                              hcr_number,
                              hcr_base,
                              in_mb,
                              out_mb,
                              in_modifier,
                              op_modifier,
                              op,
                              token,
                              in_mb_size,
                              cause);
        break;

    default:
        sxd_log_warning("%s(): Error: sx_dev_id %d unsupported "
                        "cmd_path %d in_mod: 0x%x, op_mod: 0x%x "
                        "op: 0x%x\n",
                        __func__, sx_dev_id, cmd_path, in_modifier,
                        op_modifier, op);
        err = -EINVAL;
        break;
    }

    return err;
}

static int __read_out_mailbox(int dev_id, int cmd_path, int hcr_number, int offset, u8 *buff, int size)
{
    int err = 0;

    if (size < 0) { /* read whatever you can from the mailbox */
        size = sx_glb.sx_dpt.dpt_info[dev_id].out_mb_size[hcr_number] - offset;
    }

    switch (cmd_path) {
    case DPT_PATH_I2C:
        err =
            sx_dpt_i2c_read_buf(dev_id, sx_glb.sx_dpt.dpt_info[dev_id].out_mb_offset[hcr_number] + offset, buff, size);
        break;

    case DPT_PATH_MST:
        err = sx_dpt_mst_read_buf(sx_glb.sx_dpt.dpt_info[dev_id].out_mb_offset[hcr_number] + offset, buff, size);
        break;

    default:
        break;
    }

    if (err) {
        sxd_log_err("Failed to read output mailbox (offset=0x%x, size=%d, err=%d)\n", offset, size, err);
    }

    return err;
}

static int sx_cmd_poll(struct sx_dev         *dev,
                       int                    sx_dev_id,
                       struct sx_cmd_mailbox *in_param,
                       struct sx_cmd_mailbox *out_param,
                       int                    out_is_imm,
                       u32                    in_modifier,
                       u8                     op_modifier,
                       u16                    op,
                       unsigned long          timeout,
                       int                    cmd_path,
                       int                    in_mb_size,
                       sxd_health_cause_t    *cause)
{
    struct sx_priv                *priv = sx_priv(dev);
    struct semaphore              *poll_sem = NULL;
    int                            err = 0;
    u32                            status;
    int                            i2c_dev_id = 0;
    bool                           use_hcr2;
    int                            hcr_base;
    int                            hcr_number;
    u16                            reg_size_in_bytes = 0;
    const struct sxd_emad_tlv_reg *reg_tlv = NULL;

    /* HCR details is relevant only for I2C/MST. PCI does not use this */
    use_hcr2 = (sx_cr_mode() ||
                ((cmd_path == DPT_PATH_I2C) &&
                 (op != SX_CMD_MAD_IFC && op != SX_CMD_INIT_MAD_DEMUX && op != SX_CMD_QUERY_FW_HCR1)));

    if (use_hcr2) {
        poll_sem = &priv->cmd.i2c_poll_sem;
        hcr_base = SX_HCR2_BASE;
        hcr_number = HCR2;
    } else {
        poll_sem = &priv->cmd.pci_poll_sem;
        hcr_base = SX_HCR1_BASE;
        hcr_number = HCR1;
    }

    down(poll_sem);

    if (cmd_path == DPT_PATH_I2C) {
        err = sx_dpt_get_i2c_dev_by_id(sx_dev_id, &i2c_dev_id);
        if (err) {
            goto out_sem;
        }

        if (!sx_glb.sx_i2c.enforce) {
            sx_err(dev, "enforce is NULL!!!\n");
            goto out_sem;
        }

        err = sx_glb.sx_i2c.enforce(i2c_dev_id);
        if (err) {
            sx_warn(dev, "I2C bus 0x%x of device %d is not ready. "
                    "command %s will not be performed. err = %d\n",
                    i2c_dev_id, sx_dev_id, cmd_str(op), err);
            goto out_sem;
        }
    }

    err = sx_cmd_post(dev, sx_dev_id, hcr_number, hcr_base, in_param, out_param, in_modifier,
                      op_modifier, op, CMD_POLL_TOKEN, 0, cmd_path, in_mb_size, cause);
    if (err) {
        sxd_log_warning("sx_cmd_poll: got err = %d "
                        "from sx_cmd_post\n", err);
        goto out;
    }

    /*
     *  If in SW reset flow give the logic behind PCIe 300 msec to recover
     *  before read access (increased for Spectrum3)
     */
    if (priv->dev_sw_rst_flow && (cmd_path == DPT_PATH_PCI_E)) {
        msleep(300);
    }

    err = __wait_for_cmd_pending(dev, sx_dev_id, hcr_base, cmd_path, op, timeout);
    if (err) {
        sxd_log_warning("sx_cmd_poll: got err = %d from cmd_pending\n", err);
        if (-ETIMEDOUT == err) {
            *cause = SXD_HEALTH_CAUSE_GO_BIT;
        }
        goto out;
    }

    if (out_is_imm && out_param) {
        u32 imm_data_low;
        u32 imm_data_high;

        __cmd_get_hcr_reg(dev, sx_dev_id, hcr_base, HCR_OUT_PARAM_OFFSET, cmd_path, &imm_data_high);
        __cmd_get_hcr_reg(dev, sx_dev_id, hcr_base, HCR_OUT_PARAM_OFFSET + 4, cmd_path, &imm_data_low);

        out_param->imm_data = (((u64)imm_data_high) << 32) | imm_data_low;
    }

    err = __cmd_get_hcr_reg(dev, sx_dev_id, hcr_base, HCR_STATUS_OFFSET, cmd_path, &status);
    if (err) {
        sxd_log_warning("Reading of HCR status after posting the "
                        "mailbox has failed for %s command\n",
                        cmd_str(op));
        goto out;
    }

    status >>= 24;

    if (priv->dev_sw_rst_flow) {
        /*
         *  The FW writes 0x26 to status after SW reset command.
         *  Overriding to prevent error handling flow.
         */
        if ((cmd_path == DPT_PATH_PCI_E) && (status == 0x26)) {
            sx_info(dev, "%s. Got FW status 0x%x after SW reset\n", cmd_str(op), status);
            status = CMD_STAT_OK;
        }
    }

    err = sx_status_to_errno(status);
    if (err) {
        sx_warn(dev, "%s failed. FW status = 0x%x\n", cmd_str(op), status);
        goto out;
    }

    if (out_param && out_param->buf) {
        if (op == SX_CMD_ACCESS_REG) {
            if (priv->dev_sw_rst_flow) {
                /* after reset (MRSR), not all mailbox size can be read, we need only the string TLV (size is 16 bytes) */
                err = __read_out_mailbox(sx_dev_id,
                                         cmd_path,
                                         hcr_number,
                                         0,
                                         out_param->buf,
                                         16 /* size of Operation-TLV header */);
                if (err) {
                    sxd_log_err(
                        "Failed to read operation TLV from output mailbox after reset of device %d (err=%d)\n",
                        sx_dev_id,
                        err);
                    goto out;
                }
            } else {
                /* current layout: Operation-TLV (16 bytes), Reg-TLV (4 bytes header + X bytes register)
                 * need to read the Reg-TLV to see how long (in dwords) is the register to read */
                err = __read_out_mailbox(sx_dev_id,
                                         cmd_path,
                                         hcr_number,
                                         0 /* Reg-TLV starts at offset 16 (after the Operation TLV) */,
                                         out_param->buf,
                                         20 /* size of Operation TLV + Reg-TLV header */);
                if (err) {
                    sxd_log_err(
                        "Failed to read Operation-TLV and Reg-TLV header from output mailbox of device %d (err=%d)\n",
                        sx_dev_id,
                        err);
                    goto out;
                }

                reg_tlv = (struct sxd_emad_tlv_reg*)((u8*)out_param->buf + 16);

                /* validate Reg-TLV */
                if (sxd_emad_tlv_type(reg_tlv) != TLV_TYPE_REG_E) {
                    sxd_log_err("TLV type is not Reg-TLV (type = %u) from device %d\n",
                                sxd_emad_tlv_type(reg_tlv),
                                sx_dev_id);
                    err = -EINVAL;
                    goto out;
                }

                reg_size_in_bytes = sxd_emad_tlv_len(reg_tlv) - 4; /* 4 = Reg-TLV length itself in bytes */
                err = __read_out_mailbox(sx_dev_id, cmd_path, hcr_number, 20, out_param->buf + 20, reg_size_in_bytes);
                if (err) {
                    sxd_log_err("Failed to read register from output mailbox of device %d (err=%d)\n",
                                sx_dev_id,
                                err);
                    goto out;
                }
            }
        } else {
            err = __read_out_mailbox(sx_dev_id, cmd_path, hcr_number, 0, out_param->buf, -1 /* all mailbox */);
            if (err) {
                sxd_log_err("Failed to read command-interface output mailbox of device %d for op=0x%x (err=%d)\n",
                            sx_dev_id,
                            op,
                            err);
                goto out;
            }
        }
    }

out:
    if (cmd_path == DPT_PATH_I2C) {
        sx_glb.sx_i2c.release(i2c_dev_id);
    }

out_sem:
    up(poll_sem);

    return err;
}

void sx_cmd_set_op_tlv(struct ku_operation_tlv *op_tlv, u32 reg_id, u8 method)
{
    op_tlv->type = 1;
    op_tlv->length = 4;
    op_tlv->dr = 0;
    op_tlv->status = 0;
    op_tlv->register_id = reg_id;
    op_tlv->r = 0;
    op_tlv->method = method; /* 0x01 = Query, 0x02 Write */
    op_tlv->op_class = 1;
    op_tlv->tid = 0;
}
EXPORT_SYMBOL(sx_cmd_set_op_tlv);

void sx_cmd_event(struct sx_dev *dev, u16 token, u8 status, u64 out_param)
{
    struct sx_priv        *priv = sx_priv(dev);
    struct sx_cmd_context *context =
        &priv->cmd.context[token & priv->cmd.token_mask];

    /* previously timed out command completing at long last */
    if (token != context->token) {
        return;
    }

    context->result = sx_status_to_errno(status);
    if (context->result) {
        sx_warn(dev, "command %s failed. FW status = 0x%x, " \
                "driver result = %d\n",
                cmd_str(context->opcode), status, context->result);
    }

    context->out_param = out_param;

    /* command interface got answer from FW/HW use for Health check mechanism*/
    priv->health_check.cmd_ifc_num_of_pck_received++;

    complete(&context->done);
}
EXPORT_SYMBOL(sx_cmd_event);

static int sx_cmd_wait(struct sx_dev         *dev,
                       int                    sx_dev_id,
                       struct sx_cmd_mailbox *in_param,
                       struct sx_cmd_mailbox *out_param,
                       int                    out_is_imm,
                       u32                    in_modifier,
                       u8                     op_modifier,
                       u16                    op,
                       unsigned long          timeout,
                       int                    cmd_path,
                       sxd_health_cause_t    *cause)
{
    struct sx_cmd         *cmd = &sx_priv(dev)->cmd;
    struct sx_cmd_context *context = NULL;
    int                    err = 0;

    __sx_cmd_prepare_post_events(op, cmd, false, (void**)&context);

    err = sx_cmd_post(dev, sx_dev_id, HCR1, SX_HCR1_BASE, in_param, out_param, in_modifier,
                      op_modifier, op, context->token, 1, cmd_path, 0, cause);
    if (err) {
        goto out;
    }

#ifdef INCREASED_TIMEOUT
    if (!wait_for_completion_timeout(&context->done, msecs_to_jiffies(timeout * 4000))) {
#else
    if (!wait_for_completion_timeout(&context->done, msecs_to_jiffies(timeout))) {
#endif
        if (!context->done.done) {
            sx_err(dev, "command 0x%x (%s) timeout for cmd-ifc completion event on device %d\n",
                   op, cmd_str(op), sx_dev_id);
            err = -ETIMEDOUT;
            *cause = SXD_HEALTH_CAUSE_NO_CMDIFC_COMPLETION;
            goto out;
        }
    }

    /* command interface got answer from FW/HW */
    sx_priv(dev)->health_check.cmd_ifc_num_of_pck_received++;

    err = context->result;
    if (err) {
        goto out;
    }

    if (out_is_imm && out_param) {
        out_param->imm_data = context->out_param;
    }

out:
    spin_lock(&cmd->context_lock);
    context->next = cmd->free_head;
    cmd->free_head = context - cmd->context;
    spin_unlock(&cmd->context_lock);

    up(&cmd->event_sem);
    return err;
}

void __dump_cmd(struct sx_dev         *dev,
                int                    sx_dev_id,
                struct sx_cmd_mailbox *in_param,
                struct sx_cmd_mailbox *out_param,
                int                    out_is_imm,
                u32                    in_modifier,
                u8                     op_modifier,
                u16                    op,
                unsigned long          timeout,
                int                    in_mb_size,
                int                    cmd_path)
{
    int print_cmd = 0;

    sxd_log_info("%s(): in cmd_path: %d (1- i2c, 2 - pci), op:0x%x \n",
                 __func__, cmd_path, op);

    if ((i2c_cmd_op == SX_DBG_CMD_OP_TYPE_ANY) ||
        ((i2c_cmd_op == 0x40) && (NULL != in_param) &&
         (i2c_cmd_reg_id == be16_to_cpu(((struct emad_operation *)
                                         (in_param->buf))->register_id)))) {
        print_cmd = 1;
    } else {
        return;
    }

    if (print_cmd && (NULL != in_param) && (NULL != in_param->buf)) {
        mem_blk_dump("CMD input dump", in_param->buf, 0x60);
    }

    if (print_cmd && (NULL != out_param) && (NULL != out_param->buf)) {
        mem_blk_dump("CMD out parameter dump", out_param->buf, 0x60);
    }

    if ((i2c_cmd_dump_cnt != 0xFFFF) && (i2c_cmd_dump_cnt > 0)) {
        i2c_cmd_dump_cnt--;
    }

    if (i2c_cmd_dump_cnt == 0) {
        i2c_cmd_dump = 0;
        i2c_cmd_dump_cnt = 0;
        i2c_cmd_op = 0xFFFF;
    }
}

int __sx_cmd(struct sx_dev         *dev,
             int                    sx_dev_id,
             struct sx_cmd_mailbox *in_param,
             struct sx_cmd_mailbox *out_param,
             int                    out_is_imm,
             u32                    in_modifier,
             u8                     op_modifier,
             u16                    op,
             unsigned long          timeout,
             int                    in_mb_size)
{
    struct sx_priv    *priv = sx_priv(dev);
    int                err = 0;
    int                cmd_path = 0;
    sxd_health_cause_t cause = SXD_HEALTH_CAUSE_NONE;

    if (sx_core_fw_is_faulty(dev)) {
        sxd_log_notice("Command Interface: Faulty FW - ignoring\n");
        return 0;
    }

    if (priv->global_flushing && sx_emergency_reset_done(dev)) {
        sxd_log_notice("CMD-IFC (op=%d) was called after emergency reset, ignoring\n", op);
        /* During PCI-remove flow, ASIC was already reset by emergency because
         * of a command interface problem. There is no point to continue here ...
         */
        return -ECONNRESET;
    }

    if ((sx_dev_id == DEFAULT_DEVICE_ID) && is_sgmii_supported()) {
        err = sgmii_default_dev_id_get(&sx_dev_id);
        if (err) {
            goto out;
        }
    }

    cmd_path = sx_dpt_get_cmd_path(sx_dev_id);

#ifdef PD_BU
/*
 *   Example how to add limited registers support to PD :
 *
 *   switch (op) {
 *   case SX_CMD_ACCESS_REG:
 *   {
 *       u16 reg_id = be16_to_cpu(((struct emad_operation *)
 *               (in_param->buf))->register_id);
 *       switch (reg_id) {
 *       case PLD_REG_ID:
 *           break;
 *
 *       default:
 *           sxd_log_info("__sx_cmd: command %s with reg_id 0x%x is not yet "
 *                   "supported. Not running it\n", cmd_str(op), reg_id);
 *           return 0;
 *       }
 *
 *       break;
 *   }
 *
 *   default:
 *       break;
 *   }
 */
#endif /* #ifdef PD_BU */

    if (cmd_path == DPT_PATH_INVALID) {
        if (op == SX_CMD_ACCESS_REG) {
            u16 reg_id = be16_to_cpu(((struct emad_operation *)
                                      (in_param->buf))->register_id);

            sxd_log_err("Command path in DPT for device %d is not valid. "
                        "Aborting command %s (register ID 0x%x)\n", sx_dev_id, cmd_str(op), reg_id);
        } else {
            sxd_log_err("Command path in DPT for device %d is not valid. "
                        "Aborting command %s\n", sx_dev_id, cmd_str(op));
        }

        err = -EINVAL;
        goto out;
    }

    if (sx_priv(dev)->cmd.use_events && (cmd_path != DPT_PATH_I2C)) {
        err = sx_cmd_wait(dev, sx_dev_id, in_param, out_param,
                          out_is_imm, in_modifier, op_modifier,
                          op, timeout, cmd_path, &cause);
    } else {
        err = sx_cmd_poll(dev, sx_dev_id, in_param, out_param,
                          out_is_imm, in_modifier, op_modifier,
                          op, timeout, cmd_path, in_mb_size, &cause);
    }

    if (i2c_cmd_dump) {
        __dump_cmd(dev, sx_dev_id, in_param, out_param,
                   out_is_imm, in_modifier, op_modifier,
                   op, timeout, in_mb_size, cmd_path);
    }

#ifdef PD_BU
    if (err) {
        sxd_log_info("__sx_cmd: command %s finished with err %d\n", cmd_str(op), err);
    }
#endif

    if (!err && (SXD_HEALTH_CAUSE_NONE == cause)) {
        goto out;
    }

    if (priv->global_flushing && !sx_emergency_reset_done(dev)) {
        sxd_log_err("CMD-IFC problem during global flushing (err=%d), will trigger emergency reset\n", err);
        sx_emergency_reset(dev, false);
        err = -ECONNRESET;
        goto out;
    }

    sxd_log_err("CMD-IFC timeout for device:[%d] sending SDK health event (if enabled).\n", sx_dev_id);
    if (sdk_health_test_and_disable(sx_dev_id)) {
        sx_send_health_event(sx_dev_id, cause, SXD_HEALTH_SEVERITY_FATAL, DBG_ALL_IRISCS, NULL, NULL);
    } else {
        /* in case fatal_failure_detection is active event will create from the health check mechanism*/
        u16 reg_id = 0;

        if (op == SX_CMD_ACCESS_REG) {
            reg_id = be16_to_cpu(((struct emad_operation*)in_param->buf)->register_id);
        }

        sx_health_report_error_cmdifc_timeout(sx_dev_id, cause, op, reg_id);
    }

out:
    return err;
}
EXPORT_SYMBOL(__sx_cmd);

void sx_cmd_unmap(struct sx_dev *dev)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;

    iounmap(cmd->hcr);
    cmd->hcr = NULL;
}

int sx_cmd_pool_create(struct sx_dev *dev)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;

    cmd->pool = dma_pool_create("sx_cmd", &dev->pdev->dev,
                                SX_MAILBOX_SIZE,
                                SX_MAILBOX_SIZE, 0);
    if (!cmd->pool) {
        return -ENOMEM;
    }

    return 0;
}

void sx_cmd_pool_destroy(struct sx_dev *dev)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;

    dma_pool_destroy(cmd->pool);
    cmd->pool = NULL;
}

int sx_cmd_init(struct sx_dev *dev)
{
    struct sx_cmd *cmd = &sx_priv(dev)->cmd;

    mutex_init(&cmd->hcr_mutex);
    sema_init(&cmd->pci_poll_sem, 1);
    sema_init(&cmd->i2c_poll_sem, 1);
    cmd->use_events = 0;
    cmd->toggle = 1;
    cmd->max_cmds = 10;

    return 0;
}

int sx_cmd_init_pci(struct sx_dev *dev)
{
    sx_priv(dev)->cmd.hcr = ioremap(pci_resource_start(dev->pdev, 0) +
                                    SX_HCR1_BASE, SX_HCR1_SIZE);
    if (!sx_priv(dev)->cmd.hcr) {
        sx_err(dev, "Couldn't map command register.");
        return -ENOMEM;
    }

    sx_info(dev, "map cmd: phys: 0x%llx , virtual: %p \n",
            (u64)(pci_resource_start(dev->pdev, 0) + SX_HCR1_BASE),
            sx_priv(dev)->cmd.hcr);

    return 0;
}

int sx_cmd_ifc_dump(struct seq_file *m, void *v, void *context)
{
    struct sx_dev  *dev = sx_dbg_dump_get_device(m);
    struct sx_priv *priv = NULL;
    char            header[SX_DBG_DUMP_HEADER_MAX_LEN];
    unsigned long   stuck_time;
    u32             hcr_line;
    u16             opcode;
    u8              go_bit;

    if (!dev) {
        goto out;
    }

    if (!dev->pdev) {
        seq_printf(m, "This is not a PCI device\n");
        goto out;
    }

    priv = sx_priv(dev);

    snprintf(header, SX_DBG_DUMP_HEADER_MAX_LEN, "Command Interface dump - device_id %u", dev->device_id);
    sx_dbg_dump_print_header(m, header);

    seq_printf(m, "Command_Interface_Mem\n");
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 0));
    seq_printf(m, "    in_param_h ............................... 0x%08x\n", hcr_line);
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 4));
    seq_printf(m, "    in_param_l ............................... 0x%08x\n", hcr_line);
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 8));
    seq_printf(m, "    input_modifier ........................... 0x%08x\n", hcr_line);
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 12));
    seq_printf(m, "    out_param_h .............................. 0x%08x\n", hcr_line);
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 16));
    seq_printf(m, "    out_param_l .............................. 0x%08x\n", hcr_line);
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 20));
    seq_printf(m, "    token .................................... 0x%04x\n", (hcr_line >> 16));
    hcr_line = be32_to_cpu(cmd_get_hcr_pci(dev, 24));
    opcode = hcr_line & 0xfff;
    go_bit = (hcr_line >> 23) & 0x1;
    seq_printf(m, "    status ................................... 0x%02x\n", (hcr_line >> 24));
    seq_printf(m, "    go ....................................... 0x%x (%s)\n",
               go_bit, ((go_bit) ? "command in progress" : "command-interface is idle"));
    seq_printf(m, "    e ........................................ 0x%x\n", ((hcr_line >> 22) & 0x1));
    seq_printf(m, "    opcode_modifier .......................... 0x%x\n", ((hcr_line >> 12) & 0xf));
    if (opcode == SX_CMD_ACCESS_REG) {
        seq_printf(m, "    opcode ................................... %s (0x%03x) [reg: 0x%04x]\n",
                   cmd_str(opcode), opcode, priv->cmd.last_reg_id);
    } else {
        seq_printf(m, "    opcode ................................... %s (0x%03x)\n", cmd_str(opcode), opcode);
    }

    if (sx_is_dev_stuck(dev, &stuck_time)) {
        seq_printf(m, "Device stuck ................................. Yes\n");
        seq_printf(m, "Device stuck time (seconds)................... %u\n",
                   jiffies_to_msecs(jiffies - stuck_time) / 1000);
    } else {
        seq_printf(m, "Device stuck ................................. No\n");
    }

out:
    sx_dbg_dump_print_empty_line(m);
    return 0;
}

/*
 * Switch to using events to issue FW commands (can only be called
 * after event queue for command events has been initialized).
 */
int sx_cmd_use_events(struct sx_dev *dev)
{
    struct sx_priv *priv = sx_priv(dev);
    int             i;

    if (priv->cmd.use_events == 1) {
        return 0;
    }

#if defined(PD_BU) && defined(PD_BU_DISABLE_CMD_EVENTS)
    sxd_log_info("CMD EVENTS are DISABLED in PD mode.\n");
    return 0;
#endif

    priv->cmd.context = kmalloc(priv->cmd.max_cmds *
                                sizeof(struct sx_cmd_context), GFP_KERNEL);
    if (!priv->cmd.context) {
        return -ENOMEM;
    }

    for (i = 0; i < priv->cmd.max_cmds; ++i) {
        priv->cmd.context[i].token = i;
        priv->cmd.context[i].next = i + 1;
    }

    priv->cmd.context[priv->cmd.max_cmds - 1].next = -1;
    priv->cmd.free_head = 0;
    sema_init(&priv->cmd.event_sem, priv->cmd.max_cmds);
    spin_lock_init(&priv->cmd.context_lock);
    for (priv->cmd.token_mask = 1;
         priv->cmd.token_mask < priv->cmd.max_cmds;
         priv->cmd.token_mask <<= 1) {
        /* nothing */
    }
    --priv->cmd.token_mask;

    priv->cmd.use_events = 1;
    down(&priv->cmd.pci_poll_sem);

    return 0;
}
EXPORT_SYMBOL(sx_cmd_use_events);

/*
 * Switch back to polling (used when shutting down the device)
 */
void sx_cmd_use_polling(struct sx_dev *dev)
{
    struct sx_priv *priv = sx_priv(dev);
    int             i;

    if (priv->cmd.use_events == 0) {
        return;
    }

    priv->cmd.use_events = 0;

    for (i = 0; i < priv->cmd.max_cmds; ++i) {
        down(&priv->cmd.event_sem);
    }

    kfree(priv->cmd.context);

    up(&priv->cmd.pci_poll_sem);
}
EXPORT_SYMBOL(sx_cmd_use_polling);

struct sx_cmd_mailbox * sx_alloc_cmd_mailbox(struct sx_dev *dev, int sx_dev_id)
{
    struct sx_cmd_mailbox *mailbox;

    if (!dev) {
        sxd_log_err("cannot allocate mailbox on a NULL device\n");
        return ERR_PTR(-EINVAL);
    }

    mailbox = kzalloc(sizeof *mailbox, GFP_KERNEL);
    if (!mailbox) {
        return ERR_PTR(-ENOMEM);
    }

    if (!dev->pdev || is_sgmii_device(sx_dev_id)) {
        mailbox->buf = kzalloc(SX_MAILBOX_SIZE, GFP_KERNEL);
    } else {
        if (!sx_dpt_is_path_valid(dev->device_id, DPT_PATH_PCI_E)) {
            kfree(mailbox);
            return ERR_PTR(-EINVAL);
        }

        mailbox->buf = dma_pool_alloc(sx_priv(dev)->cmd.pool,
                                      GFP_KERNEL, &mailbox->dma);
    }

    if (!mailbox->buf) {
        kfree(mailbox);
        return ERR_PTR(-ENOMEM);
    }

    return mailbox;
}
EXPORT_SYMBOL(sx_alloc_cmd_mailbox);


void sx_free_cmd_mailbox(struct sx_dev *dev, struct sx_cmd_mailbox *mailbox)
{
    if (!mailbox) {
        return;
    }

    if (!dev->pdev) {
        kfree(mailbox->buf);
    } else {
        if (mailbox->dma) {
            dma_pool_free(sx_priv(dev)->cmd.pool, mailbox->buf,
                          mailbox->dma);
        }
    }

    kfree(mailbox);
}
EXPORT_SYMBOL(sx_free_cmd_mailbox);

void sx_set_stuck_dev(struct sx_dev *dev, bool is_stuck)
{
    struct sx_priv *priv = sx_priv(dev);

    priv->dev_stuck = is_stuck;
    if (priv->dev_stuck) {
        priv->dev_stuck_time = jiffies;
    } else {
        priv->dev_stuck_time = 0;
    }
}

bool sx_is_dev_stuck(struct sx_dev *dev, unsigned long *stuck_time)
{
    struct sx_priv *priv = sx_priv(dev);

    if (!priv->dev_stuck) {
        return false;
    }

    if (stuck_time) {
        *stuck_time = priv->dev_stuck_time;
    }

    return true;
}
