/*
 * SPDX-FileCopyrightText: Copyright (c) 2008-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/************************************************
 * Includes
 ***********************************************/
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/mlx_sx/device.h>
#include <linux/mlx_sx/kernel_user.h>
#include <linux/ktime.h>
#include "sx.h"
#include "dev_db.h"
#include "sgmii.h"

/************************************************
 * Definitions
 ***********************************************/
#define SX_CR_DUMP_CMD_MEM_SIZE                     0x00020
#define SX_CR_DUMP_CMD_MEM_OPCODE_COMPLETION_OFFSET 0
#define SX_CR_DUMP_CMD_MEM_STATUS_OFFSET            0x4
#define SX_CR_DUMP_CMD_MEM_HOST_BASE_ADDR_OFFSET    0x8
#define SX_CR_DUMP_CMD_MEM_HOST_SIZE_ALLOCET_OFFSET 0x10
#define SX_CR_DUMP_CMD_MEM_HOST_SIZE_USED_OFFSET    0x18
#define SX_CR_DUMP_LAYER1_TIMER_SLEEP_US            2000
#define SX_CR_DUMP_WAIT_TIME_AFTER_CANCEL_FW        1000
#define SX_CR_DUMP_DEFAULT_HOST_SIZE                (64 * 1024 * 1024)
#define BASE_INFO_PTR_MEM                           0x100040

#define ROUNDUP(val, align) \
    ((((val) / (align)) * (align)) + (((val) % (align)) ? (align) : 0))

enum {
    SX_CR_DUMP_FW_STATUS_IDLE = 0,
    SX_CR_DUMP_FW_STATUS_ONGOING,
    SX_CR_DUMP_FW_STATUS_PENDING,
};

/************************************************
 * Globals
 ***********************************************/
extern struct sx_globals sx_glb;


/************************************************
 * Functions
 ***********************************************/
static bool __fw_in_idle_status(struct sx_dev *dev, u8 *ret_opcode, u8 *ret_status);
static bool __fw_in_pending_status(struct sx_dev *dev, u8 *ret_opcode, u8 *ret_status);
static void __get_cr_dump_ret(struct sx_dev *dev, struct sx_cr_dump_cmd_mem *cr_dump_ret);
static int __set_fw_cancel(struct sx_dev *dev);
static int __fw_crdump_precheck(struct sx_dev *dev, dma_addr_t dma_addr, u8 opcode, int dump_size);
static int __fw_crdump_postcheck(struct sx_dev *dev, u8 opcode, unsigned char *buf,
                                 struct sx_cr_dump_ret *cr_dump_ret);
static void __virt_unmap_dma_bus(struct sx_dev *dev, dma_addr_t dma_addr, int size);
static int __virt_map_dma_bus(struct sx_dev *dev, void *virt_addr, int size, dma_addr_t *dma_addr);


static bool __fw_in_idle_status(struct sx_dev *dev, u8 *ret_opcode, u8 *ret_status)
{
    u32             tmp = 0;
    u8              opcode = 0, status = 0;
    struct sx_priv *priv = sx_priv(dev);

    opcode = be32_to_cpu(__raw_readl(priv->cr_dump_base)) & 0xFF;
    tmp = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_STATUS_OFFSET));
    status = tmp & 0xFF;

    if (ret_opcode) {
        *ret_opcode = opcode;
    }
    if (ret_status) {
        *ret_status = status;
    }

    return (status == SX_CR_DUMP_FW_STATUS_IDLE) && (opcode == SX_CR_DUMP_OP_NOP);
}

static bool __fw_in_pending_status(struct sx_dev *dev, u8 *ret_opcode, u8 *ret_status)
{
    u32             tmp = 0;
    u8              opcode = 0, status = 0;
    struct sx_priv *priv = sx_priv(dev);

    opcode = be32_to_cpu(__raw_readl(priv->cr_dump_base)) & 0xFF;
    tmp = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_STATUS_OFFSET));
    status = tmp & 0xFF;

    if (ret_opcode) {
        *ret_opcode = opcode;
    }
    if (ret_status) {
        *ret_status = status;
    }

    return (status == SX_CR_DUMP_FW_STATUS_PENDING) && (opcode == SX_CR_DUMP_OP_NOP);
}

static void __get_cr_dump_ret(struct sx_dev *dev, struct sx_cr_dump_cmd_mem *cr_dump_ret)
{
    u32             tmp = 0;
    u32             size_h = 0, size_l = 0;
    struct sx_priv *priv = sx_priv(dev);

    cr_dump_ret->opcode = be32_to_cpu(__raw_readl(priv->cr_dump_base)) & 0xFF;

    tmp = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_STATUS_OFFSET));
    cr_dump_ret->trans_sn = tmp >> 16 & 0xFFFF;
    cr_dump_ret->dump_sn = tmp >> 8 & 0xFF;
    cr_dump_ret->status = tmp & 0xFF;

    size_h = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_SIZE_USED_OFFSET));
    size_l = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_SIZE_USED_OFFSET + 4));
    cr_dump_ret->host_size_used = (u64)size_h << 32 | (u64)size_l;
    if (cr_dump_ret->host_size_used > priv->cr_dump_info.cr_dump_memblk_size) {
        /* the conflict should be within FW logic, and SDK dumps within the limit queried from FW */
        sxd_log_err(
            "host_size_used is too big (0x%llx), size (MSB:0x%x, LSB:0x%x) may be wrong, and reduce it to sent blk size 0x%x\n",
            cr_dump_ret->host_size_used,
            size_h,
            size_l,
            priv->cr_dump_info.cr_dump_memblk_size);
        cr_dump_ret->host_size_used = priv->cr_dump_info.cr_dump_memblk_size;
    }
}

static void __clear_dma_map(struct sx_dev *dev, bool *dma_used, dma_addr_t *dma_addr, int *dma_size)
{
    if (*dma_used) {
        __virt_unmap_dma_bus(dev, *dma_addr, *dma_size);
        *dma_used = false;
        *dma_size = 0;
        sx_priv(dev)->crsdump_in_process = false;
    }
}

/*
 *  After setting FW cancel, FW is expected to be IDLE within 1 ms at most.
 *  FW should be in fatal error status if it is still not IDLE.
 */
static int __set_fw_cancel(struct sx_dev *dev)
{
    u8              opcode = 0, status = 0;
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);

    __raw_writel((__force u32)cpu_to_be32(SX_CR_DUMP_OP_CANCEL & 0xff), priv->cr_dump_base);

    if (!__fw_in_idle_status(dev, &opcode, &status)) {
        usleep_range(SX_CR_DUMP_WAIT_TIME_AFTER_CANCEL_FW, SX_CR_DUMP_WAIT_TIME_AFTER_CANCEL_FW + 10);
        if (!__fw_in_idle_status(dev, &opcode, &status)) {
            sxd_log_err("%s(): FW cannot cancel (status %d, opcode %d).\n",
                        __func__, status, opcode);
            err = SX_CR_DUMP_RET_FATAL_FW_ERR;
            goto out;
        }
    }
out:
    __clear_dma_map(dev,
                    &priv->cr_dump_info.dma_buff_used,
                    &priv->cr_dump_info.dma_addr,
                    &priv->cr_dump_info.dma_size);
    return err;
}

/*
 *  Check cr_dump base addr, size be 4KB align;
 *  Check dumped size + dump size will not override cap_dump_host_size.
 *  If any check fails, set FW cancel and return error.
 */
static int __fw_crdump_precheck(struct sx_dev *dev, dma_addr_t dma_addr, u8 opcode, int dump_size)
{
    int             err = 0, err2 = 0;
    struct sx_priv *priv = sx_priv(dev);

    if (dump_size % SXD_CR_DUMP_HOST_MEM_ALIGN || dma_addr % SXD_CR_DUMP_HOST_MEM_ALIGN) {
        sxd_log_err(
            "ERROR: FW params error: host base address (0x%llx) or host size (0x%x) are not %d bytes aligned.\n",
            dma_addr,
            dump_size,
            SXD_CR_DUMP_HOST_MEM_ALIGN);
        err = SX_CR_DUMP_RET_CANCEL_FW_PARAM_MISALIGN;
        goto out;
    }

    priv->cr_dump_info.cr_dump_memblk_size = dump_size;
    priv->cr_dump_info.gdb_dump_mode = false;

    switch (opcode) {
    case SX_CR_DUMP_OP_START_FLAT:
        priv->cr_dump_info.dumped_bytes = 0;
        priv->cr_dump_info.cap_current_dump_host_size = priv->cr_dump_info.cap_dump_host_size_flat;
        break;

    case SX_CR_DUMP_OP_START_REDUCED_FLAT:
        priv->cr_dump_info.dumped_bytes = 0;
        priv->cr_dump_info.cap_current_dump_host_size = priv->cr_dump_info.cap_dump_host_size_reduced_flat;
        break;

    case SX_CR_DUMP_OP_START_GW:
        priv->cr_dump_info.dumped_bytes = 0;
        priv->cr_dump_info.cap_current_dump_host_size = ROUNDUP(priv->cr_dump_info.cap_dump_host_size_gw,
                                                                SX_CR_DUMP_MEMBLK_SIZE);
        break;

    case SX_CR_DUMP_OP_START_GDB:
        priv->cr_dump_info.dumped_bytes = 0;
        priv->cr_dump_info.cap_current_dump_host_size = ROUNDUP(priv->cr_dump_info.cap_dump_host_size_gdb,
                                                                SXD_CR_DUMP_HOST_MEM_ALIGN);
        priv->cr_dump_info.gdb_dump_mode = true;
        break;

    default:
        break;
    }

    if (priv->cr_dump_info.dumped_bytes + dump_size > priv->cr_dump_info.cap_current_dump_host_size) {
        sxd_log_err(
            "Total cr_dump dump size (%u) is too big to be handled by FW: Total cr_dump size (dumped:%u, to be dumped:%u) is bigger than cap_dump_host_size (%u).\n",
            priv->cr_dump_info.dumped_bytes + dump_size,
            priv->cr_dump_info.dumped_bytes,
            dump_size,
            priv->cr_dump_info.cap_current_dump_host_size);
        err = SX_CR_DUMP_RET_CANCEL_DUMP_SIZE_OVERFLOW;
        goto out;
    }
out:
    if (err) {
        err2 = __set_fw_cancel(dev);
        if (err2) {
            sxd_log_err(
                "FATAL FW ERROR: cannot cancel FW cr-dump after a fw cr-dump pre-check error (%d), opcode (%d).\n",
                err,
                opcode);
        }
    }
    return err;
}

/*
 *  Check dump_sn, trans_sn, dumped_size after one FW cr_dump. If some error occurs, set FW cancel and return error.
 */
static int __fw_crdump_postcheck(struct sx_dev *dev, u8 opcode, unsigned char *buf, struct sx_cr_dump_ret *cr_dump_ret)
{
    int             err = 0, err2 = 0;
    u32             dw1 = 0, dw2 = 0;
    struct sx_priv *priv = sx_priv(dev);

    __get_cr_dump_ret(dev, &(cr_dump_ret->ret_cmd_mem));
    if (cr_dump_ret->ret_cmd_mem.host_size_used > priv->cr_dump_info.cr_dump_memblk_size) {
        sxd_log_err("cr_dump: returned host_size_used (%llu) is bigger than allocated memory block size: %u.\n",
                    cr_dump_ret->ret_cmd_mem.host_size_used,
                    priv->cr_dump_info.cr_dump_memblk_size);
        err = SX_CR_DUMP_RET_CANCEL_FW_WRITE_OVERWRITE;
        goto out;
    }

    switch (opcode) {
    case SX_CR_DUMP_OP_START_FLAT:
    case SX_CR_DUMP_OP_START_REDUCED_FLAT:
    case SX_CR_DUMP_OP_START_GW:
    case SX_CR_DUMP_OP_START_GDB:
    case SX_CR_DUMP_OP_START_WAIT:
        priv->cr_dump_info.dumped_sn = cr_dump_ret->ret_cmd_mem.dump_sn;
        priv->cr_dump_info.trans_sn = 0;
        break;

    case SX_CR_DUMP_OP_CONT:
    case SX_CR_DUMP_OP_CONT_WAIT:
        if (priv->cr_dump_info.dumped_sn != cr_dump_ret->ret_cmd_mem.dump_sn) {
            sxd_log_err("cr_dump dump_sn mismatch: return value (%u), expected value (%u).\n",
                        cr_dump_ret->ret_cmd_mem.dump_sn,
                        priv->cr_dump_info.dumped_sn);
            err = SX_CR_DUMP_RET_CANCEL_DUMPSN_ERR;
            goto out;
        }
        priv->cr_dump_info.trans_sn++;
        if (priv->cr_dump_info.trans_sn != cr_dump_ret->ret_cmd_mem.trans_sn) {
            sxd_log_err("cr_dump trans_sn mismatch: return value (%u), expected value (%u).\n",
                        cr_dump_ret->ret_cmd_mem.trans_sn,
                        priv->cr_dump_info.trans_sn);
            err = SX_CR_DUMP_RET_CANCEL_TRANSSN_ERR;
            goto out;
        }
        break;

    default:
        sxd_log_notice("no need to check opcode (%u).\n", opcode);
        goto out;
    }

    if (cr_dump_ret->ret_cmd_mem.host_size_used >= SX_CR_DUMP_CANARY_BYTE_NUM) {
        dw1 = be32_to_cpu(*(u32 *)(buf + cr_dump_ret->ret_cmd_mem.host_size_used - SX_CR_DUMP_CANARY_BYTE_NUM));
        dw2 = be32_to_cpu(*(u32 *)(buf + cr_dump_ret->ret_cmd_mem.host_size_used - SX_CR_DUMP_CANARY_BYTE_NUM + 4));
        if ((dw1 != SX_CR_DUMP_CANARY_MAGIC_WORD) || (dw2 != SX_CR_DUMP_CANARY_MAGIC_WORD)) {
            sxd_log_err("cr_dump canary word mismatch: return value (0x%X, 0x%X), expected value (0x%X, 0x%X).\n",
                        dw1, dw2, SX_CR_DUMP_CANARY_MAGIC_WORD, SX_CR_DUMP_CANARY_MAGIC_WORD);
            err = SX_CR_DUMP_RET_CANCEL_FW_WRITE_OVERWRITE;
            goto out;
        }
    }
    priv->cr_dump_info.dumped_bytes += cr_dump_ret->ret_cmd_mem.host_size_used;

out:
    if (err) {
        err2 = __set_fw_cancel(dev);
        if (err2) {
            sxd_log_err(
                "FATAL FW ERROR: cannot cancel FW cr-dump after a fw cr-dump post-check error (%d), opcode (%d).\n",
                err,
                opcode);
        }
    }
    return err;
}
static void __virt_unmap_dma_bus(struct sx_dev *dev, dma_addr_t dma_addr, int size)
{
    dma_unmap_single(&dev->pdev->dev, dma_addr, size, DMA_BIDIRECTIONAL);
}

static int __virt_map_dma_bus(struct sx_dev *dev, void *virt_addr, int size, dma_addr_t *dma_addr)
{
    int err = 0;

    *dma_addr = dma_map_single(&dev->pdev->dev, virt_addr, size, DMA_BIDIRECTIONAL);
    if (dma_mapping_error(&dev->pdev->dev, *dma_addr)) {
        sxd_log_err(
            "__virt_map_dma_bus: failed to map (dma_map_single) virtual_addr(0x%p, physical_addr: 0x%llx) to dma bus address\n",
            virt_addr,
            virt_to_phys(virt_addr));
        err = -ENOMEM;
        goto out;
    }
out:
    if (err) {
        sxd_log_err("__virt_map_dma_bus: err (%d)\n", err);
    }
    return err;
}

static bool __skip_setting_fw(u8 ret_opcode)
{
    return ((ret_opcode == SX_CR_DUMP_OP_START_WAIT) || (ret_opcode == SX_CR_DUMP_OP_CONT_WAIT));
}

static int __trigger_fw_cr_dump(struct sx_dev         *dev,
                                u8                     opcode,
                                unsigned char         *buf,
                                int                    size,
                                struct sx_cr_dump_ret *cr_dump_ret)
{
    u8              ret_opcode = 0, ret_status = 0;
    u32             lay1_waited_num = 0;
    u32             cr_dump_wait_us = 0;
    u32             complete_dword = 0;
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);

#ifdef PD_BU
    int pld_sleep_factor = 1000;
#else
    int pld_sleep_factor = 1;
#endif

    if (!__skip_setting_fw(opcode)) {
        if (!priv->cr_dump_info.dma_buff_used) {
            err = __virt_map_dma_bus(dev, buf, size, &priv->cr_dump_info.dma_addr);
            if (err) {
                goto out;
            }
            priv->cr_dump_info.dma_buff_used = true;
            priv->cr_dump_info.dma_size = size;
            priv->crsdump_in_process = true;
        }
        err = __fw_crdump_precheck(dev, priv->cr_dump_info.dma_addr, opcode, size);
        if (err) {
            goto out;
        }

        dma_sync_single_for_device(&dev->pdev->dev, priv->cr_dump_info.dma_addr, size, DMA_BIDIRECTIONAL);
        __raw_writel((__force u32)cpu_to_be32((__force u64)(priv->cr_dump_info.dma_addr >> 32) & 0xfffffffful),
                     priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_BASE_ADDR_OFFSET);     /*MSB */
        __raw_writel((__force u32)cpu_to_be32((__force u64)priv->cr_dump_info.dma_addr & 0xfffffffful),
                     priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_BASE_ADDR_OFFSET + 4); /*lSB */

        __raw_writel((__force u32)cpu_to_be32(0), priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_SIZE_ALLOCET_OFFSET); /*MSB */
        __raw_writel((__force u32)cpu_to_be32((size) & 0xfffffffful),
                     priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_HOST_SIZE_ALLOCET_OFFSET + 4);                          /*LSB */

        /* make sure all other stuff written before triggering opcode. */
        wmb();

        /* Write only the opcode field. */
        complete_dword = be32_to_cpu(__raw_readl(priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_OPCODE_COMPLETION_OFFSET));
        complete_dword &= 0xFFFFFF00;
        __raw_writel((__force u32)cpu_to_be32(complete_dword | (opcode & 0xff)),
                     priv->cr_dump_base + SX_CR_DUMP_CMD_MEM_OPCODE_COMPLETION_OFFSET);
    } else {
        if (!priv->cr_dump_info.dma_buff_used) {
            sxd_log_err(
                "__trigger_fw_cr_dump: wrong opcode (%d) to continue waiting because no dma transaction on-going (dma:0x%llx, dma_size:%d).\n",
                opcode,
                priv->cr_dump_info.dma_addr,
                priv->cr_dump_info.dma_size);
        }
    }

    /* LAYER1 timeout value is not greater than 3*IN_WAIT_FW_DUMP_MS. */
    do {
        if (lay1_waited_num == 0) {
            cr_dump_wait_us = SX_SECURE_DUMP_MIN_WAIT_FW_DUMP_MS(priv->cr_dump_info.cr_dump_memblk_size,
                                                                 priv->cr_dump_info.gdb_dump_mode) * 1000;
            if (cr_dump_wait_us == 0) {
                sxd_log_err("mistaken memory block (%u), and wait time (%u).\n",
                            priv->cr_dump_info.cr_dump_memblk_size,
                            cr_dump_wait_us);
                cr_dump_wait_us = 40000; /* wait time for default 512KB memory block */
            }
            usleep_range(cr_dump_wait_us * pld_sleep_factor, cr_dump_wait_us * pld_sleep_factor + 10);
            /* the remaining timeout is 2 X cr_dump_wait_us */
            cr_dump_wait_us =
                SX_SECURE_DUMP_MAX_WAIT_FW_DUMP_MS(priv->cr_dump_info.cr_dump_memblk_size,
                                                   priv->cr_dump_info.gdb_dump_mode) * 1000 - cr_dump_wait_us;
        } else {
            usleep_range(SX_CR_DUMP_LAYER1_TIMER_SLEEP_US * pld_sleep_factor,
                         SX_CR_DUMP_LAYER1_TIMER_SLEEP_US * pld_sleep_factor + 10);
        }
        if (__fw_in_idle_status(dev, &ret_opcode, &ret_status)) {
            dma_sync_single_for_cpu(&dev->pdev->dev,
                                    priv->cr_dump_info.dma_addr,
                                    priv->cr_dump_info.dma_size,
                                    DMA_BIDIRECTIONAL);
            err = __fw_crdump_postcheck(dev, opcode, buf, cr_dump_ret);
            if (err) {
                goto out;
            }
            err = SX_CR_DUMP_RET_FINISH;
            goto out;
        }
        if (ret_status == SX_CR_DUMP_FW_STATUS_PENDING) {
            dma_sync_single_for_cpu(&dev->pdev->dev,
                                    priv->cr_dump_info.dma_addr,
                                    priv->cr_dump_info.dma_size,
                                    DMA_BIDIRECTIONAL);
            err = __fw_crdump_postcheck(dev, opcode, buf, cr_dump_ret);
            if (err) {
                goto out;
            }
            err = SX_CR_DUMP_RET_TO_BE_CONT;
            goto out;
        }
        /* FW should still be ONGOING */
        if (ret_status != SX_CR_DUMP_FW_STATUS_ONGOING) {
            sxd_log_err("%s(): FW status (%d) is invalid (opcode: %d), and FW may be mess-up.\n",
                        __func__, ret_status, ret_opcode);
            err = SX_CR_DUMP_RET_FATAL_FW_ERR;
            goto out;
        }
        lay1_waited_num++;
    } while (lay1_waited_num < (cr_dump_wait_us / SX_CR_DUMP_LAYER1_TIMER_SLEEP_US));

    sxd_log_notice("cr_dump LAYER1 timeout, lay1_waited_num (%u).\n", lay1_waited_num);
    err = SX_CR_DUMP_RET_LAYER1_TIMEOUT;
out:
    if (err != SX_CR_DUMP_RET_LAYER1_TIMEOUT) {
        __clear_dma_map(dev,
                        &priv->cr_dump_info.dma_buff_used,
                        &priv->cr_dump_info.dma_addr,
                        &priv->cr_dump_info.dma_size);
    }
    return err;
}

int sx_core_cr_dump_start(struct sx_dev         *dev,
                          int                    type,
                          unsigned char         *buf,
                          int                    size,
                          struct sx_cr_dump_ret *cr_dump_ret)
{
    u8  opcode = 0, status = 0;
    int check_ret = 0;

    switch (type) {
    case SX_CR_DUMP_OP_START_FLAT:
        opcode = SX_CR_DUMP_OP_START_FLAT;
        break;

    case SX_CR_DUMP_OP_START_REDUCED_FLAT:
        opcode = SX_CR_DUMP_OP_START_REDUCED_FLAT;
        break;

    case SX_CR_DUMP_OP_START_GDB:
        opcode = SX_CR_DUMP_OP_START_GDB;
        break;

    case SX_CR_DUMP_OP_START_GW:
        opcode = SX_CR_DUMP_OP_START_GW;
        break;

    default:
        sxd_log_err("ERROR: wrong cr_dump type (%u).\n", type);
        return -EFAULT;
    }

    if (!__fw_in_idle_status(dev, NULL, &status)) {
        sxd_log_err("ERROR: cannot start cr-dump, because old dump is not finished.\n");
        /* Abnormal FW state, and should try to set FW cancel to recover FW */
        check_ret = __set_fw_cancel(dev);
        if (check_ret) {
            sxd_log_err("FATAL FW ERROR: cannot cancel FW cr-dump while starting a cr-dump.\n");
            return check_ret;
        }
        return SX_CR_DUMP_RET_CANCEL_OLD_DUMP;
    }

    return __trigger_fw_cr_dump(dev, opcode, buf, size, cr_dump_ret);
}


int sx_core_cr_dump_continue(struct sx_dev         *dev,
                             int                    type,
                             unsigned char         *buf,
                             int                    size,
                             struct sx_cr_dump_ret *cr_dump_ret)
{
    u8  opcode = 0, status = 0;
    int check_ret = 0;

    if (!__fw_in_pending_status(dev, &opcode, &status)) {
        sxd_log_err(
            "ERROR: cannot continue cr-dump, because of fw status (%d) not being PENDING. Try to set FW CANCEL.\n",
            status);
        /* Abnormal FW state, and should try to set FW cancel to recover FW */
        check_ret = __set_fw_cancel(dev);
        if (check_ret) {
            sxd_log_err("FATAL FW ERROR: cannot cancel FW cr-dump while continue a ongoing cr-dump.\n");
            return check_ret;
        }
        return SX_CR_DUMP_RET_CANCEL_MESS_FW;
    }

    return __trigger_fw_cr_dump(dev, SX_CR_DUMP_OP_CONT, buf, size, cr_dump_ret);
}

int sx_core_cr_dump_cancel(struct sx_dev *dev)
{
    int err = 0;

    err = __set_fw_cancel(dev);
    if (!err) {
        err = SX_CR_DUMP_RET_CANCEL_GENERAL;
    }
    return err;
}

static int __parse_cr_dump_params(struct ku_cr_dump *params, struct sx_dev **dev, u8 *opcode)
{
    int err = 0;

    if (params->opcode != SX_CR_DUMP_OP_INVALID) {
        *opcode = params->opcode;
    } else {
        if (params->size == 0) {
            *opcode = SX_CR_DUMP_OP_CANCEL;
        } else if (params->dumped_size == 0) {
            *opcode = SX_CR_DUMP_OP_START_FLAT;
        } else if (params->dumped_size > 0) {
            *opcode = SX_CR_DUMP_OP_CONT;
        }
    }

    *dev = sx_dev_db_get_dev_by_id(params->dev_id);
    if (!(*dev)) {
        sxd_log_err("Failed to get device from ID %d\n", params->dev_id);
        err = -ENODEV;
        goto out;
    }

out:
    return err;
}

int sx_core_cr_dump_handler(struct ku_cr_dump *read_data, unsigned char *buf)
{
    struct sx_dev  *dev = NULL;
    int             err;
    u8              opcode;
    struct sx_priv *priv = NULL;

    err = __parse_cr_dump_params(read_data, &dev, &opcode);
    if (err) {
        sxd_log_err("ctrl_cmd_cr_dump: Fails to parse syscall params (dev_id: %d), err = %d\n",
                    read_data->dev_id, err);
        goto out;
    }

    priv = sx_priv(dev);
    if (!priv->cr_dump_base) {
        sxd_log_err("CR-Dump base is not initialized - can't generate CR-Dump\n");
        err = -EFAULT;
        goto out;
    }

    switch (opcode) {
    case SX_CR_DUMP_OP_CANCEL:
        err = sx_core_cr_dump_cancel(dev);
        break;

    case SX_CR_DUMP_OP_START_FLAT:
    case SX_CR_DUMP_OP_START_REDUCED_FLAT:
    case SX_CR_DUMP_OP_START_GDB:
    case SX_CR_DUMP_OP_START_GW:
        err = sx_core_cr_dump_start(dev, opcode, buf, read_data->size, &(read_data->ret));
        break;

    case SX_CR_DUMP_OP_CONT:
        err = sx_core_cr_dump_continue(dev, opcode, buf, read_data->size, &(read_data->ret));
        break;

    case SX_CR_DUMP_OP_START_WAIT:
        err = __trigger_fw_cr_dump(dev, opcode, buf, read_data->size, &(read_data->ret));
        break;

    case SX_CR_DUMP_OP_CONT_WAIT:
        err = __trigger_fw_cr_dump(dev, opcode, buf, read_data->size, &(read_data->ret));
        break;


    default:
        sxd_log_err("ERROR: wrong cr_dump opcode (%u).\n", opcode);
        err = SX_CR_DUMP_RET_NOT_SUPPORTED;
        break;
    }
    if (err > 0) {
        switch (err) {
        case SX_CR_DUMP_RET_NOT_SUPPORTED:
        case SX_CR_DUMP_RET_CANCEL_GENERAL:
        case SX_CR_DUMP_RET_CANCEL_OLD_DUMP:
        case SX_CR_DUMP_RET_CANCEL_MESS_FW:
        case SX_CR_DUMP_RET_CANCEL_FW_PARAM_MISALIGN:
        case SX_CR_DUMP_RET_CANCEL_DUMP_SIZE_OVERFLOW:
        case SX_CR_DUMP_RET_CANCEL_DUMPSN_ERR:
        case SX_CR_DUMP_RET_CANCEL_TRANSSN_ERR:
        case SX_CR_DUMP_RET_CANCEL_FW_WRITE_OVERWRITE:
        case SX_CR_DUMP_RET_CANCEL_CANARY_ERR:
        case SX_CR_DUMP_RET_FATAL_FW_ERR:
            sxd_log_err("sx_core_cr_dump_handler(): Fails to call opcode (%d), err = %d\n",
                        read_data->opcode, err);
            break;

        case SX_CR_DUMP_RET_FINISH:
        case SX_CR_DUMP_RET_TO_BE_CONT:
        case SX_CR_DUMP_RET_LAYER1_TIMEOUT:
            break;

        default:
            sxd_log_err("sx_core_cr_dump_handler(): Fails to call opcode (%d), unknown err = %d\n",
                        read_data->opcode, err);
            break;
        }
        read_data->ret.ret_code = err;
        err = 0;
    } else {
        read_data->ret.ret_code = 0;
    }

out:
    return err;
}

int sx_core_cr_dump_get_cap_dump_host_size(u8 opcode, struct sx_dev *dev, struct sx_cr_dump_ret *ret)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);

    switch (opcode) {
    case SX_CR_DUMP_OP_GET_GDB_DUMP_LIMIT:
        ret->ret_cmd_mem.host_size_used = priv->cr_dump_info.cap_dump_host_size_gdb;
        break;

    default:
        sxd_log_err("ERROR: wrong cr_dump opcode (%u).\n", opcode);
        err = SX_CR_DUMP_RET_NOT_SUPPORTED;
        break;
    }
    if (ret->ret_cmd_mem.host_size_used == 0) {
        err = SX_CR_DUMP_RET_NOT_SUPPORTED;
    }
    ret->ret_code = err;

    return err;
}

static int __get_sgmii_cr_dump_offset(sxd_dev_id_t dev_id, u32 *cr_dump_offset_p)
{
    u32 base_info_ptr_mem; /* PRM: Base_Info_Pointer_Mem */
    u32 cr_dump_offset;
    int err = 0;

    /* On MantaRay, priv->fw is not initialized - so we read fw_dump_completion_state address
     * directly from FW (BASE_INFO_PTR_MEM is constant and defined in PRM).
     * BASE_INFO_PTR_MEM + 4 is where fw_dump_completion_state address is stored. */
    err = sx_dpt_cr_space_read(dev_id, BASE_INFO_PTR_MEM, (u8*)&base_info_ptr_mem, sizeof(base_info_ptr_mem));
    if (err) {
        sxd_log_err("failed to get SGMII base_info_ptr_mem (err=%d)\n", err);
        return err;
    }

    base_info_ptr_mem = be32_to_cpu(base_info_ptr_mem);

    err = sx_dpt_cr_space_read(dev_id, base_info_ptr_mem + 4, (u8*)&cr_dump_offset, sizeof(cr_dump_offset));
    if (err) {
        sxd_log_err("failed to get SGMII cr_dump_offset (err=%d)\n", err);
        return err;
    }

    *cr_dump_offset_p = be32_to_cpu(cr_dump_offset);
    return 0;
}

static int __get_pci_cr_dump_offset(sxd_dev_id_t dev_id, u32 *cr_dump_offset_p)
{
    struct sx_dev *dev = sx_dev_db_get_dev_by_id(dev_id);

    if (!dev) {
        sxd_log_err("failed to get pci_cr_dump_offset, device not found (dev_id=%u)\n", dev_id);
        return -ENODEV;
    }

    *cr_dump_offset_p = sx_priv(dev)->fw.cr_dump_offset;
    return 0;
}

static int __get_cr_dump_offset(sxd_dev_id_t dev_id, u32 *cr_dump_offset_p)
{
    int err;

    if (is_sgmii_supported()) {
        err = __get_sgmii_cr_dump_offset(dev_id, cr_dump_offset_p);
    } else {
        err = __get_pci_cr_dump_offset(dev_id, cr_dump_offset_p);
    }

    if (err) {
        sxd_log_err("failed to get cr_dump_offset (dev_id=%u, err=%d)\n", dev_id, err);
    }

    return err;
}

static int __get_cr_dump_completion_dword(sxd_dev_id_t dev_id, u32 cr_dump_offset, u32 *completion_dword_p)
{
    u32 completion_dword;
    int err;

    err = sx_dpt_cr_space_read(dev_id,
                               cr_dump_offset + SX_CR_DUMP_CMD_MEM_OPCODE_COMPLETION_OFFSET,
                               (u8*)&completion_dword,
                               sizeof(completion_dword));
    if (err) {
        sxd_log_err("failed to read cr_dump completion dword (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    *completion_dword_p = be32_to_cpu(completion_dword);
    return 0;
}

int sx_core_cr_dump_long_cmd_get(sxd_dev_id_t dev_id, fw_dump_completion_state_t *state)
{
    u32 completion_dword;
    u32 cr_dump_offset;
    int err;

    err = __get_cr_dump_offset(dev_id, &cr_dump_offset);
    if (err) {
        sxd_log_err("failed to query long_cmd offset to get state (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    err = __get_cr_dump_completion_dword(dev_id, cr_dump_offset, &completion_dword);
    if (err) {
        sxd_log_err("failed to query completion_dword to get state (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    *state = (fw_dump_completion_state_t)((completion_dword >> 24) & 0x3);
    return 0;
}

int sx_core_cr_dump_long_cmd_set(sxd_dev_id_t dev_id, fw_dump_completion_state_t state)
{
    u32 completion_dword;
    u32 cr_dump_offset;
    int err;

    err = __get_cr_dump_offset(dev_id, &cr_dump_offset);
    if (err) {
        sxd_log_err("failed to query long_cmd offset to set state (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    err = __get_cr_dump_completion_dword(dev_id, cr_dump_offset, &completion_dword);
    if (err) {
        sxd_log_err("failed to query completion_dword to set state (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    /* Change only the completion state. */
    completion_dword &= 0xFCFFFFFF;
    completion_dword |= (state & 0x3) << 24;
    completion_dword = cpu_to_be32(completion_dword);
    err = sx_dpt_cr_space_write(dev_id,
                                cr_dump_offset + SX_CR_DUMP_CMD_MEM_OPCODE_COMPLETION_OFFSET,
                                (u8*)&completion_dword,
                                sizeof(completion_dword));
    if (err) {
        sxd_log_err("failed to set state in cr_dump address (dev_id=%u, err=%d)\n", dev_id, err);
        return err;
    }

    return 0;
}

void sx_core_cr_dump_notify_dump_completion(sxd_dev_id_t dev_id, bool query, fw_dump_completion_state_t* state)
{
    int err;

    if (query) {
        err = sx_core_cr_dump_long_cmd_get(dev_id, state);
    } else {
        err = sx_core_cr_dump_long_cmd_set(dev_id, *state);
    }

    if (err) {
        sxd_log_err("cr_dump_notify_completion failed (dev_id=%u, query=%s, err=%d)\n",
                    dev_id, ((query) ? "yes" : "no"), err);
    }
}

int sx_core_cr_dump_init(struct sx_priv *priv)
{
    priv->cr_dump_base = ioremap(pci_resource_start(priv->dev.pdev,
                                                    priv->fw.cr_dump_bar) + priv->fw.cr_dump_offset,
                                 SX_CR_DUMP_CMD_MEM_SIZE);
    if (!priv->cr_dump_base) {
        sxd_log_err("Couldn't map cr dump command mem register, aborting.\n");
        return -ENOMEM;
    }

    priv->cr_dump_info.cap_dump_host_size_flat =
        priv->fw.cap_dump_host_size_flat ? priv->fw.cap_dump_host_size_flat : SX_CR_DUMP_DEFAULT_HOST_SIZE;
    priv->cr_dump_info.cap_dump_host_size_reduced_flat =
        priv->fw.cap_dump_host_size_reduced_flat ? priv->fw.cap_dump_host_size_reduced_flat :
        SX_CR_DUMP_DEFAULT_HOST_SIZE;
    priv->cr_dump_info.cap_dump_host_size_gw =
        priv->fw.cap_dump_host_size_gw ? priv->fw.cap_dump_host_size_gw : SX_CR_DUMP_DEFAULT_HOST_SIZE;
    priv->cr_dump_info.cap_dump_host_size_gdb =
        priv->fw.cap_dump_host_size_gdb ? priv->fw.cap_dump_host_size_gdb : SX_CR_DUMP_DEFAULT_HOST_SIZE;
    priv->cr_dump_info.cap_current_dump_host_size = 0;
    priv->cr_dump_info.dumped_sn = 0;
    priv->cr_dump_info.trans_sn = 0;
    priv->cr_dump_info.dumped_bytes = 0;
    priv->cr_dump_info.cr_dump_memblk_size = SX_CR_DUMP_MEMBLK_SIZE;
    priv->cr_dump_info.dma_addr = 0;
    priv->cr_dump_info.dma_buff_used = false;
    priv->cr_dump_info.gdb_dump_mode = false;
    priv->cr_dump_info.dma_size = 0;
    priv->crsdump_in_process = false;

    sxd_log_notice(
        "cr_dump init: dev %u, cap_dump_host_size_flat:%u, cap_dump_host_size_reduced_flat:%u, cap_dump_host_size_gw:%u, cap_dump_host_size_gdb:%u.\n",
        priv->dev.device_id,
        priv->cr_dump_info.cap_dump_host_size_flat,
        priv->cr_dump_info.cap_dump_host_size_reduced_flat,
        priv->cr_dump_info.cap_dump_host_size_gw,
        priv->cr_dump_info.cap_dump_host_size_gdb
        );

    return 0;
}

void sx_core_cr_dump_deinit(struct sx_priv *priv)
{
    iounmap(priv->cr_dump_base);
}
