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

#include <linux/delay.h>
#include "sx.h"

#define SECURED_CR_LOG_PREFIX "Secured-CR: "

/* PRM: 2.2.1 CrSpace VSEC / Table 15 - VSEC - PCI Vendor Specific Capabilities Layout */
#define VSC_CAPABILITY_ID  0x09
#define VSC_SPACE_CR_SPACE 0x02
#define VSC_LENGTH_OFFSET(priv)    ((priv)->secured_cr.vsc_start + 0x02)
#define VSC_TYPE_OFFSET(priv)      ((priv)->secured_cr.vsc_start + 0x03)
#define VSC_SPACE_OFFSET(priv)     ((priv)->secured_cr.vsc_start + 0x04)
#define VSC_COUNTER_OFFSET(priv)   ((priv)->secured_cr.vsc_start + 0x08)
#define VSC_SEMAPHORE_OFFSET(priv) ((priv)->secured_cr.vsc_start + 0x0c)
#define VSC_ADDRESS_OFFSET(priv)   ((priv)->secured_cr.vsc_start + 0x10)
#define VSC_DATA_OFFSET(priv)      ((priv)->secured_cr.vsc_start + 0x14)

static bool __is_valid_vsc(struct sx_priv *priv)
{
    u8  type = 0, length = 0;
    int err = 0;

    /* check that type is 0 */
    err = pci_read_config_byte(priv->dev.pdev, VSC_TYPE_OFFSET(priv), &type);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to get VSC type\n");
        return false;
    }

    if (type != 0) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "type is not 0 (type=%u)\n", type);
        return false;
    }

    /* check that length is 24 */
    err = pci_read_config_byte(priv->dev.pdev, VSC_LENGTH_OFFSET(priv), &length);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to get VSC length\n");
        return false;
    }

    if (length != 24) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "type is not 24 (length=%u)\n", length);
        return false;
    }

    return true;
}

static bool __init_vsc_address(struct sx_priv *priv)
{
    /* find the first Vendor-Specific Capability (VSC) */
    priv->secured_cr.vsc_start = pci_find_capability(priv->dev.pdev, VSC_CAPABILITY_ID);
    if (priv->secured_cr.vsc_start == 0) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "Secured VSC: could not get VSC address\n");
        return false;
    }

    if (!__is_valid_vsc(priv)) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "Secured VSC: address is not valid\n");
        return false;
    }

    return true;
}

static int __lock_vsec_semaphore(struct sx_priv *priv)
{
    unsigned long end = jiffies + msecs_to_jiffies(1000); /* wait up to 1 second */
    u32           sem_val = 0;
    u32           counter = 0;
    int           err = -ETIMEDOUT;

    while (time_before(jiffies, end)) {
        err = pci_read_config_dword(priv->dev.pdev, VSC_SEMAPHORE_OFFSET(priv), &sem_val);
        if (err) {
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to read semaphore value (err=%d)\n", err);
            break;
        }

        if (sem_val != 0) { /* semaphore is not free */
            msleep(1);
            continue;
        }

        /* if we're here, semaphore is free. need to acquire it now */

        /* read current counter */
        err = pci_read_config_dword(priv->dev.pdev, VSC_COUNTER_OFFSET(priv), &counter);
        if (err) {
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to get counter (err=%d)\n", err);
            break;
        }

        /* write counter value to semaphore */
        err = pci_write_config_dword(priv->dev.pdev, VSC_SEMAPHORE_OFFSET(priv), counter);
        if (err) {
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to write counter value to semaphore (err=%d)\n", err);
            break;
        }

        /* check that semaphore value is updated correctly */
        err = pci_read_config_dword(priv->dev.pdev, VSC_SEMAPHORE_OFFSET(priv), &sem_val);
        if (err) {
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to read semaphore value after updating it (err=%d)\n", err);
            break;
        }

        if (counter == sem_val) {
            err = 0;
            break;
        }
    }

    return err;
}

static int __unlock_vsec_semaphore(struct sx_priv *priv)
{
    int err = 0;

    err = pci_write_config_dword(priv->dev.pdev, VSC_SEMAPHORE_OFFSET(priv), 0);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to unlock semaphore (err=%d)\n", err);
    }

    return err;
}

static int __set_space(struct sx_priv *priv)
{
    u32 value = 0;
    int err = 0;

    value = VSC_SPACE_CR_SPACE;
    err = pci_write_config_dword(priv->dev.pdev, VSC_SPACE_OFFSET(priv), value);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to write VSD space\n");
        return -EINVAL;
    }

    err = pci_read_config_dword(priv->dev.pdev, VSC_SPACE_OFFSET(priv), &value);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to read VSD space after update\n");
        return -EINVAL;
    }

    value >>= 29; /* keep MSB 3-bit (VSC 'status') */

    if (value != 1) { /* either not supported or FW is busy */
        sxd_log_err(SECURED_CR_LOG_PREFIX "bad status (status=%u)\n", value);
        err = -EINVAL;
    }

    return err;
}

static int __wait_read_gw_done(struct sx_priv *priv)
{
    unsigned long end = jiffies + msecs_to_jiffies(5000); /* wait up to 5 seconds */
    int           err = -ETIMEDOUT;
    u32           flag = 0;

    while (time_before(jiffies, end)) {
        err = pci_read_config_dword(priv->dev.pdev, VSC_ADDRESS_OFFSET(priv), &flag);
        if (err) {
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to wait for GW read-operation (err=%d)\n", err);
            break;
        }

        flag >>= 31; /* flag is bit 31 */
        if (flag) {
            err = 0;
            break;
        }
    }

    return err;
}

/* this function must be called when semaphore is locked */
static int __gw_read(struct sx_priv *priv, u32 offset, u32 *data)
{
    int err = 0;

    /* offset is a 30-bit value (bits 0-29). bit 30 is reserved. bit 31 is the VSC flag.
     * set bit 31 to 0 to indicate read operation from this offset */
    offset &= 0x3fffffff;

    err = pci_write_config_dword(priv->dev.pdev, VSC_ADDRESS_OFFSET(priv), offset);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to write offset (err=%d)\n", err);
        goto out;
    }

    err = __wait_read_gw_done(priv);
    if (err) {
        goto out;
    }

    err = pci_read_config_dword(priv->dev.pdev, VSC_DATA_OFFSET(priv), data);
    if (err) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to read data from offset (err=%d)\n", err);
        goto out;
    }

out:
    return err;
}

static u64 __get_base_info_pointer_mem(struct sx_priv *priv)
{
    /* PRM: 2.4 Memory Map / Table 22 - Offset of fixed-offset memories */
    if (priv->dev_specific_cb.get_base_info_pointer_mem_cb) {
        return priv->dev_specific_cb.get_base_info_pointer_mem_cb();
    }

    return 0; /* invalid */
}

int sx_core_secured_cr_init(struct sx_dev *dev)
{
    struct sx_priv *priv = sx_priv(dev);
    u64             base_info_pointer_mem = 0;
    u32             base_info_mem = 0;
    u32             val = 0;
    int             err = 0;

    base_info_pointer_mem = __get_base_info_pointer_mem(priv);
    if (base_info_pointer_mem == 0) {
        return -ENOTSUPP;
    }

    base_info_mem = swab32(readl(priv->cr_space_start + base_info_pointer_mem));

    if (!__init_vsc_address(priv)) {
        sxd_log_err(SECURED_CR_LOG_PREFIX "failed to get secured CR start address!\n");
        err = -EFAULT;
        goto out;
    }

#define READ_BASE_INFO_MEM(offset)                                                                      \
    do {                                                                                                \
        err = sx_core_secured_cr_read(dev, base_info_mem + (offset), &val);                             \
        if (err) {                                                                                      \
            sxd_log_err(SECURED_CR_LOG_PREFIX "failed to call secured CR read (offset=0x%x, err=%d)\n", \
                        (base_info_mem + (offset)), err);                                               \
            goto out;                                                                                   \
        }                                                                                               \
        sxd_log_notice(SECURED_CR_LOG_PREFIX "offset=0x%x, val=%u\n", (offset), val);                   \
    } while (0)

    /* this information comes natively from QUERY_FW but if FW is stuck and QUERY_FW
     * does not work, we need to get this information elsewhere (in scratchpad)
     * PRM: 2.4.3 Base_Info_Mem */
    priv->fw.cr_dump_bar = 0;

    READ_BASE_INFO_MEM(0); /* cr_dump0_h */
    priv->fw.cr_dump_offset = ((u64)val) << 32;

    READ_BASE_INFO_MEM(0x4); /* cr_dump0_l */
    priv->fw.cr_dump_offset |= val;

    READ_BASE_INFO_MEM(0x10); /* cap_dump_host_size_flat */
    priv->fw.cap_dump_host_size_flat = val;

    READ_BASE_INFO_MEM(0x14); /* cap_dump_host_size_gw */
    priv->fw.cap_dump_host_size_gw = val;

    READ_BASE_INFO_MEM(0x18); /* cap_dump_host_size_gdb */
    priv->fw.cap_dump_host_size_gdb = val;

    READ_BASE_INFO_MEM(0x34); /* cap_dump_host_size_reduced_flat */
    priv->fw.cap_dump_host_size_reduced_flat = val;

out:
    return err;
}

int sx_core_secured_cr_read(struct sx_dev *dev, u32 offset, u32 *data)
{
    struct sx_priv *priv = sx_priv(dev);
    int             err = 0;

    err = __lock_vsec_semaphore(priv);
    if (err) {
        goto out;
    }

    err = __set_space(priv);
    if (err) {
        goto out_unlock;
    }

    err = __gw_read(priv, offset, data);
    if (err) {
        goto out_unlock;
    }

out_unlock:
    err = __unlock_vsec_semaphore(priv);
    if (err) {
        goto out;
    }

out:
    return err;
}
