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

#include <linux/module.h>
#include <linux/if_vlan.h>
#include <linux/poll.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/skb_hook.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/driver.h>

#include "sx.h"
#include "alloc.h"
#include "dev_init.h"
#include "dev_db.h"
#include "emad.h"

/************************************************
 *  Define
 ***********************************************/
#define EEPROM_UPPER_PAGE_OFFSET       (0x80)
#define EEPROM_MODULE_PAGE_SELECT_ADDR 127
#define MCIA_EEPROM_MAX_ACCESS_SIZE    48
#define MCIA_DWOARD_BYTE1(dword) (((dword) >> 24) & 0xFF)
#define MCIA_DWOARD_BYTE2(dword) (((dword) >> 16) & 0xFF)
#define MCIA_DWOARD_BYTE3(dword) (((dword) >> 8) & 0xFF)
#define MCIA_DWOARD_BYTE4(dword) (((dword)) & 0xFF)

#define MCIA_BYTE1_TO_DWOARD(byte) (((byte) << 24) & 0xFF000000)
#define MCIA_BYTE2_TO_DWOARD(byte) (((byte) << 16) & 0x00FF0000)
#define MCIA_BYTE3_TO_DWOARD(byte) (((byte) << 8) & 0x0000FF00)
#define MCIA_BYTE4_TO_DWOARD(byte) ((byte) & 0x000000FF)

#define MCIA_ACCESS_MAX_RETRIES 3

static ssize_t __module_sysfs_eeprom_bin_read(struct file          *flip,
                                              struct kobject       *kobj,
                                              struct bin_attribute *attr,
                                              char                 *buf,
                                              loff_t                pos,
                                              size_t                count);
static ssize_t __module_sysfs_eeprom_bin_write(struct file          *flip,
                                               struct kobject       *kobj,
                                               struct bin_attribute *attr,
                                               char                 *buf,
                                               loff_t                pos,
                                               size_t                count);

static struct bin_attribute module_eeprom_page0_attribute = __BIN_ATTR(data,
                                                                       (S_IRUGO | S_IWUSR),
                                                                       __module_sysfs_eeprom_bin_read,
                                                                       __module_sysfs_eeprom_bin_write,
                                                                       EEPROM_PAGE0_SIZE);
static struct bin_attribute module_eeprom_pagex_attribute = __BIN_ATTR(data,
                                                                       (S_IRUGO | S_IWUSR),
                                                                       __module_sysfs_eeprom_bin_read,
                                                                       __module_sysfs_eeprom_bin_write,
                                                                       EEPROM_UPPER_PAGE_SIZE);

/************************************************
 *  Enum
 ***********************************************/
enum eeprom_management_type {
    EEPROM_MANAGEMENT_TYPE_SFP  = 0x01,
    EEPROM_MANAGEMENT_TYPE_QSFP = 0x02,
    EEPROM_MANAGEMENT_TYPE_CMIS = 0x03,
};

enum eeprom_module_info_id {
    EEPROM_MODULE_INFO_ID_SFP            = 0x03,
    EEPROM_MODULE_INFO_ID_QSFP           = 0x0C,
    EEPROM_MODULE_INFO_ID_QSFP_PLUS      = 0x0D,
    EEPROM_MODULE_INFO_ID_QSFP28         = 0x11,
    EEPROM_MODULE_INFO_ID_QSFP_DD        = 0x18,
    EEPROM_MODULE_INFO_ID_QSFP_8X        = 0x19,
    EEPROM_MODULE_INFO_ID_SFP_DD         = 0x1A,
    EEPROM_MODULE_INFO_ID_DSFP           = 0x1B,
    EEPROM_MODULE_INFO_ID_QSFP_PLUS_CMIS = 0x1E,
};

enum mcia_module_status {
    MCIA_MODULE_STATUS_GOOD                  = 0,
    MCIA_MODULE_STATUS_NO_EEPROM_MODULE      = 0x1,
    MCIA_MODULE_STATUS_MODULE_NOT_SUPPORTED  = 0x2,
    MCIA_MODULE_STATUS_MODULE_NOT_CONNECTED  = 0x3,
    MCIA_MODULE_STATUS_MODULE_TYPE_INVALID   = 0x4,
    MCIA_MODULE_STATUS_MODULE_NOT_ACCESSIBLE = 0x5,
    MCIA_MODULE_STATUS_I2C_ERROR             = 0x9,
    MCIA_MODULE_STATUS_MODULE_DISABLED       = 0x10,
    MCIA_MODULE_STATUS_PAGE_ACCESS_FAILED    = 0x11,
};

enum mcia_module_access_type {
    MCIA_MODULE_ACCESS_TYPE_READ  = 1,
    MCIA_MODULE_ACCESS_TYPE_WRITE = 2,
};

/************************************************
 * Type declarations
 ***********************************************/
struct page_limit_bytes_segment {
    int page;
    int begin;
    int end;
};

struct page_access_segment {
    int begin;
    int end;
};

/************************************************
 * Globals
 ***********************************************/
/* entries within same page should be added adjacently and in sequence */
static struct page_limit_bytes_segment cmis_rd_limit_arr[] = {
    {0, 126, 127},
    {11, 134, 135}
};

static struct page_limit_bytes_segment cmis_wr_limit_arr[] = {
    {0, 26, 26},
    {0, 31, 36},
    {0, 126, 127},
    {10, 0, 255}
};

static struct page_limit_bytes_segment sff8636_rd_limit_arr[] = {
    {0, 3, 21},
    {0, 127, 127}
};

static struct page_limit_bytes_segment sff8636_wr_limit_arr[] = {
    {0, 86, 88},
    {0, 93, 93},
    {0, 98, 99},
    {0, 100, 106},
    {0, 127, 127},
    {3, 230, 251}
};

/* SFF8472's limitation bytes are only for i2c 0x51 */
static struct page_limit_bytes_segment sff8472_rd_limit_arr[] = {
    {0, 112, 113},
    {0, 116, 117},
    {0, 127, 127}
};

static struct page_limit_bytes_segment sff8472_wr_limit_arr[] = {
    {0, 110, 110},
    {0, 114, 115},
    {0, 118, 118},
    {0, 127, 127}
};

static int cmis_rd_limit_arr_len = ARRAY_SIZE(cmis_rd_limit_arr);
static int cmis_wr_limit_arr_len = ARRAY_SIZE(cmis_wr_limit_arr);
static int sff8636_rd_limit_arr_len = ARRAY_SIZE(sff8636_rd_limit_arr);
static int sff8636_wr_limit_arr_len = ARRAY_SIZE(sff8636_wr_limit_arr);
static int sff8472_rd_limit_arr_len = ARRAY_SIZE(sff8472_rd_limit_arr);
static int sff8472_wr_limit_arr_len = ARRAY_SIZE(sff8472_wr_limit_arr);

/************************************************
 *  Functions
 ***********************************************/

static inline void __reg_mcia_pack(struct ku_mcia_reg *mcia_reg,
                                   uint8_t             module,
                                   uint8_t             lock,
                                   uint8_t             page,
                                   uint8_t             pnv,
                                   uint16_t            device_addr,
                                   ssize_t             size,
                                   uint8_t             i2c_addr,
                                   uint8_t             slot)
{
    mcia_reg->l = lock;
    mcia_reg->pnv = pnv;
    mcia_reg->module = module;
    mcia_reg->slot_index = slot;
    mcia_reg->i2c_device_address = i2c_addr;
    mcia_reg->page_number = page;
    mcia_reg->device_address = device_addr;
    mcia_reg->size = size;
}

static int __handle_mcia_return_status(struct ku_mcia_reg mcia_reg)
{
    int err = 0;

    switch (mcia_reg.status) {
    case MCIA_MODULE_STATUS_GOOD:
        break;

    case MCIA_MODULE_STATUS_MODULE_NOT_CONNECTED:
    case MCIA_MODULE_STATUS_I2C_ERROR:
    case MCIA_MODULE_STATUS_MODULE_DISABLED:
    case MCIA_MODULE_STATUS_MODULE_TYPE_INVALID:
        sxd_log_debug("Fails to access MCIA due to unavailable hw link, status: %d.\n", mcia_reg.status);
        err = -EIO;
        break;

    default:
        sxd_log_err("Fails to access MCIA, module: %u, status: %d.\n", mcia_reg.module, mcia_reg.status);
        err = -EFAULT;
    }

    return err;
}

/* Module eeprom access via MCIA may be blocked by other access via PMMP, etc., and FW will return busy to SDK. SDK should retry several times. */
static int __stateful_access_mcia(struct sx_dev *dev, struct ku_access_mcia_reg *reg_data)
{
    int err = 0;
    int try_loop = MCIA_ACCESS_MAX_RETRIES;/* FW would hold 20mSec per try. */

    while (try_loop-- > 0) {
        err = sx_ACCESS_REG_MCIA(dev, reg_data);
        if (err || reg_data->op_tlv.status) {
            if (reg_data->op_tlv.status == SX_EMAD_STATUS_BUSY_E) {
                err = -EBUSY;
                continue;
            }
            sxd_log_err("Fails to access register MCIA, err: %d, status: %d.\n", err, reg_data->op_tlv.status);
            err = -EFAULT;
            goto out;
        }
        goto out;
    }
out:
    return err;
}

static int __sx_core_mcia_access(struct sx_dev             *dev,
                                 uint8_t                    access_type,
                                 uint8_t                    module,
                                 uint8_t                    page,
                                 uint8_t                    pnv,
                                 uint16_t                   device_addr,
                                 uint8_t                    size,
                                 uint8_t                    i2c_addr,
                                 uint8_t                    slot,
                                 struct ku_access_mcia_reg *reg_data)
{
    int     err = 0;
    uint8_t lock = 0; /* suggested to be 0 by FW team. */
    uint8_t method = EMAD_METHOD_QUERY;

    if (access_type == MCIA_MODULE_ACCESS_TYPE_WRITE) {
        method = EMAD_METHOD_WRITE;
    }

    reg_data->dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&(reg_data->op_tlv), MCIA_REG_ID, method);

    __reg_mcia_pack(&(reg_data->mcia_reg), module, lock, page, pnv, device_addr, size, i2c_addr, slot);

    sx_int_log_info(&sx_priv(dev)->module_log, "Module ID %d | MCIA pack:pnv=%d i2c_addr=0x%x page=%d offset=%d",
                    reg_data->mcia_reg.module,  reg_data->mcia_reg.pnv,
                    reg_data->mcia_reg.i2c_device_address, reg_data->mcia_reg.page_number,
                    reg_data->mcia_reg.device_address);
    err = __stateful_access_mcia(dev, reg_data);
    if (err) {
        sxd_log_err(
            "Fails to access (%d) register MCIA (module:%d, page:%d, pnv:%d, device_addr:%d, size:%d, i2c_addr:0x%x, slot:%d, status:%d), err: %d.\n",
            method,
            module,
            page,
            pnv,
            device_addr,
            size,
            i2c_addr,
            slot,
            reg_data->mcia_reg.status,
            err);
        goto out;
    }

out:
    return err;
}

/* This function is valid for independent module only.
 * It reads page value from EEPROM (byte 127 in lower page). */
int sx_core_get_module_page_from_eeprom(struct sx_dev *dev, uint8_t module, uint8_t slot, uint8_t *page_p)
{
    int                       err = 0;
    struct ku_access_mcia_reg reg_data;

    memset(&reg_data, 0, sizeof(reg_data));

    reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&reg_data.op_tlv, MCIA_REG_ID, EMAD_METHOD_QUERY);
    /* page is in byte 127, Due to Endianness issues we need to access addresses that are 4 bytes aligned */
    __reg_mcia_pack(&reg_data.mcia_reg, module, 0, 0, 1, 124, 4, 0x50, slot);

    sx_int_log_info(&sx_priv(dev)->module_log, "Module ID %d | MCIA pack:pnv=%d i2c_addr=0x%x page=%d offset=%d",
                    reg_data.mcia_reg.module,  reg_data.mcia_reg.pnv,
                    reg_data.mcia_reg.i2c_device_address, reg_data.mcia_reg.page_number,
                    reg_data.mcia_reg.device_address);

    err = __stateful_access_mcia(dev, &reg_data);
    if (err) {
        sxd_log_err("Fails to get module page, err: %d.\n", err);
        goto out;
    }

    if (reg_data.mcia_reg.status) {
        err = __handle_mcia_return_status(reg_data.mcia_reg);
        goto out;
    }
    /* location of bytes in word  : |124|125|126|127| */
    *page_p = MCIA_DWOARD_BYTE4(reg_data.mcia_reg.dword_0);
    sx_int_log_info(&sx_priv(dev)->module_log, "Module ID %d | Module page from eeprom %d", module, *page_p);

out:
    if (err != 0) {
        sx_int_log_error(&sx_priv(dev)->module_log, "Module ID %d | Get page from eeprom failed status %d", module,
                         err);
    }
    return err;
}
EXPORT_SYMBOL(sx_core_get_module_page_from_eeprom);

/* This function is valid for independent module only.
 * It sets pnv=0 if last access page changed. */
static int __sx_core_get_module_page_valid(struct sx_dev *dev,
                                           uint8_t        module,
                                           uint8_t        slot,
                                           uint8_t        page,
                                           uint8_t       *pnv_p)
{
    int     err = 0;
    uint8_t last_page = 0;

    /* Read last page access from eeprom */
    err = sx_core_get_module_page_from_eeprom(dev,
                                              module,
                                              slot,
                                              &last_page);
    if (err) {
        sxd_log_err("Failed to get module page from eeprom, err: %d.\n", err);
        goto out;
    }

    if (last_page == page) {
        /* Accessing same page: no need to write page value to page offset in EEPROM.
         * Indicate FW-MGMT to skip this operation by setting MCIA.PNV=1. */
        *pnv_p = 1;
    } else {
        /* Accessing different page: need writing to page offset in EEPROM.
         * Use legacy MCIA.PNV=0. */
        *pnv_p = 0;
    }

    sx_int_log_info(&sx_priv(dev)->module_log,
                    "Module ID %d | access page %d, last page %d, pnv %d",
                    module,
                    page,
                    last_page,
                    *pnv_p);

out:
    return err;
}

static int __sx_core_get_module_type(struct sx_dev *dev, uint8_t module, uint8_t slot, uint8_t *type)
{
    int                       err = 0;
    uint8_t                   byte0 = 0;
    struct ku_access_mcia_reg reg_data;

    memset(&reg_data, 0, sizeof(reg_data));

    reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&reg_data.op_tlv, MCIA_REG_ID, EMAD_METHOD_QUERY);

    __reg_mcia_pack(&reg_data.mcia_reg, module, 0, 0, 0, 0, 1, 0x50, slot);

    sx_int_log_info(&sx_priv(dev)->module_log, "Module ID %d | MCIA pack:pnv=%d i2c_addr=0x%x page=%d offset=%d",
                    reg_data.mcia_reg.module,  reg_data.mcia_reg.pnv,
                    reg_data.mcia_reg.i2c_device_address, reg_data.mcia_reg.page_number,
                    reg_data.mcia_reg.device_address);
    err = __stateful_access_mcia(dev, &reg_data);
    if (err) {
        sxd_log_err("Fails to get module type, err: %d.\n", err);
        goto out;
    }

    if (reg_data.mcia_reg.status) {
        err = __handle_mcia_return_status(reg_data.mcia_reg);
        goto out;
    }

    byte0 = MCIA_DWOARD_BYTE1(reg_data.mcia_reg.dword_0);
    switch (byte0) {
    case EEPROM_MODULE_INFO_ID_SFP:
        *type = EEPROM_MANAGEMENT_TYPE_SFP;
        break;

    case EEPROM_MODULE_INFO_ID_QSFP:
    case EEPROM_MODULE_INFO_ID_QSFP_PLUS:
    case EEPROM_MODULE_INFO_ID_QSFP28:
        *type = EEPROM_MANAGEMENT_TYPE_QSFP;
        break;

    case EEPROM_MODULE_INFO_ID_QSFP_DD:
    case EEPROM_MODULE_INFO_ID_QSFP_8X:
    case EEPROM_MODULE_INFO_ID_SFP_DD:
    case EEPROM_MODULE_INFO_ID_DSFP:
    case EEPROM_MODULE_INFO_ID_QSFP_PLUS_CMIS:
        *type = EEPROM_MANAGEMENT_TYPE_CMIS;
        break;

    default:
        sxd_log_err("Unknown EEPROM type: %d.\n", byte0);
        return -EFAULT;
    }
    sx_int_log_info(&sx_priv(dev)->module_log, "Module ID %d | Eeprom byte0 0x%x type %d", module, byte0, *type);
out:
    return err;
}

/*
 *  check whether buff range [buf_b, buf_e] is overlapping with a limitation byte range [limit_b, limit_e]:
 *   if yes, return true, with the overlapping range in [*hole_b, *hole_e]
 *   if no, return false
 */
static bool __range_is_overlap(loff_t buf_b, size_t buf_e, int limit_b, size_t limit_e, int *hole_b, int *hole_e)
{
    if ((buf_b > limit_e) || (buf_e < limit_b)) {
        return false;
    }

    *hole_b = buf_b;
    *hole_e = buf_e;

    if (buf_b < limit_b) {
        *hole_b = limit_b;
    }

    if (buf_e > limit_e) {
        *hole_e = limit_e;
    }

    return true;
}

/* Calculate whether any limitation holes exist in the page access range (start, len): *ret_arr_len == 0 means no holes exist. */
static int get_limit_bytes_holes_from_eeprom_page_access_range(struct page_limit_bytes_segment *limit_arr,
                                                               int                              limit_arr_len,
                                                               uint8_t                          page,
                                                               loff_t                           start,
                                                               size_t                           len,
                                                               struct page_access_segment     **ret_hole_arr,
                                                               int                             *ret_hole_arr_len)
{
    int                         err = 0;
    int                         i;
    bool                        found = false;
    int                         hole_b = 0;
    int                         hole_e = 0;
    int                         hole_num = 0;
    struct page_access_segment *holes = NULL;

    *ret_hole_arr_len = 0;

    for (i = 0; i < limit_arr_len; i++) {
        if (page == limit_arr[i].page) {
            found = true;
            break;
        }
    }
    if (!found) {
        goto out;
    }

    for (; i < limit_arr_len; i++) {
        if (page != limit_arr[i].page) {
            break;
        }
        if (__range_is_overlap(start, start + len - 1, limit_arr[i].begin, limit_arr[i].end, &hole_b, &hole_e)) {
            if (hole_b <= hole_e) {
                if (!holes) {
                    holes = kzalloc(sizeof(*holes) * limit_arr_len, GFP_KERNEL);
                    if (!holes) {
                        err = -ENOMEM;
                        goto out;
                    }
                }
                holes[hole_num].begin = hole_b;
                holes[hole_num].end = hole_e;
                hole_num++;
            }
        }
    }
    *ret_hole_arr_len = hole_num;
    *ret_hole_arr = holes;
out:
    return err;
}

/*
 *  The function should be called after get_limit_bytes_holes_from_eeprom_page_access_range(..),
 *  and it assumes that all holes should be within the page access range.
 */
static int __separate_eeprom_page_access_range_into_segments(struct page_access_segment  *hole_arr,
                                                             int                          hole_arr_len,
                                                             loff_t                       start,
                                                             size_t                       len,
                                                             struct page_access_segment **ret_arr,
                                                             int                         *ret_arr_len)
{
    int                         err = 0;
    int                         i;
    size_t                      hole_b = 0;
    size_t                      hole_e = 0;
    int                         max_segments = hole_arr_len + 1;
    int                         segments = 1;
    struct page_access_segment *segs = NULL;

    *ret_arr_len = segments;
    segs = kmalloc(sizeof(*segs) * max_segments, GFP_KERNEL);
    if (!(segs)) {
        err = -ENOMEM;
        goto out;
    }
    segs[0].begin = start;
    segs[0].end = start + len - 1;

    for (i = 0; i < hole_arr_len; i++) {
        hole_b = hole_arr[i].begin;
        hole_e = hole_arr[i].end;

        if (hole_e >= segs[segments - 1].end) {
            /* page access range is reached, and no need to compare more */
            if (hole_b == segs[segments - 1].begin) {
                segments--;
                break;
            }
            segs[segments - 1].end = hole_b - 1;
            break;
        }
        /* case: hole_e < segs[segments - 1].end */
        if (hole_b == segs[segments - 1].begin) {
            segs[segments - 1].begin = hole_e + 1;
            continue;
        }
        /* Extend a new segment */
        segs[segments].begin = hole_e + 1;
        segs[segments].end = segs[segments - 1].end;
        segs[segments - 1].end = hole_b - 1;

        segments++;
    }
    *ret_arr_len = segments;
    *ret_arr = segs;

out:
    return err;
}

static int __sx_core_get_slot_and_module(struct sx_dev *dev, uint16_t local_port, uint8_t *slot, uint8_t *module)
{
    struct sx_priv *priv = sx_priv(dev);
    int             err = 0;
    unsigned long   flags;

    if (local_port > MAX_PHYPORT_NUM) {
        sxd_log_err("Local port %d is invalid. (MAX %d).\n", local_port, MAX_PHYPORT_NUM);
        err = -EINVAL;
        goto out;
    }

    spin_lock_irqsave(&priv->db_lock, flags);
    *slot = priv->local_to_slot_map[local_port];
    *module = priv->local_to_module_map[local_port];
    spin_unlock_irqrestore(&priv->db_lock, flags);

    if ((*slot >= MAX_SLOT_NUM) || (*module >= MAX_MODULE_NUM)) {
        err = -EINVAL;
        sxd_log_err("slot id %d or module id %d is out of range.\n", *slot, *module);
        goto out;
    }

out:
    return err;
}

/* Fetch the required params for MCIA access/check */
static int __module_sysfs_eeprom_parse_params(const char                        *node_name,
                                              bool                               is_independent,
                                              loff_t                             pos,
                                              struct sx_dev                     *dev,
                                              uint8_t                            module,
                                              uint8_t                            slot,
                                              enum sx_module_sysfs_eeprom_access access,
                                              uint8_t                           *i2c_addr,
                                              uint8_t                           *page,
                                              uint8_t                           *pnv,
                                              uint16_t                          *device_addr,
                                              struct page_limit_bytes_segment  **limit_arr,
                                              int                               *limit_arr_len)
{
    int     err = 0;
    uint8_t mgmt_type = 0;

    *i2c_addr = 0x50;

    if (node_name[0] == 'i') {
        *page = 0;
        if (strcmp(node_name, "i2c-0x51") == 0) {
            *i2c_addr = 0x51;
        }
    } else {
        *page = (uint8_t)simple_strtol(node_name, NULL, 10);
    }

    *device_addr = pos;

    if (*page > 0) {
        /* add upper page offset for page 1~255 */
        *device_addr += EEPROM_UPPER_PAGE_OFFSET;
    }

    if (is_independent) {
        *limit_arr_len = 0;
        /* For independent module, MGMT FW is not aware about module type.
         * Driver is also not aware of module type.
         * For flat / un paged / passive module it is an issue, since its EEPROM is
         * Read Only, but MCIA access performs write to page offset (byte 127 in page 0).
         * So, driver should avoid attempt to write to this offset by indicating MCIA.PNV=1.
         * This indication informs FW MGMT to use current page offset and don't performs
         * page offset write.
         * */
        err = __sx_core_get_module_page_valid(dev, module, slot, *page, pnv);
        if (err) {
            sxd_log_err("Failed to get module page valid, err: %d\n", err);
            goto out;
        }
    } else {
        err = __sx_core_get_module_type(dev, module, slot, &mgmt_type);
        if (err) {
            sxd_log_debug("Failed to get the module type, err: %d\n", err);
            goto out;
        }

        if ((*i2c_addr == 0x51) && (mgmt_type != EEPROM_MANAGEMENT_TYPE_SFP)) {
            sxd_log_notice("Failed to access i2c address 0x51 because module type is not SFF-8472.\n");
            err = -EFAULT;
            goto out;
        }

        if ((*page > 0) && (mgmt_type == EEPROM_MANAGEMENT_TYPE_SFP)) {
            *i2c_addr = 0x51;
        }

        switch (mgmt_type) {
        case EEPROM_MANAGEMENT_TYPE_SFP:
            if (*i2c_addr == 0x51) {
                /* SFF8472's limitation bytes are only for i2c 0x51 */
                if (access == MODULE_SYSFS_EEPROM_READ) {
                    *limit_arr = sff8472_rd_limit_arr;
                    *limit_arr_len = sff8472_rd_limit_arr_len;
                } else {
                    *limit_arr = sff8472_wr_limit_arr;
                    *limit_arr_len = sff8472_wr_limit_arr_len;
                }
            }
            break;

        case EEPROM_MANAGEMENT_TYPE_QSFP:
            if (access == MODULE_SYSFS_EEPROM_READ) {
                *limit_arr = sff8636_rd_limit_arr;
                *limit_arr_len = sff8636_rd_limit_arr_len;
            } else {
                *limit_arr = sff8636_wr_limit_arr;
                *limit_arr_len = sff8636_wr_limit_arr_len;
            }
            break;

        case EEPROM_MANAGEMENT_TYPE_CMIS:
            if (access == MODULE_SYSFS_EEPROM_READ) {
                *limit_arr = cmis_rd_limit_arr;
                *limit_arr_len = cmis_rd_limit_arr_len;
            } else {
                *limit_arr = cmis_wr_limit_arr;
                *limit_arr_len = cmis_wr_limit_arr_len;
            }
            break;

        default:
            sxd_log_err("Invalid module type %d.\n", mgmt_type);
            err = -EINVAL;
            goto out;
            break;
        }
    }

out:
    return err;
}

ssize_t __module_sysfs_eeprom_low_level_read(struct sx_dev *dev,
                                             char          *buf,
                                             ssize_t        count,
                                             uint8_t        module,
                                             uint8_t        slot,
                                             uint8_t        page,
                                             uint8_t        pnv,
                                             uint16_t       device_addr,
                                             uint8_t        i2c_addr)
{
    int                       err = 0;
    ssize_t                   len, remainder;
    loff_t                    i, dw_end;
    uint8_t                   rd_len;
    uint16_t                  handled;
    uint32_t                 *dword = NULL;
    struct ku_access_mcia_reg reg_data;

    len = count;
    handled = 0;
    while (len > 0) {
        rd_len = len;
        if (len > MCIA_EEPROM_MAX_ACCESS_SIZE) {
            rd_len = MCIA_EEPROM_MAX_ACCESS_SIZE;
        }

        memset(&reg_data, 0, sizeof(reg_data));
        err = __sx_core_mcia_access(dev,
                                    MCIA_MODULE_ACCESS_TYPE_READ,
                                    module,
                                    page,
                                    pnv,
                                    device_addr + handled,
                                    rd_len,
                                    i2c_addr,
                                    slot,
                                    &reg_data);
        if (err) {
            sxd_log_err("Fails to read module eeprom, status: %d.\n", err);
            if (err > 0) {
                err = -err;
            }
            goto out;
        }
        if (reg_data.mcia_reg.status) {
            err = __handle_mcia_return_status(reg_data.mcia_reg);
            goto out;
        }

        dword = &(reg_data.mcia_reg.dword_0);
        remainder = rd_len % 4;
        dw_end = handled + rd_len - remainder;
        for (i = handled; i < dw_end; i += 4) {
            buf[i] = MCIA_DWOARD_BYTE1(*dword);
            buf[i + 1] = MCIA_DWOARD_BYTE2(*dword);
            buf[i + 2] = MCIA_DWOARD_BYTE3(*dword);
            buf[i + 3] = MCIA_DWOARD_BYTE4(*dword);
            dword++;
        }
        if (remainder) {
            if (remainder == 3) {
                buf[i + 2] = MCIA_DWOARD_BYTE3(*dword);
            }
            if (remainder >= 2) {
                buf[i + 1] = MCIA_DWOARD_BYTE2(*dword);
            }
            if (remainder >= 1) {
                buf[i] = MCIA_DWOARD_BYTE1(*dword);
            }
        }
        len -= rd_len;
        handled += rd_len;
    }

out:
    if (err < 0) {
        return err;
    }
    return count;
}

ssize_t __module_sysfs_eeprom_low_level_write(struct sx_dev *dev,
                                              char          *buf,
                                              ssize_t        count,
                                              uint8_t        module,
                                              uint8_t        slot,
                                              uint8_t        page,
                                              uint8_t        pnv,
                                              uint16_t       device_addr,
                                              uint8_t        i2c_addr)
{
    int                       err = 0;
    ssize_t                   len, remainder;
    loff_t                    i, dw_end;
    uint8_t                   wr_len;
    uint16_t                  handled;
    uint32_t                 *dword = NULL;
    struct ku_access_mcia_reg reg_data;

    len = count;
    handled = 0;
    while (len > 0) {
        wr_len = len;
        if (len > MCIA_EEPROM_MAX_ACCESS_SIZE) {
            wr_len = MCIA_EEPROM_MAX_ACCESS_SIZE;
        }

        memset(&reg_data, 0, sizeof(reg_data));
        dword = &(reg_data.mcia_reg.dword_0);
        remainder = wr_len % 4;
        dw_end = handled + wr_len - remainder;
        for (i = handled; i < dw_end; i += 4) {
            *dword |= MCIA_BYTE1_TO_DWOARD(buf[i]);
            *dword |= MCIA_BYTE2_TO_DWOARD(buf[i + 1]);
            *dword |= MCIA_BYTE3_TO_DWOARD(buf[i + 2]);
            *dword |= MCIA_BYTE4_TO_DWOARD(buf[i + 3]);
            dword++;
        }
        if (remainder) {
            if (remainder == 3) {
                *dword |= MCIA_BYTE3_TO_DWOARD(buf[i + 2]);
            }
            if (remainder >= 2) {
                *dword |= MCIA_BYTE2_TO_DWOARD(buf[i + 1]);
            }
            if (remainder >= 1) {
                *dword |= MCIA_BYTE1_TO_DWOARD(buf[i]);
            }
        }

        err = __sx_core_mcia_access(dev,
                                    MCIA_MODULE_ACCESS_TYPE_WRITE,
                                    module,
                                    page,
                                    pnv,
                                    device_addr + handled,
                                    wr_len,
                                    i2c_addr,
                                    slot,
                                    &reg_data);
        if (err) {
            sxd_log_err("Fails to lower level write module eeprom, status: %d.\n", err);
            if (err > 0) {
                err = -err;
            }
            goto out;
        }
        if (reg_data.mcia_reg.status) {
            err = __handle_mcia_return_status(reg_data.mcia_reg);
            goto out;
        }

        len -= wr_len;
        handled += wr_len;
    }
out:
    if (err < 0) {
        return err;
    }
    return count;
}

ssize_t sx_core_module_sysfs_eeprom_access(struct sx_dev                     *dev,
                                           const char                        *node_name,
                                           uint8_t                            slot,
                                           uint8_t                            module,
                                           enum sx_module_sysfs_eeprom_access access,
                                           char                              *buf,
                                           loff_t                             pos,
                                           size_t                             count)
{
    int                              err = 0;
    ssize_t                          offset, len;
    loff_t                           i;
    uint8_t                          page = 0;
    uint8_t                          pnv = 0;
    uint8_t                          i2c_addr = 0;
    uint16_t                         device_addr;
    bool                             release_lock = false;
    struct sx_priv                  *priv = sx_priv(dev);
    struct page_limit_bytes_segment *limit_arr = NULL;
    int                              limit_arr_len = 0;
    struct page_access_segment      *hole_arr = NULL;
    int                              hole_arr_len = 0;
    struct page_access_segment      *access_segs = NULL;
    int                              access_segs_len = 0;
    bool                             is_independent = false;

    err = sx_core_get_module_control(dev, slot, module, &is_independent);
    if (err) {
        goto err_out;
    }

    mutex_lock(&priv->module_access_mutex);
    release_lock = true;

    err = __module_sysfs_eeprom_parse_params(node_name,
                                             is_independent,
                                             pos,
                                             dev,
                                             module,
                                             slot,
                                             access,
                                             &i2c_addr,
                                             &page,
                                             &pnv,
                                             &device_addr,
                                             &limit_arr,
                                             &limit_arr_len);
    if (err) {
        sxd_log_debug("Fail to parse %s and cannot access it, err: %d\n", node_name, err);
        goto err_out;
    }

    err = get_limit_bytes_holes_from_eeprom_page_access_range(limit_arr,
                                                              limit_arr_len,
                                                              page,
                                                              device_addr,
                                                              count,
                                                              &hole_arr,
                                                              &hole_arr_len);
    if (err) {
        sxd_log_notice("Fail to get limitation bytes for %s in range of (%u, %lu), err: %d\n",
                       node_name,
                       device_addr,
                       count,
                       err);
        goto err_out;
    }

    if (access == MODULE_SYSFS_EEPROM_READ) {
        memset(buf, 0, count);
    }

    if (hole_arr_len == 0) {
        /* No limitation bytes in the access scope, simply call low-level access once. */
        if (access == MODULE_SYSFS_EEPROM_READ) {
            err =
                __module_sysfs_eeprom_low_level_read(dev, buf, count, module, slot, page, pnv, device_addr, i2c_addr);
        } else {
            err =
                __module_sysfs_eeprom_low_level_write(dev, buf, count, module, slot, page, pnv, device_addr, i2c_addr);
        }
        if (err < 0) {
            sxd_log_err("Fails to access (%d) module eeprom, status: %d.\n", access, err);
            goto err_out;
        }
        goto out;
    }

    err = __separate_eeprom_page_access_range_into_segments(hole_arr,
                                                            hole_arr_len,
                                                            device_addr,
                                                            count,
                                                            &access_segs,
                                                            &access_segs_len);
    if (err) {
        sxd_log_notice("Fail to separate access range (%u, %lu) for %s, err: %d\n",
                       device_addr,
                       count,
                       node_name,
                       err);
        goto err_out;
    }

    /* call low-level access for each segments separated by limitation bytes */
    for (i = 0; i < access_segs_len; i++) {
        offset = access_segs[i].begin - pos;
        if (page > 0) {
            offset -= EEPROM_UPPER_PAGE_OFFSET;
        }
        len = access_segs[i].end - access_segs[i].begin + 1;
        if (access == MODULE_SYSFS_EEPROM_READ) {
            err = __module_sysfs_eeprom_low_level_read(dev,
                                                       buf + offset,
                                                       len,
                                                       module,
                                                       slot,
                                                       page,
                                                       pnv,
                                                       access_segs[i].begin,
                                                       i2c_addr);
        } else {
            err = __module_sysfs_eeprom_low_level_write(dev,
                                                        buf + offset,
                                                        len,
                                                        module,
                                                        slot,
                                                        page,
                                                        pnv,
                                                        access_segs[i].begin,
                                                        i2c_addr);
        }
        if (err < 0) {
            sxd_log_err("Fails to access (%d) module eeprom, status: %d.\n", access, err);
            goto err_out;
        }
    }
    kfree(access_segs);

out:
    if (hole_arr) {
        kfree(hole_arr);
    }
    mutex_unlock(&priv->module_access_mutex);
    release_lock = false;

    return count;

err_out:
    if (release_lock) {
        mutex_unlock(&priv->module_access_mutex);
    }
    if (access_segs) {
        kfree(access_segs);
    }
    if (hole_arr) {
        kfree(hole_arr);
    }
    return err;
}

ssize_t sx_core_port_module_sysfs_eeprom_access(struct sx_dev                     *dev,
                                                const char                        *node_name,
                                                uint16_t                           local_port,
                                                enum sx_module_sysfs_eeprom_access access,
                                                char                              *buf,
                                                loff_t                             pos,
                                                size_t                             count)
{
    int     err = 0;
    uint8_t module = 0;
    uint8_t slot = 0;

    err = __sx_core_get_slot_and_module(dev, local_port, &slot, &module);
    if (err) {
        sxd_log_err("Fails to get module id, status: %d.\n", err);
        err = -EINVAL;
        goto out;
    }

    err = sx_core_module_sysfs_eeprom_access(dev,
                                             node_name,
                                             slot,
                                             module,
                                             access,
                                             buf,
                                             pos,
                                             count);
out:
    return err;
}
EXPORT_SYMBOL(sx_core_port_module_sysfs_eeprom_access);

/*
 *   sx_core module sysfs nodes are like:
 *       ./sx_core/$asic/$module_id/eeprom/pages/0/i2c-0x5x/data
 *       ./sx_core/$asic/$module_id/eeprom/pages/x/data
 *   Notice: local module id is returned in multi-asic system.
 */
static int __eeprom_sysfs_get_dev_slot_module(struct kobject *kobj, struct sx_dev **dev, uint8_t *slot,
                                              uint8_t *module)
{
    int             ret = 0;
    int             module_id = 0;
    int             module_pos = 0;
    struct kobject *kobj_parent = kobj->parent;
    uint8_t         local_module_id = 0;

    if (!kobj_parent) {
        sxd_log_err("Invalid kobj %s\n", kobject_name(kobj));
        ret = -EINVAL;
        goto out;
    }

    module_pos = 2;
    if (kobj->name[0] == 'i') {
        /* page0 has 1 more level */
        module_pos = 3;
    }
    for ( ; module_pos > 0; module_pos--) {
        if (kobj_parent) {
            kobj_parent = kobj_parent->parent;
        }
    }
    if (!kobj_parent) {
        sxd_log_err("Invalid sysfs node entry because of null parent: kobj %s\n", kobject_name(kobj));
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtoint(kobj_parent->name + strlen(MODULE_NODE_SYSFS_PREFIX), 10, &module_id);
    if (ret || (module_id > MAX_MODULE_NUM)) {
        sxd_log_err("sysfs entry got invalid module value for %s\n", kobject_name(kobj));
        ret = -EINVAL;
        goto out;
    }

    ret = sx_core_get_possible_local_module(module_id, &local_module_id);
    if (ret) {
        goto out;
    }

    kobj_parent = kobj_parent->parent;
    ret = sx_core_asic_get_dev(kobj_parent, true, module_id, dev);
    if (ret) {
        sxd_log_err("sysfs entry power_on got invalid value\n");
        goto out;
    }

    *module = local_module_id;
    *slot = sx_priv(*dev)->module_to_slot_map[*module];

out:
    return ret;
}

static int __create_module_sysfs_eeprom_page0(struct kobject           *parent,
                                              struct eeprom_page0_node *node,
                                              struct bin_attribute     *bin_attr)
{
    int err = 0, i;

    node->page = kobject_create_and_add("0", parent);
    if (!(node->page)) {
        err = -ENOMEM;
        goto out;
    }
    node->i2c[0] = kobject_create_and_add("i2c-0x50", node->page);
    if (!(node->page)) {
        err = -ENOMEM;
        goto phase1_err;
    }
    node->i2c[1] = kobject_create_and_add("i2c-0x51", node->page);
    if (!(node->page)) {
        err = -ENOMEM;
        goto phase2_err;
    }

    for (i = 0; i < MODULE_EEPROM_I2C_ADDR_NUM; i++) {
        err = sysfs_create_bin_file(node->i2c[i], bin_attr);
        if (err) {
            goto phase3_err;
        }
    }

    return err;

phase3_err:
    for (; i > 0; i--) {
        sysfs_remove_bin_file(node->i2c[i - 1], bin_attr);
    }
    kobject_put(node->i2c[1]);
phase2_err:
    kobject_put(node->i2c[0]);
phase1_err:
    kobject_put(node->page);
out:
    return err;
}

static void __delete_module_sysfs_eeprom_page0(struct eeprom_page0_node *node, struct bin_attribute *bin_attr)
{
    int i;

    for (i = 0; i < MODULE_EEPROM_I2C_ADDR_NUM; i++) {
        sysfs_remove_bin_file(node->i2c[i], bin_attr);
        kobject_put(node->i2c[i]);
    }
    kobject_put(node->page);
}

static int __create_module_sysfs_eeprom_pagex(struct kobject           *parent,
                                              struct eeprom_pagex_node *node,
                                              int                       page_id,
                                              struct bin_attribute     *bin_attr)
{
    int  err = 0;
    char num_str[8];

    snprintf(num_str, sizeof(num_str), "%d", page_id);
    node->page = kobject_create_and_add(num_str, parent);
    if (!(node->page)) {
        err = -ENOMEM;
        goto out;
    }

    err = sysfs_create_bin_file(node->page, bin_attr);
    if (err) {
        goto sysfs_file_err;
    }

    return err;

sysfs_file_err:
    kobject_put(node->page);
out:
    return err;
}

static void __delete_module_sysfs_eeprom_pagex(struct eeprom_pagex_node *node, struct bin_attribute *bin_attr)
{
    sysfs_remove_bin_file(node->page, bin_attr);
    kobject_put(node->page);
}

int sx_core_create_module_sysfs_eeprom_tree(struct kobject                  *parent,
                                            struct module_sysfs_eeprom_tree *root,
                                            struct bin_attribute            *page0_attr,
                                            struct bin_attribute            *pagex_attr)
{
    int err = 0, i;

    root->eeprom = kobject_create_and_add("eeprom", parent);
    if (!(root->eeprom)) {
        err = -ENOMEM;
        goto out;
    }
    root->pages = kobject_create_and_add("pages", root->eeprom);
    if (!(root->pages)) {
        err = -ENOMEM;
        goto phase1_err;
    }

    err = __create_module_sysfs_eeprom_page0(root->pages, &(root->page0), page0_attr);
    if (err < 0) {
        goto phase2_err;
    }

    for (i = 0; i < MODULE_EEPROM_UPPER_PAGE_NUM; i++) {
        err = __create_module_sysfs_eeprom_pagex(root->pages, &(root->page[i]), i + 1, pagex_attr);
        if (err < 0) {
            goto phase3_err;
        }
    }
    return err;

phase3_err:
    for (; i > 0; i--) {
        __delete_module_sysfs_eeprom_pagex(&(root->page[i - 1]), pagex_attr);
    }
    __delete_module_sysfs_eeprom_page0(&(root->page0), page0_attr);
phase2_err:
    kobject_put(root->pages);
phase1_err:
    kobject_put(root->eeprom);
out:
    return err;
}
EXPORT_SYMBOL(sx_core_create_module_sysfs_eeprom_tree);

void sx_core_delete_module_sysfs_eeprom_tree(struct module_sysfs_eeprom_tree *root,
                                             struct bin_attribute            *page0_attr,
                                             struct bin_attribute            *pagex_attr)
{
    int i;

    for (i = 0; i < MODULE_EEPROM_UPPER_PAGE_NUM; i++) {
        __delete_module_sysfs_eeprom_pagex(&(root->page[i]), pagex_attr);
    }
    __delete_module_sysfs_eeprom_page0(&(root->page0), page0_attr);
    kobject_put(root->pages);
    kobject_put(root->eeprom);
}
EXPORT_SYMBOL(sx_core_delete_module_sysfs_eeprom_tree);

int sx_core_create_module_sysfs_default_eeprom_tree(struct kobject *parent, struct module_sysfs_eeprom_tree *root)
{
    return sx_core_create_module_sysfs_eeprom_tree(parent,
                                                   root,
                                                   &module_eeprom_page0_attribute,
                                                   &module_eeprom_pagex_attribute);
}
EXPORT_SYMBOL(sx_core_create_module_sysfs_default_eeprom_tree);

void sx_core_delete_module_sysfs_default_eeprom_tree(struct module_sysfs_eeprom_tree *root)
{
    sx_core_delete_module_sysfs_eeprom_tree(root,
                                            &module_eeprom_page0_attribute,
                                            &module_eeprom_pagex_attribute);
}
EXPORT_SYMBOL(sx_core_delete_module_sysfs_default_eeprom_tree);

static ssize_t __module_sysfs_eeprom_bin_read(struct file          *flip,
                                              struct kobject       *kobj,
                                              struct bin_attribute *attr,
                                              char                 *buf,
                                              loff_t                pos,
                                              size_t                count)
{
    int            ret = 0;
    int            read_count = 0;
    struct sx_dev *dev = NULL;
    uint8_t        module = 0;
    uint8_t        slot = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    if (pos > attr->size) {
        return 0;
    }
    if (pos + count > attr->size) {
        count = attr->size - pos;
    }
    if (count == 0) {
        return 0;
    }

    ret = __eeprom_sysfs_get_dev_slot_module(kobj, &dev, &slot, &module);
    if (ret) {
        sxd_log_err("eeprom read: __eeprom_sysfs_get_dev_slot_module failed (%d) for %s\n", ret,
                    kobject_name(kobj));
        goto out;
    }
    sx_int_log_info(&sx_priv(dev)->module_log,
                    "Module ID %d | Eeprom read start ", module);
    read_count = sx_core_module_sysfs_eeprom_access(dev,
                                                    kobject_name(kobj),
                                                    slot,
                                                    module,
                                                    MODULE_SYSFS_EEPROM_READ,
                                                    buf,
                                                    pos,
                                                    count);
    if (read_count < 0) {
        sxd_log_debug("Fails to read eeprom, status: %d.\n", read_count);
        ret = read_count;
        goto out;
    }
    sx_int_log_info(&sx_priv(dev)->module_log,
                    "Module ID %d | Eeprom read completed,read %d bytes ", module, read_count);
    return read_count;

out:
    return ret;
}

static ssize_t __module_sysfs_eeprom_bin_write(struct file          *flip,
                                               struct kobject       *kobj,
                                               struct bin_attribute *attr,
                                               char                 *buf,
                                               loff_t                pos,
                                               size_t                count)
{
    int            ret = 0;
    int            write_count = 0;
    struct sx_dev *dev = NULL;
    uint8_t        slot = 0;
    uint8_t        module = 0;

    if (pos > attr->size) {
        return 0;
    }
    if (pos + count > attr->size) {
        count = attr->size - pos;
    }
    if (count == 0) {
        return 0;
    }

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, buf, count);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue*/
    }
    ret = __eeprom_sysfs_get_dev_slot_module(kobj, &dev, &slot, &module);
    if (ret) {
        sxd_log_err("eeprom write: __eeprom_sysfs_get_dev_slot_module failed (%d) for %s\n", ret,
                    kobject_name(kobj));
        goto out;
    }

    sx_int_log_info(&sx_priv(dev)->module_log,
                    "Module ID %d | Eeprom write start ", module);
    write_count = sx_core_module_sysfs_eeprom_access(dev,
                                                     kobject_name(kobj),
                                                     slot,
                                                     module,
                                                     MODULE_SYSFS_EEPROM_WRITE,
                                                     buf,
                                                     pos,
                                                     count);
    if (write_count < 0) {
        sxd_log_err("Fails to write eeprom, status: %d.\n", write_count);
        ret = write_count;
        goto out;
    }
    sx_int_log_info(&sx_priv(dev)->module_log,
                    "Module ID %d | Eeprom write completed, wrote %d bytes ", module, write_count);
    return write_count;

out:
    return ret;
}
