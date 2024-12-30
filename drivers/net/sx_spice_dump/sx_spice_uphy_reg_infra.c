/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#include "sx_spice_uphy_reg_infra.h"

#define UPHY_CLN_MAX_REGISTERS 161 /* CLN max address + 1 */
#define UPHY_DLN_MAX_REGISTERS 977 /* DLN max address + 1 */
#define CLN_VALID_REG_ID(reg_id) ((((int)(reg_id)) >= 0) && (((int)(reg_id)) < UPHY_CLN_MAX_REGISTERS))
#define DLN_VALID_REG_ID(reg_id) ((((int)(reg_id)) >= 0) && (((int)(reg_id)) < UPHY_DLN_MAX_REGISTERS))

/************************************************
 *  Global variables
 ***********************************************/

static struct sx_core_map __uphy_cln_reg_info_map;
static struct sx_core_map __uphy_dln_reg_info_map;

/************************************************
 *  Local variables
 ***********************************************/


/************************************************
 *  Local function declarations
 ***********************************************/

static int __uphy_map_reg_id_compare_cb(const void* key1, const void *key2);

static int __uphy_map_traverse_cb(const void *key, struct sx_core_map_info *info, void *context);


/************************************************
 *  Function implementations
 ***********************************************/

static int __uphy_map_reg_id_compare_cb(const void* key1, const void *key2)
{
    const uint16_t reg_id1 = *(uint16_t*)key1;
    const uint16_t reg_id2 = *(uint16_t*)key2;

    if (reg_id1 > reg_id2) {
        return 1;
    }

    if (reg_id1 < reg_id2) {
        return -1;
    }

    return 0;
}

static int __uphy_map_traverse_cb(const void *key, struct sx_core_map_info *info, void *context)
{
    struct sx_spice_uphy_reg_info *entry = container_of(info, struct sx_spice_uphy_reg_info, map_info);

    kfree(entry);
    return 0;
}

int sx_spice_uphy_infra_init(void)
{
    int err = 0;

    err = sx_core_map_init(&__uphy_cln_reg_info_map, __uphy_map_reg_id_compare_cb, sizeof(uint16_t));
    if (err) {
        sxd_log_err("failed to create uPhy CLN registers map (err=%d)\n", err);
        goto out;
    }

    err = sx_core_map_init(&__uphy_dln_reg_info_map, __uphy_map_reg_id_compare_cb, sizeof(uint16_t));
    if (err) {
        sxd_log_err("failed to create uPhy CLN registers map (err=%d)\n", err);
        goto out;
    }

out:
    return err;
}

void sx_spice_uphy_infra_deinit(void)
{
    sx_core_map_remove_all(&__uphy_cln_reg_info_map, __uphy_map_traverse_cb, NULL);
    sx_core_map_remove_all(&__uphy_dln_reg_info_map, __uphy_map_traverse_cb, NULL);
}

int sx_spice_uphy_infra_reg_init(uphy_reg_type_e                       reg_type,
                                 uint16_t                              reg_id,
                                 sx_spice_uphy_reg_data_to_buffer_cb_t print_cb)
{
    int                            err = 0;
    struct sx_spice_uphy_reg_info *entry = NULL;

    if (((reg_type == UPHY_REG_TYPE_DLN) && !DLN_VALID_REG_ID(reg_id)) ||
        ((reg_type == UPHY_REG_TYPE_CLN) && !CLN_VALID_REG_ID(reg_id))) {
        sxd_log_err("Fail to init: invalid reg-id: 0x%x\n", reg_id);
        err = -EFAULT;
        goto out;
    }

    entry = kzalloc(sizeof(struct sx_spice_uphy_reg_info), GFP_KERNEL);
    if (!entry) {
        sxd_log_err("Failed to allocate uPhy register info entry\n");
        err = -ENOMEM;
        goto out;
    }

    entry->reg_id = reg_id;
    entry->print_cb = print_cb;

    if (reg_type == UPHY_REG_TYPE_DLN) {
        err = sx_core_map_insert(&__uphy_dln_reg_info_map, &entry->reg_id, &entry->map_info, GFP_KERNEL);
    } else { /*UPHY_REG_TYPE_CLN*/
        err = sx_core_map_insert(&__uphy_cln_reg_info_map, &entry->reg_id, &entry->map_info, GFP_KERNEL);
    }
    if (err) {
        sxd_log_err("Failed to insert a new uPhy register entry. err=%d\n", err);
        goto out;
    }

    return 0;

out:
    if (entry) {
        kfree(entry);
    }

    return err;
}

const struct sx_spice_uphy_reg_info* sx_spice_uphy_infra_reg_info_get(uphy_reg_type_e reg_type, uint16_t reg_id)
{
    int                            err = 0;
    struct sx_core_map_info       *map_info = NULL;
    struct sx_spice_uphy_reg_info *reg_info = NULL;

    if (((reg_type == UPHY_REG_TYPE_DLN) && !DLN_VALID_REG_ID(reg_id)) ||
        ((reg_type == UPHY_REG_TYPE_CLN) && !CLN_VALID_REG_ID(reg_id))) {
        sxd_log_err("Uphy reg info get: invalid reg-id: 0x%x\n", reg_id);
        goto out;
    }

    if (reg_type == UPHY_REG_TYPE_DLN) {
        err = sx_core_map_lookup(&__uphy_dln_reg_info_map, &reg_id, &map_info);
    } else {
        err = sx_core_map_lookup(&__uphy_cln_reg_info_map, &reg_id, &map_info);
    }

    if (err) {
        sxd_log_err("%s reg info entry does not exist [0x%X]\n",
                    reg_type == UPHY_REG_TYPE_DLN ? "DLN" : "CLN", reg_id);
        goto out;
    }

    reg_info = container_of(map_info, struct sx_spice_uphy_reg_info, map_info);

out:
    return reg_info;
}
