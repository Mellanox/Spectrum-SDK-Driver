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

#include "sx_spice_tree_dynamic.h"

/************************************************
 *  Local variables
 ***********************************************/

/************************************************
 *  Type definitions
 ***********************************************/

/************************************************
 * Functions                                    *
 ***********************************************/

bool is_ib_sel_dir_supported(dev_private_data_t *priv_data)
{
    bool is_supported = false;

    /* IB select index is valid only for 16nm systems */
    switch (priv_data->hw_device_id) {
    case SXD_MGIR_HW_DEV_ID_QUANTUM:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM3:
        is_supported = true;
        break;

    case SXD_MGIR_HW_DEV_ID_QUANTUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM4:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM5:

    default:
        is_supported = false;
        break;
    }

    return is_supported;
}

bool is_fom_measurment_dir_supported(dev_private_data_t *priv_data)
{
    bool is_supported = false;

    /* fom_measurment OP is valid only for 7nm systems */
    switch (priv_data->hw_device_id) {
    case SXD_MGIR_HW_DEV_ID_QUANTUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM4:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM5:
        is_supported = true;
        break;

    case SXD_MGIR_HW_DEV_ID_QUANTUM:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM3:

    default:
        is_supported = false;
        break;
    }

    return is_supported;
}

bool is_iterations_dir_supported(dev_private_data_t *priv_data, int test_mode)
{
    bool is_supported = false;

    if (test_mode == 1) {
        is_supported = true;
    }

    return is_supported;
}

bool is_lane_dir_supported(dev_private_data_t *priv_data)
{
    bool is_supported = false;

    /* fom_measurment OP is valid only for 7nm systems */
    switch (priv_data->hw_device_id) {
    case SXD_MGIR_HW_DEV_ID_QUANTUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM4:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM5:
        is_supported = true;
        break;

    case SXD_MGIR_HW_DEV_ID_QUANTUM:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM2:
    case SXD_MGIR_HW_DEV_ID_SPECTRUM3:

    default:
        is_supported = false;
        break;
    }

    return is_supported;
}
