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

#include "sx_spice_wrapper.h"

/************************************************
 *  Local variables
 ***********************************************/

/************************************************
 *  Type definitions
 ***********************************************/

/************************************************
 * Functions                                    *
 ***********************************************/

bool is_ib_sel_dir_supported(dev_private_data_t *priv_data);

bool is_fom_measurment_dir_supported(dev_private_data_t *priv_data);

bool is_lane_dir_supported(dev_private_data_t *priv_data);

bool is_iterations_dir_supported(dev_private_data_t *priv_data, int idx_value);
