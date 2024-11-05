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

#ifndef __SPICE_ASIC_PORTS_H__
#define __SPICE_ASIC_PORTS_H__


/************************************************
 *  Type definitions
 ***********************************************/
/************************************************
 * Type declarations
 ***********************************************/

/************************************************
 *  Global variables
 ***********************************************/

/************************************************
* Global Functions                             *
************************************************/
/**
 * handle dealloc of created counter files.
 **/
void sx_spice_asic_ports_data_list_free(void);


int sx_spice_access_reg_asic_ports_file_create(struct dentry *parent, dev_private_data_t *dev_data);

#endif /* __SPICE_ASIC_PORTS_H__ */
