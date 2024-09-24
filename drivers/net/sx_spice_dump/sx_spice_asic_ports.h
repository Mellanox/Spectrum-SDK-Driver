/*
 * Copyright (c) 2010-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This software product is a proprietary product of Nvidia Corporation and its affiliates
 * (the "Company") and all right, title, and interest in and to the software
 * product, including all associated intellectual property rights, are and
 * shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
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
