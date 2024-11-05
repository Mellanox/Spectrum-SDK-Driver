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

#include <linux/debugfs.h>
#include "sx_spice_wrapper.h"
#include "sx_spice_uphy_reg_auto.h"

/************************************************
 *  Local variables
 ***********************************************/

/************************************************
 *  Type definitions
 ***********************************************/

typedef struct slrip_data {
    uint16_t            local_port;
    uint8_t             pnat;
    uint8_t             lane;
    uint8_t             port_type;
    uint8_t             ib_sel;
    struct list_head    slrip_list;
    dev_private_data_t *dev_data;
} slrip_data_t;

typedef struct slrg_data {
    uint16_t            local_port;
    uint8_t             pnat;
    uint8_t             lane;
    uint8_t             port_type;
    uint8_t             test_mode;
    struct list_head    slrg_list;
    dev_private_data_t *dev_data;
} slrg_data_t;

typedef struct slrp_data {
    uint16_t            local_port;
    uint8_t             pnat;
    uint8_t             lane;
    uint8_t             port_type;
    struct list_head    slrp_list;
    dev_private_data_t *dev_data;
} slrp_data_t;

typedef struct peucg_data {
    uint8_t             unit;
    uint16_t            local_port;
    uint8_t             pnat;
    uint8_t             lane;
    uint8_t             enum_init;
    uint16_t            db_index;
    struct list_head    peucg_list;
    dev_private_data_t *dev_data;
} peucg_data_t;

typedef struct ppll_data {
    uint8_t             pll_group;
    struct list_head    ppll_list;
    dev_private_data_t *dev_data;
} ppll_data_t;

typedef struct pmlp_data {
    uint16_t            local_port;
    uint8_t             plane_ind;
    struct list_head    pmlp_list;
    dev_private_data_t *dev_data;
} pmlp_data_t;

/************************************************
 * Functions                                    *
 ***********************************************/

int sx_spice_access_reg_slrip_file_create(struct dentry *parent, dev_private_data_t *dev_data);
void sx_spice_access_reg_slrip_list_free(void);
int sx_spice_access_reg_slrip_reg_data_to_buffer_print(char                  buffer[],
                                                       size_t                buffer_length,
                                                       struct ku_slrip_reg * reg_data);
ssize_t sx_spice_access_reg_slrip_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);

int sx_spice_access_reg_slrg_file_create(struct dentry *parent, dev_private_data_t *dev_data);
void sx_spice_access_reg_slrg_list_free(void);
int sx_spice_access_reg_slrg_reg_data_to_buffer_print(char                 buffer[],
                                                      size_t               buffer_length,
                                                      struct ku_slrg_reg * reg_data);
ssize_t sx_spice_access_reg_slrg_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);

int sx_spice_access_reg_slrp_file_create(struct dentry *parent, dev_private_data_t *dev_data);
void sx_spice_access_reg_slrp_list_free(void);
int sx_spice_access_reg_slrp_reg_data_to_buffer_print(char                 buffer[],
                                                      size_t               buffer_length,
                                                      struct ku_slrp_reg * reg_data);
ssize_t sx_spice_access_reg_slrp_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);

int sx_spice_access_reg_peucg_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_peucg_data_to_buffer_print(char                 *buffer,
                                                   size_t                buffer_length,
                                                   struct ku_peucg_reg * reg_data);
ssize_t sx_spice_access_reg_peucg_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
int release_peucg(struct inode *inodep, struct file *filp);
void sx_spice_access_reg_peucg_list_free(void);

int sx_spice_access_reg_ppll_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_ppll_data_to_buffer_print(char                 buffer[],
                                                  size_t               buffer_length,
                                                  struct ku_ppll_reg * reg_data);
ssize_t sx_spice_access_reg_ppll_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_ppll_list_free(void);
int sx_spice_access_reg_pmlp_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pmlp_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pmlp_reg * reg_data);
ssize_t sx_spice_access_reg_pmlp_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pmlp_list_free(void);
