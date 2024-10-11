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

/************************************************
 *  Local variables
 ***********************************************/

/************************************************
 *  Type definitions
 ***********************************************/

typedef struct mtcap_data {
    uint8_t slot_index;
    struct list_head mtcap_list;
    dev_private_data_t *dev_data;
} mtcap_data_t;

typedef struct mvcap_data {
    uint8_t slot_index;
    struct list_head mvcap_list;
    dev_private_data_t *dev_data;
} mvcap_data_t;

typedef struct mtmp_data {
    uint8_t i;
    uint8_t ig;
    uint8_t asic_index;
    uint8_t slot_index;
    uint16_t sensor_index;
    struct list_head mtmp_list;
    dev_private_data_t *dev_data;
} mtmp_data_t;

typedef struct mgir_data {
    struct list_head mgir_list;
    dev_private_data_t *dev_data;
} mgir_data_t;

typedef struct msgi_data {
    struct list_head msgi_list;
    dev_private_data_t *dev_data;
} msgi_data_t;

typedef struct mdir_data {
    struct list_head mdir_list;
    dev_private_data_t *dev_data;
} mdir_data_t;

typedef struct spad_data {
    struct list_head spad_list;
    dev_private_data_t *dev_data;
} spad_data_t;

typedef struct spzr_data {
    uint8_t swid;
    uint8_t router_entity;
    struct list_head spzr_list;
    dev_private_data_t *dev_data;
} spzr_data_t;

typedef struct ptys_data {
    uint16_t local_port;
    sxd_ptys_pnat_t pnat;
    sxd_ptys_port_type_t port_type;
    uint8_t plane_ind;
    sxd_ptys_proto_mask_t proto_mask;
    struct list_head ptys_list;
    dev_private_data_t *dev_data;
} ptys_data_t;

typedef struct ppcnt_data {
    uint8_t swid;
    uint16_t local_port;
    sxd_ppcnt_pnat_t pnat;
    uint8_t port_type;
    sxd_ppcnt_grp_t grp;
    uint8_t lp_gl;
    uint8_t plane_ind;
    uint8_t grp_profile;
    uint8_t prio_tc;
    struct list_head ppcnt_list;
    dev_private_data_t *dev_data;
} ppcnt_data_t;

typedef struct pmaos_data {
    uint8_t slot_index;
    uint8_t module;
    struct list_head pmaos_list;
    dev_private_data_t *dev_data;
} pmaos_data_t;

typedef struct sltp_data {
    uint16_t local_port;
    uint8_t pnat;
    uint8_t lane;
    sxd_sltp_port_type_t port_type;
    struct list_head sltp_list;
    dev_private_data_t *dev_data;
} sltp_data_t;

typedef struct pddr_data {
    uint16_t local_port;
    sxd_pddr_pnat_t pnat;
    uint8_t plane_ind;
    sxd_pddr_port_type_t port_type;
    sxd_pddr_page_select_t page_select;
    struct list_head pddr_list;
    dev_private_data_t *dev_data;
} pddr_data_t;

typedef struct pnlpnr_data {
    uint16_t local_port;
    struct list_head pnlpnr_list;
    dev_private_data_t *dev_data;
} pnlpnr_data_t;

typedef struct pmdr_data {
    uint16_t local_port;
    uint8_t pnat;
    uint8_t plane_ind;
    struct list_head pmdr_list;
    dev_private_data_t *dev_data;
} pmdr_data_t;

typedef struct pphcr_data {
    uint16_t local_port;
    sxd_pphcr_pnat_t pnat;
    uint8_t port_type;
    uint8_t plane_ind;
    uint8_t hist_type;
    struct list_head pphcr_list;
    dev_private_data_t *dev_data;
} pphcr_data_t;

typedef struct sllm_data {
    uint16_t local_port;
    uint8_t pnat;
    uint8_t lane;
    sxd_sllm_port_type_t port_type;
    struct list_head sllm_list;
    dev_private_data_t *dev_data;
} sllm_data_t;

typedef struct pemi_data {
    uint16_t local_port;
    uint8_t pnat;
    sxd_pemi_page_select_t page_select;
    struct list_head pemi_list;
    dev_private_data_t *dev_data;
} pemi_data_t;

/************************************************
 * Functions                                    *
 ***********************************************/

int sx_spice_prepare_access_reg(dev_private_data_t *priv_data);
void sx_spice_post_access_reg(dev_private_data_t *priv_data, bool sem_acquired);

int sx_spice_access_reg_mtcap_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_mtcap_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_mtcap_reg * reg_data);
ssize_t sx_spice_access_reg_mtcap_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_mtcap_list_free(void);

int sx_spice_access_reg_mvcap_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_mvcap_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_mvcap_reg * reg_data);
ssize_t sx_spice_access_reg_mvcap_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_mvcap_list_free(void);

int sx_spice_access_reg_mtmp_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_mtmp_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_mtmp_reg * reg_data);
ssize_t sx_spice_access_reg_mtmp_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_mtmp_list_free(void);

int sx_spice_access_reg_mgir_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_mgir_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_mgir_reg * reg_data);
ssize_t sx_spice_access_reg_mgir_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_mgir_list_free(void);

int sx_spice_access_reg_msgi_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_msgi_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_msgi_reg * reg_data);
ssize_t sx_spice_access_reg_msgi_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_msgi_list_free(void);

int sx_spice_access_reg_mdir_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_mdir_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_mdir_reg * reg_data);
ssize_t sx_spice_access_reg_mdir_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_mdir_list_free(void);

int sx_spice_access_reg_spad_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_spad_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_spad_reg * reg_data);
ssize_t sx_spice_access_reg_spad_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_spad_list_free(void);

int sx_spice_access_reg_spzr_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_spzr_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_spzr_reg * reg_data);
ssize_t sx_spice_access_reg_spzr_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_spzr_list_free(void);

int sx_spice_access_reg_ptys_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_ptys_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_ptys_reg * reg_data);
ssize_t sx_spice_access_reg_ptys_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_ptys_list_free(void);

int sx_spice_access_reg_ppcnt_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_ppcnt_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_ppcnt_reg * reg_data);
ssize_t sx_spice_access_reg_ppcnt_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_ppcnt_list_free(void);

int sx_spice_access_reg_pmaos_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pmaos_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pmaos_reg * reg_data);
ssize_t sx_spice_access_reg_pmaos_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pmaos_list_free(void);

int sx_spice_access_reg_sltp_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_sltp_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_sltp_reg * reg_data);
ssize_t sx_spice_access_reg_sltp_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_sltp_list_free(void);

int sx_spice_access_reg_pddr_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pddr_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pddr_reg * reg_data);
ssize_t sx_spice_access_reg_pddr_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pddr_list_free(void);

int sx_spice_access_reg_pnlpnr_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pnlpnr_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pnlpnr_reg * reg_data);
ssize_t sx_spice_access_reg_pnlpnr_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pnlpnr_list_free(void);

int sx_spice_access_reg_pmdr_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pmdr_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pmdr_reg * reg_data);
ssize_t sx_spice_access_reg_pmdr_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pmdr_list_free(void);

int sx_spice_access_reg_pphcr_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pphcr_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pphcr_reg * reg_data);
ssize_t sx_spice_access_reg_pphcr_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pphcr_list_free(void);

int sx_spice_access_reg_sllm_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_sllm_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_sllm_reg * reg_data);
ssize_t sx_spice_access_reg_sllm_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_sllm_list_free(void);

int sx_spice_access_reg_pemi_file_create(struct dentry *parent, dev_private_data_t *dev_data);
int sx_spice_access_reg_pemi_data_to_buffer_print(char buffer[], size_t buffer_length, struct ku_pemi_reg * reg_data);
ssize_t sx_spice_access_reg_pemi_read(struct file *filp, char *buf, size_t lbuf, loff_t *ppos);
void sx_spice_access_reg_pemi_list_free(void);


