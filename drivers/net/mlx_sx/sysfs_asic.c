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
#include <linux/string.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/driver.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include "sx.h"
#include "dev_db.h"
#include <linux/mlx_sx/kernel_user.h>

#define MCAM_GROUP2_CONTOL_MASK_END_ID (0x917F)
static uint8_t __max_module_num = 0;

/*********temp**********/
static ssize_t __show_asic_temp_highest(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_asic_temp_input(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_asic_temp_label(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute asic_temp_highest_attr = __ATTR(highest, S_IRUGO, __show_asic_temp_highest, NULL);
static struct kobj_attribute asic_temp_input_attr = __ATTR(input, S_IRUGO, __show_asic_temp_input, NULL);
static struct kobj_attribute asic_temp_label_attr = __ATTR(label, S_IRUGO, __show_asic_temp_label, NULL);


/********performance counters********/
#define PERF_CNTR_MAX_HW_UNIT_ID_SPEC1 34
#define PERF_CNTR_MAX_HW_UNIT_ID_SPEC2 57
#define PERF_CNTR_MAX_HW_UNIT_ID_SPEC3 62
#define PERF_CNTR_MAX_HW_UNIT_ID_SPEC4 133
#define MAX_COUNTER_FILE_ROW_LEN       12 /*max hw_unit_id is 0x84, max counter is (for SPC4) 0x1f4, + 3 char for ":,\n,\0" */
#define SYSFS_MAX_BUFF_LEN             PAGE_SIZE /*buf size is sysfs is PAGE_SIZE */

/********sysfs sniffer********/
#define SYSFS_SX_CORE_FULL_PREFIX   "/sys/module/sx_core/"
#define SYSFS_SX_NETDEV_FULL_PREFIX "/sys/module/"

static size_t perf_cntr_hw_unit_max_cntr_arr_spc1[PERF_CNTR_MAX_HW_UNIT_ID_SPEC1] =
{8, 8, 8, 0, 6, 4, 4, 8, 8, 8, 8, 4, 4, 8, 4, 8, 8, 4, 4, 8, 8, 6, 8, 8, 8, 8, 8, 4, 4, 8, 8, 4, 4, 6};

static size_t perf_cntr_hw_unit_max_cntr_arr_spc2[PERF_CNTR_MAX_HW_UNIT_ID_SPEC2] =
{4, 4, 4, 4, 16, 16, 8, 16, 16, 16, 4, 8, 8, 4, 4, 8, 4, 8, 8, 6, 8, 4, 8, 8, 8, 16, 16, 16, 16, 8, 8, 8,
 8, 8, 8, 16, 8, 4, 4, 4, 4, 16, 16, 8, 16, 8, 16, 8, 4, 8, 4, 4, 8, 8, 16, 8, 6};

static size_t perf_cntr_hw_unit_max_cntr_arr_spc3[PERF_CNTR_MAX_HW_UNIT_ID_SPEC3] =
{4, 4, 4, 4, 16, 16, 8, 16, 16, 16, 4, 8, 8, 4, 4, 8, 4, 8, 8, 6, 8, 4, 8, 8, 8, 16, 16, 16, 16, 8, 8,
 8, 8, 8, 8, 16, 8, 4, 4, 4, 4, 16, 16, 8, 16, 8, 16, 8, 4, 8, 4, 4, 8, 8, 16, 8, 6, 8, 16, 8, 8, 16};

static size_t perf_cntr_hw_unit_max_cntr_arr_spc4[PERF_CNTR_MAX_HW_UNIT_ID_SPEC4] =
{4, 16, 0, 8, 8, 6, 0, 0, 0, 0, 16, 16, 16, 16, 16, 4, 16, 16, 16, 8, 16, 16, 16, 16, 0, 0, 0, 0, 16, 16,
 16, 8, 16, 4, 16, 8, 16, 16, 4, 16, 8, 16, 8, 16, 16, 16, 16, 8, 8, 0, 0, 0, 16, 16, 2, 8, 4, 8, 8, 16,
 4, 4, 16, 4, 8, 8, 8, 8, 16, 16, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 0, 4, 4, 0, 4,
 4, 16, 4, 4, 16, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 4, 2, 2, 2, 2, 4, 16, 2, 2, 4, 16, 4, 16, 8, 4, 4, 4,
 4, 4, 4, 4, 20, 2};

static size_t perf_cntr_max_cntr_id_in_hw_unit_arr_spc1[PERF_CNTR_MAX_HW_UNIT_ID_SPEC1] =
{203, 86, 1204, 0, 85, 153, 136, 268, 315, 66, 21, 8, 10, 11, 5, 1029, 140, 153, 136, 268, 315,
 186, 135, 91, 91, 22, 260, 74, 11, 177, 32, 1589, 108, 85};

static size_t perf_cntr_max_cntr_id_in_hw_unit_arr_spc2[PERF_CNTR_MAX_HW_UNIT_ID_SPEC2] =
{153, 136, 128, 79, 202, 806, 1346, 134, 173, 491, 8, 69, 47, 14, 15, 12, 19, 159, 289, 16, 141,
 13, 49, 177, 210, 491, 1058, 775, 54, 15, 30, 312, 186, 43, 43, 1269, 2, 153, 136, 128, 79, 202,
 806, 1346, 134, 483, 222, 17, 72, 4439, 225, 225, 710, 399, 173, 1857, 16};

static size_t perf_cntr_max_cntr_id_in_hw_unit_arr_spc3[PERF_CNTR_MAX_HW_UNIT_ID_SPEC3] =
{153, 136, 128, 79, 156, 418, 1396, 130, 177, 519, 8, 69, 47, 14, 15, 12, 19, 238, 311, 16, 145,
 21, 49, 305, 338, 519, 1124, 843, 54, 15, 30, 410, 236, 51, 51, 1376, 9, 153, 136, 128, 79, 156,
 418, 1396, 130, 291, 222, 17, 136, 4926, 243, 243, 218, 437, 177, 971, 16, 93, 167, 1786, 1574, 89};

static size_t perf_cntr_max_cntr_id_in_hw_unit_arr_spc4[PERF_CNTR_MAX_HW_UNIT_ID_SPEC4] =
{6, 882, 0, 347, 317, 6, 0, 0, 0, 0, 588, 335, 201, 96, 69, 244, 207, 166, 55, 99, 539, 539, 1465,
 787, 0, 0, 0, 0, 1129, 2745, 655, 15, 1869, 6, 196, 1702, 502, 1869, 6, 196, 1702, 502, 302, 311,
 338, 72, 549, 5895, 3645, 0, 0, 0, 155, 20, 10, 237, 6, 411, 865, 239, 6, 264, 155, 123, 471, 115,
 241, 865, 239, 552, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 0, 6, 6, 0, 6, 6, 6,
 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 777, 6, 774, 3072, 3870, 48, 6, 768, 774, 777, 271, 616,
 6, 897, 625, 6, 6, 6, 264, 264, 264, 264, 20, 10};


static ssize_t __show_asic_perf_cntr_counters(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __store_asic_perf_cntr_counters(struct kobject        *kobj,
                                               struct kobj_attribute *attr,
                                               const char            *buf,
                                               size_t                 len);
static ssize_t __show_asic_perf_cntr_interval(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __store_asic_perf_cntr_interval(struct kobject        *kobj,
                                               struct kobj_attribute *attr,
                                               const char            *buf,
                                               size_t                 len);
static struct kobj_attribute asic_perf_cntr_counters_attr =
    __ATTR(counters, (S_IRUGO | S_IWUSR), __show_asic_perf_cntr_counters, __store_asic_perf_cntr_counters);
static struct kobj_attribute asic_perf_cntr_interval_attr =
    __ATTR(interval, (S_IRUGO | S_IWUSR), __show_asic_perf_cntr_interval, __store_asic_perf_cntr_interval);

#define GA_MAX_NUM (GA_MAX_INDEX - GA_MIN_INDEX + 1)

/* MMAM have same module type enum as PMTM */
#define MODULE_IS_BACKPLANE_TYPE(module_type)                              \
    ((module_type == SXD_PMTM_MODULE_TYPE_BACKPLANE_WITH_SINGLE_LANE_E) || \
     (module_type == SXD_PMTM_MODULE_TYPE_BACKPLANE_WITH_TWO_LANES_E) ||   \
     (module_type == SXD_PMTM_MODULE_TYPE_BACKPLANE_WITH_4_LANES_E) ||     \
     (module_type == SXD_PMTM_MODULE_TYPE_BACKPLANE_WITH_8_LANES_E))

struct sx_global_module {
    bool    inited;
    uint8_t ga;             /* Asic GA id */
    uint8_t local_module;   /* Local module id */
    uint8_t module_type;    /* Module type */
};

struct sx_local_module {
    bool    inited;
    uint8_t global_module;   /* Global module id */
};

struct sx_ga_map_dev_id_entry {
    bool         inited;
    sxd_dev_id_t dev_id;
};

struct sx_module_type {
    bool    inited;
    uint8_t module_type;    /* Module type */
};

static struct sx_global_module       __global_modules[MAX_MODULE_NUM] = {
    {0}
};
static struct sx_local_module        __local_modules[GA_MAX_NUM][MAX_MODULE_NUM] = {
    {
        {0}
    }
};
static struct sx_ga_map_dev_id_entry ga_devid_map[GA_MAX_NUM] = {
    {0}
};

static struct sx_module_type __modules[MAX_MODULE_NUM] = {
    {0}
};
struct module_sysfs_node    *__default_module_sysfs_root_arr = NULL;

char * __sx_sysfs_get_str(char *buffer, char **str, const char* delimiters);
char * __sx_sysfs_get_id_str(char *buffer, char **str);
char * __sx_sysfs_get_hw_unit_counter_pair_str(char *buffer, char **str);
static int __perf_cntr_add_pair_to_counters_db(struct kobject  *kobj,
                                               int              hw_unit_id,
                                               int              counter_id,
                                               sxd_chip_types_t chip_type);
static int __perf_cntr_validate_hw_unit_id(sxd_chip_types_t chip_type, size_t hw_unit_id);
static int __perf_cntr_validate_counter_id(sxd_chip_types_t chip_type, size_t hw_unit_id, size_t counter_id);
static int __perf_cntr_validate_hw_unit_and_cntr_id(struct kobject  *kobj,
                                                    size_t           hw_unit_id,
                                                    size_t           counter_id,
                                                    sxd_chip_types_t chip_type);
static int __perf_cntr_add_new_mopct_node_to_list(struct sx_perf_cntr *perf_cntr_p,
                                                  int                  hw_unit_id,
                                                  int                  counter_id);
static struct mopct_node* __perf_cntr_allocate_mopct_node(int hw_unit_id,
                                                          int counter_id,
                                                          int group_id);

int find_full_path(struct kobject               *kobj,
                   char                        * path_p,
                   const char                   *file_name,
                   enum sysfs_sniffer_event_type sysfs_type);

/*********************************************************************/


static int __read_frequency_support_to_db(struct sx_dev *dev)
{
    int                       err = 0;
    struct sx_priv           *priv = sx_priv(dev);
    struct ku_access_mcam_reg mcam_reg_data;
    bool                      frequency_support = false;

    memset(&mcam_reg_data, 0, sizeof(mcam_reg_data));
    mcam_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&mcam_reg_data.op_tlv, MLXSW_MCAM_ID, EMAD_METHOD_QUERY);
    mcam_reg_data.mcam_reg.access_reg_group = SXD_MCAM_ACCESS_REG_GROUP_REGISTER_IDS_0X9100_E;

    err = sx_ACCESS_REG_MCAM(dev, &mcam_reg_data);
    if (err) {
        sxd_log_notice("Failed to query MCAM, err=%d\n", err);
        goto out;
    }

    if (mcam_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_notice("Failed to query MCAM, status=%d\n", mcam_reg_data.op_tlv.status);
        goto out;
    }

    if (SX_CORE_BITMAP_LE_GET(mcam_reg_data.mcam_reg.mng_access_reg_cap_mask,
                              SXD_MCAM_MNG_ACCESS_REG_CAP_MASK_NUM,
                              sizeof(mcam_reg_data.mcam_reg.mng_access_reg_cap_mask[0]) * 8,
                              (MLXSW_MCFS_ID & 0xff))) {
        frequency_support = true;
    } else {
        frequency_support = false;
    }

out:
    priv->independent_module_params.frequency_support = frequency_support;
    return err;
}

static int __read_apply_im_supported(struct sx_dev *dev)
{
    int                       err = 0;
    struct sx_priv           *priv = sx_priv(dev);
    struct ku_access_pcam_reg pcam_reg_data;
    bool                      apply_im_supported = false;

    memset(&pcam_reg_data, 0, sizeof(pcam_reg_data));
    pcam_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&pcam_reg_data.op_tlv, MLXSW_PCAM_ID, EMAD_METHOD_QUERY);

    err = sx_ACCESS_REG_PCAM(dev, &pcam_reg_data);
    if (err) {
        sxd_log_notice("Failed to query PCAM, err=%d\n", err);
        goto out;
    }

    if (pcam_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_notice("Failed to query PCAM, status=%d\n", pcam_reg_data.op_tlv.status);
        goto out;
    }

    apply_im_supported =
        !!(pcam_reg_data.pcam_reg.feature_cap_mask[1] & SXD_PCAM_FEATURE_CAP_MASK_PMMP_APPLY_IM_SUPPORTED_E);

out:
    priv->apply_im_supported = apply_im_supported;
    return err;
}

static int __init_max_module_num(struct sx_dev *dev)
{
    int                        err = 0;
    struct ku_access_mgpir_reg reg_data;

    reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&reg_data.op_tlv, MLXSW_MGPIR_ID, EMAD_METHOD_QUERY);
    reg_data.mgpir_reg.hw_info.slot_index = 0; /*slot is set 0 by default */

    err = sx_ACCESS_REG_MGPIR(dev, &reg_data);
    if (err || reg_data.op_tlv.status) {
        sxd_log_err("Fails to access register MGPIR, err: %d, status: %d.\n", err, reg_data.op_tlv.status);
        err = -EFAULT;
        goto out;
    }
    __max_module_num = reg_data.mgpir_reg.hw_info.num_of_modules;
    if (sx_core_has_predefined_devices()) {
        /* number of total modules in all ASICs together */
        __max_module_num = reg_data.mgpir_reg.hw_info.num_of_modules_per_system;
    }
    sxd_log_info("__max_module_num:%d.\n", __max_module_num);

out:
    return err;
}

static int __get_pmtm_module_type(struct sx_dev *dev, uint8_t module, uint8_t *module_type)
{
    int                       err = 0;
    struct ku_access_pmtm_reg pmtm_reg_data;

    memset(&pmtm_reg_data, 0, sizeof(pmtm_reg_data));
    pmtm_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&pmtm_reg_data.op_tlv, MLXSW_PMTM_ID, EMAD_METHOD_QUERY);
    pmtm_reg_data.pmtm_reg.slot_index = 0;
    pmtm_reg_data.pmtm_reg.module = module;

    err = sx_ACCESS_REG_PMTM(dev, &pmtm_reg_data);
    if (err) {
        sxd_log_err("Failed to query PMTM, err=%d\n", err);
        goto out;
    }

    if (pmtm_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("Failed to query PMTM, status=%d\n", pmtm_reg_data.op_tlv.status);
        goto out;
    }

    if (module_type) {
        *module_type = pmtm_reg_data.pmtm_reg.module_type;
    }

out:
    return err;
}

static int __init_module_type_map(struct sx_dev *dev, uint8_t module)
{
    int     ret = 0;
    uint8_t module_type = 0;

    ret = __get_pmtm_module_type(dev, module, &module_type);
    if (ret) {
        goto out;
    }

    __modules[module].module_type = module_type;
    __modules[module].inited = true;

out:
    return ret;
}

static void __deinit_module_type_map(struct sx_dev *dev, uint8_t module)
{
    __modules[module].module_type = 0;
    __modules[module].inited = false;
}

int sx_module_sysfs_dump(struct seq_file *m, void *v, void *context)
{
    int i = 0;

    /* this function MUST NOT be called from interrupt context */

    seq_printf(m, "Module Sysfs Mappings\n");
    seq_printf(m, "-------------------------------------------------------------------------------\n\n");
    seq_printf(m, "Predefined device IDs: %s\n\n", (sx_core_has_predefined_devices() ? "yes" : "no"));

    seq_printf(m, "\n%-14s   %s\n", "Module", "Module-Type");
    seq_printf(m, "...............................................................................\n");
    for (i = 0; i < MAX_MODULE_NUM; i++) {
        if (!__modules[i].inited) {
            continue;
        }
        seq_printf(m, "%-14d   %u\n", i, __modules[i].module_type);
    }

    seq_printf(m, "\n\n");
    return 0;
}

static void __get_skip_sysfs_mode_for_modules(bool *module_skip_sysfs_arr, uint8_t module_num)
{
    int i = 0;

    if (sx_core_has_predefined_devices()) {
        for (i = 0; i < module_num; i++) {
            module_skip_sysfs_arr[i] = __global_modules[(i)].inited && MODULE_IS_BACKPLANE_TYPE(
                __global_modules[(i)].module_type);
        }
    } else {
        for (i = 0; i < module_num; i++) {
            module_skip_sysfs_arr[i] = __modules[i].inited && MODULE_IS_BACKPLANE_TYPE(__modules[i].module_type);
        }
    }

    return;
}

/*
 *  "use_global_module" should be true for multi-asic system module sysfs entries, plus a valid "global_module".
 *  In multi-asic system, module sysfs entries are only under "asic0" directory, hence global_module id is used to choose sx_dev.
 *  They will be ignored for single-asic system.
 */
int sx_core_asic_get_dev(struct kobject *asic_kobj, bool use_global_module, uint8_t global_module, struct sx_dev **dev)
{
    int          ret = 0;
    sxd_dev_id_t dev_id = 0;
    long         asic_id = 0;
    bool         global_module_map_inited = false;

    ret = kstrtol(asic_kobj->name + strlen(ASIC_SYSFS_PREFIX), 0, &asic_id);
    if (ret) {
        sxd_log_err("Failed to get asic id, err=%d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    if (sx_core_has_predefined_devices()) {
        dev_id = (sxd_dev_id_t)(asic_id + 1);
        if (use_global_module) {
            /* Multi-asic module sysfs entries are only under asic0 directory. */
            ret = sx_multi_asic_module_sysfs_module_is_inited(global_module, &global_module_map_inited);
            if (ret) {
                goto out;
            }
            if (global_module_map_inited) {
                ret = sx_multi_asic_module_sysfs_get_devid_via_ga(__global_modules[global_module].ga, &dev_id);
                if (ret) {
                    sxd_log_err("Failed to get device via ga %d of global_module %d, err: %d.\n",
                                __global_modules[global_module].ga, global_module, ret);
                    goto out;
                }
            }
        }

        *dev = sx_dev_db_get_dev_by_id(dev_id);
    } else {
        *dev = sx_dev_db_get_default_device();
    }

    if (!(*dev)) {
        sxd_log_err("Failed to get device\n");
        ret = -ENODEV;
        goto out;
    }

out:
    return ret;
}

static int __get_global_module_info_from_mmam(struct sx_dev *dev,
                                              uint8_t        global_module_id,
                                              uint8_t       *ga,
                                              uint8_t       *local_module_id,
                                              uint8_t       *module_type)
{
    int                       err = 0;
    struct ku_access_mmam_reg mmam_reg_data;

    memset(&mmam_reg_data, 0, sizeof(mmam_reg_data));
    sx_cmd_set_op_tlv(&mmam_reg_data.op_tlv, MLXSW_MMAM_ID, EMAD_METHOD_QUERY);
    mmam_reg_data.dev_id = dev->device_id;
    mmam_reg_data.mmam_reg.module = global_module_id;

    err = sx_ACCESS_REG_MMAM(dev, &mmam_reg_data);
    if (err) {
        sxd_log_err("Failed to access MMAM, dev_id: %d, module %u, err=%d.\n", dev->device_id, global_module_id, err);
        goto out;
    }

    if (mmam_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("MMAM return error status %d,dev_id: %d, module %u. \n",
                    mmam_reg_data.op_tlv.status,
                    dev->device_id,
                    global_module_id);
        goto out;
    }

    *ga = mmam_reg_data.mmam_reg.ga;
    *local_module_id = mmam_reg_data.mmam_reg.local_module;
    *module_type = mmam_reg_data.mmam_reg.module_type;

out:
    return err;
}

const char * sx_get_ga_asic_str(enum asic_ga_index ga)
{
    const char *ret;

    switch (ga) {
    case GA_ASIC_0:
        ret = "ASIC0";
        break;

    case GA_ASIC_1:
        ret = "ASIC1";
        break;

    case GA_ASIC_2:
        ret = "ASIC2";
        break;

    case GA_ASIC_3:
        ret = "ASIC3";
        break;

    default:
        ret = "N/A";
    }

    return ret;
}

int sx_multi_asic_module_sysfs_map_ga_to_devid(u8 ga, sxd_dev_id_t dev_id)
{
    int ret = 0;

    if (ga > GA_MAX_INDEX) {
        sxd_log_err("Invalid ga %d for device_id %d.\n", ga, dev_id);
        ret = -EINVAL;
        goto out;
    }
    ga_devid_map[ga].dev_id = dev_id;
    ga_devid_map[ga].inited = true;
out:
    return ret;
}

void sx_multi_asic_module_unmap_ga_devid(u8 ga, sxd_dev_id_t dev_id)
{
    if (ga > GA_MAX_INDEX) {
        return;
    }
    ga_devid_map[ga].dev_id = 0;
    ga_devid_map[ga].inited = false;
}

int sx_multi_asic_module_sysfs_get_devid_via_ga(u8 ga, sxd_dev_id_t *dev_id)
{
    int ret = 0;

    if (ga > GA_MAX_INDEX) {
        sxd_log_err("Invalid ga %d.\n", ga);
        ret = -EINVAL;
        goto out;
    }
    if (!ga_devid_map[ga].inited) {
        sxd_log_err("ga %d is not mapped to a dev_id.\n", ga);
        ret = -EINVAL;
        goto out;
    }

    if (dev_id) {
        *dev_id = ga_devid_map[ga].dev_id;
    }
out:
    return ret;
}

int sx_multi_asic_module_sysfs_get_global_module(uint8_t ga, uint8_t local_module, uint8_t *global_module)
{
    int ret = 0;

    if (ga >= GA_MAX_NUM) {
        sxd_log_err("Input ga (%u) is out of range (%d).\n", ga, GA_MAX_NUM);
        ret = -EINVAL;
        goto out;
    }

    if (local_module >= MAX_MODULE_NUM) {
        sxd_log_err("Input local module (%u) is out of range (%d).\n", local_module, MAX_MODULE_NUM);
        ret = -EINVAL;
        goto out;
    }

    if (!__local_modules[ga][local_module].inited) {
        sxd_log_err("Input local module (%u) map is not inited.\n", local_module);
        ret = -EINVAL;
        goto out;
    }

    if (global_module) {
        *global_module = __local_modules[ga][local_module].global_module;
    }

out:
    return ret;
}

int sx_multi_asic_module_sysfs_module_is_inited(uint8_t global_module, bool *inited)
{
    int ret = 0;

    if (global_module >= MAX_MODULE_NUM) {
        sxd_log_err("Input global module (%u) is out of range (%d).\n", global_module, MAX_MODULE_NUM);
        ret = -EINVAL;
        goto out;
    }

    if (inited) {
        *inited = __global_modules[global_module].inited;
    }

out:
    return ret;
}

/*
 *   Used for module related PRM register access, necessary for multi-asic system while not necessary for single asic system (nor independent or standalone module):
 *   - For multi-asic system, local module is used for most module related PRM register access, which may be different from global module.
 *   - For single asic system, local module is assumed to be same as global module for PRM register access.
 */
int sx_core_get_possible_local_module(uint8_t global_module, uint8_t *local_module)
{
    int  ret = 0;
    bool global_module_map_inited = false;

    if (local_module) {
        *local_module = global_module;
        if (sx_core_has_predefined_devices()) {
            ret = sx_multi_asic_module_sysfs_module_is_inited(global_module, &global_module_map_inited);
            if (ret) {
                goto out;
            }
            if (global_module_map_inited && local_module) {
                *local_module = __global_modules[global_module].local_module;
            }
        }
    }
out:
    return ret;
}

static int __init_mmam_support(struct sx_dev *dev)
{
    int                       err = 0;
    struct sx_priv           *priv = sx_priv(dev);
    struct ku_access_mcam_reg mcam_reg_data;
    bool                      mmam_support = false;

    memset(&mcam_reg_data, 0, sizeof(mcam_reg_data));
    mcam_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&mcam_reg_data.op_tlv, MLXSW_MCAM_ID, EMAD_METHOD_QUERY);
    mcam_reg_data.mcam_reg.access_reg_group = SXD_MCAM_ACCESS_REG_GROUP_REGISTER_IDS_0X9100_E;

    err = sx_ACCESS_REG_MCAM(dev, &mcam_reg_data);
    if (err) {
        sxd_log_err("Failed to query MCAM, err=%d\n", err);
        goto out;
    }

    if (mcam_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("Failed to query MCAM, status=%d\n", mcam_reg_data.op_tlv.status);
        goto out;
    }

    /* mcam_reg.mng_access_reg_cap_mask is little-endian */
    if (SX_CORE_BITMAP_LE_GET(mcam_reg_data.mcam_reg.mng_access_reg_cap_mask,
                              SXD_MCAM_MNG_ACCESS_REG_CAP_MASK_NUM,
                              sizeof(mcam_reg_data.mcam_reg.mng_access_reg_cap_mask[0]) * 8,
                              (MLXSW_MMAM_ID & 0xff))) {
        mmam_support = true;
    } else {
        mmam_support = false;
    }

out:
    priv->mmam_support = mmam_support;
    return err;
}

int sx_multi_asic_module_sysfs_env_init(struct sx_dev *dev)
{
    int err = 0;

    err = __init_mmam_support(dev);
    if (err) {
        goto out;
    }

out:
    return err;
}

/* Set up map of global module idx - ga - local module id */
static int __init_map_of_global_module_and_ga_local_module(struct sx_dev *dev, uint8_t global_module)
{
    int     ret = 0;
    uint8_t ga = 0;
    uint8_t local_module = 0;
    uint8_t module_type = 0;

    ret = __get_global_module_info_from_mmam(dev,
                                             global_module,
                                             &ga,
                                             &local_module,
                                             &module_type);
    if (ret) {
        goto out;
    }

    __global_modules[global_module].ga = ga;
    __global_modules[global_module].local_module = local_module;
    __global_modules[global_module].module_type = module_type;
    __global_modules[global_module].inited = true;

    __local_modules[ga][local_module].global_module = global_module;
    __local_modules[ga][local_module].inited = true;

out:
    return ret;
}

static int __deinit_map_of_global_module_and_ga_local_module(struct sx_dev *dev, uint8_t global_module)
{
    int     ret = 0;
    uint8_t ga = 0;
    uint8_t local_module = 0;
    uint8_t module_type = 0;

    ret = __get_global_module_info_from_mmam(dev,
                                             global_module,
                                             &ga,
                                             &local_module,
                                             &module_type);
    if (ret) {
        goto out;
    }

    __global_modules[global_module].ga = 0;
    __global_modules[global_module].local_module = 0;
    __global_modules[global_module].module_type = 0;
    __global_modules[global_module].inited = false;

    __local_modules[ga][local_module].global_module = 0;
    __local_modules[ga][local_module].inited = false;

out:
    return ret;
}

/*
 *   ga -> pci device id
 *   global module id -> ga, local module id, type (including those backplane types)
 *   <pci device id, local module> -> global module
 */
int sx_multi_asic_module_sysfs_dump(struct seq_file *m, void *v, void *context)
{
    int            i = 0;
    int            j = 0;
    struct sx_dev *dev = NULL;

    /* this function MUST NOT be called from interrupt context */

    seq_printf(m, "Multi-asic Module Sysfs Mappings\n");
    seq_printf(m, "-------------------------------------------------------------------------------\n\n");
    seq_printf(m, "Predefined device IDs: %s\n\n", (sx_core_has_predefined_devices() ? "yes" : "no"));
    if (!sx_core_has_predefined_devices()) {
        goto out;
    }

    seq_printf(m, "\n%-6s   %-5s   %-9s\n", "GA", "Inited", "Device-Id");
    seq_printf(m, "...............................................................................\n");
    for (i = 0; i < GA_MAX_NUM; i++) {
        if (ga_devid_map[i].inited) {
            dev = sx_dev_db_get_dev_by_id(ga_devid_map[i].dev_id);
            if (dev) {
                seq_printf(m, "%-6s   %-5s   %-9u\n",
                           sx_get_ga_asic_str(i),
                           "yes",
                           ga_devid_map[i].dev_id);
            }
        } else {
            seq_printf(m, "%-6s   %-5s   %-9s\n",
                       sx_get_ga_asic_str(i), "no", "NA");
        }
    }

    seq_printf(m, "\n%-14s   %-6s   %-14s   %s\n", "Global-Module", "GA", "Local-Module", "Module-Type");
    seq_printf(m, "...............................................................................\n");
    for (i = 0; i < MAX_MODULE_NUM; i++) {
        if (!__global_modules[i].inited) {
            continue;
        }
        seq_printf(m, "%-14d   %-6s   %-14u   %u\n", i,
                   sx_get_ga_asic_str(__global_modules[i].ga),
                   __global_modules[i].local_module,
                   __global_modules[i].module_type);
    }

    seq_printf(m, "\n%-6s   %-14s   %-14s\n", "GA", "Local-Module", "Global-Module");
    seq_printf(m, "...............................................................................\n");
    for (i = 0; i < GA_MAX_NUM; i++) {
        for (j = 0; j < MAX_MODULE_NUM; j++) {
            if (!__local_modules[i][j].inited) {
                continue;
            }
            seq_printf(m, "%-6s   %-14u   %-14u\n",
                       sx_get_ga_asic_str(i), j,
                       __local_modules[i][j].global_module);
        }
    }

out:
    seq_printf(m, "\n\n");
    return 0;
}

int sx_multi_asic_module_sysfs_need_skip(uint8_t module, bool *need_skip)
{
    int ret = 0;

    if (module >= MAX_MODULE_NUM) {
        sxd_log_err("Input module (%u) is out of range (%d).\n", module, MAX_MODULE_NUM);
        ret = -EINVAL;
        goto out;
    }

    if (!need_skip) {
        goto out;
    }

    *need_skip = false;
    if (sx_core_has_predefined_devices()) {
        *need_skip = __global_modules[module].inited && MODULE_IS_BACKPLANE_TYPE(__global_modules[module].module_type);
    } else {
        *need_skip = __modules[module].inited && MODULE_IS_BACKPLANE_TYPE(__modules[module].module_type);
    }

out:
    return ret;
}

int sx_core_create_default_modules_sysfs_tree(struct sx_dev             *dev,
                                              struct kobject            *parent,
                                              struct module_sysfs_node **root_arr)
{
    int     err = 0;
    int     err2 = 0;
    uint8_t i, j, k, l;
    char    mod_name[16];
    bool    module_skip_sysfs_arr[MAX_MODULE_NUM];
    uint8_t h = 0;

    sxd_log_debug("create module sysfs for dev id %u.\n", dev->device_id);
    err = __init_max_module_num(dev);
    if (err) {
        sxd_log_err("module sysfs nodes handler failed to get maximum module number.\n");
        goto out;
    }

    if (!__max_module_num || (__max_module_num > MAX_MODULE_NUM)) {
        sxd_log_notice("module eeprom sysfs will not be created because __max_module_num (%d) is out of range.\n",
                       __max_module_num);
        goto out;
    }

    err = __read_apply_im_supported(dev);
    if (err) {
        sxd_log_err("Failed to read apply immediate is supported.\n");
        goto out;
    }

    err = sx_internal_log_init(&sx_priv(dev)->module_log,
                               10000,
                               SX_INTERNAL_LOG_SEVERITY_INFO_E,
                               "module_log");
    if (err) {
        printk(KERN_ERR "Failed to init internal log for module.\n");
        goto out;
    }
    sx_priv(dev)->module_log_init = true;

    *root_arr = kzalloc(__max_module_num * sizeof(struct module_sysfs_node), GFP_KERNEL);
    if (!(*root_arr)) {
        sxd_log_err("module sysfs nodes handler failed to allocated memory.\n");
        err = -ENOMEM;
        goto out;
    }

    if (sx_core_has_predefined_devices() && MULTI_ASIC_MODULE_SYSFS_IS_SUPPORT(sx_priv(dev))) {
        for (h = 0; h < __max_module_num; h++) {
            err = __init_map_of_global_module_and_ga_local_module(dev, h);
            if (err) {
                sxd_log_err("Failed to build global module (%u) map for multi-asic system (device_id: %u).\n",
                            h,
                            dev->device_id);
                goto deinit_map;
            }
        }
    } else {
        for (h = 0; h < __max_module_num; h++) {
            err = __init_module_type_map(dev, h);
            if (err) {
                sxd_log_err("Failed to build module (%u) map.\n", h);
                goto deinit_map;
            }
        }
    }

    memset(&module_skip_sysfs_arr, 0, sizeof(module_skip_sysfs_arr));
    __get_skip_sysfs_mode_for_modules(module_skip_sysfs_arr, __max_module_num);

    /* for module eeprom sysfs */
    for (i = 0; i < __max_module_num; i++) {
        if (module_skip_sysfs_arr[i]) {
            continue;
        }
        memset(mod_name, 0, sizeof(mod_name));
        sprintf(mod_name, "%s%d", MODULE_NODE_SYSFS_PREFIX, i);
        (*root_arr)[i].module = kobject_create_and_add(mod_name, parent);
        if (!((*root_arr)[i].module)) {
            err = -ENOMEM;
            goto phase1_err;
        }
    }

    for (j = 0; j < __max_module_num; j++) {
        if (module_skip_sysfs_arr[j]) {
            continue;
        }
        err = sx_core_create_module_sysfs_default_eeprom_tree((*root_arr)[j].module,
                                                              &((*root_arr)[j].eeprom_tree));
        if (err) {
            sxd_log_err("module sysfs nodes handler failed to create eeprom sysfs sub-tree.\n");
            err = -ENOMEM;
            goto phase2_err;
        }
    }

    for (k = 0; k < __max_module_num; k++) {
        if (module_skip_sysfs_arr[k]) {
            continue;
        }
        err = sx_core_create_module_sysfs_extension_for_s3ip((*root_arr)[k].module);
        if (err) {
            sxd_log_err("module sysfs nodes handler failed to create s3ip sysfs sub-tree.\n");
            err = -ENOMEM;
            goto phase3_err;
        }
    }

    for (l = 0; l < __max_module_num; l++) {
        if (module_skip_sysfs_arr[l]) {
            continue;
        }
        err = sx_core_create_module_sysfs_extension_for_misc((*root_arr + l));
        if (err) {
            sxd_log_err("module sysfs nodes handler failed to create s3ip sysfs sub-tree.\n");
            err = -ENOMEM;
            goto phase4_err;
        }
    }

    return err;

phase4_err:
    for (; l > 0; l--) {
        if (module_skip_sysfs_arr[l - 1]) {
            continue;
        }
        sx_core_delete_module_sysfs_extension_for_misc((*root_arr + l - 1));
    }

phase3_err:
    for (; k > 0; k--) {
        if (module_skip_sysfs_arr[k - 1]) {
            continue;
        }
        sx_core_delete_module_sysfs_extension_for_s3ip((*root_arr)[k - 1].module);
    }
phase2_err:
    for (; j > 0; j--) {
        if (module_skip_sysfs_arr[j - 1]) {
            continue;
        }
        sx_core_delete_module_sysfs_default_eeprom_tree(&((*root_arr)[j - 1].eeprom_tree));
    }
phase1_err:
    for (; i > 0; i--) {
        if (module_skip_sysfs_arr[i - 1]) {
            continue;
        }
        kobject_put((*root_arr)[i - 1].module);
    }
    kfree(*root_arr);
    *root_arr = NULL;

deinit_map:
    if (sx_core_has_predefined_devices() && MULTI_ASIC_MODULE_SYSFS_IS_SUPPORT(sx_priv(dev))) {
        for (; h > 0; h--) {
            err2 = __deinit_map_of_global_module_and_ga_local_module(dev, h - 1);
            if (err2) {
                sxd_log_err("Failed to deinit global module (%u) map for multi-asic system (device_id: %u).\n",
                            h - 1,
                            dev->device_id);
            }
        }
    } else {
        for (; h > 0; h--) {
            __deinit_module_type_map(dev, h - 1);
        }
    }

out:
    if (sx_priv(dev)->module_log_init == true) {
        sx_internal_log_deinit(&sx_priv(dev)->module_log);
        sx_priv(dev)->module_log_init = false;
    }
    return err;
}

void sx_core_delete_default_modules_sysfs_tree(struct module_sysfs_node **root_arr)
{
    uint8_t i;
    bool    module_skip_sysfs_arr[MAX_MODULE_NUM];

    if (!__max_module_num) {
        return;
    }

    memset(&module_skip_sysfs_arr, 0, sizeof(module_skip_sysfs_arr));
    __get_skip_sysfs_mode_for_modules(module_skip_sysfs_arr, __max_module_num);

    for (i = 0; i < __max_module_num; i++) {
        if (module_skip_sysfs_arr[i]) {
            continue;
        }
        sx_core_delete_module_sysfs_default_eeprom_tree(&((*root_arr)[i].eeprom_tree));
        sx_core_delete_module_sysfs_extension_for_s3ip((*root_arr)[i].module);
        sx_core_delete_module_sysfs_extension_for_misc((*root_arr + i));
        kobject_put((*root_arr)[i].module);
    }
    kfree(*root_arr);
    *root_arr = NULL;

    /* global and local module maps only exist in default module sysfs */
    memset(__global_modules, 0, sizeof(__global_modules));
    memset(__local_modules, 0, sizeof(__local_modules));
    memset(__modules, 0, sizeof(__modules));
}

void sx_core_set_default_modules_sysfs_tree_root(struct module_sysfs_node *root_arr)
{
    __default_module_sysfs_root_arr = root_arr;
}

void sx_core_get_default_modules_sysfs_tree_root(struct module_sysfs_node **root_arr)
{
    if (root_arr) {
        *root_arr = __default_module_sysfs_root_arr;
    }
}

int sx_core_create_independent_modules_sysfs_tree(struct sx_dev *dev, struct module_sysfs_node **root_arr)
{
    int     err = 0;
    uint8_t k;
    bool    module_skip_sysfs_arr[MAX_MODULE_NUM];

    memset(&module_skip_sysfs_arr, 0, sizeof(module_skip_sysfs_arr));
    __get_skip_sysfs_mode_for_modules(module_skip_sysfs_arr, __max_module_num);

    for (k = 0; k < __max_module_num; k++) {
        if (module_skip_sysfs_arr[k]) {
            continue;
        }
        err = sx_core_create_module_sysfs_extension_for_indmod((*root_arr)[k].module);
        if (err) {
            sxd_log_err("module sysfs nodes handler failed to create independent module sysfs sub-tree.\n");
            err = -ENOMEM;
            goto out;
        }
    }

    return err;

out:
    for (; k > 0; k--) {
        if (module_skip_sysfs_arr[k - 1]) {
            continue;
        }
        sx_core_delete_module_sysfs_extension_for_indmod((*root_arr)[k - 1].module);
    }

    return err;
}

void sx_core_delete_independent_modules_sysfs_tree(struct module_sysfs_node **root_arr)
{
    uint8_t i;
    bool    module_skip_sysfs_arr[MAX_MODULE_NUM];

    memset(&module_skip_sysfs_arr, 0, sizeof(module_skip_sysfs_arr));
    __get_skip_sysfs_mode_for_modules(module_skip_sysfs_arr, __max_module_num);

    for (i = 0; i < __max_module_num; i++) {
        if (module_skip_sysfs_arr[i]) {
            continue;
        }
        sx_core_delete_module_sysfs_extension_for_indmod((*root_arr)[i].module);
    }
}


int sx_sysfs_asic_independent_init(struct sx_dev *dev)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);
    uint8_t         i = 0, j = 0;

    priv->independent_module_params.frequency_support = false;
    err = sx_core_create_independent_modules_sysfs_tree(dev,
                                                        &(priv->module_sysfs_arr));
    if (err) {
        goto out;
    }

    for (i = 0; i < MAX_SLOT_NUM; i++) {
        for (j = 0; j < MAX_MODULE_NUM; j++) {
            priv->module_data[i][j].independent_params.hw_present = SX_MODULE_HW_PRESENT_INVALID;
            priv->module_data[i][j].independent_params.interrupt = SX_MODULE_INTERRUPT_INVALID;
            priv->module_data[i][j].independent_params.power_good = SX_MODULE_POWER_GOOD_INVALID;
        }
    }

    err = __read_frequency_support_to_db(dev);
    if (err) {
        sxd_log_notice("Failed to read frequency support, err: %d.\n", err);
        err = 0;
    }


out:
    return err;
}

int sx_sysfs_asic_create(struct sx_dev *dev)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);
    char            object_name[ASIC_NAME_LEN_MAX + 1];
    uint8_t         asic_id = 0;

    if (priv->dev_specific_cb.multi_asic_sysfs_env_init != NULL) {
        err = priv->dev_specific_cb.multi_asic_sysfs_env_init(dev);
        if (err) {
            goto out;
        }
    }

    if (sx_core_has_predefined_devices() && MULTI_ASIC_MODULE_SYSFS_IS_SUPPORT(priv)) {
        err = sx_multi_asic_module_sysfs_map_ga_to_devid(priv->dev_info.dev_info_ro.mgir.hw_info.ga,
                                                         priv->dev.device_id);
        if (err < 0) {
            sxd_log_err("__sx_map_ga_to_sxdev() failed (err=%d)\n", err);
            goto clear_multi_asic_module_map;
        }
    }

    memset(object_name, 0, sizeof(object_name));

    if (sx_core_has_predefined_devices()) {
        asic_id = dev->device_id - 1;
    } else {
        asic_id = 0;
    }

    sprintf(object_name, "%s%d", ASIC_SYSFS_PREFIX, asic_id);

    priv->kobj[SX_KOBJECT_ASIC] = kobject_create_and_add(object_name, &(THIS_MODULE->mkobj.kobj));
    if (priv->kobj[SX_KOBJECT_ASIC] == NULL) {
        sxd_log_err("Failed to create asic sysfs\n");
        err = -ENOMEM;
        goto clear_multi_asic_module_map;
    }
    priv->kobj[SX_KOBJECT_ASIC_TEMP] = kobject_create_and_add("temperature", priv->kobj[SX_KOBJECT_ASIC]);
    if (priv->kobj[SX_KOBJECT_ASIC_TEMP] == NULL) {
        sxd_log_err("Failed to create asic temperature sysfs\n");
        err = -ENOMEM;
        goto temperature_kobj_failed;
    }

    err = sysfs_create_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_highest_attr.attr));
    if (err) {
        sxd_log_err("Failed to create asic temperature sysfs highest attribute\n");
        goto highest_failed;
    }
    err = sysfs_create_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_input_attr.attr));
    if (err) {
        sxd_log_err("Failed to create asic temperature sysfs input attribute\n");
        goto input_failed;
    }
    err = sysfs_create_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_label_attr.attr));
    if (err) {
        sxd_log_err("Failed to create asic temperature sysfs label attribute\n");
        goto label_failed;
    }
    /* ASIC performance counters*/
    priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR] = kobject_create_and_add("performance", priv->kobj[SX_KOBJECT_ASIC]);
    if (priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR] == NULL) {
        sxd_log_err("Failed to create asic performance sysfs\n");
        err = -ENOMEM;
        goto perf_cntr_kobj_failed;
    }

    err = sysfs_create_file(priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR], &(asic_perf_cntr_counters_attr.attr));
    if (err) {
        sxd_log_err("Failed to create asic performance counters sysfs counters attribute\n");
        goto counters_failed;
    }
    err = sysfs_create_file(priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR], &(asic_perf_cntr_interval_attr.attr));
    if (err) {
        sxd_log_err("Failed to create asic performance counters sysfs interval attribute\n");
        goto interval_failed;
    }


    return 0;

interval_failed:
    sysfs_remove_file(priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR], &(asic_perf_cntr_interval_attr.attr));

counters_failed:
    sysfs_remove_file(priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR], &(asic_perf_cntr_counters_attr.attr));

perf_cntr_kobj_failed:
    kobject_put(priv->kobj[SX_KOBJECT_ASIC]);
    sysfs_remove_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_label_attr.attr));
    priv->kobj[SX_KOBJECT_ASIC] = NULL;

label_failed:
    sysfs_remove_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_input_attr.attr));

input_failed:
    sysfs_remove_file(priv->kobj[SX_KOBJECT_ASIC_TEMP], &(asic_temp_highest_attr.attr));

highest_failed:
    kobject_put(priv->kobj[SX_KOBJECT_ASIC_TEMP]);
    priv->kobj[SX_KOBJECT_ASIC_TEMP] = NULL;

temperature_kobj_failed:
    kobject_put(priv->kobj[SX_KOBJECT_ASIC]);
    priv->kobj[SX_KOBJECT_ASIC] = NULL;

clear_multi_asic_module_map:
    if (sx_core_has_predefined_devices() && MULTI_ASIC_MODULE_SYSFS_IS_SUPPORT(priv)) {
        sx_multi_asic_module_unmap_ga_devid(priv->dev_info.dev_info_ro.mgir.hw_info.ga, priv->dev.device_id);
    }

out:
    return err;
}

void sx_sysfs_asic_remove(struct sx_dev *dev)
{
    struct sx_priv *priv = sx_priv(dev);

    if (priv->module_sysfs_arr) {
        if (priv->independent_module_params.module_support_type == SXD_MODULE_MASTER_MODE_SW_CONTROL_E) {
            sx_core_delete_independent_modules_sysfs_tree(&(priv->module_sysfs_arr));
        }

        sx_core_delete_default_modules_sysfs_tree(&(priv->module_sysfs_arr));

        if (sx_priv(dev)->module_log_init == true) {
            sx_internal_log_deinit(&sx_priv(dev)->module_log);
            sx_priv(dev)->module_log_init = false;
        }
    }

    if (priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR]) {
        kobject_put(priv->kobj[SX_KOBJECT_ASIC_PERF_CNTR]);
    }

    if (priv->kobj[SX_KOBJECT_ASIC_TEMP]) {
        kobject_put(priv->kobj[SX_KOBJECT_ASIC_TEMP]);
    }

    if (priv->kobj[SX_KOBJECT_ASIC]) {
        kobject_put(priv->kobj[SX_KOBJECT_ASIC]);
    }
}

static int __init_mtmp(struct sx_dev *dev, uint8_t slot_id, uint16_t sensor_index)
{
    int                       err = 0;
    struct ku_access_mtmp_reg mtmp_reg_data;

    memset(&mtmp_reg_data, 0, sizeof(mtmp_reg_data));
    sx_cmd_set_op_tlv(&mtmp_reg_data.op_tlv, MLXSW_MTMP_ID, EMAD_METHOD_QUERY);
    mtmp_reg_data.dev_id = dev->device_id;
    mtmp_reg_data.mtmp_reg.sensor_index = sensor_index;
    mtmp_reg_data.mtmp_reg.slot_index = slot_id;

    err = sx_ACCESS_REG_MTMP(dev, &mtmp_reg_data);
    if (err) {
        sxd_log_err("Failed to access MTMP, err=%d\n", err);
        goto out;
    }

    if (mtmp_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("Failed to access MTMP, status=%d\n", mtmp_reg_data.op_tlv.status);
        goto out;
    }

    if (mtmp_reg_data.mtmp_reg.mte == 1) {
        goto out;
    }

    sx_cmd_set_op_tlv(&mtmp_reg_data.op_tlv, MLXSW_MTMP_ID, EMAD_METHOD_WRITE);
    mtmp_reg_data.mtmp_reg.mte = 1;
    mtmp_reg_data.mtmp_reg.mtr = 1;

    err = sx_ACCESS_REG_MTMP(dev, &mtmp_reg_data);
    if (err) {
        sxd_log_err("Failed to access MTMP, err=%d\n", err);
        goto out;
    }

    if (mtmp_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("Failed to access MTMP, status=%d\n", mtmp_reg_data.op_tlv.status);
        goto out;
    }

out:
    return err;
}

int sx_sysfs_asic_init_tempeature(struct sx_dev *dev)
{
    int                        err = 0;
    uint32_t                   sensor_idx = 0;
    struct ku_access_mtecr_reg mtecr_reg_data;

    memset(&mtecr_reg_data, 0, sizeof(mtecr_reg_data));
    sx_cmd_set_op_tlv(&mtecr_reg_data.op_tlv, MLXSW_MTECR_ID, EMAD_METHOD_QUERY);
    mtecr_reg_data.dev_id = dev->device_id;
    mtecr_reg_data.mtecr_reg.slot_index = 0;

    err = sx_ACCESS_REG_MTECR(dev, &mtecr_reg_data);
    if (err) {
        sxd_log_err("Failed to access MTECR, err=%d\n", err);
        goto out;
    }

    if (mtecr_reg_data.op_tlv.status) {
        err = -EINVAL;
        sxd_log_err("Failed to access MTECR, status=%d\n", mtecr_reg_data.op_tlv.status);
        goto out;
    }

    err = __init_mtmp(dev, 0, sensor_idx);
    if (err) {
        sxd_log_err("Failed to init MTMP, err=%d\n", err);
        goto out;
    }

out:
    return err;
}

static int __sx_core_get_asic_temperature(struct kobject *kobj, struct sx_temperature_params *params)
{
    int                       ret = 0;
    long                      asic_id = 0;
    sxd_dev_id_t              dev_id = 0;
    struct sx_dev            *dev = NULL;
    struct kobject           *kobj_asic = kobj->parent;
    uint16_t                  temperature = 0;
    struct ku_access_mtbr_reg mtbr_reg_data;

    if (!kobj_asic) {
        sxd_log_err("asic sysfs node is NULL\n");
        ret = -EINVAL;
        goto out;
    }

    ret = kstrtol(kobj_asic->name + strlen(ASIC_SYSFS_PREFIX), 0, &asic_id);
    if (ret) {
        sxd_log_err("Failed to get asic id, err=%d\n", ret);
        goto out;
    }

    if (sx_core_has_predefined_devices()) {
        dev_id = (sxd_dev_id_t)(asic_id + 1);
        dev = sx_dev_db_get_dev_by_id(dev_id);
    } else {
        dev = sx_dev_db_get_default_device();
    }

    if (!dev) {
        sxd_log_err("Failed to get device\n");
        ret = -ENODEV;
        goto out;
    }

    memset(params, 0, sizeof(struct sx_temperature_params));

    memset(&mtbr_reg_data, 0, sizeof(mtbr_reg_data));
    mtbr_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&mtbr_reg_data.op_tlv, MTBR_REG_ID, EMAD_METHOD_QUERY);

    mtbr_reg_data.mtbr_reg.base_sensor_index = 0;
    mtbr_reg_data.mtbr_reg.slot_index = 0;
    mtbr_reg_data.mtbr_reg.num_rec = 1;

    ret = sx_ACCESS_REG_MTBR(dev, &mtbr_reg_data);
    if (ret) {
        sxd_log_err("Failed to access MTBR, err=%d\n", ret);
        goto out;
    }
    if (mtbr_reg_data.op_tlv.status) {
        ret = -EINVAL;
        sxd_log_err("Failed to access MTBR, status=%d\n", mtbr_reg_data.op_tlv.status);
        goto out;
    }

    temperature = mtbr_reg_data.mtbr_reg.temperature_record[0].temperature;
    if ((temperature == 0) || (temperature == SXD_MTBR_NO_CABLE) || (temperature == SXD_MTBR_NO_READ) ||
        (temperature == SXD_MTBR_INVALID_INDEX) || (temperature == SXD_MTBR_READ_FAILED) ||
        (temperature == SXD_MTBR_NO_SENSOR)) {
        ret = -ENODEV;
        sxd_log_debug("Temperature sensing is not supported on asic, status=0x%x\n", temperature);
        goto out;
    }

    params->highest = mtbr_reg_data.mtbr_reg.temperature_record[0].max_temperature;
    params->input = mtbr_reg_data.mtbr_reg.temperature_record[0].temperature;

    sprintf(params->label, "Asic%ld", asic_id);

out:
    return ret;
}

static ssize_t __show_asic_temp_highest(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                          ret = 0;
    struct sx_temperature_params params;
    int                          len = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }


    ret = __sx_core_get_asic_temperature(kobj, &params);
    if (ret) {
        if (ret != -ENODEV) {
            sxd_log_err("Failed to get ASIC temperature highest information\n");
        }
        return ret;
    }

    len = sprintf(buf, "%llu\n", params.highest);

    return len;
}

static ssize_t __show_asic_temp_input(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                          ret = 0;
    struct sx_temperature_params params;
    int                          len = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = __sx_core_get_asic_temperature(kobj, &params);
    if (ret) {
        if (ret != -ENODEV) {
            sxd_log_err("Failed to get ASIC temperature input information\n");
        }
        return ret;
    }

    len = sprintf(buf, "%llu\n", params.input);

    return len;
}

static ssize_t __show_asic_temp_label(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                          ret = 0;
    struct sx_temperature_params params;
    int                          len = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = __sx_core_get_asic_temperature(kobj, &params);
    if (ret) {
        if (ret != -ENODEV) {
            sxd_log_err("Failed to get ASIC temperature label information\n");
        }
        return ret;
    }

    len = sprintf(buf, "%s\n", params.label);

    return len;
}


/*performance counters*/
static int __sx_core_get_asic_perf_cntr_interval(struct kobject *kobj, int *interval)
{
    int             ret = 0;
    struct sx_dev  *dev = NULL;
    struct kobject *kobj_asic = kobj->parent;
    struct sx_priv *priv = NULL;

    ret = sx_core_asic_get_dev(kobj_asic, false, 0, &dev);
    if (ret) {
        sxd_log_err("sysfs entry performance counters got invalid value\n");
        goto out;
    }

    priv = sx_priv(dev);

    *interval = priv->perf_cntr.interval;

out:
    return ret;
}


static int __sx_core_set_asic_perf_cntr_interval(struct kobject *kobj, int interval)
{
    int                         ret = 0;
    struct sx_dev              *dev = NULL;
    struct kobject             *kobj_asic = kobj->parent;
    struct sx_priv             *priv = NULL;
    struct ku_access_mopgcr_reg mopgcr_reg_data;


    ret = sx_core_asic_get_dev(kobj_asic, false, 0, &dev);
    if (ret) {
        sxd_log_err("sysfs entry performance counters got invalid value\n");
        goto out;
    }

    priv = sx_priv(dev);

    priv->perf_cntr.interval = interval;

    memset(&mopgcr_reg_data, 0, sizeof(mopgcr_reg_data));
    mopgcr_reg_data.dev_id = dev->device_id;
    sx_cmd_set_op_tlv(&mopgcr_reg_data.op_tlv, MLXSW_MOPGCR_ID, EMAD_METHOD_WRITE);

    mopgcr_reg_data.mopgcr_reg.perf_cnt_interval = interval;

    ret = sx_ACCESS_REG_MOPGCR(dev, &mopgcr_reg_data);
    if (ret) {
        sxd_log_err("Failed to access MOPGCR, err=%d\n", ret);
        goto out;
    }
    if (mopgcr_reg_data.op_tlv.status) {
        ret = -EINVAL;
        sxd_log_err("Failed to access ,MOPGCR, status=%d\n", mopgcr_reg_data.op_tlv.status);
        goto out;
    }

out:
    return ret;
}

static int __perf_cntr_validate_counter_id(sxd_chip_types_t chip_type, size_t hw_unit_id, size_t counter_id)
{
    int ret = 0;

    switch (chip_type) {
    case SXD_CHIP_TYPE_SPECTRUM:
    case SXD_CHIP_TYPE_SPECTRUM_A1:
        if (counter_id > perf_cntr_max_cntr_id_in_hw_unit_arr_spc1[hw_unit_id]) {
            sxd_log_err("counter_id %lu for hw_unit_id %lu is invalid. The maximum for SPC1 is %lu\n",
                        counter_id, hw_unit_id, perf_cntr_max_cntr_id_in_hw_unit_arr_spc1[hw_unit_id]);
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM2:
        if (counter_id > perf_cntr_max_cntr_id_in_hw_unit_arr_spc2[hw_unit_id]) {
            sxd_log_err("counter_id %lu for hw_unit_id %lu is invalid. The maximum for SPC2 is %lu\n",
                        counter_id, hw_unit_id, perf_cntr_max_cntr_id_in_hw_unit_arr_spc2[hw_unit_id]);
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM3:
        if (counter_id > perf_cntr_max_cntr_id_in_hw_unit_arr_spc3[hw_unit_id]) {
            sxd_log_err("counter_id %lu for hw_unit_id %lu is invalid. The maximum for SPC3 is %lu\n",
                        counter_id, hw_unit_id, perf_cntr_max_cntr_id_in_hw_unit_arr_spc3[hw_unit_id]);
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM4:
        if (counter_id > perf_cntr_max_cntr_id_in_hw_unit_arr_spc4[hw_unit_id]) {
            sxd_log_err("counter_id %lu for hw_unit_id %lu is invalid. The maximum for SPC4 is %lu\n",
                        counter_id, hw_unit_id, perf_cntr_max_cntr_id_in_hw_unit_arr_spc4[hw_unit_id]);
            ret = -EINVAL;
            goto out;
        }
        break;

    default:
        sxd_log_err("chip type %u is unknown \n", chip_type);
        ret = -EINVAL;
        goto out;
    }
out:
    return ret;
}


static int __perf_cntr_validate_hw_unit_id(sxd_chip_types_t chip_type, size_t hw_unit_id)
{
    int ret = 0;


    switch (chip_type) {
    case SXD_CHIP_TYPE_SPECTRUM:
    case SXD_CHIP_TYPE_SPECTRUM_A1:
        if (hw_unit_id >= PERF_CNTR_MAX_HW_UNIT_ID_SPEC1) {
            sxd_log_err("hw_unit_id %lu value is invalid. The maximum for SPC1 is %u\n",
                        hw_unit_id, (PERF_CNTR_MAX_HW_UNIT_ID_SPEC1 - 1));
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM2:
        if (hw_unit_id >= PERF_CNTR_MAX_HW_UNIT_ID_SPEC2) {
            sxd_log_err("hw_unit_id %lu value is invalid. The maximum for SPC2 is %u\n",
                        hw_unit_id, (PERF_CNTR_MAX_HW_UNIT_ID_SPEC2 - 1));
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM3:
        if (hw_unit_id >= PERF_CNTR_MAX_HW_UNIT_ID_SPEC3) {
            sxd_log_err("hw_unit_id %lu value is invalid. The maximum for SPC3 is %u\n",
                        hw_unit_id, (PERF_CNTR_MAX_HW_UNIT_ID_SPEC3 - 1));
            ret = -EINVAL;
            goto out;
        }
        break;

    case SXD_CHIP_TYPE_SPECTRUM4:
        if (hw_unit_id >= PERF_CNTR_MAX_HW_UNIT_ID_SPEC4) {
            sxd_log_err("hw_unit_id %lu value is invalid. The maximum for SPC4 is %u\n",
                        hw_unit_id, (PERF_CNTR_MAX_HW_UNIT_ID_SPEC4 - 1));
            ret = -EINVAL;
            goto out;
        }
        break;

    default:
        sxd_log_err("chip type %u is unknown \n", chip_type);
        ret = -EINVAL;
        goto out;
    }
out:
    return ret;
}


static int __perf_cntr_validate_hw_unit_and_cntr_id(struct kobject  *kobj,
                                                    size_t           hw_unit_id,
                                                    size_t           counter_id,
                                                    sxd_chip_types_t chip_type)
{
    int ret = 0;


    ret = __perf_cntr_validate_hw_unit_id(chip_type, hw_unit_id);
    if (ret) {
        sxd_log_err("Invalid hw_unit_id\n");
        goto out;
    }

    ret = __perf_cntr_validate_counter_id(chip_type, hw_unit_id, counter_id);
    if (ret) {
        sxd_log_err("Invalid counter_id\n");
        goto out;
    }
out:
    return ret;
}

static int __perf_cntr_get_hw_unit_max_counters(sxd_chip_types_t chip_type, int hw_unit_id)
{
    int ret = 0;

    switch (chip_type) {
    case SXD_CHIP_TYPE_SPECTRUM:
    case SXD_CHIP_TYPE_SPECTRUM_A1:
        return perf_cntr_hw_unit_max_cntr_arr_spc1[hw_unit_id];

    case SXD_CHIP_TYPE_SPECTRUM2:
        return perf_cntr_hw_unit_max_cntr_arr_spc2[hw_unit_id];

    case SXD_CHIP_TYPE_SPECTRUM3:
        return perf_cntr_hw_unit_max_cntr_arr_spc3[hw_unit_id];

    case SXD_CHIP_TYPE_SPECTRUM4:
        return perf_cntr_hw_unit_max_cntr_arr_spc4[hw_unit_id];

    default:
        sxd_log_err("chip type %u is unknown \n", chip_type);
        ret = -EINVAL;
        goto out;
    }
out:
    return ret;
}


static struct mopct_node* __perf_cntr_allocate_mopct_node(int hw_unit_id, int counter_id, int group_id)
{
    struct mopct_node *mopct_node = NULL;

    mopct_node = (struct mopct_node*)kmalloc(sizeof(struct  mopct_node), GFP_KERNEL);

    if (mopct_node) {
        INIT_LIST_HEAD(&mopct_node->hw_unit_list);
        INIT_LIST_HEAD(&mopct_node->group_id_list);

        mopct_node->mopct.cnt_grp_id = group_id;
        mopct_node->mopct.enabled_counters[0] = counter_id;
        mopct_node->mopct.force = 0;
        mopct_node->mopct.hw_unit_id = hw_unit_id;
        mopct_node->mopct.num_active_counters = 1;
    }

    return mopct_node;
}


static int __perf_cntr_add_new_mopct_node_to_list(struct sx_perf_cntr *perf_cntr_p, int hw_unit_id, int counter_id)
{
    struct mopct_node *new_mopct_node = NULL;
    int                group_id = 0;
    int                ret = 0;

    if (perf_cntr_p == NULL) {
        ret = -EINVAL;
        goto out;
    }
    /*Need to add new node to the hw_unit_id and the group_id lists */
    group_id = perf_cntr_p->hw_units_arr[hw_unit_id].mopct_in_hw_unit;

    new_mopct_node = __perf_cntr_allocate_mopct_node(hw_unit_id,
                                                     counter_id,
                                                     group_id);
    if (new_mopct_node == NULL) {
        sxd_log_err("Cannot add new performance counters entry.\n");
        ret = -ENOMEM;
        goto out;
    }

    list_add_tail(&new_mopct_node->hw_unit_list, &perf_cntr_p->hw_units_arr[hw_unit_id].mopct_list);
    list_add(&new_mopct_node->group_id_list, &perf_cntr_p->counter_group_arr[group_id].mopct_list);

    perf_cntr_p->counter_group_arr[group_id].mopct_in_group++;
    perf_cntr_p->hw_units_arr[hw_unit_id].mopct_in_hw_unit++;


out:
    return ret;
}


static int __perf_cntr_add_pair_to_counters_db(struct kobject  *kobj,
                                               int              hw_unit_id,
                                               int              counter_id,
                                               sxd_chip_types_t chip_type)
{
    struct sx_dev     *dev = NULL;
    struct kobject    *kobj_asic = kobj->parent;
    struct sx_priv    *priv = NULL;
    struct mopct_node *last_mopct_node = NULL;
    int                hw_unit_max_counters = 0;
    int                ret = 0;


    ret = sx_core_asic_get_dev(kobj_asic, false, 0, &dev);
    if (ret) {
        sxd_log_err("sysfs entry performance counters got invalid value\n");
        goto out;
    }

    priv = sx_priv(dev);

    /* Retrieve the hw_unit_id mopct list
     * If list is empty, add new a mopct node.
     * If list is not empty, we should look at the last mopct node,
     * We check if counters_num <= max_counters_num for the hw_unit_id.
     * If the last node still has a room, add the counter_id to the node.
     * If not, we should generate a new mopct node and add it to the end of the list.
     */
    if (list_empty(&priv->perf_cntr.hw_units_arr[hw_unit_id].mopct_list) == 0) { /* list is not empty*/
        hw_unit_max_counters = __perf_cntr_get_hw_unit_max_counters(chip_type, hw_unit_id);

        last_mopct_node = list_last_entry(&priv->perf_cntr.hw_units_arr[hw_unit_id].mopct_list,
                                          struct mopct_node,
                                          hw_unit_list);
        if (last_mopct_node->mopct.num_active_counters < hw_unit_max_counters) {
            last_mopct_node->mopct.enabled_counters[last_mopct_node->mopct.num_active_counters] = counter_id;
            last_mopct_node->mopct.num_active_counters++;
        } else {
            ret = __perf_cntr_add_new_mopct_node_to_list(&priv->perf_cntr, hw_unit_id, counter_id);
            if (ret) {
                sxd_log_err("failed to add new sysfs entry performance counter\n");
                goto out;
            }
        }
    } else {
        ret = __perf_cntr_add_new_mopct_node_to_list(&priv->perf_cntr, hw_unit_id, counter_id);
        if (ret) {
            sxd_log_err("failed to add new counter_id [0x%x], hw_unit_id [0x%x] for sysfs entry performance counter\n",
                        counter_id,
                        hw_unit_id);
            goto out;
        }
    }

out:
    return ret;
}

char * __sx_sysfs_get_str(char *buffer, char **str, const char* delimiters)
{
    char *running;
    char *token;

    running = buffer;
    token = strsep(&running, delimiters);
    if (token == NULL) {
        *str = 0;
        return NULL;
    }

    *str = token;
    return running;
}


char * __sx_sysfs_get_id_str(char *buffer, char **str)
{
    const char delimiters[] = ":";
    char      *running;

    running = __sx_sysfs_get_str(buffer, str, delimiters);
    return running;
}

char * __sx_sysfs_get_hw_unit_counter_pair_str(char *buffer, char **str)
{
    const char delimiters[] = "\r\n";
    char      *running;

    running = __sx_sysfs_get_str(buffer, str, delimiters);
    return running;
}


static ssize_t __show_asic_perf_cntr_interval(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int ret = 0;
    int interval = 0;
    int len = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue*/
    }

    ret = __sx_core_get_asic_perf_cntr_interval(kobj, &interval);
    if (ret) {
        sxd_log_err("Failed to get module performance counter information\n");
        return ret;
    }

    len = sprintf(buf, "%d\n", interval);

    return len;
}

static ssize_t __store_asic_perf_cntr_interval(struct kobject        *kobj,
                                               struct kobj_attribute *attr,
                                               const char            *buf,
                                               size_t                 len)
{
    int ret = 0;
    int interval = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, buf, len);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue*/
    }

    ret = kstrtoint(buf, 10, &interval);
    if (ret) {
        sxd_log_err("sysfs entry /interval got invalid value %d\n", ret);
        ret = -EINVAL;
        goto out;
    }

    /* Interval valid value is 100usec to 5sec
     * interval units are 100usec*/
    if ((interval < 1) || (interval > 50000)) {
        sxd_log_err("sysfs entry interval value is out of range\n");
        ret = -EINVAL;
        goto out;
    }

    ret = __sx_core_set_asic_perf_cntr_interval(kobj, interval);
    if (ret) {
        sxd_log_err("Failed to get module performance counter information\n");
        goto out;
    }
    return len;

out:
    return ret;
}

static ssize_t __show_asic_perf_cntr_counters(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                ret = 0;
    struct sx_dev     *dev = NULL;
    struct kobject    *kobj_asic = kobj->parent;
    struct sx_priv    *priv = NULL;
    struct mopct_node *iter = NULL;
    int                hw_unit_index = 0;
    int                counter_index = 0;
    ssize_t            len = 0, buf_len = 0;
    char               temp_buf[MAX_COUNTER_FILE_ROW_LEN] = {""};

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue*/
    }
    ret = sx_core_asic_get_dev(kobj_asic, false, 0, &dev);
    if (ret) {
        sxd_log_err("sysfs entry performance counters got invalid value\n");
        return ret;
    }

    priv = sx_priv(dev);

    for (hw_unit_index = 0; hw_unit_index < PERF_CNTR_MAX_HW_UNIT_ID; hw_unit_index++) {
        if (!list_empty(&priv->perf_cntr.hw_units_arr[hw_unit_index].mopct_list)) {
            list_for_each_entry(iter, &priv->perf_cntr.hw_units_arr[hw_unit_index].mopct_list, hw_unit_list){
                for (counter_index = 0; counter_index < (iter->mopct.num_active_counters); counter_index++) {
                    len = snprintf(temp_buf, MAX_COUNTER_FILE_ROW_LEN, "0x%x:0x%x\n",
                                   iter->mopct.hw_unit_id, iter->mopct.enabled_counters[counter_index]);
                    if (len < 0) {
                        sxd_log_err("sysfs entry performance counters internal error. \n");
                        goto out;
                    }


                    if ((buf_len + len) < (SYSFS_MAX_BUFF_LEN - 1)) {
                        strcat(buf, temp_buf);
                        buf_len += len;
                    }
                }
            }
        }
    }
    /*add the null char */
    buf_len++;
out:
    return buf_len;
}

int find_full_path(struct kobject *kobj, char* path_p, const char *file_name, enum sysfs_sniffer_event_type sysfs_type)
{
    int             ret = 0;
    struct kobject *kobj_module = kobj;
    char            path[SXD_SYSFS_FILE_PATH_MAX] = {'\0'};
    char            tmp_path[SXD_SYSFS_FILE_PATH_MAX] = {'\0'};
    char            sysfs_type_prefix[SXD_SYSFS_CB_NAME_MAX] = {'\0'};
    char            sysfs_full_path_prefix[SXD_SYSFS_CB_NAME_MAX] = {'\0'};

    if (!kobj) {
        sxd_log_err("Invalid kobj %s\n", kobject_name(kobj));
        ret = -EINVAL;
        goto out;
    }

    if (!path_p) {
        sxd_log_err("Invalid path pointer\n");
        ret = -EINVAL;
        goto out;
    }

    if (sysfs_type == SYSFS_SX_CORE) {
        strcpy(sysfs_type_prefix, ASIC_SYSFS_PREFIX);
        strcpy(sysfs_full_path_prefix, SYSFS_SX_CORE_FULL_PREFIX);
    } else {
        strcpy(sysfs_type_prefix, NETDEV_PREFIX);
        strcpy(sysfs_full_path_prefix, SYSFS_SX_NETDEV_FULL_PREFIX);
    }

    snprintf(path, SXD_SYSFS_FILE_PATH_MAX, "%s", file_name);

    if (strstr(kobject_name(kobj_module), "synce") == NULL) {
        while (strstr(kobject_name(kobj_module), sysfs_type_prefix) == NULL) {
            sprintf(tmp_path, "%s", kobject_name(kobj_module));
            strcat(tmp_path, "/");
            strcat(tmp_path, path);
            strcpy(path, tmp_path);
            tmp_path[0] = '\0';

            kobj_module = kobj_module->parent;
        }
        sprintf(tmp_path, "%s", kobject_name(kobj_module));
    }

    strcat(tmp_path, "/");
    strcat(tmp_path, path);
    strcpy(path, sysfs_full_path_prefix);
    strcat(path, tmp_path);
    strncpy(path_p, path, SXD_SYSFS_FILE_PATH_MAX);

out:
    return ret;
}


static ssize_t __store_asic_perf_cntr_counters(struct kobject        *kobj,
                                               struct kobj_attribute *attr,
                                               const char            *buf,
                                               size_t                 len)
{
    int              ret = 0;
    struct sx_dev   *dev = NULL;
    char            *running = NULL;
    char            *hw_unit_counter_id_pair = NULL;
    char            *token = NULL;
    size_t           hw_unit_id = 0;
    size_t           counter_id = 0;
    struct kobject  *kobj_asic = kobj->parent;
    struct sx_priv  *priv = NULL;
    sxd_chip_types_t chip_type = SXD_CHIP_TYPE_UNKNOWN;
    size_t           buff_parsed_len = 0;

    ret = sx_core_send_sniffer_event(kobj, __FUNCTION__, attr->attr.name, buf, len);
    if (ret) {
        sxd_log_err("sx_core_send_sniffer_event from sysfs entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue*/
    }

    ret = sx_core_asic_get_dev(kobj_asic, false, 0, &dev);
    if (ret) {
        sxd_log_err("sysfs entry performance counters got invalid value\n");
        goto out;
    }

    priv = sx_priv(dev);
    chip_type = priv->dev_info.dev_info_ro.chip_type;

    running = (char*)buf;

    /* Parse the counters file and store in DB. The DB is array of linked lists.
     * The counter file holds a list of <hw_unit_id : counter_id>.
     * Each element in the DB array is a head of a hw_unit list.
     * The index to the DB array is the hw_unit_id.
     * Each hw_unit list builds up from MOPCT registers that stores the counters of the hw_unit_id.
     * Every node in the lists is ku_mopct_reg.
     * Every time the user opens the counters file, the DB is initialize with the new counter file content.
     */
    sx_asic_perf_counter_deinit(dev);
    sx_asic_perf_counter_init(dev);

    while (*running) {
        if (buff_parsed_len >= (len - 1)) {
            sxd_log_notice("Reached end of counters file buffer. %ld \n", (len - 1));
            goto out;
        }
        running = __sx_sysfs_get_hw_unit_counter_pair_str(running, &hw_unit_counter_id_pair);
        buff_parsed_len += strlen(hw_unit_counter_id_pair); /*the hw_unit_id:counter_id length + \n . */
        buff_parsed_len++;
        sxd_log_notice("buff_parsed_len: %ld, hw_unit_counter_id_pair %s\n",
                       buff_parsed_len, hw_unit_counter_id_pair);

        hw_unit_counter_id_pair = __sx_sysfs_get_id_str(hw_unit_counter_id_pair, &token);
        ret = kstrtol(token, 0, &hw_unit_id);
        if (ret) {
            sxd_log_err("Failed to get hw unit id, err=%d, token: %s\n", ret, token);
            ret = -EINVAL;
            goto out;
        }
        hw_unit_counter_id_pair = __sx_sysfs_get_id_str(hw_unit_counter_id_pair, &token);
        ret = kstrtol(token, 0, &counter_id);
        if (ret) {
            sxd_log_err("Failed to get counter id, err=%d, token: %s\n", ret, token);
            ret = -EINVAL;
            goto out;
        }

        ret = __perf_cntr_validate_hw_unit_and_cntr_id(kobj, hw_unit_id, counter_id, chip_type);
        if (ret) {
            sxd_log_err("counter_id [0x%lx] or hw_unit_id [0x%lx] value is invalid and will be ignored.\n",
                        counter_id, hw_unit_id);
            continue;
        }
        ret = __perf_cntr_add_pair_to_counters_db(kobj, hw_unit_id, counter_id, chip_type);
        if (ret != 0) {
            sxd_log_err("Failed to process counter_id [0x%lx], hw_unit_id [0x%lx].\n",
                        counter_id, hw_unit_id);
            goto out;
        }
    }

out:
    return len;
}


int sx_sysfs_asic_perf_cntr_counters_db_groups_num_get(struct sx_dev *dev, size_t *perf_counter_groups_max)
{
    int             ret = 0;
    struct sx_priv *priv = NULL;
    int             i = 0;

    priv = sx_priv(dev);

    for (i = 0; i < PERF_CNTR_MAX_GROUP_ID; i++) {
        if (priv->perf_cntr.counter_group_arr[i].mopct_in_group == 0) {
            /*search for the first empty group. */
            *perf_counter_groups_max = i;
            break;
        }
    }
    return ret;
}
EXPORT_SYMBOL(sx_sysfs_asic_perf_cntr_counters_db_groups_num_get);

int sx_sysfs_asic_perf_cntr_counters_db_get(struct sx_dev *dev, const struct group_id_counters_list **counters_bank)
{
    int             ret = 0;
    struct sx_priv *priv = NULL;

    priv = sx_priv(dev);

    *counters_bank = priv->perf_cntr.counter_group_arr;

    return ret;
}
EXPORT_SYMBOL(sx_sysfs_asic_perf_cntr_counters_db_get);

ssize_t sx_asic_perf_counter_init(struct sx_dev *dev)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);
    int             i = 0;

    for (i = 0; i < PERF_CNTR_MAX_HW_UNIT_ID; i++) {
        INIT_LIST_HEAD(&priv->perf_cntr.hw_units_arr[i].mopct_list);
        priv->perf_cntr.hw_units_arr[i].mopct_in_hw_unit = 0;
    }

    for (i = 0; i < PERF_CNTR_MAX_GROUP_ID; i++) {
        INIT_LIST_HEAD(&priv->perf_cntr.counter_group_arr[i].mopct_list);
        priv->perf_cntr.counter_group_arr[i].mopct_in_group = 0;
    }

    return err;
}

void sx_asic_perf_counter_deinit(struct sx_dev *dev)
{
    struct sx_priv    *priv = sx_priv(dev);
    int                i = 0;
    struct mopct_node *iter, *tmp;

    for (i = 0; i < PERF_CNTR_MAX_HW_UNIT_ID; i++) {
        list_for_each_entry_safe(iter, tmp, &priv->perf_cntr.hw_units_arr[i].mopct_list, hw_unit_list) {
            list_del(&iter->hw_unit_list);
            /* We don't free the allocation here because hw_unit_list and group_id_list are pointing to the same allocation*/
        }
    }

    for (i = 0; i < PERF_CNTR_MAX_GROUP_ID; i++) {
        list_for_each_entry_safe(iter, tmp, &priv->perf_cntr.counter_group_arr[i].mopct_list, group_id_list) {
            list_del(&iter->group_id_list);
            kfree(iter);
        }
    }

    return;
}


int send_sysfs_common_sniffer_event(struct kobject               *kobj,
                                    struct sx_dev                *dev,
                                    const char                   *cb_name,
                                    const char                   *file_name,
                                    const char                   *buf,
                                    size_t                        size,
                                    enum sysfs_sniffer_event_type sysfs_type)
{
    int                                      ret = 0;
    struct sx_timeval                        now;
    sxd_sysfs_access_sniffer_notification_t *sysfs_access_sniff_p = NULL;
    int                                      sniff_struct_len = sizeof(sxd_sysfs_access_sniffer_notification_t);
    struct sx_priv                          *priv = NULL;

    priv = sx_priv(dev);

    if (priv->sniffer_enable == false) {
        goto out;
    }

    if ((!priv->sniffer_read_enable) && (size == 0)) {
        goto out;
    }

    if (((size > 0) && (buf == NULL)) || ((size == 0) && (buf != NULL))) {
        sxd_log_err("sysfs entry %s failed to send sys sniffer event. Invalid buffer value\n", cb_name);
        ret = -EINVAL;
        goto out;
    } else {
        sniff_struct_len += size;
    }

    sysfs_access_sniff_p = (sxd_sysfs_access_sniffer_notification_t*)kzalloc(sniff_struct_len + 1, GFP_KERNEL);
    if (!sysfs_access_sniff_p) {
        sxd_log_err("module sysfs, sx_core_send_sniffer_event() failed to allocated memory.\n");
        ret = -ENOMEM;
        goto out;
    }

    ret = find_full_path(kobj, sysfs_access_sniff_p->file_path, file_name, sysfs_type);
    if (ret) {
        sxd_log_err("find_full_path faild for cb %s, ret [%d]\n", cb_name, ret);
        goto out;
    }

    sysfs_access_sniff_p->device_id = dev->device_id;
    strncpy(sysfs_access_sniff_p->func_name, cb_name, SXD_SYSFS_CB_NAME_MAX);
    sysfs_access_sniff_p->len = size;

    if (size > 0) {
        memcpy(sysfs_access_sniff_p->buf, buf, size);
    }
    sysfs_access_sniff_p->buf[size] = '\0';

    sx_dbg_get_time(&now);
    sysfs_access_sniff_p->timestamp.tv_sec = now.t.tv_sec;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
    sysfs_access_sniff_p->timestamp.tv_nsec = now.t.tv_nsec;
#else
    sysfs_access_sniff_p->timestamp.tv_nsec = 1000 * now.t.tv_usec;
#endif

    sxd_log_debug(
        "Sending sysfs access notification [dev=%u, cb_name=%s, path=%s, total len = %d, write_buf_len = %d, buf = %s]\n",
        sysfs_access_sniff_p->device_id,
        sysfs_access_sniff_p->func_name,
        sysfs_access_sniff_p->file_path,
        sniff_struct_len,
        sysfs_access_sniff_p->len,
        sysfs_access_sniff_p->buf);

    ret = send_trap(sysfs_access_sniff_p,
                    sniff_struct_len,
                    SXD_TRAP_ID_SYSFS_SNIFFER,
                    0,
                    dev->device_id,
                    TARGET_PID_DONT_CARE,
                    GFP_KERNEL);
    if (ret) {
        sxd_log_err("send_trap failed for cb %s, ret [%d]\n", cb_name, ret);
        goto out;
    }

out:
    if (sysfs_access_sniff_p) {
        kfree(sysfs_access_sniff_p);
    }

    return ret;
}
EXPORT_SYMBOL(send_sysfs_common_sniffer_event);


int sx_core_send_sniffer_event(struct kobject *kobj,
                               const char     *cb_name,
                               const char     *file_name,
                               const char     *buf,
                               size_t          size)
{
    int             ret = 0;
    struct sx_dev  *dev = NULL;
    struct kobject *kobj_parent = kobj->parent;

    if (strstr(kobject_name(kobj), "synce") != NULL) {
        dev = sx_dev_db_get_default_device();
    } else {
        if (!kobj_parent) {
            sxd_log_err("sx_core_send_sniffer_event: Invalid kobj %s\n", kobject_name(kobj));
            ret = -EINVAL;
            goto out;
        }

        while (strstr(kobject_name(kobj_parent), ASIC_SYSFS_PREFIX) == NULL) {
            kobj_parent = kobj_parent->parent;
        }

        ret = sx_core_asic_get_dev(kobj_parent, false, 0, &dev);
        if (ret) {
            sxd_log_err("sysfs entry %s failed to find device. Invalid value\n", cb_name);
            ret = -EINVAL;
            goto out;
        }
    }

    ret = send_sysfs_common_sniffer_event(kobj, dev, cb_name, file_name, buf, size, SYSFS_SX_CORE);
    if (ret) {
        sxd_log_err("send_sniffer_event for %s failed.\n", cb_name);
        ret = -EINVAL;
        goto out;
    }

out:

    return ret;
}
