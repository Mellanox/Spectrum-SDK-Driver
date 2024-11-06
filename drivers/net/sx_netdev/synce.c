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

#include <linux/mlx_sx/driver.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/auto_registers/reg.h>
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include "sx_netdev.h"

enum {
    SX_MSEES_FIELD_SELECT_ENABLE             = 0x1 << 0,
    SX_MSEES_FIELD_SELECT_ADMIN_STATUS       = 0x1 << 1,
    SX_MSEES_FIELD_SELECT_ADMIN_FREQ_MEASURE = 0x1 << 2,
};

enum {
    SX_MSEES_OPER_STATUS_FREE_RUNNING                = 0,
    SX_MSEES_OPER_STATUS_SELF_TRACK                  = 1,
    SX_MSEES_OPER_STATUS_OTHER_TRACK                 = 2,
    SX_MSEES_OPER_STATUS_HAND_OVER                   = 3,
    SX_MSEES_OPER_STATUS_HAND_OVER_DUE_TO_FAILURE    = 4,
    SX_MSEES_OPER_STATUS_FREE_RUNNING_DUE_TO_FAILURE = 5,
};

static ssize_t __show_synce_admin_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __store_synce_admin_status(struct kobject        *kobj,
                                          struct kobj_attribute *attr,
                                          const char            *buf,
                                          size_t                 len);
static ssize_t __show_synce_admin_freq_measure(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __store_synce_admin_freq_measure(struct kobject        *kobj,
                                                struct kobj_attribute *attr,
                                                const char            *buf,
                                                size_t                 len);
static ssize_t __show_synce_oper_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_synce_oper_freq_measure(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_synce_ho_acq(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_synce_freq_diff(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t __show_synce_failure_reason(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static struct kobj_attribute admin_status_attr = __ATTR(synce_admin_status,
                                                        (S_IRUGO | S_IWUSR),
                                                        __show_synce_admin_status,
                                                        __store_synce_admin_status);
static struct kobj_attribute admin_freq_measure_attr = __ATTR(synce_admin_freq_measure,
                                                              (S_IRUGO | S_IWUSR),
                                                              __show_synce_admin_freq_measure,
                                                              __store_synce_admin_freq_measure);
static struct kobj_attribute oper_status_attr = __ATTR(synce_oper_status,
                                                       S_IRUGO,
                                                       __show_synce_oper_status,
                                                       NULL);
static struct kobj_attribute oper_freq_measure_attr = __ATTR(synce_oper_freq_measure,
                                                             S_IRUGO,
                                                             __show_synce_oper_freq_measure,
                                                             NULL);
static struct kobj_attribute ho_acq_attr = __ATTR(synce_ho_acq,
                                                  S_IRUGO,
                                                  __show_synce_ho_acq,
                                                  NULL);
static struct kobj_attribute freq_diff_attr = __ATTR(synce_freq_diff,
                                                     S_IRUGO,
                                                     __show_synce_freq_diff,
                                                     NULL);
static struct kobj_attribute failure_reason_attr = __ATTR(synce_failure_reason,
                                                          S_IRUGO,
                                                          __show_synce_failure_reason,
                                                          NULL);

static struct attribute* synce_attrs[] = {
    &admin_status_attr.attr,
    &admin_freq_measure_attr.attr,
    &oper_status_attr.attr,
    &oper_freq_measure_attr.attr,
    &ho_acq_attr.attr,
    &freq_diff_attr.attr,
    &failure_reason_attr.attr,
};

static inline bool __is_oper_status_failure(int oper_status)
{
    switch (oper_status) {
    case SX_MSEES_OPER_STATUS_HAND_OVER_DUE_TO_FAILURE:
    case SX_MSEES_OPER_STATUS_FREE_RUNNING_DUE_TO_FAILURE:
        return true;

    default:
        return false;
    }
}

/* must be called from the context of sx_netdev_sysfs_handler_start() */
static int __get_msees(struct net_device *netdev, struct ku_access_msees_reg *msees_reg)
{
    int                       err = 0;
    struct sx_net_priv       *priv = netdev_priv(netdev);
    struct ku_access_mspi_reg mspi_reg;

    memset(&mspi_reg, 0, sizeof(mspi_reg));
    mspi_reg.dev_id = priv->dev->device_id;
    CALL_SX_CORE_FUNC_WITHOUT_RET(sx_cmd_set_op_tlv, &mspi_reg.op_tlv, MLXSW_MSPI_ID, EMAD_METHOD_QUERY);
    CALL_SX_CORE_FUNC_WITH_RET(sx_ACCESS_REG_MSPI, err, priv->dev, &mspi_reg);
    if (err) {
        goto out;
    }

    if (!mspi_reg.mspi_reg.synce_support) {
        err = -EOPNOTSUPP;
        goto out;
    }

    memset(msees_reg, 0, sizeof(*msees_reg));
    msees_reg->dev_id = priv->dev->device_id;
    CALL_SX_CORE_FUNC_WITHOUT_RET(sx_cmd_set_op_tlv, &msees_reg->op_tlv, MLXSW_MSEES_ID, EMAD_METHOD_QUERY);
    SX_PORT_EXTRACT_LSB_MSB_FROM_PHY_ID(msees_reg->msees_reg.local_port,
                                        msees_reg->msees_reg.lp_msb,
                                        priv->port);
    msees_reg->msees_reg.pnat = SXD_PDDR_PNAT_LOCAL_PORT_NUMBER_E;
    CALL_SX_CORE_FUNC_WITH_RET(sx_ACCESS_REG_MSEES, err, priv->dev, msees_reg);
    if (err) {
        goto out;
    }

out:
    return err;
}

static int __set_msees(struct kobject *kobj, u32 field_select, u8 val)
{
    int                        err;
    struct net_device         *netdev = NULL;
    struct sx_net_priv        *priv;
    struct ku_access_msees_reg msees_reg;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    priv = netdev_priv(netdev);
    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    switch (field_select) {
    case SX_MSEES_FIELD_SELECT_ADMIN_STATUS:
        msees_reg.msees_reg.field_select = SX_MSEES_FIELD_SELECT_ENABLE | field_select;
        msees_reg.msees_reg.admin_status = !!val;
        break;

    case SX_MSEES_FIELD_SELECT_ADMIN_FREQ_MEASURE:
        msees_reg.msees_reg.field_select = SX_MSEES_FIELD_SELECT_ENABLE | field_select;
        msees_reg.msees_reg.admin_freq_measure = !!val;
        break;

    default:
        err = -EINVAL;
        goto out;
    }

    CALL_SX_CORE_FUNC_WITHOUT_RET(sx_cmd_set_op_tlv, &msees_reg.op_tlv, MLXSW_MSEES_ID, EMAD_METHOD_WRITE);
    CALL_SX_CORE_FUNC_WITH_RET(sx_ACCESS_REG_MSEES, err, priv->dev, &msees_reg);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return err;
}

static ssize_t __show_synce_admin_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.admin_status);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __store_synce_admin_status(struct kobject        *kobj,
                                          struct kobj_attribute *attr,
                                          const char            *buf,
                                          size_t                 len)
{
    int err;
    u8  val;


    /*err = send_netdev_sniffer_event(kobj, __FUNCTION__, attr->attr.name, buf, len, SX_NET_KOBJECT_PORT);
     *  if (err) {
     *   sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, err);
     *   err = 0;
     *  }
     */

    err = kstrtou8(buf, 0, &val);
    if (err) {
        return err;
    }

    err = __set_msees(kobj, SX_MSEES_FIELD_SELECT_ADMIN_STATUS, val);
    if (err) {
        return err;
    }

    return len;
}
static ssize_t __show_synce_admin_freq_measure(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.admin_freq_measure);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __store_synce_admin_freq_measure(struct kobject        *kobj,
                                                struct kobj_attribute *attr,
                                                const char            *buf,
                                                size_t                 len)
{
    int err;
    u8  val;

    /*err = send_netdev_sniffer_event(kobj, __FUNCTION__, attr->attr.name, buf, len, SX_NET_KOBJECT_PORT);
     *  if (err) {
     *   sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, err);
     *   err = 0;
     *  }
     */

    err = kstrtou8(buf, 0, &val);
    if (err) {
        return err;
    }

    err = __set_msees(kobj, SX_MSEES_FIELD_SELECT_ADMIN_FREQ_MEASURE, val);
    if (err) {
        return err;
    }

    return len;
}

static ssize_t __show_synce_oper_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.oper_status);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __show_synce_oper_freq_measure(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.oper_freq_measure);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __show_synce_ho_acq(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.ho_acq);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __show_synce_freq_diff(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    if (!msees_reg.msees_reg.oper_freq_measure) {
        err = -ENODATA;
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.frequency_diff);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

static ssize_t __show_synce_failure_reason(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                        err = 0, len = 0;
    struct ku_access_msees_reg msees_reg;
    struct net_device         *netdev = NULL;

    err = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_PORT, &netdev);
    if (err) {
        return err;
    }

    err = __get_msees(netdev, &msees_reg);
    if (err) {
        goto out;
    }

    if (!__is_oper_status_failure(msees_reg.msees_reg.oper_status)) {
        err = -ENODATA;
        goto out;
    }

    len = sprintf(buf, "%u\n", msees_reg.msees_reg.failure_reason);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (err) ? err : len;
}

int sx_netdev_synce_sysfs_init(struct kobject *kobj)
{
    int err;
    int i;

    for (i = 0; i < ARRAY_SIZE(synce_attrs); i++) {
        err = sysfs_create_file(kobj, synce_attrs[i]);
        if (err) {
            goto err_sysfs_create_file;
        }
    }
    return 0;

err_sysfs_create_file:
    for (i--; i >= 0; i--) {
        sysfs_remove_file(kobj, synce_attrs[i]);
    }
    return err;
}

void sx_netdev_synce_sysfs_deinit(struct kobject *kobj)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(synce_attrs); i++) {
        sysfs_remove_file(kobj, synce_attrs[i]);
    }
}
