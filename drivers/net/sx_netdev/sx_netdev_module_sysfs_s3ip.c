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

#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <net/addrconf.h>
#include <linux/vmalloc.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/device.h>
#include <linux/mlx_sx/driver.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/kernel_user.h>

#include "sx_netdev.h"

static ssize_t show_module_power_on(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t store_module_power_on(struct kobject        *kobj,
                                     struct kobj_attribute *attr,
                                     const char            *buf,
                                     size_t                 len);
static ssize_t show_module_tx_disable(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t store_module_tx_disable(struct kobject        *kobj,
                                       struct kobj_attribute *attr,
                                       const char            *buf,
                                       size_t                 len);
static ssize_t show_module_present(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t show_module_rx_los(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t show_module_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t show_module_error_type(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

static struct kobj_attribute module_power_on_attr = __ATTR(power_on,
                                                           (S_IRUGO | S_IWUSR),
                                                           show_module_power_on,
                                                           store_module_power_on);
static struct kobj_attribute module_tx_disable_attr = __ATTR(tx_disable,
                                                             (S_IRUGO | S_IWUSR),
                                                             show_module_tx_disable,
                                                             store_module_tx_disable);
static struct kobj_attribute module_present_attr = __ATTR(present, S_IRUGO, show_module_present, NULL);
static struct kobj_attribute module_rx_los_attr = __ATTR(rx_los, S_IRUGO, show_module_rx_los, NULL);
static struct kobj_attribute module_status_attr = __ATTR(status, S_IRUGO, show_module_status, NULL);
static struct kobj_attribute module_error_type_attr = __ATTR(statuserror, S_IRUGO, show_module_error_type, NULL);

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_get_power_on(struct net_device *dev, bool *power_on)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_get_port_module_power_on, ret, net_priv->dev, net_priv->port, power_on);
    return ret;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_power_on_off(struct net_device *dev, bool power_on)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_power_on_off_port_module, ret, net_priv->dev, net_priv->port, power_on);
    return ret;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_status_get(struct net_device *dev, struct sx_module_status_params *params)
{
    int                 ret = 0;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_get_port_module_status, ret, net_priv->dev, net_priv->port, params);
    return ret;
}

static ssize_t show_module_power_on(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                ret = 0;
    struct net_device *netdev = NULL;
    bool               power_on = false;
    int                len = 0;
    int                val = 0;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = sx_netdev_module_get_power_on(netdev, &power_on);
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_get_power_on\n");
        goto out;
    }

    if (power_on) {
        val = 1;
    }

    len = sprintf(buf, "%d\n", val);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}


static ssize_t store_module_power_on(struct kobject        *kobj,
                                     struct kobj_attribute *attr,
                                     const char            *buf,
                                     size_t                 len)
{
    int                ret = 0;
    int                power_on = 0;
    struct net_device *netdev = NULL;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, buf, len);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = kstrtoint(buf, 10, &power_on);
    if (ret) {
        sxd_log_err("sysfs entry power_on got invalid value\n");
        ret = -EINVAL;
        goto out;
    }

    if ((power_on != SX_MODULE_POWER_ON) &&
        (power_on != SX_MODULE_POWER_OFF)) {
        sxd_log_err("sysfs entry power_on got invalid value\n");
        ret = -EINVAL;
        goto out;
    }

    if (!kobj->parent) {
        sxd_log_err("Parent of power_on sysfs node is NULL\n");
        ret = -EINVAL;
        goto out;
    }

    ret = sx_netdev_module_power_on_off(netdev, (power_on == SX_MODULE_POWER_ON));
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_power_on_off, ret %d\n", ret);
        goto out;
    }

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_get_tx_disable(struct net_device *dev, bool *tx_disable)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_get_port_module_tx_disable, ret, net_priv->dev, net_priv->port, tx_disable);
    return ret;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_tx_disable(struct net_device *dev, bool tx_disable)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_set_port_module_tx_disable, ret, net_priv->dev, net_priv->port, tx_disable);
    return ret;
}

static ssize_t show_module_tx_disable(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                ret = 0;
    struct net_device *netdev = NULL;
    bool               tx_disable = false;
    int                len = 0;
    int                val = 0;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = sx_netdev_module_get_tx_disable(netdev, &tx_disable);
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_get_power_on\n");
        goto out;
    }

    if (tx_disable) {
        val = 1;
    }

    len = sprintf(buf, "%d\n", val);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

static ssize_t store_module_tx_disable(struct kobject        *kobj,
                                       struct kobj_attribute *attr,
                                       const char            *buf,
                                       size_t                 len)
{
    int                ret = 0;
    int                tx_disable = 0;
    struct net_device *netdev = NULL;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, buf, len);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = kstrtoint(buf, 10, &tx_disable);
    if (ret) {
        sxd_log_err("sysfs entry tx_disable got invalid value\n");
        ret = -EINVAL;
        goto out;
    }

    if ((tx_disable != SX_MODULE_TX_DEFAULT) &&
        (tx_disable != SX_MODULE_TX_DISABLE)) {
        sxd_log_err("sysfs entry tx_disable got invalid value\n");
        ret = -EINVAL;
        goto out;
    }

    if (!kobj->parent) {
        sxd_log_err("Parent of tx_disable sysfs node is NULL\n");
        ret = -EINVAL;
        goto out;
    }

    ret = sx_netdev_module_tx_disable(netdev, (tx_disable == SX_MODULE_TX_DISABLE));
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_tx_disable\n");
        goto out;
    }

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_module_get_present(struct net_device *dev, enum sx_oper_module_present_state *present)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_get_port_module_present, ret, net_priv->dev, net_priv->port, present);
    return ret;
}

static ssize_t show_module_present(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                               ret = 0;
    struct net_device                *netdev = NULL;
    enum sx_oper_module_present_state present = SX_OPER_MODULE_NOT_PRESENT;
    int                               len = 0;
    int                               val = 0;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    ret = sx_netdev_module_get_present(netdev, &present);
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_get_present\n");
        goto out;
    }

    if (present == SX_OPER_MODULE_PRESENT) {
        val = 1;
    } else if (present == SX_OPER_MODULE_PRESENT_ERROR) {
        val = 2;
    }

    len = sprintf(buf, "%d\n", val);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

/* must be called within the context of sx_netdev_sysfs_handler_start() */
static int sx_netdev_get_rx_los(struct net_device *dev, bool *rx_los)
{
    int                 ret;
    struct sx_net_priv *net_priv = netdev_priv(dev);

    if (!net_priv->is_port_netdev || net_priv->is_lag) {
        return -ENODATA;
    }

    CALL_SX_CORE_FUNC_WITH_RET(sx_core_get_port_module_rx_los, ret, net_priv->dev, net_priv->port, rx_los);
    return ret;
}

static ssize_t show_module_rx_los(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                           ret = 0;
    struct net_device            *netdev = NULL;
    struct sx_link_ext_state_info link_ext_state_info;
    int                           len = 0;
    bool                          rx_los = false;
    int                           val = 0;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    memset(&link_ext_state_info, 0, sizeof(link_ext_state_info));
    ret = sx_netdev_get_rx_los(netdev, &rx_los);
    if (ret) {
        sxd_log_err("Cannot get state info in sx_netdev_get_rx_los (ret:%d)\n", ret);
        goto out;
    }

    if (rx_los) {
        val = 1;
    }

    len = sprintf(buf, "%d\n", val);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

static ssize_t show_module_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                            ret = 0;
    struct net_device             *netdev = NULL;
    int                            len = 0;
    struct sx_module_status_params params;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    memset(&params, 0, sizeof(params));
    ret = sx_netdev_module_status_get(netdev, &params);
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_status_get\n");
        goto out;
    }

    len = sprintf(buf, "%d\n", params.status);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

static ssize_t show_module_error_type(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    int                            ret = 0;
    struct net_device             *netdev = NULL;
    int                            len = 0;
    struct sx_module_status_params params;

    ret = sx_netdev_sysfs_handler_start(kobj, SX_NET_KOBJECT_MODULE, &netdev);
    if (ret) {
        return ret;
    }

    ret = send_netdev_sniffer_event(netdev, kobj, __FUNCTION__, attr->attr.name, NULL, 0);
    if (ret) {
        sxd_log_err("send_netdev_sniffer_event from sysfs netdev entry %s failed [%d]\n", __FUNCTION__, ret);
        ret = 0;
        /*continue */
    }

    memset(&params, 0, sizeof(params));
    ret = sx_netdev_module_status_get(netdev, &params);
    if (ret) {
        sxd_log_err("Failed in sx_netdev_module_status_get\n");
        goto out;
    }

    len = sprintf(buf, "%d\n", params.error_type);

out:
    sx_netdev_sysfs_handler_end(netdev);
    return (ret) ? ret : len;
}

int sx_netdev_create_module_sysfs_extension_for_s3ip(struct kobject *parent)
{
    int err = 0;

    err = sysfs_create_file(parent, &(module_power_on_attr.attr));
    if (err) {
        goto out;
    }

    err = sysfs_create_file(parent, &(module_tx_disable_attr.attr));
    if (err) {
        goto phase1_err;
    }
    err = sysfs_create_file(parent, &(module_present_attr.attr));
    if (err) {
        goto phase2_err;
    }
    err = sysfs_create_file(parent, &(module_rx_los_attr.attr));
    if (err) {
        goto phase3_err;
    }
    err = sysfs_create_file(parent, &(module_status_attr.attr));
    if (err) {
        goto phase4_err;
    }
    err = sysfs_create_file(parent, &(module_error_type_attr.attr));
    if (err) {
        goto phase5_err;
    }

    return err;

phase5_err:
    sysfs_remove_file(parent, &(module_status_attr.attr));
phase4_err:
    sysfs_remove_file(parent, &(module_rx_los_attr.attr));
phase3_err:
    sysfs_remove_file(parent, &(module_present_attr.attr));
phase2_err:
    sysfs_remove_file(parent, &(module_tx_disable_attr.attr));
phase1_err:
    sysfs_remove_file(parent, &(module_power_on_attr.attr));
out:
    return err;
}

void sx_netdev_delete_module_sysfs_extension_for_s3ip(struct kobject *parent)
{
    sysfs_remove_file(parent, &(module_power_on_attr.attr));
    sysfs_remove_file(parent, &(module_rx_los_attr.attr));
    sysfs_remove_file(parent, &(module_present_attr.attr));
    sysfs_remove_file(parent, &(module_tx_disable_attr.attr));
    sysfs_remove_file(parent, &(module_status_attr.attr));
    sysfs_remove_file(parent, &(module_error_type_attr.attr));
}
