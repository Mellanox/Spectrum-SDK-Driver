/*
 * Copyright (C) 2010-2024 NVIDIA CORPORATION & AFFILIATES, Ltd. ALL RIGHTS RESERVED.
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
#include <linux/version.h>
#include <linux/init.h>
#include <linux/errno.h>
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
#include <linux/vmalloc.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/rtnetlink.h>

#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/device.h>
#include <linux/mlx_sx/driver.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/kernel_user.h>
#include "sx_netdev.h"

extern struct sx_core_interface sx_core_if;

static void sx_bridge_setup(struct net_device *dev)
{
    struct sx_net_priv *net_priv = netdev_priv(dev);

    sxd_log_info("%s: called\n", __func__);

    memset(net_priv, 0, sizeof(*net_priv));
    ether_setup(dev);
    dev->hard_header_len = ETH_HLEN + ISX_HDR_SIZE;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
    dev->max_mtu = 0; /* do not limit the max MTU */
    dev->needs_free_netdev = true;
#endif
    net_priv->netdev = dev;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
static int sx_bridge_validate(struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
#else
static int sx_bridge_validate(struct nlattr *tb[], struct nlattr *data[])
#endif
{
    __u16 id;

    sxd_log_info("%s: called\n", __func__);

    if (tb[IFLA_ADDRESS]) {
        if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN) {
            sxd_log_debug("invalid link address (not ethernet)\n");
            return -EINVAL;
        }

        if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS]))) {
            sxd_log_debug("invalid all zero ethernet address\n");
            return -EADDRNOTAVAIL;
        }
    }

    if (!data) {
        sxd_log_info("%s: Data invalid\n", __func__);
        return -EINVAL;
    }

    if (!data[IFLA_SX_BRIDGE_ID]) {
        sxd_log_info("%s: bridge doesn't exists\n", __func__);
        return -EINVAL;
    }

    id = nla_get_u16(data[IFLA_SX_BRIDGE_ID]);
    if ((id > MAX_BRIDGE_ID) || (id < MIN_BRIDGE_ID)) {
        sxd_log_info("%s: BRIDGE is out of range - %d\n", __func__, id);
        return -ERANGE;
    }

    sxd_log_info("%s: exit\n", __func__);
    return 0;
}

static size_t sx_bridge_get_size(const struct net_device *dev)
{
    return nla_total_size(sizeof(__u16)) +  /* IFLA_SX_BRIDGE_ID */
           0;
}

static int sx_bridge_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    struct sx_net_priv *net_priv = netdev_priv(dev);

    if (nla_put_u16(skb, IFLA_SX_BRIDGE_ID, net_priv->bridge_id)) {
        goto nla_put_failure;
    }

    return 0;

nla_put_failure:
    return -EMSGSIZE;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0))
static int sx_bridge_newlink(struct net             *net,
                             struct net_device      *dev,
                             struct nlattr          *tb[],
                             struct nlattr          *data[],
                             struct netlink_ext_ack *extack)
#else
static int sx_bridge_newlink(struct net *net, struct net_device *dev, struct nlattr *tb[], struct nlattr *data[])
#endif
{
    struct sx_net_priv *net_priv = netdev_priv(dev);
    int                 swid = 0;
    int                 err;
    int                 i;
    __u16               bridge_id;
    u8                  uc_type = 0;
    unsigned long       flags;

    sxd_log_info("%s: called\n", __func__);

    read_lock_irqsave(&sx_core_if.access_lock, flags);
    if (!sx_core_if.init_done) {
        read_unlock_irqrestore(&sx_core_if.access_lock, flags);
        sxd_log_err("%s: can't create bridge netdevice during sx_core detach/reset. \n", __func__);
        return -ENXIO;
    }
    read_unlock_irqrestore(&sx_core_if.access_lock, flags);

    if (!data[IFLA_SX_BRIDGE_ID]) {
        return -EINVAL;
    }

    mutex_lock(&g_netdev_resources->rsc_lock);

    if (!g_netdev_resources->sx_netdevs[swid]) {
        mutex_unlock(&g_netdev_resources->rsc_lock);
        sxd_log_info("%s: SWID %d, doesn't exists\n", __func__, swid);
        return -EINVAL;
    }

    bridge_id = nla_get_u16(data[IFLA_SX_BRIDGE_ID]);
    if ((bridge_id > MAX_BRIDGE_ID) || (bridge_id < MIN_BRIDGE_ID)) {
        mutex_unlock(&g_netdev_resources->rsc_lock);
        sxd_log_info("%s: BRIDGE is out of range - %d\n", __func__, bridge_id);
        return -EINVAL;
    }

    net_priv->swid = swid;
    net_priv->dev = ((struct sx_net_priv*)netdev_priv(g_netdev_resources->sx_netdevs[swid]))->dev;
    net_priv->bridge_id = bridge_id;
    net_priv->is_bridge = 1;
    net_priv->is_oper_state_up = 1;
    net_priv->is_port_netdev = 0;
    net_priv->mac = 0;
    net_priv->skip_tunnel = g_skip_tunnel;

    for (uc_type = USER_CHANNEL_L3_NETDEV; uc_type < NUM_OF_NET_DEV_TYPE; uc_type++) {
        for (i = 0; i < MAX_NUM_TRAPS_TO_REGISTER; i++) {
            net_priv->trap_ids[uc_type][i].synd = SX_INVALID_TRAP_ID;
        }
        net_priv->num_of_traps[uc_type] = 0;
    }

    mutex_unlock(&g_netdev_resources->rsc_lock);

    err = sx_netdev_register_device(dev, 0, 0);
    if (err) {
        sxd_log_info("%s: sx_netdev_register_device() failed error - %d\n", __func__, err);
        return -ENXIO;
    }

    bridge_netdev_db[net_priv->bridge_id - MIN_BRIDGE_ID] = dev;

    sxd_log_info("%s: exit\n", __func__);

    return 0;
}

static void sx_bridge_dellink(struct net_device *dev, struct list_head *head)
{
    struct sx_net_priv *net_priv = netdev_priv(dev);
    unsigned long       flags;

    sxd_log_info("%s: called\n", __func__);

    read_lock_irqsave(&sx_core_if.access_lock, flags);
    if (!sx_core_if.init_done) {
        read_unlock_irqrestore(&sx_core_if.access_lock, flags);
        sxd_log_err("%s: can't delete bridge netdevice during sx_core detach/reset. \n", __func__);
        return;
    }
    read_unlock_irqrestore(&sx_core_if.access_lock, flags);


    if (net_priv->is_bridge) {
        bridge_netdev_db[net_priv->bridge_id - MIN_BRIDGE_ID] = NULL;
    }

    netif_tx_disable(dev);
    netif_carrier_off(dev);

    CALL_SX_CORE_FUNC_WITHOUT_RET(sx_core_flush_synd_by_context, dev);

    unregister_netdevice_queue(dev, head);

    sxd_log_info("%s: exit\n", __func__);
}


static const struct nla_policy                 sx_bridge_policy[IFLA_SX_BRIDGE_MAX + 1] = {
    [IFLA_SX_BRIDGE_ID] = { .type = NLA_U16 },
};
static struct rtnl_link_ops sx_bridge_link_ops __read_mostly = {
    .kind = "sx_bridge",
    .maxtype = IFLA_SX_BRIDGE_MAX,
    .policy = sx_bridge_policy,
    .priv_size = sizeof(struct sx_net_priv),
    .setup = sx_bridge_setup,
    .validate = sx_bridge_validate,
    .newlink = sx_bridge_newlink,
    .dellink = sx_bridge_dellink,
    .get_size = sx_bridge_get_size,
    .fill_info = sx_bridge_fill_info
};

int sx_bridge_rtnl_link_register()
{
    return rtnl_link_register(&sx_bridge_link_ops);
}

void sx_bridge_rtnl_link_unregister()
{
    rtnl_link_unregister(&sx_bridge_link_ops);
}
