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

#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/mlx_sx/cmd.h>
#include <linux/mlx_sx/device.h>
#include <linux/pci.h>
#include "sx.h"
#include "dq.h"
#include "alloc.h"
#include "dev_db.h"
#include "sgmii.h"
#include <linux/mlx_sx/auto_registers/cmd_auto.h>
#include <linux/mlx_sx/auto_registers/reg.h>

static int reset_trigger = 1;
module_param_named(reset_trigger, reset_trigger, int, 0644);
MODULE_PARM_DESC(reset_trigger, "a trigger to perform chip reset");

static int debug_fw_trace_boot_flow = 0;
module_param_named(debug_fw_trace_boot_flow, debug_fw_trace_boot_flow, int, 0644);
MODULE_PARM_DESC(debug_fw_trace_boot_flow, "only for debug environment - enable when debugging FW boot flow");

static int force_reset_type = 0;
module_param_named(force_reset_type, force_reset_type, int, 0644);
MODULE_PARM_DESC(force_reset_type, "force reset type: 1 - SW_RSR, 2 - PCI_DIS_RST");

static int force_no_pci_link_reporting_cap = 0;
module_param_named(force_no_pci_link_reporting_cap, force_no_pci_link_reporting_cap, int, 0644);
MODULE_PARM_DESC(force_no_pci_link_reporting_cap,
                 "force no PCI link reporting capability, relevant for PCI disable reset type");

extern int skip_reset;

#define RESET_TRIGGER_TIMEOUT     (10 * HZ)
#define SX_RESET_TIMEOUT_JIFFIES  (2 * HZ)
#define SX_SYSTEM_STATUS_REG_MASK 0xFF
#define SX_SYSTEM_STATUS_ENABLED  0x5E
#ifdef INCREASED_TIMEOUT
    #define SX_SW_RESET_TIMEOUT_MSECS (25 * 60 * 1000)           /* 15 minutes */
#else
    #define SX_SW_RESET_TIMEOUT_MSECS (5 * 1000)           /* 5 seconds */
#endif
#if defined(INCREASED_TIMEOUT)
#define SX_PCI_TOGGLE_TIMEOUT_MS       (20 * 60 * 1000)   /* 20 minutes */
#define SX_PCI_LINK_DOWN_TIME          (1 * 60 * 1000)    /* 1 minute */
#define SX_PCI_WAIT_AFTER_LINK_UP_TIME (7 * 60 * 1000)    /* 7 minutes */
#define SX_WAIT_WHEN_NO_LNKCAP_DLLLARC (5 * 60 * 1000)    /* 5 minutes */
#else
#define SX_PCI_TOGGLE_TIMEOUT_MS       (2 * 1000)         /* 2 seconds */
#define SX_PCI_LINK_DOWN_TIME          (500)              /* 500 msec */
#define SX_PCI_WAIT_AFTER_LINK_UP_TIME (500)              /* 500 msec */
#define SX_WAIT_WHEN_NO_LNKCAP_DLLLARC (1000)
#endif
#define SX_HCA_HEADERS_SIZE 256
#define SX_ASIC_ID(dev) ((dev)->pdev->device)
#define SX_RESET_PFX "reset-flow: "

#define MCAM_REG_CAP_MRSR_CMD_6_SUPPORTED_BIT          (48)
#define MCAM_REG_CAP_MRSR_CMD_6_WITH_SBR_SUPPORTED_BIT (67)
#define IS_MRSR_CMD_6_SUPPORTED(feature_cap_mask1) \
    ((feature_cap_mask1) &                         \
     (1 << (MCAM_REG_CAP_MRSR_CMD_6_SUPPORTED_BIT - 32)))
#define IS_MRSR_CMD_6_WITH_SBR_SUPPORTED_BIT(feature_cap_mask2) \
    ((feature_cap_mask2) &                                      \
     (1 << (MCAM_REG_CAP_MRSR_CMD_6_WITH_SBR_SUPPORTED_BIT - 64)))

static int __pci_wait_after_link_up_time = SX_PCI_WAIT_AFTER_LINK_UP_TIME;
static int __set_pci_wait_after_link_up_time(const char *val, const struct kernel_param *kp);
static const struct kernel_param_ops __pci_wait_after_link_up_time_ops = {
    .set = __set_pci_wait_after_link_up_time,
    .get = param_get_int,
};
module_param_cb(__pci_wait_after_link_up_time,
                &__pci_wait_after_link_up_time_ops,
                &__pci_wait_after_link_up_time,
                0644);
__MODULE_PARM_TYPE(__pci_wait_after_link_up_time, "int");
MODULE_PARM_DESC(__pci_wait_after_link_up_time,
                 "Time (in ms) to wait for PCI bridge link to be UP, "
                 "default and minimum are both 500 ms, relevant for PCI disable reset type");

const char * sx_reset_type_str(enum sx_reset_type type)
{
    static const char *type_str[] = {
        [SX_RESET_TYPE_NONE] = "None",
        [SX_RESET_TYPE_EMERGENCY] = "Emergency",
        [SX_RESET_TYPE_NORMAL] = "Normal"
    };

    if (((int)type >= 0) && ((int)type < sizeof(type_str) / sizeof(type_str[0]))) {
        return type_str[type];
    }

    return "N/A";
}

static int __set_pci_wait_after_link_up_time(const char *val, const struct kernel_param *kp)
{
    int n = 0;
    int ret;

    ret = kstrtoint(val, 10, &n);
    if ((ret != 0) || (n < SX_PCI_WAIT_AFTER_LINK_UP_TIME)) {
        return -EINVAL;
    }

    return param_set_int(val, kp);
}

static int __wait_for_system_ready(struct sx_dev *dev, u32 wait_for_reset_msec, u32 *time_waited_msec)
{
    unsigned long start;
    unsigned long end;
    int           ret = 0;
    u16           val = 0xffff, prev_val = 0xffff;
    bool          system_ready = false;

    start = jiffies;
    end = jiffies + msecs_to_jiffies(wait_for_reset_msec);

    do {
        ret = get_system_status(dev, &val);
        if (ret) {
            break;
        }

        if (prev_val == 0xffff) { /* only in 1st iteration */
            prev_val = val;
        }

        if (val != prev_val) {
            sx_notice(dev, SX_RESET_PFX "device %u status changed to 0x%x\n", dev->device_id, val);
            prev_val = val;
        }

        if (val == SX_SYSTEM_STATUS_ENABLED) {
            if (time_waited_msec != NULL) {
                *time_waited_msec = jiffies_to_msecs(jiffies - start);
            }

            system_ready = true;
            break;
        }

        msleep(100);
    } while (time_before(jiffies, end));

    if (!system_ready) {
        sx_notice(dev, SX_RESET_PFX "device %u is not ready, current status is 0x%x\n", dev->device_id, val);
        return -ETIME;
    }

    return 0;
}


static u32 __get_chip_reset_duration(u16 asic_id)
{
    u32 duration;

    switch (asic_id) {
    case QUANTUM_PCI_DEV_ID:
    case QUANTUM2_PCI_DEV_ID:
    case QUANTUM3_PCI_DEV_ID:
        duration = 15 * 1000; /* 15 seconds */
        break;

    case SPECTRUM2_PCI_DEV_ID:
    case SPECTRUM3_PCI_DEV_ID:
    case SPECTRUM4_PCI_DEV_ID:
    case SPECTRUM5_PCI_DEV_ID:
        duration = 5 * 60 * 1000; /* 5 minutes */
        break;

    default:
        duration = SX_SW_RESET_TIMEOUT_MSECS;
        break;
    }

#if defined(PD_BU) && defined(QUANTUM3_BU)
    duration = 20 * 60 * 1000; /* wait 20 minutes for reset on palladium */
#endif

    return duration;
}

static int __run_dev_reset_type_callback(struct sx_dev *dev, enum sx_reset_type reset_type)
{
    bool cb_called = false;
    int  err = 0;

    if (!dev) {
        sx_err(dev, SX_RESET_PFX "device is NULL\n");
        return -ENODEV;
    }

    err = __sx_core_dev_specific_cb_get_reference(dev);
    if (err) {
        sx_err(dev, SX_RESET_PFX "failed to get device specific callback reference (err=%d)\n", err);
        return err;
    }

    switch (reset_type) {
    case SX_RESET_TYPE_EMERGENCY:
        sx_info(dev, SX_RESET_PFX "running reset type 'emergency'\n");
        if (sx_priv(dev)->dev_specific_cb.chip_emergency_reset_cb) {
            err = sx_priv(dev)->dev_specific_cb.chip_emergency_reset_cb(dev);
            cb_called = true;
        }
        break;

    case SX_RESET_TYPE_NORMAL:
        sx_info(dev, SX_RESET_PFX "running reset type 'normal'\n");
        if (sx_priv(dev)->dev_specific_cb.chip_reset_cb) {
            err = sx_priv(dev)->dev_specific_cb.chip_reset_cb(dev);
            cb_called = true;
        }
        break;

    default:
        sx_err(dev, SX_RESET_PFX "invalid reset type (%d)\n", reset_type);
        err = -EINVAL;
        goto out;
    }

    if (!cb_called) {
        sx_err(dev, SX_RESET_PFX "no callback assigned for this reset type\n");
        err = -ENOENT;
        goto out;
    }

out:
    __sx_core_dev_specific_cb_release_reference(dev);
    return err;
}

static int __run_dev_post_reset(struct sx_dev *dev)
{
    int err = 0;

    if (!dev) {
        sxd_log_err(SX_RESET_PFX "device is NULL\n");
        return -ENODEV;
    }

    err = __sx_core_dev_specific_cb_get_reference(dev);
    if (err) {
        sx_err(dev, SX_RESET_PFX "failed to get device specific callback reference (err=%d)\n", err);
        return err;
    }

    if (sx_priv(dev)->dev_specific_cb.chip_post_reset_cb) {
        err = sx_priv(dev)->dev_specific_cb.chip_post_reset_cb(dev);
    }

    __sx_core_dev_specific_cb_release_reference(dev);
    return err;
}

static int __do_sw_reset_flow(struct sx_dev *dev, enum sx_reset_type reset_type)
{
    struct sx_priv      *priv = sx_priv(dev);
    union sx_event_data *event_data = NULL;
    u32                  wait_for_reset, time_waited;
    int                  err = 0;
    bool                 is_pre_reset_event = false;

    sx_info(dev, SX_RESET_PFX "starting reset flow (type=%s)\n", sx_reset_type_str(reset_type));

    /* allocate it here even if needed later because we want to make sure that
     * reset post-event will be sent if pre-event was.
     */
    event_data = kzalloc(sizeof(union sx_event_data), GFP_KERNEL);
    if (!event_data) {
        sx_err(dev, SX_RESET_PFX "failed to allocate reset event\n");
        err = -ENOMEM;
        goto out;
    }

    wait_for_reset = __get_chip_reset_duration(SX_ASIC_ID(dev));

    sx_info(dev, SX_RESET_PFX "waiting for device to be in ready-state before reset (up to %u seconds)\n",
            wait_for_reset / 1000);

    err = __wait_for_system_ready(dev, wait_for_reset, &time_waited);
    if (err) {
        sx_err(dev, SX_RESET_PFX "device is not in ready-state and cannot be reset (err=%d)!\n", err);
        goto out;
    }

    err = sx_core_dispatch_event(dev, SX_DEV_EVENT_PRE_RESET, NULL);
    if (err) {
        sx_err(dev, SX_RESET_PFX "failed to send pre-reset event (err=%d)\n", err);
        goto out;
    }

    is_pre_reset_event = true;
    sx_info(dev, SX_RESET_PFX "device is ready for reset [waited %u msec], resetting now\n", time_waited);

    priv->dev_sw_rst_flow = true;
    err = __run_dev_reset_type_callback(dev, reset_type);
    if (err) {
        if (err == -EOPNOTSUPP) {
            /* PCI-Toggle is not supported (SimX), don't print an error. */
            sx_warn(dev, SX_RESET_PFX "reset type is not supported on this platform\n");
        } else {
            sx_err(dev, SX_RESET_PFX "reset function failed (err=%d)\n", err);
        }

        goto out;
    }

    sx_info(dev, SX_RESET_PFX "waiting for device to be in ready-state after reset (up to %u seconds)\n",
            wait_for_reset / 1000);

    /* now wait for device to be in ready-state */
    err = __wait_for_system_ready(dev, wait_for_reset, &time_waited);
    if (err) {
        sx_err(dev, SX_RESET_PFX "reset operation has timed out, device is not in ready-state (err=%d)\n", err);
        goto out;
    }

    err = __run_dev_post_reset(dev);
    if (err) {
        sx_err(dev, SX_RESET_PFX "post reset function failed (err=%d)\n", err);
        goto out;
    }

    sx_info(dev, SX_RESET_PFX "device is in ready-state after reset [waited %u msec]\n", time_waited);
    priv->reset_info.last_chip_reset_type = reset_type;
    priv->reset_info.duration_msec = time_waited;

out:
    if (is_pre_reset_event) {
        event_data->post_reset.err = err;
        err = sx_core_dispatch_event(dev, SX_DEV_EVENT_POST_RESET, event_data);
        if (err) {
            sx_err(dev, SX_RESET_PFX "failed to send post-reset event with status=%d (err=%d)\n",
                   event_data->post_reset.err, err);
        }
        err = event_data->post_reset.err;
    }

    kfree(event_data);
    priv->dev_sw_rst_flow = false;
    return err;
}

static int __pci_link_toggle(struct sx_dev * dev)
{
    struct pci_bus *bridge_bus = dev->pdev->bus;
    struct pci_dev *bridge = bridge_bus->self;
    u16             reg16, dev_id, sdev_id;
    unsigned long   timeout, start_time;
    struct pci_dev *sdev;
    int             cap, err;
    u32             reg32;

    /* Check that all functions under the pci bridge are PFs of
     * this device otherwise fail this function.
     */
    err = pci_read_config_word(dev->pdev, PCI_DEVICE_ID, &dev_id);
    if (err) {
        sx_err(dev, SX_RESET_PFX "pci_read_config_word failed , err: %d\n", err);
        return err;
    }

    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        err = pci_read_config_word(sdev, PCI_DEVICE_ID, &sdev_id);
        if (err) {
            sx_err(dev, SX_RESET_PFX "pci_read_config_word failed , err: %d\n", err);
            return err;
        }
        if (sdev_id != dev_id) {
            sx_err(dev, SX_RESET_PFX "sdev_id %d (0x%x) != dev_id %d (0x%x) \n", sdev_id, sdev_id, dev_id, dev_id);
            return -EPERM;
        }
    }

    sx_info(dev, SX_RESET_PFX "toggle PCI link\n");

    cap = pci_find_capability(bridge, PCI_CAP_ID_EXP);
    if (!cap) {
        sx_warn(dev, SX_RESET_PFX "pci_find_capability failed\n");
        return -EOPNOTSUPP;
    }

    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        pci_save_state(sdev);
        pci_cfg_access_lock(sdev);
    }

    /* PCI link toggle */
    sx_info(dev, SX_RESET_PFX "set bridge link DOWN\n");
    err = pci_read_config_word(bridge, cap + PCI_EXP_LNKCTL, &reg16);
    if (err) {
        sx_err(dev, SX_RESET_PFX "bridge pci_read_config_word cap + PCI_EXP_LNKCTL failed (err=%d)\n", err);
        goto restore;
    }
    reg16 |= PCI_EXP_LNKCTL_LD;
    err = pci_write_config_word(bridge, cap + PCI_EXP_LNKCTL, reg16);
    if (err) {
        sx_err(dev, SX_RESET_PFX "bridge pci_write_config_word cap + PCI_EXP_LNKCTL failed (err=%d)\n", err);
        goto restore;
    }

    msleep(SX_PCI_LINK_DOWN_TIME);

    sx_info(dev, SX_RESET_PFX "set bridge link UP\n");
    reg16 &= ~PCI_EXP_LNKCTL_LD;
    err = pci_write_config_word(bridge, cap + PCI_EXP_LNKCTL, reg16);
    if (err) {
        goto restore;
    }

    sx_info(dev, SX_RESET_PFX "waiting for bridge link to be UP\n");
    msleep(__pci_wait_after_link_up_time);

    /* Check link */
    err = pci_read_config_dword(bridge, cap + PCI_EXP_LNKCAP, &reg32);
    if (err) {
        goto restore;
    }
    if (!(reg32 & PCI_EXP_LNKCAP_DLLLARC) || force_no_pci_link_reporting_cap) {
        sx_info(dev, SX_RESET_PFX "no PCI link reporting capability (0x%08x)\n", reg32);
        msleep(SX_WAIT_WHEN_NO_LNKCAP_DLLLARC);
        goto restore;
    }

    start_time = jiffies;
    timeout = jiffies + msecs_to_jiffies(SX_PCI_TOGGLE_TIMEOUT_MS);
    do {
        err = pci_read_config_word(bridge, cap + PCI_EXP_LNKSTA, &reg16);
        if (err) {
            goto restore;
        }
        if (reg16 & PCI_EXP_LNKSTA_DLLLA) {
            break;
        }
        msleep(20);
    } while (!time_after(jiffies, timeout));

    if (reg16 & PCI_EXP_LNKSTA_DLLLA) {
        sx_info(dev, SX_RESET_PFX "PCI Link up  (0x%04x) after %lu jiffies\n", reg16, start_time - jiffies);
    } else {
        sx_err(dev, SX_RESET_PFX "PCI link not ready (0x%04x) after %u ms\n", reg16, SX_PCI_TOGGLE_TIMEOUT_MS);
        err = -ETIMEDOUT;
    }

restore:
    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        pci_cfg_access_unlock(sdev);
        pci_restore_state(sdev);
    }

    return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
static int __pci_secondary_bus_reset(struct sx_dev * dev)
{
    struct pci_bus *bridge_bus = dev->pdev->bus;
    struct pci_dev *bridge = bridge_bus->self;
    u16             dev_id, sdev_id;
    struct pci_dev *sdev;
    int             err = 0;

    /* Check that all functions under the pci bridge are PFs of
     * this device otherwise fail this function.
     */
    err = pci_read_config_word(dev->pdev, PCI_DEVICE_ID, &dev_id);
    if (err) {
        sx_err(dev, SX_RESET_PFX "pci_read_config_word failed , err: %d\n", err);
        return err;
    }

    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        err = pci_read_config_word(sdev, PCI_DEVICE_ID, &sdev_id);
        if (err) {
            sx_err(dev, SX_RESET_PFX "pci_read_config_word failed , err: %d\n", err);
            return err;
        }
        if (sdev_id != dev_id) {
            sx_err(dev, SX_RESET_PFX "sdev_id %d (0x%x) != dev_id %d (0x%x) \n", sdev_id, sdev_id, dev_id, dev_id);
            return -EPERM;
        }
    }

    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        pci_save_state(sdev);
        pci_cfg_access_lock(sdev);
    }

    err = pci_bridge_secondary_bus_reset(bridge);
    if (err) {
        sx_err(dev, SX_RESET_PFX "Failed to do SBR.\n");
    } else {
        sx_info(dev, SX_RESET_PFX "SBR performed successfully on PCI bridge\n");
    }

    list_for_each_entry(sdev, &bridge_bus->devices, bus_list) {
        pci_cfg_access_unlock(sdev);
        pci_restore_state(sdev);
    }

    return err;
}
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) */

/* This function saves PCI headers for restoration after SW reset,
 * using __restore_headers_data, according to device type.
 * SwitchX                                                      - Saves and restores PCI headers.
 * Spectrum, SwitchIB, SwitchIB2	- Doesn't save PCI headers.
 *
 *
 * @param dev[in]				- sx device.
 * @param hca_header_p[in/out]	- hca headers, must be size of SX_HCA_HEADERS_SIZE.
 */
static int __save_headers_data_SwitchX(struct sx_dev *dev, u32* hca_header_p)
{
    int err = 0;
    int i = 0;
    int pcie_cap = 0;

    memset(hca_header_p, 0, SX_HCA_HEADERS_SIZE);

    pcie_cap = pci_find_capability(dev->pdev, PCI_CAP_ID_EXP);

    /* We skip config space offsets 22
     * and 23 since those have a special meaning.
     */
    for (i = 0; i < 64; ++i) {
        if ((i == 22) || (i == 23)) {
            continue;
        }
        if (pci_read_config_dword(dev->pdev, i * 4, hca_header_p + i)) {
            err = -ENODEV;
            sx_err(dev, "%s: Couldn't save HCA PCI header, aborting, err[%d]\n", __func__, err);
            goto out;
        }
    }

out:
    return err;
}


/* This function restores PCI headers after SW reset, according to
 * headers as saved by __save_headers_data, according to device type.
 * SwitchX                                                      - Restores and restores PCI headers.
 * Spectrum, SwitchIB, SwitchIB2	- Doesn't restore PCI headers.
 *
 *
 * @param dev[in]				- sx device.
 * @param hca_header_p[in]	    - hca headers, must be size of SX_HCA_HEADERS_SIZE.
 */
static int __restore_headers_data_SwitchX(struct sx_dev *dev, u32* hca_header_p)
{
    int err = 0;
    int pcie_cap;
    int i = 0;
    u16 devctl = 0;
    u16 linkctl = 0;

    /* restore PCIE headers to restore after reset from hca_header_p */
    /* Now restore the PCI headers */
    pcie_cap = pci_find_capability(dev->pdev, PCI_CAP_ID_EXP);
    if (pcie_cap) {
        devctl = hca_header_p[(pcie_cap + PCI_EXP_DEVCTL) / 4];
        if (pci_write_config_word(dev->pdev, pcie_cap + PCI_EXP_DEVCTL, devctl)) {
            err = -ENODEV;
            sx_err(dev, "%s: Couldn't restore HCA PCI Express "
                   "Device Control register, aborting, err[%d]\n", __func__, err);
            goto out;
        }

        linkctl = hca_header_p[(pcie_cap + PCI_EXP_LNKCTL) / 4];
        if (pci_write_config_word(dev->pdev, pcie_cap + PCI_EXP_LNKCTL,
                                  linkctl)) {
            err = -ENODEV;
            sx_err(dev, "%s: Couldn't restore HCA PCI Express "
                   "Link control register, aborting, err[%d]\n", __func__, err);
            goto out;
        }
    }

    for (i = 0; i < 16; ++i) {
        if (i * 4 == PCI_COMMAND) {
            continue;
        }

        if (pci_write_config_dword(dev->pdev, i * 4, hca_header_p[i])) {
            err = -ENODEV;
            sx_err(dev, "%s: Couldn't restore HCA reg %x, aborting, err[%d]\n", __func__, i, err);
            goto out;
        }
    }

    if (pci_write_config_dword(dev->pdev, PCI_COMMAND,
                               hca_header_p[PCI_COMMAND / 4])) {
        err = -ENODEV;
        sx_err(dev, "%s: Couldn't restore HCA COMMAND, aborting, err[%d]\n", __func__, err);
        goto out;
    }

out:
    return err;
}


/* This function is used to read system status from FW
 *
 * @param dev[in]				- sx device.
 * @param system_status[out]	- system status.
 */

int get_system_status(struct sx_dev *dev, u16 *system_status)
{
    int           err = 0;
    u32           val = 0;
    void __iomem *sys_status_addr = NULL;
    u32           system_status_reg_offset = sx_priv(dev)->reset_info.system_status_mem_offset;

    if (!dev) {
        sx_err(dev, SX_RESET_PFX "Get-System-Status: device is NULL\n");
        err = -EINVAL;
        goto out;
    }

    if (!system_status) {
        sx_err(dev, SX_RESET_PFX "Get-System-Status: system status is NULL\n");
        err = -EINVAL;
        goto out;
    }

    if (unlikely(sx_cr_mode())) {
        err = sx_dpt_cr_space_read(dev->device_id, system_status_reg_offset, (unsigned char*)&val, sizeof(val));
        if (err) {
            sx_err(dev, SX_RESET_PFX "Get-System-Status: failed to read system status via I2C, err=%d\n", err);
            goto out;
        }

        val = be32_to_cpu(val);
    } else {
        sys_status_addr = ioremap(pci_resource_start(dev->pdev, 0) + system_status_reg_offset, sizeof(u32));
        if (!sys_status_addr) {
            err = -ENOMEM;
            sx_err(dev, "Get-System-Status: couldn't map system status register\n");
            goto out;
        }

        val = ioread32be(sys_status_addr);
        iounmap(sys_status_addr);
    }

    *system_status = val & SX_SYSTEM_STATUS_REG_MASK;

out:
    return err;
}

static int __do_legacy_reset(struct sx_dev *dev)
{
    void __iomem *reset;
    int           err = 0;

    sx_info(dev, SX_RESET_PFX "starting legacy reset\n");

#define SX_RESET_BASE  0xf0010
#define SX_RESET_SIZE  (4)
#define SX_RESET_VALUE swab32(1)

    reset = ioremap(pci_resource_start(dev->pdev, 0) + SX_RESET_BASE, SX_RESET_SIZE);
    if (!reset) {
        err = -ENOMEM;
        sx_err(dev, "Couldn't map reset register, aborting.\n");
        goto out;
    }

    /* actually hit reset */
    writel(SX_RESET_VALUE, reset);
    iounmap(reset);

    /* Wait three seconds before accessing device */
#ifndef INCREASED_TIMEOUT
    msleep(3000);
#else
    msleep(180000);
#endif

out:
    return err;
}


static int __legacy_reset_SwitchX(struct sx_dev *dev)
{
    u16           vendor = 0xffff;
    unsigned long end;
    int           err = 0;

    sx_info(dev, SX_RESET_PFX "performing SwitchX legacy reset\n");

    if (!dev->pdev) {
        sx_err(dev, "SW reset will not be executed since PCI device is not present");
        err = -ENODEV;
        goto out;
    }

    err = __do_legacy_reset(dev);
    if (err) {
        sx_err(dev, "failed SwitchX legacy reset [err=%d]\n", err);
        goto out;
    }

    /* SwitchX does not support System_Status register, so we will poll the vendor-id */
    end = jiffies + SX_RESET_TIMEOUT_JIFFIES;
    do {
        if (!pci_read_config_word(dev->pdev, PCI_VENDOR_ID, &vendor) && (vendor != 0xffff)) {
            break;
        }

        msleep(1);
    } while (time_before(jiffies, end));

    if (vendor == 0xffff) {
        err = -ENODEV;
        sx_err(dev, "PCI device did not come back after reset, aborting.\n");
        goto out;
    }

out:
    return err;
}

/* wait for device to come up after reset, depending on device type.
 * SwitchX                                                      - 3 seconds timeout.
 * Spectrum, SwitchIB, SwitchIB2	- wait for FW ready control register.
 */
static int __perform_dev_sw_reset(struct sx_dev *dev)
{
    int err = 0;

    if (SX_ASIC_ID(dev) == SWITCHX_PCI_DEV_ID) {
        return __legacy_reset_SwitchX(dev);
    }

    err = __do_sw_reset_flow(dev, SX_RESET_TYPE_NORMAL);
    if (err == -EOPNOTSUPP) {
        /* PCI-Toggle is not supported (SimX), don't print an error. fallback to legacy reset */
        sx_warn(dev, "reset-flow: normal reset is not supported, fallback to legacy reset\n");
        err = __do_sw_reset_flow(dev, SX_RESET_TYPE_EMERGENCY);
    }

    if (err) {
        sx_err(dev, "reset-flow: reset failed (err=%d)\n", err);
    }

    return err;
}

int sx_reset(struct sx_dev *dev, u8 perform_chip_reset)
{
    u32          *hca_header = NULL;
    unsigned long end;
    int           err = 0;
    bool          is_switchx = false;

    if (skip_reset) {
        sx_warn(dev, SX_RESET_PFX "skipping ASIC reset on demand!\n");
        return 0;
    }

    if ((dev == NULL) || (!sx_cr_mode() && !dev->pdev)) {
        sx_err(dev, SX_RESET_PFX "SW reset will not be executed since PCI device is not present\n");
        err = -ENODEV;
        goto out;
    }

    is_switchx = (SX_ASIC_ID(dev) == SWITCHX_PCI_DEV_ID);

    if (!sx_cr_mode() && is_switchx) {
        hca_header = kmalloc(SX_HCA_HEADERS_SIZE, GFP_KERNEL);
        if (!hca_header) {
            err = -ENOMEM;
            sx_err(dev, "%s: Couldn't allocate memory to save HCA "
                   "PCI header, aborting, err[%d]\n", __func__, err);
            goto out;
        }

        err = __save_headers_data_SwitchX(dev, hca_header);
        if (err) {
            sx_err(dev, "PCI device reset failed saving PCI headers data, err [%d].\n", err);
            goto out;
        }
    }

    /* return device to use polling */
    sx_cmd_use_polling(dev);

    if (reset_trigger) {
        sx_info(dev, "reset trigger is already set\n");
    } else {
        sx_info(dev, "waiting for reset trigger\n");

        end = jiffies + RESET_TRIGGER_TIMEOUT;

        while (!reset_trigger && time_before(jiffies, end)) {
            msleep(100);
        }

        if (reset_trigger) {
            sx_info(dev, "reset trigger is set\n");
        } else {
            sx_err(dev, "reset trigger timeout. self triggering.\n");
            reset_trigger = 1;
        }
    }

    if (perform_chip_reset) {
        sx_info(dev, "performing chip reset in this phase\n");

        err = __perform_dev_sw_reset(dev);
        if (err) {
            sx_err(dev, "PCI device reset failed waiting for device, err [%d].\n", err);
            goto out;
        }
    } else {
        sx_info(dev, "chip was not reset in this phase, check that system is in ready-state\n");

        if (!debug_fw_trace_boot_flow) {
            /* check that system is in ready state */
            err = __wait_for_system_ready(dev, 0, NULL);
            if (err) {
                err = -ENODEV;
                sx_err(dev, SX_RESET_PFX "system is not ready.\n");
                goto out;
            }
        }
    }

    if (is_switchx) {
        /* Now restore the PCI headers */
        err = __restore_headers_data_SwitchX(dev, hca_header);
        if (err) {
            sx_err(dev, "PCI device reset failed restoring PCI headers data, err [%d].\n", err);
            goto out;
        }
    }

out:
    if (hca_header) {
        kfree(hca_header);
    }

    return err;
}

static int __call_MRSR(struct sx_dev *dev, enum sxd_mrsr_command reset_command)
{
    int                       err = 0;
    struct ku_access_mrsr_reg reg_data;

    memset(&reg_data, 0, sizeof(reg_data));

    reg_data.dev_id = dev->device_id;
    reg_data.op_tlv.type = TLV_TYPE_OPERATION_E;
    reg_data.op_tlv.length = TLV_LEN;
    reg_data.op_tlv.register_id = MRSR_REG_ID;
    reg_data.op_tlv.r = TLV_REQUEST;
    reg_data.op_tlv.method = EMAD_METHOD_WRITE;
    reg_data.op_tlv.op_class = EMAD_CLASS_REG_ACCESS;
    reg_data.mrsr_reg.command = reset_command;

    err = sx_ACCESS_REG_MRSR(dev, &reg_data);
    if (err) {
        sx_err(dev, SX_RESET_PFX "failed accessing MRSR(%d) for SW reset command, err [%d]\n", reset_command, err);
        goto out;
    }

out:
    return err;
}

/* this is a device callback function */
int sx_reset_with_mrsr_1(struct sx_dev *dev)
{
    int err;

    sx_info(dev, SX_RESET_PFX "triggering MRSR(1)\n");
    err = __call_MRSR(dev, SXD_MRSR_CMD_SW_RESET);
    if (err) {
        sx_err(dev, SX_RESET_PFX "MRSR(1) failed (err=%d)\n", err);
    }

    return err;
}

static int sx_reset_with_mrsr_6_and_pci_toggle(struct sx_dev *dev)
{
    int err = 0;

    sx_info(dev, SX_RESET_PFX "triggering MRSR(6) before reset\n");
    err = __call_MRSR(dev, SXD_MRSR_CMD_RESET_AT_PCI_DISABLE);
    if (err) {
        sx_err(dev, SX_RESET_PFX "MRSR(6) failed before reset (err=%d)\n", err);
        goto out;
    }

    err = __pci_link_toggle(dev);
    if (err == -EOPNOTSUPP) {
        sx_warn(dev, SX_RESET_PFX "device does not support bridge PCI link toggling\n");
        goto out;
    }

    if (err) { /* and != EOPNOTSUPP */
        sx_err(dev, SX_RESET_PFX "PCI link toggling failed (err=%d)\n", err);
        goto out;
    }

out:
    return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
static int sx_reset_with_mrsr_6_and_sbr(struct sx_dev *dev)
{
    int err = 0;

    sx_info(dev, SX_RESET_PFX "triggering MRSR(6) before reset\n");
    err = __call_MRSR(dev, SXD_MRSR_CMD_RESET_AT_PCI_DISABLE);
    if (err) {
        sx_err(dev, SX_RESET_PFX "MRSR(6) failed before reset (err=%d)\n", err);
        goto out;
    }

    err = __pci_secondary_bus_reset(dev);
    if (err == -EOPNOTSUPP) {
        sx_warn(dev, SX_RESET_PFX "device does not support PCI secondary bus reset \n");
        goto out;
    }

    if (err) { /* and != EOPNOTSUPP */
        sx_err(dev, SX_RESET_PFX "PCI secondary bus reset failed (err=%d)\n", err);
        goto out;
    }

out:
    return err;
}
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) */

/* this is a device callback function */
int sx_reset_by_capability(struct sx_dev *dev)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);

    if (priv->reset_cap.reset_cap_initialized == false) {
        err = -EINVAL;
        sxd_log_err("Reset capabilities isn't initialised (err=%d)\n", err);
        goto out;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
    if (priv->reset_cap.mrsr6_with_sbr_is_supported == true) {
        err = sx_reset_with_mrsr_6_and_sbr(dev);
    } else
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) */
    if (priv->reset_cap.mrsr6_is_supported == true) {
        err = sx_reset_with_mrsr_6_and_pci_toggle(dev);
    } else {
        err = sx_reset_with_mrsr_1(dev);
    }

out:
    return err;
}

/* this is a device callback function */
int sx_emergency_reset_with_cr_space(struct sx_dev *dev)
{
    return __do_legacy_reset(dev);
}

static int sx_emergency_reset_with_pci_toggle(struct sx_dev *dev)
{
    int err = __pci_link_toggle(dev);

    if (err == -EOPNOTSUPP) {
        /* PCI-Toggle is not supported (SimX), don't print an error. */
        err = __do_legacy_reset(dev);
    }

    return err;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
static int sx_emergency_reset_with_sbr(struct sx_dev *dev)
{
    int err = __pci_secondary_bus_reset(dev);

    if (err == -EOPNOTSUPP) {
        /* PCI-Toggle is not supported (SimX), don't print an error. */
        err = __do_legacy_reset(dev);
    }

    return err;
}
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) */

/* this is a device callback function */
int sx_emergency_reset_by_capability(struct sx_dev *dev)
{
    int             err = 0;
    struct sx_priv *priv = sx_priv(dev);

    if (priv->reset_cap.reset_cap_initialized == false) {
        err = -EINVAL;
        sxd_log_err("Reset capabilities isn't initialised (err=%d)\n", err);
        goto out;
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
    if (priv->reset_cap.mrsr6_with_sbr_is_supported == true) {
        err = sx_emergency_reset_with_sbr(dev);
    } else
#endif /* #if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)) */
    if (priv->reset_cap.mrsr6_is_supported == true) {
        err = sx_emergency_reset_with_pci_toggle(dev);
    } else {
        err = sx_emergency_reset_with_cr_space(dev);
    }

out:
    return err;
}

/* this is a device callback function */
int sx_post_reset_mrsr_6(struct sx_dev *dev)
{
    /* preparing the device for sudden reset by PCI-toggle at any time
     * (reset ASIC when FW is dead and MRSR is useless) */
    int err;

    sx_info(dev, SX_RESET_PFX "triggering MRSR(6) after reset\n");
    err = __call_MRSR(dev, SXD_MRSR_CMD_RESET_AT_PCI_DISABLE);
    if (err) {
        sx_err(dev, SX_RESET_PFX "MRSR(6) failed after reset (err=%d)\n", err);
    }

    /* This will call MCAM on the new FW running after reset */
    err = sx_init_reset_capabilities(dev);
    if (err) {
        sx_err(dev, SX_RESET_PFX "failed to get chip reset capabilities (err=%d)\n", err);
        goto out;
    }

out:
    return err;
}

static bool __emergency_reset_allowed(struct sx_dev *dev)
{
    struct sx_priv *priv = NULL;

    if (is_sgmii_supported()) { /* not supported on director systems */
        return false;
    }

    priv = sx_priv(dev);
    return (priv->health_check.is_fatal || priv->reset_info.in_pci_restart);
}

void sx_emergency_reset(struct sx_dev *dev, bool force)
{
    struct sx_priv *priv = sx_priv(dev);

    if (!force && !__emergency_reset_allowed(dev)) {
        sxd_log_notice("emergency reset is not allowed\n");
        return;
    }

    /* do not touch this log, SDK verification counts on it */
    sx_info(dev, SX_RESET_PFX "Triggering emergency reset!\n");

    /* return device to use polling */
    sx_cmd_use_polling(dev);
    __do_sw_reset_flow(dev, SX_RESET_TYPE_EMERGENCY);
    priv->reset_info.emergency_reset_done = true;
}

bool sx_emergency_reset_done(struct sx_dev *dev)
{
    return (sx_priv(dev)->reset_info.emergency_reset_done);
}

int sx_emergency_reset_proc_handler(int argc, const char *argv[], void *context)
{
    struct sx_dev *dev = NULL;
    int            dev_id, err = 0;

    if (argc != 2) {
        return -EINVAL;
    }

    err = kstrtoint(argv[1], 10, &dev_id);
    if (err) {
        return -EINVAL;
    }

    sxd_log_notice("emergency reset command: handling request for device %d\n", dev_id);

    dev = sx_dev_db_get_dev_by_id(dev_id);
    if (!dev) {
        sxd_log_warning("emergency reset command: device %d does not exist\n", dev_id);
        return -ENODEV;
    }

    if (!dev->pdev) {
        sxd_log_warning("emergency reset command: this operation is not supported on non-PCI device\n");
        return -EOPNOTSUPP;
    }

    sx_emergency_reset(dev, true);
    return 0;
}

int sx_init_reset_capabilities(struct sx_dev *dev)
{
    struct sx_priv           *priv = sx_priv(dev);
    struct ku_access_mcam_reg reg_mcam;
    int                       err = 0;

    if (is_sgmii_supported()) {
        priv->reset_cap.reset_cap_initialized = true;
        priv->reset_cap.mrsr6_with_sbr_is_supported = false;
        priv->reset_cap.mrsr6_is_supported = false;
        goto skip_mcam;
    }

    memset(&priv->reset_cap, 0, sizeof(priv->reset_cap));

    memset(&reg_mcam, 0, sizeof(reg_mcam));
    reg_mcam.dev_id = priv->dev.device_id;
    sx_cmd_set_op_tlv(&reg_mcam.op_tlv, MLXSW_MCAM_ID, EMAD_METHOD_QUERY);
    err = sx_ACCESS_REG_MCAM(&priv->dev, &reg_mcam);
    if (err) {
        sxd_log_err("Failed to read MCAM (err=%d)\n", err);
        goto failed_mcam;
    }

    priv->reset_cap.reset_cap_initialized = true;

    if (IS_MRSR_CMD_6_WITH_SBR_SUPPORTED_BIT(reg_mcam.mcam_reg.mng_feature_cap_mask[2])) {
        priv->reset_cap.mrsr6_with_sbr_is_supported = true;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0))
        sxd_log_notice("FW supports SBR flow but kernel does not support it, will use other reset flow.\n");
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)) */
    }

    if (IS_MRSR_CMD_6_SUPPORTED(reg_mcam.mcam_reg.mng_feature_cap_mask[1])) {
        priv->reset_cap.mrsr6_is_supported = true;
    }

skip_mcam:
    sxd_log_info("initialize chip reset capabilities: mrsr6=%s, sbr=%s\n",
                 ((priv->reset_cap.mrsr6_is_supported) ? "yes" : "no"),
                 ((priv->reset_cap.mrsr6_with_sbr_is_supported) ? "yes" : "no"));

failed_mcam:
    return err;
}
