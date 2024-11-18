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

#include <linux/mlx_sx/kernel_user.h>

#include "sx.h"
#include "ioctl_internal.h"
#include "dev_init.h"

long ctrl_cmd_set_pci_profile(struct file *file, unsigned int cmd, unsigned long data)
{
    return sx_core_ioctl_set_pci_profile(file, NULL, data, 1);
}


long ctrl_cmd_set_pci_profile_driver_only(struct file *file, unsigned int cmd, unsigned long data)
{
    return sx_core_ioctl_set_pci_profile(file, NULL, data, 0);
}


long ctrl_cmd_pci_register_driver(struct file *file, unsigned int cmd, unsigned long data)
{
    struct sx_dev *dev;
    sxd_dev_id_t   device_id = DEFAULT_DEVICE_ID;

    if (sx_core_has_predefined_devices()) {
        device_id = get_device_id_from_fd(file);
    }

    dev = sx_dev_db_get_dev_by_id(device_id);

    sxd_log_info("ioctl PCI register driver called for device\n");

    if (!dev) {
        sxd_log_err("default device wasn't found\n");
        return -ENODEV;
    }

    return sx_restart_one_pci(dev, true);
}


long ctrl_cmd_pci_device_restart(struct file *file, unsigned int cmd, unsigned long data)
{
    sxd_dev_id_t   dev_id = (sxd_dev_id_t)data;
    struct sx_dev *dev;

    if (sx_core_has_predefined_devices()) {
        dev_id = get_device_id_from_fd(file);
    }

    sxd_log_info("ioctl PCI device restart called for device %u\n", dev_id);

    dev = sx_dev_db_get_dev_by_id(dev_id);

    if (!dev) {
        sxd_log_err("device %u wasn't found\n", dev_id);
        return -ENODEV;
    }

    return sx_restart_one_pci(dev, true);
}


long ctrl_cmd_get_pci_profile(struct file *file, unsigned int cmd, unsigned long data)
{
    struct sx_dev            *dev;
    struct ku_get_pci_profile pci_prof;
    int                       err = 0;

    err = copy_from_user(&pci_prof,
                         (void*)data, sizeof(pci_prof));

    if (sx_core_has_predefined_devices()) {
        pci_prof.dev_id = get_device_id_from_fd(file);
    }

    if (err) {
        return -ENOMEM;
    }

    dev = sx_core_ioctl_get_dev(pci_prof.dev_id);
    if (!dev) {
        return -ENODEV;
    }

    return sx_core_ioctl_get_pci_profile(dev, data);
}


long ctrl_cmd_reset(struct file *file, unsigned int cmd, unsigned long data)
{
    sxd_dev_id_t   dev_id = (sxd_dev_id_t)data;
    struct sx_dev *dev;

    if (sx_core_has_predefined_devices()) {
        dev_id = get_device_id_from_fd(file);
    }

    dev = sx_core_ioctl_get_dev(dev_id);
    if (!dev) {
        return -ENODEV;
    }

    return sx_change_configuration(dev);
}
