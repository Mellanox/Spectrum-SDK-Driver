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
#include "memtrack.h"

MODULE_AUTHOR("NVIDIA");
MODULE_DESCRIPTION("Memory allocations tracking");
MODULE_LICENSE("GPL");

int init_module(void)
{
    int err = 0;

    sxd_log_mem_info("initializing module\n");

    err = memtrack_db_create();
    if (err) {
        sxd_log_mem_err("failed to create database (err=%d)\n", err);
        goto out;
    }

    err = memtrack_debugfs_create();
    if (err) {
        sxd_log_mem_err("failed to create debugfs entries (err=%d)\n", err);
        goto out_db_destroy;
    }

    return 0;

out_db_destroy:
    memtrack_db_destroy();

out:
    return err;
}

void cleanup_module(void)
{
    memtrack_debugfs_destroy();
    memtrack_db_destroy();
    sxd_log_mem_info("cleanup module\n");
}
