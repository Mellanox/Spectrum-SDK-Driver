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

#include <linux/io-mapping.h>
#include "memtrack.h"

static void __memtrack_iomap_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "user_addr=%lx", (unsigned long)entry->u_metadata.io_map_info.user_addr);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_iomap_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = NULL,
    .memtrack_dump_type_data = __memtrack_iomap_dump_cb,
    .memtrack_hex_dump_params = NULL
};

void __iomem * memtrack_ioremap(const char *src_file, int src_line, resource_size_t offset, unsigned long size)
{
    void __iomem *user_addr;

    user_addr = ioremap(offset, size);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .io_map_info.user_addr = user_addr
        };

        memtrack_db_add(src_file,
                        src_line,
                        GFP_KERNEL,
                        MEMTRACK_TYPE_IOMAP,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_iomap_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_ioremap);

void memtrack_iounmap(const char *src_file, int src_line, void __iomem *user_addr)
{
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_IOMAP,
                        (unsigned long)user_addr,
                        NULL,
                        NULL);
    }

    iounmap(user_addr);
}
EXPORT_SYMBOL(memtrack_iounmap);
