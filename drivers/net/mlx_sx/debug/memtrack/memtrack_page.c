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
#include <linux/mm.h>
#include "memtrack.h"

static void __memtrack_page_validate_cb(const char                         *dealloc_src_file,
                                        int                                 dealloc_src_line,
                                        const struct memtrack_entry        *entry,
                                        const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.page_info.order != u_metadata_check->page_info.order) {
        sxd_log_mem_err("deallocated page with the wrong order value! "
                        "allocated in [%s:%d] with order %u,, "
                        "deallocated in [%s:%d] with order %u\n",
                        entry->src_file,
                        entry->src_line,
                        entry->u_metadata.page_info.order,
                        dealloc_src_file,
                        dealloc_src_line,
                        u_metadata_check->page_info.order);
    }
}

static void __memtrack_page_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "page=%lx, order=%lu",
             (unsigned long)entry->u_metadata.page_info.user_addr,
             (unsigned long)entry->u_metadata.page_info.order);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_page_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_page_validate_cb,
    .memtrack_dump_type_data = __memtrack_page_dump_cb,
    .memtrack_hex_dump_params = NULL
};

struct page * memtrack_alloc_pages(const char *src_file, int src_line, gfp_t gfp, unsigned int order)
{
    struct page *user_addr;

    user_addr = alloc_pages(gfp, order);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .page_info.user_addr = user_addr,
            .page_info.order = order
        };

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_PAGE,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_page_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_alloc_pages);

void memtrack___free_pages(const char *src_file, int src_line, struct page *page, unsigned int order)
{
    if (!ZERO_OR_NULL_PTR(page)) {
        union memtrack_type_metadata check = {
            .page_info.order = order
        };

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_PAGE,
                        (unsigned long)page,
                        &check,
                        NULL);
    }

    __free_pages(page, order);
}
EXPORT_SYMBOL(memtrack___free_pages);
