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

#include <linux/slab.h>
#include <linux/kernel.h>

#include "memtrack.h"

static void __memtrack_kfree_validate_cb(const char                         *dealloc_src_file,
                                         int                                 dealloc_src_line,
                                         const struct memtrack_entry        *entry,
                                         const union memtrack_type_metadata *u_metadata_check)
{
    /* check if we have margins */
    if (entry->u_metadata.malloc_info.real_addr != entry->u_metadata.malloc_info.user_addr) {
        memtrack_check_margins(entry->src_file,
                               entry->src_line,
                               dealloc_src_file,
                               dealloc_src_line,
                               entry->u_metadata.malloc_info.user_addr,
                               entry->u_metadata.malloc_info.user_size);
    }
}

static void __memtrack_malloc_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "real_addr=%lx, user_addr=%lx, user_size=%lu",
             (unsigned long)entry->u_metadata.malloc_info.real_addr,
             (unsigned long)entry->u_metadata.malloc_info.user_addr,
             (unsigned long)entry->u_metadata.malloc_info.user_size);
    buff[buffsize - 1] = '\0';
}

static void __memtrack_malloc_hex_dump_cb(const struct memtrack_entry *entry, void **buff, unsigned long *buffsize)
{
    *buff = entry->u_metadata.malloc_info.user_addr;
    *buffsize = entry->u_metadata.malloc_info.user_size;
}

static const struct memtrack_entry_ops __memtrack_malloc_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_kfree_validate_cb,
    .memtrack_dump_type_data = __memtrack_malloc_dump_cb,
    .memtrack_hex_dump_params = __memtrack_malloc_hex_dump_cb
};

void * memtrack_kzalloc(const char *src_file, int src_line, size_t user_size, gfp_t gfp)
{
    void *user_addr = NULL;
    void *real_addr;

    real_addr = kzalloc(MEMTRACK_SIZE_INCLUDING_MARGINS(user_size), gfp);
    if (!ZERO_OR_NULL_PTR(real_addr)) {
        union memtrack_type_metadata u_metadata = {
            .malloc_info.real_addr = real_addr,
            .malloc_info.user_addr = MEMTRACK_MARGIN_TO_USER_PTR(real_addr),
            .malloc_info.user_size = user_size
        };

        user_addr = u_metadata.malloc_info.user_addr;

        memtrack_apply_margin_pattern(real_addr, user_size);
        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_malloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kzalloc);

void * memtrack_kcalloc(const char *src_file, int src_line, size_t n, size_t user_size, gfp_t gfp)
{
    void *user_addr = NULL;
    void *real_addr;

    real_addr = kcalloc(n, MEMTRACK_SIZE_INCLUDING_MARGINS(user_size), gfp);
    if (!ZERO_OR_NULL_PTR(real_addr)) {
        union memtrack_type_metadata u_metadata = {
            .malloc_info.real_addr = real_addr,
            .malloc_info.user_addr = MEMTRACK_MARGIN_TO_USER_PTR(real_addr),
            .malloc_info.user_size = user_size
        };

        user_addr = u_metadata.malloc_info.user_addr;

        memtrack_apply_margin_pattern(real_addr, user_size);
        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_malloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kcalloc);

void * memtrack_kmalloc(const char *src_file, int src_line, size_t user_size, gfp_t gfp)
{
    void *user_addr = NULL;
    void *real_addr;

    real_addr = kmalloc(MEMTRACK_SIZE_INCLUDING_MARGINS(user_size), gfp);
    if (!ZERO_OR_NULL_PTR(real_addr)) {
        union memtrack_type_metadata u_metadata = {
            .malloc_info.real_addr = real_addr,
            .malloc_info.user_addr = MEMTRACK_MARGIN_TO_USER_PTR(real_addr),
            .malloc_info.user_size = user_size
        };

        user_addr = u_metadata.malloc_info.user_addr;

        memtrack_apply_margin_pattern(real_addr, user_size);
        memtrack_poison_after_alloc(user_addr, user_size);

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_malloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kmalloc);

void * memtrack_kmemdup(const char *src_file, int src_line, const void *p, size_t user_size, gfp_t gfp)
{
    void *user_addr;

    user_addr = kmemdup(p, user_size, gfp);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .malloc_info.real_addr = user_addr, /* no margins */
            .malloc_info.user_addr = user_addr,
            .malloc_info.user_size = user_size
        };

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_malloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kmemdup);

char * memtrack_kstrdup(const char *src_file, int src_line, const char *s, gfp_t gfp)
{
    void *user_addr;

    user_addr = kstrdup(s, gfp);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .malloc_info.real_addr = user_addr, /* no margins */
            .malloc_info.user_addr = user_addr,
            .malloc_info.user_size = strlen(s) + 1
        };

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_malloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kstrdup);

void memtrack_kfree(const char *src_file, int src_line, const void *user_addr)
{
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata entry_metadata;

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_MALLOC,
                        (unsigned long)user_addr,
                        NULL,
                        &entry_metadata);

        memtrack_poison_before_free(entry_metadata.malloc_info.user_addr,
                                    entry_metadata.malloc_info.user_size);

        kfree(entry_metadata.malloc_info.real_addr);
    }
}
EXPORT_SYMBOL(memtrack_kfree);
