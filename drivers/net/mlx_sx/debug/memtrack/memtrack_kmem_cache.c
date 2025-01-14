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

#include <linux/version.h>
#include <linux/slab.h>
#include "memtrack.h"

static void __memtrack_cache_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "cache=%lx", (unsigned long)entry->u_metadata.cache_info.cache);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_cache_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = NULL,
    .memtrack_dump_type_data = __memtrack_cache_dump_cb,
    .memtrack_hex_dump_params = NULL
};

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0))
struct kmem_cache * memtrack_kmem_cache_create(const char   *src_file,
                                               int           src_line,
                                               const char   *name,
                                               size_t        size,
                                               size_t        align,
                                               unsigned long flags,
                                               void (       *ctor )(void *))
#else
struct kmem_cache * memtrack_kmem_cache_create(const char  *src_file,
                                               int          src_line,
                                               const char  *name,
                                               unsigned int size,
                                               unsigned int align,
                                               slab_flags_t flags,
                                               void (      *ctor )(void *))
#endif /* LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0) */
{
    struct kmem_cache *cache;

    cache = kmem_cache_create(name, size, align, flags, ctor);
    if (!ZERO_OR_NULL_PTR(cache)) {
        union memtrack_type_metadata u_metadata = {
            .cache_info.cache = cache
        };

        memtrack_db_add(src_file,
                        src_line,
                        GFP_KERNEL,
                        MEMTRACK_TYPE_CACHE,
                        (unsigned long)cache,
                        &u_metadata,
                        &__memtrack_cache_ops);
    }

    return cache;
}
EXPORT_SYMBOL(memtrack_kmem_cache_create);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0))
struct kmem_cache * memtrack_kmem_cache_create_usercopy(const char  *src_file,
                                                        int          src_line,
                                                        const char  *name,
                                                        unsigned int size,
                                                        unsigned int align,
                                                        slab_flags_t flags,
                                                        unsigned int useroffset,
                                                        unsigned int usersize,
                                                        void (      *ctor )(void *))
{
    struct kmem_cache *cache;

    cache = kmem_cache_create_usercopy(name, size, align, flags, useroffset, usersize, ctor);
    if (!ZERO_OR_NULL_PTR(cache)) {
        union memtrack_type_metadata u_metadata = {
            .cache_info.cache = cache
        };

        memtrack_db_add(src_file,
                        src_line,
                        GFP_KERNEL,
                        MEMTRACK_TYPE_CACHE,
                        (unsigned long)cache,
                        &u_metadata,
                        &__memtrack_cache_ops);
    }

    return cache;
}
EXPORT_SYMBOL(memtrack_kmem_cache_create_usercopy);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0) */

void memtrack_kmem_cache_destroy(const char *src_file, int src_line, struct kmem_cache *cache)
{
    if (!ZERO_OR_NULL_PTR(cache)) {
        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_CACHE,
                        (unsigned long)cache,
                        NULL,
                        NULL);
    }

    kmem_cache_destroy(cache);
}
EXPORT_SYMBOL(memtrack_kmem_cache_destroy);

static void __memtrack_cache_alloc_validate_cb(const char                         *dealloc_src_file,
                                               int                                 dealloc_src_line,
                                               const struct memtrack_entry        *entry,
                                               const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.cache_alloc_info.cache != u_metadata_check->cache_alloc_info.cache) {
        sxd_log_mem_err("deallocated cache entry from the wrong cache! "
                        "allocated in [%s:%d] from cache %lx, "
                        "deallocated in [%s:%d] from cache %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.cache_alloc_info.cache,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->cache_alloc_info.cache);
    }
}

static void __memtrack_cache_alloc_dump_cb(const struct memtrack_entry *entry,
                                           char                        *buff,
                                           int                          buffsize)
{
    snprintf(buff, buffsize - 1, "cache=%lx, user_addr=%lx",
             (unsigned long)entry->u_metadata.cache_alloc_info.cache,
             (unsigned long)entry->u_metadata.cache_alloc_info.user_addr);
    buff[buffsize - 1] = '\0';
}

static void __memtrack_cache_alloc_hex_dump_cb(const struct memtrack_entry *entry, void **buff,
                                               unsigned long *buffsize)
{
    *buff = entry->u_metadata.cache_alloc_info.user_addr;
    *buffsize = kmem_cache_size(entry->u_metadata.cache_alloc_info.cache);
}

static const struct memtrack_entry_ops __memtrack_cache_alloc_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_cache_alloc_validate_cb,
    .memtrack_dump_type_data = __memtrack_cache_alloc_dump_cb,
    .memtrack_hex_dump_params = __memtrack_cache_alloc_hex_dump_cb
};

void * memtrack_kmem_cache_alloc(const char *src_file, int src_line, struct kmem_cache *cache, gfp_t gfp)
{
    void *user_addr;

    user_addr = kmem_cache_alloc(cache, gfp);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .cache_alloc_info.user_addr = user_addr,
            .cache_alloc_info.cache = cache
        };

        memtrack_poison_after_alloc(user_addr, kmem_cache_size(cache));
        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_CACHE_ALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_cache_alloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kmem_cache_alloc);

void * memtrack_kmem_cache_zalloc(const char *src_file, int src_line, struct kmem_cache *cache, gfp_t gfp)
{
    void *user_addr = NULL;

    user_addr = kmem_cache_zalloc(cache, gfp);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .cache_alloc_info.user_addr = user_addr,
            .cache_alloc_info.cache = cache
        };

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_CACHE_ALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_cache_alloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_kmem_cache_zalloc);

void memtrack_kmem_cache_free(const char *src_file, int src_line, struct kmem_cache *cache, void *user_addr)
{
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata check = {
            .cache_alloc_info.cache = cache
        };
        union memtrack_type_metadata entry_metadata;

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_CACHE_ALLOC,
                        (unsigned long)user_addr,
                        &check,
                        &entry_metadata);

        memtrack_poison_before_free(entry_metadata.cache_alloc_info.user_addr,
                                    kmem_cache_size(entry_metadata.cache_alloc_info.cache));
    }

    kmem_cache_free(cache, user_addr);
}
EXPORT_SYMBOL(memtrack_kmem_cache_free);
