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

#include <linux/sched.h>
#include <linux/vmalloc.h>
#include "memtrack.h"

/* prime: http://www.utm.edu/research/primes/lists/2small/0bit.html */
#define MEMTRACK_HASH_SZ ((1 << 15) - 19)
#define MEMTRACK_HASH(val) ((val) % MEMTRACK_HASH_SZ)

struct memtrack_db_per_type_info {
    struct list_head list;
    int              count;
};

struct memtrack_db {
    struct list_head                 hashed_list[MEMTRACK_HASH_SZ];
    struct memtrack_db_per_type_info per_type_info[MEMTRACK_TYPE_MAX];
    spinlock_t                       lock;
};

static struct memtrack_db *__memtrack_db;
static struct kmem_cache  *__memtrack_cache;

static void __memtrack_safe_strcpy(char *dst, const char *src, size_t dst_size)
{
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static void __memtrack_file_name_from_fullpath(const char *fullpath, char *filename)
{
    const char *src_file_name_only;

    src_file_name_only = strrchr(fullpath, '/');
    if (src_file_name_only) {
        src_file_name_only++;
    } else {
        src_file_name_only = fullpath;
    }

    __memtrack_safe_strcpy(filename, src_file_name_only, MEMTRACK_FILENAME_MAX_SIZE);
}

static struct memtrack_entry
* __memtrack_db_alloc_entry(const char                         *src_file,
                            int                                 src_line,
                            gfp_t                               gfp,
                            enum memtrack_types                 type,
                            unsigned long                       key,
                            const union memtrack_type_metadata *u_metadata,
                            const struct memtrack_entry_ops    *ops)
{
    struct memtrack_entry *entry;
    gfp_t                  entry_alloc_gfp = (gfp & GFP_ATOMIC) ? GFP_ATOMIC : GFP_KERNEL;

    entry = kmem_cache_alloc(__memtrack_cache, entry_alloc_gfp);
    if (unlikely(!entry)) {
        sxd_log_mem_err("failed to allocate entry! [%s:%u]\n", src_file, src_line);
        dump_stack();
        return NULL;
    }

    __memtrack_file_name_from_fullpath(src_file, entry->src_file);
    entry->src_line = src_line;
    entry->pid = current->pid;
    __memtrack_safe_strcpy(entry->process_name, current->comm, sizeof(entry->process_name));
    atomic_set(&entry->refcnt, 1);
    entry->timestamp = jiffies;
    entry->type = type;
    entry->key = key;
    memcpy(&entry->u_metadata, u_metadata, sizeof(entry->u_metadata));
    entry->ops = ops;
    INIT_LIST_HEAD(&entry->hashed_list);
    INIT_LIST_HEAD(&entry->list);
    return entry;
}

void __memtrack_inc_ref(struct memtrack_entry *entry)
{
    atomic_inc(&entry->refcnt);
}

void __memtrack_dec_ref(struct memtrack_entry *entry)
{
    if (atomic_dec_and_test(&entry->refcnt)) {
        kmem_cache_free(__memtrack_cache, entry);
    }
}

static struct memtrack_db_per_type_info * __memtrack_db_get_per_type_info(enum memtrack_types type)
{
    WARN_ON(type < 0 || type >= MEMTRACK_TYPE_MAX);
    return &__memtrack_db->per_type_info[type];
}

static void __memtrack_db_attach_entry(struct memtrack_entry *entry)
{
    struct memtrack_db_per_type_info *pti = NULL;
    unsigned long                     flags;
    unsigned short                    hash;

    hash = memtrack_db_hash_get(entry->key);
    pti = __memtrack_db_get_per_type_info(entry->type);
    spin_lock_irqsave(&__memtrack_db->lock, flags);
    list_add(&entry->hashed_list, &__memtrack_db->hashed_list[hash]);
    list_add(&entry->list, &pti->list);
    pti->count++;
    spin_unlock_irqrestore(&__memtrack_db->lock, flags);
}

static void __memtrack_db_detach_entry(struct memtrack_entry *entry)
{
    struct memtrack_db_per_type_info *pti = __memtrack_db_get_per_type_info(entry->type);

    list_del(&entry->hashed_list);
    list_del(&entry->list);
    pti->count--;

    WARN_ON(pti->count < 0);
}

unsigned short memtrack_db_hash_get(unsigned long key)
{
#if MEMTRACK_HASH_SZ > 0xffff
#error "hash range is larger than function's return value!"
#endif
    return MEMTRACK_HASH(key);
}

void memtrack_db_add(const char                         *src_file,
                     int                                 src_line,
                     gfp_t                               gfp,
                     enum memtrack_types                 type,
                     unsigned long                       key,
                     const union memtrack_type_metadata *u_metadata,
                     const struct memtrack_entry_ops    *ops)
{
    struct memtrack_entry *entry = NULL;

    WARN_ON(!u_metadata);
    WARN_ON(!ops || !ops->memtrack_dump_type_data);

    entry = __memtrack_db_alloc_entry(src_file, src_line, gfp, type, key, u_metadata, ops);
    if (unlikely(!entry)) {
        sxd_log_mem_err("failed to create allocation entry\n");
        return;
    }

    __memtrack_db_attach_entry(entry);
}

void memtrack_db_del(const char                         *src_file,
                     int                                 src_line,
                     enum memtrack_types                 type,
                     unsigned long                       key,
                     const union memtrack_type_metadata *u_metadata_check,
                     union memtrack_type_metadata       *u_metadata_entry)
{
    struct memtrack_entry *entry;
    char                   filename[MEMTRACK_FILENAME_MAX_SIZE];
    unsigned long          flags;
    bool                   found_exact = false;
    unsigned short         hash;

    __memtrack_file_name_from_fullpath(src_file, filename);
    hash = memtrack_db_hash_get(key);

    spin_lock_irqsave(&__memtrack_db->lock, flags);
    list_for_each_entry(entry, &__memtrack_db->hashed_list[hash], hashed_list) {
        if ((entry->type == type) && (entry->key == key) &&
            (!entry->ops->memtrack_extra_key_check || entry->ops->memtrack_extra_key_check(entry, u_metadata_check))) {
            /* found an exact match! */
            __memtrack_db_detach_entry(entry);
            found_exact = true;
            break;
        }
    }
    spin_unlock_irqrestore(&__memtrack_db->lock, flags);

    if (unlikely(!found_exact)) {
        sxd_log_mem_err("[%s:%d] trying to deallocate entry that does not exist "
                        "(key=0x%lx, type=%s)\n",
                        filename,
                        src_line,
                        key,
                        memtrack_type_str(type));

        return; /* if no exact match, don't continue the flow */
    }

    if (entry->ops->memtrack_validate) {
        entry->ops->memtrack_validate(filename, src_line, entry, u_metadata_check);
    }

    if (u_metadata_entry) {
        memcpy(u_metadata_entry, &entry->u_metadata, sizeof(*u_metadata_entry));
    }

    __memtrack_dec_ref(entry);
}

void memtrack_db_init_debugfs_list(struct list_head *debugfs_list)
{
    struct memtrack_entry            *entry;
    struct memtrack_db_per_type_info *pti;
    unsigned long                     flags;
    int                               i;

    spin_lock_irqsave(&__memtrack_db->lock, flags);
    for (i = 0; i < MEMTRACK_TYPE_MAX; i++) {
        pti = __memtrack_db_get_per_type_info(i);

        list_for_each_entry(entry, &pti->list, list) {
            list_add_tail(&entry->debugfs_list, debugfs_list);
            __memtrack_inc_ref(entry);
        }
    }
    spin_unlock_irqrestore(&__memtrack_db->lock, flags);
}

void memtrack_db_deinit_debugfs_list(struct list_head *debugfs_list)
{
    struct memtrack_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, debugfs_list, debugfs_list) {
        list_del(&entry->debugfs_list);
        __memtrack_dec_ref(entry);
    }
}

int memtrack_db_create(void)
{
    struct memtrack_db_per_type_info *pti = NULL;
    int                               i;

    WARN_ON(__memtrack_db);
    WARN_ON(__memtrack_cache);

    /* create a cache for the memtrack_entry structures */
    __memtrack_cache = kmem_cache_create("memtrack_entry",
                                         sizeof(struct memtrack_entry), 0,
                                         SLAB_HWCACHE_ALIGN, NULL);
    if (!__memtrack_cache) {
        sxd_log_mem_err("failed to allocate cache\n");
        goto out_err;
    }

    __memtrack_db = vmalloc(sizeof(struct memtrack_db));
    if (!__memtrack_db) {
        sxd_log_mem_err("failed to allocate database\n");
        goto out_err;
    }

    spin_lock_init(&__memtrack_db->lock);
    for (i = 0; i < MEMTRACK_HASH_SZ; i++) {
        INIT_LIST_HEAD(&__memtrack_db->hashed_list[i]);
    }

    for (i = 0; i < MEMTRACK_TYPE_MAX; i++) {
        pti = __memtrack_db_get_per_type_info(i);

        INIT_LIST_HEAD(&pti->list);
        pti->count = 0;
    }

    return 0;

out_err:
    if (__memtrack_db) {
        vfree(__memtrack_db);
        __memtrack_db = NULL;
    }

    if (__memtrack_cache) {
        kmem_cache_destroy(__memtrack_cache);
        __memtrack_cache = NULL;
    }

    return -ENOMEM;
}

void memtrack_db_destroy(void)
{
    struct memtrack_entry            *entry = NULL, *tmp = NULL;
    struct memtrack_db_per_type_info *pti = NULL;
    char                              type_info_str[256];
    unsigned long                     flags;
    int                               i, leaks = 0;
    void                             *user_addr;
    unsigned long                     user_size;

    spin_lock_irqsave(&__memtrack_db->lock, flags);

    for (i = 0; i < MEMTRACK_TYPE_MAX; i++) {
        pti = __memtrack_db_get_per_type_info(i);

        sxd_log_mem_info("%d) %s:\n", i + 1, memtrack_type_str(i));
        list_for_each_entry_safe(entry, tmp, &pti->list, list) {
            entry->ops->memtrack_dump_type_data(entry, type_info_str, sizeof(type_info_str));

            sxd_log_mem_err("LEAK ==> file [%s:%d], process [%s:%d] [%s]\n",
                            entry->src_file,
                            entry->src_line,
                            entry->process_name,
                            entry->pid,
                            type_info_str);

            if (entry->ops->memtrack_hex_dump_params) {
                entry->ops->memtrack_hex_dump_params(entry, &user_addr, &user_size);
                print_hex_dump(KERN_INFO, "   ", DUMP_PREFIX_OFFSET, 16, 1, user_addr, user_size, 1);
            }

            __memtrack_dec_ref(entry);
            leaks++;
        }
    }

    spin_unlock_irqrestore(&__memtrack_db->lock, flags);

    if (leaks == 0) {
        sxd_log_mem_info("Summary: No leak(s) detected\n");
    } else {
        sxd_log_mem_err("Summary: %d leak(s) were found\n", leaks);
    }

    vfree(__memtrack_db);
    __memtrack_db = NULL;

    kmem_cache_destroy(__memtrack_cache);
    __memtrack_cache = NULL;
}
