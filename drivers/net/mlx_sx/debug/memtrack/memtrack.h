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

#ifndef H_MEMTRACK_H
#define H_MEMTRACK_H

#include <linux/types.h>
#include <linux/slab.h>

#if !defined(ZERO_OR_NULL_PTR)
#error ZERO_OR_NULL_PTR not defined!
#endif /* !defined(ZERO_OR_NULL_PTR) */

#define sxd_log_mem(verbosity, prefix, fmt, arg ...) \
    printk(verbosity "sxd_memtrack: " prefix fmt, ## arg)
#define sxd_log_mem_err(fmt, arg ...)     sxd_log_mem(KERN_ERR, "[error] ", fmt, ## arg)
#define sxd_log_mem_warning(fmt, arg ...) sxd_log_mem(KERN_WARNING, "", fmt, ## arg)
#define sxd_log_mem_notice(fmt, arg ...)  sxd_log_mem(KERN_NOTICE, "", fmt, ## arg)
#define sxd_log_mem_info(fmt, arg ...)    sxd_log_mem(KERN_INFO, "", fmt, ## arg)
#define sxd_log_mem_err_dump_stack(fmt, arg ...) \
    do {                                         \
        sxd_log_mem_err(fmt, ## arg);            \
        dump_stack();                            \
    } while (0)
#define sxd_log_mem_hex_dump(prefix, buff, size) \
    print_hex_dump(KERN_NOTICE, (prefix), DUMP_PREFIX_OFFSET, 16, 1, (buff), (size), 0);

#define MEMTRACK_FILENAME_MAX_SIZE     (32)
#define MEMTRACK_PROCESS_NAME_MAX_SIZE (16)
#define MEMTRACK_MARGIN_SIZE           (16)
#define MEMTRACK_SIZE_INCLUDING_MARGINS(size) ((size) + (2 * MEMTRACK_MARGIN_SIZE))
#define MEMTRACK_MARGIN_TO_USER_PTR(ptr)      ((void*)(((unsigned long)(ptr)) + MEMTRACK_MARGIN_SIZE))
#define MEMTRACK_USER_TO_MARGIN_PTR(ptr)      ((void*)(((unsigned long)(ptr)) - MEMTRACK_MARGIN_SIZE))

enum memtrack_types {
    MEMTRACK_TYPE_MALLOC,         /* kmalloc(), kcalloc(), kzalloc(), kstrdup(), kmemdup(), kfree() */
    MEMTRACK_TYPE_VMALLOC,        /* vmalloc(), vzalloc(), vmalloc_user(), vfree() */
    MEMTRACK_TYPE_CACHE,          /* kmem_cache_create(), kmem_cache_destroy() */
    MEMTRACK_TYPE_CACHE_ALLOC,    /* kmem_cache_alloc(), kmem_cache_zalloc(), kmem_cache_free() */
    MEMTRACK_TYPE_IOMAP,          /* ioremap(), iounmap() */
    MEMTRACK_TYPE_PAGE,           /* alloc_pages(), __free_pages() */
    MEMTRACK_TYPE_DMA_COHERENT,   /* dma_alloc_coherent(), dma_free_coherent() */
    MEMTRACK_TYPE_DMA_SINGLE,     /* dma_map_single(), dma_unmap_single() */
    MEMTRACK_TYPE_DMA_POOL,       /* dma_pool_create(), dma_pool_destroy() */
    MEMTRACK_TYPE_DMA_POOL_ALLOC, /* dma_pool_alloc(), dma_pool_free() */
    MEMTRACK_TYPE_DMA_MAP_SG,     /* dma_map_sg() / dma_unmap_sg() */
    MEMTRACK_TYPE_MAX
};

union memtrack_type_metadata {
    struct {
        void         *user_addr; /* [KEY] address returned to the user */
        void         *real_addr;
        unsigned long user_size; /* size requested by user */
    } malloc_info; /* MEMTRACK_TYPE_MALLOC */
    struct {
        void         *user_addr; /* [KEY] address returned to the user */
        void         *real_addr;
        unsigned long user_size; /* size requested by user */
    } vmalloc_info; /* MEMTRACK_TYPE_VMALLOC */
    struct {
        struct kmem_cache *cache; /* [KEY] the cache the was created and returned to user */
    } cache_info; /* MEMTRACK_TYPE_CACHE */
    struct {
        struct kmem_cache *cache; /* the cache from which allocation was invoked */
        void              *user_addr; /* [KEY] address returned to the user */
    } cache_alloc_info; /* MEMTRACK_TYPE_CACHE_ALLOC */
    struct {
        void *user_addr; /* [KEY] address returned to the user */
    } io_map_info; /* MEMTRACK_TYPE_IOMAP */
    struct {
        void        *user_addr; /* [KEY] address returned to the user */
        unsigned int order; /* 2^order of allocated pages */
    } page_info; /* MEMTRACK_TYPE_PAGE */
    struct {
        void          *user_addr; /* [KEY] address returned to the user */
        unsigned long  user_size; /* size of DMA mapping requested by the user */
        struct device *dev; /* the device on which the DMA coherent mapping was requested */
        dma_addr_t     dma_handle; /* DMA handle */
    } dma_coherent_info; /* MEMTRACK_TYPE_DMA_COHERENT */
    struct {
        dma_addr_t     dma_handle; /* [KEY] DMA handle */
        struct device *dev; /* the device on which the DMA mapping was requested */
        void          *user_addr;
        unsigned long  user_size; /* size of DMA mapping requested by the user */
    } dma_single_info; /* MEMTRACK_TYPE_DMA_SINGLE */
    struct {
        struct dma_pool *dma_pool; /* [KEY] the dma_pool the was created */
    } dma_pool_info; /* MEMTRACK_TYPE_DMA_POOL */
    struct {
        void            *user_addr; /* [KEY] address returned to the user */
        struct dma_pool *dma_pool; /* the dma_pool from which the allocation was requested */
        dma_addr_t       dma_handle; /* the DMA handle returned by the allocation */
    } dma_pool_alloc_info; /* MEMTRACK_TYPE_DMA_POOL_ALLOC */
    struct {
        struct scatterlist *sg; /* [KEY] scatter-list that was initialized */
        struct device      *dev; /* the device on which the DMA mapping was requested */
        int                 nents; /* number of entries in the scatter list array */
    } dma_map_sg_info; /* MEMTRACK_TYPE_DMA_MAP_SG */
};

struct memtrack_entry;
struct memtrack_entry_ops {
    void (*memtrack_dump_type_data)(const struct memtrack_entry *entry,
                                    char                        *buff,
                                    int                          buffsize);
    bool (*memtrack_extra_key_check)(const struct memtrack_entry        *entry,
                                     const union memtrack_type_metadata *u_metadata);
    void (*memtrack_validate)(const char                         *dealloc_src_file,
                              int                                 dealloc_src_line,
                              const struct memtrack_entry        *entry,
                              const union memtrack_type_metadata *u_metadata_check);
    void (*memtrack_hex_dump_params)(const struct memtrack_entry *entry,
                                     void                       **buff,
                                     unsigned long               *buffsize);
};


struct memtrack_entry {
    char             src_file[MEMTRACK_FILENAME_MAX_SIZE];
    int              src_line;
    pid_t            pid;
    char             process_name[MEMTRACK_PROCESS_NAME_MAX_SIZE];
    struct list_head hashed_list; /* list of all allocations with the same hash (per type) */
    struct list_head list; /* list of all allocations in the database (per type) */
    struct list_head debugfs_list;
    atomic_t         refcnt;
    unsigned long    timestamp;

    /* key to the hash table:
     * MEMTRACK_TYPE_MALLOC:         user_addr
     * MEMTRACK_TYPE_VMALLOC:        user_addr
     * MEMTRACK_TYPE_CACHE:          cache pointer
     * MEMTRACK_TYPE_CACHE_ALLOC:    user_addr
     * MEMTRACK_TYPE_IOMAP:          user_addr
     * MEMTRACK_TYPE_PAGE:           user_addr
     * MEMTRACK_TYPE_DMA_COHERENT:   user_addr
     * MEMTRACK_TYPE_DMA_SINGLE:     DMA address
     * MEMTRACK_TYPE_DMA_POOL:       pool pointer
     * MEMTRACK_TYPE_DMA_POOL_ALLOC: user_addr
     * MEMTRACK_TYPE_DMA_MAP_SG:     scatter_list pointer
     */
    unsigned long                    key;
    enum memtrack_types              type;
    union memtrack_type_metadata     u_metadata;
    const struct memtrack_entry_ops *ops;
};

/* Debug FS */
int memtrack_debugfs_create(void);
void memtrack_debugfs_destroy(void);

/* database API */
int memtrack_db_create(void);
void memtrack_db_destroy(void);

unsigned short memtrack_db_hash_get(unsigned long key);
void memtrack_db_add(const char                         *src_file,
                     int                                 src_line,
                     gfp_t                               gfp,
                     enum memtrack_types                 type,
                     unsigned long                       key,
                     const union memtrack_type_metadata *u_metadata,
                     const struct memtrack_entry_ops    *ops);

void memtrack_db_del(const char                         *src_file,
                     int                                 src_line,
                     enum memtrack_types                 type,
                     unsigned long                       key,
                     const union memtrack_type_metadata *u_metadata_check,
                     union memtrack_type_metadata       *u_metadata_entry);

void memtrack_db_init_debugfs_list(struct list_head *debugfs_list);
void memtrack_db_deinit_debugfs_list(struct list_head *debugfs_list);

/* helpers */
const char * memtrack_type_str(enum memtrack_types type);
void memtrack_poison_after_alloc(void *user_addr, unsigned long user_size);
void memtrack_poison_before_free(void *user_addr, unsigned long user_size);
void memtrack_apply_margin_pattern(void *real_addr, unsigned long user_size);
void memtrack_check_margins(const char   *alloc_src_file,
                            int           alloc_src_line,
                            const char   *free_src_file,
                            int           free_src_line,
                            void         *user_addr,
                            unsigned long user_size);

#endif /* ifndef H_MEMTRACK_H */
