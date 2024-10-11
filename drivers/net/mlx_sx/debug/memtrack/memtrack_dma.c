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

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include "memtrack.h"

static void __memtrack_dma_coherent_validate_cb(const char                         *dealloc_src_file,
                                                int                                 dealloc_src_line,
                                                const struct memtrack_entry        *entry,
                                                const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.dma_coherent_info.dev != u_metadata_check->dma_coherent_info.dev) {
        sxd_log_mem_err("deallocated DMA coherent from the wrong device! "
                        "allocated in [%s:%d] with device %lx, "
                        "deallocated in [%s:%d] with device %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_coherent_info.dev,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_coherent_info.dev);
    }

    if (entry->u_metadata.dma_coherent_info.dma_handle != u_metadata_check->dma_coherent_info.dma_handle) {
        sxd_log_mem_err("deallocated DMA coherent with the wrong DMA handle! "
                        "allocated in [%s:%d] with DMA handle %lx, "
                        "deallocated in [%s:%d] with DMA handle %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_coherent_info.dma_handle,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_coherent_info.dma_handle);
    }

    if (entry->u_metadata.dma_coherent_info.user_size != u_metadata_check->dma_coherent_info.user_size) {
        sxd_log_mem_err("deallocated DMA coherent with the wrong size! "
                        "allocated in [%s:%d] with size %lx, "
                        "deallocated in [%s:%d] with size %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_coherent_info.user_size,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_coherent_info.user_size);
    }
}

static void __memtrack_dma_coherent_dump_cb(const struct memtrack_entry *entry,
                                            char                        *buff,
                                            int                          buffsize)
{
    snprintf(buff, buffsize - 1, "dev=%lx, user_addr=%lx, user_size=%lu, dma_handle=%lx",
             (unsigned long)entry->u_metadata.dma_coherent_info.dev,
             (unsigned long)entry->u_metadata.dma_coherent_info.user_addr,
             entry->u_metadata.dma_coherent_info.user_size,
             (unsigned long)entry->u_metadata.dma_coherent_info.dma_handle);
    buff[buffsize - 1] = '\0';
}

static void __memtrack_dma_coherent_hex_dump_cb(const struct memtrack_entry *entry,
                                                void                       **buff,
                                                unsigned long               *buffsize)
{
    *buff = entry->u_metadata.dma_coherent_info.user_addr;
    *buffsize = entry->u_metadata.dma_coherent_info.user_size;
}

static const struct memtrack_entry_ops __memtrack_dma_coherent_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_dma_coherent_validate_cb,
    .memtrack_dump_type_data = __memtrack_dma_coherent_dump_cb,
    .memtrack_hex_dump_params = __memtrack_dma_coherent_hex_dump_cb
};

void * memtrack_dma_alloc_coherent(const char    *src_file,
                                   int            src_line,
                                   struct device *dev,
                                   size_t         size,
                                   dma_addr_t    *dma_handle,
                                   gfp_t          gfp)
{
    void *user_addr;

    user_addr = dma_alloc_coherent(dev, size, dma_handle, gfp);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .dma_coherent_info.user_addr = user_addr,
            .dma_coherent_info.user_size = size,
            .dma_coherent_info.dma_handle = *dma_handle,
            .dma_coherent_info.dev = dev
        };

        memtrack_db_add(src_file,
                        src_line,
                        gfp,
                        MEMTRACK_TYPE_DMA_COHERENT,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_dma_coherent_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_dma_alloc_coherent);

void memtrack_dma_free_coherent(const char    *src_file,
                                int            src_line,
                                struct device *dev,
                                size_t         size,
                                void          *user_addr,
                                dma_addr_t     dma_handle)
{
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata check = {
            .dma_coherent_info.user_size = size,
            .dma_coherent_info.dma_handle = dma_handle,
            .dma_coherent_info.dev = dev
        };

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_DMA_COHERENT,
                        (unsigned long)user_addr,
                        &check,
                        NULL);
    }
    dma_free_coherent(dev, size, user_addr, dma_handle);
}
EXPORT_SYMBOL(memtrack_dma_free_coherent);

static bool __memtrack_dma_single_extra_key_check_cb(const struct memtrack_entry        *entry,
                                                     const union memtrack_type_metadata *u_metadata_check)
{
    /* dma_handle_t (primary key in memtrack database) is in the scope of device, so 2 devices may
     * have the same DMA handle. Adding the device as a secondary key to make the key unique. */
    return (entry->u_metadata.dma_single_info.dev == u_metadata_check->dma_single_info.dev);
}

static void __memtrack_dma_single_validate_cb(const char                         *dealloc_src_file,
                                              int                                 dealloc_src_line,
                                              const struct memtrack_entry        *entry,
                                              const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.dma_single_info.user_size != u_metadata_check->dma_single_info.user_size) {
        sxd_log_mem_err("deallocated DMA single with the wrong size! "
                        "allocated in [%s:%d] with DMA handle %lx, "
                        "deallocated in [%s:%d] with DMA handle %lx\n",
                        entry->src_file,
                        entry->src_line,
                        entry->u_metadata.dma_single_info.user_size,
                        dealloc_src_file,
                        dealloc_src_line,
                        u_metadata_check->dma_single_info.user_size);
    }
}

static void __memtrack_dma_single_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "dev=%lx, user_addr=%lx, user_size=%lu, dma_handle=%lx",
             (unsigned long)entry->u_metadata.dma_single_info.dev,
             (unsigned long)entry->u_metadata.dma_single_info.user_addr,
             (unsigned long)entry->u_metadata.dma_single_info.user_size,
             (unsigned long)entry->u_metadata.dma_single_info.dma_handle);
    buff[buffsize - 1] = '\0';
}

static void __memtrack_dma_single_hex_dump_cb(const struct memtrack_entry *entry, void **buff, unsigned long *buffsize)
{
    *buff = entry->u_metadata.dma_single_info.user_addr;
    *buffsize = entry->u_metadata.dma_single_info.user_size;
}

static const struct memtrack_entry_ops __memtrack_dma_single_ops = {
    .memtrack_extra_key_check = __memtrack_dma_single_extra_key_check_cb,
    .memtrack_validate = __memtrack_dma_single_validate_cb,
    .memtrack_dump_type_data = __memtrack_dma_single_dump_cb,
    .memtrack_hex_dump_params = __memtrack_dma_single_hex_dump_cb
};

dma_addr_t memtrack_dma_map_single(const char             *src_file,
                                   int                     src_line,
                                   struct device          *dev,
                                   void                   *user_addr,
                                   size_t                  size,
                                   enum dma_data_direction dir)
{
    dma_addr_t dma_handle;

    dma_handle = dma_map_single(dev, user_addr, size, dir);
    if (!dma_mapping_error(dev, dma_handle)) {
        union memtrack_type_metadata u_metadata = {
            .dma_single_info.dma_handle = dma_handle,
            .dma_single_info.dev = dev,
            .dma_single_info.user_addr = user_addr,
            .dma_single_info.user_size = size
        };

        memtrack_db_add(src_file,
                        src_line,
                        GFP_ATOMIC,
                        MEMTRACK_TYPE_DMA_SINGLE,
                        (unsigned long)dma_handle,
                        &u_metadata,
                        &__memtrack_dma_single_ops);
    }

    return dma_handle;
}
EXPORT_SYMBOL(memtrack_dma_map_single);

void memtrack_dma_unmap_single(const char             *src_file,
                               int                     src_line,
                               struct device          *dev,
                               dma_addr_t              addr,
                               size_t                  size,
                               enum dma_data_direction dir)
{
    if (!dma_mapping_error(dev, addr)) {
        union memtrack_type_metadata check = {
            .dma_single_info.dev = dev,
            .dma_single_info.user_size = size
        };

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_DMA_SINGLE,
                        (unsigned long)addr,
                        &check,
                        NULL);
    }

    dma_unmap_single(dev, addr, size, dir);
}
EXPORT_SYMBOL(memtrack_dma_unmap_single);

static void __memtrack_dma_pool_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "pool=%lx", (unsigned long)entry->u_metadata.dma_pool_info.dma_pool);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_dma_pool_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = NULL,
    .memtrack_dump_type_data = __memtrack_dma_pool_dump_cb,
    .memtrack_hex_dump_params = NULL
};

struct dma_pool * memtrack_dma_pool_create(const char    *src_file,
                                           int            src_line,
                                           const char    *name,
                                           struct device *dev,
                                           size_t         size,
                                           size_t         align,
                                           size_t         allocation)
{
    struct dma_pool *pool;

    pool = dma_pool_create(name, dev, size, align, allocation);
    if (!ZERO_OR_NULL_PTR(pool)) {
        union memtrack_type_metadata u_metadata = {
            .dma_pool_info.dma_pool = pool
        };
        memtrack_db_add(src_file,
                        src_line,
                        GFP_KERNEL,
                        MEMTRACK_TYPE_DMA_POOL,
                        (unsigned long)pool,
                        &u_metadata,
                        &__memtrack_dma_pool_ops);
    }

    return pool;
}
EXPORT_SYMBOL(memtrack_dma_pool_create);

void memtrack_dma_pool_destroy(const char *src_file, int src_line, struct dma_pool *pool)
{
    if (!ZERO_OR_NULL_PTR(pool)) {
        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_DMA_POOL,
                        (unsigned long)pool,
                        NULL,
                        NULL);
    }

    dma_pool_destroy(pool);
}
EXPORT_SYMBOL(memtrack_dma_pool_destroy);

static void __memtrack_dma_pool_alloc_validate_cb(const char                         *dealloc_src_file,
                                                  int                                 dealloc_src_line,
                                                  const struct memtrack_entry        *entry,
                                                  const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.dma_pool_alloc_info.dma_pool != u_metadata_check->dma_pool_alloc_info.dma_pool) {
        sxd_log_mem_err("deallocated DMA pool allocation from the wrong pool! "
                        "allocated in [%s:%d] with pool %lx, "
                        "deallocated in [%s:%d] with pool %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_pool_alloc_info.dma_pool,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_pool_alloc_info.dma_pool);
    }

    if (entry->u_metadata.dma_pool_alloc_info.dma_handle != u_metadata_check->dma_pool_alloc_info.dma_handle) {
        sxd_log_mem_err("deallocated DMA pool allocation with the wrong DMA handle! "
                        "allocated in [%s:%d] with pool %lx, "
                        "deallocated in [%s:%d] with pool %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_pool_alloc_info.dma_handle,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_pool_alloc_info.dma_handle);
    }
}

static void __memtrack_dma_pool_alloc_dump_cb(const struct memtrack_entry *entry,
                                              char                        *buff,
                                              int                          buffsize)
{
    snprintf(buff, buffsize - 1, "pool=%lx, user_addr=%lx, dma_handle=%lx",
             (unsigned long)entry->u_metadata.dma_pool_alloc_info.dma_pool,
             (unsigned long)entry->u_metadata.dma_pool_alloc_info.user_addr,
             (unsigned long)entry->u_metadata.dma_pool_alloc_info.dma_handle);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_dma_pool_alloc_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_dma_pool_alloc_validate_cb,
    .memtrack_dump_type_data = __memtrack_dma_pool_alloc_dump_cb,
    .memtrack_hex_dump_params = NULL
};

void * memtrack_dma_pool_alloc(const char      *src_file,
                               int              src_line,
                               struct dma_pool *pool,
                               gfp_t            mem_flags,
                               dma_addr_t      *handle)
{
    void *user_addr;

    user_addr = dma_pool_alloc(pool, mem_flags, handle);
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata u_metadata = {
            .dma_pool_alloc_info.user_addr = user_addr,
            .dma_pool_alloc_info.dma_pool = pool,
            .dma_pool_alloc_info.dma_handle = *handle
        };

        memtrack_db_add(src_file,
                        src_line,
                        mem_flags,
                        MEMTRACK_TYPE_DMA_POOL_ALLOC,
                        (unsigned long)user_addr,
                        &u_metadata,
                        &__memtrack_dma_pool_alloc_ops);
    }

    return user_addr;
}
EXPORT_SYMBOL(memtrack_dma_pool_alloc);

void memtrack_dma_pool_free(const char *src_file, int src_line, struct dma_pool *pool, void *user_addr,
                            dma_addr_t addr)
{
    if (!ZERO_OR_NULL_PTR(user_addr)) {
        union memtrack_type_metadata check = {
            .dma_pool_alloc_info.dma_pool = pool,
            .dma_pool_alloc_info.dma_handle = addr
        };

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_DMA_POOL_ALLOC,
                        (unsigned long)user_addr,
                        &check,
                        NULL);
    }

    dma_pool_free(pool, user_addr, addr);
}
EXPORT_SYMBOL(memtrack_dma_pool_free);

static void __memtrack_dma_map_sg_validate_cb(const char                         *dealloc_src_file,
                                              int                                 dealloc_src_line,
                                              const struct memtrack_entry        *entry,
                                              const union memtrack_type_metadata *u_metadata_check)
{
    if (entry->u_metadata.dma_map_sg_info.dev != u_metadata_check->dma_map_sg_info.dev) {
        sxd_log_mem_err("deallocated DMA SG allocation with the wrong device! "
                        "allocated in [%s:%d] with device %lx, "
                        "deallocated in [%s:%d] with device %lx\n",
                        entry->src_file,
                        entry->src_line,
                        (unsigned long)entry->u_metadata.dma_map_sg_info.dev,
                        dealloc_src_file,
                        dealloc_src_line,
                        (unsigned long)u_metadata_check->dma_map_sg_info.dev);
    }

    if (entry->u_metadata.dma_map_sg_info.nents != u_metadata_check->dma_map_sg_info.nents) {
        sxd_log_mem_err("deallocated DMA SG allocation with the wrong number of entries! "
                        "allocated in [%s:%d] with number of entries %d, "
                        "deallocated in [%s:%d] with number of entries %d\n",
                        entry->src_file,
                        entry->src_line,
                        entry->u_metadata.dma_map_sg_info.nents,
                        dealloc_src_file,
                        dealloc_src_line,
                        u_metadata_check->dma_map_sg_info.nents);
    }
}

static void __memtrack_dma_map_sg_dump_cb(const struct memtrack_entry *entry, char *buff, int buffsize)
{
    snprintf(buff, buffsize - 1, "sg=%lx, dev=%lx, entries=%lu",
             (unsigned long)entry->u_metadata.dma_map_sg_info.sg,
             (unsigned long)entry->u_metadata.dma_map_sg_info.dev,
             (unsigned long)entry->u_metadata.dma_map_sg_info.nents);
    buff[buffsize - 1] = '\0';
}

static const struct memtrack_entry_ops __memtrack_dma_map_sg_ops = {
    .memtrack_extra_key_check = NULL,
    .memtrack_validate = __memtrack_dma_map_sg_validate_cb,
    .memtrack_dump_type_data = __memtrack_dma_map_sg_dump_cb,
    .memtrack_hex_dump_params = NULL
};

int memtrack_dma_map_sg(const char             *src_file,
                        int                     src_line,
                        struct device          *dev,
                        struct scatterlist     *sg,
                        int                     nents,
                        enum dma_data_direction dir)
{
    int ret;

    ret = dma_map_sg(dev, sg, nents, dir); /* returns 0 on error */
    if (ret) { /* no error */
        union memtrack_type_metadata u_metadata = {
            .dma_map_sg_info.sg = sg,
            .dma_map_sg_info.dev = dev,
            .dma_map_sg_info.nents = nents
        };

        memtrack_db_add(src_file,
                        src_line,
                        GFP_KERNEL,
                        MEMTRACK_TYPE_DMA_MAP_SG,
                        (unsigned long)sg,
                        &u_metadata,
                        &__memtrack_dma_map_sg_ops);
    }

    return ret;
}
EXPORT_SYMBOL(memtrack_dma_map_sg);

void memtrack_dma_unmap_sg(const char             *src_file,
                           int                     src_line,
                           struct device          *dev,
                           struct scatterlist     *sg,
                           int                     nents,
                           enum dma_data_direction dir)
{
    if (!ZERO_OR_NULL_PTR(sg)) {
        union memtrack_type_metadata check = {
            .dma_map_sg_info.dev = dev,
            .dma_map_sg_info.nents = nents
        };

        memtrack_db_del(src_file,
                        src_line,
                        MEMTRACK_TYPE_DMA_MAP_SG,
                        (unsigned long)sg,
                        &check,
                        NULL);
    }
    dma_unmap_sg(dev, sg, nents, dir);
}
EXPORT_SYMBOL(memtrack_dma_unmap_sg);
