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

#ifndef __mtrack_h_
#define __mtrack_h_

#ifdef SX_MEMTRACK_MODULE
/* when compiling memtrack module - it should not compile with all macros of wrappers! */
#else /* SX_MEMTRACK_MODULE */

/* must include all headers that contain the original functions
 * because if that are included later, the definitions will be replaced
 * with the macros and then we have compilation errors.
 */
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/io-mapping.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/mm.h>

#ifdef kzalloc
#undef kzalloc
#endif
void *memtrack_kzalloc(const char *src_file,
                       int src_line,
                       size_t user_size,
                       gfp_t gfp);
#define kzalloc(size, gfp) memtrack_kzalloc(__FILE__, __LINE__, size, gfp)

#ifdef kcalloc
#undef kcalloc
#endif
void *memtrack_kcalloc(const char *src_file,
                       int src_line,
                       size_t n,
                       size_t size,
                       gfp_t gfp);
#define kcalloc(n, size, gfp) memtrack_kcalloc(__FILE__, __LINE__, n, size, gfp)

#ifdef kmalloc
#undef kmalloc
#endif
void *memtrack_kmalloc(const char *src_file,
                       int src_line,
                       size_t size,
                       gfp_t gfp);
#define kmalloc(size, gfp) memtrack_kmalloc(__FILE__, __LINE__, size, gfp)

#ifdef kmemdup
#undef kmemdup
#endif
void *memtrack_kmemdup(const char *src_file,
                       int src_line,
                       const void *p,
                       size_t size,
                       gfp_t gfp);
#define kmemdup(p, size, gfp) memtrack_kmemdup(__FILE__, __LINE__, p, size, gfp)

#ifdef kstrdup
#undef kstrdup
#endif
char *memtrack_kstrdup(const char *src_file,
                       int src_line,
                       const char *s,
                       gfp_t gfp);
#define kstrdup(s, gfp) memtrack_kstrdup(__FILE__, __LINE__, s, gfp)

#ifdef kfree
#undef kfree
#endif
void memtrack_kfree(const char *src_file,
                    int src_line,
                    const void *user_addr);
#define kfree(p) memtrack_kfree(__FILE__, __LINE__, p)

#ifdef vmalloc
#undef vmalloc
#endif
void *memtrack_vmalloc(const char *src_file,
                       int src_line,
                       unsigned long user_size);
#define vmalloc(size) memtrack_vmalloc(__FILE__, __LINE__, size)

#ifdef vzalloc
#undef vzalloc
#endif
void *memtrack_vzalloc(const char *src_file,
                       int src_line,
                       unsigned long user_size);
#define vzalloc(size) memtrack_vzalloc(__FILE__, __LINE__, size)

#ifdef vmalloc_user
#undef vmalloc_user
#endif
void *memtrack_vmalloc_user(const char *src_file,
                            int src_line,
                            unsigned long user_size);
#define vmalloc_user(size) memtrack_vmalloc_user(__FILE__, __LINE__, size)

#ifdef vfree
#undef vfree
#endif
void memtrack_vfree(const char *src_file,
                    int src_line,
                    const void *user_addr);
#define vfree(addr) memtrack_vfree(__FILE__, __LINE__, addr)

#ifdef kmem_cache_create
#undef kmem_cache_create
#endif
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0))
struct kmem_cache *memtrack_kmem_cache_create(const char *src_file,
                                              int src_line,
                                              const char *name,
                                              size_t size,
                                              size_t align,
                                              unsigned long flags,
                                              void (*ctor)(void *));
#else
struct kmem_cache *memtrack_kmem_cache_create(const char *src_file,
                                              int src_line,
                                              const char *name,
                                              unsigned int size,
                                              unsigned int align,
                                              slab_flags_t flags,
                                              void (*ctor)(void *));
#endif /* LINUX_VERSION_CODE <= KERNEL_VERSION(4, 14, 0) */
#define kmem_cache_create(name, size, align, flags, ctor) \
        memtrack_kmem_cache_create(__FILE__, __LINE__, name, size, align, flags, ctor)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0))
#ifdef kmem_cache_create_usercopy
#undef kmem_cache_create_usercopy
#endif
struct kmem_cache * memtrack_kmem_cache_create_usercopy(const char *src_file,
                                                        int src_line,
                                                        const char *name,
                                                        unsigned int size,
                                                        unsigned int align,
                                                        slab_flags_t flags,
                                                        unsigned int useroffset,
                                                        unsigned int usersize,
                                                        void (*ctor)(void *));
#define kmem_cache_create_usercopy(name, size, align, flags, useroffset, usersize, ctor) \
        memtrack_kmem_cache_create_usercopy(__FILE__, __LINE__, name, size, align, \
                                            flags, useroffset, usersize, ctor)
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0) */

#ifdef kmem_cache_destroy
#undef kmem_cache_destroy
#endif
void memtrack_kmem_cache_destroy(const char *src_file,
                                 int src_line,
                                 struct kmem_cache *cache);
#define kmem_cache_destroy(cache) memtrack_kmem_cache_destroy(__FILE__, __LINE__, cache)

#ifdef kmem_cache_alloc
#undef kmem_cache_alloc
#endif
void *memtrack_kmem_cache_alloc(const char *src_file,
                                int src_line,
                                struct kmem_cache *cache,
                                gfp_t gfp);
#define kmem_cache_alloc(cache, gfp) memtrack_kmem_cache_alloc(__FILE__, __LINE__, cache, gfp)

#ifdef kmem_cache_zalloc
#undef kmem_cache_zalloc
#endif
void *memtrack_kmem_cache_zalloc(const char *src_file,
                                 int src_line,
                                 struct kmem_cache *cache,
                                 gfp_t gfp);
#define kmem_cache_zalloc(cache, gfp) memtrack_kmem_cache_zalloc(__FILE__, __LINE__, cache, gfp)

#ifdef kmem_cache_free
#undef kmem_cache_free
#endif
void memtrack_kmem_cache_free(const char *src_file,
                              int src_line,
                              struct kmem_cache *cache,
                              void *user_addr);
#define kmem_cache_free(cache, addr) memtrack_kmem_cache_free(__FILE__, __LINE__, cache, addr)

#ifdef ioremap
#undef ioremap
#endif
void __iomem *memtrack_ioremap(const char *src_file,
                               int src_line,
                               resource_size_t offset,
                               unsigned long size);
#define ioremap(offset, size) memtrack_ioremap(__FILE__, __LINE__, offset, size)

#ifdef iounmap
#undef iounmap
#endif
void memtrack_iounmap(const char *src_file,
                      int src_line,
                      void __iomem *user_addr);
#define iounmap(addr) memtrack_iounmap(__FILE__, __LINE__, addr)

#ifdef alloc_pages
#undef alloc_pages
#endif
struct page *memtrack_alloc_pages(const char *src_file,
                                  int src_line,
                                  gfp_t gfp,
                                  unsigned int order);
#define alloc_pages(gfp, order) memtrack_alloc_pages(__FILE__, __LINE__, gfp, order)

#ifdef __free_pages
#undef __free_pages
#endif
void memtrack___free_pages(const char *src_file,
                           int src_line,
                           struct page *page,
                           unsigned int order);
#define __free_pages(page, order) memtrack___free_pages(__FILE__, __LINE__, page, order)

#ifdef dma_alloc_coherent
#undef dma_alloc_coherent
#endif
void *memtrack_dma_alloc_coherent(const char *src_file,
                                  int src_line,
                                  struct device *dev,
                                  size_t size,
                                  dma_addr_t *dma_handle,
                                  gfp_t gfp);
#define dma_alloc_coherent(dev, size, dma_handle, gfp) \
        memtrack_dma_alloc_coherent(__FILE__, __LINE__, dev, size, dma_handle, gfp)

#ifdef dma_free_coherent
#undef dma_free_coherent
#endif
void memtrack_dma_free_coherent(const char *src_file,
                                int src_line,
                                struct device *dev,
                                size_t size,
                                void *user_addr,
                                dma_addr_t dma_handle);
#define dma_free_coherent(dev, size, user_addr, dma_handle) \
        memtrack_dma_free_coherent(__FILE__, __LINE__, dev, size, user_addr, dma_handle)

#ifdef dma_map_single
#undef dma_map_single
#endif
dma_addr_t memtrack_dma_map_single(const char *src_file,
                                   int src_line,
                                   struct device *dev,
                                   void *user_addr,
                                   size_t size,
                                   enum dma_data_direction dir);
#define dma_map_single(dev, user_addr, size, dir) \
        memtrack_dma_map_single(__FILE__, __LINE__, dev, user_addr, size, dir)

#ifdef dma_unmap_single
#undef dma_unmap_single
#endif
void memtrack_dma_unmap_single(const char *src_file,
                               int src_line,
                               struct device *dev,
                               dma_addr_t addr,
                               size_t size,
                               enum dma_data_direction dir);
#define dma_unmap_single(dev, user_addr, size, dir) \
        memtrack_dma_unmap_single(__FILE__, __LINE__, dev, user_addr, size, dir)

#ifdef dma_pool_create
#undef dma_pool_create
#endif
struct dma_pool *memtrack_dma_pool_create(const char *src_file,
                                          int src_line,
                                          const char *name,
                                          struct device *dev,
                                          size_t size,
                                          size_t align,
                                          size_t allocation);
#define dma_pool_create(name, dev, size, align, allocation) \
        memtrack_dma_pool_create(__FILE__, __LINE__, name, dev, size, align, allocation)

#ifdef dma_pool_destroy
#undef dma_pool_destroy
#endif
void memtrack_dma_pool_destroy(const char *src_file,
                               int src_line,
                               struct dma_pool *pool);
#define dma_pool_destroy(pool) memtrack_dma_pool_destroy(__FILE__, __LINE__, pool)

#ifdef dma_pool_alloc
#undef dma_pool_alloc
#endif
void *memtrack_dma_pool_alloc(const char *src_file,
                              int src_line,
                              struct dma_pool *pool,
                              gfp_t mem_flags,
                              dma_addr_t *handle);
#define dma_pool_alloc(pool, mem_flags, handle) \
        memtrack_dma_pool_alloc(__FILE__, __LINE__, pool, mem_flags, handle)

#ifdef dma_pool_free
#undef dma_pool_free
#endif
void memtrack_dma_pool_free(const char *src_file,
                            int src_line,
                            struct dma_pool *pool,
                            void *user_addr,
                            dma_addr_t addr);
#define dma_pool_free(pool, user_addr, addr) \
        memtrack_dma_pool_free(__FILE__, __LINE__, pool, user_addr, addr)

#ifdef dma_map_sg
#undef dma_map_sg
#endif
int memtrack_dma_map_sg(const char *src_file,
                        int src_line,
                        struct device *dev,
                        struct scatterlist *sg,
                        int nents,
                        enum dma_data_direction dir);
#define dma_map_sg(dev, sg, nents, dir) \
        memtrack_dma_map_sg(__FILE__, __LINE__, dev, sg, nents, dir)

#ifdef dma_unmap_sg
#undef dma_unmap_sg
#endif
void memtrack_dma_unmap_sg(const char *src_file,
                           int src_line,
                           struct device *dev,
                           struct scatterlist *sg,
                           int nents,
                           enum dma_data_direction dir);
#define dma_unmap_sg(dev, sg, nents, dir) \
        memtrack_dma_unmap_sg(__FILE__, __LINE__, dev, sg, nents, dir)

#endif /* SX_MEMTRACK_MODULE */

#endif /* __mtrack_h_ */
