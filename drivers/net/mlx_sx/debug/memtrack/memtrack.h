/*
 * Copyright (C) 2010-2023 NVIDIA CORPORATION & AFFILIATES, Ltd. ALL RIGHTS RESERVED.
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

#define MEMTRACK_MARGIN_SIZE (16)
#define MEMTRACK_SIZE_INCLUDING_MARGINS(size) ((size) + (2 * MEMTRACK_MARGIN_SIZE))
#define MEMTRACK_MARGIN_TO_USER_PTR(ptr)                                      \
    (ZERO_OR_NULL_PTR(ptr) ? ((void*)ptr) : ((void*)(((unsigned long)(ptr)) + \
                                                     MEMTRACK_MARGIN_SIZE)))
#define MEMTRACK_USER_TO_MARGIN_PTR(ptr, used_margins)         \
    ((void*)((used_margins) ?                                  \
             (((unsigned long)(ptr)) - MEMTRACK_MARGIN_SIZE) : \
             ((unsigned long)(ptr))))

enum memtrack_memtype_t {
    MEMTRACK_KMALLOC,
    MEMTRACK_KSTRDUP,
    MEMTRACK_VMALLOC,
    MEMTRACK_KMEM_OBJ,
    MEMTRACK_IOREMAP,       /* IO-RE/UN-MAP */
    MEMTRACK_WORK_QUEUE,    /* Handle work-queue create & destroy */
    MEMTRACK_PAGE_ALLOC,    /* Handle page allocation and free */
    MEMTRACK_DMA_MAP_SINGLE, /* Handle ib_dma_single map and unmap */
    MEMTRACK_DMA_MAP_PAGE,  /* Handle ib_dma_page map and unmap */
    MEMTRACK_DMA_MAP_SG,    /* Handle ib_dma_sg map and unmap with and without attributes */
    MEMTRACK_NUM_OF_MEMTYPES
};

enum memtrack_margins_op {
    MEMTRACK_MARGINS_OP_DONT,
    MEMTRACK_MARGINS_OP_DO
};

enum memtrack_pattern_op {
    MEMTRACK_PATTERN_OP_DONT,
    MEMTRACK_PATTERN_OP_DO
};

/* Invoke on memory allocation */
void memtrack_alloc(enum memtrack_memtype_t memtype, unsigned long dev,
                    unsigned long addr, unsigned long size,
                    enum memtrack_margins_op margins_op,
                    enum memtrack_pattern_op pattern_op,
                    int direction, const char *filename,
                    const unsigned long line_num, int alloc_flags);

/* Invoke on memory free */
bool memtrack_free(enum memtrack_memtype_t memtype, unsigned long dev,
                   unsigned long addr, unsigned long size, enum memtrack_pattern_op pattern_op, int direction,
                   const char *filename, const unsigned long line_num);

/*
 * This function recognizes allocations which
 * may be released by kernel (e.g. skb & vnic) and
 * therefore not trackable by memtrack.
 * The allocations are recognized by the name
 * of their calling function.
 */
int is_non_trackable_alloc_func(const char *func_name);
/*
 * In some cases we need to free a memory
 * we defined as "non trackable" (see
 * is_non_trackable_alloc_func).
 * This function recognizes such releases
 * by the name of their calling function.
 */
int is_non_trackable_free_func(const char *func_name);

/* WA - In this function handles confirm
 *  the the function name is
 *  '__ib_umem_release' or 'ib_umem_get'
 *  In this case we won't track the
 *  memory there because the kernel
 *  was the one who allocated it.
 *  Return value:
 *    1 - if the function name is match, else 0    */
int is_umem_put_page(const char *func_name);

/* Check page order size
 *  When Freeing a page allocation it checks whether
 *  we are trying to free the same amount of pages
 *  we ask to allocate (In log2(order)).
 *  In case an error if found it will print
 *  an error msg                                    */
int memtrack_check_size(enum memtrack_memtype_t memtype, unsigned long addr,
                        unsigned long size, const char *filename,
                        const unsigned long line_num);

/* Search for a specific addr whether it exist in the
 *  current data-base.
 *  If not it will print an error msg,
 *  Return value: 0 - if addr exist, else 1 */
int memtrack_is_new_addr(enum memtrack_memtype_t memtype, unsigned long addr, int expect_exist,
                         const char *filename, const unsigned long line_num);

/* Return current page reference counter */
int memtrack_get_page_ref_count(unsigned long addr);

#endif /* ifndef H_MEMTRACK_H */