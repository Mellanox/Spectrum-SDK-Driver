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

#include "memtrack.h"

#define MEMTRACK_ALLOC_PATTERN        (0x5a)
#define MEMTRACK_FREE_PATTERN         (0x6b)
#define MEMTRACK_LEFT_MARGIN_PATTERN  (0x7c)
#define MEMTRACK_RIGHT_MARGIN_PATTERN (0x8d)

const char * memtrack_type_str(enum memtrack_types type)
{
    static const char *str[] = {
        [MEMTRACK_TYPE_MALLOC] = "Malloc",
        [MEMTRACK_TYPE_VMALLOC] = "VMalloc",
        [MEMTRACK_TYPE_CACHE] = "Kmem-Cache",
        [MEMTRACK_TYPE_CACHE_ALLOC] = "Kmem-Cache-Alloc",
        [MEMTRACK_TYPE_IOMAP] = "IO-Map",
        [MEMTRACK_TYPE_PAGE] = "DMA-Page",
        [MEMTRACK_TYPE_DMA_COHERENT] = "DMA-Coherent",
        [MEMTRACK_TYPE_DMA_SINGLE] = "DMA-Single",
        [MEMTRACK_TYPE_DMA_POOL] = "DMA-Pool",
        [MEMTRACK_TYPE_DMA_POOL_ALLOC] = "DMA-Pool-Alloc",
        [MEMTRACK_TYPE_DMA_MAP_SG] = "DMA-Map-SG"
    };

    if ((type >= 0) && (type < MEMTRACK_TYPE_MAX)) {
        return str[type];
    }

    return "N/A";
}

void memtrack_apply_margin_pattern(void *real_addr, unsigned long user_size)
{
    void *user_addr = MEMTRACK_MARGIN_TO_USER_PTR(real_addr);

    memset(real_addr, MEMTRACK_LEFT_MARGIN_PATTERN, MEMTRACK_MARGIN_SIZE);
    memset(user_addr + user_size, MEMTRACK_RIGHT_MARGIN_PATTERN, MEMTRACK_MARGIN_SIZE);
}

void memtrack_poison_after_alloc(void *user_addr, unsigned long user_size)
{
    memset(user_addr, MEMTRACK_ALLOC_PATTERN, user_size);
}

void memtrack_poison_before_free(void *user_addr, unsigned long user_size)
{
    memset(user_addr, MEMTRACK_FREE_PATTERN, user_size);
}

static void __memtrack_check_margin(const char          *alloc_src_file,
                                    int                  alloc_src_line,
                                    const char          *free_src_file,
                                    int                  free_src_line,
                                    void                *user_addr,
                                    unsigned long        user_size,
                                    const char          *margin_side,
                                    const unsigned char *margin,
                                    unsigned char        pattern)
{
    bool ok = true;
    int  i;

    for (i = 0; i < MEMTRACK_MARGIN_SIZE; i++) {
        if (margin[i] != pattern) {
            ok = false;
            break;
        }
    }

    if (!ok) {
        sxd_log_mem_err_dump_stack("[%s:%d] %s margin is corrupted! (allocated in [%s:%d])\n",
                                   free_src_file,
                                   free_src_line,
                                   margin_side,
                                   alloc_src_file,
                                   alloc_src_line);
        sxd_log_mem_hex_dump(margin_side, margin, MEMTRACK_MARGIN_SIZE);
    }
}

void memtrack_check_margins(const char   *alloc_src_file,
                            int           alloc_src_line,
                            const char   *free_src_file,
                            int           free_src_line,
                            void         *user_addr,
                            unsigned long user_size)
{
    const char *left_margin = MEMTRACK_USER_TO_MARGIN_PTR(user_addr);
    const char *right_margin = user_addr + user_size;

    __memtrack_check_margin(alloc_src_file,
                            alloc_src_line,
                            free_src_file,
                            free_src_line,
                            user_addr,
                            user_size,
                            "left",
                            left_margin,
                            MEMTRACK_LEFT_MARGIN_PATTERN);

    __memtrack_check_margin(alloc_src_file,
                            alloc_src_line,
                            free_src_file,
                            free_src_line,
                            user_addr,
                            user_size,
                            "right",
                            right_margin,
                            MEMTRACK_RIGHT_MARGIN_PATTERN);
}
