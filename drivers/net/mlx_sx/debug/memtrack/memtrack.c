/*
 * Copyright (C) 2010-2024 NVIDIA CORPORATION & AFFILIATES, Ltd. ALL RIGHTS RESERVED.
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

#ifdef kmalloc
    #undef kmalloc
#endif
#ifdef kstrdup
    #undef kstrdup
#endif
#ifdef kmemdup
    #undef kmemdup
#endif
#ifdef kfree
    #undef kfree
#endif
#ifdef vmalloc
    #undef vmalloc
#endif
#ifdef vzalloc
    #undef vzalloc
#endif
#ifdef vzalloc_node
    #undef vzalloc_node
#endif
#ifdef vfree
    #undef vfree
#endif
#ifdef kmem_cache_alloc
    #undef kmem_cache_alloc
#endif
#ifdef kmem_cache_free
    #undef kmem_cache_free
#endif
#ifdef ioremap
    #undef ioremap
#endif
#ifdef io_mapping_create_wc
    #undef io_mapping_create_wc
#endif
#ifdef io_mapping_free
    #undef io_mapping_free
#endif
#ifdef ioremap_nocache
    #undef ioremap_nocache
#endif
#ifdef iounmap
    #undef iounmap
#endif
#ifdef alloc_pages
    #undef alloc_pages
#endif
#ifdef free_pages
    #undef free_pages
#endif
#ifdef get_page
    #undef get_page
#endif
#ifdef put_page
    #undef put_page
#endif
#ifdef create_workqueue
    #undef create_workqueue
#endif
#ifdef create_rt_workqueue
    #undef create_rt_workqueue
#endif
#ifdef create_freezeable_workqueue
    #undef create_freezeable_workqueue
#endif
#ifdef create_singlethread_workqueue
    #undef create_singlethread_workqueue
#endif
#ifdef destroy_workqueue
    #undef destroy_workqueue
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include "memtrack.h"

#include <linux/moduleparam.h>


MODULE_AUTHOR("NVIDIA");
MODULE_DESCRIPTION("Memory allocations tracking");
MODULE_LICENSE("GPL");

#define MEMTRACK_ALLOC_PATTERN        (0x5a)
#define MEMTRACK_FREE_PATTERN         (0x6b)
#define MEMTRACK_LEFT_MARGIN_PATTERN  (0x7c)
#define MEMTRACK_RIGHT_MARGIN_PATTERN (0x8d)

#define MEMTRACK_HASH_SZ ((1 << 15) - 19)   /* prime: http://www.utm.edu/research/primes/lists/2small/0bit.html */
#define MAX_FILENAME_LEN 31

#define memtrack_spin_lock(spl, flags)   spin_lock_irqsave(spl, flags)
#define memtrack_spin_unlock(spl, flags) spin_unlock_irqrestore(spl, flags)

#define sxd_mem_log(verbosity, prefix, fmt, arg ...) printk(verbosity "sxd_memtrack: " prefix fmt, ## arg)

#define sxd_log_mem_err(fmt, arg ...)     sxd_mem_log(KERN_ERR, "[error] ", fmt, ## arg) /*KERN_EMRG KERN_ALERT and KERN_CRIT should use sxd_log_err  */
#define sxd_log_mem_warning(fmt, arg ...) sxd_mem_log(KERN_WARNING, "", fmt, ## arg)
#define sxd_log_mem_notice(fmt, arg ...)  sxd_mem_log(KERN_NOTICE, "", fmt, ## arg)
#define sxd_log_mem_info(fmt, arg ...)    sxd_mem_log(KERN_INFO, "", fmt, ## arg)

struct memtrack_meminfo_t {
    unsigned long              addr;
    unsigned long              size;
    enum memtrack_margins_op   margins_op;
    unsigned long              line_num;
    unsigned long              dev;
    int                        direction;
    struct memtrack_meminfo_t *next;
    struct list_head           list; /* used to link all items from a certain type together */
    char                       filename[MAX_FILENAME_LEN + 1]; /* putting the char array last is better for struct. packing */
    char                       ext_info[32];
};
static struct kmem_cache *meminfo_cache;
struct tracked_obj_desc_t {
    struct memtrack_meminfo_t *mem_hash[MEMTRACK_HASH_SZ];
    spinlock_t                 hash_lock;
    unsigned long              count; /* size of memory tracked (*malloc) or number of objects tracked */
    struct list_head           tracked_objs_head; /* head of list of all objects */
};
static struct tracked_obj_desc_t *tracked_objs_arr[MEMTRACK_NUM_OF_MEMTYPES];
static const char                *rsc_names[MEMTRACK_NUM_OF_MEMTYPES] = {
    "kmalloc",
    "vmalloc",
    "kmem_cache_alloc",
    "io_remap",
    "create_workqueue",
    "alloc_pages",
    "ib_dma_map_single",
    "ib_dma_map_page",
    "ib_dma_map_sg"
};
static const char                *rsc_free_names[MEMTRACK_NUM_OF_MEMTYPES] = {
    "kfree",
    "vfree",
    "kmem_cache_free",
    "io_unmap",
    "destroy_workqueue",
    "free_pages",
    "ib_dma_unmap_single",
    "ib_dma_unmap_page",
    "ib_dma_unmap_sg"
};
static inline const char * memtype_alloc_str(enum memtrack_memtype_t memtype)
{
    switch (memtype) {
    case MEMTRACK_KMALLOC:
    case MEMTRACK_VMALLOC:
    case MEMTRACK_KMEM_OBJ:
    case MEMTRACK_IOREMAP:
    case MEMTRACK_WORK_QUEUE:
    case MEMTRACK_PAGE_ALLOC:
    case MEMTRACK_DMA_MAP_SINGLE:
    case MEMTRACK_DMA_MAP_PAGE:
    case MEMTRACK_DMA_MAP_SG:
        return rsc_names[memtype];

    default:
        return "(Unknown allocation type)";
    }
}

static inline const char * memtype_free_str(enum memtrack_memtype_t memtype)
{
    switch (memtype) {
    case MEMTRACK_KMALLOC:
    case MEMTRACK_VMALLOC:
    case MEMTRACK_KMEM_OBJ:
    case MEMTRACK_IOREMAP:
    case MEMTRACK_WORK_QUEUE:
    case MEMTRACK_PAGE_ALLOC:
    case MEMTRACK_DMA_MAP_SINGLE:
    case MEMTRACK_DMA_MAP_PAGE:
    case MEMTRACK_DMA_MAP_SG:
        return rsc_free_names[memtype];

    default:
        return "(Unknown allocation type)";
    }
}

/*
 *  overlap_a_b
 */
static inline int overlap_a_b(unsigned long a_start, unsigned long a_end, unsigned long b_start, unsigned long b_end)
{
    if ((b_start > a_end) || (a_start > b_end)) {
        return 0;
    }

    return 1;
}

/* Invoke on memory allocation */
void memtrack_alloc(enum memtrack_memtype_t memtype,
                    unsigned long           dev,
                    unsigned long           addr,
                    unsigned long           size,
                    enum memtrack_margins_op margins_op,
                    enum memtrack_pattern_op pattern_op,
                    int                     direction,
                    const char             *filename,
                    const unsigned long     line_num,
                    int                     alloc_flags)
{
    unsigned long              hash_val;
    struct memtrack_meminfo_t *cur_mem_info_p, *new_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;

    if (memtype >= MEMTRACK_NUM_OF_MEMTYPES) {
        sxd_log_mem_err( "%s: Invalid memory type (%d)\n", __func__, memtype);
        return;
    }

    if (!tracked_objs_arr[memtype]) {
        /* object is not tracked */
        return;
    }

    if (margins_op == MEMTRACK_MARGINS_OP_DO) {
        memset((void*) addr, MEMTRACK_LEFT_MARGIN_PATTERN, MEMTRACK_MARGIN_SIZE);
        addr = (unsigned long) MEMTRACK_MARGIN_TO_USER_PTR(addr);
        memset((void*) (addr + size), MEMTRACK_RIGHT_MARGIN_PATTERN, MEMTRACK_MARGIN_SIZE);
    }

    if (pattern_op == MEMTRACK_PATTERN_OP_DO) {
        memset((void*) addr, MEMTRACK_ALLOC_PATTERN, size);
    }

    obj_desc_p = tracked_objs_arr[memtype];

    hash_val = addr % MEMTRACK_HASH_SZ;

    new_mem_info_p = (struct memtrack_meminfo_t *)kmem_cache_alloc(meminfo_cache, alloc_flags);
    if (new_mem_info_p == NULL) {
        sxd_log_mem_err("%s: Failed allocating kmem_cache item for new mem_info. "
               "Lost tracking on allocation at %s:%lu...\n", __func__,
               filename, line_num);
        return;
    }
    /* save allocation properties */
    new_mem_info_p->addr = addr;
    new_mem_info_p->size = size;
    new_mem_info_p->margins_op = margins_op;
    new_mem_info_p->dev = dev;
    new_mem_info_p->direction = direction;

    new_mem_info_p->line_num = line_num;
    *new_mem_info_p->ext_info = '\0';
    /* Make sure that we will print out the path tail if the given filename is longer
     * than MAX_FILENAME_LEN. (otherwise, we will not see the name of the actual file
     * in the printout -- only the path head!
     */
    if (strlen(filename) > MAX_FILENAME_LEN) {
        strncpy(new_mem_info_p->filename, filename + strlen(filename) - MAX_FILENAME_LEN, MAX_FILENAME_LEN);
    } else {
        strncpy(new_mem_info_p->filename, filename, MAX_FILENAME_LEN);
    }

    new_mem_info_p->filename[MAX_FILENAME_LEN] = 0; /* NULL terminate anyway */

    memtrack_spin_lock(&obj_desc_p->hash_lock, flags);
    /* make sure given memory location is not already allocated */
    if ((memtype != MEMTRACK_DMA_MAP_SINGLE) && (memtype != MEMTRACK_DMA_MAP_PAGE) &&
        (memtype != MEMTRACK_DMA_MAP_SG)) {
        /* make sure given memory location is not already allocated */
        cur_mem_info_p = obj_desc_p->mem_hash[hash_val];
        while (cur_mem_info_p != NULL) {
            if ((cur_mem_info_p->addr == addr) && (cur_mem_info_p->dev == dev)) {
                /* Found given address in the database */
                sxd_log_mem_err(
                    "mtl rsc inconsistency: %s: %s::%lu: %s @ addr=0x%lX which is already known from %s:%lu\n",
                    __func__,
                    filename,
                    line_num,
                    memtype_alloc_str(memtype),
                    addr,
                    cur_mem_info_p->filename,
                    cur_mem_info_p->line_num);
                memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
                kmem_cache_free(meminfo_cache, new_mem_info_p);
                return;
            }
            cur_mem_info_p = cur_mem_info_p->next;
        }
    }
    /* not found - we can put in the hash bucket */
    /* link as first */
    new_mem_info_p->next = obj_desc_p->mem_hash[hash_val];
    obj_desc_p->mem_hash[hash_val] = new_mem_info_p;
    obj_desc_p->count += size;
    list_add(&new_mem_info_p->list, &obj_desc_p->tracked_objs_head);

    memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
    return;
}
EXPORT_SYMBOL(memtrack_alloc);

static void __check_margin(enum memtrack_memtype_t memtype,
                           const char* dealloc_filename,
                           unsigned long dealloc_line_num,
                           const char *margin_side,
                           const unsigned char *margin,
                           unsigned char pattern,
                           const struct memtrack_meminfo_t *cur_mem_info)
{
    int i;

    for (i = 0; i < MEMTRACK_MARGIN_SIZE; i++) {
        if (margin[i] != pattern) {
            sxd_log_mem_err("%s margin at offset %d is corrupted [expected: 0x%02x, actual: 0x%02x]! "
                            "%s:%lu: %s for addr 0x%lX: size:%lu, (allocated in %s:%lu)\n",
                   margin_side,
                   i,
                   pattern,
                   margin[i],
                   dealloc_filename,
                   dealloc_line_num,
                   memtype_free_str(memtype),
                   cur_mem_info->addr,
                   cur_mem_info->size,
                   cur_mem_info->filename,
                   cur_mem_info->line_num);
        }
    }
}

/* Invoke on memory free */
bool memtrack_free(enum memtrack_memtype_t memtype,
                   unsigned long           dev,
                   unsigned long           addr,
                   unsigned long           size,
                   enum memtrack_pattern_op pattern_op,
                   int                     direction,
                   const char             *filename,
                   const unsigned long     line_num)
{
    unsigned long              hash_val;
    struct memtrack_meminfo_t *cur_mem_info_p, *prev_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;
    const unsigned char *left_margin, *right_margin;
    bool used_margins = false;

    if (memtype >= MEMTRACK_NUM_OF_MEMTYPES) {
        sxd_log_mem_err("%s: Invalid memory type (%d)\n", __func__, memtype);
        return false;
    }

    if (!tracked_objs_arr[memtype]) {
        /* object is not tracked */
        return false;
    }
    obj_desc_p = tracked_objs_arr[memtype];

    hash_val = addr % MEMTRACK_HASH_SZ;

    memtrack_spin_lock(&obj_desc_p->hash_lock, flags);
    /* find  mem_info of given memory location */
    prev_mem_info_p = NULL;
    cur_mem_info_p = obj_desc_p->mem_hash[hash_val];
    while (cur_mem_info_p != NULL) {
        if ((cur_mem_info_p->addr == addr) && (cur_mem_info_p->dev == dev)) {
            /* Found given address in the database */
            if ((memtype == MEMTRACK_DMA_MAP_SINGLE) || (memtype == MEMTRACK_DMA_MAP_PAGE) ||
                (memtype == MEMTRACK_DMA_MAP_SG)) {
                if (direction != cur_mem_info_p->direction) {
                    sxd_log_mem_err(
                        "mtl rsc inconsistency: %s: %s::%lu: %s bad direction for addr 0x%lX: alloc:0x%x, free:0x%x (allocated in %s::%lu)\n",
                        __func__,
                        filename,
                        line_num,
                        memtype_free_str(memtype),
                        addr,
                        cur_mem_info_p->direction,
                        direction,
                        cur_mem_info_p->filename,
                        cur_mem_info_p->line_num);
                }

                if (size != cur_mem_info_p->size) {
                    sxd_log_mem_err(
                        "mtl rsc inconsistency: %s: %s::%lu: %s bad size for addr 0x%lX: size:%lu, free:%lu (allocated in %s::%lu)\n",
                        __func__,
                        filename,
                        line_num,
                        memtype_free_str(memtype),
                        addr,
                        cur_mem_info_p->size,
                        size,
                        cur_mem_info_p->filename,
                        cur_mem_info_p->line_num);
                }
            }

            if (cur_mem_info_p->margins_op == MEMTRACK_MARGINS_OP_DO) {
                left_margin = (char*) (cur_mem_info_p->addr - MEMTRACK_MARGIN_SIZE);
                right_margin = (char*) (cur_mem_info_p->addr + cur_mem_info_p->size);

                __check_margin(memtype,
                               filename,
                               line_num,
                               "left",
                               left_margin,
                               MEMTRACK_LEFT_MARGIN_PATTERN,
                               cur_mem_info_p);

                __check_margin(memtype,
                               filename,
                               line_num,
                               "right",
                               right_margin,
                               MEMTRACK_RIGHT_MARGIN_PATTERN,
                               cur_mem_info_p);

                used_margins = true;
            }

            if (pattern_op == MEMTRACK_PATTERN_OP_DO) {
                memset((void*) cur_mem_info_p->addr, MEMTRACK_FREE_PATTERN, cur_mem_info_p->size);
            }

            /* Remove from the bucket/list */
            if (prev_mem_info_p == NULL) {
                obj_desc_p->mem_hash[hash_val] = cur_mem_info_p->next;  /* removing first */
            } else {
                prev_mem_info_p->next = cur_mem_info_p->next;   /* "crossover" */
            }
            list_del(&cur_mem_info_p->list);

            obj_desc_p->count -= cur_mem_info_p->size;
            memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            kmem_cache_free(meminfo_cache, cur_mem_info_p);
            return used_margins;
        }
        prev_mem_info_p = cur_mem_info_p;
        cur_mem_info_p = cur_mem_info_p->next;
    }

    /* not found */
    sxd_log_mem_err("mtl rsc inconsistency: %s: %s::%lu: %s for unknown address=0x%lX, device=0x%lX\n",
           __func__, filename, line_num, memtype_free_str(memtype), addr, dev);
    memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
    return false;
}
EXPORT_SYMBOL(memtrack_free);

/*
 * This function recognizes allocations which
 * may be released by kernel (e.g. skb) and
 * therefore not trackable by memtrack.
 * The allocations are recognized by the name
 * of their calling function.
 */
int is_non_trackable_alloc_func(const char *func_name)
{
    static const char * const str_str_arr[] = {
        /* functions containing these strings consider non trackable */
        "skb",
    };
    static const char * const str_str_excep_arr[] = {
        /* functions which are exception to the str_str_arr table */
        "ipoib_cm_skb_too_long",
        "rx_skb"
    };
    static const char * const str_cmp_arr[] = {
        /* functions that allocate SKBs */
        "mlx4_en_alloc_frags",
        "mlx4_en_alloc_frag",
        "mlx4_en_init_allocator",
        "mlx4_en_free_frag",
        "mlx4_en_free_rx_desc",
        "mlx4_en_destroy_allocator",
        "mlx4_en_complete_rx_desc",
        "mlx4_alloc_pages",
        /* vnic skb functions */
        "free_single_frag",
        "vnic_alloc_rx_skb",
        "vnic_rx_skb",
        "vnic_alloc_frag",
        "vnic_empty_rx_entry",
        "vnic_init_allocator",
        "vnic_destroy_allocator",
        "sdp_post_recv",
        "sdp_rx_ring_purge",
        "sdp_post_srcavail",
        "sk_stream_alloc_page",
        "update_send_head",
        "sdp_bcopy_get",
        "sdp_destroy_resources",
    };
    size_t                    str_str_arr_size = sizeof(str_str_arr) / sizeof(char *);
    size_t                    str_str_excep_size = sizeof(str_str_excep_arr) / sizeof(char *);
    size_t                    str_cmp_arr_size = sizeof(str_cmp_arr) / sizeof(char *);
    int                       i, j;

    for (i = 0; i < str_str_arr_size; ++i) {
        if (strstr(func_name, str_str_arr[i])) {
            for (j = 0; j < str_str_excep_size; ++j) {
                if (!strcmp(func_name, str_str_excep_arr[j])) {
                    return 0;
                }
            }
            return 1;
        }
    }
    for (i = 0; i < str_cmp_arr_size; ++i) {
        if (!strcmp(func_name, str_cmp_arr[i])) {
            return 1;
        }
    }
    return 0;
}
EXPORT_SYMBOL(is_non_trackable_alloc_func);

/*
 * In some cases we need to free a memory
 * we defined as "non trackable" (see
 * is_non_trackable_alloc_func).
 * This function recognizes such releases
 * by the name of their calling function.
 */
int is_non_trackable_free_func(const char *func_name)
{
    return 0;
}
EXPORT_SYMBOL(is_non_trackable_free_func);


/* WA - In this function handles confirm
 *  the the function name is
 *  '__ib_umem_release' or 'ib_umem_get'
 *  In this case we won't track the
 *  memory there because the kernel
 *  was the one who allocated it.
 *  Return value:
 *    1 - if the function name is match, else 0 */
int is_umem_put_page(const char *func_name)
{
    const char func_str[18] = "__ib_umem_release";
    /* In case of error flow put_page is called as part of ib_umem_get */
    const char func_str1[12] = "ib_umem_get";

    return ((strstr(func_name, func_str) != NULL) ||
            (strstr(func_name, func_str1) != NULL)) ? 1 : 0;
}
EXPORT_SYMBOL(is_umem_put_page);

/* Check page order size
 *  When Freeing a page allocation it checks whether
 *  we are trying to free the same size
 *  we asked to allocate                             */
int memtrack_check_size(enum memtrack_memtype_t memtype,
                        unsigned long           addr,
                        unsigned long           size,
                        const char             *filename,
                        const unsigned long     line_num)
{
    unsigned long              hash_val;
    struct memtrack_meminfo_t *cur_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;
    int                        ret = 0;

    if (memtype >= MEMTRACK_NUM_OF_MEMTYPES) {
        sxd_log_mem_err("%s: Invalid memory type (%d)\n", __func__, memtype);
        return 1;
    }

    if (!tracked_objs_arr[memtype]) {
        /* object is not tracked */
        return 1;
    }
    obj_desc_p = tracked_objs_arr[memtype];

    hash_val = addr % MEMTRACK_HASH_SZ;

    memtrack_spin_lock(&obj_desc_p->hash_lock, flags);
    /* find mem_info of given memory location */
    cur_mem_info_p = obj_desc_p->mem_hash[hash_val];
    while (cur_mem_info_p != NULL) {
        if (cur_mem_info_p->addr == addr) {
            /* Found given address in the database - check size */
            if (cur_mem_info_p->size != size) {
                sxd_log_mem_err(
                    "mtl size inconsistency: %s: %s::%lu: try to %s at address=0x%lX with size %lu while was created with size %lu\n",
                    __func__,
                    filename,
                    line_num,
                    memtype_free_str(memtype),
                    addr,
                    size,
                    cur_mem_info_p->size);
                snprintf(cur_mem_info_p->ext_info, sizeof(cur_mem_info_p->ext_info),
                         "invalid free size %lu\n", size);
                ret = 1;
            }
            memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            return ret;
        }
        cur_mem_info_p = cur_mem_info_p->next;
    }

    /* not found - This function will not give any indication
     *          but will only check the correct size\order
     *          For inconsistency the 'free' function will check that */
    memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
    return 1;
}
EXPORT_SYMBOL(memtrack_check_size);

/* Search for a specific addr whether it exist in the
 *  current data-base.
 *  It will print an error msg if we get an unexpected result,
 *  Return value: 0 - if addr exist, else 1 */
int memtrack_is_new_addr(enum memtrack_memtype_t memtype,
                         unsigned long           addr,
                         int                     expect_exist,
                         const char             *filename,
                         const unsigned long     line_num)
{
    unsigned long              hash_val;
    struct memtrack_meminfo_t *cur_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;

    if (memtype >= MEMTRACK_NUM_OF_MEMTYPES) {
        sxd_log_mem_err("%s: Invalid memory type (%d)\n", __func__, memtype);
        return 1;
    }

    if (!tracked_objs_arr[memtype]) {
        /* object is not tracked */
        return 0;
    }
    obj_desc_p = tracked_objs_arr[memtype];

    hash_val = addr % MEMTRACK_HASH_SZ;

    memtrack_spin_lock(&obj_desc_p->hash_lock, flags);
    /* find mem_info of given memory location */
    cur_mem_info_p = obj_desc_p->mem_hash[hash_val];
    while (cur_mem_info_p != NULL) {
        if (cur_mem_info_p->addr == addr) {
            /* Found given address in the database - exiting */
            memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            return 0;
        }
        cur_mem_info_p = cur_mem_info_p->next;
    }

    /* not found */
    if (expect_exist) {
        sxd_log_mem_err("mtl rsc inconsistency: %s: %s::%lu: %s for unknown address=0x%lX\n",
               __func__, filename, line_num, memtype_free_str(memtype), addr);
    }

    memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
    return 1;
}
EXPORT_SYMBOL(memtrack_is_new_addr);

/* Return current page reference counter */
int memtrack_get_page_ref_count(unsigned long addr)
{
    unsigned long              hash_val;
    struct memtrack_meminfo_t *cur_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    atomic_t                  *refcount = NULL;
    unsigned long              flags;
    /* This function is called only for page allocation */
    enum memtrack_memtype_t memtype = MEMTRACK_PAGE_ALLOC;
    int                     refcount_val = 0;

    if (!tracked_objs_arr[memtype]) {
        /* object is not tracked */
        return refcount_val;
    }
    obj_desc_p = tracked_objs_arr[memtype];

    hash_val = addr % MEMTRACK_HASH_SZ;

    memtrack_spin_lock(&obj_desc_p->hash_lock, flags);
    /* find mem_info of given memory location */
    cur_mem_info_p = obj_desc_p->mem_hash[hash_val];
    while (cur_mem_info_p != NULL) {
        if (cur_mem_info_p->addr == addr) {
            /* Found given address in the database - check ref-count */
            struct page *page = (struct page *)(cur_mem_info_p->addr);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0))
            refcount = &page->_refcount;
#else
            refcount = &page->_count;
#endif
            refcount_val = atomic_read(refcount);
            memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            return refcount_val;
        }
        cur_mem_info_p = cur_mem_info_p->next;
    }

    /* not found */
    memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
    return refcount_val;
}
EXPORT_SYMBOL(memtrack_get_page_ref_count);

static bool __can_hexdump(enum memtrack_memtype_t memtype)
{
    return (memtype == MEMTRACK_KMALLOC || memtype == MEMTRACK_VMALLOC);
}

/* Report current allocations status (for all memory types) */
static void memtrack_report(void)
{
    enum memtrack_memtype_t    memtype;
    unsigned long              cur_bucket;
    struct memtrack_meminfo_t *cur_mem_info_p;
    const unsigned char       *left_margin, *right_margin;
    int                        serial = 1;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;
    unsigned long              detected_leaks = 0;

    sxd_log_mem_info("%s: Currently known allocations:\n", __func__);
    for (memtype = 0; memtype < MEMTRACK_NUM_OF_MEMTYPES; memtype++) {
        if (tracked_objs_arr[memtype]) {
            sxd_log_mem_info("%d) %s:\n", serial, memtype_alloc_str(memtype));
            obj_desc_p = tracked_objs_arr[memtype];
            /* Scan all buckets to find existing allocations */
            /* TBD: this may be optimized by holding a linked list of all hash items */
            for (cur_bucket = 0; cur_bucket < MEMTRACK_HASH_SZ; cur_bucket++) {
                memtrack_spin_lock(&obj_desc_p->hash_lock, flags);      /* protect per bucket/list */
                cur_mem_info_p = obj_desc_p->mem_hash[cur_bucket];
                while (cur_mem_info_p != NULL) {        /* scan bucket */
                    sxd_log_mem_info("%s::%lu: %s(%lu)==%lX dev=%lX %s\n",
                           cur_mem_info_p->filename,
                           cur_mem_info_p->line_num,
                           memtype_alloc_str(memtype),
                           cur_mem_info_p->size,
                           cur_mem_info_p->addr,
                           cur_mem_info_p->dev,
                           cur_mem_info_p->ext_info);

                    if (cur_mem_info_p->margins_op == MEMTRACK_MARGINS_OP_DO) {
                        left_margin = (char*) (cur_mem_info_p->addr - MEMTRACK_MARGIN_SIZE);
                        right_margin = (char*) (cur_mem_info_p->addr + cur_mem_info_p->size);

                        __check_margin(memtype,
                                       "N/A",
                                       0,
                                       "left",
                                       left_margin,
                                       MEMTRACK_LEFT_MARGIN_PATTERN,
                                       cur_mem_info_p);

                        __check_margin(memtype,
                                       "N/A",
                                       0,
                                       "right",
                                       right_margin,
                                       MEMTRACK_RIGHT_MARGIN_PATTERN,
                                       cur_mem_info_p);
                    }

                    if (__can_hexdump(memtype)) {
                        print_hex_dump(KERN_INFO, "   ", DUMP_PREFIX_OFFSET, 16, 1,
                                       (void*) cur_mem_info_p->addr, cur_mem_info_p->size, 1);
                    }

                    cur_mem_info_p = cur_mem_info_p->next;
                    ++detected_leaks;
                }       /* while cur_mem_info_p */
                memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            }       /* for cur_bucket */
            serial++;
        }
    } /* for memtype */
    if (detected_leaks == 0) {
        sxd_log_mem_info("%s: Summary: No leak(s) detected\n", __func__);
    } else {
        sxd_log_mem_err("%s: Summary: %lu leak(s) detected\n", __func__, detected_leaks);
    }
}


static struct proc_dir_entry  *memtrack_tree;
static enum memtrack_memtype_t get_rsc_by_name(const char *name)
{
    enum memtrack_memtype_t i;

    for (i = 0; i < MEMTRACK_NUM_OF_MEMTYPES; ++i) {
        if (strcmp(name, rsc_names[i]) == 0) {
            return i;
        }
    }

    return i;
}


static ssize_t memtrack_read(struct file *filp, char __user *buf, size_t size, loff_t *offset)
{
    unsigned long           cur, flags;
    loff_t                  pos = *offset;
    static char             kbuf[20];
    static int              file_len;
    int                     _read, to_ret, left;
    const char             *fname;
    enum memtrack_memtype_t memtype;

    if (pos < 0) {
        return -EINVAL;
    }

    fname = filp->f_path.dentry->d_name.name;

    memtype = get_rsc_by_name(fname);
    if (memtype >= MEMTRACK_NUM_OF_MEMTYPES) {
        sxd_log_mem_err("invalid file name\n");
        return -EINVAL;
    }

    if (pos == 0) {
        memtrack_spin_lock(&tracked_objs_arr[memtype]->hash_lock, flags);
        cur = tracked_objs_arr[memtype]->count;
        memtrack_spin_unlock(&tracked_objs_arr[memtype]->hash_lock, flags);
        _read = sprintf(kbuf, "%lu\n", cur);
        if (_read < 0) {
            return _read;
        } else {
            file_len = _read;
        }
    }

    left = file_len - pos;
    to_ret = (left < size) ? left : size;
    if (copy_to_user(buf, kbuf + pos, to_ret)) {
        return -EFAULT;
    } else {
        *offset = pos + to_ret;
        return to_ret;
    }
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static const struct proc_ops memtrack_proc_fops = {
    .proc_read = memtrack_read
};
#else
static const struct file_operations memtrack_proc_fops = {
    .read = memtrack_read
};
#endif

static const char                  *memtrack_proc_entry_name = "mt_memtrack";
static int create_procfs_tree(void)
{
    struct proc_dir_entry *dir_ent;
    struct proc_dir_entry *proc_ent;
    int                    i, j;
    unsigned long          bit_mask;

    dir_ent = proc_mkdir(memtrack_proc_entry_name, NULL);
    if (!dir_ent) {
        return -1;
    }

    memtrack_tree = dir_ent;

    for (i = 0, bit_mask = 1; i < MEMTRACK_NUM_OF_MEMTYPES; ++i, bit_mask <<= 1) {
        proc_ent = proc_create_data(rsc_names[i], S_IRUGO, memtrack_tree, &memtrack_proc_fops, NULL);
        if (!proc_ent) {
            sxd_log_mem_info("Warning: Cannot create /proc/%s/%s\n",
                   memtrack_proc_entry_name, rsc_names[i]);
            goto undo_create_root;
        }
    }

    goto exit_ok;

undo_create_root:
    for (j = 0, bit_mask = 1; j < i; ++j, bit_mask <<= 1) {
        remove_proc_entry(rsc_names[j], memtrack_tree);
    }
    remove_proc_entry(memtrack_proc_entry_name, NULL);
    return -1;

exit_ok:
    return 0;
}


static void destroy_procfs_tree(void)
{
    int           i;
    unsigned long bit_mask;

    for (i = 0, bit_mask = 1; i < MEMTRACK_NUM_OF_MEMTYPES; ++i, bit_mask <<= 1) {
        remove_proc_entry(rsc_names[i], memtrack_tree);
    }
    remove_proc_entry(memtrack_proc_entry_name, NULL);
}

/* module entry points */

int init_module(void)
{
    enum memtrack_memtype_t i;
    int                     j;
    unsigned long           bit_mask;


    /* create a cache for the memtrack_meminfo_t structures */
    meminfo_cache = kmem_cache_create("memtrack_meminfo_t",
                                      sizeof(struct memtrack_meminfo_t), 0,
                                      SLAB_HWCACHE_ALIGN, NULL);
    if (!meminfo_cache) {
        sxd_log_mem_err("memtrack::%s: failed to allocate meminfo cache\n", __func__);
        return -1;
    }

    /* initialize array of descriptors */
    memset(tracked_objs_arr, 0, sizeof(tracked_objs_arr));

    /* create a tracking object descriptor for all required objects */
    for (i = 0, bit_mask = 1; i < MEMTRACK_NUM_OF_MEMTYPES; ++i, bit_mask <<= 1) {
        tracked_objs_arr[i] = vmalloc(sizeof(struct tracked_obj_desc_t));
        if (!tracked_objs_arr[i]) {
            sxd_log_mem_err("memtrack: failed to allocate tracking object\n");
            goto undo_cache_create;
        }

        memset(tracked_objs_arr[i], 0, sizeof(struct tracked_obj_desc_t));
        spin_lock_init(&tracked_objs_arr[i]->hash_lock);
        INIT_LIST_HEAD(&tracked_objs_arr[i]->tracked_objs_head);
    }

    if (create_procfs_tree()) {
        sxd_log_mem_err("%s: create_procfs_tree() failed\n", __FILE__);
        goto undo_cache_create;
    }

    sxd_log_mem_info("memtrack::%s done.\n", __func__);

    return 0;

undo_cache_create:
    for (j = 0; j < i; ++j) {
        if (tracked_objs_arr[j]) {
            vfree(tracked_objs_arr[j]);
        }
    }

    kmem_cache_destroy(meminfo_cache);
    return -1;
}


void cleanup_module(void)
{
    enum memtrack_memtype_t    memtype;
    unsigned long              cur_bucket;
    struct memtrack_meminfo_t *cur_mem_info_p, *next_mem_info_p;
    struct tracked_obj_desc_t *obj_desc_p;
    unsigned long              flags;


    memtrack_report();


    destroy_procfs_tree();

    /* clean up any hash table left-overs */
    for (memtype = 0; memtype < MEMTRACK_NUM_OF_MEMTYPES; memtype++) {
        /* Scan all buckets to find existing allocations */
        /* TBD: this may be optimized by holding a linked list of all hash items */
        if (tracked_objs_arr[memtype]) {
            obj_desc_p = tracked_objs_arr[memtype];
            for (cur_bucket = 0; cur_bucket < MEMTRACK_HASH_SZ; cur_bucket++) {
                memtrack_spin_lock(&obj_desc_p->hash_lock, flags);      /* protect per bucket/list */
                cur_mem_info_p = obj_desc_p->mem_hash[cur_bucket];
                while (cur_mem_info_p != NULL) {        /* scan bucket */
                    next_mem_info_p = cur_mem_info_p->next; /* save "next" pointer before the "free" */
                    kmem_cache_free(meminfo_cache, cur_mem_info_p);
                    cur_mem_info_p = next_mem_info_p;
                }       /* while cur_mem_info_p */
                memtrack_spin_unlock(&obj_desc_p->hash_lock, flags);
            }       /* for cur_bucket */
            vfree(obj_desc_p);
        }
    }                       /* for memtype */

    kmem_cache_destroy(meminfo_cache);
    sxd_log_mem_info("memtrack::cleanup_module done.\n");
}
