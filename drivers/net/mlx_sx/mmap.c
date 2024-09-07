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

#include <linux/hashtable.h>
#include <linux/seq_file.h>
#include <linux/mlx_sx/kernel_user.h>
#include <linux/sched.h>
#include "sx.h"

#define HASH_SIZE_IN_BITS (6) /* 64 buckets */

static DEFINE_HASHTABLE(__mmap_entries, HASH_SIZE_IN_BITS);
static DEFINE_SPINLOCK(__mmap_entries_lock);

struct sx_mmap_metadata {
    pid_t                      pid; /* the PID of the mmap() caller */
    void                      *realdata; /* the real allocation for mmap() */
    void                      *data; /* the page-aligned pointer within the real allocation */
    unsigned long              user_ptr; /* user-space pointer of mmap() */
    unsigned long              size; /* size of allocation */
    uint32_t                   refcnt; /* reference count for the mmap() allocation */
    struct hlist_node          h_entry;
    ku_mmap_mem_alloc_scheme_e mmap_alloc_scheme;  /* memory map allocation scheme (vmalloc or kmalloc) */
};

static void __sx_vm_open(struct vm_area_struct *vma)
{
    struct sx_mmap_metadata *metadata = (struct sx_mmap_metadata*)vma->vm_private_data;

    spin_lock_bh(&__mmap_entries_lock);
    metadata->refcnt++;
    spin_unlock_bh(&__mmap_entries_lock);
}

static void __sx_vm_close(struct vm_area_struct *vma)
{
    struct sx_mmap_metadata *metadata = (struct sx_mmap_metadata*)vma->vm_private_data;

    spin_lock_bh(&__mmap_entries_lock);
    if (--metadata->refcnt == 0) {
        hash_del(&metadata->h_entry);
        spin_unlock_bh(&__mmap_entries_lock);

        if (metadata->mmap_alloc_scheme == KU_MMAP_MEM_ALLOC_SCHEME_VMALLOC) {
            vfree(metadata->realdata);
        } else {
            kfree(metadata->realdata);
        }
        kfree(metadata);
    } else {
        spin_unlock_bh(&__mmap_entries_lock);
    }
}

const struct vm_operations_struct __sx_vm_ops = {
    .open = __sx_vm_open,
    .close = __sx_vm_close
};

int sx_core_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long            pfn, size;
    struct sx_mmap_metadata *metadata = NULL;
    void                    *alloc = NULL;
    int                      ret = 0;
    struct sx_rsc           *rsc = filp->private_data;

    if (!PAGE_ALIGNED(vma->vm_start) || !PAGE_ALIGNED(vma->vm_end)) {
        sxd_log_err("mapped area is not aligned with PAGE_SIZE\n");
        ret = -EINVAL;
        goto out;
    }

    size = vma->vm_end - vma->vm_start; /* size is multiple of PAGE_SIZE */
    if (size == 0) {
        sxd_log_err("size of mapped area is 0\n");
        ret = -EINVAL;
        goto out;
    }

    metadata = kzalloc(sizeof(*metadata), GFP_KERNEL);
    if (!metadata) {
        ret = -ENOMEM;
        goto out;
    }

    /* on debug-kernel, the allocation that is mapped to userspace MUST be aligned to PAGE_SIZE.
     * thus, we're allocating enough space that we can return a page-aligned pointer */
    if (rsc->mmap_alloc_scheme == KU_MMAP_MEM_ALLOC_SCHEME_VMALLOC) {
        metadata->realdata = vmalloc_user(size + PAGE_SIZE);
        if (!metadata->realdata) {
            sxd_log_err("vmalloc memory allocation failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        /* if allocation succeeded, get the page-aligned pointer within the allocated area */
        alloc = (void*)PAGE_ALIGN((unsigned long)metadata->realdata);
        ret = remap_vmalloc_range(vma, alloc, 0);
        if (ret) {
            sxd_log_err("vmalloc remap failed error=%d, vma=0x%p, alloc=0x%p, size=%ld, start=%ld, end=%ld\n",
                        ret, vma, alloc, size, vma->vm_start, vma->vm_end);
            goto out;
        }
    } else {
        if (size + PAGE_SIZE > KMALLOC_MAX_SIZE) {
            sxd_log_err("Size of mapped area %ld exceed max size %ld with kmalloc memory allocation scheme.\n",
                        size + PAGE_SIZE, KMALLOC_MAX_SIZE);
            ret = -EINVAL;
            goto out;
        }

        metadata->realdata = kmalloc(size + PAGE_SIZE, GFP_KERNEL);
        if (!metadata->realdata) {
            sxd_log_err("kmalloc memory allocation failed.\n");
            ret = -ENOMEM;
            goto out;
        }
        /* if allocation succeeded, get the page-aligned pointer within the allocated area */
        alloc = (void*)PAGE_ALIGN((unsigned long)metadata->realdata);
        pfn = virt_to_phys(alloc) >> PAGE_SHIFT;
        ret = remap_pfn_range(vma,
                              vma->vm_start,
                              pfn,
                              size,
                              vma->vm_page_prot);
        if (ret) {
            sxd_log_err("kmalloc remap failed error=%d, vma=0x%p, alloc=0x%p, size=%ld, start=%ld, end=%ld\n",
                        ret, vma, alloc, size, vma->vm_start, vma->vm_end);
            goto out;
        }
    }

    metadata->pid = current->tgid;
    metadata->refcnt = 1;
    metadata->data = alloc;
    metadata->user_ptr = vma->vm_start;
    metadata->size = size;
    metadata->mmap_alloc_scheme = rsc->mmap_alloc_scheme;

    spin_lock_bh(&__mmap_entries_lock);
    hash_add(__mmap_entries, &metadata->h_entry, metadata->user_ptr);
    spin_unlock_bh(&__mmap_entries_lock);

    vma->vm_ops = &__sx_vm_ops;
    vma->vm_private_data = metadata;

out:
    if (ret) {
        if (metadata) {
            if (metadata->realdata) {
                if (rsc->mmap_alloc_scheme == KU_MMAP_MEM_ALLOC_SCHEME_VMALLOC) {
                    vfree(metadata->realdata);
                } else {
                    kfree(metadata->realdata);
                }
            }
            kfree(metadata);
        }
    }
    return ret;
}

void* sx_mmap_user_to_kernel(pid_t pid, unsigned long user_ptr)
{
    struct sx_mmap_metadata *iter;
    void                    *ptr = NULL;

    spin_lock_bh(&__mmap_entries_lock);

    hash_for_each_possible(__mmap_entries, iter, h_entry, user_ptr) {
        if ((iter->pid == pid) && (iter->user_ptr == user_ptr)) {
            ptr = iter->data;
            break;
        }
    }

    spin_unlock_bh(&__mmap_entries_lock);
    return ptr;
}

void sx_mmap_ref_inc(pid_t pid, unsigned long user_ptr)
{
    struct sx_mmap_metadata *iter;

    spin_lock_bh(&__mmap_entries_lock);

    hash_for_each_possible(__mmap_entries, iter, h_entry, user_ptr) {
        if ((iter->pid == pid) && (iter->user_ptr == user_ptr)) {
            iter->refcnt++;
            break;
        }
    }

    spin_unlock_bh(&__mmap_entries_lock);
}

void sx_mmap_ref_dec(pid_t pid, unsigned long user_ptr)
{
    struct sx_mmap_metadata *iter;

    spin_lock_bh(&__mmap_entries_lock);

    hash_for_each_possible(__mmap_entries, iter, h_entry, user_ptr) {
        if ((iter->pid == pid) && (iter->user_ptr == user_ptr)) {
            iter->refcnt--;
            if (iter->refcnt == 0) {
                if (iter->mmap_alloc_scheme == KU_MMAP_MEM_ALLOC_SCHEME_VMALLOC) {
                    vfree(iter->realdata);
                } else {
                    kfree(iter->realdata);
                }
                hash_del(&iter->h_entry);
                kfree(iter);
            }
            break;
        }
    }
    spin_unlock_bh(&__mmap_entries_lock);
}

int sx_mmap_dump(struct seq_file *m, void *v, void *context)
{
    struct sx_mmap_metadata *iter;
    int                      bucket;

    seq_printf(m, "----------------------------------------------------------------------\n");
    seq_printf(m, "%-8s   %-18s   %-8s   %-6s\n",
               "owner", "allocation", "size", "refcnt");
    seq_printf(m, "----------------------------------------------------------------------\n");

    spin_lock_bh(&__mmap_entries_lock);

    hash_for_each(__mmap_entries, bucket, iter, h_entry) {
        seq_printf(m, "%-8u   0x%-16p   %-8lu   %-6u\n",
                   iter->pid,
                   iter->data,
                   iter->size,
                   iter->refcnt);
    }

    spin_unlock_bh(&__mmap_entries_lock);
    return 0;
}
