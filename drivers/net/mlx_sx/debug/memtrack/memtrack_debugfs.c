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

#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include "memtrack.h"

struct memtrack_dump_info {
    struct dentry   *dentry;
    struct list_head alloc_list;
    struct mutex     lock;
    bool             locked;
};
static struct memtrack_dump_info __memtrack_dump_info;

static void * __memtrack_dump_start(struct seq_file *m, loff_t *pos)
{
    return seq_list_start(&__memtrack_dump_info.alloc_list, *pos);
}

static int __memtrack_dump_show(struct seq_file *m, void *v)
{
    struct memtrack_entry *entry;
    char                   file_info_str[32];
    char                   process_info_str[32];
    char                   type_info_str[256];
    unsigned short         hash;

    entry = list_entry(v, struct memtrack_entry, debugfs_list);

    snprintf(file_info_str, sizeof(file_info_str) - 1, "%s:%d", entry->src_file, entry->src_line);
    file_info_str[sizeof(file_info_str) - 1] = '\0';

    snprintf(process_info_str, sizeof(process_info_str) - 1, "%d:%s", entry->pid, entry->process_name);
    process_info_str[sizeof(process_info_str) - 1] = '\0';

    entry->ops->memtrack_dump_type_data(entry, type_info_str, sizeof(type_info_str));
    hash = memtrack_db_hash_get(entry->key);

    seq_printf(m, "%-15s  %-20s  %-20s  %5us  %05u  [%s]\n",
               memtrack_type_str(entry->type),
               file_info_str,
               process_info_str,
               jiffies_to_msecs(jiffies - entry->timestamp) / 1000, /* age in seconds */
               hash,
               type_info_str);

    return 0;
}

static void * __memtrack_dump_next(struct seq_file *m, void *v, loff_t *pos)
{
    return seq_list_next(v, &__memtrack_dump_info.alloc_list, pos);
}

static void __memtrack_dump_stop(struct seq_file *m, void *v)
{
    /* for now, do nothing here */
}

static const struct seq_operations __memtrack_seq_ops = {
    .start = __memtrack_dump_start,
    .show = __memtrack_dump_show,
    .next = __memtrack_dump_next,
    .stop = __memtrack_dump_stop
};

static int __memtrack_dump_open(struct inode *inode, struct file *file)
{
    int ret;

    ret = seq_open(file, &__memtrack_seq_ops);
    if (ret == 0) {
        /* trying to grab the mutex and let user terminate the operation */
        ret = mutex_lock_interruptible(&__memtrack_dump_info.lock);
        if (ret == 0) {
            __memtrack_dump_info.locked = true;

            INIT_LIST_HEAD(&__memtrack_dump_info.alloc_list);
            memtrack_db_init_debugfs_list(&__memtrack_dump_info.alloc_list);
        }
    }

    return ret;
}

static int __memtrack_dump_release(struct inode *inode, struct file *file)
{
    if (__memtrack_dump_info.locked) {
        memtrack_db_deinit_debugfs_list(&__memtrack_dump_info.alloc_list);
        __memtrack_dump_info.locked = false;
        mutex_unlock(&__memtrack_dump_info.lock);
    }

    return seq_release(inode, file);
}

static const struct file_operations __memtrack_dump_fops = {
    .owner = THIS_MODULE,
    .open = __memtrack_dump_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = __memtrack_dump_release
};

int memtrack_debugfs_create(void)
{
    int ret = 0;

    mutex_init(&__memtrack_dump_info.lock);
    __memtrack_dump_info.locked = false;
    __memtrack_dump_info.dentry = debugfs_create_file("memtrack_dump", 0444, NULL, NULL, &__memtrack_dump_fops);
    if (IS_ERR(__memtrack_dump_info.dentry)) {
        ret = PTR_ERR(__memtrack_dump_info.dentry);
    }

    return ret;
}

void memtrack_debugfs_destroy(void)
{
    debugfs_remove(__memtrack_dump_info.dentry);
}
