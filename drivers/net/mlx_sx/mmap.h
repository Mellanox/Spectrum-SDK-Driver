/*
 * SPDX-FileCopyrightText: Copyright (c) 2010-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

#ifndef __SX_CORE_MMAP_H__
#define __SX_CORE_MMAP_H__

struct file;
struct vm_area_struct;
struct seq_file;

typedef void (*mmap_pfn_dtor)(unsigned long user_ptr, pid_t pid, unsigned long size);

int sx_core_mmap(struct file *filp, struct vm_area_struct *vma);
void* sx_mmap_user_to_kernel(pid_t pid, unsigned long user_ptr);
int sx_mmap_dump(struct seq_file *m, void *v, void *context);
void sx_mmap_ref_inc(pid_t pid, unsigned long user_ptr);
void sx_mmap_ref_dec(pid_t pid, unsigned long user_ptr);
void sx_mmap_set_pfn_dtor(unsigned long user_ptr, pid_t pid, uint64_t usr_size, mmap_pfn_dtor pfn_dtor);
#endif /* __SX_CORE_MMAP_H__ */
