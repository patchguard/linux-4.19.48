/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause) */
/**
 * Copyright(c) 2016-19 Intel Corporation.
 */
#ifndef _X86_ENCL2_H
#define _X86_ENCL2_H

#include <linux/cpumask.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/radix-tree.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>
#include "sgx.h"

struct sgx_encl_page *sgx_encl_augment(struct vm_area_struct *vma,
				       unsigned long addr,
				       bool write);
long modify_range(struct sgx_encl *encl,struct sgx_range *rg, unsigned long flags);
int remove_page(struct sgx_encl *encl, unsigned long address, bool trim);

#endif /* _X86_ENCL2_H */

