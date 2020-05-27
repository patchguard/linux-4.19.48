/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Serge Ayoun <serge.ayoun@intel.com>
 * Angie Chinchilla <angie.v.chinchilla@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Cedric Xing <cedric.xing@intel.com>
 */

#include "sgx.h"
#include "driver.h"
#include "encl.h"
#include "encls.h"
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <uapi/asm/sgx.h>

#define SGX_NR_MOD_CHUNK_PAGES 16

#if 0
/*
 *     SGX2.0 definitions
 */

struct sgx_range {
        __u64 start_addr;
        __u64 nr_pages;
};

struct sgx_modification_param {
        struct sgx_range range;
        __u64 flags;
};
#endif

void sgx_ipi_cb(void *info)
{
}


int sgx_init_page(struct sgx_encl *encl, struct sgx_encl_page *entry,
		  unsigned long addr, unsigned int alloc_flags,
		  struct sgx_epc_page **va_src, bool already_locked)
{
	struct sgx_va_page *va_page;
	struct sgx_epc_page *epc_page = NULL;
	unsigned int va_offset = PAGE_SIZE;
	void *vaddr;
	int ret = 0;

	list_for_each_entry(va_page, &encl->va_pages, list) {
		va_offset = sgx_alloc_va_slot(va_page);
		if (va_offset < PAGE_SIZE)
			break;
	}

	if (va_offset == PAGE_SIZE) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;

		if (va_src) {
			epc_page = *va_src;
			*va_src = NULL;
		} else {
			epc_page = sgx_alloc_page(NULL,true);
			if (IS_ERR(epc_page)) {
				kfree(va_page);
				return PTR_ERR(epc_page);
			}
		}

		vaddr = sgx_epc_addr(epc_page);
		if (!vaddr) {
			sgx_free_page(epc_page);
			kfree(va_page);
			return -EFAULT;
		}

		ret = __epa(vaddr);

		if (ret) {
			sgx_free_page(epc_page);
			kfree(va_page);
			return -EFAULT;
		}

		va_page->epc_page = epc_page;
		va_offset = sgx_alloc_va_slot(va_page);

		if (!already_locked)
			mutex_lock(&encl->lock);
		list_add(&va_page->list, &encl->va_pages);
		if (!already_locked)
			mutex_unlock(&encl->lock);
	}

	entry->va_page = va_page;

	return 0;
}

static int sgx_test_and_clear_young_cb(pte_t *ptep,
		pgtable_t token,
		unsigned long addr, void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}

/**
 * sgx_test_and_clear_young() - Test and reset the accessed bit
 * @page:	enclave EPC page to be tested for recent access
 * @encl:	enclave which owns @page
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it.  Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
int sgx_test_and_clear_young(struct sgx_encl_page *page, struct sgx_encl *encl,unsigned long addr)
{
	struct vm_area_struct *vma;
        struct sgx_encl_mm *encl_mm;
	int ret;

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
                 if (!mmget_not_zero(encl_mm->mm))
                         continue;

                 ret = sgx_encl_find(encl_mm->mm, addr, &vma);
                 if (ret)
                        break;
        }

	if (encl != vma->vm_private_data)
		return 0;

	return apply_to_page_range(vma->vm_mm, addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}


/**
 * sgx_encl_augment() - adds a page to an enclave
 * @addr:	virtual address where the page should be added
 *
 * the address is checked against the dynamic ranges defined for
 * the enclave. If it matches one, a page is added at the
 * corresponding location
 *
 * Note: Invoking function must already hold the encl->lock
 */
struct sgx_encl_page *sgx_encl_augment(struct vm_area_struct *vma,
				       unsigned long addr,
				       bool write)
{

        struct sgx_pageinfo pginfo;
	struct sgx_epc_page *epc_page, *va_page = NULL;
	struct sgx_epc_page *secs_epc_page = NULL;
	struct sgx_encl_page *encl_page;
	struct sgx_encl *encl = (struct sgx_encl *) vma->vm_private_data;
	void *epc_va;
	void *secs_va;
	int ret = -EFAULT;

	if (!sgx_has_sgx2)
		return ERR_PTR(-EFAULT);

	/* if vma area is not writable then we will not eaug */
	if (unlikely(!(vma->vm_flags & VM_WRITE)))
		return ERR_PTR(-EFAULT);

	addr &= ~(PAGE_SIZE-1);

	/* Note: Invoking function holds the encl->lock */

	epc_page = sgx_alloc_page(NULL, true);
	if (IS_ERR(epc_page)) {
		return ERR_PTR(PTR_ERR(epc_page));
	}

	va_page = sgx_alloc_va_page();
	if (IS_ERR(va_page)) {
		sgx_free_page(va_page);
		return ERR_PTR(PTR_ERR(va_page));
	}

	encl_page = kzalloc(sizeof(struct sgx_encl_page), GFP_KERNEL);
	if (!encl_page) {
		sgx_free_page(epc_page);
		sgx_free_page(va_page);
		return ERR_PTR(-EFAULT);
	}
#if 0
	if (!(encl->flags & SGX_ENCL_INITIALIZED))
		goto out;

	if (encl->flags & (SGX_ENCL_SUSPEND | SGX_ENCL_DEAD))
		goto out;
#endif
	/*
	if ((rg->rg_desc.flags & SGX_GROW_DOWN_FLAG) && !write)
		goto out;
	*/

	/* Start the augmenting process */
	ret = sgx_init_page(encl, encl_page, addr, 0, &va_page, true);
	if (ret)
		goto out;

	secs_va = sgx_epc_addr(encl->secs.epc_page);
	epc_va = sgx_epc_addr(epc_page);

	pginfo.contents = 0;
	pginfo.metadata = 0;
	pginfo.addr = addr;
	pginfo.secs = (unsigned long) secs_va;

	ret = __eaug(&pginfo, epc_va);
	if (ret) {
		goto out;
	}

	ret = vmf_insert_pfn(vma, addr, PFN_DOWN(epc_page->desc));
	if (ret != VM_FAULT_NOPAGE) {
		goto out;
	}

	epc_page->owner = encl_page;
	encl_page->epc_page = epc_page;
	encl->secs_child_cnt++;

	ret = radix_tree_insert(&encl->page_tree, PFN_DOWN(encl_page->desc),
			        encl_page);
	if (ret) {
		goto out;
	}
	sgx_test_and_clear_young(encl_page, encl,addr);

	if (va_page)
		sgx_free_page(va_page);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page);

	/*
	 * Write operation corresponds to stack extension
	 * In this case the #PF is caused by a write operation,
	 * most probably a push.
	 * We return SIGBUS such that the OS invokes the enclave's exception
	 * handler which will execute eaccept.
	 */
	if (write)
		return ERR_PTR(-EFAULT);

	return encl_page;

out:
	if (encl_page->va_page)
		sgx_free_va_slot(encl_page->va_page, SGX_ENCL_PAGE_VA_OFFSET(encl_page));
	sgx_free_page(epc_page);
	if (va_page)
		sgx_free_page(va_page);
	kfree(encl_page);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page);

	if ((ret == -EBUSY)||(ret == -ERESTARTSYS))
		return ERR_PTR(ret);

	return ERR_PTR(-EFAULT);


}

static int isolate_range(struct sgx_encl *encl,
			 struct sgx_range *rg, struct list_head *list)
{
        unsigned long address, end;
	struct sgx_encl_page *encl_page;
        struct sgx_encl_mm *encl_mm;
	struct vm_area_struct *vma;
	int ret;
        int idx;

	address = rg->start_addr;
	end = address + rg->nr_pages * PAGE_SIZE;

	for (; address < end; address += PAGE_SIZE) {

                idx = srcu_read_lock(&encl->srcu);

                list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
               		 if (!mmget_not_zero(encl_mm->mm))
       		                 continue;

       	        	 ret = sgx_encl_find(encl_mm->mm, address, &vma);
	                 if (ret)
                	        break;
       		}

	        srcu_read_unlock(&encl->srcu, idx);


		if (ret || encl != vma->vm_private_data) {
			return -EINVAL;
		}
#if 0
		encl_page = ERR_PTR(-EBUSY);
		while (encl_page == ERR_PTR(-EBUSY))
			/* bring back page in case it was evicted */
			encl_page = sgx_fault_page(vma, address,
						   SGX_FAULT_RESERVE, NULL);
#endif
       		encl_page = radix_tree_lookup(&encl->page_tree, address >> PAGE_SHIFT);

	        if (!encl_page)
        	        return -EINVAL;

		/* We do not need the reserved bit anymore as page
		 * is removed from the load list
		 */
		mutex_lock(&encl->lock);
		list_move_tail(&encl_page->epc_page->list, list);
#if 0
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
#endif
		mutex_unlock(&encl->lock);
	}

	return 0;
}

static int __modify_range(struct sgx_encl *encl,
			  struct sgx_range *rg, struct sgx_secinfo *secinfo)
{
        struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page, *tmp;
	LIST_HEAD(list);
	bool emodt = secinfo->flags & (SGX_SECINFO_TRIM | SGX_SECINFO_TCS);
	unsigned int epoch = 0;
	void *epc_va;
	int ret = 0, cnt, status = 0;

	ret = isolate_range(encl, rg, &list);
	if (ret)
		goto out;

	if (list_empty(&list))
		goto out;

	/* EMODT / EMODPR */
	list_for_each_entry_safe(epc_page, tmp, &list, list) {
#if 0
		encl_page = epc_page->encl_page;
		if (!emodt && (encl_page->flags & SGX_ENCL_PAGE_TCS)) {
			ret = -EINVAL;
			continue;
		}
#endif
		mutex_lock(&encl->lock);
		epc_va = sgx_epc_addr(epc_page);
		status = SGX_LOCKFAIL;
		cnt = 0;
		while (SGX_LOCKFAIL == status && cnt < SGX_EDMM_SPIN_COUNT) {
			if (emodt) {
				status = __emodt(secinfo, epc_va);
				//if (!status)
				//	encl_page->flags |= SGX_ENCL_PAGE_TCS;
			} else
				status = __emodpr(secinfo, epc_va);
			cnt++;
		}

		mutex_unlock(&encl->lock);

		if (status) {
			ret = (ret) ? ret : status;
		} else {
//			if (SGX_SECINFO_TRIM == secinfo->flags)
//				encl_page->flags |= SGX_ENCL_PAGE_TRIM;
		}

		/* ETRACK */
		mutex_lock(&encl->lock);
		__etrack(epc_va);
		mutex_unlock(&encl->lock);
	}

	smp_call_function(sgx_ipi_cb, NULL, 1);

out:
	if (!list_empty(&list)) {
		mutex_lock(&encl->lock);
		list_splice(&list, &encl_page->epc_page->list);
		mutex_unlock(&encl->lock);
	}

	return ret;

}

long modify_range(struct sgx_encl *encl,struct sgx_range *rg, unsigned long flags)
{
	struct sgx_secinfo secinfo;
	struct sgx_range _rg ;
        unsigned long end = 0;
        int ret = 0;

	end = rg->start_addr + rg->nr_pages * PAGE_SIZE;
	if (rg->start_addr & (PAGE_SIZE - 1))
		return -EINVAL;

	if (!rg->nr_pages)
		return -EINVAL;

	if (end > encl->base + encl->size) {
		return -EINVAL;
	}

	memset(&secinfo, 0, sizeof(secinfo));
	secinfo.flags = flags;

	/*
	 * Modifying the range by chunks of 16 pages:
	 * these pages are removed from the load list. Bigger chunks
	 * may empty EPC load lists and stall SGX.
	 */
	for (_rg.start_addr = rg->start_addr;
	     _rg.start_addr < end;
	     rg->nr_pages -= SGX_NR_MOD_CHUNK_PAGES,
	     _rg.start_addr += SGX_NR_MOD_CHUNK_PAGES*PAGE_SIZE) {
		_rg.nr_pages = rg->nr_pages > 0x10 ? 0x10 : rg->nr_pages;
		ret = __modify_range(encl, &_rg, &secinfo);
		if (ret)
			break;
	}

	return ret;
}

int remove_page(struct sgx_encl *encl, unsigned long address, bool trim)
{
	struct sgx_va_page *va_page;
	int ret;

	struct vm_area_struct *vma = NULL;
	struct sgx_encl_mm *encl_mm;
	struct sgx_encl_page *encl_page;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		ret = sgx_encl_find(encl_mm->mm, address, &vma);
        	if (ret)
			break;
	}

	srcu_read_unlock(&encl->srcu, idx);

	if (encl != vma->vm_private_data || !ret)
		return -EINVAL;


	encl_page = radix_tree_lookup(&encl->page_tree, address >> PAGE_SHIFT);

	if (!encl_page)
		return -EINVAL;

#if 0
	if (trim && !(encl_page->flags & SGX_ENCL_PAGE_TRIM)) {
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		return -EINVAL;
	}

	if (!(encl_page->flags & SGX_ENCL_PAGE_ADDED)) {
		encl_page->flags &= ~SGX_ENCL_PAGE_RESERVED;
		return -EINVAL;
	}

#endif

	mutex_lock(&encl->lock);

	radix_tree_delete(&encl_page->encl->page_tree, PFN_DOWN(encl_page->desc));
	va_page = encl_page->va_page;

	if (va_page) {
		sgx_free_va_slot(va_page, SGX_ENCL_PAGE_VA_OFFSET(encl_page));
		sgx_free_page(va_page->epc_page);
		list_del(&va_page->list);
		kfree(va_page);
	}

	if (encl_page->epc_page) {
		list_del(&encl_page->epc_page->list);
		zap_vma_ptes(vma, SGX_ENCL_PAGE_ADDR(encl_page->epc_page), PAGE_SIZE);
		sgx_free_page(encl_page->epc_page);
		encl->secs_child_cnt--;
	}

	mutex_unlock(&encl->lock);

	kfree(encl_page);

	return 0;
}
