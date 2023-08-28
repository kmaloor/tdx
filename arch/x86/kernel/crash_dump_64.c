// SPDX-License-Identifier: GPL-2.0
/*
 *	Memory preserving reboot related code.
 *
 *	Created by: Hariprasad Nellitheertha (hari@in.ibm.com)
 *	Copyright (C) IBM Corporation, 2004. All rights reserved
 */

#include <linux/errno.h>
#include <linux/crash_dump.h>
#include <linux/uio.h>
#include <linux/io.h>
#include <linux/cc_platform.h>

static inline bool pud_decrypted(pud_t pud)
{
	return cc_mkdec(pud_val(pud)) == pud_val(pud);
}

static inline bool pmd_decrypted(pmd_t pmd)
{
	return cc_mkdec(pmd_val(pmd)) == pmd_val(pmd);
}

static inline bool pte_decrypted(pte_t pte)
{
	return cc_mkdec(pte_val(pte)) == pte_val(pte);
}

/* Assumes page tables are encrypted */
static int __oldmem_is_shared(pgd_t *pgd, unsigned long vaddr)
{
	void *p4d_vaddr = NULL;
	void *pud_vaddr = NULL;
	void *pmd_vaddr = NULL;
	void *pte_vaddr = NULL;
	unsigned long paddr;
	int ret = -ENOENT;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd += pgd_index(vaddr);
	if (!pgd_present(*pgd))
		return -ENOENT;

	if (pgtable_l5_enabled()) {
		paddr = (unsigned long)pgd_val(*pgd) & PTE_PFN_MASK;
		p4d_vaddr = (__force void *)ioremap_encrypted(paddr, PAGE_SIZE);
		if (!p4d_vaddr) {
			ret = -ENOMEM;
			goto out;
		}
		p4d = (p4d_t *)p4d_vaddr + p4d_index(vaddr);
		if (!p4d_present(*p4d))
			goto out;
	} else {
		p4d = (p4d_t *)pgd;
	}

	paddr = (unsigned long)p4d_val(*p4d) & p4d_pfn_mask(*p4d);
	pud_vaddr = (__force void *)ioremap_encrypted(paddr, PAGE_SIZE);
	if (!pud_vaddr) {
		ret = -ENOMEM;
		goto out;
	}
	pud = (pud_t *)pud_vaddr + pud_index(vaddr);
	if (!pud_present(*pud))
		goto out;
	if (pud_leaf(*pud)) {
		ret = pud_decrypted(*pud);
		goto out;
	}

	paddr = (unsigned long)pud_val(*pud) & pud_pfn_mask(*pud);
	pmd_vaddr = (__force void *)ioremap_encrypted(paddr, PAGE_SIZE);
	if (!pmd_vaddr) {
		ret = -ENOMEM;
		goto out;
	}
	pmd = (pmd_t *)pmd_vaddr + pmd_index(vaddr);
	if (!pmd_present(*pmd))
		goto out;
	if (pmd_leaf(*pmd)) {
		ret = pmd_decrypted(*pmd);
		goto out;
	}

	paddr = (unsigned long)pmd_val(*pmd) & pmd_pfn_mask(*pmd);
	pte_vaddr = (__force void *)ioremap_encrypted(paddr, PAGE_SIZE);
	if (!pte_vaddr) {
		ret = -ENOMEM;
		goto out;
	}
	pte = (pte_t *)pte_vaddr + pte_index(vaddr);
	if (!pte_present(*pte))
		goto out;
	ret = pte_decrypted(*pte);
out:
	if (pte_vaddr)
		iounmap((void __iomem *)pte_vaddr);
	if (pmd_vaddr)
		iounmap((void __iomem *)pmd_vaddr);
	if (pud_vaddr)
		iounmap((void __iomem *)pud_vaddr);
	if (p4d_vaddr)
		iounmap((void __iomem *)p4d_vaddr);

	return ret;
}

static pgd_t *oldmem_pgd(void)
{
	unsigned long paddr;
	unsigned long val;
	static pgd_t *pgd;
	static bool done;
	void *ptr;
	int err;

	if (done)
		return pgd;
	done = true;

	err = vmcore_scan_elf_notes("SYMBOL(swapper_pg_dir)=", &val);
	if (err) {
		/*
		 * vmcore ELF notes are read from old memory, which is a
		 * circular dependency, resolved by vmcore by returning
		 * -ENODATA. It has to be assumed that vmcore ELF headers are
		 * not themselves in shared memory.
		 */
		if (err == -ENODATA)
			done = false;
		return pgd;
	}

	err = vmcore_virt_to_phys(val, &paddr);
	if (err) {
		/* See comment above */
		if (err == -ENODATA)
			done = false;
		return pgd;
	}

	/* Assumes page tables are encrypted */
	ptr = (__force void *)ioremap_encrypted(paddr, PAGE_SIZE);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	pgd = ptr;

	return pgd;
}

static int oldmem_is_shared(unsigned long old_vaddr)
{
	pgd_t *pgd = oldmem_pgd();

	if (!pgd)
		return 0;

	if (IS_ERR(pgd))
		return PTR_ERR(pgd);

	return __oldmem_is_shared(pgd, old_vaddr);
}

static ssize_t __copy_oldmem_page(struct iov_iter *iter, unsigned long pfn,
				  unsigned long old_vaddr,
				  size_t csize, unsigned long offset,
				  bool encrypted)
{
	phys_addr_t start = pfn << PAGE_SHIFT;
	void  *vaddr;

	if (!csize)
		return 0;

	if (encrypted) {
		phys_addr_t end = start + PAGE_SIZE;
		int shared;

		if (range_contains_unaccepted_memory(start, end))
			return iov_iter_zero(csize, iter);

		shared = oldmem_is_shared(old_vaddr);
		if (shared < 0) {
			if (shared == -ENOMEM) /* ioremap failed */
				return shared;
			return iov_iter_zero(csize, iter);
		}

		if (shared)
			vaddr = (__force void *)ioremap_cache(start, PAGE_SIZE);
		else
			vaddr = (__force void *)ioremap_encrypted(start, PAGE_SIZE);
	} else {
		vaddr = (__force void *)ioremap_cache(start, PAGE_SIZE);
	}

	if (!vaddr)
		return -ENOMEM;

	csize = copy_to_iter(vaddr + offset, csize, iter);

	iounmap((void __iomem *)vaddr);
	return csize;
}

ssize_t copy_oldmem_page(struct iov_iter *iter, unsigned long pfn, size_t csize,
			 unsigned long offset)
{
	return __copy_oldmem_page(iter, pfn, 0, csize, offset, false);
}

/*
 * copy_oldmem_page_encrypted - same as copy_oldmem_page() above but ioremap the
 * memory with the encryption mask set to accommodate kdump on SME-enabled
 * machines.
 */
ssize_t copy_oldmem_page_encrypted(struct iov_iter *iter, unsigned long pfn, unsigned long old_vaddr,
				   size_t csize, unsigned long offset)
{
	return __copy_oldmem_page(iter, pfn, old_vaddr, csize, offset, true);
}

int remap_oldmem_pfn_range(struct vm_area_struct *vma,
			   unsigned long from, unsigned long pfn,
			   unsigned long size, pgprot_t prot)
{
	unsigned long vma_start, pfn_start, mem_size;
	int shared_mem, ret;

	shared_mem = 0;
	vma_start = from;
	pfn_start = pfn;
	mem_size = size;

	if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST)) {
		unsigned long page, old_vaddr;
		int last_shared = -1;

		mem_size = 0;

		for (page = pfn; page < pfn + size / PAGE_SIZE; page++) {
			mem_size += PAGE_SIZE;

			ret = vmcore_phys_to_virt(page << PAGE_SHIFT, &old_vaddr);
			if (ret < 0)
				return ret;

			shared_mem = oldmem_is_shared(old_vaddr);

			if (last_shared == -1)
				last_shared = shared_mem;

			if (last_shared != shared_mem) {
				ret = remap_pfn_range(vma, vma_start, pfn_start,
						      mem_size - PAGE_SIZE,
						      last_shared ? pgprot_decrypted(prot) :
						      pgprot_encrypted(prot));
				if (ret < 0)
					return ret;

				vma_start += mem_size - PAGE_SIZE;
				pfn_start = page;
				mem_size = PAGE_SIZE;
			}
			last_shared = shared_mem;
		}
	}

	return remap_pfn_range(vma, vma_start, pfn_start, mem_size,
			       shared_mem ? pgprot_decrypted(prot) : pgprot_encrypted(prot));
}

ssize_t elfcorehdr_read(char *buf, size_t count, u64 *ppos)
{
	struct kvec kvec = { .iov_base = buf, .iov_len = count };
	struct iov_iter iter;

	iov_iter_kvec(&iter, ITER_DEST, &kvec, 1, count);

	return read_from_oldmem(&iter, count, ppos,
				cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT));
}
