#define pr_fmt(fmt)  "tdx: " fmt

#include <linux/pagewalk.h>
#include <asm/tdx.h>
#include <asm/x86_init.h>

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

static inline void unshare_range(unsigned long start, unsigned long end)
{
	int pages = (end - start) / PAGE_SIZE;

	if (!tdx_enc_status_changed(start, pages, true))
		pr_err("Failed to unshare range %#lx-%#lx\n", start, end);
}

static int unshare_pud(pud_t *pud, unsigned long addr, unsigned long next,
		       struct mm_walk *walk)
{
	if (pud_decrypted(*pud))
		unshare_range(addr, next);

	return 0;
}

static int unshare_pmd(pmd_t *pmd, unsigned long addr, unsigned long next,
		       struct mm_walk *walk)
{
	if (pmd_decrypted(*pmd))
		unshare_range(addr, next);

	return 0;
}

static int unshare_pte(pte_t *pte, unsigned long addr, unsigned long next,
		       struct mm_walk *walk)
{
	if (pte_decrypted(*pte))
		unshare_range(addr, next);

	return 0;
}

static const struct mm_walk_ops unshare_ops = {
	.pud_entry = unshare_pud,
	.pmd_entry = unshare_pmd,
	.pte_entry = unshare_pte,
};

void tdx_kexec_prepare(bool crash)
{
	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return;

	/*
	 * Crash kernel may want to see data in the shared buffers.
	 * Do not revert them to private on kexec of crash kernel.
	 */
	if (crash)
		return;

	/*
	 * Walk direct mapping and convert all shared memory back to private,
	 * so the target kernel will be able use it normally.
	 */
	mmap_write_lock(&init_mm);
	walk_page_range_novma(&init_mm,
			      PAGE_OFFSET,
			      PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT),
			      &unshare_ops, init_mm.pgd, NULL);
	mmap_write_unlock(&init_mm);
}
