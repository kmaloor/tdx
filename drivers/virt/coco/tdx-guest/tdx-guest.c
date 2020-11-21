// SPDX-License-Identifier: GPL-2.0
/*
 * TDX guest user interface driver
 *
 * Copyright (C) 2022 Intel Corporation
 */

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/set_memory.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <keys/tsm.h>

#include <uapi/linux/tdx-guest.h>

#include <asm/cpu_device_id.h>
#include <asm/irqdomain.h>
#include <asm/tdx.h>

/*
 * Intel's SGX QE implementation generally uses Quote size less
 * than 8K; Use 16K as MAX size to handle future updates and other
 * 3rd party implementations.
 */
#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)

#define GET_QUOTE_CMD_VER		1

/* TDX GetQuote status codes */
#define GET_QUOTE_SUCCESS		0
#define GET_QUOTE_IN_FLIGHT		0xffffffffffffffff

/* struct tdx_quote_buf: Format of Quote request buffer.
 * @version: Quote format version, filled by TD.
 * @status: Status code of Quote request, filled by VMM.
 * @in_len: Length of TDREPORT, filled by TD.
 * @out_len: Length of Quote data, filled by VMM.
 * @data: Quote data on output or TDREPORT on input.
 *
 * More details of Quote request buffer can be found in TDX
 * Guest-Host Communication Interface (GHCI) for Intel TDX 1.0,
 * section titled "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_buf {
	u64 version;
	u64 status;
	u32 in_len;
	u32 out_len;
	u8 data[];
};

/**
 * struct quote_entry - Quote request struct
 * @buf: Kernel buffer to share data with VMM (size is page aligned).
 * @buf_len: Size of the buf in bytes.
 * @compl: Completion object to track completion of GetQuote request.
 */
struct quote_entry {
	void *buf;
	size_t buf_len;
	struct completion compl;
};

/* Quote data entry */
static struct quote_entry *qentry;

/* Lock to streamline quote requests */
static DEFINE_MUTEX(quote_lock);

static long tdx_get_report0(struct tdx_report_req __user *req)
{
	u8 *reportdata, *tdreport;
	long ret;

	reportdata = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	tdreport = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(reportdata, req->reportdata, TDX_REPORTDATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret)
		goto out;

	if (copy_to_user(req->tdreport, tdreport, TDX_REPORT_LEN))
		ret = -EFAULT;

out:
	kfree(reportdata);
	kfree(tdreport);

	return ret;
}

static void free_shared_pages(void *buf, size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;

	set_memory_encrypted((unsigned long)buf, count);

	free_pages_exact(buf, PAGE_ALIGN(len));
}

static void *alloc_shared_pages(size_t len)
{
	unsigned int count = PAGE_ALIGN(len) >> PAGE_SHIFT;
	void *addr;
	int ret;

	addr = alloc_pages_exact(len, GFP_KERNEL);
	if (!addr)
		return NULL;

	ret = set_memory_decrypted((unsigned long)addr, count);
	if (ret) {
		free_pages_exact(addr, PAGE_ALIGN(len));
		return NULL;
	}

	return addr;
}

static struct quote_entry *alloc_quote_entry(size_t len)
{
	struct quote_entry *entry = NULL;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->buf = alloc_shared_pages(len);
	if (!entry->buf) {
		kfree(entry);
		return NULL;
	}

	entry->buf_len = PAGE_ALIGN(len);
	init_completion(&entry->compl);

	return entry;
}

static void free_quote_entry(struct quote_entry *entry)
{
	free_shared_pages(entry->buf, entry->buf_len);
	kfree(entry);
}

static int tdx_auth_new(struct tsm_key_payload *t, void *data)
{
	struct tdx_quote_buf *quote_buf = qentry->buf;
	long ret;

	if (t->pubkey_len != TDX_REPORTDATA_LEN)
		return -EINVAL;

	/* TDX attestation does not support multiple formats */
	if (t->auth_blob_format[0])
		return -EINVAL;

	u8 *reportdata __free(kfree) = kmalloc(TDX_REPORTDATA_LEN, GFP_KERNEL);
	if (!reportdata)
		return -ENOMEM;

	u8 *tdreport __free(kfree) = kzalloc(TDX_REPORT_LEN, GFP_KERNEL);
	if (!tdreport)
		return -ENOMEM;

	guard(mutex)(&quote_lock);

	memcpy(reportdata, t->pubkey, TDX_REPORTDATA_LEN);

	/* Generate TDREPORT0 using "TDG.MR.REPORT" TDCALL */
	ret = tdx_mcall_get_report0(reportdata, tdreport);
	if (ret) {
		pr_err("GetReport call failed\n");
		return ret;
	}

	memset(qentry->buf, 0, qentry->buf_len);

	/* Update Quote buffer header */
	quote_buf->version = GET_QUOTE_CMD_VER;
	quote_buf->status = GET_QUOTE_SUCCESS;
	quote_buf->in_len = TDX_REPORT_LEN;
	quote_buf->out_len = 0;

	memcpy(quote_buf->data, tdreport, TDX_REPORT_LEN);

	reinit_completion(&qentry->compl);

	/*
	 * Submit GetQuote request using GetQuote hypercall. Since buf is
	 * a shared memory, set the shared (decrypted) bits. Refer to section
	 * titled "TDG.VP.VMCALL<GetQuote>" in the TDX GHCI v1.0 specification
	 * for more information on GetQuote hypercall.
	 */
	ret = _tdx_hypercall(TDVMCALL_GET_QUOTE, cc_mkdec(virt_to_phys(qentry->buf)),
			     qentry->buf_len, 0, 0);
	if (ret) {
		pr_err("GetQuote hypercall failed, status:%lx\n", ret);
		return -EIO;
	}

	/*
	 * Although the GHCI specification does not state explicitly that
	 * the VMM must not wait indefinitely for the Quote request to be
	 * completed, a sane VMM should always notify the guest after a
	 * certain time, regardless of whether the Quote generation is
	 * successful or not.  For now just assume the VMM will do so.
	 */
	wait_for_completion(&qentry->compl);

	t->auth_blob = kvmemdup(quote_buf->data, quote_buf->out_len, GFP_KERNEL);
	if (!t->auth_blob)
		return -ENOMEM;

	t->auth_blob_len = quote_buf->out_len;
	t->auth_blob_desc = "tdx";

	return 0;
}

static long tdx_guest_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	switch (cmd) {
	case TDX_CMD_GET_REPORT0:
		return tdx_get_report0((struct tdx_report_req __user *)arg);
	default:
		return -ENOTTY;
	}
}

static irqreturn_t quote_irq_handler(int irq, void *dev_id)
{
	struct tdx_quote_buf *quote_buf = qentry->buf;

	/* Use version and in_len to check for a valid request */
	if (quote_buf->version == GET_QUOTE_CMD_VER &&
	    quote_buf->in_len == TDX_REPORT_LEN &&
	    quote_buf->status != GET_QUOTE_IN_FLIGHT)
		complete(&qentry->compl);

	return IRQ_HANDLED;
}

/*
 * tdx_guest_alloc_irq() - Allocate IRQ for event notification between VMM and
 *			   the TDX Guest.
 *
 * Use SetupEventNotifyInterrupt TDVMCALL to register the event notification
 * IRQ with the VMM, which is used by the VMM to notify the TDX guest when
 * VMM finishes the GetQuote request from the TDX guest. The VMM always
 * notifies the TDX guest via the same CPU that calls the
 * SetupEventNotifyInterrupt TDVMCALL. Allocate an IRQ/vector from the
 * x86_vector_domain and pin it on the same CPU on which TDVMCALL is called.
 */
static int tdx_guest_alloc_irq(struct device *dev)
{
	cpumask_t saved_cpumask;
	int ret, cpu, irq;
	u64 vector;

	cpu = smp_processor_id();

	/* Allocate IRQ and pin it on the given CPU */
	irq = tdx_get_event_irq(cpu);
	if (irq <= 0)
		return -EIO;

	/*
	 * Set the IRQ with IRQF_NOBALANCING to prevent its affinity from being
	 * changed.
	 */
	ret = request_irq(irq, quote_irq_handler, IRQF_NOBALANCING | IRQF_SHARED,
			  "tdx_quote_irq", dev);
	if (ret) {
		pr_err("Event notification IRQ request failed ret:%d\n", ret);
		return -EIO;
	}

	cpumask_copy(&saved_cpumask, current->cpus_ptr);
	set_cpus_allowed_ptr(current, cpumask_of(cpu));

	vector = irqd_cfg(irq_get_irq_data(irq))->vector;

	if (_tdx_hypercall(TDVMCALL_SETUP_NOTIFY_INTR, vector, 0, 0, 0)) {
		pr_err("Event notification hypercall failed\n");
		free_irq(irq, NULL);
		return -EIO;
	}

	set_cpus_allowed_ptr(current, &saved_cpumask);

	return 0;
}

static void tdx_guest_free_irq(void)
{
	int irq = tdx_get_event_irq(smp_processor_id());

	if (irq <= 0)
		return;

	free_irq(irq, NULL);
}

static const struct file_operations tdx_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tdx_guest_ioctl,
	.llseek = no_llseek,
};

static struct miscdevice tdx_misc_dev = {
	.name = KBUILD_MODNAME,
	.minor = MISC_DYNAMIC_MINOR,
	.fops = &tdx_guest_fops,
};

static const struct x86_cpu_id tdx_guest_ids[] = {
	X86_MATCH_FEATURE(X86_FEATURE_TDX_GUEST, NULL),
	{}
};
MODULE_DEVICE_TABLE(x86cpu, tdx_guest_ids);

static const struct tsm_key_ops tdx_tsm_ops = {
	.name = KBUILD_MODNAME,
	.module = THIS_MODULE,
	.auth_new = tdx_auth_new,
};

static int __init tdx_guest_init(void)
{
	int ret;

	if (!x86_match_cpu(tdx_guest_ids))
		return -ENODEV;

	ret = misc_register(&tdx_misc_dev);
	if (ret)
		return ret;

	qentry = alloc_quote_entry(GET_QUOTE_MAX_SIZE);
	if (!qentry) {
		pr_err("Failed to allocate Quote buffer\n");
		ret = -ENOMEM;
		goto free_misc;
	}

	ret = tdx_guest_alloc_irq(tdx_misc_dev.this_device);
	if (ret)
		goto free_quote;

	ret = register_tsm_provider(&tdx_tsm_ops, &tdx_misc_dev);
	if (ret)
		goto free_irq;

	return 0;

free_irq:
	tdx_guest_free_irq();
free_quote:
	free_quote_entry(qentry);
free_misc:
	misc_deregister(&tdx_misc_dev);

	return ret;
}
module_init(tdx_guest_init);

static void __exit tdx_guest_exit(void)
{
	unregister_tsm_provider(&tdx_tsm_ops);
	tdx_guest_free_irq();
	free_quote_entry(qentry);
	misc_deregister(&tdx_misc_dev);
}
module_exit(tdx_guest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX Guest Driver");
MODULE_LICENSE("GPL");
