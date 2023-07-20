// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. All rights reserved. */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/uuid.h>
#include <linux/slab.h>
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/cleanup.h>
#include <linux/key-type.h>

#include <keys/tsm.h>
#include <keys/user-type.h>

static struct tsm_provider {
	const struct tsm_key_ops *ops;
	void *data;
} provider;
static DECLARE_RWSEM(tsm_key_rwsem);

static const struct tsm_key_ops *get_ops(void)
{
	down_read(&tsm_key_rwsem);
	return provider.ops;
}

static void *get_data(void)
{
	lockdep_assert_held(&tsm_key_rwsem);
	return provider.data;
}

static void put_ops(void)
{
	up_read(&tsm_key_rwsem);
}

int register_tsm_provider(const struct tsm_key_ops *ops,
			  void *provider_data)
{
	const struct tsm_key_ops *conflict;
	int rc;

	down_write(&tsm_key_rwsem);
	conflict = provider.ops;
	if (conflict) {
		pr_err("\"%s\" ops already registered\n", conflict->name);
		rc = -EEXIST;
		goto out;
	}
	try_module_get(ops->module);
	provider.ops = ops;
	provider.data = provider_data;
	rc = 0;
out:
	up_write(&tsm_key_rwsem);
	return rc;
}
EXPORT_SYMBOL_GPL(register_tsm_provider);

void unregister_tsm_provider(const struct tsm_key_ops *ops)
{
	down_write(&tsm_key_rwsem);
	provider.ops = NULL;
	provider.data = NULL;
	module_put(ops->module);
	up_write(&tsm_key_rwsem);
}
EXPORT_SYMBOL_GPL(unregister_tsm_provider);

enum {
	Opt_err,
	Opt_auth,
	Opt_format,
	Opt_privlevel,
};

static const match_table_t tsm_tokens = {
	{ Opt_auth, "auth" },
	{ Opt_privlevel, "privlevel=%s" },
	{ Opt_format, "format=%s" },
	{ Opt_err, NULL },
};

/*
 * tsm_parse - parse the tsm request data
 *
 * input format: "auth <hex pubkey data> [options]"
 *
 * Checks for options like privilege level (vmpl), and a hex blob of data
 * to be wrapped by the TSM attestation format.
 *
 * On success returns 0, otherwise -EINVAL.
 */
static int tsm_parse(char *input, struct tsm_key_payload *t)
{
	substring_t args[MAX_OPT_ARGS];
	unsigned long optmask = 0;
	unsigned int privlevel;
	int token, rc;
	char *p;

	/* all tsm keys must start with "auth" as a placeholder command */
	p = strsep(&input, " \t");
	if (!p)
		return -EINVAL;
	token = match_token(p, tsm_tokens, args);
	switch (token) {
	case Opt_auth:
		break;
	default:
		return -EINVAL;
	}

	/* next is the pubkey hex blob */
	p = strsep(&input, " \t");
	if (!p)
		return -EINVAL;
	t->pubkey_len = strlen(p) / 2;
	if (t->pubkey_len > TSM_PUBKEY_MAX)
		return -EINVAL;
	rc = hex2bin(t->pubkey, p, t->pubkey_len);
	if (rc < 0)
		return -EINVAL;

	/* last is zero or more options */
	while ((p = strsep(&input, " \t"))) {
		if (*p == '\0' || *p == ' ' || *p == '\t')
			continue;
		token = match_token(p, tsm_tokens, args);
		/* each option can appear only once */
		if (test_and_set_bit(token, &optmask))
			return -EINVAL;
		switch (token) {
		case Opt_privlevel:
			rc = kstrtouint(args[0].from, 16, &privlevel);
			if (rc)
				return rc;
			t->privlevel = privlevel;
			break;
		case Opt_format:
			if (strlen(args[0].from) >= TSM_FORMAT_MAX)
				return -EINVAL;
			strscpy(t->auth_blob_format, args[0].from,
				TSM_FORMAT_MAX);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int tsm_instantiate(struct key *key, struct key_preparsed_payload *prep)
{
	size_t datalen = prep->datalen;
	const struct tsm_key_ops *ops;
	int rc;

	if (datalen <= 0 || datalen > TSM_DATA_MAX || !prep->data)
		return -EINVAL;

	char *datablob __free(kfree) =
		kmemdup_nul(prep->data, datalen, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;

	struct tsm_key_payload *t __free(kfree) =
		kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return -ENOMEM;

	rc = tsm_parse(datablob, t);
	if (rc < 0)
		return rc;

	ops = get_ops();
	if (ops)
		rc = ops->auth_new(t, get_data());
	else
		rc = -ENXIO;
	put_ops();

	if (rc)
		return rc;

	rc = key_payload_reserve(key, sizeof(*t) + t->auth_blob_len);
	if (rc) {
		kvfree(t->auth_blob);
		return rc;
	}

	rcu_assign_keypointer(key, t);
	no_free_ptr(t);
	return 0;
}

/*
 * tsm_read - format and copy out the tsm auth record
 *
 * The resulting datablob format is:
 * <pubkey blob> <auth blob desc[:format]> <auth blob>
 *
 * On success, return to userspace the size of the formatted payload.
 */
static long tsm_read(const struct key *key, char *buffer, size_t buflen)
{
	size_t asciiblob_len, desc_len;
	struct tsm_key_payload *t;
	char *buf, *format = NULL;
	const int nr_spaces = 2;

	t = dereference_key_locked(key);

	desc_len = strlen(t->auth_blob_desc);
	if (t->auth_blob_format[0]) {
		format = &t->auth_blob_format[0];
		desc_len += strlen(format) + 1;
	}

	asciiblob_len =
		t->pubkey_len * 2 + desc_len + t->auth_blob_len * 2 + nr_spaces;

	if (!buffer || buflen < asciiblob_len)
		return asciiblob_len;

	buf = bin2hex(buffer, t->pubkey, t->pubkey_len);
	if (format)
		buf += sprintf(buf, " %s:%s ", t->auth_blob_desc, format);
	else
		buf += sprintf(buf, " %s ", t->auth_blob_desc);
	buf = bin2hex(buf, t->auth_blob, t->auth_blob_len);

	/* sanity check for future changes to this function */
	WARN_ON_ONCE(buf - buffer != asciiblob_len);

	return asciiblob_len;
}

static void tsm_destroy(struct key *key)
{
	struct tsm_key_payload *t = key->payload.data[0];

	kvfree(t->auth_blob);
	kfree(t);
}

static struct key_type key_type_tsm = {
	.name = "tsm",
	.instantiate = tsm_instantiate,
	.destroy = tsm_destroy,
	.describe = user_describe,
	.read = tsm_read,
};

static int __init tsm_key_init(void)
{
	return register_key_type(&key_type_tsm);
}
module_init(tsm_key_init);

static void __exit tsm_key_exit(void)
{
	unregister_key_type(&key_type_tsm);
}
module_exit(tsm_key_exit);

MODULE_LICENSE("GPL");
