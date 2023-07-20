/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TSM_H
#define __TSM_H

#include <linux/types.h>
#include <linux/module.h>

/*
 * @TSM_DATA_MAX: a reasonable max with enough space for known attestation
 * report formats. This mirrors the trusted/encrypted key blob max size.
 */
#define TSM_DATA_MAX 32767
#define TSM_PUBKEY_MAX 64
#define TSM_FORMAT_MAX 16

/**
 * DOC: TSM Keys
 *
 * Trusted Security Module Keys are a common provider of blobs that
 * facilitate key-exchange between a TVM (confidential computing guest)
 * and an attestation service. A TSM key combines a Diffie-Hellman
 * public-key with a HMAC encoded attestation report. That blob is then
 * used to establish a shared secret with the attestation agent.
 *
 * A full implementation uses a tsm key to establish a shared secret and
 * then uses that communication channel to instantiate other keys. The
 * expectation is that the requester of the tsm key knows a priori the
 * key-exchange protocol associated with the 'pubkey'.
 *
 * The attestation report format is TSM provider specific, when / if a
 * standard materializes it is only a change to the auth_blob_desc
 * member of 'struct tsm_key_payload', to convey that common format.
 */

/**
 * struct tsm_key_payload - generic payload for vendor TSM blobs
 * @privlevel: optional privilege level to associate with @pubkey
 * @pubkey_len: how much of @pubkey is valid
 * @pubkey: the public key-exchange blob to include in the attestation report
 * @auth_blob_desc: base ascii descriptor of @auth_blob
 * @auth_blob_format: for TSMs with multiple formats, extend @auth_blob_desc
 * @auth_blob_len: TSM provider length of the array it publishes in @auth_blob
 * @auth_blob: TSM specific attestation report blob
 */
struct tsm_key_payload {
	int privlevel;
	size_t pubkey_len;
	u8 pubkey[TSM_PUBKEY_MAX];
	const char *auth_blob_desc;
	char auth_blob_format[TSM_FORMAT_MAX];
	size_t auth_blob_len;
	u8 *auth_blob;
};

/*
 * arch specific ops, only one is expected to be registered at a time
 * i.e. only one of SEV, TDX, COVE, etc.
 */
struct tsm_key_ops {
	const char *name;
	struct module *module;
	int (*auth_new)(struct tsm_key_payload *t, void *provider_data);
};

int register_tsm_provider(const struct tsm_key_ops *ops, void *provider_data);
void unregister_tsm_provider(const struct tsm_key_ops *ops);

#endif /* __TSM_H */
