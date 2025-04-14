/*
   Unix SMB/CIFS implementation.
   Group Key Distribution Protocol functions

   Copyright (C) Catalyst.Net Ltd 2023

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "lib/crypto/gnutls_helpers.h"

#include "lib/util/bytearray.h"

#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/gkdi.h"
#include "librpc/gen_ndr/ndr_gkdi.h"

#include "lib/crypto/gkdi.h"
#include "lib/util/data_blob.h"

static const uint8_t kds_service[] = {
	/* “KDS service” as a NULL‐terminated UTF‐16LE string. */
	'K', 0, 'D', 0, 'S', 0, ' ', 0, 's', 0, 'e', 0,
	'r', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0, 0,   0,
};

static const uint8_t dh_algorithm[] = {
	/* “DH” as a NULL‐terminated UTF‐16LE string. */
	'D',
	0,
	'H',
	0,
	0,
	0,
};

static const uint8_t ecdh_p256_algorithm[] = {
	/* "ECDH_P256" as a NULL‐terminated UTF‐16LE string. */
	'E', 0, 'C', 0, 'D', 0, 'H', 0, '_', 0,
	'P', 0, '2', 0, '5', 0, '6', 0, 0,   0,
};

static const uint8_t ecdh_p384_algorithm[] = {
	/* "ECDH_P384" as a NULL‐terminated UTF‐16LE string. */
	'E', 0, 'C', 0, 'D', 0, 'H', 0, '_', 0,
	'P', 0, '3', 0, '8', 0, '4', 0, 0,   0,
};

static const uint8_t ecdh_p521_algorithm[] = {
	/* "ECDH_P521" as a NULL‐terminated UTF‐16LE string. */
	'E', 0, 'C', 0, 'D', 0, 'H', 0, '_', 0,
	'P', 0, '5', 0, '2', 0, '1', 0, 0,   0};

/*
 * [MS-GKDI] 2.2.3.1 FFC DH Key
 */
static const uint32_t dh_magic = 0x42504844;

/*
 * [FIPS-186-4] Appendix D.1.2.3 Curve P-256 - Gx
 */
static unsigned char ecdh_p256_x[] = {
	0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
	0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
	0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
};

/*
 * [FIPS-186-4] Appendix D.1.2.3 Curve P-256 - Gy
 */
static unsigned char ecdh_p256_y[] = {
	0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
	0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
	0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
};

/*
 * [MS-GKDI] 2.2.3.2 ECDH Key
 */
static const uint32_t ecdh_p256_magic = 0x45434B31;

/*
 * [FIPS-186-4] Appendix D.1.2.4 Curve P-384 - Gx
 */
static unsigned char ecdh_p384_x[] = {
	0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e,
	0xf3, 0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
	0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d,
	0xbf, 0x55, 0x29, 0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
};

/*
 * [FIPS-186-4] Appendix D.1.2.4 Curve P-384 - Gy
 */
static unsigned char ecdh_p384_y[] = {
	0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf,
	0x92, 0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
	0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce,
	0x1d, 0x7e, 0x81, 0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
};

/*
 * [MS-GKDI] 2.2.3.2 ECDH Key
 */
static const uint32_t ecdh_p384_magic = 0x45434B33;

/*
 * [FIPS-186-4] Appendix D.1.2.5 Curve P-521 - Gx
 */
static unsigned char ecdh_p521_x[] = {
	0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e,
	0x3e, 0xcb, 0x66, 0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39,
	0x05, 0x3f, 0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d,
	0xba, 0xa1, 0x4b, 0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d,
	0xc1, 0x27, 0xa2, 0xff, 0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85,
	0x6a, 0x42, 0x9b, 0xf9, 0x7e, 0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66,
};

/*
 * [FIPS-186-4] Appendix D.1.2.5 Curve P-521 - Gy
 */
static unsigned char ecdh_p521_y[] = {
	0x01, 0x18, 0x39, 0x29, 0x6a, 0x78, 0x9a, 0x3b, 0xc0, 0x04, 0x5c,
	0x8a, 0x5f, 0xb4, 0x2c, 0x7d, 0x1b, 0xd9, 0x98, 0xf5, 0x44, 0x49,
	0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17, 0x27, 0x3e, 0x66,
	0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40, 0xc5, 0x50,
	0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70, 0x86, 0xa2,
	0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50,
};

/*
 * [MS-GKDI] 2.2.3.2 ECDH Key
 */
static const uint32_t ecdh_p521_magic = 0x45434B35;

static struct Gkid gkid_from_u32_indices(const uint32_t l0_idx,
					 const uint32_t l1_idx,
					 const uint32_t l2_idx)
{
	/* Catch out‐of‐range indices. */
	if (l0_idx > INT32_MAX || l1_idx > INT8_MAX || l2_idx > INT8_MAX) {
		return invalid_gkid;
	}

	return Gkid(l0_idx, l1_idx, l2_idx);
}

NTSTATUS gkdi_pull_KeyEnvelope(TALLOC_CTX *mem_ctx,
			       const DATA_BLOB *key_env_blob,
			       struct KeyEnvelope *key_env_out)
{
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err;

	if (key_env_blob == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (key_env_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	err = ndr_pull_struct_blob(key_env_blob,
				   mem_ctx,
				   key_env_out,
				   (ndr_pull_flags_fn_t)ndr_pull_KeyEnvelope);
	status = ndr_map_error2ntstatus(err);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* If we felt so inclined, we could check the version field here. */

	return status;
}

/*
 * Retrieve the GKID and root key ID from a KeyEnvelope blob. The returned
 * structure is guaranteed to have a valid GKID.
 */
const struct KeyEnvelopeId *gkdi_pull_KeyEnvelopeId(
	const DATA_BLOB key_env_blob,
	struct KeyEnvelopeId *key_env_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct KeyEnvelope key_env;
	const struct KeyEnvelopeId *key_env_ret = NULL;
	NTSTATUS status;

	if (key_env_out == NULL) {
		goto out;
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		goto out;
	}

	status = gkdi_pull_KeyEnvelope(tmp_ctx, &key_env_blob, &key_env);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	{
		const struct Gkid gkid = gkid_from_u32_indices(
			key_env.l0_index, key_env.l1_index, key_env.l2_index);
		if (!gkid_is_valid(gkid)) {
			/* The KeyId is not valid: we can’t use it. */
			goto out;
		}

		*key_env_out = (struct KeyEnvelopeId){
			.root_key_id = key_env.root_key_id, .gkid = gkid};
	}

	/* Return a pointer to the buffer passed in by the caller. */
	key_env_ret = key_env_out;

out:
	TALLOC_FREE(tmp_ctx);
	return key_env_ret;
}

NTSTATUS ProvRootKey(
	TALLOC_CTX *mem_ctx,
	const struct GUID root_key_id,
	const int32_t version,
	const DATA_BLOB root_key_data,
	const NTTIME create_time,
	const NTTIME use_start_time,
	const char *const domain_id,
	const struct KdfAlgorithm kdf_algorithm,
	const struct SecretAgreementAlgorithm secret_agreement_algorithm,
	const uint64_t public_key_length,
	const uint64_t private_key_length,
	const struct ProvRootKey **const root_key_out)
{
	NTSTATUS status = NT_STATUS_OK;
	struct ProvRootKey *root_key = NULL;

	if (root_key_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	*root_key_out = NULL;

	root_key = talloc(mem_ctx, struct ProvRootKey);
	if (root_key == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*root_key = (struct ProvRootKey){
		.id = root_key_id,
		.data = {.data = talloc_steal(root_key, root_key_data.data),
			 .length = root_key_data.length},
		.create_time = create_time,
		.use_start_time = use_start_time,
		.domain_id = talloc_steal(root_key, domain_id),
		.kdf_algorithm = kdf_algorithm,
		.secret_agreement_algorithm =
			{.param.dh_parameters = talloc_steal(
				 root_key,
				 secret_agreement_algorithm.param
					 .dh_parameters),
			 .id = secret_agreement_algorithm.id},
		.public_key_length = public_key_length,
		.private_key_length = private_key_length,
		.version = version,
	};

	*root_key_out = root_key;
	return status;
}

struct Gkid gkdi_get_interval_id(const NTTIME time)
{
	return Gkid(time / (gkdi_l1_key_iteration * gkdi_l2_key_iteration *
			    gkdi_key_cycle_duration),
		    time / (gkdi_l2_key_iteration * gkdi_key_cycle_duration) %
			    gkdi_l1_key_iteration,
		    time / gkdi_key_cycle_duration % gkdi_l2_key_iteration);
}

bool gkdi_get_key_start_time(const struct Gkid gkid, NTTIME *start_time_out)
{
	if (!gkid_is_valid(gkid)) {
		return false;
	}

	{
		enum GkidType key_type = gkid_key_type(gkid);
		if (key_type != GKID_L2_SEED_KEY) {
			return false;
		}
	}

	{
		/*
		 * Make sure that the GKID is not so large its start time can’t
		 * be represented in NTTIME.
		 */
		const struct Gkid max_gkid = {
			UINT64_MAX /
				(gkdi_l1_key_iteration * gkdi_l2_key_iteration *
				 gkdi_key_cycle_duration),
			UINT64_MAX /
				(gkdi_l2_key_iteration *
				 gkdi_key_cycle_duration) %
				gkdi_l1_key_iteration,
			UINT64_MAX / gkdi_key_cycle_duration %
				gkdi_l2_key_iteration};
		if (!gkid_less_than_or_equal_to(gkid, max_gkid)) {
			return false;
		}
	}

	*start_time_out = ((uint64_t)gkid.l0_idx * gkdi_l1_key_iteration *
				   gkdi_l2_key_iteration +
			   (uint64_t)gkid.l1_idx * gkdi_l2_key_iteration +
			   (uint64_t)gkid.l2_idx) *
			  gkdi_key_cycle_duration;
	return true;
}

/*
 * This returns the equivalent of
 * gkdi_get_key_start_time(gkdi_get_interval_id(time)).
 */
NTTIME gkdi_get_interval_start_time(const NTTIME time)
{
	return time / gkdi_key_cycle_duration * gkdi_key_cycle_duration;
}

bool gkid_less_than_or_equal_to(const struct Gkid g1, const struct Gkid g2)
{
	if (g1.l0_idx != g2.l0_idx) {
		return g1.l0_idx < g2.l0_idx;
	}

	if (g1.l1_idx != g2.l1_idx) {
		return g1.l1_idx < g2.l1_idx;
	}

	return g1.l2_idx <= g2.l2_idx;
}

bool gkdi_rollover_interval(const int64_t managed_password_interval,
			    NTTIME *result)
{
	/*
	 * This is actually a conservative reckoning. The interval could be one
	 * higher than this maximum and not overflow. But there’s no reason to
	 * support intervals that high (and Windows will start producing strange
	 * results for intervals beyond that).
	 */
	const int64_t maximum_interval = UINT64_MAX / gkdi_key_cycle_duration *
					 10 / 24;

	if (managed_password_interval < 0 ||
	    managed_password_interval > maximum_interval)
	{
		return false;
	}

	*result = (uint64_t)managed_password_interval * 24 / 10 *
		  gkdi_key_cycle_duration;
	return true;
}

struct GkdiContextShort {
	uint8_t buf[sizeof((struct GUID_ndr_buf){}.buf) + sizeof(int32_t) +
		    sizeof(int32_t) + sizeof(int32_t)];
};

static NTSTATUS make_gkdi_context(const struct GkdiDerivationCtx *ctx,
				  struct GkdiContextShort *out_ctx)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB b = {.data = out_ctx->buf, .length = sizeof out_ctx->buf};

	if (ctx->target_security_descriptor.length) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&b, ctx, (ndr_push_flags_fn_t)ndr_push_GkdiDerivationCtx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

static NTSTATUS make_gkdi_context_security_descriptor(
	TALLOC_CTX *mem_ctx,
	const struct GkdiDerivationCtx *ctx,
	const DATA_BLOB security_descriptor,
	DATA_BLOB *out_ctx)
{
	enum ndr_err_code ndr_err;
	struct GkdiDerivationCtx ctx_with_sd = *ctx;

	if (ctx_with_sd.target_security_descriptor.length != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx_with_sd.target_security_descriptor = security_descriptor;

	ndr_err = ndr_push_struct_blob(out_ctx,
				       mem_ctx,
				       &ctx_with_sd,
				       (ndr_push_flags_fn_t)
					       ndr_push_GkdiDerivationCtx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

struct GkdiContext {
	struct GkdiDerivationCtx ctx;
	gnutls_mac_algorithm_t algorithm;
};

gnutls_mac_algorithm_t get_sp800_108_mac_algorithm(
	const struct KdfAlgorithm kdf_algorithm)
{
	switch (kdf_algorithm.id) {
	case KDF_ALGORITHM_SP800_108_CTR_HMAC:
		switch (kdf_algorithm.param.sp800_108) {
		case KDF_PARAM_SHA1:
			return GNUTLS_MAC_SHA1;
		case KDF_PARAM_SHA256:
			return GNUTLS_MAC_SHA256;
		case KDF_PARAM_SHA384:
			return GNUTLS_MAC_SHA384;
		case KDF_PARAM_SHA512:
			return GNUTLS_MAC_SHA512;
		}
		break;
	}

	return GNUTLS_MAC_UNKNOWN;
}

static NTSTATUS GkdiContext(const struct ProvRootKey *const root_key,
			    struct GkdiContext *const ctx)
{
	NTSTATUS status = NT_STATUS_OK;
	gnutls_mac_algorithm_t algorithm = GNUTLS_MAC_UNKNOWN;

	if (ctx == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (root_key == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (root_key->version != root_key_version_1) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	if (root_key->data.length != GKDI_KEY_LEN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	algorithm = get_sp800_108_mac_algorithm(root_key->kdf_algorithm);
	if (algorithm == GNUTLS_MAC_UNKNOWN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	/*
	 * The context comprises the GUID corresponding to the root key, the
	 * GKID (which we shall initialize to zero), and the encoded target
	 * security descriptor (which will initially be empty).
	 */
	*ctx = (struct GkdiContext){
		.ctx = {.guid = root_key->id,
			.l0_idx = 0,
			.l1_idx = 0,
			.l2_idx = 0,
			.target_security_descriptor = {}},
		.algorithm = algorithm,
	};
out:
	return status;
}

static NTSTATUS compute_l1_seed_key(TALLOC_CTX *mem_ctx,
				    struct GkdiContext *ctx,
				    const DATA_BLOB security_descriptor,
				    const struct ProvRootKey *const root_key,
				    const struct Gkid gkid,
				    uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	struct GkdiContextShort short_ctx;
	int8_t n;

	ctx->ctx.l0_idx = gkid.l0_idx;
	ctx->ctx.l1_idx = -1;
	ctx->ctx.l2_idx = -1;

	status = make_gkdi_context(&ctx->ctx, &short_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* Derive an L0 seed key with GKID = (L0, −1, −1). */

	status = samba_gnutls_sp800_108_derive_key(root_key->data.data,
						   root_key->data.length,
						   NULL,
						   0,
						   kds_service,
						   sizeof kds_service,
						   short_ctx.buf,
						   sizeof short_ctx.buf,
						   ctx->algorithm,
						   key,
						   GKDI_KEY_LEN);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* Derive an L1 seed key with GKID = (L0, 31, −1). */

	ctx->ctx.l1_idx = 31;

	{
		DATA_BLOB security_descriptor_ctx;

		status = make_gkdi_context_security_descriptor(
			mem_ctx,
			&ctx->ctx,
			security_descriptor,
			&security_descriptor_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(
			key,
			GKDI_KEY_LEN,
			NULL,
			0,
			kds_service,
			sizeof kds_service,
			security_descriptor_ctx.data,
			security_descriptor_ctx.length,
			ctx->algorithm,
			key,
			GKDI_KEY_LEN);
		data_blob_free(&security_descriptor_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	for (n = 30; n >= gkid.l1_idx; --n) {
		/* Derive an L1 seed key with GKID = (L0, n, −1). */

		ctx->ctx.l1_idx = n;

		status = make_gkdi_context(&ctx->ctx, &short_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(key,
							   GKDI_KEY_LEN,
							   NULL,
							   0,
							   kds_service,
							   sizeof kds_service,
							   short_ctx.buf,
							   sizeof short_ctx.buf,
							   ctx->algorithm,
							   key,
							   GKDI_KEY_LEN);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

static NTSTATUS derive_l2_seed_key(struct GkdiContext *ctx,
				   const struct Gkid gkid,
				   uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	int8_t n;

	ctx->ctx.l0_idx = gkid.l0_idx;
	ctx->ctx.l1_idx = gkid.l1_idx;

	for (n = 31; n >= gkid.l2_idx; --n) {
		struct GkdiContextShort short_ctx;

		/* Derive an L2 seed key with GKID = (L0, L1, n). */

		ctx->ctx.l2_idx = n;

		status = make_gkdi_context(&ctx->ctx, &short_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(key,
							   GKDI_KEY_LEN,
							   NULL,
							   0,
							   kds_service,
							   sizeof kds_service,
							   short_ctx.buf,
							   sizeof short_ctx.buf,
							   ctx->algorithm,
							   key,
							   GKDI_KEY_LEN);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

enum GkidType gkid_key_type(const struct Gkid gkid)
{
	if (gkid.l0_idx == -1) {
		return GKID_DEFAULT;
	}

	if (gkid.l1_idx == -1) {
		return GKID_L0_SEED_KEY;
	}

	if (gkid.l2_idx == -1) {
		return GKID_L1_SEED_KEY;
	}

	return GKID_L2_SEED_KEY;
}

bool gkid_is_valid(const struct Gkid gkid)
{
	if (gkid.l0_idx < -1) {
		return false;
	}

	if (gkid.l1_idx < -1 || gkid.l1_idx >= gkdi_l1_key_iteration) {
		return false;
	}

	if (gkid.l2_idx < -1 || gkid.l2_idx >= gkdi_l2_key_iteration) {
		return false;
	}

	if (gkid.l0_idx == -1 && gkid.l1_idx != -1) {
		return false;
	}

	if (gkid.l1_idx == -1 && gkid.l2_idx != -1) {
		return false;
	}

	return true;
}

NTSTATUS compute_seed_key(TALLOC_CTX *mem_ctx,
			  const DATA_BLOB target_security_descriptor,
			  const struct ProvRootKey *const root_key,
			  const struct Gkid gkid,
			  uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	enum GkidType gkid_type;
	struct GkdiContext ctx;

	if (!gkid_is_valid(gkid)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	gkid_type = gkid_key_type(gkid);
	if (gkid_type < GKID_L1_SEED_KEY) {
		/* Don’t allow derivation of L0 seed keys. */
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = GkdiContext(root_key, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = compute_l1_seed_key(
		mem_ctx, &ctx, target_security_descriptor, root_key, gkid, key);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (gkid_type == GKID_L2_SEED_KEY) {
		status = derive_l2_seed_key(&ctx, gkid, key);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

NTSTATUS compute_group_private_key(TALLOC_CTX *mem_ctx,
				   const struct ProvRootKey *const root_key,
				   uint8_t seed_key[static const GKDI_KEY_LEN],
				   DATA_BLOB *key_out)
{
	NTSTATUS status = NT_STATUS_OK;
	gnutls_mac_algorithm_t algorithm = GNUTLS_MAC_UNKNOWN;
	const uint8_t *secret_agreement_algorithm_id = NULL;
	uint32_t secret_algorithm_size = 0;

	if (key_out == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * If RK.msKds-PrivateKey-Length is not a multiple of 8, it needs to be
	 * rounded up to the next multiple of 8. RK.msKds-PrivateKey-Length is
	 * in bits but key_out->length is in bytes.
	 */
	key_out->length = (root_key->private_key_length / 64) * 8;

	algorithm = get_sp800_108_mac_algorithm(root_key->kdf_algorithm);
	if (algorithm == GNUTLS_MAC_UNKNOWN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	switch (root_key->secret_agreement_algorithm.id) {
	case SECRET_AGREEMENT_ALGORITHM_DH:
		secret_agreement_algorithm_id = dh_algorithm;
		secret_algorithm_size = sizeof(dh_algorithm);
		break;
	case SECRET_AGREEMENT_ALGORITHM_ECDH_P256:
		secret_agreement_algorithm_id = ecdh_p256_algorithm;
		secret_algorithm_size = sizeof(ecdh_p256_algorithm);
		break;
	case SECRET_AGREEMENT_ALGORITHM_ECDH_P384:
		secret_agreement_algorithm_id = ecdh_p384_algorithm;
		secret_algorithm_size = sizeof(ecdh_p384_algorithm);
		break;
	case SECRET_AGREEMENT_ALGORITHM_ECDH_P521:
		secret_agreement_algorithm_id = ecdh_p521_algorithm;
		secret_algorithm_size = sizeof(ecdh_p521_algorithm);
		break;
	default:
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	status = samba_gnutls_sp800_108_derive_key(
		seed_key,
		GKDI_KEY_LEN,
		NULL,
		0,
		kds_service,
		sizeof kds_service,
		(uint8_t *)secret_agreement_algorithm_id,
		secret_algorithm_size,
		algorithm,
		key_out->data,
		key_out->length);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

out:
	return status;
}

NTSTATUS compute_group_public_key(TALLOC_CTX *mem_ctx,
				  const struct ProvRootKey *const root_key,
				  uint8_t seed_key[static const GKDI_KEY_LEN],
				  const struct Gkid gkid,
				  DATA_BLOB *group_public_key_out)
{
	NTSTATUS status = NT_STATUS_OK;
	int rc = 0;
	DATA_BLOB private_key = {};
	gnutls_privkey_t privkey = NULL;
	gnutls_datum_t privkey_data = {};
	gnutls_pubkey_t pubkey = NULL;
	gnutls_datum_t pubkey_data = {};
	gnutls_datum_t prime_data = {};
	gnutls_datum_t generator_data = {};
	gnutls_dh_params_t dh_params = NULL;
	gnutls_ecc_curve_t priv_curve = GNUTLS_ECC_CURVE_SECP256R1;
	gnutls_ecc_curve_t pub_curve = GNUTLS_ECC_CURVE_SECP256R1;
	gnutls_datum_t pub_x = {};
	gnutls_datum_t pub_y = {};
	gnutls_datum_t out_x = {};
	gnutls_datum_t out_y = {};
	uint32_t magic = 0;
	struct ECDHKey ecdh_key = {};
	struct FfcDhKey ffc_dh_key = {};
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	TALLOC_CTX *tmp_ctx = NULL;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (group_public_key_out == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * 1. First, the server MUST validate the root key configuration
	 * attributes related to public keys:
	 * * If RK.msKds-SecretAgreement-AlgorithmID is equal to "DH", RK.msKds-
	 * SecretAgreement-Param MUST be in the format specified in
	 * section 2.2.2, and the Key length field of
	 * RK.msKds-SecretAgreement-Param MUST be equal to RK.msKds-
	 * PublicKey-Length.
	 * * If RK.msKds-SecretAgreement-AlgorithmID is equal to "ECDH_P256",
	 * "ECDH_P384" or "ECDH_P521", the RK.msKds-SecretAgreement-Param MUST
	 * be NULL.
	 */
	if (root_key->secret_agreement_algorithm.id ==
	    SECRET_AGREEMENT_ALGORITHM_DH)
	{
		if (root_key->secret_agreement_algorithm.param.dh_parameters ==
		    NULL)
		{
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	} else if (root_key->secret_agreement_algorithm.id ==
			   SECRET_AGREEMENT_ALGORITHM_ECDH_P256 ||
		   root_key->secret_agreement_algorithm.id ==
			   SECRET_AGREEMENT_ALGORITHM_ECDH_P384 ||
		   root_key->secret_agreement_algorithm.id ==
			   SECRET_AGREEMENT_ALGORITHM_ECDH_P521)
	{
		if (root_key->secret_agreement_algorithm.param.dh_parameters !=
		    NULL)
		{
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	} else {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	private_key.data = talloc_array(tmp_ctx,
					uint8_t,
					root_key->private_key_length);
	if (!private_key.data) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	private_key.length = root_key->private_key_length;

	/*
	 * 2. Having validated the root key configuration, the server MUST then
	 * compute the group private key in the following manner: PrivKey(SD,
	 * RK, L0, L1, L2) = KDF(HashAlg, Key(SD, RK, L0, L1, L2), "KDS
	 * service", RK.msKds-SecretAgreement-AlgorithmID,
	 * RK.msKds-PrivateKey-Length) Note If RK.msKds-PrivateKey-Length is not
	 * a multiple of 8, it needs to be rounded up to the next multiple of 8.
	 */
	status = compute_group_private_key(tmp_ctx,
					   root_key,
					   seed_key,
					   &private_key);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/*
	 * 3. Lastly, the server MUST compute the group public key PubKey(SD,
	 * RK, L0, L1, L2) as follows:
	 * * If RK.msKds-SecretAgreement-AlgorithmID is equal to "DH", the
	 * server MUST compute PubKey(SD, RK, L0, L1, L2) by using the method
	 * specified in [SP800-56A] section 5.6.1.1, with the group parameters
	 * specified in RK.msKds-SecretAgreement-Param, and with PrivKey(SD, RK,
	 * L0, L1, L2) as the private key.
	 * * If RK.msKds-SecretAgreement-AlgorithmID is equal to "ECDH_P256",
	 * "ECDH_P384", or "ECDH_P521", the server MUST compute PubKey(SD, RK,
	 * L0, L1, L2) by using the method specified in [SP800-56A]
	 * section 5.6.1.2, with PrivKey(SD, RK, L0, L1, L2) as the private key
	 * d, and by using the domain parameters from [FIPS186] Appendix
	 * D.1.2.3, D.1.2.4, or D.1.2.5, respectively.
	 */
	rc = gnutls_pubkey_init(&pubkey);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
		goto out;
	}
	privkey_data = (gnutls_datum_t){.data = private_key.data,
					.size = private_key.length};

	rc = gnutls_privkey_init(&privkey);
	if (rc < 0) {
		status = gnutls_error_to_ntstatus(rc, NT_STATUS_INTERNAL_ERROR);
		goto out;
	}

	if (root_key->secret_agreement_algorithm.id ==
	    SECRET_AGREEMENT_ALGORITHM_DH)
	{
		prime_data = (gnutls_datum_t){
			.data = root_key->secret_agreement_algorithm.param
					.dh_parameters->field_order,
			.size = root_key->secret_agreement_algorithm.param
					.dh_parameters->key_length};

		generator_data = (gnutls_datum_t){
			.data = root_key->secret_agreement_algorithm.param
					.dh_parameters->generator,
			.size = root_key->secret_agreement_algorithm.param
					.dh_parameters->key_length};

		rc = gnutls_dh_params_init(&dh_params);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_dh_params_import_raw(dh_params,
						 &prime_data,
						 &generator_data);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_privkey_import_dh_raw(privkey,
						  dh_params,
						  &generator_data,
						  &privkey_data);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_privkey_derive_secret(
			privkey, pubkey, NULL, &pubkey_data, 0);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
	} else {
		switch (root_key->secret_agreement_algorithm.id) {
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P256:
			priv_curve = GNUTLS_ECC_CURVE_SECP256R1;

			pub_x.data = ecdh_p256_x;
			pub_x.size = sizeof ecdh_p256_x;

			pub_y.data = ecdh_p256_y;
			pub_y.size = sizeof ecdh_p256_y;

			magic = ecdh_p256_magic;
			break;
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P384:
			priv_curve = GNUTLS_ECC_CURVE_SECP384R1;

			pub_x.data = ecdh_p384_x;
			pub_x.size = sizeof ecdh_p384_x;

			pub_y.data = ecdh_p384_y;
			pub_y.size = sizeof ecdh_p384_y;

			magic = ecdh_p384_magic;
			break;
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P521:
			priv_curve = GNUTLS_ECC_CURVE_SECP521R1;

			pub_x.data = ecdh_p521_x;
			pub_x.size = sizeof ecdh_p521_x;

			pub_y.data = ecdh_p521_y;
			pub_y.size = sizeof ecdh_p521_y;

			magic = ecdh_p521_magic;
			break;
		default:
			break;
		}

		rc = gnutls_privkey_import_ecc_raw(
			privkey, priv_curve, &pub_x, &pub_y, &privkey_data);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_pubkey_import_privkey(pubkey, privkey, 0, 0);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}

		rc = gnutls_pubkey_export_ecc_raw(pubkey, NULL, &out_x, &out_y);
		if (rc < 0) {
			status = gnutls_error_to_ntstatus(
				rc, NT_STATUS_INTERNAL_ERROR);
			goto out;
		}
	}

	if (root_key->secret_agreement_algorithm.id ==
	    SECRET_AGREEMENT_ALGORITHM_DH)
	{
		ffc_dh_key.magic = dh_magic;
		ffc_dh_key.key_length = pubkey_data.size;
		ffc_dh_key.field_order = prime_data.data;
		ffc_dh_key.generator = generator_data.data;
		ffc_dh_key.public_key = pubkey_data.data;

		ndr_err = ndr_push_struct_blob(group_public_key_out,
					       mem_ctx,
					       &ffc_dh_key,
					       (ndr_push_flags_fn_t)
						       ndr_push_FfcDhKey);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			/*
			 * We fallthrough to out here anyway and we need
			 * to cleanup pubkey_data.data, hence we do not
			 * use 'goto out' here.
			 */
		}
	} else {
		ecdh_key.magic = magic;
		ecdh_key.x = out_x.data;
		ecdh_key.y = out_y.data;
		ecdh_key.key_length = pub_x.size;

		ndr_err = ndr_push_struct_blob(group_public_key_out,
					       mem_ctx,
					       &ecdh_key,
					       (ndr_push_flags_fn_t)
						       ndr_push_ECDHKey);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			status = ndr_map_error2ntstatus(ndr_err);
			goto out;
		}
	}

out:
	if (privkey_data.data) {
		memset_s(privkey_data.data,
			 privkey_data.size,
			 0,
			 privkey_data.size);
	}

	talloc_free(tmp_ctx);

	if (dh_params) {
		gnutls_dh_params_deinit(dh_params);
	}

	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);

	return status;
}

NTSTATUS kdf_sp_800_108_from_params(
	const DATA_BLOB *const kdf_param,
	struct KdfAlgorithm *const kdf_algorithm_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err;
	enum KdfSp800_108Param sp800_108_param = KDF_PARAM_SHA256;
	struct KdfParameters kdf_parameters;

	if (kdf_param != NULL) {
		tmp_ctx = talloc_new(NULL);
		if (tmp_ctx == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		err = ndr_pull_struct_blob(kdf_param,
					   tmp_ctx,
					   &kdf_parameters,
					   (ndr_pull_flags_fn_t)
						   ndr_pull_KdfParameters);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			status = ndr_map_error2ntstatus(err);
			DBG_WARNING("KdfParameters pull failed: %s\n",
				    nt_errstr(status));
			goto out;
		}

		if (kdf_parameters.hash_algorithm == NULL) {
			status = NT_STATUS_NOT_SUPPORTED;
			goto out;
		}

		/* These string comparisons are case‐sensitive. */
		if (strcmp(kdf_parameters.hash_algorithm, "SHA1") == 0) {
			sp800_108_param = KDF_PARAM_SHA1;
		} else if (strcmp(kdf_parameters.hash_algorithm, "SHA256") == 0)
		{
			sp800_108_param = KDF_PARAM_SHA256;
		} else if (strcmp(kdf_parameters.hash_algorithm, "SHA384") == 0)
		{
			sp800_108_param = KDF_PARAM_SHA384;
		} else if (strcmp(kdf_parameters.hash_algorithm, "SHA512") == 0)
		{
			sp800_108_param = KDF_PARAM_SHA512;
		} else {
			status = NT_STATUS_NOT_SUPPORTED;
			goto out;
		}
	}

	*kdf_algorithm_out = (struct KdfAlgorithm){
		.id = KDF_ALGORITHM_SP800_108_CTR_HMAC,
		.param.sp800_108 = sp800_108_param,
	};
out:
	talloc_free(tmp_ctx);
	return status;
}

NTSTATUS kdf_algorithm_from_params(const char *const kdf_algorithm_id,
				   const DATA_BLOB *const kdf_param,
				   struct KdfAlgorithm *const kdf_algorithm_out)
{
	if (kdf_algorithm_id == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* This string comparison is case‐sensitive. */
	if (strcmp(kdf_algorithm_id, "SP800_108_CTR_HMAC") == 0) {
		return kdf_sp_800_108_from_params(kdf_param, kdf_algorithm_out);
	}

	/* Unknown algorithm. */
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS secret_agreement_algorithm_from_params(
	const char *const algorithm_id,
	const DATA_BLOB *const secret_agreement_algorithm_params,
	struct SecretAgreementAlgorithm *const secret_agreement_algorithm_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err;
	struct FfcDhParameters *ffc_dh_params = NULL;
	enum SecretAgreementAlgorithmID id = SECRET_AGREEMENT_ALGORITHM_DH;

	if (secret_agreement_algorithm_params != NULL) {
		tmp_ctx = talloc_new(NULL);
		if (tmp_ctx == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (strcmp(algorithm_id, "DH") == 0) {
			ffc_dh_params = talloc(tmp_ctx, struct FfcDhParameters);
			if (ffc_dh_params == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}

			err = ndr_pull_struct_blob(
				secret_agreement_algorithm_params,
				tmp_ctx,
				ffc_dh_params,
				(ndr_pull_flags_fn_t)ndr_pull_FfcDhParameters);
			if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
				status = ndr_map_error2ntstatus(err);
				DBG_WARNING("FfcDhParameters pull failed: %s\n",
					    nt_errstr(status));
				goto out;
			}
		} else if (strcmp(algorithm_id, "ECDH_P256") == 0) {
			id = SECRET_AGREEMENT_ALGORITHM_ECDH_P256;
		} else if (strcmp(algorithm_id, "ECDH_P384") == 0) {
			id = SECRET_AGREEMENT_ALGORITHM_ECDH_P384;
		} else if (strcmp(algorithm_id, "ECDH_P521") == 0) {
			id = SECRET_AGREEMENT_ALGORITHM_ECDH_P521;
		} else {
			DBG_WARNING(
				"Unsupported secrete agrement algorithm %s\n",
				algorithm_id);
			status = NT_STATUS_NOT_SUPPORTED;
			goto out;
		}

		*secret_agreement_algorithm_out =
			(struct SecretAgreementAlgorithm){
				.id = SECRET_AGREEMENT_ALGORITHM_DH,
				.param.dh_parameters = talloc_steal(
					secret_agreement_algorithm_out,
					ffc_dh_params),
			};
	}
out:
	talloc_free(tmp_ctx);
	return status;
}
