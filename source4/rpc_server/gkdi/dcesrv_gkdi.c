#include "includes.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"

#include "source4/librpc/rpc/dcerpc.h"

#include "librpc/gen_ndr/ndr_gkdi.h"
#include "librpc/gen_ndr/ndr_gkdi_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"

#include "auth/common_auth.h"
#include "auth/credentials/credentials.h"

#include "param/param.h"

#include "dsdb/common/util.h"
#include "dsdb/samdb/samdb.h"

#include "dsdb/gmsa/gkdi.h"

#include "libds/common/roles.h"

#include "lib/ldb/include/ldb_errors.h"

#include "libcli/util/ntstatus.h"
#include "libcli/util/hresult.h"

#include "libcli/security/access_check.h"

#include "lib/crypto/gkdi.h"

#include <stdbool.h>
#include <string.h>

#define DCESRV_INTERFACE_GKDI_BIND(context, iface) \
	dcesrv_interface_gkdi_bind(context, iface)
static NTSTATUS dcesrv_interface_gkdi_bind(
	struct dcesrv_connection_context *context,
	const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(context, iface);
}

bool gkdi_current_time(NTTIME *current_time_out)
{
	struct timespec current_timespec;
	int ret;

	ret = clock_gettime(CLOCK_REALTIME, &current_timespec);
	if (ret) {
		return false;
	}

	*current_time_out = full_timespec_to_nt_time(&current_timespec);
	return true;
}

static NTSTATUS dcesrv_gkdi_get_root_key(
	TALLOC_CTX *mem_ctx,
	struct ldb_context *const ldb_ctx,
	const NTTIME current_time,
	const NTTIME not_after,
	bool can_create_root_key,
	struct GUID *root_key_id,
	const struct ProvRootKey **const root_key_out)
{
	const struct ldb_message *root_key_msg = NULL;

	if (gkdi_most_recently_created_root_key(mem_ctx,
						ldb_ctx,
						current_time,
						not_after,
						root_key_id,
						&root_key_msg))
	{
		if (!can_create_root_key) {
			return NT_STATUS_NOT_FOUND;
		}

		if (gkdi_new_root_key(mem_ctx,
				      ldb_ctx,
				      current_time,
				      current_time,
				      root_key_id,
				      &root_key_msg))
		{
			return NT_STATUS_NOT_FOUND;
		}
	}

	return gkdi_root_key_from_msg(mem_ctx,
				      *root_key_id,
				      root_key_msg,
				      root_key_out);
}

static struct GroupKeyEnvelope *dcesrv_gkdi_create_envelope(
	TALLOC_CTX *mem_ctx,
	struct ldb_context *const ldb_ctx,
	const struct Gkid *gkid,
	const struct ProvRootKey *root_key)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct GroupKeyEnvelope *envelope = NULL;
	const char *root_key_config_DomainID = NULL;
	const char *root_key_config_ForestID = NULL;
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err = NDR_ERR_SUCCESS;
	struct KdfParameters kdf_parameters = {};
	DATA_BLOB secret_agreement_parameters_blob = {};
	DATA_BLOB kdf_parameters_blob = {};

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		goto out;
	}

	root_key_config_DomainID = samdb_default_domain_name(ldb_ctx, mem_ctx);
	if (!root_key_config_DomainID) {
		goto out;
	}

	root_key_config_ForestID = samdb_forest_name(ldb_ctx, tmp_ctx);
	if (!root_key_config_ForestID) {
		goto out;
	}

	envelope = talloc_zero(tmp_ctx, struct GroupKeyEnvelope);
	if (!envelope) {
		goto out;
	}

	envelope->magic = key_envelope_magic;

	envelope->version = root_key->version;

	envelope->l0_index = gkid->l0_idx;
	envelope->l1_index = gkid->l1_idx;
	envelope->l2_index = gkid->l2_idx;

	envelope->root_key_id = root_key->id;

	/*
	 * MS-GKDI specifies only one supported algorithm SP800_108_CTR_HMAC.
	 */
	envelope->kdf_algorithm = SP800_108_CTR_HMAC;
	envelope->kdf_algorithm_len = sizeof(SP800_108_CTR_HMAC);

	{
		switch (root_key->kdf_algorithm.param.sp800_108) {
		case KDF_PARAM_SHA1:
			kdf_parameters.hash_algorithm = "SHA1";
			kdf_parameters.hash_algorithm_len = sizeof("SHA1");
			break;
		case KDF_PARAM_SHA256:
			kdf_parameters.hash_algorithm = "SHA256";
			kdf_parameters.hash_algorithm_len = sizeof("SHA256");
			break;
		case KDF_PARAM_SHA384:
			kdf_parameters.hash_algorithm = "SHA384";
			kdf_parameters.hash_algorithm_len = sizeof("SHA384");
			break;
		case KDF_PARAM_SHA512:
			kdf_parameters.hash_algorithm = "SHA512";
			kdf_parameters.hash_algorithm_len = sizeof("SHA512");
			break;
		default:
			break;
		}
	}

	err = ndr_push_struct_blob(&kdf_parameters_blob,
				   envelope,
				   &kdf_parameters,
				   (ndr_push_flags_fn_t)ndr_push_KdfParameters);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		envelope = NULL;
		DBG_WARNING("KdfParameters push failed: %s\n",
			    nt_errstr(status));
		goto out;
	}

	envelope->kdf_parameters = kdf_parameters_blob.data;
	envelope->kdf_parameters_len = kdf_parameters_blob.length;

	if (root_key->secret_agreement_algorithm.id ==
	    SECRET_AGREEMENT_ALGORITHM_DH)
	{
		envelope->secret_agreement_algorithm = talloc_strdup(envelope,
								     "DH");
		envelope->secret_agreement_algorithm_len = sizeof("DH");

		err = ndr_push_struct_blob(&secret_agreement_parameters_blob,
					   envelope,
					   root_key->secret_agreement_algorithm
						   .param.dh_parameters,
					   (ndr_push_flags_fn_t)
						   ndr_push_FfcDhParameters);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			envelope = NULL;
			DBG_WARNING("FfcDhParameters push failed: %s\n",
				    nt_errstr(status));
			goto out;
		}

		envelope->secret_agreement_parameters =
			secret_agreement_parameters_blob.data;
		envelope->secret_agreement_parameters_len =
			secret_agreement_parameters_blob.length;
	} else {
		switch (root_key->secret_agreement_algorithm.id) {
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P256:
			envelope->secret_agreement_algorithm = talloc_strdup(
				envelope, "ECDH_P256");
			envelope->secret_agreement_algorithm_len = sizeof(
				"ECDH_P256");
			break;
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P384:
			envelope->secret_agreement_algorithm = talloc_strdup(
				envelope, "ECDH_P384");
			envelope->secret_agreement_algorithm_len = sizeof(
				"ECDH_P384");
			break;
		case SECRET_AGREEMENT_ALGORITHM_ECDH_P521:
			envelope->secret_agreement_algorithm = talloc_strdup(
				envelope, "ECDH_P521");
			envelope->secret_agreement_algorithm_len = sizeof(
				"ECDH_P521");
			break;
		default:
			break;
		}

		envelope->secret_agreement_parameters = NULL;
		envelope->secret_agreement_parameters_len = 0;
	}

	envelope->domain_name = talloc_strdup(envelope,
					      root_key_config_DomainID);
	if (!envelope->domain_name) {
		envelope = NULL;
		DBG_WARNING("Failed to allocate domain name.\n");
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	envelope->domain_name_len = strlen(root_key_config_DomainID);

	envelope->forest_name = talloc_strdup(envelope,
					      root_key_config_ForestID);
	if (!envelope->forest_name) {
		envelope = NULL;
		DBG_WARNING("Failed to allocate forest name.\n");
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	envelope->forest_name_len = strlen(root_key_config_ForestID);

	envelope->public_key_len = root_key->public_key_length;
	envelope->private_key_len = root_key->private_key_length;

	talloc_steal(mem_ctx, envelope);

out:
	talloc_free(tmp_ctx);

	return envelope;
}

static HRESULT dcesrv_gkdi_GetKey_from_writeable_dc(
	struct dcesrv_call_state *dce_call,
	struct gkdi_GetKey *r,
	TALLOC_CTX *mem_ctx,
	const char *domain_id,
	uint32_t *key_length,
	uint8_t **key)
{
	NTSTATUS status = NT_STATUS_OK;
	HRESULT result = HRES_ERROR(0);

	struct netr_DsRGetDCNameInfo *info = NULL;
	WERROR werror = WERR_OK;
	TALLOC_CTX *tmp_ctx = NULL;

	struct dcerpc_pipe *netr_pipe = NULL;
	char *netr_binding_string = NULL;
	struct dcerpc_pipe *gkdi_pipe = NULL;
	char *gkdi_binding_string = NULL;
	struct cli_credentials *credentials = NULL;
	struct loadparm_context *lp_ctx = dce_call->conn->dce_ctx->lp_ctx;
	struct tevent_context *ev_ctx = dce_call->conn->event_ctx;

	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	credentials = cli_credentials_init_server(tmp_ctx, lp_ctx);
	if (!credentials) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	// TODO: Check connection parameters for MS-RPC call.
	netr_binding_string = talloc_asprintf(tmp_ctx,
					      "ncacn_ip_tcp:%s",
					      domain_id);
	if (!netr_binding_string) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	status = dcerpc_pipe_connect(tmp_ctx,
				     &netr_pipe,
				     netr_binding_string,
				     &ndr_table_netlogon,
				     credentials,
				     ev_ctx,
				     lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	status = dcerpc_netr_DsRGetDCNameEx2(
		netr_pipe->binding_handle,
		tmp_ctx,
		NULL,
		NULL,
		0,
		domain_id,
		NULL,
		NULL,
		DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_8_REQUIRED,
		&info,
		&werror);
	if (!NT_STATUS_IS_OK(status)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	if (!W_ERROR_EQUAL(werror, WERR_OK)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	// TODO: Check connection parameters for MS-RPC call.
	gkdi_binding_string = talloc_asprintf(tmp_ctx,
					      "ncacn_ip_tcp:%s",
					      info->domain_name);
	if (!gkdi_binding_string) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	status = dcerpc_pipe_connect(tmp_ctx,
				     &gkdi_pipe,
				     gkdi_binding_string,
				     &ndr_table_gkdi,
				     credentials,
				     ev_ctx,
				     lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	status = dcerpc_gkdi_GetKey(gkdi_pipe->binding_handle,
				    tmp_ctx,
				    r->in.target_sd_len,
				    r->in.target_sd,
				    r->in.root_key_id,
				    r->in.l0_key_id,
				    r->in.l1_key_id,
				    r->in.l2_key_id,
				    key_length,
				    key,
				    &result);
	if (!NT_STATUS_IS_OK(status)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	if (!HRES_IS_OK(result)) {
		result = HRES_RPC_E_SERVERCALL_REJECTED;
		goto out;
	}

	talloc_steal(mem_ctx, *key);

out:
	talloc_free(tmp_ctx);

	return result;
}

static bool unpack_GroupKeyEnvelope(TALLOC_CTX *mem_ctx,
				    uint8_t *data,
				    uint32_t size,
				    struct GroupKeyEnvelope **envelope_out)
{
	DATA_BLOB data_blob = {.data = data, .length = size};
	enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
	*envelope_out = talloc_zero(mem_ctx, struct GroupKeyEnvelope);
	if (!*envelope_out) {
		return false;
	}
	ndr_status = ndr_pull_struct_blob(&data_blob,
					  mem_ctx,
					  *envelope_out,
					  (ndr_pull_flags_fn_t)
						  ndr_pull_GroupKeyEnvelope);
	return ndr_status == NDR_ERR_SUCCESS;
}

static HRESULT dcesrv_gkdi_rodc_process_request(
	struct dcesrv_call_state *dce_call,
	TALLOC_CTX *mem_ctx,
	struct gkdi_GetKey *r,
	const struct Gkid *gkid,
	NTTIME current_time,
	bool access_seed_keys)
{
	NTSTATUS status = NT_STATUS_OK;
	HRESULT result = HRES_ERROR(0);
	const char *domain_id = NULL;

	uint32_t key_length = 0;
	uint8_t *key = NULL;
	struct GroupKeyEnvelope *envelope = 0;
	bool rc = false;
	bool return_group_key = false;

	uint8_t l2_seed_key[GKDI_KEY_LEN];
	DATA_BLOB public_group_key = {};
	DATA_BLOB blobenvelope = {};
	const struct ProvRootKey *root_key = NULL;

	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	struct ldb_context *ldb_ctx = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	NTTIME key_start_time = 0;
	DATA_BLOB security_descriptor_blob = {.data = r->in.target_sd,
					      .length = r->in.target_sd_len};

	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	ldb_ctx = dcesrv_samdb_connect_as_system(tmp_ctx, dce_call);
	if (!ldb_ctx) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	domain_id = samdb_default_domain_name(ldb_ctx, tmp_ctx);
	if (!domain_id) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}
	/*
	 * The Group Key Distribution Protocol client receives requests from a
	 * higher layer. The caller requests the retrieval of a key for a given
	 * security descriptor, while optionally specifying a root key
	 * identifier and group key identifier. The caller also specifies the
	 * name of the Active Directory domain from which to retrieve keys and
	 * provides valid user credentials for authenticating in a specific
	 * domain.
	 */

	/* Current implementation does not support key caching. */

	/*
	 * If no key is found in the cache, the client MUST attempt to connect
	 * to a server and retrieve a key as specified in section 3.2.4.2.
	 */
	result = dcesrv_gkdi_GetKey_from_writeable_dc(
		dce_call, r, mem_ctx, domain_id, &key_length, &key);
	if (!HRES_IS_OK(result)) {
		goto out;
	}

	rc = unpack_GroupKeyEnvelope(mem_ctx, key, key_length, &envelope);
	if (!rc || !envelope) {
		result = HRES_RPC_E_INVALID_DATA;
		goto out;
	}

	/*
	 * 1. If bit 31 of the dwFlags field of the returned Group Key Envelope
	 * is set to 1, the value in the L2 key field is a public key with group
	 * key identifier (L0 field, L1 field, L2 field).
	 */
	if (envelope->flags & ENVELOPE_FLAG_TRANSPORTING_PUBLIC_KEY) {
		/*
		 * 1. If the root key identifier was not specified in the
		 * request from the higher layer (for example, the higher layer
		 * requesting the most recent key), and the server returned a
		 * public key, the client MUST return the public key to the
		 * caller.
		 */
		if (!r->in.root_key_id) {
			return_group_key = true;
		} else if (envelope->l0_index == r->in.l0_key_id &&
			   envelope->l1_index == r->in.l1_key_id &&
			   envelope->l2_index == r->in.l2_key_id)
		{
			return_group_key = true;
		}

		/* If we have most recent group key or a group key with
		 * exact root key id return it to user.
		 */
		if (return_group_key && !access_seed_keys) {
			r->out.out = &key;
			r->out.out_len = &key_length;
			result = HRES_ERROR(0);
			goto out;
		}

		result = HRES_RPC_E_INVALID_DATA;
		goto out;
	}

	/*
	 * 2. If bit 31 of the dwFlags field of the returned Group Key Envelope
	 * is set to 0 and the L2 Key field is present, the value in the L2 key
	 * field is an L2 seed key with group key identifier (L0 field, L1
	 * field, L2 field).
	 */
	if (envelope->l2_key) {
		/*
		 * 2. Otherwise, the server MUST have returned a seed key. If no
		 * root key identifier was specified in the request from the
		 * higher layer (for example, the higher layer was requesting
		 * the most recent key), then:
		 * * If the server's response contains an L2 key, return that to
		 * the caller.
		 */
		if (!r->in.root_key_id) {
			/* We already have most recent valid seed key. */
		} else {
			/*
			 * 3. If the server returned a seed key in response to a
			 * request with a specified root key identifier, then:
			 *    * If the response contains an L2 key whose group
			 * key identifier matches the requested group key
			 * identifier, return this L2 key to the caller.
			 */
			if (envelope->l0_index == r->in.l0_key_id &&
			    envelope->l1_index == r->in.l1_key_id &&
			    envelope->l2_index == r->in.l2_key_id)
			{
				/* We already have valid seed key. */
			} else if (envelope->l0_index == r->in.l0_key_id &&
				   envelope->l1_index == r->in.l1_key_id &&
				   envelope->l2_index > r->in.l2_key_id)
			{
				access_seed_keys = false;
			} else {
				result = HRES_RPC_E_INVALID_DATA;
				goto out;
			}
		}

		if (!access_seed_keys) {
			if (GKDI_KEY_LEN == envelope->l2_key_len) {
				memcpy(l2_seed_key,
				       envelope->l2_key,
				       GKDI_KEY_LEN);
			} else {
				result = HRES_RPC_E_INVALID_DATA;
				goto out;
			}
		}
	}
	/*
	 * 3. If bit 31 of the dwFlags field of the returned Group Key Envelope
	 * is set to 0 and the L1 Key field is present, then:
	 * * If the value in the L2 index field is 31, the value in the L1 Key
	 * field is an L1 seed key with group key identifier (L0 field, L1
	 * field, -1).
	 * * If the value in the L2 index field is not 31, the value in the L1
	 * Key field is an L1 seed key with group key identifier (L0 field, L1
	 * field - 1, -1).
	 */
	else if (envelope->l1_key)
	{
		/*
		 * 4. Otherwise, if the response contains an L1 key that has the
		 * same L0 index and the same or greater L1 index as the
		 * requested group key, use this to derive the requested group
		 * key, as specified in section 3.1.4.1.2, and return the result
		 * to the caller.
		 */
		if (!access_seed_keys) {
			if (gkid->l0_idx != envelope->l0_index) {
				result = HRES_RPC_E_INVALID_DATA;
				goto out;
			}

			/*
			 * Current API prevent us from using L1 key to derive L2
			 * key. We need to derive L2 key from gkid.
			 */
			status = compute_seed_key(tmp_ctx,
						  security_descriptor_blob,
						  root_key,
						  *gkid,
						  l2_seed_key);
			if (!NT_STATUS_IS_OK(status)) {
				result = HRES_RPC_E_INVALID_PARAMETER;
				goto out;
			}
		}
	} else {
		result = HRES_RPC_E_INVALID_DATA;
		goto out;
	}

	if (access_seed_keys) {
		r->out.out = &key;
		r->out.out_len = &key_length;
		result = HRES_ERROR(0);
		goto out;
	} else {
		if (!gkdi_get_key_start_time(*gkid, &key_start_time)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		status = dcesrv_gkdi_get_root_key(tmp_ctx,
						  ldb_ctx,
						  current_time,
						  key_start_time,
						  false,
						  r->in.root_key_id,
						  &root_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		envelope->flags = ENVELOPE_FLAG_TRANSPORTING_PUBLIC_KEY;

		envelope->l1_key = NULL;
		envelope->l1_key_len = 0;

		status = compute_group_public_key(tmp_ctx,
						  root_key,
						  l2_seed_key,
						  *gkid,
						  &public_group_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		envelope->l2_key = talloc_memdup(envelope,
						 public_group_key.data,
						 public_group_key.length);
		envelope->l2_key_len = public_group_key.length;
		if (!envelope->l2_key) {
			result = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}

		ndr_err = ndr_push_struct_blob(
			&blobenvelope,
			mem_ctx,
			envelope,
			(ndr_push_flags_fn_t)ndr_push_GroupKeyEnvelope);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			result = HRES_RPC_E_SERVER_CANTMARSHAL_DATA;
			goto out;
		}

		uint32_t *length = talloc(mem_ctx, uint32_t);
		if (!length) {
			result = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}
		*length = blobenvelope.length;

		uint8_t **data = talloc(mem_ctx, uint8_t *);
		if (!data) {
			result = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}
		*data = blobenvelope.data;

		r->out.out = data;
		r->out.out_len = length;

		result = HRES_ERROR(0);
		goto out;
	}

out:
	talloc_free(tmp_ctx);

	return result;
}

static HRESULT dcesrv_gkdi_process_request(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct gkdi_GetKey *r,
					   const struct Gkid *gkid,
					   NTTIME current_time,
					   const bool access_seed_keys)
{
	bool is_rodc = false;
	struct ldb_context *ldb_ctx = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	HRESULT result = HRES_ERROR(0);

	tmp_ctx = talloc_new(NULL);
	if (!tmp_ctx) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	/*
	 * The server MUST then determine whether it is running on a writable DC
	 * or a read-only domain controller (RODC) via implementation-specific
	 * means. If it is running on an RODC, the server MUST process the
	 * request as a client, as specified in section 3.2.4.1. Specifically,
	 * it MUST look for a cached key using the group key identifier GKID
	 * computed in the previous step 4. If a matching key is not found in
	 * the cache, the server MUST forward the request to a writable DC with
	 * group key identifier (L0KeyID, L1KeyID, L2KeyID), as specified by the
	 * caller.
	 */
	ldb_ctx = dcesrv_samdb_connect_as_system(tmp_ctx, dce_call);
	if (!ldb_ctx) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	if (samdb_rodc(ldb_ctx, &is_rodc) != LDB_SUCCESS) {
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	if (is_rodc) {
		result = dcesrv_gkdi_rodc_process_request(dce_call,
							  mem_ctx,
							  r,
							  gkid,
							  current_time,
							  access_seed_keys);
		goto out;
	}

	const struct ProvRootKey *root_key = NULL;
	struct GUID root_key_id = {};
	uint8_t l1_seed_key[GKDI_KEY_LEN];
	uint8_t l2_seed_key[GKDI_KEY_LEN];
	DATA_BLOB public_group_key = {};
	DATA_BLOB blobenvelope = {};
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	struct Gkid l1_gkid = {};

	/*
	 * 1. If the pRootKeyID parameter is not NULL, locate the root
	 * key object whose CN matches the pRootKeyID parameter value
	 * and proceed to step 5. If no such root key object is found,
	 * return an error and exit.
	 */
	if (r->in.root_key_id != NULL) {
		const struct ldb_message *root_key_msg = NULL;
		root_key_id = *r->in.root_key_id;

		if (gkdi_root_key_from_id(
			    tmp_ctx, ldb_ctx, &root_key_id, &root_key_msg))
		{
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		status = gkdi_root_key_from_msg(tmp_ctx,
						root_key_id,
						root_key_msg,
						&root_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}
	}
	/*
	 * 2. If the L0KeyID, L1KeyID, and L2KeyID parameters are all
	 * equal to -1, select the root key object that has the highest
	 * value in its msKds-UseStartTime attribute. If the set of root
	 * keys is empty, create a new root key by using the method
	 * specified in section 3.1.4.1.1 and proceed to step 5.
	 */
	else if (r->in.l0_key_id == -1 && r->in.l1_key_id == -1 &&
		 r->in.l2_key_id == -1)
	{
		const NTTIME one_interval = gkdi_key_cycle_duration +
					    gkdi_max_clock_skew;
		const NTTIME one_interval_ago = current_time -
						MIN(one_interval, current_time);

		status = dcesrv_gkdi_get_root_key(tmp_ctx,
						  ldb_ctx,
						  current_time,
						  one_interval_ago,
						  true,
						  &root_key_id,
						  &root_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}
	}
	/*
	 * 3. Convert the GKID value to an unsigned 64-bit number by
	 * reversing the method specified in step 2 of the previous
	 * procedure. Let this number be denoted KeyStartTime.
	 * 4. From the set of root key objects, select the subset of
	 * root keys that have the msKds- UseStartTime attribute value
	 * less than or equal to KeyStartTime. If this subset contains
	 * more than one root key object, select the one with the
	 * highest msKds-CreateTime attribute value. If no suitable root
	 * key object can be found, return an error and exit.
	 */
	else
	{
		NTTIME key_start_time = 0;

		if (!gkdi_get_key_start_time(*gkid, &key_start_time)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		status = dcesrv_gkdi_get_root_key(tmp_ctx,
						  ldb_ctx,
						  current_time,
						  key_start_time,
						  false,
						  &root_key_id,
						  &root_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}
	}

	DATA_BLOB security_descriptor_blob = {.data = r->in.target_sd,
					      .length = r->in.target_sd_len};

	/*
	 * 5. Let the root key object selected in the above steps be
	 * denoted RK. Compute the seed key corresponding to security
	 * descriptor pbTargetSD, root key RK, and group key identifier
	 * GKID, as specified in section 3.1.4.1.2. Let this seed key be
	 * denoted SK.
	 */
	status = compute_seed_key(tmp_ctx,
				  security_descriptor_blob,
				  root_key,
				  *gkid,
				  l2_seed_key);
	if (!NT_STATUS_IS_OK(status)) {
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	struct GroupKeyEnvelope *envelope = dcesrv_gkdi_create_envelope(
		tmp_ctx, ldb_ctx, gkid, root_key);
	if (!envelope) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	/*
	 * 6. If the client is only authorized to access public keys, as
	 * determined by the access checks in steps 5 and 7 of the
	 * previous procedure, compute the public key corresponding to
	 * the SK, as specified in section 3.1.4.1.2. Return the result
	 * in the ppbOut parameter of the GetKey method, by using the
	 * format specified in section 2.2.4, and then exit.
	 */
	if (!access_seed_keys) {
		envelope->flags |= ENVELOPE_FLAG_TRANSPORTING_PUBLIC_KEY;

		envelope->l1_key = NULL;
		envelope->l1_key_len = 0;

		status = compute_group_public_key(tmp_ctx,
						  root_key,
						  l2_seed_key,
						  *gkid,
						  &public_group_key);
		if (!NT_STATUS_IS_OK(status)) {
			result = HRES_RPC_E_INVALID_PARAMETER;
			goto out;
		}

		envelope->l2_key = talloc_memdup(envelope,
						 public_group_key.data,
						 public_group_key.length);
		envelope->l2_key_len = public_group_key.length;
		if (!envelope->l2_key) {
			result = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}
	}
	/*
	 * 7. Client is authorized to access seed keys, as determined by
	 * the access check in step 5 of the previous procedure.
	 */
	else
	{
		/*
		 * A 32-bit unsigned integer. Bit 31 (LSB) MUST be set
		 * to 1 when this structure is being used to transport a
		 * public key, otherwise set to 0. Bit 30 MUST be set to
		 * 1 when the key being transported by this structure
		 * might be used for encryption and decryption,
		 * otherwise it should only be used for decryption. This
		 * field is encoded using little-endian format.
		 */
		envelope->flags |= ENVELOPE_FLAG_KEY_MAY_ENCRYPT_NEW_DATA;

		/*
		 * If the L2 component of GKID is equal to 31, return
		 * the L1 seed key corresponding to SK in the ppbOut
		 * parameter by using the format specified in
		 * section 2.2.4, with the L2 key field omitted.
		 */
		if (gkid->l2_idx == 31) {
			l1_gkid = Gkid(gkid->l0_idx, gkid->l1_idx, -1);
			status = compute_seed_key(tmp_ctx,
						  security_descriptor_blob,
						  root_key,
						  l1_gkid,
						  l1_seed_key);
			if (!NT_STATUS_IS_OK(status)) {
				result = HRES_RPC_E_INVALID_PARAMETER;
				goto out;
			}

			envelope->l1_key = talloc_memdup(envelope,
							 l1_seed_key,
							 GKDI_KEY_LEN);
			envelope->l1_key_len = GKDI_KEY_LEN;
			if (!envelope->l1_key) {
				result = HRES_RPC_E_OUT_OF_RESOURCES;
				goto out;
			}

			envelope->l2_key = NULL;
			envelope->l2_key_len = 0;
		}
		/*
		 * Otherwise, if the L1 component of GKID is equal to 0,
		 * return SK in the ppbOut parameter by using the format
		 * specified in section 2.2.4, with the L1 key field
		 * omitted.
		 */
		else if (gkid->l1_idx == 0)
		{
			envelope->l1_key = NULL;
			envelope->l1_key_len = 0;

			envelope->l2_key = talloc_memdup(envelope,
							 l2_seed_key,
							 GKDI_KEY_LEN);
			envelope->l2_key_len = GKDI_KEY_LEN;
			if (!envelope->l2_key) {
				result = HRES_RPC_E_OUT_OF_RESOURCES;
				goto out;
			}
		}
		/*
		 * If neither of the above two cases apply, construct
		 * the return value in the ppbOut parameter by using the
		 * format specified in section 2.2.4, with SK in the L2
		 * key field and the next older L1 seed key in the L1
		 * key field.
		 */
		else
		{
			// Downgrade l1_idx by one and set l2_idx to -1.
			// When calculate next older L1.
			l1_gkid = Gkid(gkid->l0_idx, gkid->l1_idx - 1, -1);
			status = compute_seed_key(tmp_ctx,
						  security_descriptor_blob,
						  root_key,
						  l1_gkid,
						  l1_seed_key);
			if (!NT_STATUS_IS_OK(status)) {
				result = HRES_RPC_E_INVALID_PARAMETER;
				goto out;
			}

			envelope->l1_key = talloc_memdup(envelope,
							 l1_seed_key,
							 GKDI_KEY_LEN);
			envelope->l1_key_len = GKDI_KEY_LEN;
			if (!envelope->l1_key) {
				result = HRES_RPC_E_OUT_OF_RESOURCES;
				goto out;
			}

			envelope->l2_key = talloc_memdup(envelope,
							 l2_seed_key,
							 GKDI_KEY_LEN);
			envelope->l2_key_len = GKDI_KEY_LEN;
			if (!envelope->l2_key) {
				result = HRES_RPC_E_OUT_OF_RESOURCES;
				goto out;
			}
		}
	}

	ndr_err = ndr_push_struct_blob(&blobenvelope,
				       mem_ctx,
				       envelope,
				       (ndr_push_flags_fn_t)
					       ndr_push_GroupKeyEnvelope);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		result = HRES_RPC_E_SERVER_CANTMARSHAL_DATA;
		goto out;
	}

	uint32_t *length = talloc(mem_ctx, uint32_t);
	if (!length) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}
	*length = blobenvelope.length;

	uint8_t **data = talloc(mem_ctx, uint8_t *);
	if (!data) {
		result = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}
	*data = blobenvelope.data;

	r->out.out = data;
	r->out.out_len = length;

out:
	talloc_free(tmp_ctx);

	return result;
}

static bool unpack_security_descriptor(TALLOC_CTX *mem_ctx,
				       uint8_t *data,
				       uint32_t size,
				       struct security_descriptor **descriptor)
{
	DATA_BLOB data_blob = {.data = data, .length = size};
	enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
	*descriptor = talloc_zero(mem_ctx, struct security_descriptor);
	if (!*descriptor) {
		return false;
	}
	ndr_status = ndr_pull_struct_blob(&data_blob,
					  mem_ctx,
					  *descriptor,
					  (ndr_pull_flags_fn_t)
						  ndr_pull_security_descriptor);
	return ndr_status == NDR_ERR_SUCCESS;
}

/*
  gkdi_GetKey
*/
static HRESULT dcesrv_gkdi_GetKey(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct gkdi_GetKey *r)
{
	HRESULT result = HRES_RPC_E_SERVERFAULT;
	NTTIME current_time = 0;
	uint32_t access_granted = 0;
	NTSTATUS status = NT_STATUS_OK;
	struct security_descriptor *target_sd = NULL;
	struct auth_session_info *session_info = dcesrv_call_session_info(
		dce_call);
	bool access_seed_keys = (r->in.l0_key_id > -1 && r->in.l1_key_id > -1 &&
				 r->in.l2_key_id > -1);

	if (lpcfg_server_role(dce_call->conn->dce_ctx->lp_ctx) !=
	    ROLE_ACTIVE_DIRECTORY_DC)
	{
		return HRES_RPC_E_CALL_REJECTED;
	}

	/*
	 * When a Group Key Distribution Protocol server receives the GetKey
	 * request, it must first validate that the pbTargetSD parameter is a
	 * valid security descriptor in self-relative format. The server MUST
	 * also verify that the L0KeyID, L1KeyID, and L2KeyID parameters are
	 * either all equal to -1 or all greater than or equal to 0. If any of
	 * these conditions are not met, the server MUST return an error and
	 * exit.
	 */
	if (!unpack_security_descriptor(
		    mem_ctx, r->in.target_sd, r->in.target_sd_len, &target_sd))
	{
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	struct Gkid gkid = Gkid(r->in.l0_key_id,
				r->in.l1_key_id,
				r->in.l2_key_id);

	if (!gkid_is_valid(gkid)) {
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	if (!gkdi_current_time(&current_time)) {
		result = HRES_RPC_E_SERVERFAULT;
		goto out;
	}

	/*
	 * 1. Retrieve the current time in the FILETIME format specified in
	 * [MS-DTYP] section 2.3.3. Construct an unsigned 64-bit number by
	 * setting the low-order word to dwLowDateTime and the high-order word
	 * to dwHighDateTime. Call this 64-bit number CurrentTime.
	 * 2. Convert the CurrentTime value to a group key identifier (L0, L1,
	 * L2) as follows; the division operator in the following calculations
	 * represents integer division:
	 * * L0 = CurrentTime / (32 * 32 * 3.6 * 1011)
	 * * L1 = (CurrentTime mod (32 * 32 * 3.6 * 1011)) / (32 * 3.6 * 1011)
	 * * L2 = (CurrentTime mod (32 * 3.6 * 1011)) / (3.6 * 1011)
	 * 3. If (L0KeyID, L1KeyID, L2KeyID) is lexically greater than (L0, L1,
	 * L2), then return an error and exit.
	 */
	const struct Gkid current_time_gkid = gkdi_get_interval_id(
		current_time + gkdi_max_clock_skew);

	if (!gkid_less_than_or_equal_to(gkid, current_time_gkid)) {
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * 4. Otherwise, compute a group key identifier (GKID) as follows:
	 * * If the pRootKeyID parameter is equal to NULL and L0KeyID >= 0, GKID
	 * = (L0KeyID, L1KeyID, L2KeyID).
	 * * Otherwise, if the pRootKeyID parameter is not equal to NULL and 0
	 * =< L0KeyID < L0, GKID = (L0KeyID, 31, 31).
	 * * Otherwise, GKID = (L0, L1, L2).
	 */
	if (r->in.root_key_id == NULL && r->in.l0_key_id >= 0) {
		// We already have GKID.
	} else if (r->in.root_key_id != NULL &&
		   (0 <= r->in.l0_key_id &&
		    r->in.l0_key_id < current_time_gkid.l0_idx))
	{
		gkid = Gkid(r->in.l0_key_id, 31, 31);
	} else {
		gkid = current_time_gkid;
	}

	/*
	 * 5. Using the method specified in [MS-DTYP] section 2.5.3.2, perform
	 * an access check with the pbTargetSD parameter value as the
	 * SecurityDescriptor, the caller's authorization context as the Token,
	 * 0x3 as the Access Request mask, and with the Object Tree and
	 * PrincipalSelfSubst SID set to NULL. If access is granted, the client
	 * is authorized to access seed keys. Otherwise, if access is not
	 * granted, proceed to step 6.
	 */
	status = sec_access_check_ds(target_sd,
				     session_info->security_token,
				     SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				     &access_granted,
				     NULL,
				     NULL);

	if (NT_STATUS_IS_OK(status)) {
		// The client is authorized to access seed keys.
		result = dcesrv_gkdi_process_request(
			dce_call, mem_ctx, r, &gkid, current_time, true);
		goto out;
	}
	/*
	 * 6. If the L0KeyID, L1KeyID, and L2KeyID parameters are not all equal
	 * to -1, return an error and exit.
	 */
	else if (r->in.l0_key_id != -1 || r->in.l1_key_id != -1 ||
		 r->in.l2_key_id != -1)
	{
		result = HRES_RPC_E_INVALID_PARAMETER;
		goto out;
	}

	/*
	 * 7. Otherwise, using the method specified in [MS-DTYP]
	 * section 2.5.3.2, perform an access check with pbTargetSD parameter
	 * value as the SecurityDescriptor, the caller's authorization context
	 * as the Token, 0x2 as the Access Request mask, and with the Object
	 * Tree and PrincipalSelfSubst SID set to NULL. If access is granted,
	 * the client is only authorized to access public keys. Otherwise, if
	 * access is not granted, return an error and exit.
	 */
	status = sec_access_check_ds(target_sd,
				     session_info->security_token,
				     SEC_FILE_WRITE_DATA,
				     &access_granted,
				     NULL,
				     NULL);

	if (NT_STATUS_IS_OK(status)) {
		// The client is only authorized to access public keys.
		result = dcesrv_gkdi_process_request(
			dce_call, mem_ctx, r, &gkid, current_time, false);
		goto out;
	} else {
		result = HRES_RPC_E_ACCESS_DENIED;
		goto out;
	}

out:
	talloc_unlink(mem_ctx, target_sd);

	return result;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_gkdi_s.c"
