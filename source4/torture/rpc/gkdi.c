#include "includes.h"
#include "../libcli/security/security.h"

#include "torture/rpc/torture_rpc.h"
#include "torture/ndr/ndr.h"

#include "dsdb/gmsa/gkdi.h"

#include "dcerpc.h"
#include "librpc/gen_ndr/ndr_gkdi_c.h"
#include "librpc/gen_ndr/ndr_gkdi.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "lib/cmdline/cmdline.h"
#include "lib/crypto/gkdi.h"
#include "lib/ldb/include/ldb.h"
#include "libcli/auth/proto.h"
#include "ldb_wrap.h"
#include <system/network.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

bool get_current_time(NTTIME *current_time_out)
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

static bool create_test_secutiry_descriptor(struct torture_context *tctx,
					    const uint32_t access_mask,
					    DATA_BLOB *out_sdblob)
{
	NTSTATUS status;
	struct security_descriptor *sd;
	struct security_ace *ace;
	struct dom_sid *sid;

	ace = talloc_zero(tctx, struct security_ace);
	torture_assert(tctx, ace, "Unable to allocate ace.");

	sid = talloc_zero(tctx, struct dom_sid);
	torture_assert(tctx, sid, "Unable to allocate sid.");

	sd = security_descriptor_dacl_create(
		tctx, 0, SID_NT_SYSTEM, SID_NT_SYSTEM, NULL);

	torture_assert(tctx,
		       dom_sid_parse(SID_NT_AUTHENTICATED_USERS, sid),
		       "Unable to parse user sid.");
	init_sec_ace(ace, sid, SEC_ACE_TYPE_ACCESS_ALLOWED, access_mask, 0);
	status = security_descriptor_dacl_add(sd, ace);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "Unable to add ace to security descriptor.");

	torture_assert(tctx,
		       dom_sid_parse(SID_WORLD, sid),
		       "Unable to parse world sid.");
	init_sec_ace(
		ace, sid, SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_FILE_WRITE_DATA, 0);
	status = security_descriptor_dacl_add(sd, ace);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "Unable to add ace to security descriptor.");

	torture_assert_ndr_success(
		tctx,
		ndr_push_struct_blob(out_sdblob,
				     tctx,
				     sd,
				     (ndr_push_flags_fn_t)
					     ndr_push_security_descriptor),
		"Failed to push security_descriptor ?!\n");

	return true;
}

static bool create_invalid_secutiry_descriptor(struct torture_context *tctx,
					       DATA_BLOB *out_sdblob)
{
	struct security_descriptor *sd;

	sd = security_descriptor_dacl_create(
		tctx,
		0,
		NULL,
		NULL,
		SID_NT_AUTHENTICATED_USERS,
		SEC_ACE_TYPE_ACCESS_ALLOWED,
		SEC_GENERIC_ALL,
		SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT,
		NULL);

	torture_assert_ndr_success(
		tctx,
		ndr_push_struct_blob(out_sdblob,
				     tctx,
				     sd,
				     (ndr_push_flags_fn_t)
					     ndr_push_security_descriptor),
		"Failed to push security_descriptor ?!\n");

	return true;
}

static struct gkdi_GetKey *createRetrieveKeyStruct(
	struct torture_context *tctx,
	struct dcerpc_pipe *p,
	int32_t l0_key_id,
	int32_t l1_key_id,
	int32_t l2_key_id,
	struct GUID *root_key_id,
	const DATA_BLOB security_descriptor,
	DATA_BLOB *out)
{
	struct dcerpc_binding *binding;
	const struct dcerpc_binding *b = NULL;
	struct gkdi_GetKey *r = talloc_zero(tctx, struct gkdi_GetKey);
	NTSTATUS status;

	if (r == NULL) {
		return NULL;
	}

	b = dcerpc_binding_handle_get_binding(p->binding_handle);
	binding = dcerpc_binding_dup(tctx, b);
	if (binding == NULL) {
		return NULL;
	}

	status = dcerpc_binding_set_flags(binding,
					  DCERPC_SEAL | DCERPC_AUTH_SPNEGO,
					  0);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	r->in.l0_key_id = l0_key_id;
	r->in.l1_key_id = l1_key_id;
	r->in.l2_key_id = l2_key_id;

	r->in.root_key_id = root_key_id;

	r->in.target_sd = security_descriptor.data;
	r->in.target_sd_len = security_descriptor.length;

	r->out.out = &out->data;
	r->out.out_len = talloc(r, uint32_t);

	return r;
}

/*
 * **Test Case GKDI-001: Latest Group Key Request**
 * - **Description**: When the pRootKeyID parameter is equal to NULL and
 * the values of the L0KeyID, L1KeyID, and L2KeyID parameters are all
 * equal to -1, the latest group key is being requested by the caller.
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Valid security descriptor
 * - **Expected Result**: Returns current seed key or public key based
 * on access rights.
 */
static bool test_RetrieveLatestGroupKey(struct torture_context *tctx,
					struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	struct gkdi_GetKey *r;

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, -1, -1, NULL, security_descriptor, &out_blob);
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Get Latest Group Key");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_ACCESS_DENIED,
					      "Get Latest Group Key");
	}

	return true;
}

/*
 * **Test Case GKDI-002: Specific Seed Key Request**
 * - **Description**: When the pRootKeyID parameter is equal to NULL and
 * the values of the L0KeyID, L1KeyID, and L2KeyID parameters are all
 * greater than -1, the seed key used at a specific time in the past is
 *                    being requested by the caller.
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: Valid historical values (all >=
 * 0)
 *  - Valid security descriptor
 * - **Expected Result**: Returns seed key or public key for the
 * specified time period
 */
static bool test_RetrieveSpecificSeedKey(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	NTTIME current_time = 0;
	struct Gkid interval_id;
	struct gkdi_GetKey *r = NULL;

	if (!get_current_time(&current_time)) {
		torture_fail(tctx, "Unable to get current time.");
	}

	interval_id = gkdi_get_interval_id(current_time);

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(tctx,
				    p,
				    interval_id.l0_idx,
				    interval_id.l1_idx,
				    interval_id.l2_idx,
				    NULL,
				    security_descriptor,
				    &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Get Specific Seed Key");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Get Specific Seed Key");
	}

	return true;
}

/*
 * **Test Case GKDI-003: Latest Group Key From Specific Root Key
 * Request**
 * - **Description**: When the pRootKeyID parameter is not equal to NULL
 * and the values of the L0KeyID, L1KeyID, and L2KeyID parameters are
 * all equal to -1, the latest group key derived from the specified root
 *                    key is being requested by the caller.
 * - **Input Parameters**:
 *  - `pRootKeyID`: Valid GUID
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Valid security descriptor
 * - **Expected Result**: Returns seed key or public key from specified
 * root key
 */
static bool test_RetrieveLatestGroupKeyFromSpecificRootKey(
	struct torture_context *tctx,
	struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct GUID *root_key_id = NULL;
	const struct ldb_message *root_key_msg = NULL;
	NTTIME key_start_time = 0;
	NTTIME current_time = 0;
	struct ldb_context *ldb_ctx = NULL;
	char *url = NULL;
	struct gkdi_GetKey *r = NULL;

	if (dcerpc_server_name(p)) {
		/* Set up connection to SAMDB on DC */
		url = talloc_asprintf(tctx, "ldap://%s", dcerpc_server_name(p));
		ldb_ctx = ldb_wrap_connect(tctx,
					   tctx->ev,
					   tctx->lp_ctx,
					   url,
					   NULL,
					   samba_cmdline_get_creds(),
					   0);

		torture_assert(tctx,
			       ldb_ctx,
			       "Connection to the SAMDB on DC failed!");
	}

	root_key_id = talloc_zero(tctx, struct GUID);
	if (root_key_id == NULL) {
		torture_fail(tctx, "Unable to create root_key_id.");
	}

	if (!get_current_time(&current_time)) {
		torture_fail(tctx, "Unable to get current time.");
	}

	if (!gkdi_get_key_start_time(gkdi_get_interval_id(current_time),
				     &key_start_time))
	{
		torture_fail(tctx, "Unable to create key start time.");
	}

	if (gkdi_most_recently_created_root_key(tctx,
						ldb_ctx,
						current_time,
						key_start_time,
						root_key_id,
						&root_key_msg) != LDB_SUCCESS)
	{
		torture_fail(tctx, "Most recent GKDI root key not found.");
	}

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(tctx,
				    p,
				    -1,
				    -1,
				    -1,
				    root_key_id,
				    security_descriptor,
				    &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(
			tctx,
			dcerpc_gkdi_GetKey_r(b, tctx, r),
			"Get Latest Group Key From Specific Root Key");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(
			tctx,
			dcerpc_gkdi_GetKey_r(b, tctx, r),
			NT_STATUS_CONNECTION_DISCONNECTED,
			"Get Latest Group Key From Specific Root Key");
	}

	return true;
}

/*
 * **Test Case GKDI-004 Specific Seed Key From Specific Root Key
 * Request**
 * - **Description**: When the pRootKeyID parameter is not equal to NULL
 * and the values of the L0KeyID, L1KeyID, and L2KeyID parameters are
 * all greater than -1, a specific seed key is being requested by the
 *                    caller.
 * - **Input Parameters**:
 *  - `pRootKeyID`: Valid GUID
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: Valid historical values (all >=
 * 0)
 *  - Valid security descriptor
 * - **Expected Result**: Returns seed key or public key from specified
 * root key
 */
static bool test_SpecificSeedKeyFromSpecificRootKey(
	struct torture_context *tctx,
	struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct GUID *root_key_id = NULL;
	const struct ldb_message *root_key_msg = NULL;
	NTTIME key_start_time = 0;
	NTTIME current_time = 0;
	struct ldb_context *ldb_ctx = NULL;
	char *url = NULL;
	struct Gkid interval_id;
	struct gkdi_GetKey *r = NULL;

	if (dcerpc_server_name(p)) {
		/* Set up connection to SAMDB on DC */
		url = talloc_asprintf(tctx, "ldap://%s", dcerpc_server_name(p));
		ldb_ctx = ldb_wrap_connect(tctx,
					   tctx->ev,
					   tctx->lp_ctx,
					   url,
					   NULL,
					   samba_cmdline_get_creds(),
					   0);

		torture_assert(tctx,
			       ldb_ctx,
			       "Connection to the SAMDB on DC failed!");
	}

	root_key_id = talloc_zero(tctx, struct GUID);
	if (root_key_id == NULL) {
		torture_fail(tctx, "Unable to create root_key_id.");
	}

	if (!get_current_time(&current_time)) {
		torture_fail(tctx, "Unable to get current time.");
	}

	interval_id = gkdi_get_interval_id(current_time);

	if (!gkdi_get_key_start_time(interval_id, &key_start_time)) {
		torture_fail(tctx, "Unable to create key start time.");
	}

	if (gkdi_most_recently_created_root_key(tctx,
						ldb_ctx,
						current_time,
						key_start_time,
						root_key_id,
						&root_key_msg) != LDB_SUCCESS)
	{
		torture_fail(tctx, "Most recent GKDI root key not found.");
	}

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(tctx,
				    p,
				    interval_id.l0_idx,
				    interval_id.l1_idx,
				    interval_id.l2_idx,
				    root_key_id,
				    security_descriptor,
				    &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(
			tctx,
			dcerpc_gkdi_GetKey_r(b, tctx, r),
			"Get Specific Seed Key From Specific Root Key");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(
			tctx,
			dcerpc_gkdi_GetKey_r(b, tctx, r),
			NT_STATUS_CONNECTION_DISCONNECTED,
			"Get Specific Seed Key From Specific Root Key");
	}

	return true;
}

/*
 * **Test Case GKDI-101: Seed Key Access Control**
 * - **Description**: Test access control for seed key retrieval (0x3 access
 * mask)
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Security descriptor granting read/write access
 * - **Expected Result**: Returns seed key when authorized
 */
static bool test_SeedKeyAccessControl(struct torture_context *tctx,
				      struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
	struct gkdi_GetKey *r;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct GroupKeyEnvelope *envelope = NULL;

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, -1, -1, NULL, security_descriptor, &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Get Latest Group Key");

		out_blob.data = *r->out.out;
		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");

		envelope = talloc_zero(tctx, struct GroupKeyEnvelope);
		torture_assert(tctx, envelope != NULL, "Envelope is NULL.");

		ndr_status = ndr_pull_struct_blob(
			&out_blob,
			tctx,
			envelope,
			(ndr_pull_flags_fn_t)ndr_pull_GroupKeyEnvelope);
		torture_assert_ndr_success(
			tctx, ndr_status, "Failed to unpack GroupKeyEnvelope.");

		torture_assert(tctx,
			       envelope->flags &
				       ENVELOPE_FLAG_KEY_MAY_ENCRYPT_NEW_DATA,
			       "Expected seed key, but did not get it.");

	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Get Latest Group Key");
	}

	return true;
}

/*
 * **Test Case GKDI-102: Public Key Access Control**
 * - **Description**: Test access control for public key retrieval (0x2 access
 * mask)
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Security descriptor granting write-only access
 * - **Expected Result**: Returns public key only, not seed keys
 */
static bool test_PublicKeyAccessControl(struct torture_context *tctx,
					struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum ndr_err_code ndr_status = NDR_ERR_SUCCESS;
	struct gkdi_GetKey *r;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct GroupKeyEnvelope *envelope = NULL;

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, -1, -1, NULL, security_descriptor, &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Public Key Access Control");

		out_blob.data = *r->out.out;
		out_blob.length = *r->out.out_len;
		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");

		envelope = talloc_zero(tctx, struct GroupKeyEnvelope);
		torture_assert(tctx, envelope != NULL, "Envelope is NULL.");

		ndr_status = ndr_pull_struct_blob(
			&out_blob,
			tctx,
			envelope,
			(ndr_pull_flags_fn_t)ndr_pull_GroupKeyEnvelope);
		torture_assert_ndr_success(
			tctx, ndr_status, "Failed to unpack GroupKeyEnvelope.");

		torture_assert(
			tctx,
			envelope->flags & ENVELOPE_FLAG_TRANSPORTING_PUBLIC_KEY,
			"Expected public group key, but did not get it.");

	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Public Key Access Control");
	}

	return true;
}

/*
 * **Test Case GKDI-103: Access Denied Scenario**
 * - **Description**: Test behavior when client lacks proper access rights
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Security descriptor with no relevant ACEs
 * - **Expected Result**: Returns ACCESS_DENIED error
 */
static bool test_KeyAccessDeniedScenario(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	struct gkdi_GetKey *r;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	if (!create_test_secutiry_descriptor(tctx, 0, &security_descriptor)) {
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, -1, -1, NULL, security_descriptor, &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Key Access Denied Scenario");

		torture_assert_hresult_ok(tctx,
					  r->out.result,
					  "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Key Access Denied Scenario");
	}

	return true;
}
/*
 * **Test Case GKDI-201: Invalid Security Descriptor**
 * - **Description**: Test response to malformed security descriptor
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Invalid or corrupted security descriptor data
 * - **Expected Result**: Returns INVALID_PARAMETER
 */
static bool test_InvalidSecurityDescriptor(struct torture_context *tctx,
					   struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	struct gkdi_GetKey *r;

	if (!create_invalid_secutiry_descriptor(tctx, &security_descriptor)) {
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, -1, -1, NULL, security_descriptor, &out_blob);
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Invalid Security Descriptor");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_equal(tctx,
					     r->out.result,
					     HRES_E_INVALIDARG,
					     "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_ACCESS_DENIED,
					      "Invalid Security Descriptor");
	}

	return true;
}

/*
 * **Test Case GKDI-202: Invalid Key ID Combinations**
 * - **Description**: Test various invalid key ID parameter combinations
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: Mixed -1 and positive values, negative
 * values > -1
 *  - Valid security descriptor
 * - **Expected Result**: Returns HRES_E_INVALIDARG
 */
static bool test_InvalidKeyIDCombinations(struct torture_context *tctx,
					  struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct gkdi_GetKey *r = NULL;

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(
		tctx, p, -1, 0, -1, NULL, security_descriptor, &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Invalid Key ID Combinations");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_equal(tctx,
					     r->out.result,
					     HRES_E_INVALIDARG,
					     "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Invalid Key ID Combinations");
	}

	return true;
}

/*
 * **Test Case GKDI-203: Future Key Request**
 * - **Description**: Test requesting key for future time period
 * - **Input Parameters**:
 *  - `pRootKeyID`: NULL
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: IDs lexically greater than current time
 * IDs
 *  - Valid security descriptor
 * - **Expected Result**: Returns HRES_E_INVALIDARG error
 */
static bool test_FutureKeyRequest(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	NTTIME current_time = 0;
	struct Gkid interval_id;
	struct gkdi_GetKey *r = NULL;

	if (!get_current_time(&current_time)) {
		torture_fail(tctx, "Unable to get current time.");
	}

	interval_id = gkdi_get_interval_id(current_time +
					   gkdi_key_cycle_duration);

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(tctx,
				    p,
				    interval_id.l0_idx,
				    interval_id.l1_idx,
				    interval_id.l2_idx,
				    NULL,
				    security_descriptor,
				    &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Future Key Request");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_equal(tctx,
					     r->out.result,
					     HRES_E_INVALIDARG,
					     "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Future Key Request");
	}

	return true;
}

/*
 * **Test Case GKDI-204: Non-existent Root Key**
 * - **Description**: Test request with non-existent root key ID
 * - **Input Parameters**:
 *  - `pRootKeyID`: Valid but non-existent root key GUID
 *  - `L0KeyID`, `L1KeyID`, `L2KeyID`: All -1
 *  - Valid security descriptor
 * - **Expected Result**: Returns HRES_NTE_NO_KEY error
 */
static bool test_NonExistentRootKey(struct torture_context *tctx,
				    struct dcerpc_pipe *p)
{
	struct dcerpc_binding_handle *b = p->binding_handle;
	DATA_BLOB out_blob;
	DATA_BLOB security_descriptor;
	struct GUID root_key_id;
	enum dcerpc_AuthType auth_type;
	enum dcerpc_AuthLevel auth_level;
	struct gkdi_GetKey *r = NULL;
	NTSTATUS status = NT_STATUS_SUCCESS;

	status = GUID_from_string("{00000000-0000-4000-8000-000000000000}",
				  &root_key_id);

	torture_assert_ntstatus_ok(tctx,
				   status,
				   "Unable to create root key GUID.");

	if (!create_test_secutiry_descriptor(tctx,
					     SEC_FILE_READ_DATA |
						     SEC_FILE_WRITE_DATA,
					     &security_descriptor))
	{
		return false;
	}

	r = createRetrieveKeyStruct(tctx,
				    p,
				    -1,
				    -1,
				    -1,
				    &root_key_id,
				    security_descriptor,
				    &out_blob);

	if (r == NULL) {
		return false;
	}

	dcerpc_binding_handle_auth_info(b, &auth_type, &auth_level);

	if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		torture_assert_ntstatus_ok(tctx,
					   dcerpc_gkdi_GetKey_r(b, tctx, r),
					   "Non-Existent Root Key");

		out_blob.length = *r->out.out_len;
		torture_assert_hresult_equal(tctx,
					     r->out.result,
					     HRES_NTE_NO_KEY,
					     "Wrong dce/rpc error code");
	} else {
		torture_assert_ntstatus_equal(tctx,
					      dcerpc_gkdi_GetKey_r(b, tctx, r),
					      NT_STATUS_CONNECTION_DISCONNECTED,
					      "Non-Existent Root Key");
	}

	return true;
}

struct torture_suite *torture_rpc_gkdi(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "gkdi");

	struct torture_rpc_tcase *tcase;

	/*
	 * Test processing rules for the GetKey request.
	 */
	tcase = torture_suite_add_rpc_iface_tcase(suite,
						  "gkdi",
						  &ndr_table_gkdi);

	torture_rpc_tcase_add_test(tcase,
				   "retrieve_latest_group_key",
				   test_RetrieveLatestGroupKey);

	torture_rpc_tcase_add_test(tcase,
				   "retrieve_specific_seed_key",
				   test_RetrieveSpecificSeedKey);

	torture_rpc_tcase_add_test(
		tcase,
		"retrieve_latest_group_key_from_specific_root_key",
		test_RetrieveLatestGroupKeyFromSpecificRootKey);

	torture_rpc_tcase_add_test(
		tcase,
		"retrieve_specific_seed_key_from_specific_root_key",
		test_SpecificSeedKeyFromSpecificRootKey);

	/*
	 * Test security and access control.
	 */
	torture_rpc_tcase_add_test(tcase,
				   "seed_key_access_control",
				   test_SeedKeyAccessControl);

	torture_rpc_tcase_add_test(tcase,
				   "public_key_access_control",
				   test_PublicKeyAccessControl);

	torture_rpc_tcase_add_test(tcase,
				   "key_access_denied_scenario",
				   test_KeyAccessDeniedScenario);

	/*
	 *  Error handling tests.
	 */
	torture_rpc_tcase_add_test(tcase,
				   "invalid_security_descriptor",
				   test_InvalidSecurityDescriptor);

	torture_rpc_tcase_add_test(tcase,
				   "invalid_key_id_combinations",
				   test_InvalidKeyIDCombinations);

	torture_rpc_tcase_add_test(tcase,
				   "future_key_request",
				   test_FutureKeyRequest);

	torture_rpc_tcase_add_test(tcase,
				   "non-existent_root_key",
				   test_NonExistentRootKey);

	return suite;
}
