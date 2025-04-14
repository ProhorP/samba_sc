/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Catalyst.Net Ltd 2023
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "replace.h"
#include <talloc.h>
#include "libcli/util/ntstatus.h"
#include "lib/crypto/gkdi.h"

#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/gkdi.h"
#include "librpc/gen_ndr/ndr_gkdi.h"

static const uint8_t ffc_dh_parameters[] = {
    12,  2,	  0,   0,   68,	 72,  80,  77,	0,   1,	  0,   0,   135, 168,
    230, 29,  180, 182, 102, 60,  255, 187, 209, 156, 101, 25,  89,	 153,
    140, 238, 246, 8,   102, 13,  208, 242, 93,  44,  238, 212, 67,	 94,
    59,  0,	  224, 13,  248, 241, 214, 25,	87,  212, 250, 247, 223, 69,
    97,  178, 170, 48,  22,	 195, 217, 17,	52,  9,	  111, 170, 59,	 244,
    41,  109, 131, 14,  154, 124, 32,  158, 12,  100, 151, 81,  122, 189,
    90,  138, 157, 48,  107, 207, 103, 237, 145, 249, 230, 114, 91,	 71,
    88,  192, 34,  224, 177, 239, 66,  117, 191, 123, 108, 91,  252, 17,
    212, 95,  144, 136, 185, 65,  245, 78,	177, 229, 155, 184, 188, 57,
    160, 191, 18,  48,  127, 92,  79,  219, 112, 197, 129, 178, 63,	 118,
    182, 58,  202, 225, 202, 166, 183, 144, 45,  82,  82,  103, 53,	 72,
    138, 14,  241, 60,  109, 154, 81,  191, 164, 171, 58,  216, 52,	 119,
    150, 82,  77,  142, 246, 161, 103, 181, 164, 24,  37,  217, 103, 225,
    68,  229, 20,  5,   100, 37,  28,  202, 203, 131, 230, 180, 134, 246,
    179, 202, 63,  121, 113, 80,  96,  38,	192, 184, 87,  246, 137, 150,
    40,  86,  222, 212, 1,	 10,  189, 11,	230, 33,  195, 163, 150, 10,
    84,  231, 16,  195, 117, 242, 99,  117, 215, 1,	  65,  3,   164, 181,
    67,  48,  193, 152, 175, 18,  97,  22,	210, 39,  110, 17,  113, 95,
    105, 56,  119, 250, 215, 239, 9,   202, 219, 9,	  74,  233, 30,	 26,
    21,  151, 63,  179, 44,	 155, 115, 19,	77,  11,  46,  119, 80,	 102,
    96,  237, 189, 72,  76,	 167, 177, 143, 33,  239, 32,  84,  7,	 244,
    121, 58,  26,  11,  161, 37,  16,  219, 193, 80,  119, 190, 70,	 63,
    255, 79,  237, 74,  172, 11,  181, 85,	190, 58,  108, 27,  12,	 107,
    71,  177, 188, 55,  115, 191, 126, 140, 111, 98,  144, 18,  40,	 248,
    194, 140, 187, 24,  165, 90,  227, 19,	65,  0,	  10,  101, 1,	 150,
    249, 49,  199, 122, 87,	 242, 221, 244, 99,  229, 233, 236, 20,	 75,
    119, 125, 230, 42,  170, 184, 168, 98,	138, 195, 118, 210, 130, 214,
    237, 56,  100, 230, 121, 130, 66,  142, 188, 131, 29,  20,  52,	 143,
    111, 47,  145, 147, 181, 4,   90,  242, 118, 113, 100, 225, 223, 201,
    103, 193, 251, 63,  46,	 85,  164, 189, 27,  255, 232, 59,  156, 128,
    208, 82,  185, 133, 209, 130, 234, 10,	219, 42,  59,  115, 19,	 211,
    254, 20,  200, 72,  75,	 30,  5,   37,	136, 185, 183, 210, 187, 210,
    223, 1,	  97,  153, 236, 208, 110, 21,	87,  205, 9,   21,  179, 53,
    59,  187, 100, 224, 236, 55,  127, 208, 40,  55,  13,  249, 43,	 82,
    199, 137, 20,  40,  205, 198, 126, 182, 24,  75,  82,  61,  29,	 178,
    70,  195, 47,  99,  7,	 132, 144, 240, 14,  248, 214, 71,  209, 72,
    212, 121, 84,  81,  94,	 35,  39,  207, 239, 152, 197, 130, 102, 75,
    76,  15,  108, 196, 22,	 89};
static const DATA_BLOB ffc_dh_parameters_blob =
    {discard_const_p(uint8_t, ffc_dh_parameters), sizeof ffc_dh_parameters};

#define GKID(l0_idx_, l1_idx_, l2_idx_) \
	((struct Gkid){.l0_idx = l0_idx_, .l1_idx = l1_idx_, .l2_idx = l2_idx_})

#define GUID_LITERAL(                                                 \
	time_low_, time_mid_, time_hi_and_version_, clock_seq_, node_)    \
	((struct GUID){.time_low = (0x##time_low_),                       \
               .time_mid = (0x##time_mid_),                           \
               .time_hi_and_version = (0x##time_hi_and_version_),     \
               .clock_seq = {(uint32_t)(0x##clock_seq_) >> 8,         \
                     (uint8_t)(0x##clock_seq_)},                      \
               .node = {(uint64_t)(0x##node_) >> 40,                  \
                (uint8_t)((uint64_t)(0x##node_) >> 32),               \
                (uint8_t)((uint64_t)(0x##node_) >> 24),               \
                (uint8_t)((uint64_t)(0x##node_) >> 16),               \
                (uint8_t)((uint64_t)(0x##node_) >> 8),                \
				(uint8_t)(0x##node_)}})

struct test_vector {
	const char *name; /* The name of the test scenario. */
	struct Gkid gkid; /* The GKID of the key to derive. */
	struct ProvRootKey root_key;
    uint8_t seed_key [GKDI_KEY_LEN]; /* The seed key. */
	NTSTATUS expected_status;
	uint8_t expected_key[GKDI_KEY_LEN]; /* The expected derived key. */
};

#define DATA_BLOB_CONST(data_, length_)                         \
	((DATA_BLOB){.data = (discard_const_p(uint8_t, data_)), \
		     .length = (length_)})

#define ARRAY(...) ((const uint8_t[]){__VA_ARGS__})
#define ROOT_KEY_DATA(...) \
	DATA_BLOB_CONST(ARRAY(__VA_ARGS__), sizeof(ARRAY(__VA_ARGS__)))
#define SEED_KEY(...) {__VA_ARGS__}
#define EXPECTED_KEY(...) {__VA_ARGS__}
#define ROOT_KEY_VERSION(version) (version)

#define ARBITRARY_ROOT_KEY_DATA                                            \
    ROOT_KEY_DATA(72,  159, 53,  49,  197, 55,  119, 77,  67,  45,	107, \
              151, 227, 188, 31,  67,  210, 232, 198, 220, 23,	235,     \
              14,  79,	217, 160, 135, 13,  47,	 30,  191, 146, 226,      \
              73,  102, 104, 168, 181, 189, 17,	 174, 162, 211, 45,       \
              10,  171, 113, 111, 72,  254, 86,	 159, 92,  155, 80,       \
		      255, 63,	155, 245, 222, 174, 165, 114, 251)

#define ARBITRARY_GUID GUID_LITERAL(4cdf4285, c46a, 62a3, 2f7d, 95f97342685b)

#define SUCCESS_VECTOR(                                               \
	name_, root_key_id, algorithm, gkid_, seed_key_, private_key_len_, expected_key_) \
    {                                                                 \
        .name = (name_), .gkid = (gkid_),                             \
		.root_key = {.version = root_key_version_1,                   \
                 .id = (root_key_id),                                 \
                 .data = ARBITRARY_ROOT_KEY_DATA,                     \
                 .kdf_algorithm =                                     \
                     {.id = KDF_ALGORITHM_SP800_108_CTR_HMAC,         \
                      .param.sp800_108 = (algorithm)},                \
                 .secret_agreement_algorithm =                        \
                     {.id = SECRET_AGREEMENT_ALGORITHM_DH,            \
                      .param.dh_parameters =                          \
                          NULL},                                      \
                  .public_key_length = 2048,                          \
                  .private_key_length = 512},                         \
        .seed_key = seed_key_,                                        \
		.expected_status = NT_STATUS_OK,                              \
		.expected_key = expected_key_,                                \
	}

#define FAILURE_VECTOR(                                               \
	name_, root_key_id, algorithm, gkid_, seed_key_, private_key_len_, expected_status_) \
    {                                                                 \
        .name = (name_), .gkid = (gkid_),                             \
		.root_key = {.version = root_key_version_1,                   \
                 .id = (root_key_id),                                 \
                 .data = ARBITRARY_ROOT_KEY_DATA,                     \
                 .kdf_algorithm =                                     \
                     {.id = KDF_ALGORITHM_SP800_108_CTR_HMAC,         \
                      .param.sp800_108 = (algorithm)},                \
                 .secret_agreement_algorithm =                        \
                     {.id = SECRET_AGREEMENT_ALGORITHM_DH,            \
                      .param.dh_parameters = NULL }},                 \
        .seed_key = seed_key_,                                        \
		.expected_status = (expected_status_), .expected_key = {},    \
	}

/* Test vectors derived from samba.tests.krb5.gkdi_tests Python tests. */
static struct test_vector gkdi_vectors[] = {
    SUCCESS_VECTOR(
        "samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha512 (L2)",
        GUID_LITERAL(1a3d6c30, aa81, cb7f, d3fe, 80775d135dfe),
        KDF_PARAM_SHA512,
        GKID(321, 0, 12),
        SEED_KEY(187, 189, 147, 118, 205, 22,  194, 71, 237, 64,
                 245, 145, 45,  25,	 8,   33,  140, 8,  240, 145,
                 91,  174, 2,   254, 2,   203, 251, 55, 83,	 189,
                 228, 6,   249, 197, 83,  172, 217, 81, 67,	 207,
                 99,  144, 106, 4,	 64,  227, 207, 35, 125, 35,
                 53,  174, 78,  75,	 156, 210, 217, 70, 167, 19,
                 81,  235, 203, 123),
        256,
        EXPECTED_KEY(0x57, 0xF2, 0xAD, 0xB3, 0xDE, 0x75, 0xF1, 0xC6,
                     0x09, 0x9B, 0x03, 0xF6, 0xE6, 0xD8, 0x6E, 0xC1,
                     0xD4, 0xB9, 0xB9, 0x7F, 0x5C, 0x54, 0x4D, 0x7B,
                     0x07, 0x3F, 0x3E, 0x3B, 0xE0, 0xBF, 0xC5, 0x5A,
                     0xBA, 0xE8, 0xE5, 0xAD, 0x73, 0x5A, 0xD8, 0x98,
                     0x1B, 0x2A, 0xB6, 0xF5, 0x30, 0x75, 0x31, 0x4A,
                     0xD7, 0xD7, 0x7C, 0x8B, 0x6A, 0x2A, 0x5B, 0x72,
                     0xDB, 0xBD, 0x84, 0xEA, 0x8D, 0xCE, 0xC9, 0xC7)),
    SUCCESS_VECTOR(
        "samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha1 (L2)",
        GUID_LITERAL(970abad6, fe55, 073a, caf1, b801d3f26bd3),
        KDF_PARAM_SHA1,
        GKID(1, 2, 3),
        SEED_KEY(63,  251, 130, 90,	 218, 241, 22,	182, 83,  50,
                 7,	  213, 104, 163, 14,  211, 211, 242, 28,  104,
                 132, 9,   65,  201, 69,  102, 132, 249, 175, 161,
                 27,  5,   110, 12,	 89,  57,  27,	77,  136, 196,
                 149, 217, 132, 195, 214, 128, 2,	156, 197, 197,
                 148, 99,  15,  52,	 23,  145, 25,	193, 197, 172,
                 170, 229, 233, 14),
        256,
        EXPECTED_KEY(0x09, 0x88, 0x32, 0xFC, 0xC8, 0xB3, 0x7C, 0xD8,
                     0x4B, 0xD6, 0x4F, 0xC5, 0x52, 0x6C, 0x97, 0x23,
                     0x74, 0x31, 0x49, 0xC9, 0x48, 0x85, 0x37, 0x1B,
                     0x12, 0xC0, 0xB0, 0xDF, 0xF6, 0xD6, 0x3E, 0x99,
                     0xCA, 0x84, 0x66, 0xE5, 0xF6, 0x20, 0xAB, 0x0C,
                     0xD7, 0xA4, 0x83, 0x81, 0x88, 0x96, 0xE9, 0x99,
                     0x60, 0x9C, 0xFD, 0x4E, 0xFD, 0xC7, 0x00, 0x5E,
                     0x33, 0x8B, 0xB5, 0x04, 0xA5, 0x58, 0xF8, 0x74)),
    SUCCESS_VECTOR(
        "samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha256 (L2)",
        GUID_LITERAL(45e26207, ed33, dcd5, 925a, 518a0deef69e),
        KDF_PARAM_SHA256,
        GKID(222, 22, 22),
        SEED_KEY(117, 42,  8,   121, 174, 36,  36,	192, 80,  76,
                 116, 147, 89,  159, 19,  229, 136, 225, 187, 220,
                 37,  47,  131, 50,	 90,  213, 177, 251, 145, 194,
                 76,  137, 1,   212, 64,  243, 255, 159, 251, 165,
                 159, 205, 101, 187, 151, 87,  50,	217, 243, 131,
                 221, 80,  184, 152, 23,  75,  185, 57,  62,  56,
                 61,  37,  213, 64),
        256,
        EXPECTED_KEY(0x58, 0xDE, 0xF9, 0xBA, 0x31, 0xE2, 0x70, 0x4F,
                     0x65, 0xF6, 0x72, 0xC2, 0xAC, 0x79, 0xFF, 0xFE,
                     0x97, 0xD4, 0xF9, 0x06, 0x9D, 0xA9, 0x3D, 0x05,
                     0xDE, 0x41, 0x78, 0x63, 0x5C, 0xAB, 0x78, 0x45,
                     0x76, 0x96, 0x06, 0x37, 0x89, 0x31, 0x42, 0x84,
                     0xFC, 0xD3, 0x92, 0xDC, 0x33, 0x92, 0xE7, 0xF5,
                     0xB0, 0x30, 0xBB, 0x38, 0xBD, 0x86, 0x2A, 0xEF,
                     0x0C, 0x28, 0x3D, 0x06, 0x0D, 0xB4, 0x65, 0xD3)),
    SUCCESS_VECTOR(
        "samba.tests.krb5.gkdi_tests.GkdiSelfTests.test_sha384 (L2)",
        GUID_LITERAL(66e6d9f7, 4924, f3fc, fe34, 605634d42ebd),
        KDF_PARAM_SHA384,
        GKID(287, 28, 27),
        SEED_KEY(236, 28,  101, 99,	 75,  86,  148, 129, 142, 29,
                 52,  29,  169, 153, 109, 184, 242, 161, 239, 106,
                 44,  119, 106, 113, 38,  167, 235, 209, 139, 55,
                 160, 115, 175, 218, 196, 76,  65,	177, 103, 177,
                 78,  75,  135, 45,	 72,  91,  187, 109, 123, 112,
                 150, 66,  21,  208, 232, 74,  47,	241, 66,  169,
                 217, 67,  242, 5),
        256,
        EXPECTED_KEY(0x5B, 0x36, 0x44, 0xA5, 0x0F, 0xEB, 0xF5, 0x6D,
                     0xE4, 0x6E, 0x1F, 0xAB, 0x02, 0x27, 0xB4, 0xDA,
                     0xD6, 0x1C, 0x13, 0x4A, 0x65, 0xB7, 0xC4, 0x7D,
                     0xE1, 0x1E, 0x04, 0x21, 0x6A, 0x3B, 0xA5, 0xE5,
                     0xBB, 0xA3, 0xC0, 0x9A, 0x9D, 0xB6, 0xF7, 0x57,
                     0x75, 0xF5, 0x4B, 0x9F, 0x03, 0x74, 0x76, 0x05,
                     0x40, 0x52, 0x91, 0xB4, 0x58, 0x9A, 0xB5, 0x43,
                     0x25, 0x88, 0x42, 0x85, 0xD5, 0x6F, 0xC4, 0x2B)),
    FAILURE_VECTOR("unsupported algorithm (−1)",
               ARBITRARY_GUID,
               -1 /* an unsupported algorithm */,
               GKID(0, 0, 0),
               SEED_KEY(0),
               0,
               NT_STATUS_NOT_SUPPORTED),
};

static struct FfcDhParameters *unpack_ffc_parameters(TALLOC_CTX *mem_ctx)
{
    struct FfcDhParameters *params = talloc_zero(mem_ctx,
                             struct FfcDhParameters);

    ndr_pull_struct_blob(&ffc_dh_parameters_blob,
                 mem_ctx,
                 params,
                 (ndr_pull_flags_fn_t)ndr_pull_FfcDhParameters);

    return params;
}

static void test_gkdi_private_key_derivation(void **state)
{
	TALLOC_CTX *mem_ctx = NULL;
	size_t n;

	mem_ctx = talloc_new(NULL);
	assert_non_null(mem_ctx);

	for (n = 0; n < ARRAY_SIZE(gkdi_vectors); ++n) {
		const struct test_vector *test_vector = &gkdi_vectors[n];
        uint8_t seed_key[GKDI_KEY_LEN];
        memcpy(seed_key, test_vector->seed_key, GKDI_KEY_LEN);
		DATA_BLOB out = {};
        NTSTATUS status;
        print_message("Running: %s\n", test_vector->name);

        out.data = talloc_zero_array(mem_ctx, uint8_t, GKDI_KEY_LEN);
        assert_non_null(out.data);

        gkdi_vectors[n]
            .root_key.secret_agreement_algorithm.param
            .dh_parameters = unpack_ffc_parameters(mem_ctx);

		status = compute_group_private_key(
			mem_ctx,
			&test_vector->root_key,
            seed_key,
			&out);
		assert_int_equal(NT_STATUS_V(test_vector->expected_status),
				 NT_STATUS_V(status));
		
		if (NT_STATUS_IS_OK(status)) {
			assert_memory_equal(test_vector->expected_key,
				    out.data,
				    GKDI_KEY_LEN);
		}
		
		data_blob_free(&out);
	}

	talloc_free(mem_ctx);
}

int main(int argc, char *argv[])
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_gkdi_private_key_derivation),
	};

	if (argc == 2) {
		cmocka_set_test_filter(argv[1]);
	}
	cmocka_set_message_output(CM_OUTPUT_SUBUNIT);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
