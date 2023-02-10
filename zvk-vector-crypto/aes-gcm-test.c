// Copyright 2022 Rivos Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "vlen-bits.h"
#include "zvkb.h"
#include "zvkned.h"

#include "aes-gcm-test.h"
// 'aes-gcm-vectors.h' is auto-generated by `make test-vectors`
#include "test-vectors/aes-gcm-vectors.h"


// ----------------------------------------------------------------------
// Test Case 1 from
// <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>

__attribute__((aligned(16)))
static const uint8_t tc1Iv[12] = {
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
};

__attribute__((aligned(16)))
static const uint8_t tc1Tag[16] = {
    0x58,0xe2,0xfc,0xce,
    0xfa,0x7e,0x30,0x61,
    0x36,0x7f,0x1d,0x57,
    0xa4,0xe7,0x45,0x5a,
};

static const struct aes_gcm_test tc1Test =
{
    .key = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
    .iv = tc1Iv,
    .ivlen = 12,
    .pt = NULL,
    .ct = NULL,
    .ctlen = 0,
    .aad = NULL,
    .aadlen = 0,
    .tag = tc1Tag,
    .taglen = 16,
    .encrypt = true,
    .expect_fail = false
};

// ----------------------------------------------------------------------
// Test Case 2 from
//  <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>

__attribute__((aligned(16)))
static const uint8_t tc2Pt[16] = {
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
};

__attribute__((aligned(16)))
static const uint8_t tc2Iv[12] = {
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
};

__attribute__((aligned(16)))
static const uint8_t tc2Ct[16] = {
    0x03,0x88,0xda,0xce,
    0x60,0xb6,0xa3,0x92,
    0xf3,0x28,0xc2,0xb9,
    0x71,0xb2,0xfe,0x78,
};

__attribute__((aligned(16)))
static const uint8_t tc2Tag[16] = {
    0xab,0x6e,0x47,0xd4,
    0x2c,0xec,0x13,0xbd,
    0xf5,0x3a,0x67,0xb2,
    0x12,0x57,0xbd,0xdf,
};

static const struct aes_gcm_test tc2Test =
{
    .key = {0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,},
    .iv = tc2Iv,
    .ivlen = 12,
    .pt = tc2Pt,
    .ct = tc2Ct,
    .ctlen = 16,
    .aad = NULL,
    .aadlen = 0,
    .tag = tc2Tag,
    .taglen = 16,
    .encrypt = true,
    .expect_fail = false
};

// ----------------------------------------------------------------------
// Test Case 4 from
// <https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>

__attribute__((aligned(16)))
static const uint8_t tc4Pt[] = {
    0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,
    0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
    0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,
    0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
    0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,
    0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
    0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,
    0xba,0x63,0x7b,0x39,
};

__attribute__((aligned(16)))
static const uint8_t tc4Aad[] = {
    0xfe,0xed,0xfa,0xce,
    0xde,0xad,0xbe,0xef,
    0xfe,0xed,0xfa,0xce,
    0xde,0xad,0xbe,0xef,
    0xab,0xad,0xda,0xd2,
};

__attribute__((aligned(16)))
static const uint8_t tc4Iv[12] = {
    0xca,0xfe,0xba,0xbe,
    0xfa,0xce,0xdb,0xad,
    0xde,0xca,0xf8,0x88,
};

__attribute__((aligned(16)))
static const uint8_t tc4Ct[60] = {
    0x42,0x83,0x1e,0xc2,
    0x21,0x77,0x74,0x24,
    0x4b,0x72,0x21,0xb7,
    0x84,0xd0,0xd4,0x9c,
    0xe3,0xaa,0x21,0x2f,
    0x2c,0x02,0xa4,0xe0,
    0x35,0xc1,0x7e,0x23,
    0x29,0xac,0xa1,0x2e,
    0x21,0xd5,0x14,0xb2,
    0x54,0x66,0x93,0x1c,
    0x7d,0x8f,0x6a,0x5a,
    0xac,0x84,0xaa,0x05,
    0x1b,0xa3,0x0b,0x39,
    0x6a,0x0a,0xac,0x97,
    0x3d,0x58,0xe0,0x91,
};

__attribute__((aligned(16)))
static const uint8_t tc4Tag[16] = {
    0x5b,0xc9,0x4f,0xbc,
    0x32,0x21,0xa5,0xdb,
    0x94,0xfa,0xe9,0x5a,
    0xe7,0x12,0x1a,0x47
};

static const struct aes_gcm_test tc4Test =
{
    .key = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,
        0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    },
    .iv = tc4Iv,
    .ivlen = 12,
    .pt = tc4Pt,
    .ct = tc4Ct,
    .ctlen = 60,
    .aad = tc4Aad,
    .aadlen = 20,
    .tag = tc4Tag,
    .taglen = 16,
    .encrypt = true,
    .expect_fail = false
};

// ----------------------------------------------------------------------


#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef union uint128 {
    uint64_t dwords[2];
    uint32_t words[4];
    uint8_t bytes[16];
} uint128;


//
// Debugging/logging Helpers
//

// Enable to get debug logs.
#if 0
#define DLOG(...) LOG(__VA_ARGS__)
#else
#define DLOG(...) ((void)0)
#endif

//
// Common Routines
//

struct expanded_key {
    // 240 bytes for AES-256, less needed for AES-128.
    // Using uint32_t guarantees alignment.
    uint32_t expanded[60];
    //
    size_t keylen;
};

static void
expand_key(struct expanded_key* dest, const uint8_t* key, size_t keylen) {
    dest->keylen = keylen;
    switch (keylen) {
      case 128:
        // 128b -> 11*128b, 176B, 44 uin32_t
        zvkned_aes128_expand_key(dest->expanded, key);
        break;
      case 256:
        // 256b -> 15*128b, 240B, 60 uint32_t
        zvkned_aes256_expand_key(dest->expanded, key);
        break;
      default:
        LOG("Invalid keylen %zu", keylen);
        assert(false);
    }
}

static void
encrypt_block(
    void* out,
    const uint128* in,
    const struct expanded_key* key
)
{
    switch (key->keylen) {
      case 128:
        zvkned_aes128_encode_vs_lmul4(out, in, 16, key->expanded);
        break;
      case 256:
        zvkned_aes256_encode_vs_lmul4(out, in, 16, key->expanded);
        break;
      default:
        LOG("Invalid keylen %zu", key->keylen);
        assert(false);
    }
}

// H = CIPH_K({0}_128)
static uint128
compute_h(const struct expanded_key* key) {
    const uint128 zero = {};
    uint128 h = {};
    encrypt_block(&h, &zero, key);
    return h;
}

// Increment the counter in the counter block (CB)
static void
increment_counter_block(uint128* cb) {
    // The count is stored in the high word (last 4 bytes),
    // in big-endian format.
    const uint32_t counter = __builtin_bswap32(cb->words[3]);
    cb->words[3] = __builtin_bswap32(counter + 1);
}

//
// Zvkb Implementation
//
// This implementation is a proof of concept to show how GCM can be
// implemented in the absence of the Zvkg extension.

static void
ghash(uint128* Y, const uint128* X, uint128* H)
{
    zvkb_ghash(&Y->dwords[0], &H->dwords[0]);

    Y->dwords[0] ^= X->dwords[0];
    Y->dwords[1] ^= X->dwords[1];
}

static void
zvkb_prepare_icb(
    uint128* ICB,
    uint128* H,
    const uint8_t* iv,
    int ivlen
) {
    // Easy case.
    // ICB = IV | round_nr
    // round_nr starts with 1
    if (ivlen == 12) {
        memcpy(&ICB->words[0], iv, ivlen);
        ICB->words[3] = 0;
        ICB->bytes[15] = 1;
        return;
    }

    const uint64_t blen = 8 * ivlen;
    bzero(ICB, sizeof(*ICB));
    memcpy(ICB, iv, MIN(16, ivlen));
    iv += MIN(16, ivlen);
    ivlen -= MIN(16, ivlen);

    // First apply GHASH to full, 128 bit blocks of IV.
    while (ivlen >= 16) {
        ghash(ICB, (const uint128 *)iv, H);
        iv += 16;
        ivlen -= 16;
    }

    // For a tail block append zeroes and run GHASH.
    uint128 X = {};
    if (ivlen > 0) {
        bzero(&X, sizeof(X));
        memcpy(&X, iv, ivlen);
        ghash(ICB, &X, H);
    }

    X.dwords[0] = 0;
    X.dwords[1] = __builtin_bswap64(blen);
    ghash(ICB, &X, H);

    bzero(&X, sizeof(X));
    ghash(ICB, &X, H);
}

static int
run_test_zvkb(const struct aes_gcm_test* test, int keylen)
{
    __attribute__((aligned(16)))
    uint8_t buf[1024];

    assert(keylen == 128 || keylen == 256);

    struct expanded_key key;
    expand_key(&key, test->key, keylen);

    // H = ENC(0, K)
    uint128 H = compute_h(&key);
    zvkb_ghash_init(&H.dwords[0]);

    uint128 counter_block;
    zvkb_prepare_icb(&counter_block, &H, test->iv, test->ivlen);

    // Copy initial ICB, it'll later be used to construct
    // the authentication tag.
    // The actual ICB used in cipher needs to have the counter
    // incremented because of that.
    uint128 tag = counter_block;

    increment_counter_block(&counter_block);

    const uint8_t* xordata;
    if (test->encrypt) {
        xordata = test->pt;
    } else {
        xordata = test->ct;
    }

    uint128 temp = {}, Y = {};

    size_t aadlen = test->aadlen;
    const uint8_t* aad = test->aad;
    memcpy(&Y, aad, MIN(aadlen, 16));
    aad += MIN(aadlen, 16);
    aadlen -= MIN(aadlen, 16);


    while (aadlen >= 16) {
        ghash(&Y, (uint128 *)aad, &H);
        aad += 16;
        aadlen -= 16;
    }
    if (aadlen > 0) {
        bzero(&temp, sizeof(temp));
        memcpy(&temp, aad, aadlen);
        ghash(&Y, &temp, &H);
    }

    for (int i = 0; i < test->ctlen / 16; i++) {
        if (!test->encrypt)
            ghash(&Y, (uint128 *)(&xordata[16 * i]), &H);

        encrypt_block(&buf[16 * i], &counter_block, &key);
        for (int j = 0; j < 16; j++)
            buf[16 * i + j] ^= xordata[16 * i + j];

        if (test->encrypt)
            ghash(&Y, (uint128 *)(&buf[16 * i]), &H);

        increment_counter_block(&counter_block);
    }

    int rem = test->ctlen % 16;
    if (rem != 0) {
        if (!test->encrypt) {
            bzero(&temp, sizeof(temp));
            memcpy(&temp, &xordata[test->ctlen - rem], rem);
            ghash(&Y, &temp, &H);
        }

        // buf shall have enough space to fit the extra bytes.
        encrypt_block(&buf[test->ctlen - rem], &counter_block, &key);
        for (int i = 0; i < rem; i++)
            buf[test->ctlen - rem + i] ^= xordata[test->ctlen - rem + i];

        if (test->encrypt) {
            bzero(&temp, sizeof(temp));
            memcpy(&temp, &buf[test->ctlen - rem], rem);
            ghash(&Y, &temp, &H);
        }
    }

    temp.dwords[0] = __builtin_bswap64(8 * test->aadlen);
    temp.dwords[1] = __builtin_bswap64(8 * test->ctlen);
    ghash(&Y, &temp, &H);

    bzero(&temp, sizeof(temp));
    ghash(&Y, &temp, &H);

    // Prepare auth tag.
    encrypt_block(&tag.bytes[0], &tag, &key);
    tag.dwords[0] ^= Y.dwords[0];
    tag.dwords[1] ^= Y.dwords[1];

    assert(test->taglen <= sizeof(tag));
    int rc = memcmp(&tag, test->tag, test->taglen);
    rc = (!!rc) != test->expect_fail;
    if (rc != 0) {
        printf("\nTag mismatch\n");
        printf("\noutput:   0x");
        for (int i = 0; i < test->taglen; i++) {
            printf("%02x", tag.bytes[i]);
        }
        printf("\nexpected: 0x");
        for (int i = 0; i < test->taglen; i++) {
            printf("%02x", test->tag[i]);
        }
        printf("\n");
        return rc;
    }

    if (test->pt == NULL) {
        return 0;
    }

    if (test->encrypt) {
        rc = memcmp(buf, test->ct, test->ctlen);
    } else {
        rc = memcmp(buf, test->pt, test->ctlen);
    }
    if (rc == 0) {
        return 0;
    }

    printf("\nText mismatch");
    printf("\ninput:    0x");
    for (int i = 0; i < test->ctlen; i++) {
        if (test->encrypt) {
            printf("%02x", test->pt[i]);
        } else {
            printf("%02x", test->ct[i]);
        }
    }
    printf("\noutput:   0x");
    for (int i = 0; i < test->ctlen; i++) {
        printf("%02x", buf[i]);
    }
    printf("\nexpected: 0x");
    for (int i = 0; i < test->ctlen; i++) {
        if (test->encrypt) {
            printf("%02x", test->ct[i]);
        } else {
            printf("%02x", test->pt[i]);
        }
    }
    printf("\n");

    return rc;
}

// ----------------------------------------------------------------------

static void
run_testcase(
    const char* name,
    size_t test_idx,
    const struct aes_gcm_test* test,
    size_t keylen
) {
    {
        LOG("--- Running %s (#%zu) test against Zvkb... ", name, test_idx);
        const int rc = run_test_zvkb(test, keylen);
        if (rc != 0) {
            printf("Test '%s' (#%zu) failed (%d)\n", name, test_idx, rc);
            exit(1);
        }
        DLOG("Success");
    }
}

int
main()
{
    assert(sizeof(struct aes_gcm_test) % 16 == 0);

    const uint64_t vlen = vlen_bits();
    LOG("VLEN = %" PRIu64, vlen);

    // Some simple test cases with documented intermediate values.
    run_testcase("Test Case 1", 0, &tc1Test, 128);
    run_testcase("Test Case 2", 0, &tc2Test, 128);
    run_testcase("Test Case 4", 0, &tc4Test, 128);

    // Test suites
    const size_t num_suites = sizeof(gcm_suites) / sizeof(*gcm_suites);
    for (size_t suite_idx = 0; suite_idx < num_suites; suite_idx++) {
        const struct aes_gcm_test_suite* const suite = &gcm_suites[suite_idx];
        if (suite->keylen != 128 && suite->keylen != 256) {
            LOG("Skipping test suite '%s' with unsupported keylen %zu",
                suite->name, suite->keylen);
            continue;
        }

        LOG("------ Running '%s' test suite (%zu tests)... ",
             suite->name, suite->count);
        for (size_t test_idx = 0; test_idx < suite->count; test_idx++) {
            const struct aes_gcm_test* test = &suite->tests[test_idx];
            run_testcase(suite->name, test_idx, test, suite->keylen);
        }
        LOG("Success, '%s' test suite, %zu tests run.",
            suite->name, suite->count);
    }
    return 0;
}
