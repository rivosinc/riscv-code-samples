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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zvknh.h"
#include "sha-test.h"
#include "test-vectors/sha256-vectors.h"
#include "test-vectors/sha512-vectors.h"

typedef void (*block_t)(uint8_t* hash, const void* block, const void* round_constants);

struct sha_param {
    int digest_size;
    int block_size;
    int size_field_len;
    const void* initial_hash;
    int initial_hash_size;
    const void* round_constants;
    block_t block;
};

struct sha_param sha256_param = {
    .digest_size = SHA256_DIGEST_SIZE,
    .block_size = SHA256_BLOCK_SIZE,
    .size_field_len = sizeof(uint64_t),
    .initial_hash = kSha256InitialHash,
    .initial_hash_size = sizeof(kSha256InitialHash),
    .round_constants = kSha256RoundConstants,
    .block = sha256_block
};

struct sha_param sha512_param = {
    .digest_size = SHA512_DIGEST_SIZE,
    .block_size = SHA512_BLOCK_SIZE,
    .size_field_len = 16,    // sizeof(uint128_t)
    .initial_hash = kSha512InitialHash,
    .initial_hash_size = sizeof(kSha512InitialHash),
    .round_constants = kSha512RoundConstants,
    .block = sha512_block
};

uint8_t hash[SHA512_DIGEST_SIZE];
uint8_t buf[2 * SHA512_BLOCK_SIZE];

static void
final_bswap_32(uint32_t* hash)
{
    const uint32_t f = __builtin_bswap32(hash[0]);
    const uint32_t e = __builtin_bswap32(hash[1]);
    const uint32_t b = __builtin_bswap32(hash[2]);
    const uint32_t a = __builtin_bswap32(hash[3]);

    const uint32_t h = __builtin_bswap32(hash[4]);
    const uint32_t g = __builtin_bswap32(hash[5]);
    const uint32_t d = __builtin_bswap32(hash[6]);
    const uint32_t c = __builtin_bswap32(hash[7]);

    hash[0] = a;
    hash[1] = b;
    hash[2] = c;
    hash[3] = d;

    hash[4] = e;
    hash[5] = f;
    hash[6] = g;
    hash[7] = h;
}

static void
final_bswap_64(uint64_t* hash)
{
    const uint64_t f = __builtin_bswap64(hash[0]);
    const uint64_t e = __builtin_bswap64(hash[1]);
    const uint64_t b = __builtin_bswap64(hash[2]);
    const uint64_t a = __builtin_bswap64(hash[3]);

    const uint64_t h = __builtin_bswap64(hash[4]);
    const uint64_t g = __builtin_bswap64(hash[5]);
    const uint64_t d = __builtin_bswap64(hash[6]);
    const uint64_t c = __builtin_bswap64(hash[7]);

    hash[0] = a;
    hash[1] = b;
    hash[2] = c;
    hash[3] = d;

    hash[4] = e;
    hash[5] = f;
    hash[6] = g;
    hash[7] = h;
}

static int
run_test(const struct sha_test* test, const struct sha_param* param)
{
    int len = test->msglen;
    const uint8_t* block = test->msg;

    memcpy(hash, param->initial_hash, param->initial_hash_size);

    while (len >= param->block_size) {
        param->block(hash, block, param->round_constants);
        block += param->block_size;
        len -= param->block_size;
    }

    // Handle partial last block.
    memcpy(buf, block, len);
    // Add delimiter.
    buf[len++] = 0x80;
    // Calculate padding size.
    int padding = param->block_size - len;
    // Can we fit message length into padding?
    if (padding < param->size_field_len)
        padding += param->block_size;

    padding -= param->size_field_len;
    bzero(&buf[len], padding);
    len += padding;

    uint64_t* ptr = (uint64_t *)&buf[len];
    switch (param->size_field_len) {
      case 8:
        *ptr = __builtin_bswap64(8 * test->msglen);
        break;
      case 16:
        // Message length of a test is stored in an int, so it will
        // always fit into 64 bits.
        *ptr = 0;
        ptr++;
        *ptr = __builtin_bswap64(8 * test->msglen);
        break;
      default:
        assert(false);
    };

    param->block(hash, buf, param->round_constants);
    if (len > param->block_size) {
        param->block(hash, buf + param->block_size, param->round_constants);
    }

    // Following the last block, convert from the "native" representation
    // of 'H' to the NIST order/endianness.
    switch (param->size_field_len) {
      case 8:
        final_bswap_32((uint32_t*)hash);
        break;
      case 16:
        final_bswap_64((uint64_t*)hash);
        break;
      default:
        assert(false);
    };

    return memcmp(test->md, hash, param->digest_size);
}

int
main()
{
    int n = sizeof(sha256_suites) / sizeof(*sha256_suites);

    for (int i = 0; i < n; i++) {
        const struct sha_test* test = sha256_suites[i].tests;
        printf("Running %s test suite... ", sha256_suites[i].name);

        for (int j = 0; j < sha256_suites[i].count; j++, test++) {
            int rc = run_test(test, &sha256_param);
            if (rc != 0) {
                printf("test %d failed\n", j);
                exit(1);
            }
        }

        printf("success, %d tests were run.\n", sha256_suites[i].count);
    }

    n = sizeof(sha512_suites) / sizeof(*sha512_suites);

    for (int i = 0; i < n; i++) {
        const struct sha_test* test = sha512_suites[i].tests;
        printf("Running %s test suite... ", sha512_suites[i].name);

        for (int j = 0; j < sha512_suites[i].count; j++, test++) {
            int rc = run_test(test, &sha512_param);
            if (rc != 0) {
                printf("test %d failed\n", j);
                exit(1);
            }
        }

        printf("success, %d tests were run.\n", sha512_suites[i].count);
    }

    return 0;
}
