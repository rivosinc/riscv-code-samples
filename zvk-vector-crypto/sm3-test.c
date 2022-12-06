/*
 * Copyright 2022 Rivos Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <stdint.h>

#include "zvksh.h"
#include "sm3-test.h"
#include "test-vectors/sm3-test-vectors.h"

__attribute__((aligned(16)))
uint32_t buf[128] = {0};

/*
 * Pad input to block size, append delimiter and length.
 */
static size_t sm3_pad(uint8_t *output, const uint8_t *input, size_t len)
{
    uint32_t *ptr;
    uint64_t blen;
    size_t padding;

    blen = 8 * len;
    memcpy(output, input, len);
    output[len++] |= 0x80;

    /*
     * Calculate the padding size.
     * Message size is appended at the end of the last block,
     * take that into account.
     */
    padding = 64 - (len % 64);
    if (padding < sizeof(uint64_t))
	    padding += 64;

    bzero(output + len, padding);
    len += padding;

    ptr = (uint32_t *)(output + len - sizeof(uint64_t));

    *ptr = __bswap_32(blen >> 32);
    *(++ptr) = __bswap_32(blen & UINT32_MAX);

    return len;
}

static int run_sm3_test(struct sm3_test_vector *vector)
{
    size_t len;

    assert(vector->message_len + 128 < sizeof(buf));

    len = sm3_pad((uint8_t *)buf, (uint8_t *)vector->message, vector->message_len);
    zvksh_sm3_encode_vv(buf, buf, len);

    return memcmp(buf, vector->expected, sizeof(vector->expected));
}

int main()
{
    uint64_t result;
    struct sm3_test_vector *vector;
    size_t vector_count;

    vector_count = sizeof(sm3_test_vectors) / sizeof(sm3_test_vectors[0]);

    printf("Running SM3 test suite...");
    for (size_t i = 0; i < vector_count; ++i) {
        result = run_sm3_test(&sm3_test_vectors[i]);
        if (result) {
            printf("test %zu failed\n", i);
            exit(1);
        }
        memset(buf, 0, sizeof(buf));
    }

    printf("success, %zu tests were run.\n", vector_count);

    return 0;
}
