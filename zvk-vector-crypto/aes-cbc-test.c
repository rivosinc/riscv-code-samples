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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zvkns.h"
#include "aes-cbc-test.h"
/* This file is auto-generated by `make test-vectors` */
#include "test-vectors/aes-cbc-vectors.h"

__attribute__((aligned(16)))
uint8_t input_buf[256];

__attribute__((aligned(16)))
uint8_t output_buf[256];

static void
aes_encrypt_single(uint8_t *key, int keylen, uint8_t *in, uint8_t *out, bool encrypt)
{

	switch (keylen) {
	case 128:
		if (encrypt)
			zvkns_aes128_encode_vv(out, in, 16, key);
		else
			zvkns_aes128_decode_rk_vv(out, in, 16, key);
	break;
	case 256:
		if (encrypt)
			zvkns_aes256_encode_vv(out, in, 16, key);
		else
			zvkns_aes256_decode_rk_vv(out, in, 16, key);
	break;
	default:
		printf("Unsupported keylen: %d\n", keylen);
		exit(1);
	}
}

static int
run_test(struct aes_cbc_test *test, int keylen)
{
	uint8_t *in, *out;
	uint8_t *expected;
	uint8_t *iv;
	int len;

	len = test->plaintextlen;
	iv = test->iv;
	assert(len % 16 == 0);

	if (test->encrypt) {
		in = test->plaintext;
		expected = test->ciphertext;
	} else {
		in = test->ciphertext;
		expected = test->plaintext;
	}

	/*
	 * Copy the input, to leave the test data intact.
	 * In the future we might want to run a test case multiple times.
	 * For example we could use different LMUL, or vs/vv variant
	 * of an instruction.
	 */
	memcpy(input_buf, in, len);
	in = input_buf;
	out = output_buf;

	for (int i = 0; i < len / 16; i++) {
		if (test->encrypt) {
			for (int j = 0; j < 16; j++) {
				in[j] ^= iv[j];
			}
			iv = out;
		}

		aes_encrypt_single(test->key, keylen, in, out, test->encrypt);

		if (!test->encrypt) {
			for (int j = 0; j < 16; j++) {
				out[j] ^= iv[j];
			}
			iv = in;
		}
		in += 16;
		out += 16;
	}

	return memcmp(output_buf, expected, len);
}

int
main()
{
	int rc, n;
	struct aes_cbc_test *test;

	n = sizeof(cbc_suites) / sizeof(*cbc_suites);

	for (int i = 0; i < n; i++) {
		if (cbc_suites[i].keylen != 128 &&
		    cbc_suites[i].keylen != 256) {
			printf("Skipping test suite %s with unsupported keylen %d\n",
			    cbc_suites[i].name, cbc_suites[i].keylen);
			continue;
		}

		test = cbc_suites[i].tests;
		printf("Running %s test suite... ", cbc_suites[i].name);

		for (int j = 0; j < cbc_suites[i].count; j++, test++) {
			rc = run_test(test, cbc_suites[i].keylen);
			if (rc != 0) {
				printf("test %d failed\n", j);
				exit(1);
			}
		}

		printf("success, %d tests were run.\n", cbc_suites[i].count);
	}

	return 0;
}
