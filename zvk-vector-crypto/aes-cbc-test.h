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

#ifndef _AES_CBC_TESTS
#define _AES_CBC_TESTS

struct aes_cbc_test {
	uint8_t key[32];
	uint8_t iv[16];
	uint8_t *plaintext;
	uint8_t *ciphertext;
	int plaintextlen;
	bool encrypt;
	/* Everything needs to be aligned to 16 bytes. */
	char foo[15];
};

struct aes_cbc_test_suite {
	const char *name;
	int count;
	int keylen;
	struct aes_cbc_test *tests;
};

#endif
