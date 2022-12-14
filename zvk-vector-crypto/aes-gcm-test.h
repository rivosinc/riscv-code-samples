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

#ifndef _AES_GCM_TESTS
#define _AES_GCM_TESTS

__attribute__((aligned(16)))
struct aes_gcm_test {
	uint8_t key[32];
	uint8_t *iv;
	uint8_t *ct;
	uint8_t *aad;
	uint8_t *tag;
	uint8_t *pt;
	int ivlen;
	int ctlen;
	int aadlen;
	int taglen;
	bool encrypt;
	bool expect_fail;
	uint8_t align[6];
};

struct aes_gcm_test_suite {
	struct aes_gcm_test *tests;
	const char *name;
	int keylen;
	int count;
};

#endif
