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

#ifndef _SHA256_TESTS
#define _SHA256_TESTS

struct sha_test {
	uint8_t md[64];
	uint8_t *msg;
	int msglen;
	uint8_t align[4];
};

#define sha256_test sha_test
#define sha512_test sha_test

struct sha_test_suite {
	struct sha_test *tests;
	const char *name;
	int keylen;
	int count;
};

#define sha256_test_suite sha_test_suite
#define sha512_test_suite sha_test_suite

#endif
