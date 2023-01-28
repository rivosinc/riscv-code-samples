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

#ifndef AES_GCM_TESTS_H_
#define AES_GCM_TESTS_H_

#include <stdint.h>

struct aes_gcm_test {
    uint8_t key[32];
    const uint8_t* iv;
    const uint8_t* ct;
    const uint8_t* aad;
    const uint8_t* tag;
    const uint8_t* pt;
    int ivlen;
    int ctlen;
    int aadlen;
    int taglen;
    bool encrypt;
    bool expect_fail;
    // Ensure alignment of the key in a well-aligned array.
    uint8_t padding[6];
};

struct aes_gcm_test_suite {
    const struct aes_gcm_test* tests;
    const char* name;
    int keylen;
    int count;
};

#endif  // AES_GCM_TESTS_H_
