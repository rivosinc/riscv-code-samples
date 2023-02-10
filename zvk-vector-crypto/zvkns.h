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

#ifndef ZVKNS_H_
#define ZVKNS_H_

#include <stdint.h>

extern uint64_t
zvkns_aes128_encode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint8_t* key128
);

extern uint64_t
zvkns_aes128_decode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint8_t* key128
);

extern uint64_t
zvkns_aes256_encode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint8_t* key256
);

extern uint64_t
zvkns_aes256_decode_vv_lmul1(
   void* dest,
   const void* src,
   uint64_t n,
   const uint8_t* key256
);

#endif  // ZVKNS_H_
