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

#ifndef _ZVKNS_H
#define _ZVKNS_H

uint64_t
zvkns_aes128_encode_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const void* key128
);

uint64_t
zvkns_aes128_decode_rk_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const char key[16]
);

uint64_t
zvkns_aes256_encode_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const void* key256
);

uint64_t
zvkns_aes256_decode_rk_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const char key[32]
);

#endif	/* _ZVKNS_H */
