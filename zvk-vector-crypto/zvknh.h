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

#ifndef _ZVKNH_H
#define _ZVKNH_H

#define sha256_digest_size 32
#define sha256_block_size 64
#define sha256_rounds 64

/* We do not need to byteswap those values as they are "native"
 * values. The hash and text bytes are interpreted as big-endian
 * when converting bytes<->words, so getting words requires
 * byteswapping in little-endian orders. This is not the case
 * for those words, which are in memory in the native (big) endianness.
 */
static const uint32_t kSha256RoundConstants[sha256_rounds] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  /* 0-3 */
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,  /* 4-7 */
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2   /* 60-63 */
};

/* We arrange the initial hash value to remove the need for byte-swapping
 * and re-arranging in the SHA logic.
 * The logic wants H0 (a), ... H7 (h) in the following order (listed
 * from most significant to least significant in each group of 4 32b values):
 *  {a,b,e,f} {h,g,d,c}
 *
 * So we want the constant array content arranged as:
 *   kHash[0] = f
 *   kHash[1] = e
 *   kHash[2] = b
 *   kHash[3] = a
 *
 *   kHash[4] = h
 *   kHash[5] = g
 *   kHash[6] = d
 *   kHash[7] = c
 *
 * Each constant is stored in the platform endianess, i.e., little endian.
 * The final hash value (updated values of a...h) needs to be byteswapped
 * (to big endian) and reordered to match the expected bit stream of SHA-2.
 */
static const uint32_t kSha256InitialHash[8] = {
    0x9b05688c,  /* [0]: H5 = f */
    0x510e527f,  /* [1]: H4 = e */
    0xbb67ae85,  /* [2]: H1 = b */
    0x6a09e667,  /* [3]: H0 = a */

    0x5be0cd19,  /* [4]: H7 = h */
    0x1f83d9ab,  /* [5]: H6 = g */
    0xa54ff53a,  /* [6]: H3 = d */
    0x3c6ef372,  /* [7]: H2 = c */
};

#define sha512_digest_size 64
#define sha512_block_size 128
#define sha512_rounds 80

/* We do not need to byteswap those values as they are "native"
 * values. The hash and text bytes are interpreted as big-endian
 * when converting bytes<->words, so getting words requires
 * byteswapping in little-endian orders. This is not the case
 * for those words, which are in memory in the native (big) endianness.
 */
static const uint64_t kSha512RoundConstants[sha512_rounds] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,  /* 0-3 */
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,  /* 4-7 */
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,  /* 64-67 */
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,  /* 76-79 */
};

/* We arrange the initial hash value to remove the need for byte-swapping
 * and re-arranging in the SHA logic.
 * The logic wants H0 (a), ... H7 (h) in the following order (listed
 * from most significant to least significant in each group of 4 32b values):
 *  {a,b,e,f} {h,g,d,c}
 *
 * So we want the constant array content arranged as:
 *   kHash[0] = f
 *   kHash[1] = e
 *   kHash[2] = b
 *   kHash[3] = a
 *
 *   kHash[4] = h
 *   kHash[5] = g
 *   kHash[6] = d
 *   kHash[7] = c
 *
 * Each constant is stored in the platform endianess, i.e., little endian.
 * The final hash value (updated values of a...h) needs to be byteswapped
 * (to big endian) and reordered to match the expected bit stream of SHA-2.
 */
static const uint64_t kSha512InitialHash[sha512_digest_size / sizeof(uint64_t)] = {
    0x9b05688c2b3e6c1f,  /* [0]: H5 = f */
    0x510e527fade682d1,  /* [1]: H4 = e */
    0xbb67ae8584caa73b,  /* [2]: H1 = b */
    0x6a09e667f3bcc908,  /* [3]: H0 = a */

    0x5be0cd19137e2179,  /* [4]: H7 = h */
    0x1f83d9abfb41bd6b,  /* [5]: H6 = g */
    0xa54ff53a5f1d36f1,  /* [6]: H3 = d */
    0x3c6ef372fe94f82b,  /* [7]: H2 = c */
};

void
sha256_block(uint8_t *hash, const void* block, const void* round_constants);

void
sha512_block(uint8_t *hash, const void* block, const void* round_constants);
#endif
