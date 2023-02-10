# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# AES-128 and AES-256 encoding, decoding, and key expansion routines
# using the proposed Zvkned instructions (vaeskf1, vaeskf2, vaesem, vaesef,
# vaesdm, vaesdf).
#
# Those routines are vector-length (VLEN) agnostic, only requiring
# that VLEN is a multiple of 128.
#
# This code was developed to validate the design of the Zvkned extension,
# understand and demonstrate expected usage patterns.
#
# DISCLAIMER OF WARRANTY:
#  This code is not intended for use in real cryptographic applications,
#  has not been reviewed, even less audited by cryptography or security
#  experts, etc.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY EXPRESS
#  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
#  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
#  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

.text

######################################################################
# AES-128 Routines, "vaes[ed][mf].vv" Versions
######################################################################


# Note that the routines using vaes[ed][mf].vv were written when the
# ".vs" variants of those instructions did not exist. The logic needed
# to replicate the keys across all element groups is unnecessary once
# the ".vs" variants are availabe.
#
# We keep the logic using ".vv" around for the following reasons:
#  - it provides some basic validation of those instructions,
#  - it could prove useful on hypothetical micro-architectures where
#    the broadcasting cost of the ".vs" variants would be expensive.
#  - it allows to highlight the logic needed, in the .vv variants,
#    to replicate the key across all element groups, and the constraints
#    this imposes (.e.g, see the LMUL=8 differences). This can help
#    motivate the existence of the .vs variants.
#
# If we assume that the .vs variants exist, the use of the .vv variants
# may be limited to cases where we want to encode messages (same or different)
# with different keys simultaneously.

# zvkned_aes128_encode_vv_lmul1
#
# Encodes the provided plain text content at 'src', of length 'n' bytes,
# with the given (unexpanded) 128 bits key (16 bytes) at 'key',
# and places the 'n' cypher text (i.e., encrypted bytes) at 'dest'.
#
# 'n' should be a multiple of 16 bytes (128b).
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# This variant uses LMUL=1, processing a single vector register of text
# during each iteration of the core encode loop. The round keys are kept
# in vector registers (11 of them, one per round).
#
# This routine performs an initial round of key expansion prior to
# key use in the core encoding loop. If the key is used for multiple
# invocations of the encode/decode routines, it might be  more efficient
# to expand the key separately and pass in the address of the pre-expanded
# key. Using a pre-expanded key instead would be straightforward (see
# the decode logic). We use this variant to show that there are multiple ways
# to express the base algorithm. It is interesting to demonstrate how
# the splating logic changes between an expand-inline case vs a load-from
# memory pre-expansion case.
#
# C/C++ Signature
#   extern "C" uint64_t
#   zvkned_aes128_encode_vv_lmul1(
#       void* dest,         // a0
#       const void* src,    // a1
#       uint64_t n,         // a2
#       const char key[16]  // a3
#   );
#  a0=dest, a1=src, a2=n, a3=&key[0]
#
.balign 4
.global zvkned_aes128_encode_vv_lmul1
zvkned_aes128_encode_vv_lmul1:
    # a2 on input is number of bytes of the plaintext. We round it down
    # to a multiple of 16 bytes (128b), keep that in t0 that we return.
    andi t0, a2, -16  # 0xFF0 in two's completment, clear low 4 bits.
    beqz t0, 2f  # Early exit in the "0 bytes to process" case
    # t3 <- t0 / 4, number of remaining 4B elements
    srli t3, t0, 2

    # We generate the 11 round keys into 11 vector registers, v10-v20,
    # with the 4x32b round keys repeated across each 4x32b element groups
    # of those vectors.

    # The first step is to get all element groups set to the initial key
    # in v10.
    # There are two approaches:
    #  1) Load 64b values in scalar registers, splat in different vector
    #     registers configures with SEW=64b elements, generate a mask
    #     and use vmerge.vxm to place the right "half" of the keys
    #     in the right 64b elements.
    #
    #     This approach is commented out below, used in multiple routines
    #     in this file. It works well for element groups that are 128b wide,
    #     but might be cumbersome for 256b-wide element groups.
    #
    #  2) Load one 128b element group by configuring vectors to contain
    #     a single element group -- using a 32bx4 element group aligns
    #     well with the Zvkned logic, but using 64bx2 would work too --,
    #     then replicating the element group across a full vector (/ vector
    #     group) using a vrgather. This is the logic we use below.
    #     Depending on the relative costs of vmv.v.x+vmerge and vrgather,
    #     one approach might be more efficient than the other.
    #
    # --- Approach (1) outlined above, commented out. ---
    #
    # # Generate a mask register that alternates 0s and 1s,
    # # so that we can use vmerge to copy a 64b value to the odd 64b elements.
    # # We use x0 and set t2 to get VLMAX.
    # # Note that using SEW=64 here reduces the amount of code needed. Its
    # # use here is not relevant to the SEW in place once the AES instructions
    # # are used.
    # vsetvli t2, x0, e64, m1, ta, ma   # Vectors of 8 bytes
    # vid.v    v3           # v3[i] <- i
    # vand.vi  v3, v3, 0x1  # v3[i] <- i & 0b1, i.e., v3[i] <- is_odd?(i)
    # vmseq.vi v0, v3, 0x1  # v0.mask[i] <- is_odd?(i)
    # # Load low 8B of first round key (w[0, 1]), splat across v10
    # ld t4, (a3)
    # vmv.v.x v10, t4
    # # Load high 8B of first round key (w[2, 3]), merge into into v10
    # # using the mask to only replace the odd 8B lanes
    # addi a3, a3, 8
    # ld t4, (a3)
    # vmerge.vxm v10, v10, t4, v0  # v10 <- splat(w[0, 3])
    # # Change SEW to 32 bits elements.
    # vsetvli t2, x0, e32, m1, ta, ma   # Vectors of 4 bytes elements.
    #
    # --- Approach (2) outlined above ---
    # Load the 128 bits of the key into v11, as 4*32b (i.e., one element group).
    vsetivli t2, 4, e32, m1, ta, ma
    vle32.v v11, (a3)
    # Increase VL to cover whole vectors (LMUL=1) with 32b elements.
    vsetvli t2, x0, e32, m1, ta, ma
    # Generate the repeated index sequence [0, 1, 2, 3, 0, 1, 2, 3, ....] in v3.
    vid.v v3
    vand.vi v3, v3, 0x3
    # Copy the initial 4x32b of v11 into every 4x32b element group of v10.
    vrgather.vv v10, v11, v3

    # Now that we have the first key in v10, we can iterate
    # to get all subsequent keys in each element groups of v11-v20.
    # vaeskf1 generates w[4*(round+1) .. 4*(round+1)+3]
    # from w[4*round .. 4*round+3]
    vaeskf1.vi v11, v10,  1  # v11 <- splat(w[ 4, 7])
    vaeskf1.vi v12, v11,  2  # v12 <- splat(w[ 8, 11])
    vaeskf1.vi v13, v12,  3  # v13 <- splat(w[12, 15])
    vaeskf1.vi v14, v13,  4  # v14 <- splat(w[16, 19])
    vaeskf1.vi v15, v14,  5  # v15 <- splat(w[20, 23])
    vaeskf1.vi v16, v15,  6  # v16 <- splat(w[24, 27])
    vaeskf1.vi v17, v16,  7  # v17 <- splat(w[28, 31])
    vaeskf1.vi v18, v17,  8  # v18 <- splat(w[32, 35])
    vaeskf1.vi v19, v18,  9  # v19 <- splat(w[36, 39])
    vaeskf1.vi v20, v19, 10  # v20 <- splat(w[40, 43])

1:
    # t3: number of remaining 4B elements (which is a multiple of 4)
    # e32: vector of 32/4B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # t2 receives the number of 4B elements in the vector
    vsetvli t2, t3, e32, m1, ta, ma   # Vectors of 4B

    # Load plain text from `src`, 4B(*4) at a time
    vle32.v v1, (a1)

    # Initial AddRoundKey
    vxor.vv v1, v1, v10   # with round key w[ 0, 4]
    # Middle rounds, vaesem performs
    # SubBytes+ShiftRows+MixColumns+AddRoundKey
    vaesem.vv v1, v11  # with round key w[ 4, 7]
    vaesem.vv v1, v12  # with round key w[ 8,11]
    vaesem.vv v1, v13  # with round key w[12,15]
    vaesem.vv v1, v14  # with round key w[16,19]
    vaesem.vv v1, v15  # with round key w[20,23]
    vaesem.vv v1, v16  # with round key w[24,27]
    vaesem.vv v1, v17  # with round key w[28,31]
    vaesem.vv v1, v18  # with round key w[32,35]
    vaesem.vv v1, v19  # with round key w[36,39]
    # Final round, vaesef does
    # SubBytes+ShiftRows+AddRoundKey,
    # i.e., the same as vaesem except that MixColumns is not missing.
    vaesef.vv v1, v20  # with round key w[40,43]

    # Store cypher test
    # a0 is the destination (updated)
    vse32.v v1, (a0)

    # t2 contains the number of 32b/4B elements processed
    sub t3, t3, t2              # Decrement count (4B elements)

    # Scale by 4 to get number of bytes
    slli t2, t2, 2              # t2 (#bytes) <- t2 (#4B) * 4
    add a1, a1, t2              # Increment source address (bytes)
    add a0, a0, t2              # Increment target address (bytes)

    bnez t3, 1b                 # Continue the loop?

    # Return the number of bytes actually processed
2:
    mv a0, t0  # 'n' bytes result, computed on entry.
    ret
# zvkned_aes128_encode_vv_lmul1


# zvkned_aes128_decode_vv_lmul1
#
# Decode the provided cipher text content at 'src', of length 'n' bytes,
# with the given (unexpanded) 128 bits key (32 bytes) at 'key',
# and places the 'n' clear text (i.e., decrypted bytes) at 'dest'.
#
# 'n' should be a multiple of 16 bytes (256b).
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# This variant uses LMUL=1, processing a single vector register of text
# during each iteration of the core decode loop. The round keys are kept
# in vector registers (11 of them, one per round).
#
# This routine performs an initial round of key expansion prior to
# key use in the core encoding loop. If the key is used for multiple
# invocations of the encode/decode routines, it might be more efficient
# to expand the key separately and pass in the address of the pre-expanded
# key. Using a pre-expanded key instead would be straightforward (see
# the decode logic). We use this variant to show that there are multiple ways
# to express the base algorithm. It is interesting to demonstrate how
# the splating logic changes between an expand-inline case vs a load-from
# memory pre-expansion case.
#
# C/C++ Signature
#   extern "C" uint64_t
#   zvkned_aes128_decode_vv_lmul1(
#       void* dest,           // a0
#       const void* src,      // a1
#       uint64_t n,           // a2
#       const char key[32]    // a3
#   );
#  a0=dest, a1=src, a2=n, a3=&key[0]
#
.balign 4
.global zvkned_aes128_decode_vv_lmul1
zvkned_aes128_decode_vv_lmul1:
    # a2 on input is number of bytes of the plaintext. We round it down
    # to a multiple of 16 bytes (128b), keep that in t0 that we return.
    andi t0, a2, -16  # 0xFF0 in two's completment, clear low 4 bits.
    beqz t0, 2f  # Early exit in the "0 bytes to process" case
    # t3 <- t0 / 4, number of remaining 4B elements
    srli t3, t0, 2

    # Load the 128 bits of the key into v11, as 4*32b (i.e., one element group).
    vsetivli t2, 4, e32, m1, ta, ma
    vle32.v v11, (a3)
    # Increase VL to cover whole vectors (LMUL=1) with 32b elements.
    vsetvli t2, x0, e32, m1, ta, ma
    # Generate the repeated index sequence [0, 1, 2, 3, 0, 1, 2, 3, ....] in v3.
    vid.v v3
    vand.vi v3, v3, 0x3
    # Copy the initial 4x32b of v11 into every 4x32b element group of v10.
    vrgather.vv v10, v11, v3

    # Change SEW to 32 bits elements.
    vsetvli t2, x0, e32, m1, ta, ma   # Vectors of 4 bytes elements.

    # Generate keys for round 1-10 into registers v11-v20.
    vaeskf1.vi v11, v10,  1  # v11 <- Round  1 expanded key, w[ 4,  7].
    vaeskf1.vi v12, v11,  2  # v12 <- Round  2 expanded key, w[ 8, 11].
    vaeskf1.vi v13, v12,  3  # v13 <- Round  3 expanded key, w[12, 15].
    vaeskf1.vi v14, v13,  4  # v14 <- Round  4 expanded key, w[16, 19].
    vaeskf1.vi v15, v14,  5  # v15 <- Round  5 expanded key, w[20, 23].
    vaeskf1.vi v16, v15,  6  # v16 <- Round  6 expanded key, w[24, 27].
    vaeskf1.vi v17, v16,  7  # v17 <- Round  7 expanded key, w[28, 31].
    vaeskf1.vi v18, v17,  8  # v18 <- Round  8 expanded key, w[32, 35].
    vaeskf1.vi v19, v18,  9  # v19 <- Round  9 expanded key, w[36, 39].
    vaeskf1.vi v20, v19, 10  # v20 <- Round 10 expanded key, w[40, 43].

1:
    # t3: number of remaining 4B elements (which is 4*k)
    # e32: vector of 64b/8B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # t2 receives the number of 8B elements in the vector
    vsetvli t2, t3, e32, m1, ta, ma   # Vectors of 4B

    # v1 contains the text, from cipher to clear,
    # v10-v20 contain the 11 per-round keys.

    # Load cipher text from `src`, one vector full at a time.
    vle32.v v1, (a1)

    # Initial round, AddRoundKey
    vxor.vv v1, v1, v20  # with round key w[43,47]
    # Middle rounds, vaesdm performs
    # InvShiftRows+InvSubBytes+AddRoundKey+InvMixColumns.
    vaesdm.vv v1, v19  # with round key w[36,39]
    vaesdm.vv v1, v18  # with round key w[32,35]
    vaesdm.vv v1, v17  # with round key w[28,31]
    vaesdm.vv v1, v16  # with round key w[24,27]
    vaesdm.vv v1, v15  # with round key w[20,23]
    vaesdm.vv v1, v14  # with round key w[16,19]
    vaesdm.vv v1, v13  # with round key w[12,15]
    vaesdm.vv v1, v12  # with round key w[ 8,11]
    vaesdm.vv v1, v11  # with round key w[ 4, 7]
    # Final round, vaesdf performs
    # InvShiftRows+InvSubBytes+AddRoundKey,
    # i.e., the same as vaesdm except that InvMixColumns is missing.
    vaesdf.vv v1, v10  # with round key w[ 0, 4]

    # Store clear test
    # a0 is the destination (updated)
    vse32.v v1, (a0)

    # t2 contains the number of 32b/4B elements processed
    sub t3, t3, t2  # Decrement count (4B elements)

    # Scale by 4 to get number of bytes
    slli t2, t2, 2  # t2 (#bytes) <- t2 (#4B) * 4
    add a1, a1, t2  # Increment source address (bytes)
    add a0, a0, t2  # Increment target address (bytes)

    bnez t3, 1b     # Loop if text remains.

    # Return the number of bytes actually processed
2:
    mv a0, t0  # 'n' bytes result, computed on entry.
    ret
# zvkned_aes128_decode_vv_lmul1


######################################################################
# AES-256 Routines, "vaes[ed][mf].vv" Versions
######################################################################


# zvkned_aes256_encode_vv_lmul1
#
# Encodes the provided plain text content at 'src', of length 'n' bytes,
# with the given (unexpanded) 256 bits key (32 bytes) at 'key',
# and places the 'n' cypher text (i.e., encrypted bytes) at 'dest'.
#
# 'n' should be a multiple of 16 bytes (128b).
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# This routine performs key expansion during encoding, which may be
# lower performance than using a pre-expanded key, either kept
# in memory or in vector registers.
#
# C/C++ Signature
#   extern "C" uint64_t
#   zvkned_aes256_encode_vv_lmul1(
#       void* dest,           // a0
#       const void* src,      // a1
#       uint64_t n,           // a2
#       const char key[32]    // a3
#   );
#  a0=dest, a1=src, a2=n, a3=&key[0]
#
.balign 4
.global zvkned_aes256_encode_vv_lmul1
zvkned_aes256_encode_vv_lmul1:
    # a2 on input is number of bytes of the plaintext.
    # Since we don't have SEW=128b, we use SEW=32b,
    # so we divide a2 by 4 to get the number of 8B(64b) elements
    # to be processed, and round it down to a multiple of 4 to avoid
    # and infinite loop when subtracting 4 on every iteration.
    srli t3, a2, 2
    andi t3, t3, -4 # 0xFFC in two's complement, clear low 2 bits.
    # T3 now contains the (4*k) number of 4B values we'll be going
    # through.
    slli t0, t3, 2  # This is the "processed bytes" value we return
    beqz t3, 2f  # Early exit in the "0 bytes to process" case

    # We generate the 15 round keys into 11 vector registers, v10-v24,
    # with the 16B (4 words) round keys repeated across each 128b
    # lane of those vectors.

    # Load the starting (32B) key in v10 (16B * lanes) and v11 (16B * lanes),
    # splat each 128b across all 4x32b element groups of the respective vectors.
    # Generate a mask register that alternates 0s and 1s,
    # so that we can use vmerge to copy a 64b value to the odd 64b lanes.
    # We use x0 and set t2 to get VLMAX.
    # Note that using SEW=64 here reduces the amount of code needed. Its
    # use here is not relevant to the SEW in place once the AES instructions
    # are used.
    vsetvli t2, x0, e64, m1, ta, ma   # Vectors of 8 bytes
    vid.v    v3           # v3[i] <- i
    vand.vi  v3, v3, 0x1  # v3[i] <- i & 0b1, i.e., v3[i] <- is_odd?(i)
    vmseq.vi v0, v3, 0x1  # v0.mask[i] <- is_odd?(i)
    # Load low 8B of first round key (w[0, 1]), splat across v10
    ld t4, (a3)
    vmv.v.x v10, t4
    # Load high 8B of first round key (w[2, 3]), merge into into v10
    # using the mask to only replace the odd 8B lanes
    addi a3, a3, 8
    ld t4, (a3)
    vmerge.vxm v10, v10, t4, v0  # v10 <- splat(w[0, 3])
    # Load low 8B of second round key (w[0, 1]), splat across v11
    addi a3, a3, 8
    ld t4, (a3)
    vmv.v.x v11, t4
    # Load high 8B of first round key (w[2, 3]), merge into into v10
    # using the mask to only replace the odd 8B lanes
    addi a3, a3, 8
    ld t4, (a3)
    vmerge.vxm v11, v11, t4, v0  # v11 <- splat(w[ 4,  7])

    # Change SEW to 32 bits elements.
    vsetvli t2, x0, e32, m1, ta, ma   # Vectors of 4 bytes elements.

    # Now that we have the first keys in v10/v11, we can iterate
    # to get all subsequent keys

    # vaeskf2 generates w[4*(round+1) .. 4*(round+1)+3] in vd
    # from w[4*round .. 4*round+3]  in vs2,
    # and  w[4*(round-1) .. 4*(round-1)+3] in vd.
    vmv.v.v v12, v10
    vaeskf2.vi v12, v11,  2  # v12 <- splat(w[ 8, 11])
    vmv.v.v v13, v11
    vaeskf2.vi v13, v12,  3  # v13 <- splat(w[12, 14])
    vmv.v.v v14, v12
    vaeskf2.vi v14, v13,  4  # v14 <- splat(w[16, 19])
    vmv.v.v v15, v13
    vaeskf2.vi v15, v14,  5  # v15 <- splat(w[20, 23])
    vmv.v.v v16, v14
    vaeskf2.vi v16, v15,  6  # v16 <- splat(w[24, 27])
    vmv.v.v v17, v15
    vaeskf2.vi v17, v16,  7  # v17 <- splat(w[28, 31])
    vmv.v.v v18, v16
    vaeskf2.vi v18, v17,  8  # v18 <- splat(w[32, 35])
    vmv.v.v v19, v17
    vaeskf2.vi v19, v18,  9  # v19 <- splat(w[36, 39])
    vmv.v.v v20, v18
    vaeskf2.vi v20, v19, 10  # v20 <- splat(w[40, 43])
    vmv.v.v v21, v19
    vaeskf2.vi v21, v20, 11  # v21 <- splat(w[44, 47])
    vmv.v.v v22, v20
    vaeskf2.vi v22, v21, 12  # v22 <- splat(w[48, 51])
    vmv.v.v v23, v21
    vaeskf2.vi v23, v22, 13  # v23 <- splat(w[52, 55])
    vmv.v.v v24, v22
    vaeskf2.vi v24, v23, 14  # v24 <- splat(w[56, 59])

1:
    # t3: number of remaining 4B elements (which is a multiple of 4)
    # e32: vector of 32b/4B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # t2 receives the number of 8B elements in the vector
    vsetvli t2, t3, e32, m1, ta, ma   # Vectors of 4B

    # v0 contains the text (from clear to cipher)
    # Load plain text from `src`, 4B(*4) at a time
    vle32.v v0, (a1)

    # Round 0, Initial AddRoundKey of w[0, 3]
    vxor.vv v0, v0, v10
    # vaesem does SubBytes+ShiftRows+MixColumns+AddRoundKey of w[4*round .. 4*round+3]
    vaesem.vv v0, v11  # v11 contains round 1 key, w[4, 7]
    vaesem.vv v0, v12
    vaesem.vv v0, v13
    vaesem.vv v0, v14
    vaesem.vv v0, v15
    vaesem.vv v0, v16
    vaesem.vv v0, v17
    vaesem.vv v0, v18
    vaesem.vv v0, v19
    vaesem.vv v0, v20
    vaesem.vv v0, v21
    vaesem.vv v0, v22
    vaesem.vv v0, v23
    # Final round
    # vaesef does SubBytes+ShiftRows+AddRoundKey of w[56,59]
    # (same as vaesem except that MixColumns is not performed)
    vaesef.vv v0, v24

    # Store cypher test
    # a0 is the destination (updated)
    vse32.v v0, (a0)
    # ret # Test a single write

    # t2 contains the number of 32b/4B elements processed
    sub t3, t3, t2              # Decrement count (4B elements)

    # Scale by 8 to get number of bytes
    slli t2, t2, 2              # t2 (#bytes) <- t2 (#4B) * 4
    add a1, a1, t2              # Increment source address (bytes)
    add a0, a0, t2              # Increment target address (bytes)

    bnez t3, 1b                 # Continue the loop?

    # Return the number of bytes actually processed
2:
    mv a0, t0  # 'n' bytes result, computed on entry.
    ret
# zvkned_aes256_encode_vv_lmul1


# zvkned_aes256_decode_vv_lmul1
#
# Decode the provided cipher text content at 'src', of length 'n' bytes,
# with the given (unexpanded) 256 bits key (32 bytes) at 'key',
# and places the 'n' clear text (i.e., decrypted bytes) at 'dest'.
#
# 'n' should be a multiple of 16 bytes (256b).
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# C/C++ Signature
#   extern "C" uint64_t
#   zvkned_aes256_decode_vv_lmul1(
#       void* dest,           // a0
#       const void* src,      // a1
#       uint64_t n,           // a2
#       const char key[32]    // a3
#   );
#  a0=dest, a1=src, a2=n, a3=&key[0]
#
.balign 4
.global zvkned_aes256_decode_vv_lmul1
zvkned_aes256_decode_vv_lmul1:
    # a2 on input is number of bytes of the plaintext.
    # Since we don't have SEW=128b, we use SEW=32b,
    # so we divide a2 by 4 to get the number of 8B(64b) elements
    # to be processed, and round it down to a multiple of 4 to avoid
    # and infinite loop when subtracting 4 on every iteration.
    srli t3, a2, 2
    andi t3, t3, -4 # 0xFFC in two's complement, clear low 2 bits.
    # T3 now contains the (4*k) number of 4B values we'll be going
    # through.
    slli t0, t3, 2  # This is the "processed bytes" value we return
    beqz t3, 2f  # Early exit in the "0 bytes to process" case

    # We generate the 15 round keys into 11 vector registers, v10-v24,
    # with the 16B (4 words) round keys repeated across each 128b
    # lane of those vectors.

    # Load the starting (32B) key in v10 (16B * lanes) and v11 (16B * lanes),
    # splat each 128b across all 4x32b element groups of the respective vectors.
    # Generate a mask register that alternates 0s and 1s,
    # so that we can use vmerge to copy a 64b value to the odd 64b lanes.
    # We use x0 and set t2 to get VLMAX.
    # Note that using SEW=64 here reduces the amount of code needed. Its
    # use here is not relevant to the SEW in place once the AES instructions
    # are used.
    vsetvli t2, x0, e64, m1, ta, ma   # Vectors of 8 bytes
    vid.v    v3           # v3[i] <- i
    vand.vi  v3, v3, 0x1  # v3[i] <- i & 0b1, i.e., v3[i] <- is_odd?(i)
    vmseq.vi v0, v3, 0x1  # v0.mask[i] <- is_odd?(i)
    # Load low 8B of first round key (w[0, 1]), splat across v10
    ld t4, (a3)
    vmv.v.x v10, t4
    # Load high 8B of first round key (w[2, 3]), merge into into v10
    # using the mask to only replace the odd 8B lanes
    addi a3, a3, 8
    ld t4, (a3)
    vmerge.vxm v10, v10, t4, v0  # v10 <- splat(w[0, 3])
    # Load low 8B of second round key (w[0, 1]), splat across v11
    addi a3, a3, 8
    ld t4, (a3)
    vmv.v.x v11, t4
    # Load high 8B of first round key (w[2, 3]), merge into into v10
    # using the mask to only replace the odd 8B lanes
    addi a3, a3, 8
    ld t4, (a3)
    vmerge.vxm v11, v11, t4, v0  # v11 <- splat(w[ 4,  7])

    # Change SEW to 32 bits elements.
    vsetvli t2, x0, e32, m1, ta, ma   # Vectors of 4 bytes elements.

    # Now that we have the first keys in v10/v11, we can iterate
    # to get all subsequent keys

    # vaeskf2 generates w[4*(round+1) .. 4*(round+1)+3] in vd
    # from w[4*round .. 4*round+3]  in vs2,
    # and  w[4*(round-1) .. 4*(round-1)+3] in vd.
    vmv.v.v v12, v10
    vaeskf2.vi v12, v11,  2  # v12 <- Round  2 expanded key, w[8, 13].
    vmv.v.v v13, v11
    vaeskf2.vi v13, v12,  3  # v13 <- Round  3 expanded key, w[12, 15].
    vmv.v.v v14, v12
    vaeskf2.vi v14, v13,  4  # v14 <- Round  4 expanded key, w[16, 19].
    vmv.v.v v15, v13
    vaeskf2.vi v15, v14,  5  # v15 <- Round  5 expanded key, w[20, 23].
    vmv.v.v v16, v14
    vaeskf2.vi v16, v15,  6  # v16 <- Round  6 expanded key, w[24, 27].
    vmv.v.v v17, v15
    vaeskf2.vi v17, v16,  7  # v17 <- Round  7 expanded key, w[28, 31].
    vmv.v.v v18, v16
    vaeskf2.vi v18, v17,  8  # v18 <- Round  8 expanded key, w[32, 35].
    vmv.v.v v19, v17
    vaeskf2.vi v19, v18,  9  # v19 <- Round  9 expanded key, w[36, 39].
    vmv.v.v v20, v18
    vaeskf2.vi v20, v19, 10  # v20 <- Round 10 expanded key, w[40, 43].
    vmv.v.v v21, v19
    vaeskf2.vi v21, v20, 11  # v21 <- Round 11 expanded key, w[44, 47].
    vmv.v.v v22, v20
    vaeskf2.vi v22, v21, 12  # v22 <- Round 12 expanded key, w[48, 51].
    vmv.v.v v23, v21
    vaeskf2.vi v23, v22, 13  # v23 <- Round 13 expanded key, w[52, 55].
    vmv.v.v v24, v22
    vaeskf2.vi v24, v23, 14  # v24 <- Round 14 expanded key, w[56, 59].

1:
    # t3: number of remaining 4B elements (which is even)
    # e32: vector of 32b/4B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # t2 receives the number of 8B elements in the vector
    vsetvli t2, t3, e32, m1, ta, ma   # Vectors of 8b

    # v0 will contain the text, from cipher to clear,
    # v10-v24 contain the 15 per-round keys.

    # Load cipher text from `src`, 8B(*2) at a time
    vle32.v v0, (a1)

    # Initial round, AddRoundKey
    vxor.vv v0, v0, v24  # with round key w[56,59]
    # Middle rounds, vaesdm performs
    # InvShiftRows+InvSubBytes+AddRoundKey+InvMixColumns.
    vaesdm.vv v0, v23  # with round key w[52,55]
    vaesdm.vv v0, v22  # with round key w[48,51]
    vaesdm.vv v0, v21  # with round key w[44,47]
    vaesdm.vv v0, v20  # with round key w[40,43]
    vaesdm.vv v0, v19  # with round key w[36,39]
    vaesdm.vv v0, v18  # with round key w[32,35]
    vaesdm.vv v0, v17  # with round key w[28,31]
    vaesdm.vv v0, v16  # with round key w[24,27]
    vaesdm.vv v0, v15  # with round key w[20,23]
    vaesdm.vv v0, v14  # with round key w[16,19]
    vaesdm.vv v0, v13  # with round key w[12,15]
    vaesdm.vv v0, v12  # with round key w[ 8,11]
    vaesdm.vv v0, v11  # with round key w[ 4, 7]
    # Final round, vaesdf performs
    # InvShiftRows+InvSubBytes+AddRoundKey,
    # i.e., the same as vaesdm except that InvMixColumns is missing.
    vaesdf.vv v0, v10  # with round key w[ 0, 4]

    # Store clear test
    # a0 is the destination (updated)
    vse32.v v0, (a0)
    # ret # Test a single write

    # t2 contains the number of 32b/4B elements processed
    sub t3, t3, t2              # Decrement count (4B elements)

    # Scale by 8 to get number of bytes
    slli t2, t2, 2              # t2 (#bytes) <- t2 (#4B) * 4
    add a1, a1, t2              # Increment source address (bytes)
    add a0, a0, t2              # Increment target address (bytes)

    bnez t3, 1b                 # Continue the loop?

2:
    # Return the number of bytes actually processed
    mv a0, t0  # 'n' bytes result, computed on entry.
    ret
# zvkned_aes256_decode_vv_lmul1
