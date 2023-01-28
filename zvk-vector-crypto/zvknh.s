# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# SHA-256/SHA-512 routines using the proposed Zvknh instructions (vsha2ms,
# vsha2cl, vsha2ch).
#
# This code was developed to validate the design of the Zvknh extension,
# understand and demonstrate expected usage patterns.
#
# The SHA-256 routines here require VLEN being a multiple of 128 bits.
# The SHA-512 routines here require VLEN being a multiple of 256 bits.
# When using vector units with smaller VLEN values, LMUL>1 should be used
# to present vector groups that contain multiples of 128bits/256bits.
# This is not being validated here.
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
# SHA-256 Routines
######################################################################

# sha256_block
#
# hash: current H value in "native" representation, with every uint32_t
#       word in little-endian order.
#          hash[0] = f
#          hash[1] = e
#          hash[2] = b
#          hash[3] = a
#          hash[4] = h
#          hash[5] = g
#          hash[6] = d
#          hash[7] = c
# block: pointer to the bytes to be hashed.
# round_constants: SHA256 round constants table.
#
# C/C++ Signature
#  extern "C" void
#  sha256_block(
#      uint32_t hash[8],                   // a0
#      const void* block,                  // a1
#      const uint32_t round_constants[64]  // a2
#  );
#
.balign 4
.global sha256_block
sha256_block:

    # Register use in this function:
    #
    # SCALARS:
    #  a0 (i.e., x10): initially the address of the first byte of `hash`,
    #      modified during the logic.
    #  a1: initially the address of the first byte of the message block,
    #      modified during the initial load.
    #  a2: initially the address of the first byte of the round constants
    #      'Kt', incremented during the rounds.
    #
    # VECTORS
    #  v10 - v13 (512-bits / 4*128 bits / 4*4*32 bits), hold the message
    #             schedule words (Wt). They start with the message block
    #             content (W0 to W15), then further words in the message
    #             schedule generated via vsha2ms from previous Wt.
    #   Initially:
    #     v10 = W[  3:0] = { W3,  W2,  W1,  W0}
    #     v11 = W[  7:4] = { W7,  W6,  W5,  W4}
    #     v12 = W[ 11:8] = {W11, W10,  W9,  W8}
    #     v13 = W[15:12] = {W15, W14, W13, W12}
    #
    #  v16 - v17 hold the working state variables (a, b, ..., h)
    #    v16 = {a[t],b[t],e[t],f[t]}
    #    v17 = {c[t],d[t],g[t],h[t]}
    #   Initially:
    #    v16 = {H5i-1, H4i-1, H1i-1 , H0i-1}
    #    v17 = {H7i-i, H6i-1, H3i-1 , H2i-1}
    #
    #  v0 = masks for vrgather/vmerge. Single value during the 16 rounds.
    #
    #  v14 = temporary, Wt+Kt
    #  v15 = temporary, Kt
    #
    #  v18/v19 = temporaries, in the epilogue, to re-arrange
    #            and byte-swap v16/v17
    #
    #  v26/v27 = hold the initial values of the hash, byte-swapped.
    #
    #  v30/v31 = used to generate masks, vrgather indices.
    #
    # During most of the function the vector state is configured so that each
    # vector is interpreted as containing four 32 bits (e32) elements (128 bits).

    # Set vectors as 4 * 32 bits
    #
    # e32: vector of 32b/4B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those lanes)
    # ma: mask agnostic (don't care about those lanes)
    # x0 is not written, we known the number of vector elements, 4.
    vsetivli x0, 4, e32, m1, ta, ma

    # Load the 512-bits of the message block in v10-v13 and perform
    # an endian swap on each 4 bytes element.
    #
    # If Zvkb is not implemented, one can use vrgather with the right index
    # sequence. It requires loading in separate registers since the destination
    # of vrgather cannot overlap the source.
    #    # We generate the lane (byte) index sequence
    #    #    v24 = [3 2 1 0   7 6 5 4  11 10 9 8   15 14 13 12]
    #    # <https://oeis.org/A004444> gives us "N ^ 3" as a nice formula to generate
    #    # this sequence. 'vid' gives us the N.
    #    #
    #    # We switch the vector type to SEW=8 temporarily.
    #    vsetivli x0, 16, e8, m1, ta, ma
    #    vid.v v24
    #    vxor.vi v24, v24, 0x3
    #    # Byteswap the bytes in each word of the text.
    #    vrgather.vv v10, v20, v24
    #    vrgather.vv v11, v21, v24
    #    vrgather.vv v12, v22, v24
    #    vrgather.vv v13, v23, v24
    #    # Switch back to SEW=32
    #    vsetivli x0, 4, e32, m1, ta, ma
    vle32.v v10, (a1)
    vrev8.v v10, v10
    add a1, a1, 16
    vle32.v v11, (a1)
    vrev8.v v11, v11
    add a1, a1, 16
    vle32.v v12, (a1)
    vrev8.v v12, v12
    add a1, a1, 16
    vle32.v v13, (a1)
    vrev8.v v13, v13

    # Load H[0..8] to produce
    #  v26 = v16 = {a[t],b[t],e[t],f[t]}
    #  v27 = v17 = {c[t],d[t],g[t],h[t]}
    #
    # To minimize per-block work, H is provided as {f,e,b,a, h,g,d,c}
    # with the bytes in little endian order, i.e., not in NIST endianness
    # or order.
    vle32.v v16, (a0)
    addi a0, a0, 16
    vle32.v v17, (a0)
    # Capture the initial H values in v26 and v27 to allow for computing
    # the resulting H', since H' = H+{a',b',c',...,h'}.
    vmv.v.v v26, v16
    vmv.v.v v27, v17

    # Set v0 up for the vmerge that replaces the first word (idx==0)
    vid.v v0
    vmseq.vi v0, v0, 0x0    # v0.mask[i] = (i == 0 ? 1 : 0)

    # Overview of the logic in each "quad round".
    #
    # The code below repeats 16 times the logic implementing four rounds
    # of the SHA-256 core loop as documented by NIST. 16 "quad rounds"
    # to implementing the 64 single rounds.
    #
    #    # Load four word (u32) constants (K[t+3], K[t+2], K[t+1], K[t+0])
    #    # Output:
    #    #   v15 = {K[t+3], K[t+2], K[t+1], K[t+0]}
    #    vl1re32.v v15, (a2)
    #
    #    # Increment word contant address by stride (16 bytes, 4*4B, 128b)
    #    addi a2, a2, 16
    #
    #    # Add constants to message schedule words:
    #    #  Input
    #    #    v15 = {K[t+3], K[t+2], K[t+1], K[t+0]}
    #    #    v10 = {W[t+3], W[t+2], W[t+1], W[t+0]}; // Vt0 = W[3:0];
    #    #  Output
    #    #    v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    vadd.vv v14, v15, v10
    #
    #    #  2 rounds of working variables updates.
    #    #     v17[t+4] <- v17[t], v16[t], v14[t]
    #    #  Input:
    #    #    v17 = {c[t],d[t],g[t],h[t]}   " = v17[t] "
    #    #    v16 = {a[t],b[t],e[t],f[t]}
    #    #    v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    #  Output:
    #    #    v17 = {f[t+2],e[t+2],b[t+2],a[t+2]}  " = v16[t+2] "
    #    #        = {h[t+4],g[t+4],d[t+4],c[t+4]}  " = v17[t+4] "
    #    vsha2cl.vv v17, v16, v14
    #
    #    #  2 rounds of working variables updates.
    #    #     v16[t+4] <- v16[t], v16[t+2], v14[t]
    #    #  Input
    #    #   v16 = {a[t],b[t],e[t],f[t]}       " = v16[t] "
    #    #       = {h[t+2],g[t+2],d[t+2],c[t+2]}   " = v17[t+2] "
    #    #   v17 = {f[t+2],e[t+2],b[t+2],a[t+2]}   " = v16[t+2] "
    #    #   v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    #  Output:
    #    #   v16 = {f[t+4],e[t+4],b[t+4],a[t+4]}   " = v16[t+4] "
    #    vsha2ch.vv v16, v17, v14
    #
    #    # Combine 2QW into 1QW
    #    #
    #    # To generate the next 4 words, "new_v10"/"v14" from v10-v13, vsha2ms needs
    #    #     v10[0..3], v11[0], v12[1..3], v13[0, 2..3]
    #    # and it can only take 3 vectors as inputs. Hence we need to combine
    #    # v11[0] and v12[1..3] in a single vector.
    #    #
    #    # vmerge Vt4, Vt1, Vt2, V0
    #    # Input
    #    #  V0 = mask // first word from v12, 1..3 words from v11
    #    #  V12 = {Wt-8, Wt-7, Wt-6, Wt-5}
    #    #  V11 = {Wt-12, Wt-11, Wt-10, Wt-9}
    #    # Output
    #    #  Vt4 = {Wt-12, Wt-7, Wt-6, Wt-5}
    #    vmerge.vvm v14, v12, v11, v0
    #
    #    # Generate next Four Message Schedule Words (hence allowing for 4 more rounds)
    #    # Input
    #    #  V10 = {W[t+ 3], W[t+ 2], W[t+ 1], W[t+ 0]}     W[ 3: 0]
    #    #  V13 = {W[t+15], W[t+14], W[t+13], W[t+12]}     W[15:12]
    #    #  V14 = {W[t+11], W[t+10], W[t+ 9], W[t+ 4]}     W[11: 9,4]
    #    # Output (next four message schedule words)
    #    #  v10 = {W[t+19],  W[t+18],  W[t+17],  W[t+16]}  W[19:16]
    #    vsha2ms.vv v10, v14, v13
    #
    # BEFORE
    #  v10 - v13 hold the message schedule words (initially the block words)
    #    v10 = W[ 3: 0]   "oldest"
    #    v11 = W[ 7: 4]
    #    v12 = W[11: 8]
    #    v13 = W[15:12]   "newest"
    #
    #  vt6 - vt7 hold the working state variables
    #    v16 = {a[t],b[t],e[t],f[t]}   // initially {H5,H4,H1,H0}
    #    v17 = {c[t],d[t],g[t],h[t]}   // initially {H7,H6,H3,H2}
    #
    # AFTER
    #  v10 - v13 hold the message schedule words (initially the block words)
    #    v11 = W[ 7: 4]   "oldest"
    #    v12 = W[11: 8]
    #    v13 = W[15:12]
    #    v10 = W[19:16]   "newest"
    #
    #  v16 and v17 hold the working state variables
    #    v16 = {a[t+4],b[t+4],e[t+4],f[t+4]}
    #    v17 = {c[t+4],d[t+4],g[t+4],h[t+4]}
    #
    #  The group of vectors v10,v11,v12,v13 is "rotated" by one in each quad-round,
    #  hence the uses of those vectors rotate in each round, and we get back to the
    #  initial configuration every 4 quad-rounds. We could avoid those changes at
    #  the cost of moving those vectors at the end of each quad-rounds.

    #--------------------------------------------------------------------------------
    # Quad-round 0 (+0, Wt from oldest to newest in v10->v11->v12->v13)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13  # Generate W[19:16]
    #--------------------------------------------------------------------------------
    # Quad-round 1 (+1, v11->v12->v13->v10)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10  # Generate W[23:20]
    #--------------------------------------------------------------------------------
    # Quad-round 2 (+2, v12->v13->v10->v11)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11  # Generate W[27:24]
    #--------------------------------------------------------------------------------
    # Quad-round 3 (+3, v13->v10->v11->v12)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12  # Generate W[31:28]

    #--------------------------------------------------------------------------------
    # Quad-round 4 (+0, v10->v11->v12->v13)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13  # Generate W[35:32]
    #--------------------------------------------------------------------------------
    # Quad-round 5 (+1, v11->v12->v13->v10)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10  # Generate W[39:36]
    #--------------------------------------------------------------------------------
    # Quad-round 6 (+2, v12->v13->v10->v11)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11  # Generate W[43:40]
    #--------------------------------------------------------------------------------
    # Quad-round 7 (+3, v13->v10->v11->v12)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12  # Generate W[47:44]

    #--------------------------------------------------------------------------------
    # Quad-round 8 (+0, v10->v11->v12->v13)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13  # Generate W[51:48]
    #--------------------------------------------------------------------------------
    # Quad-round 9 (+1, v11->v12->v13->v10)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10  # Generate W[55:52]
    #--------------------------------------------------------------------------------
    # Quad-round 10 (+2, v12->v13->v10->v11)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11  # Generate W[59:56]
    #--------------------------------------------------------------------------------
    # Quad-round 11 (+3, v13->v10->v11->v12)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12  # Generate W[63:60]

    #--------------------------------------------------------------------------------
    # Quad-round 12 (+0, v10->v11->v12->v13)
    # Note that we stop generating new message schedule words (Wt, v10-13)
    # as we already generated all the words we end up consuming (i.e., W[63:60]).
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    #--------------------------------------------------------------------------------
    # Quad-round 13 (+1, v11->v12->v13->v10)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    #--------------------------------------------------------------------------------
    # Quad-round 14 (+2, v12->v13->v10->v11)
    vl1re32.v v15, (a2)
    addi a2, a2, 16
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14
    #--------------------------------------------------------------------------------
    # Quad-round 15 (+3, v13->v10->v11->v12)
    vl1re32.v v15, (a2)
    # No a2 increment needed.
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vslidedown.vi v14, v14, 2
    vsha2cl.vv v16, v17, v14

    #--------------------------------------------------------------------------------
    # Compute the updated hash value H'
    #   H' = H + {h',g',...,b',a'}
    #      = {h,g,...,b,a} + {h',g',...,b',a'}
    #      = {h+h',g+g',...,b+b',a+a'}
    #
    # v26 = {a,b,e,f}  (original values)
    # v27 = {c,d,g,h}  (original values)
    #
    # v16 = {a',b',e',f'}
    # v17 = {c',d',g',h'}

    # H' = H+{a',b',c',...,h'}
    vadd.vv v16, v26, v16
    vadd.vv v17, v27, v17
    # Save the hash
    vse32.v v17, (a0)   # {c',d',g',h'}
    addi a0, a0, -16
    vse32.v v16, (a0)   # {a',b',e',f'}

    ret

# sha256_block

######################################################################
# SHA-512 Routines
######################################################################

# sha512_block
#
# hash: current H value in "native" representation, with every uint64_t
#       word in little-endian order.
#          hash[0] = f
#          hash[1] = e
#          hash[2] = b
#          hash[3] = a
#          hash[4] = h
#          hash[5] = g
#          hash[6] = d
#          hash[7] = c
# block: pointer to the bytes to be hashed.
# round_constants: SHA512 round constants table.
#
# C/C++ Signature
#  extern "C" void
#  sha512_block(
#      uint64_t hash[8],                   // a0
#      const void* block,                  // a1
#      const uint32_t round_constants[80]  // a2
#  );
#
.balign 4
.global sha512_block
sha512_block:

    # Register use in this function:
    #
    # SCALARS:
    #  a0 (i.e., x10): initially the address of the first byte of `hash`,
    #      modified during the logic.
    #  a1: initially the address of the first byte of the message block,
    #      modified during the initial load.
    #  a2: initially the address of the first byte of the round constants
    #      'Kt', incremented during the rounds.
    #
    # VECTORS
    #  v10 - v13 (1024-bits / 4*256 bits / 4*4*54 bits), hold the message
    #             schedule words (Wt). They start with the message block
    #             content (W0 to W15), then further words in the message
    #             schedule generated via vsha2ms from previous Wt.
    #   Initially:
    #     v10 = W[  3:0] = { W3,  W2,  W1,  W0}
    #     v11 = W[  7:4] = { W7,  W6,  W5,  W4}
    #     v12 = W[ 11:8] = {W11, W10,  W9,  W8}
    #     v13 = W[15:12] = {W15, W14, W13, W12}
    #
    #  v16 - v17 hold the working state variables (a, b, ..., h)
    #    v16 = {a[t],b[t],e[t],f[t]}
    #    v17 = {c[t],d[t],g[t],h[t]}
    #   Initially:
    #    v16 = {H5i-1, H4i-1, H1i-1 , H0i-1}
    #    v17 = {H7i-i, H6i-1, H3i-1 , H2i-1}
    #
    #  v0 = masks for vrgather/vmerge. Single value during the 16 rounds.
    #
    #  v14 = temporary, Wt+Kt
    #  v15 = temporary, Kt
    #
    #  v18/v19 = temporaries, in the epilogue, to re-arrange
    #            and byte-swap v16/v17
    #
    #  v26/v27 = hold the initial values of the hash, byte-swapped.
    #
    #  v30/v31 = used to generate masks, vrgather indices.
    #
    # During most of the function the vector state is configured so that each
    # vector is interpreted as containing four 64 bits (e64) elements (256 bits).

    # Set vectors as 4 * 64
    #
    # e64: vector of 64b/8B elements
    # m1: LMUL=1
    # ta: tail agnostic (don't care about those lanes)
    # ma: mask agnostic (don't care about those lanes)
    # x0 is not written, we known the number of vector elements, 2.
    vsetivli x0, 4, e64, m1, ta, ma

    # Load the 1024-bits of the message block in v10-v13 and perform
    # an endian swap on each 8 bytes element.
    #
    # If Zvkb is not implemented, similar to SHA-256, one can use vrgather
    # with an index sequence to byte-swap.
    #  sequence = [3 2 1 0   7 6 5 4  11 10 9 8   15 14 13 12]
    #   <https://oeis.org/A004444> gives us "N ^ 3" as a nice formula to generate
    #  this sequence. 'vid' gives us the N.
    vle64.v v10, (a1)
    vrev8.v v10, v10
    add a1, a1, 32
    vle64.v v11, (a1)
    vrev8.v v11, v11
    add a1, a1, 32
    vle64.v v12, (a1)
    vrev8.v v12, v12
    add a1, a1, 32
    vle64.v v13, (a1)
    vrev8.v v13, v13

    # Load H[0..8] to produce
    #  v26 = v16 = {a[t],b[t],e[t],f[t]}  // H0i-1 , H1i-1 , H4i-1 , H5i-1
    #  v27 = v17 = {c[t],d[t],g[t],h[t]}  // H2i-1 , H3i-1 , H6i-1 , H7i-1
    #
    # To minimize per-block work, H is provided as {f,e,b,a, h,g,d,c}
    # with the bytes in little endian order, i.e., not in NIST endianness
    # or order.
    vle64.v v16, (a0)
    addi a0, a0, 32
    vle64.v v17, (a0)
    # Capture the initial H values in v26 and v27 to allow for computing
    # the resulting H', since H' = H+{a',b',c',...,h'}.
    vmv.v.v v26, v16
    vmv.v.v v27, v17

    # Set v0 up for the vmerge that replaces the first word (idx==0)
    vid.v v0
    vmseq.vi v0, v0, 0x0    # v0.mask[i] = (i == 0 ? 1 : 0)

    # Overview of the logic in each "quad round".
    #
    # The code below repeats 20 times the logic implementing four rounds
    # of the SHA-512 core loop as documented by NIST. 20 "quad rounds"
    # to implementing the 80 single rounds.
    #
    #    # Load four word (u64) constants (K[t+3], K[t+2], K[t+1], K[t+0])
    #    # Output:
    #    #   v15 = {K[t+3], K[t+2], K[t+1], K[t+0]}
    #    vl1re32.v v15, (a2)
    #
    #    # Increment word contant address by stride (32 bytes, 4*8B, 256b)
    #    addi a2, a2, 32
    #
    #    # Add constants to message schedule words:
    #    #  Input
    #    #    v15 = {K[t+3], K[t+2], K[t+1], K[t+0]}
    #    #    v10 = {W[t+3], W[t+2], W[t+1], W[t+0]}; // Vt0 = W[3:0];
    #    #  Output
    #    #    v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    vadd.vv v14, v15, v10
    #
    #    #  2 rounds of working variables updates.
    #    #     v17[t+4] <- v17[t], v16[t], v14[t]
    #    #  Input:
    #    #    v17 = {c[t],d[t],g[t],h[t]}   " = v17[t] "
    #    #    v16 = {a[t],b[t],e[t],f[t]}
    #    #    v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    #  Output:
    #    #    v17 = {f[t+2],e[t+2],b[t+2],a[t+2]}  " = v16[t+2] "
    #    #        = {h[t+4],g[t+4],d[t+4],c[t+4]}  " = v17[t+4] "
    #    vsha2cl.vv v17, v16, v14
    #
    #    #  2 rounds of working variables updates.
    #    #     v16[t+4] <- v16[t], v16[t+2], v14[t]
    #    #  Input
    #    #   v16 = {a[t],b[t],e[t],f[t]}       " = v16[t] "
    #    #       = {h[t+2],g[t+2],d[t+2],c[t+2]}   " = v17[t+2] "
    #    #   v17 = {f[t+2],e[t+2],b[t+2],a[t+2]}   " = v16[t+2] "
    #    #   v14 = {W[t+3]+K[t+3], W[t+2]+K[t+2], W[t+1]+K[t+1], W[t+0]+K[t+0]}
    #    #  Output:
    #    #   v16 = {f[t+4],e[t+4],b[t+4],a[t+4]}   " = v16[t+4] "
    #    vsha2ch.vv v16, v17, v14
    #
    #    # Combine 2QW into 1QW
    #    #
    #    # To generate the next 4 words, "new_v10"/"v14" from v10-v13, vsha2ms needs
    #    #     v10[0..3], v11[0], v12[1..3], v13[0, 2..3]
    #    # and it can only take 3 vectors as inputs. Hence we need to combine
    #    # v11[0] and v12[1..3] in a single vector.
    #    #
    #    # vmerge Vt4, Vt1, Vt2, V0
    #    # Input
    #    #  V0 = mask // first word from v12, 1..3 words from v11
    #    #  V12 = {Wt-8, Wt-7, Wt-6, Wt-5}
    #    #  V11 = {Wt-12, Wt-11, Wt-10, Wt-9}
    #    # Output
    #    #  Vt4 = {Wt-12, Wt-7, Wt-6, Wt-5}
    #    vmerge.vvm v14, v12, v11, v0
    #
    #    # Generate next Four Message Schedule Words (hence allowing for 4 more rounds)
    #    # Input
    #    #  V10 = {W[t+ 3], W[t+ 2], W[t+ 1], W[t+ 0]}     W[ 3: 0]
    #    #  V13 = {W[t+15], W[t+14], W[t+13], W[t+12]}     W[15:12]
    #    #  V14 = {W[t+11], W[t+10], W[t+ 9], W[t+ 4]}     W[11: 9,4]
    #    # Output (next four message schedule words)
    #    #  v10 = {W[t+19],  W[t+18],  W[t+17],  W[t+16]}  W[19:16]
    #    vsha2ms.vv v10, v14, v13
    #
    # BEFORE
    #  v10 - v13 hold the message schedule words (initially the block words)
    #    v10 = W[ 3: 0]   "oldest"
    #    v11 = W[ 7: 4]
    #    v12 = W[11: 8]
    #    v13 = W[15:12]   "newest"
    #
    #  vt6 - vt7 hold the working state variables
    #    v16 = {a[t],b[t],e[t],f[t]}   // initially {H5,H4,H1,H0}
    #    v17 = {c[t],d[t],g[t],h[t]}   // initially {H7,H6,H3,H2}
    #
    # AFTER
    #  v10 - v13 hold the message schedule words (initially the block words)
    #    v11 = W[ 7: 4]   "oldest"
    #    v12 = W[11: 8]
    #    v13 = W[15:12]
    #    v10 = W[19:16]   "newest"
    #
    #  v16 and v17 hold the working state variables
    #    v16 = {a[t+4],b[t+4],e[t+4],f[t+4]}
    #    v17 = {c[t+4],d[t+4],g[t+4],h[t+4]}
    #
    #  The group of vectors v10,v11,v12,v13 is "rotated" by one in each quad-round,
    #  hence the uses of those vectors rotate in each round, and we get back to the
    #  initial configuration every 4 quad-rounds. We could avoid those changes at
    #  the cost of moving those vectors at the end of each quad-rounds.

    #--------------------------------------------------------------------------------
    # Quad-round 0 (+0, v10->v11->v12->v13)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13
    #--------------------------------------------------------------------------------
    # Quad-round 1 (+1, v11->v12->v13->v10)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10
    #--------------------------------------------------------------------------------
    # Quad-round 2 (+2, v12->v13->v10->v11)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11
    #--------------------------------------------------------------------------------
    # Quad-round 3 (+3, v13->v10->v11->v12)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12

    #--------------------------------------------------------------------------------
    # Quad-round 4 (+0, v10->v11->v12->v13)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13
    #--------------------------------------------------------------------------------
    # Quad-round 5 (+1, v11->v12->v13->v10)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10
    #--------------------------------------------------------------------------------
    # Quad-round 6 (+2, v12->v13->v10->v11)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11
    #--------------------------------------------------------------------------------
    # Quad-round 7 (+3, v13->v10->v11->v12)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12

    #--------------------------------------------------------------------------------
    # Quad-round 8 (+0, v10->v11->v12->v13)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13
    #--------------------------------------------------------------------------------
    # Quad-round 9 (+1, v11->v12->v13->v10)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10
    #--------------------------------------------------------------------------------
    # Quad-round 10 (+2, v12->v13->v10->v11)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11
    #--------------------------------------------------------------------------------
    # Quad-round 11 (+3, v13->v10->v11->v12)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12

    #--------------------------------------------------------------------------------
    # Quad-round 12 (+0, v10->v11->v12->v13)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    vsha2ms.vv v10, v14, v13
    #--------------------------------------------------------------------------------
    # Quad-round 13 (+1, v11->v12->v13->v10)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    vsha2ms.vv v11, v14, v10
    #--------------------------------------------------------------------------------
    # Quad-round 14 (+2, v12->v13->v10->v11)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    vsha2ms.vv v12, v14, v11
    #--------------------------------------------------------------------------------
    # Quad-round 15 (+3, v13->v10->v11->v12)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v11, v10, v0
    vsha2ms.vv v13, v14, v12

    #--------------------------------------------------------------------------------
    # Quad-round 16 (+0, v10->v11->v12->v13)
    # Note that we stop generating new message schedule words (Wt, v10-13)
    # as we already generated all the words we end up consuming (i.e., W[79:76]).
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v10
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v12, v11, v0
    #--------------------------------------------------------------------------------
    # Quad-round 17 (+1, v11->v12->v13->v10)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v11
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v13, v12, v0
    #--------------------------------------------------------------------------------
    # Quad-round 18 (+2, v12->v13->v10->v11)
    vl1re64.v v15, (a2)
    addi a2, a2, 32
    vadd.vv v14, v15, v12
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14
    vmerge.vvm v14, v10, v13, v0
    #--------------------------------------------------------------------------------
    # Quad-round 19 (+3, v13->v10->v11->v12)
    vl1re64.v v15, (a2)
    # No a2 increment needed.
    vadd.vv v14, v15, v13
    vsha2cl.vv v17, v16, v14
    vsha2ch.vv v16, v17, v14

    #--------------------------------------------------------------------------------
    # Compute the updated hash value H'
    #   H' = H + {h',g',...,b',a'}
    #      = {h,g,...,b,a} + {h',g',...,b',a'}
    #      = {h+h',g+g',...,b+b',a+a'}
    #
    # v26 = {a,b,e,f}  (original values)
    # v27 = {c,d,g,h}  (original values)
    #
    # v16 = {a',b',e',f'}
    # v17 = {c',d',g',h'}

    # H' = H+{a',b',c',...,h'}
    vadd.vv v16, v26, v16
    vadd.vv v17, v27, v17
    # Save the  hash
    vse64.v v17, (a0)
    addi a0, a0, -32
    vse64.v v16, (a0)

    ret

# sha512_block
