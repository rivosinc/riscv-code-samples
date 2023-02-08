# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# ShangMi Hash (SM3) routines using the proposed Zvksh instructions (vsm3me.vv,
# vsm3c.vv).
#
# This code was developed to validate the design of the Zvksh extension,
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

.data
.balign 4
# Initialization vector
# Used as a initial state of the context.
IV: .word 0x6f168073, 0xb9b21449, 0xd7422417, 0x68ada, 0xbc306fa9, 0xaa383116
    .word 0x4dee8de3, 0x4e0efbb0


.text
# zvksh_sm3_encode_vv
#
# Hash the provided input text content at 'src'.
# Data shall already be padded as defined in the specification.
# The output is placed in 'dst' with length of 32 bytes.
#
# 'n' should be multiple of 64 byte block size.
#
# Returns the number of bytes processed.
# This routine uses LMUL=1, processing 64 bytes in each iteration.
#
# C/C++ Signature
#   extern "C" void
#   zvksh_sm3_encode_vv(
#       void* dst,         // a0
#       const void* src,    // a1
#       uint64_t n,    // a2
#   );
#  a0=dest, a1=src, a2=n
#
.balign 4
.global zvksh_sm3_encode_vv
zvksh_sm3_encode_vv:
    # Load the IV and use it the an initial state of the hash context.
    la t6, IV
    vsetivli x0, 8, e32, m1, ta, ma
    vle32.v v0, (t6)

1:
    # Copy the previous state to v1.
    # It will be XOR'ed with the current state at the end of the round.
    vmv.v.v v1, v0

    # Load the 64B block in 2x32B chunks.
    vle32.v v3, (a1)
    add a1, a1, 32

    vle32.v v5, (a1)
    add a1, a1, 32

    add a2, a2, -64

    # As vsm3c consumes only w0, w1, w4, w5 we need to slide the input
    # 2 elements down so we process elements w2, w3, w6, w7
    # This will be repeated for each odd round.
    vslidedown.vi v2, v3, 2 # v2 := {w2, ..., w7, 0, 0}

    vsm3c.vi v0, v3, 0
    vsm3c.vi v0, v2, 1

    # Prepare a vector with {w4, ..., w11}
    vslidedown.vi v2, v2, 2 # v2 := {w4, ..., w7, 0, 0, 0, 0}
    vslideup.vi v2, v5, 4   # v2 := {w4, w5, w6, w7, w8, w9, w10, w11}

    vsm3c.vi v0, v2, 2
    vslidedown.vi v2, v2, 2 # v2 := {w6, w7, w8, w9, w10, w11, 0, 0}
    vsm3c.vi v0, v2, 3

    vsm3c.vi v0, v5, 4
    vslidedown.vi v2, v5, 2 # v2 := {w10, w11, w12, w13, w14, w15, 0, 0}
    vsm3c.vi v0, v2, 5

    vsm3me.vv v3, v5, v3    # v3 := {w16, w17, w18, w19, w20, w21, w22, w23}

    # Prepare a register with {w12, w13, w14, w15, w16, w17, w18, w19}
    vslidedown.vi v2, v2, 2 # v2 := {w12, w13, w14, w15, 0, 0, 0, 0}
    vslideup.vi v2, v3, 4   # v2 := {w12, w13, w14, w15, w16, w17, w18, w19}

    vsm3c.vi v0, v2, 6
    vslidedown.vi v2, v2, 2 # v2 := {w14, w15, w16, w17, w18, w19, 0, 0}
    vsm3c.vi v0, v2, 7

    vsm3c.vi v0, v3, 8
    vslidedown.vi v2, v3, 2 # v2 := {w18, w19, w20, w21, w22, w23, 0, 0}
    vsm3c.vi v0, v2, 9

    vsm3me.vv v5, v3, v5    # v5 := {w24, w25, w26, w27, w28, w29, w30, w31}

    # Prepare a register with {w20, w21, w22, w23, w24, w25, w26, w27}
    vslidedown.vi v2, v2, 2 # v2 := {w20, w21, w22, w23, 0, 0, 0, 0}
    vslideup.vi v2, v5, 4   # v2 := {w20, w21, w22, w23, w24, w25, w26, w27}

    vsm3c.vi v0, v2, 10
    vslidedown.vi v2, v2, 2 # v2 := {w22, w23, w24, w25, w26, w27, 0, 0}
    vsm3c.vi v0, v2, 11

    vsm3c.vi v0, v5, 12
    vslidedown.vi v2, v5, 2 # v2 := {w26, w27, w28, w29, w30, w31, 0, 0}
    vsm3c.vi v0, v2, 13

    vsm3me.vv v3, v5, v3    # v3 := {w32, w33, w34, w35, w36, w37, w38, w39}

    # Prepare a register with {w28, w29, w30, w31, w32, w33, w34, w35}
    vslidedown.vi v2, v2, 2 # v2 := {w28, w29, w30, w31, 0, 0, 0, 0}
    vslideup.vi v2, v3, 4   # v2 := {w28, w29, w30, w31, w32, w33, w34, w35}

    vsm3c.vi v0, v2, 14
    vslidedown.vi v2, v2, 2 # v2 := {w30, w31, w32, w33, w34, w35, 0, 0}
    vsm3c.vi v0, v2, 15

    vsm3c.vi v0, v3, 16
    vslidedown.vi v2, v3, 2 # v2 := {w34, w35, w36, w37, w38, w39, 0, 0}
    vsm3c.vi v0, v2, 17

    vsm3me.vv v5, v3, v5    # v5 := {w40, w41, w42, w43, w44, w45, w46, w47}

    # Prepare a register with {w36, w37, w38, w39, w40, w41, w42, w43}
    vslidedown.vi v2, v2, 2 # v2 := {w36, w37, w38, w39, 0, 0, 0, 0}
    vslideup.vi v2, v5, 4   # v2 := {w36, w37, w38, w39, w40, w41, w42, w43}

    vsm3c.vi v0, v2, 18
    vslidedown.vi v2, v2, 2 # v2 := {w38, w39, w40, w41, w42, w43, 0, 0}
    vsm3c.vi v0, v2, 19

    vsm3c.vi v0, v5, 20
    vslidedown.vi v2, v5, 2 # v2 := {w42, w43, w44, w45, w46, w47, 0, 0}
    vsm3c.vi v0, v2, 21

    vsm3me.vv v3, v5, v3    # v3 := {w48, w49, w50, w51, w52, w53, w54, w55}

    # Prepare a register with {w44, w45, w46, w47, w48, w49, w50, w51}
    vslidedown.vi v2, v2, 2 # v2 := {w44, w45, w46, w47, 0, 0, 0, 0}
    vslideup.vi v2, v3, 4   # v2 := {w44, w45, w46, w47, w48, w49, w50, w51}

    vsm3c.vi v0, v2, 22
    vslidedown.vi v2, v2, 2 # v2 := {w46, w47, w48, w49, w50, w51, 0, 0}
    vsm3c.vi v0, v2, 23

    vsm3c.vi v0, v3, 24
    vslidedown.vi v2, v3, 2 # v2 := {w50, w51, w52, w53, w54, w55, 0, 0}
    vsm3c.vi v0, v2, 25

    vsm3me.vv v5, v3, v5    # v5 := {w56, w57, w58, w59, w60, w61, w62, w63}

    # Prepare a register with {w52, w53, w54, w55, w56, w57, w58, w59}
    vslidedown.vi v2, v2, 2 # v2 := {w52, w53, w54, w55, 0, 0, 0, 0}
    vslideup.vi v2, v5, 4   # v2 := {w52, w53, w54, w55, w56, w57, w58, w59}

    vsm3c.vi v0, v2, 26
    vslidedown.vi v2, v2, 2 # v2 := {w54, w55, w56, w57, w58, w59, 0, 0}
    vsm3c.vi v0, v2, 27

    vsm3c.vi v0, v5, 28
    vslidedown.vi v2, v5, 2 # v2 := {w58, w59, w60, w61, w62, w63, 0, 0}
    vsm3c.vi v0, v2, 29

    vsm3me.vv v3, v5, v3    # v3 := {w64, w65, w66, w67, w68, w69, w70, w71}

    # Prepare a register with {w60, w61, w62, w63, w64, w65, w66, w67}
    vslidedown.vi v2, v2, 2 # v2 := {w60, w61, w62, w63, 0, 0, 0, 0}
    vslideup.vi v2, v3, 4   # v2 := {w60, w61, w62, w63, w64, w65, w66, w67}

    vsm3c.vi v0, v2, 30
    vslidedown.vi v2, v2, 2 # v2 := {w62, w63, w64, w65, w66, w67, 0, 0}
    vsm3c.vi v0, v2, 31

    # XOR in the previous state.
    vxor.vv v0, v0, v1

    bnez a2, 1b     # Check if there are any more block to process
2:
    vse32.v v0, (a0)
    ret
