# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# The Zvkb extension contains vectorized bit manipulation operations AND-NOT
# (vandn), carryless multiply  (vclmul, vclmulh), rotate left (vrol),
# and rotate right (vror).
#
# Those routines are vector-length (VLEN) agnostic, only requiring
# that VLEN is a multiple of 64. Smaller VLENs should work when using
# LMUL>1, but this is not exercised here.
#
# This code was developed to validate the design of the Zvkb extension, and to
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
# Vector AND-NOT routines (8 bits)
######################################################################

# zvkb_vandn8_vv
#
# Takes two byte vectors vs2, vs1, and their number of elements (btyes)
# 'n' as inputs, sets destination vector to (vs1 & (!vs2))
#
# The vectors are treated as vectors of bytes. Given the bitwise
# nature of vandn we could set them with other element widths.
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vandn8_vv(
#       uint8_t* dest,          // a0
#       const uint8_t* vs2,     // a1
#       const uint8_t* vs1,     // a2
#       uint64_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vandn8_vv
zvkb_vandn8_vv:
    mv t1, a3  # Save 'n' to return later.
    xor x0, x0, x0
1:
    vsetvli t0, a3, e8, m1, ta, ma # Set vector length based on 8-bit vectors
    vle8.v v2, (a1) # load vs2
    vle8.v v1, (a2) # load vs1

    vandn.vv v0, v2, v1   # v0 = vs1 &~ vs2
    vse8.v v0, (a0) # store in dest

    sub a3, a3, t0 # decrement number of elements done
    add a1, a1, t0 # bump pointer
    add a2, a2, t0 # bump pointer
    add a0, a0, t0 # bump pointer
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vandn8_vx
#
# Takes one 'n' byte-length vectors vs2 and a register rs1 as input,
# sets destination vector to (rs1 & (!vs2))
#
# 'n' should be a multiple of 16 bytes (128b).
# The vectors are treated as 8-bit vectors here.
# In later implementations, this will change
#
# Returns the number of bytes processed, which is 'n' when 'n'
# is a multiple of 16, and  floor(n/16)*16 otherwise.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vandn8_vx(
#       uint8_t* dest,        // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = rs1, a3 = n
#
.balign 4
.global zvkb_vandn8_vx
zvkb_vandn8_vx:
    mv t1, a3  # Save 'n' to return later.
1:
    vsetvli t0, a3, e8, m1,ta,ma # Set vector length based on 8-bit vectors
    vle8.v v2, (a1) # load vs2

    vandn.vx v0, v2, a2   # v0 = rs1 &~ v2
    vse8.v v0, (a0) # store in dest

    sub a3, a3, t0 # decrement number of elements done
    add a1, a1, t0 # bump pointer
    add a0, a0, t0 # bump pointer
    bnez a3, 1b

    mv a0, t1
    ret

######################################################################
# Vector Carryless Multiply routines
######################################################################

# zvkb_vclmul_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to clmul(vs2, vs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vclmul_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       const uint64_t* vs1,  // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vclmul_vv
zvkb_vclmul_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1)  # get vs2
    vle64.v v1, (a2)  # get vs1
    vclmul.vv v0, v2, v1  # vd, vs2, vs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    add a2, a2, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vclmul_vx
#
# Takes a vector of uint64_t elements vs2, a uint64_t scalar rs1,
# and a number of (64 bit) elements 'n' as inputs, sets the destination
# vector to vclmul(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vclmul_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vclmul_vx
zvkb_vclmul_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vclmul.vx v0, v2, a2  # vd, vs2, rs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vclmulh_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to clmulh(vs2, vs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vclmulh_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       const uint64_t* vs1,  // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vclmulh_vv
zvkb_vclmulh_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1)  # get vs2
    vle64.v v1, (a2)  # get vs1
    vclmulh.vv v0, v2, v1  # vd, vs2, vs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    add a2, a2, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vclmulh_vx
#
# Takes a vector of uint64_t elements vs2, a uint64_t scalar rs1,
# and a number of (64 bit) elements 'n' as inputs, sets the destination
# vector to vclmulh(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vclmulh_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#  );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vclmulh_vx
zvkb_vclmulh_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vclmulh.vx v0, v2, a2  # vd, vs2, rs1
    vse64.v v0, (a0)
    sub a3, a3, t0
    slli t0, t0, 3  # t0 <- #bytes processed in this iteration.
    add a0, a0, t0
    add a1, a1, t0
    bnez a3, 1b

    mv a0, t1
    ret


######################################################################
# Vector Rotate Left routines
######################################################################

# zvkb_vrol_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to vrol(vs1, vs2)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vrol_vv(
#       void* dest,          // a0
#       const void* vs2,     // a1
#       const void* vs1,     // a2
#       size_t n             // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vrol_vv
zvkb_vrol_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vle64.v v1, (a2) # get vs1
    vrol.vv v0, v2, v1  # vd vs2 vs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a2, a2, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vrol_vx
#
# Takes a vector of uint64_t elements vs2, a scalar rs1,
# and a number of (64 bit) elements 'n' as inputs,
# sets destination vector to vrol(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vrol_vx(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vrol_vx
zvkb_vrol_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vrol.vx v0, v2, a2  # vd vs2 rs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

######################################################################
# Vector Rotate Right routines
######################################################################

# zvkb_vror_vv
#
# Takes two vectors of uint64_t elements vs2, vs1 as input,
# a number of (64 bit) elements 'n', sets destination vector
# to vror(vs1, vs2)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vror_vv(
#       void* dest,          // a0
#       const void* vs2,     // a1
#       const void* vs1,     // a2
#       size_t n             // a3
#   );
#  a0=dest, a1=vs2, a2 = vs1, a3 = n
#
.balign 4
.global zvkb_vror_vv
zvkb_vror_vv:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vle64.v v1, (a2) # get vs1
    vror.vv v0, v2, v1  # vd vs2 vs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a2, a2, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vror_vx
#
# Takes a vector of uint64_t elements vs2, a scalar rs1,
# and a number of (64 bit) elements 'n' as inputs,
# sets destination vector to vror(vs2, rs1)
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       uint64_t rs1,         // a2
#       size_t n              // a3
#   );
#  a0=dest, a1=vs2, a2 = rs1, a3 = n
#
.balign 4
.global zvkb_vror_vx
zvkb_vror_vx:
    mv t1, a3
1:
    vsetvli t0, a3, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vror.vx v0, v2, a2  # vd vs2 rs1
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a3, a3, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a3, 1b

    mv a0, t1
    ret

# zvkb_vror_vi56
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vror(vs2, 56).
#
# Returns the number of elements processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vror_vi56(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvkb_vror_vi56
zvkb_vror_vi56:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vror.vi v0, v2, 56  # vd vs2 56
    vse64.v v0, (a0)

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvkb_vrev8_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vrev8(vs2)
# The last parameter sets the SEW to use.
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#       size_t sew            // a3
#   );
#  a0=dest, a1=vs2, a2 = n, a3 = sew
#
.balign 4
.global zvkb_vrev8_v
zvkb_vrev8_v:
    mv t1, a2
    li t2, 64
    div t2, t2, a3 # Determine SEW element scaler
    mul a2, a2, t2 # Scale number of elements according to SEW
1:
.sew8:
    li t2, 8
    bne a3, t2, .sew16
    vsetvli t0, a2, e8, m1, ta, ma
    vle8.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse8.v v0, (a0) # put vs2
    li t3, 1 # bump size is 1 byte
    j .do_loop
.sew16:
    li t2, 16
    bne a3, t2, .sew32
    vsetvli t0, a2, e16, m1, ta, ma
    vle16.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse16.v v0, (a0) # put vs2
    li t3, 2 # bump size is 2 bytes
    j .do_loop
.sew32:
    li t2, 32
    bne a3, t2, .sew64
    vsetvli t0, a2, e32, m1, ta, ma
    vle32.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse32.v v0, (a0) # put vs2
    li t3, 4 # bump size is 4 bytes
    j .do_loop
.sew64:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vrev8.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2
    li t3, 8 # bump size is 8 bytes

.do_loop:
    # Bump the addresses by the number of bytes (#elts*sew/8) processed.
    sub a2, a2, t0
    mul t0, t0, t3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvkb_vbrev8_v
#
# Takes a vector of uint64_t elements vs2, and a number of (64 bit)
# elements 'n' as inputs, sets destination vector to vbrev8(vs2).
#
# Returns the number of bytes processed, which is 'n'.
#
# C Signature
#   extern "C" uint64_t
#   zvkb_vror_vv(
#       uint64_t* dest,       // a0
#       const uint64_t* vs2,  // a1
#       size_t n              // a2
#   );
#  a0=dest, a1=vs2, a2 = n
#
.balign 4
.global zvkb_vbrev8_v
zvkb_vbrev8_v:
    mv t1, a2
1:
    vsetvli t0, a2, e64, m1, ta, ma
    vle64.v v2, (a1) # get vs2
    vbrev8.v v0, v2  # vd vs2
    vse64.v v0, (a0) # put vs2

    # Bump the addresses by the number of bytes (#elts*8) processed.
    sub a2, a2, t0
    slli t0, t0, 3
    add a1, a1, t0
    add a0, a0, t0
    bnez a2, 1b

    mv a0, t1
    ret

# zvkb_ghash_init
#
# Pre-process the H value in order to have it it the most optimilar form
# for the hotpath logic.
# Two things are done:
# 1. Swap the endianness.
# 2. Multiply it by 2. This way we won't have to shift the 256bit product
#    in the main loop
#
#   zvkb_ghash_init(
#       uint64_t X[2],     // a0
#   );
#
.balign 4
.global zvkb_ghash_init
zvkb_ghash_init:
    # Load/store data in reverse order.
    # This is needed as a part of endianness swap.
    add a0, a0, 8
    li t0, -8
    li t1, 63
    la t2, polymod

    vsetivli x0, 2, e64, m1, ta, ma

    vlse64.v v1, (a0), t0
    vle64.v v2, (t2)

    # Byte order swap
    vrev8.v v1, v1

    # Shift one left and get the carry bits.
    vsrl.vx v3, v1, t1
    vsll.vi v1, v1, 1

    # Use the fact that the polynomial degree is no more than 128,
    # i.e. only the LSB of the upper half could be set.
    # Thanks to we don't need to do the full reduction here.
    # Instead simply subtract the reduction polynomial.
    # This idea was taken from x86 ghash implementation in OpenSSL.
    vslideup.vi v4, v3, 1
    vslidedown.vi v3, v3, 1

    vmv.v.i v0, 2
    vor.vv v1, v1, v4, v0.t

    # Need to set the mask to 3, if the carry bit is set.
    # Not sure if there is a better way of doing this.
    vmv.v.v v0, v3
    vmv.v.i v3, 0
    vmerge.vim v3, v3, 3, v0
    vmv.v.v v0, v3

    vxor.vv v1, v1, v2, v0.t

    add a0, a0, -8
    vse64.v v1, (a0)
    ret

# zvkb_ghash
#
# Performs one step of GHASH function as described in NIST GCM publication.
# It uses vclmul* instruction from zvkb extension.
#
#   zvkb_ghash(
#       uint64_t X[2],     // a0
#       uint64_t H[2]      // a1
#   );
#
.balign 4
.global zvkb_ghash
zvkb_ghash:
    ld t0, (a1)
    ld t1, 8(a1)
    li t2, 63
    la t3, polymod
    ld t3, 8(t3)

    # Load/store data in reverse order.
    # This is needed as a part of endianness swap.
    add a0, a0, 8
    li t4, -8

    vsetivli x0, 2, e64, m1, ta, ma

    vlse64.v v5, (a0), t4
    vrev8.v v5, v5

    # Multiplication

    # Do two 64x64 multiplications in one go to save some time
    # and simplify things.

    # A = a1a0 (t1, t0)
    # B = b1b0 (v5)
    # C = c1c0 (256 bit)
    # c1 = a1b1 + (a0b1)h + (a1b0)h
    # c0 = a0b0 + (a0b1)l + (a1b0)h

    # v1 = (a0b1)l,(a0b0)l
    vclmul.vx v1, v5, t0
    # v3 = (a0b1)h,(a0b0)h
    vclmulh.vx v3, v5, t0

    # v4 = (a1b1)l,(a1b0)l
    vclmul.vx v4, v5, t1
    # v2 = (a1b1)h,(a1b0)h
    vclmulh.vx v2, v5, t1

    # Is there a better way to do this?
    # Would need to swap the order of elements within a vector register.
    vslideup.vi v5, v3, 1
    vslideup.vi v6, v4, 1
    vslidedown.vi v3, v3, 1
    vslidedown.vi v4, v4, 1

    vmv.v.i v0, 1
    # v2 += (a0b1)h
    vxor.vv v2, v2, v3, v0.t
    # v2 += (a1b1)l
    vxor.vv v2, v2, v4, v0.t

    vmv.v.i v0, 2
    # v1 += (a0b0)h,0
    vxor.vv v1, v1, v5, v0.t
    # v1 += (a1b0)l,0
    vxor.vv v1, v1, v6, v0.t

    # Now the 256bit product should be stored in (v2,v1)
    # v1 = (a0b1)l + (a0b0)h + (a1b0)l, (a0b0)l
    # v2 = (a1b1)h, (a1b0)h + (a0b1)h + (a1b1)l

    # Reduction
    # Let C := A*B = c3,c2,c1,c0 = v2[1],v2[0],v1[1],v1[0]
    # This is a slight variation of the Gueron's Montgomery reduction.
    # The difference being the order of some operations has been changed,
    # to make a better use of vclmul(h) instructions.

    # First step:
    # c1 += (c0 * P)l
    # vmv.v.i v0, 2
    vslideup.vi v3, v1, 1, v0.t
    vclmul.vx v3, v3, t3, v0.t
    vxor.vv v1, v1, v3, v0.t

    # Second step:
    # D = d1,d0 is final result
    # We want:
    # m1 = c1 + (c1 * P)h
    # m0 = (c1 * P)l + (c0 * P)h + c0
    # d1 = c3 + m1
    # d0 = c2 + m0

    #v3 = (c1 * P)l, 0
    vclmul.vx v3, v1, t3, v0.t
    #v4 = (c1 * P)h, (c0 * P)h
    vclmulh.vx v4, v1, t3

    vmv.v.i v0, 1
    vslidedown.vi v3, v3, 1

    vxor.vv v1, v1, v4
    vxor.vv v1, v1, v3, v0.t

    # XOR in the upper upper part of the product
    vxor.vv v2, v2, v1

    vrev8.v v2, v2
    vsse64.v v2, (a0), t4
    ret

.align  16
polymod:
        .dword 0x0000000000000001
        .dword 0xc200000000000000
