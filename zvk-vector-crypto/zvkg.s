# SPDX-FileCopyrightText: Copyright (c) 2022 by Rivos Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Vector Carryless Multiply Accumulate over GHASH Galois-Field routine using
# the proposed Zvkg instructions (vghmac.vv).
#
# This code was developed to validate the design of the Zvkg extension,
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

# zvkg_ghash
#
# Performs one step of GHASH function as described in NIST GCM publication.
# It uses the vghmac instruction from zvkg extension.
#
#   zvkb_ghash(
#       uint64_t Y[2],     // a0
#       uint64_t X[2],     // a1
#       uint64_t H[2]      // a2
#   );
#
.balign 4
.global zvkg_ghash
zvkg_ghash:
    vsetivli x0, 4, e32, m1, ta, ma

    vle32.v v0, (a0)
    vle32.v v1, (a1)
    vle32.v v2, (a2)

    vghmac.vv v0, v1, v2
    vse32.v v0, (a0)
    ret
