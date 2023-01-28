RISC-V Vector Crypto Proof of Concepts
======================================

This directory contains a set of examples designed to showcase the
functionality of RISC-V Vector Crypto ISA extensions.

Assembly (.s) files contain routines for algorithms utilizing instructions of a
given extension (denoted by the file name) directly while C (.c) files contain
all the support code required to verify them.

Specifically:

- aes-cbc-test.c - implements the AES-CBC with a 128 or 256 bit key using the
  Zvkns extension. The resulting program runs this implementation against NIST
  Known Answer Tests.
- aes-gcm-test.c - implements the AES-GCM with a 128 or 256 bit key using Zvkns,
  Zvkg and Zvkb extensions. The resulting program runs this implementation
  against NIST Known Answer Tests. In order to disable the usage of Zvkg
  extension the `SKIP_ZVKG` build variable can be set. See below for details.
- zvkb-test.c - shows proper usage of instructions in the Zvkb extension. The
  resulting program generates a set of random verification data and applies
  the Zvkb routines to that.
- sm4-test.c - implements the SM4 block cypher using the Zvksed extension. The
  resulting program runs this implementation against test vectors defined in
  SM4 IETF draft (see [1]).

Pre-requisites
--------------

To compile and run programs in this directory a several pre-requisites have to
be met:

1. `riscv64-linux-gnu` toolchain available in the `PATH`.
2. Vector Crypto compatible `binutils-gdb` available in the `PATH` overriding
   the above toolchain (see [2]).
3. Vector Crypto compatible Spike available in the `PATH` (see [3]).
4. The RISC-V Proxy kernel (`riscv-pk`) compiled and available in
   `~/RISC-V/riscv64-linux-gnu/bin/pk` (can be overridden with the `PK` make
   variable).

Build & run
-----------

The default `make` target (`default`) will compile the code for all examples.

To run all examples run the `run-tests` target.

### Example `make` invocations

```bash
# Build and run all examples with the default toolchain and riscv-pk location
make run-tests
# Build and run the aes-gcm-test example with the default toolchain and
# riscv-pk location.
make run-aes-gcm
# Override riscv-pk location
make run-tests PK=/opt/prefix/riscv64-linux-gnu/bin/pk
# Override target triplet and riscv-pk location
make run-tests TARGET=riscv64-unknown-linux-gnu \
               PK=/opt/prefix/riscv64-linux-gnu/bin/pk
```

### Make targets

- `default` - Build all examples.
- `clean` - Clean build artifacts.
- `aes-cbc-test` - Build the AES-CBC example.
- `aes-gcm-test` - Build the AES-GCM example.
- `sha-test` - Build the SHA example.
- `sm4-test` - Build the SM4 example.
- `zvkb-test` - Build the Zvkb example.
- `run-tests` - Build and run all examples.
- `run-aes-cbc` - Build and run the AES-CBC example in Spike.
- `run-aes-gcm` - Build and run the AES-GCM example in Spike.
- `run-sha` - Build and run the SHA example in Spike.
- `run-sm4` - Build and run the SM4 example in Spike.
- `run-zvkb` - Build and run the Zvkb example in Spike.

### Make variables

- `TARGET` - Target triplet to use. By default riscv64-linux-gnu.
- `PK` - Location of the riscv-pk binary. By default it's
  `~/RISC-V/$(TARGET)/bin/pk`.
- `SKIP_ZVKG` - Don't use the Zvkg extension in GCM tests.

See Makefile for more details.

References
----------

- [1] https://datatracker.ietf.org/doc/html/draft-ribose-cfrg-sm4-10
- [2] FIXME: Add the public binutils-gdb repo here.
- [3] FIXME: Add the public riscv-isa-sim repo here.
