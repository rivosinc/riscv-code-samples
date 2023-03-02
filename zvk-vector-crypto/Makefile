# Copyright 2022 Rivos Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SDK_ROOT?=~/RISC-V
TARGET?=riscv64-linux-gnu
SPIKE?=spike
PK?=$(SDK_ROOT)/$(TARGET)/bin/pk
LDFLAGS?=

AS?=$(TARGET)-as
CC?=$(TARGET)-gcc
LD?=$(TARGET)-gcc

MARCH_EXT_FLAGS=_zvkb
CFLAGS?=-march=rv64gcv$(MARCH_EXT_FLAGS)
CFLAGS+=-Wall
LDFLAGS+=-static
# Note that each Spike invocation adds a --isa flag of the form
#    --varch=vlen:$(VLEN),elen:64
# with different values of VLEN.
COMMON_SPIKE_FLAGS?=--isa=rv64gcv$(MARCH_EXT_FLAGS)

TEST_VECTORS_DIR=test-vectors

C_OBJECTS=\
	zkb-test.o \

ASM_OBJECTS=\
	vlen-bits.o \
	zvkb.o \

default: zvkb-test

$(C_OBJECTS): %.o: %.c test-vectors
	$(CC) -c $(CFLAGS) -o $@ $<

$(ASM_OBJECTS): %.o: %.s
	$(AS) -c $(CFLAGS) -o $@ $^

zvkb-test: zvkb-test.o zvkb.o log.o vlen-bits.o
	$(LD) $(LDFLAGS) -o $@ $^

.PHONY: run-zvkb
run-zvkb: zvkb-test
	for VLEN in 64 128 256 512; do \
	    $(SPIKE) --varch=vlen:$${VLEN},elen:64 $(COMMON_SPIKE_FLAGS) $(PK) $< || exit 1; \
	done

.PHONY: run-tests
run-tests: run-zvkb

.PHONY: clean
clean:
	rm -f *.o
	rm -f zvkb-test
