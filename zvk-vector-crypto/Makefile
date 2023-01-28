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
VLEN?=256
LDFLAGS?=

AS?=$(TARGET)-as
CC?=$(TARGET)-gcc
LD?=$(TARGET)-gcc

MARCH_EXT_FLAGS=_zvkb_zvkns

# By default run the GCM tests using both zvkg and zvkb extensions.
# If your implementation doesn't support Zvkg set the SKIP_ZVKG env.
ifndef SKIP_ZVKG
MARCH_EXT_FLAGS:=$(MARCH_EXT_FLAGS)_zvkg
DFLAGS+=-DUSE_ZVKG
endif

CFLAGS?=-march=rv64gcv$(MARCH_EXT_FLAGS)
CFLAGS+=-Wall
LDFLAGS+=-static
SPIKE_FLAGS?=--varch=vlen:$(VLEN),elen:64 --isa=rv64gcv$(MARCH_EXT_FLAGS)

TEST_VECTORS_DIR=test-vectors

CBC_VECTORS=\
	CBCGFSbox128.h    \
	CBCGFSbox256.h    \
	CBCKeySbox128.h   \
	CBCKeySbox256.h   \
	CBCMMT128.h       \
	CBCMMT256.h       \
	CBCVarKey128.h    \
	CBCVarKey256.h    \
	CBCVarTxt128.h    \
	CBCVarTxt256.h    \
	aes-cbc-vectors.h \

GCM_VECTORS=\
	aes-gcm-vectors.h    \
	gcmDecrypt128.h      \
	gcmDecrypt256.h      \
	gcmEncryptExtIV128.h \
	gcmEncryptExtIV256.h \

SUBDIR_CBC_VECTORS=$(CBC_VECTORS:%=$(TEST_VECTORS_DIR)/%)
SUBDIR_GCM_VECTORS=$(GCM_VECTORS:%=$(TEST_VECTORS_DIR)/%)

OBJECTS=\
	aes-cbc-test.o \
	aes-gcm-test.o \
	log.o \
	vlen-bits.o \
	zvkb-test.o \
	zvkb.o \
	zvkg.o \
	zvknh.o \
	zvkns.o \

default: aes-cbc-test aes-gcm-test zvkb-test

.PHONY: test-vectors
test-vectors: $(SUBDIR_CBC_VECTORS) $(SUBDIR_GCM_VECTORS)

$(SUBDIR_CBC_VECTORS):
	python3 gentests.py cbc

$(SUBDIR_GCM_VECTORS):
	python3 gentests.py gcm

%.s: %.c test-vectors
	$(CC) -S $(CFLAGS) $(DFLAGS) -o $@ $<

$(OBJECTS): %.o: %.s
	$(AS) -c $(CFLAGS) -o $@ $^

aes-cbc-test: aes-cbc-test.o zvkns.o vlen-bits.o log.o
	$(LD) $(LDFLAGS) -o $@ $^

aes-gcm-test: aes-gcm-test.o zvkns.o zvkb.o zvkg.o
	$(LD) $(LDFLAGS) -o $@ $^

zvkb-test: zvkb-test.o zvkb.o
	$(LD) $(LDFLAGS) -o $@ $^

.PHONY: run-aes-cbc
run-aes-cbc: aes-cbc-test
	$(SPIKE) $(SPIKE_FLAGS) $(PK) $<

.PHONY: run-aes-gcm
run-aes-gcm: aes-gcm-test
	$(SPIKE) $(SPIKE_FLAGS) $(PK) $<

.PHONY: run-zvkb
run-zvkb: zvkb-test
	$(SPIKE) $(SPIKE_FLAGS) $(PK) $<

.PHONY: run-tests
run-tests: run-aes-cbc run-aes-gcm run-zvkb

.PHONY: clean
clean:
	rm -f $(SUBDIR_CBC_VECTORS)
	rm -f $(SUBDIR_GCM_VECTORS)
	rm -f *.o
	rm -f aes-cbc-test
	rm -f aes-gcm-test
	rm -f zvkb-test
