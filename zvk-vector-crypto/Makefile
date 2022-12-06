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

AS?=$(TARGET)-as
CC?=$(TARGET)-gcc
LD?=$(TARGET)-gcc

MARCH_EXT_FLAGS=_zvkns_zvknhb
CFLAGS+=-march=rv64gcv$(MARCH_EXT_FLAGS)
LDFLAGS+=-static
SPIKE_FLAGS?=--varch=vlen:$(VLEN),elen:64 --isa=rv64gcv$(MARCH_EXT_FLAGS)

TEST_VECTORS_DIR=test-vectors
CBC_VECTORS=aes-cbc-vectors.h \
	    CBCKeySbox128.h   \
	    CBCGFSbox128.h    \
	    CBCMMT128.h       \
	    CBCVarKey128.h    \
	    CBCVarTxt128.h    \
	    CBCKeySbox256.h   \
	    CBCGFSbox256.h    \
	    CBCMMT256.h       \
	    CBCVarKey256.h    \
	    CBCVarTxt256.h
SHA_VECTORS=sha256-vectors.h \
	    SHA256LongMsg.h  \
	    SHA256ShortMsg.h \
	    sha512-vectors.h \
	    SHA512LongMsg.h  \
	    SHA512ShortMsg.h

SUBDIR_CBC_VECTORS=$(CBC_VECTORS:%=$(TEST_VECTORS_DIR)/%)
SUBDIR_SHA_VECTORS=$(SHA_VECTORS:%=$(TEST_VECTORS_DIR)/%)

OBJECTS=aes-cbc-test.o \
	sha-test.o \
	zvkns.o \
	zvknh.o

default: aes-cbc-test sha-test

.PHONY: test-vectors
test-vectors: $(SUBDIR_CBC_VECTORS) $(SUBDIR_SHA_VECTORS)

$(SUBDIR_CBC_VECTORS):
	python3 gentests.py cbc

$(SUBDIR_SHA_VECTORS):
	python3 gentests.py sha256 sha512

%.s: %.c test-vectors
	$(CC) -S $(CFLAGS) -o $@ $<

$(OBJECTS): %.o: %.s
	$(AS) -c $(CFLAGS) -o $@ $^

aes-cbc-test: aes-cbc-test.o zvkns.o
	$(LD) $(LDFLAGS) -o $@ $^

sha-test: sha-test.o zvknh.o
	$(LD) $(LDFLAGS) -o $@ $^

.PHONY: run-aes-cbc
run-aes-cbc: aes-cbc-test
	$(SPIKE) $(SPIKE_FLAGS) $(PK) $<

.PHONY: run-sha
run-sha: sha-test
	$(SPIKE) $(SPIKE_FLAGS) $(PK) $<

.PHONY: run-tests
run-tests: run-aes-cbc run-sha

.PHONY: clean
clean:
	rm -f $(SUBDIR_CBC_VECTORS)
	rm -f $(SUBDIR_SHA_VECTORS)
	rm -f *.o
	rm -f aes-cbc-test
	rm -f sha-test
