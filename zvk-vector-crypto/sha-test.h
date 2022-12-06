// XXX: License
#ifndef _SHA256_TESTS
#define _SHA256_TESTS

struct sha_test {
	uint8_t md[64];
	uint8_t *msg;
	int msglen;
	uint8_t align[4];
};

#define sha256_test sha_test
#define sha512_test sha_test

struct sha_test_suite {
	struct sha_test *tests;
	const char *name;
	int keylen;
	int count;
};

#define sha256_test_suite sha_test_suite
#define sha512_test_suite sha_test_suite

#endif
