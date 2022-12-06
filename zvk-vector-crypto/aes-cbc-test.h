// XXX: License
#ifndef _AES_CBC_TESTS
#define _AES_CBC_TESTS

struct aes_cbc_test {
	uint8_t key[32];
	uint8_t iv[16];
	uint8_t *plaintext;
	uint8_t *ciphertext;
	int plaintextlen;
	bool encrypt;
	/* Everything needs to be aligned to 16 bytes. */
	char foo[15];
};

struct aes_cbc_test_suite {
	const char *name;
	int count;
	int keylen;
	struct aes_cbc_test *tests;
};

#endif
