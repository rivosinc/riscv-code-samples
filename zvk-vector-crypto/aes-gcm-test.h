// XXX: License
#ifndef _AES_GCM_TESTS
#define _AES_GCM_TESTS

__attribute__((aligned(16)))
struct aes_gcm_test {
	uint8_t key[32];
	uint8_t *iv;
	uint8_t *ct;
	uint8_t *aad;
	uint8_t *tag;
	uint8_t *pt;
	int ivlen;
	int ctlen;
	int aadlen;
	int taglen;
	bool encrypt;
	bool expect_fail;
	uint8_t align[6];
};

struct aes_gcm_test_suite {
	struct aes_gcm_test *tests;
	const char *name;
	int keylen;
	int count;
};

#endif
