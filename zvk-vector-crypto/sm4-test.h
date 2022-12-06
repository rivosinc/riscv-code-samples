#ifndef _SM4_TEST_H
#define _SM4_TEST_H

__attribute__((aligned(16)))
struct sm4_test_vector {
    uint32_t *message;
    uint32_t *output;
    uint32_t *master_key;
    size_t message_len;
    size_t iterarions;
    bool encrypt;
	char foo[3];
};

struct sm4_test_suite {
    const char *name;
    struct sm4_test_vector *vectors;
    size_t tests_count;
};

#endif
// _SM4_TEST_H
