// XXX: License
#ifndef _ZVKSH_H
#define _ZVKSH_H

void
zvksed_sm4_encode_vv(
    void* dest,
    const void* src,
    uint64_t length,
    const void* masterKey
);

void
zvksed_sm4_decode_vv(
    void* dest,
    const void* src,
    uint64_t length,
    const void* masterKey
);


#endif	/* _ZVKNS_H */
