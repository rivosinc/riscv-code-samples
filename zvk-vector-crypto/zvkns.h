// XXX: License
#ifndef _ZVKNS_H
#define _ZVKNS_H

uint64_t
zvkns_aes128_encode_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const void* key128
);

uint64_t
zvkns_aes128_decode_rk_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const char key[16]
);

uint64_t
zvkns_aes256_encode_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const void* key256
);

uint64_t
zvkns_aes256_decode_rk_vv(
   void* dest,
   const void* src,
   uint64_t n,
   const char key[32]
);

#endif	/* _ZVKNS_H */
