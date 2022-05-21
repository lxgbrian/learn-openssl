#ifndef EVP_PKEY_TEST_H
#define EVP_PKEY_TEST_H
#include <openssl/evp.h>
#include <openssl/ec.h>

EVP_PKEY* gen_evp_pkey();

size_t do_encrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);


size_t do_decrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);

#endif
