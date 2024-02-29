#ifndef EVP_PKEY_TEST_H
#define EVP_PKEY_TEST_H
#include <openssl/evp.h>
#include <openssl/ec.h>

#ifdef __cpluscplus
extern "C"{
#endif

void test_sm2();


EVP_PKEY* gen_evp_pkey();

EVP_PKEY* setPriKey(const char* privkey_hex);

EVP_PKEY* setPubKey(const char* pubkey_hex);

EVP_PKEY* getPriKey(const unsigned char* priKeyBuf,int keyLen,const unsigned char* pubKeyBuf,int pubKeyLen);

EVP_PKEY* getPubKey(const unsigned char* pubKeyBuf,int kenLen);

//EC_KEY *setKey(const char *pub_X_hex, const char *pub_Y_hex, const char *privkey_hex);

size_t do_encrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);


size_t do_decrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen);

#ifdef __cpluscplus
}
#endif

#endif
