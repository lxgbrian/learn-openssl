#include <iostream>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "evp_pkey_test.h"

EVP_PKEY* gen_evp_pkey()
{

    //     EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    unsigned char rawprikey[32] ={0};
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SM2, 0,
                                        rawprikey, 32);
    return pkey;
#if 0
    //ctx = EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!ctx)
        goto error;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto error;
        /* Error */

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto error;
        /* Error */
    
    
error:
    if(ctx)
        EVP_PKEY_CTX_free(ctx);
    return pkey;
#endif

}

size_t do_encrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen)
{
    size_t ret        = 0;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

size_t do_decrypt(EVP_PKEY* key, unsigned char* out, const unsigned char* in,
                  size_t inlen)
{
    size_t ret        = inlen;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int ds_sign(EVP_PKEY* pkey, const unsigned char* message,
            const size_t message_len, unsigned char* sig, size_t* sig_len)
{
    const unsigned char sm2_id[]  = "1234567812345678";
    const unsigned int sm2_id_len = sizeof(sm2_id);

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX* sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);

    EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);

    EVP_DigestSign(md_ctx, NULL, sig_len, message, message_len);
    sig = (unsigned char*)realloc(sig, *sig_len);
    EVP_DigestSign(md_ctx, sig, sig_len, message, message_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(sctx);
    return 0;
}

int ds_verify(EVP_PKEY* pkey, const unsigned char* message,
              const size_t message_len, unsigned char* sig, size_t sig_len)
{
    const unsigned char sm2_id[]  = "1234567812345678";
    const unsigned int sm2_id_len = sizeof(sm2_id);

    EVP_MD_CTX* md_ctx_verify = EVP_MD_CTX_new();
    EVP_PKEY_CTX* sctx        = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);

    EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey);

    if ((EVP_DigestVerify(md_ctx_verify, sig, sig_len, message, message_len)) !=
        1) {
        printf("Verify SM2 signature failed!\n");
    } else {
        printf("Verify SM2 signature succeeded!\n");
    }

    EVP_PKEY_CTX_free(sctx);
    EVP_MD_CTX_free(md_ctx_verify);
    return 0;
}