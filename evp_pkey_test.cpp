#include <iostream>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "evp_pkey_test.h"
#include "util.h"

#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

EC_KEY *setKey(const char *pub_X_hex, const char *pub_Y_hex, const char *privkey_hex)
{

    BIGNUM *pubx = NULL;
    BIGNUM *puby = NULL;
    BIGNUM *priv = NULL;
    EC_KEY *key = NULL;
    EC_GROUP *gm_group = NULL;

    bool genOK = false;

    if (pub_X_hex != NULL && BN_hex2bn(&pubx, pub_X_hex) == NULL)
    {
        goto done;
    }
    if (pub_Y_hex != NULL && BN_hex2bn(&puby, pub_Y_hex) == NULL)
    {
        goto done;
    }
    if (privkey_hex != NULL && BN_hex2bn(&priv, privkey_hex) == NULL)
    {
        goto done;
    }

    key = EC_KEY_new();

    if (key == NULL)
    {
        goto done;
    }
    /*
    gm_group = create_EC_group(
        "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
        "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
        "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
        "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
        "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
        "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
        "1");
    */

    gm_group = EC_GROUP_new_by_curve_name(NID_sm2);

    if (EC_KEY_set_group(key, gm_group) == NULL)
    {
        goto done;
    }
    if (privkey_hex != NULL && EC_KEY_set_private_key(key, priv) == NULL)
    {
        goto done;
    }
    if (pub_X_hex != NULL && EC_KEY_set_public_key_affine_coordinates(key, pubx, puby) == NULL)
    {
        goto done;
    }

    genOK = true;

done:
    BN_free(pubx);
    BN_free(puby);
    BN_free(priv);
    if (genOK == false)
    {
        EC_GROUP_free(gm_group);

        EC_KEY_free(key);
        key = NULL;
    }

    return key;
}

EVP_PKEY *gen_evp_pkey()
{
#if 0
    //     EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    unsigned int len =0;
    unsigned char rawprikey[33] ={0};
    HexStrTobyte((char*)"00bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf",rawprikey,&len);
    printf("the len is: %d\r\n",len);
    for(int i=0;i<len;i++)
    {
        printf("%02x ",rawprikey[i]);
    }

    printf("\r\n");

    unsigned char rawpubkey[64] = {0};
    //HexStrTobyte((char*)"dc73ae455cf8abd0f7f68e5daa8b48f47ddb93eb7e42cb3d932f3203177e9866b3ad10a3742e6aca4770a7cbefd974edbd0a5c985f23e2bd0ef1329b707a2f53",rawpubkey,&len);

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SM2, 0, rawprikey, len);
    //pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_SM2, 0, rawpubkey, 64);
    if(pkey == 0)
    {
        printf("the new raw public key error!\r\n");

    }
    

    return pkey;
#endif

    EVP_PKEY *pkey = 0;
    EVP_PKEY_CTX *ctx;


    // ctx = EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (!ctx)
    {
        printf("the new ctx is error \r\n");
        goto error;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        printf("the keygen init is error \r\n");
        goto error;
    }
    /* Error */

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        printf("the keygen is error \r\n");
        goto error;
    }
   
   /*
    EVP_PKEY_get_raw_private_key(pkey, priv, &len);
    printf("the priv key len is: %d\r\n", (int)len);
    for (int i = 0; i < len; i++)
    {
        printf("%02x ", priv[i]);
    }
    printf("\r\n");
    */
error:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return pkey;

}

size_t do_encrypt(EVP_PKEY *key, unsigned char *out, const unsigned char *in,
                  size_t inlen)
{
    size_t ret = 0;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

size_t do_decrypt(EVP_PKEY *key, unsigned char *out, const unsigned char *in,
                  size_t inlen)
{
    size_t ret = inlen;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_decrypt(ctx, out, &ret, in, inlen);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int ds_sign(EVP_PKEY *pkey, const unsigned char *message,
            const size_t message_len, unsigned char *sig, size_t *sig_len)
{
    const unsigned char sm2_id[] = "1234567812345678";
    const unsigned int sm2_id_len = sizeof(sm2_id);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx, sctx);

    EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);

    EVP_DigestSign(md_ctx, NULL, sig_len, message, message_len);
    sig = (unsigned char *)realloc(sig, *sig_len);
    EVP_DigestSign(md_ctx, sig, sig_len, message, message_len);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_CTX_free(sctx);
    return 0;
}

int ds_verify(EVP_PKEY *pkey, const unsigned char *message,
              const size_t message_len, unsigned char *sig, size_t sig_len)
{
    const unsigned char sm2_id[] = "1234567812345678";
    const unsigned int sm2_id_len = sizeof(sm2_id);

    EVP_MD_CTX *md_ctx_verify = EVP_MD_CTX_new();
    EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(sctx, sm2_id, sm2_id_len);
    EVP_MD_CTX_set_pkey_ctx(md_ctx_verify, sctx);

    EVP_DigestVerifyInit(md_ctx_verify, NULL, EVP_sm3(), NULL, pkey);

    if ((EVP_DigestVerify(md_ctx_verify, sig, sig_len, message, message_len)) !=
        1)
    {
        printf("Verify SM2 signature failed!\n");
    }
    else
    {
        printf("Verify SM2 signature succeeded!\n");
    }

    EVP_PKEY_CTX_free(sctx);
    EVP_MD_CTX_free(md_ctx_verify);
    return 0;
}

void test_sm2()
{
    unsigned char out[256] = {0};
    unsigned char in[256];
    size_t inlen = 0;
    size_t outlen = 0;
    const char *pub_x = "dc73ae455cf8abd0f7f68e5daa8b48f47ddb93eb7e42cb3d932f3203177e9866";
    const char *pub_y = "b3ad10a3742e6aca4770a7cbefd974edbd0a5c985f23e2bd0ef1329b707a2f53";
    const char *priv = "bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf";
    EC_KEY *ecckey = setKey(pub_x, pub_y, priv);

    /*
        EVP_PKEY* pkey = 0;
        EVP_PKEY_CTX* ctx;

        //ctx = EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
        if (!ctx)
        {
            printf("the new ctx is error \r\n");
            return;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0)
        {
            printf("the keygen init is error \r\n");
            return;
        }


        if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            printf("the keygen is error \r\n");
             return;
        }
     */

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set_type(pkey, EVP_PKEY_SM2);

    int ret = EVP_PKEY_set1_EC_KEY(pkey, ecckey);
    printf("the set key result: %d \r\n", ret);

    const char *cipherHex = "30730220594db4130a40cff748678554ea10c0beda0ec881f1a896a4bc2f1ad847fa2de1022100ac0cac00cd52fd8efa2eb97093fce5c6227a7836f67086b448f6ab421a70aaba04209c03086b0f193b7090a382bb6610183c57fc4fe3b13cd59e157058eb679d69bf040abbabd54b27c3bf1f600d";
    // const char* cipherHex = "594db4130a40cff748678554ea10c0beda0ec881f1a896a4bc2f1ad847fa2de1ac0cac00cd52fd8efa2eb97093fce5c6227a7836f67086b448f6ab421a70aababbabd54b27c3bf1f600d9c03086b0f193b7090a382bb6610183c57fc4fe3b13cd59e157058eb679d69bf";

    HexStrTobyte((char *)cipherHex, in, (unsigned int *)&inlen);
    printf("the inlen is: %d\r\n", (int)inlen);

    long start = timestamp();
    for (int i = 0; i < 1000; i++)
    {
        outlen = do_decrypt(pkey, out, in, inlen);
    }
    long end = timestamp();

    printf("the decrypt elapsed time: %ld \r\n", end - start);

    out[outlen] = 0;
    printf("the plaintext is: %s\r\n", out);

    start = timestamp();
    for (int i = 0; i < 1000; i++)
    {
        outlen = do_encrypt(pkey, out, (const unsigned char *)"1234567890123456", 16);
    }
    end = timestamp();
    printf("the encrypt elapsed time: %ld \r\n", end - start);

    start = timestamp();
    for (int i = 0; i < 1000; i++)
    {
        EVP_PKEY* pkey = gen_evp_pkey();
        EVP_PKEY_free(pkey);
    }
    end = timestamp();
    printf("the gen key  elapsed time: %ld \r\n", end - start);

}