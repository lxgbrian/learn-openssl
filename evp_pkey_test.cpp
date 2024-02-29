#include <iostream>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "evp_pkey_test.h"
#include "util.h"

#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif
/**
 * Deprecated

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
   
    gm_group_old = create_EC_group(
        "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
        "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
        "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
        "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
        "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
        "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
        "1");
    

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
*/

EVP_PKEY *gen_evp_pkey()
{
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
    
    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        printf("the keygen is error \r\n");
        goto error;
    }
   
    
    
error:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return pkey;

}

EVP_PKEY* getPriKey(const unsigned char* srcKeyBuf,int keyLen,const unsigned char* pubKeyBuf,int pubKeyLen)
{
    unsigned char priv[121] ={0x30,0x77,0x02,0x01,0x01,0x04,0x20,0x2b,0xba,0x72,0x8e,0x8a,0xe9,0x6f,0x17,0x93,0x22,0xbf,0x8a,0xb6,0xe2,0xb4,0x96,0x75,0x10,0x4d,0x41,0x80,0x61,0x91,0xb7,0x82,0x24,0x3b,0x9a,0x91,0x2d,0x9a,0x67,0xa0,0x0a,0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x82,0x2d,0xa1,0x44,0x03,0x42,0x00,0x04,0x2e,0xd0,0x64,0x25,0xe0,0x1d,0x0f,0xa4,0x2b,0x9a,0x5d,0x99,0x66,0x62,0x8b,0xe8,0x3c,0x8e,0x79,0x2b,0x5c,0x46,0xae,0x90,0x27,0x14,0xbc,0x74,0xa2,0x54,0xb4,0x0e,0x0d,0xdd,0x28,0x04,0x39,0x35,0xb7,0xca,0x11,0x55,0xdb,0xd8,0x1a,0x38,0xbb,0x66,0x49,0xb1,0x5b,0x91,0xbd,0x94,0x33,0xa9,0x55,0x7b,0x7b,0x00,0xdc,0xc2,0x57,0x7d};
    int ret;
    int len;
    
    unsigned char* outp;

    //EVP_PKEY* pKey=EVP_PKEY_new();
    //EVP_PKEY_set_type(pKey,EVP_PKEY_SM2);//gen_evp_pkey();
    EVP_PKEY* pKey=gen_evp_pkey();
    
    EVP_PKEY* r=0;
    /*
    len = i2d_PrivateKey(pKey, NULL);
    if(len < 0)
    {
        goto error;
    }
    
    outp = priv;
    ret = i2d_PrivateKey(pKey,&outp);
    if( ret > 0)
    {
        printf("the priv key len is: %d\r\n", (int)ret);

        for (int i = 0; i < ret; i++)
        {
            printf("%02x ", priv[i]);
        }
        printf("\r\n");
    }
    else
    {
        goto error;
        printf("get the raw key error!\r\n");
    }    
    */
    //replace the key value 
    memcpy(priv+7,srcKeyBuf,keyLen);
    memcpy(priv+121-65,pubKeyBuf,pubKeyLen);
    
    outp = priv;
    r = d2i_PrivateKey(EVP_PKEY_SM2,&pKey,(const unsigned char**)&outp,sizeof(priv));
    
//verify the pub key
    len = i2d_PublicKey(r, NULL);
    if(len < 0)
    {
        goto error;
    }
    
    outp = priv;
    ret = i2d_PublicKey(r,&outp);
    if( ret > 0)
    {
        printf("the pub key len is: %d\r\n", (int)ret);

        for (int i = 0; i < ret; i++)
        {
            printf("%02x ", priv[i]);
        }
        printf("\r\n");
    }
    else
    {
        goto error;
        printf("get the pub key error!\r\n");
    }

    return r;
error:
    return NULL;

}

EVP_PKEY* getPubKey(const unsigned char* srcKeyBuf,int keyLen)
{
    unsigned char pub[300];
    int ret;
    int len;
    
    unsigned char* outp;

    EVP_PKEY* pKey=gen_evp_pkey();

     EVP_PKEY* r = 0;
/*
    len = i2d_PublicKey(srcKey, NULL);
    if(len < 0)
    {
        goto error;
    }
    
    outp = pub;
    ret = i2d_PublicKey(srcKey,&outp);
    if( ret > 0)
    {
        printf("the pub key len is: %d\r\n", (int)ret);

        for (int i = 0; i < ret; i++)
        {
            printf("%02x ", pub[i]);
        }
        printf("\r\n");
    }
    else
    {
        goto error;
        printf("get the pub key error!\r\n");
    }
    */    
    //outp = (unsigned char*)srcKeyBuf;
    r =  d2i_PublicKey(EVP_PKEY_SM2,&pKey,(const unsigned char**)&srcKeyBuf,keyLen);
    if(r)
    {
        printf("set public  key successful!\r\n ");
    }
    else
    {
        printf("set public key failed!\r\n");
    }
    return r;
error:
    return NULL;

}

EVP_PKEY* setPriKey(const char* privkey_hex)
{
    EVP_PKEY *pkey = NULL;
    unsigned int len =0;
    unsigned char rawprikey[33] ={0};
    //HexStrTobyte((char*)"00bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf",rawprikey,&len);
    HexStrTobyte((char*)privkey_hex,rawprikey,&len);
    printf("the len is: %d\r\n",len);
    for(int i=0;i<len;i++)
    {
        printf("%02x ",rawprikey[i]);
    }

    printf("\r\n");

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_SM2, 0, rawprikey, len);
    if(pkey == 0)
    {
        printf("the new raw private key error!\r\n");

    }
    return pkey;
}


EVP_PKEY* setPubKey(const char* pubkey_hex)
{
    EVP_PKEY *pkey = NULL;
    unsigned int len =0;
    unsigned char rawpubkey[65] = {0};
    HexStrTobyte((char*)pubkey_hex,rawpubkey,&len);

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_SM2, 0, rawpubkey, 64);
    if(pkey == 0)
    {
        printf("the new raw public key error!\r\n");

    }

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
    //sig = (unsigned char *)realloc(sig, *sig_len);
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
    /*
    const char *pub_x = "dc73ae455cf8abd0f7f68e5daa8b48f47ddb93eb7e42cb3d932f3203177e9866";
    const char *pub_y = "b3ad10a3742e6aca4770a7cbefd974edbd0a5c985f23e2bd0ef1329b707a2f53";
    const char *priv = "bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf";
    */
    //const char *pub_hex = "00dc73ae455cf8abd0f7f68e5daa8b48f47ddb93eb7e42cb3d932f3203177e9866b3ad10a3742e6aca4770a7cbefd974edbd0a5c985f23e2bd0ef1329b707a2f53";

    //const char *priv_hex = "bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf";

    //EVP_PKEY *privKey = setPriKey(priv_hex);
    //EVP_PKEY* pubKey = setPubKey(pub_hex);

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

    const char *pub_hex = "04dc73ae455cf8abd0f7f68e5daa8b48f47ddb93eb7e42cb3d932f3203177e9866b3ad10a3742e6aca4770a7cbefd974edbd0a5c985f23e2bd0ef1329b707a2f53";

    const char *priv_hex = "bb1b06660e81271c51db324707073c2c826baed0cd14e99d8933ed300fe8cbdf";
    unsigned int len =0;
    unsigned int len2 = 0;
    unsigned char buf[128] = {0};
    unsigned char buf2[128] ={0};
    
    unsigned char sig[128]={0};
    unsigned int sig_len = 0;

    EVP_PKEY *pkey = gen_evp_pkey();
   
    outlen = do_encrypt(pkey, out, (const unsigned char *)"1234567890123456", 16);
    
    memcpy(in,out,outlen);
    inlen = outlen;

    outlen = do_decrypt(pkey, out, in, inlen);
    out[outlen] = 0;
    printf("the plaintext is: %s\r\n", out);

    ds_sign(pkey,(const unsigned char*)"1234",4,sig,(size_t*)&sig_len);
    ds_verify(pkey,(const unsigned char*)"1234",4,sig,sig_len);

    HexStrTobyte((char*)pub_hex,buf,&len);
    EVP_PKEY *pubKey = getPubKey(buf,len);

    HexStrTobyte((char*)priv_hex,buf2,&len2);
    EVP_PKEY *priKey = getPriKey(buf2,len2,buf,len);

    ds_sign(priKey,(const unsigned char*)"1234",4,sig,(size_t*)&sig_len);
    ds_verify(pubKey,(const unsigned char*)"1234",4,sig,sig_len);

    printf("encrypt-----\r\n");
    if(pubKey)
    {
        outlen = do_encrypt(pubKey, out, (const unsigned char *)"1234567890123456", 16);
        printf("encrypt end -----\r\n");
    }

    memcpy(in,out,outlen);
    inlen = outlen;
    printf("decrypt------\r\n");
    if(priKey)
    {
        outlen = do_decrypt(priKey, out, in, inlen);
        out[outlen] = 0;
        printf("the plaintext is: %s\r\n", out);
        printf("decrypt end----\r\n");
    }
    

    
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(priKey);    
    EVP_PKEY_free(pubKey);    

}