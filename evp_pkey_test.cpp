#include <iostream>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "evp_pkey_test.h"

static int HexStrTobyte(char* str, unsigned char* out, unsigned int* outlen)
{
	char* p = str;
	char high = 0, low = 0;
	int tmplen = strlen(p), cnt = 0;
	tmplen = strlen(p);
	while (cnt < (tmplen / 2))
	{
		high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p)-48 - 7 : *(p)-48;
		out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
		p++;
		cnt++;
	}
	if (tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

	if (outlen != NULL) *outlen = tmplen / 2 + tmplen % 2;
	return tmplen / 2 + tmplen % 2;
}


EVP_PKEY* gen_evp_pkey()
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
#if 1
    EVP_PKEY* pkey = 0;
    EVP_PKEY_CTX* ctx;

     unsigned char priv[128] = {0};
    size_t len = 0;

   unsigned char out[128];
    unsigned char out2[128] ={0};
 
    //ctx = EVP_PKEY_CTX_new_from_name(libctx, "SM2", NULL);
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
        /* Error */
   
    len = do_encrypt(pkey, out, (const unsigned char*)"1234",4);
  
     len = do_decrypt(pkey, out2, out,len);
    out2[len] = 0;
     printf("%s \r\n",out2);

    len = 128;
    EVP_PKEY_get_raw_private_key(pkey,priv,&len);
    printf("the priv key len is: %d\r\n",(int)len);
    for(int i=0;i<len;i++)
    {
        printf("%02x ",priv[i]);
    }
    printf("\r\n");
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

void test_sm2()
{
    EVP_PKEY* pkey = gen_evp_pkey();

    unsigned char out[128] = {0};
    unsigned char in[256];
    size_t inlen =0;

    HexStrTobyte((char*)"594db4130a40cff748678554ea10c0beda0ec881f1a896a4bc2f1ad847fa2de1ac0cac00cd52fd8efa2eb97093fce5c6227a7836f67086b448f6ab421a70aababbabd54b27c3bf1f600d9c03086b0f193b7090a382bb6610183c57fc4fe3b13cd59e157058eb679d69bf",
    in,(unsigned int*)&inlen);
    printf("the inlen is: %d\r\n",(int)inlen);

    do_decrypt( pkey,out, in, inlen);

    printf("the plaintext is: %s\r\n",out);
    
}