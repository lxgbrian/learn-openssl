#include <iostream>
#include <iomanip>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include "util.h"
#include "evp_test_aes.h"

const static unsigned char test_key[16] ={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                                0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

const static unsigned char test_iv[16] ={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

const static unsigned char test_plain_text[16] ={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
                                            0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
int evp_test_sync_enc(const char* algo,int num)
{
    OSSL_LIB_CTX* libctx = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    EVP_CIPHER* cipher = NULL;

    unsigned char test_output[64];
    int out_len = 0;

    int result = 0;

    long start;
    long end ;


    libctx = OSSL_LIB_CTX_new();
    if(libctx == NULL){
        std::cout << "the OSSL_LIB_CTX_new() failed." << std::endl;
        goto cleanup;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
    {
        std::cout << "the EVP_CIPHER_CTX_new() failed." << std::endl;
        goto cleanup;
    }

    cipher = EVP_CIPHER_fetch(libctx,algo,/*"aes-128-ecb",*/NULL);
    if(cipher == NULL)
    {
        std::cout << "the EVP_CIPHER_fetch() faile." << std::endl;
        goto cleanup;
    }

    if( EVP_EncryptInit(ctx,cipher,test_key,test_iv) == 0)
    {
        std::cout << "the EVP_EncryptInit failed." << std::endl;
        goto cleanup;
    }

    start = timestamp();
    for(int i=0;i<num;i++)
    {

        if(EVP_EncryptUpdate(ctx,test_output,&out_len,test_plain_text,sizeof(test_plain_text)) == 0)
        {
            std::cout << "the EVP_EncryptUpdate() failed." << std::endl;
            goto cleanup;
        }
    }
    end = timestamp();
    std::cout << "calc " << num << " the " << algo << " elapsed: " << end -start << std::endl;
    std::cout << "the output len is : " << out_len << std::endl;


    if(EVP_EncryptFinal_ex(ctx,test_output+out_len,&out_len) == 0)
    {
        std::cout << "the EVP_EncryptFinal() failed." << std::endl;
        goto cleanup;
    }

     std::cout << "the output len is : " << out_len << std::endl;

    for(int i=0;i<sizeof(test_output);i++){
        std::cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (test_output[i]&0xFF) << ' ';
    }

    std::cout << std::dec << std::endl;

   

    EVP_CIPHER_CTX_cleanup(ctx);

    result = 1;
cleanup:

    EVP_CIPHER_free(cipher);

    EVP_CIPHER_CTX_free(ctx);

    OSSL_LIB_CTX_free(libctx);    

    return result;
}