#include <iostream>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "evp_test_rand.h"

int evp_test_rand()
{

    int result = 0;

    OSSL_LIB_CTX* libctx = NULL;

    EVP_RAND* rand = NULL;
    EVP_RAND_CTX* randctx = NULL;

    OSSL_PARAM param[4];
    OSSL_PARAM* p = param;

    unsigned char out_buf[100];
    unsigned char entropy[1000] = {0};
    unsigned char nonce[20] = {0};

    unsigned int strength = 48;

    libctx = OSSL_LIB_CTX_new();
    if(libctx == NULL){
        std::cout << "OSSL_LIB_CTX_new failed." << std::endl;
        goto cleanup;

    }

    rand = EVP_RAND_fetch(libctx,"TEST-RAND",NULL);
    if(rand == NULL){
        std::cout << "EVP_RAND_fetch failed." << std::endl;
        goto cleanup;
    }

    randctx = EVP_RAND_CTX_new(rand,NULL);
    if(randctx == NULL){
        std::cout << "EVP_RAND_CTX_new failed." << std::endl;
        goto cleanup;
    }

    *p++ = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH,&strength);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,entropy,sizeof(entropy));

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE,nonce,sizeof(nonce));

    *p = OSSL_PARAM_construct_end();

    EVP_RAND_instantiate(randctx,strength,0,NULL,0,param);

    EVP_RAND_generate(randctx,out_buf,sizeof(out_buf),strength,0,NULL,0);

    result = 1;

    cleanup:

    EVP_RAND_free(rand);

    EVP_RAND_CTX_free(randctx);
    
    OSSL_LIB_CTX_free(libctx);

    return result;
}