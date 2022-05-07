#include <iostream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>

#include "evp_test_digest.h"

int evp_test_digest()
{
    std::cout << "this is a test of evp digest" << std::endl;
    //todo
    int result = 0;

    const char* in_message = "123456789";

    //get the openssl library context
    OSSL_LIB_CTX* library_context;

    
    EVP_MD* message_digest = NULL;
    const char* option_properties = NULL;

    EVP_MD_CTX* digest_context = NULL;
    unsigned int digest_length;
    unsigned char* digest_value = NULL;
    


    library_context = OSSL_LIB_CTX_new();
    if(library_context == NULL)
    {
        std::cout << "OSSL_LIB_CTX_new() return NULL" << std::endl;
        goto cleanup;
    }

    /*
    *Fetch a message digest by name
    *The algorithm name is case insensitive.
    *See providers(7) for details about algorithm fetching
    */
   
   message_digest = EVP_MD_fetch(library_context,"sm3",option_properties);
   if(message_digest == NULL){
       std::cout << "EVP_MD_fetch could not find sm3." << std::endl;
       goto cleanup;
   }

   /*Determine the length of the fetched digest type*/
   digest_length = EVP_MD_get_size(message_digest);
   if(digest_length == 0){
       std::cout << "EVP_MD_get_size returned invaild size." << std::endl;
       goto cleanup;
   }

    //allocate the digest value memory
   digest_value = (unsigned char*)OPENSSL_malloc(digest_length);
   if(digest_value == NULL){
       std::cout << "the malloc operation is failed." << std::endl;
       goto cleanup;
   }

   //get the digest context
   digest_context = EVP_MD_CTX_new();
   if(digest_context == NULL){
       std::cout << "EVP_MD_CTX_new failed." << std::endl;
       goto cleanup;
   }

   if(EVP_DigestInit(digest_context,message_digest) != 1){
       std::cout << "EVP_DigestInit failed." << std::endl;
       goto cleanup;
   }

    if(EVP_DigestUpdate(digest_context,in_message,strlen(in_message)) != 1)
    {
        std::cout << "EVP_DigestUpdate failed." << std::endl;
        goto cleanup;
    }

    if(EVP_DigestFinal(digest_context,digest_value,&digest_length) != 1)
    {
        std::cout << "EVP_DigestFinal failed." << std::endl;
    }

    //output the digest value
    for(int i=0;i<digest_length;i++){
        std::cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) <<  (digest_value[i]&0xFF) << ' ';
    }
    std::cout << std::endl;

    result = 1;

cleanup:
    EVP_MD_CTX_free(digest_context);
    OPENSSL_free(digest_value);

    EVP_MD_free(message_digest);
    OSSL_LIB_CTX_free(library_context);  

     return result;  
}