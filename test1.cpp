#include <iostream>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "evp_test_digest.h"
#include "evp_test_aes.h"
#include "evp_test_rand.h"
#include "evp_pkey_test.h"
#include "c11_test.h"
#include "c11_base64.h"
#include "util.h"
#include "test_oid.h"

int main()
{
    
   //test_oid();

    //test_sm2();
    evp_test_sync_enc("sm4",1000*10000);
    /*
    evp_test_aes();

    
    evp_test_digest();

    evp_test_rand();

    std_test_container();

    std::cout << "the c version: " << __STDC__ << std::endl;
    auto a = 1;
    std::cout << "Hello world! " << std::endl << "the value is: " << a << std::endl;
    */

   
    return 1;
}