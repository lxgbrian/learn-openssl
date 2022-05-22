#include <iostream>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include "evp_test_digest.h"
#include "evp_test_aes.h"
#include "evp_test_rand.h"
#include "evp_pkey_test.h"
#include "c11_test.h"
#include "c11_base64.h"


int main()
{
    
    const unsigned char in[6] = {0x30,0x31,0x32,0x33,0x34,0x35};

    char out[128];
    unsigned char out2[128] ={0};
    int outlen = 128;
    int outlen2 = 128;
    for(int i=0;i<=sizeof(in);i++)
    {
        outlen = 127;
        base64_encode(in,i,out,&outlen);
        out[outlen] = 0;
        printf("the encode str: %s\r\n",out);
        outlen2 = 127;
        base64_decode(out,outlen,out2, &outlen2);
        printf("the out2 len is %d\r\n",outlen2);
        out2[outlen2] = 0;
        printf("the decode str: %s\r\n",out2);
    }

    //test_sm2();
    //evp_test_sync_enc("sm4",1000*1000);
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