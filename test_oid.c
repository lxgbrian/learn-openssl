#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include <string.h>

#include "util.h"
#include "test_oid.h"
typedef struct oid_test_st{
        int ret;
        char s;
};



OID_TEST* test_oid()
{
    static struct oid_test_st g_oid_test;

    unsigned char out[256];

    ASN1_OBJECT *obj = OBJ_nid2obj(NID_SM2_with_SM3);

    int len = OBJ_length(obj);
    const unsigned char* pd = OBJ_get0_data(obj);
    printf("the obj len is %d\r\n",len);
    int hexlen = 256;
    timestamp();
    byteToHexStr((unsigned char*)pd,len,(char*)out,&hexlen);
    out[hexlen ] = 0;

    printf("the obj data is: %s\r\n",out);

    return (OID_TEST*)&g_oid_test;
}