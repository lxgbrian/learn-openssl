#ifndef _C11_BASE64_H
#define _C11_BASE64_H

#define BASE64_OK               1
#define BASE64_ERROR_LEN        -1
#define BASE64_INVAILD_CHAR     -2


#ifdef __cplusplus
extern "C"{
#endif
    int base64_encode(const unsigned char* src,int inlen,char* out,int* outlen);

    int base64_decode(const char* src,int inlen,unsigned char* out,int* outlen);
#ifdef __cplusplus
}
#endif

#endif
