#include <string.h>
#include "c11_base64.h"

#define  u32_t unsigned long

static const char base64_encode_table[64] = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                                'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
                                '0','1','2','3','4','5','6','7','8','9','+', '/' };

static const char base64_decode_table[256] ={ /*0x00*/0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                       /*0x10*/ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                       /*0x20*/ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,62,  0xFF,0xFF,0xFF,63,
                                       /*0x30*/ 52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                       /*0x40*/ 0xFF,0,   1,   2,   3,   4,    5,  6,   7,   8,   9,   10,  11,  12,  13,  14,
                                       /*0x50*/ 15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  0xFF,0xFF,0xFF,0xFF,0xFF,
                                       /*0x60*/ 0xFF,26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                       /*0x70*/ 41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  0xFF,0xFF,0xFF,0xFF,0xFF,
                                       /*0x80*/ 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,};                                

int base64_encode(const unsigned char* src,int inlen,char* out,int* outlen)
{
    int tlen = inlen*4/3;
    int padlen = (inlen%3);
    int i=0;
    int j = 0;
    int k = 0;
    int index = 0;
    u32_t t;    
    if(padlen)
    {
        padlen = 3 - padlen;
    }

    //verify the out buffer length is enough or not
    if( (*outlen) < tlen + padlen)
    {
        *outlen = tlen + padlen;
        return BASE64_OK;
    }

    for(i=0;i<inlen/3;i++,index+=3)
    {
        
        t = (src[index]<<16) + (src[index+1]<<8) + src[index+2];
    
        out[j++] = base64_encode_table[(t>>18)&0x3F];
        out[j++] = base64_encode_table[(t>>12)&0x3F];
        out[j++] = base64_encode_table[(t>>6)&0x3F];
        out[j++] = base64_encode_table[t&0x3F];
        
    }
    if( index == inlen-2)
    {
        t = (src[index]<<10) + (src[index+1]<<2);
        
        out[j++] = base64_encode_table[(t>>12)&0x3F];
        out[j++] = base64_encode_table[(t>>6)&0x3F];
        out[j++] = base64_encode_table[t&0x3F];
        out[j++] = '=';
    }
    else if(index == inlen -1 )
    {
        t = src[index]<<4;
         out[j++] = base64_encode_table[(t>>6)&0x3F];
        out[j++] = base64_encode_table[t&0x3F];
        out[j++] = '=';
        out[j++] = '=';
    }

    *outlen = j;

    return BASE64_OK;
}

int base64_decode(const char* src,int inlen,unsigned char* out,int* outlen)
{
    int i =0;
    int j = 0;
    int index = 0;
    u32_t t;
    char tc;
    int padlen = 0;

    if(inlen < 2)
    {
        return BASE64_ERROR_LEN;
    }
    if(src[inlen-1] == '=')
    {
        padlen += 1;
        inlen--;
    }
    if(src[inlen-1] == '=')
    {
        padlen += 1;
        inlen--;
    }

    t = inlen*3/4 + 3- padlen;
    if( *outlen < t)
    {
        *outlen = t;
        return BASE64_OK;
    }

    for(i=0;i<inlen/4;i++)
    {
        t = 0;
        for(j=0;j<4;j++)
        {
            tc = src[i*4+j];
            if(base64_decode_table[ tc ] == 0xFF)
            {
                return BASE64_INVAILD_CHAR;
            }
            t = (t<<6) + base64_decode_table[ tc ];
        }

        out[index++] = (t>>16)&0xFF;
        out[index++] = (t>>8)&0xFF;
        out[index++] = t&0xFF;
    }

    if(padlen)
    {
        t = 0;
        for(j=0;j<4-padlen;j++)
        {
            tc = src[i*4+j];
            if(base64_decode_table[ tc ] == 0xFF)
            {
                return BASE64_INVAILD_CHAR;
            }
            t = (t<<6) + base64_decode_table[ tc ];
        }

        if(padlen == 1)
        {
            out[index++] = (t>>10)&0xFF;
            out[index++] = (t>>2)&0xFF;
        }
        else
        {
            out[index++] = (t>>4)&0xFF;
        }
    }


    *outlen = index;

    return BASE64_OK;
}