#ifndef _UTIL_H
#define _UTIL_H
#ifdef __cplusplus
extern "C"{
#endif

long timestamp(void);

int HexStrTobyte(char* str, unsigned char* out, unsigned int* outlen);

int  byteToHexStr(unsigned char* byte_arr, int arr_len, char* HexStr, int* HexStrLen);

#ifdef __cplusplus
}
#endif
#endif


