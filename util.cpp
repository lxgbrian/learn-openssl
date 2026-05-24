
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

long timestamp()
{
    struct timeval tv;
     
    gettimeofday(&tv, NULL);
    return (tv.tv_sec*1000 + tv.tv_usec/1000);
}


int HexStrTobyte(char* str, unsigned char* out, unsigned int* outlen)
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

int  byteToHexStr(unsigned char* byte_arr, int arr_len, char* HexStr, int* HexStrLen) {
	int  i, index = 0;
	for (i = 0; i < arr_len; i++)
	{
		char hex1;
		char hex2;
		int value = byte_arr[i];
		int v1 = value / 16;
		int v2 = value % 16;
		if (v1 >= 0 && v1 <= 9)
			hex1 = (char)(48 + v1);
		else
			hex1 = (char)(55 + v1);
		if (v2 >= 0 && v2 <= 9)
			hex2 = (char)(48 + v2);
		else
			hex2 = (char)(55 + v2);
		if (*HexStrLen <= i) {
			return -1;
		}
		HexStr[index++] = hex1;
		HexStr[index++] = hex2;
	}
	*HexStrLen = index;
	return 0;
}

int sm2_encrypt(const char* pubkey_hex, const char* data_hex, char* output, int* output_len) {
    if (!pubkey_hex || !data_hex || !output || !output_len || *output_len <= 0) return -1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Check pubkey_hex length (128 hex chars for 64 bytes)
    size_t pubkey_hex_len = strlen(pubkey_hex);
    if (pubkey_hex_len != 128) return -1;

    // Convert pubkey_hex to binary (64 bytes x+y)
    unsigned char pubkey_bin[64];
    unsigned int pubkey_len;
    HexStrTobyte((char*)pubkey_hex, pubkey_bin, &pubkey_len);
    if (pubkey_len != 64) return -1;

    // Create full uncompressed pubkey: 04 + x + y
    unsigned char full_pubkey[65];
    full_pubkey[0] = 0x04;
    memcpy(full_pubkey + 1, pubkey_bin, 64);

    // Create EVP_PKEY using modern API
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_fromdata_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"SM2", 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, full_pubkey, 65),
        OSSL_PARAM_END
    };

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    // Convert data_hex to binary
    size_t data_hex_len = strlen(data_hex);
    if (data_hex_len % 2 != 0 || data_hex_len > 2048) return -1; // assume max 1024 bytes
    unsigned char data_bin[1024];
    unsigned int data_len;
    HexStrTobyte((char*)data_hex, data_bin, &data_len);

    // Encrypt
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, data_bin, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    unsigned char* encrypted = (unsigned char*)malloc(outlen);
    if (!encrypted) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, data_bin, data_len) <= 0) {
        free(encrypted);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    // Check if output buffer is large enough
    int needed_len = outlen * 2;
    if (*output_len < needed_len + 1) { // +1 for null terminator
        free(encrypted);
        return -1;
    }

    // Convert to hex
    int temp_len = *output_len;
    if (byteToHexStr(encrypted, outlen, output, &temp_len) != 0) {
        free(encrypted);
        return -1;
    }
    output[temp_len] = '\0';
    *output_len = temp_len;

    free(encrypted);

    return 0;
}
