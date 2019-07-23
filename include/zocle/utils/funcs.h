#ifndef ZOCLE_UTILS_FUNCS_H
#define ZOCLE_UTILS_FUNCS_H

#include <stdio.h>
#include <stdint.h>


#if defined(__APPLE__)

#include <libkern/OSByteOrder.h>

#define zc_htob16(x) OSSwapHostToBigInt16(x)
#define zc_htob32(x) OSSwapHostToBigInt32(x)
#define zc_htob64(x) OSSwapHostToBigInt64(x)
#define zc_btoh16(x) OSSwapBigToHostInt16(x)
#define zc_btoh32(x) OSSwapBigToHostInt32(x)
#define zc_btoh64(x) OSSwapBigToHostInt64(x)

#else

#include <endian.h>
#include <byteswap.h>

#define zc_htob16(x) bswap_16(x)
#define zc_htob32(x) bswap_32(x)
#define zc_htob64(x) bswap_64(x)
#define zc_btoh16(x) bswap_16(x)
#define zc_btoh32(x) bswap_32(x)
#define zc_btoh64(x) bswap_64(x)

#endif



int zc_cmp_int(void *a, void *b, int);
int zc_cmp_int_ptr(void *a, void *b, int);
int zc_cmp_pint(void *a, void *b, int);
int zc_cmp_float_ptr(void *a, void *b, int);
int zc_cmp_double_ptr(void *a, void *b, int);
int zc_cmp_str(void *a, void *b, int);
int zc_cmp_str_ptr(void *a, void *b, int);
int zc_cmp_pstr(void *a, void *b, int);
int zc_cmp_obj(void *a, void *b, int);
int zc_cmp_simple(void *a, void *b, int);

uint32_t zc_hash_bkdr(void *str, int len);
uint32_t zc_hash_rs(void *str, int len);
uint32_t zc_hash_ap(void *str, int len);
uint32_t zc_hash_js(void *str, int len);
uint32_t zc_hash_elf(void *str, int len);


int zc_format_hex(char *out, const char *data, int len);

#endif
