#include <zocle/utils/funcs.h>
#include <string.h>
#include <zocle/log/logfile.h>

int 
zc_cmp_int(void *a, void *b, int len)
{
    long a1 = (long)a, b1 = (long)b;
    //ZCINFO("a:%ld, b:%ld\n", a1, b1);
    if (a1 == b1)
        return 0;
    if (a1 > b1)
        return 1;
    return -1;
}

int 
zc_cmp_int_ptr(void *a, void *b, int len)
{
    int a1 = *(int*)a, b1 = *(int*)b;
    if (a1 == b1)
        return 0;
    if (a1 > b1)
        return 1;
    return -1;
}

int 
zc_cmp_pint(void *a, void *b, int len)
{
    long a1 = *(long*)a, b1 = (long)b;
    if (a1 == b1)
        return 0;
    if (a1 > b1)
        return 1;
    return -1;
}

int 
zc_cmp_float_ptr(void *a, void *b, int len)
{
    float a1 = *(float*)a;
    float b1 = *(float*)b;
    float x = a1 - b1;
    if (x > 0 && x < 0.000001)
        return 0;
    if (x > 0)
        return 1;
    return -1;
}

int 
zc_cmp_double_ptr(void *a, void *b, int len)
{
    double a1 = *(double*)a, b1 = *(double*)b;
    double x = a1 - b1;
    if (x > 0 && x < 0.000001)
        return 0;
    if (x > 0)
        return 1;
    return -1;
}

int 
zc_cmp_str(void *a, void *b, int len)
{
    if (len > 0) {
        return strncmp((char*)a, (char*)b, len);
    }else{
        return strcmp((char*)a, (char*)b);
    }
}

int 
zc_cmp_str_ptr(void *a, void *b, int len)
{
    char *a1 = *(char**)a;
    char *b1 = *(char**)b;

    if (len > 0) {
        return strncmp(a1, b1, len);
    }else{
        return strcmp(a1, b1);
    }
}

int 
zc_cmp_pstr(void *a, void *b, int len)
{
    char *a1 = *(char**)a;
    char *b1 = (char*)b;

    if (len > 0) {
        return strncmp(a1, b1, len);
    }else{
        return strcmp(a1, b1);
    }
}


int 
zc_cmp_obj(void *a, void *b, int len)
{
    return memcmp(a, b, sizeof(*a));
}

int 
zc_cmp_simple(void *a, void *b, int len)
{
    return a-b;
}

uint32_t 
zc_hash_bkdr(void *s, int len)
{
    //BKDR Hash
    char *str = (char*)s;
    uint32_t seed = 131;
    uint32_t hash = 0;

    if (len <= 0)
        len = strlen(str);

    int i;
    for (i = 0; i < len; i++) {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

uint32_t 
zc_hash_rs(void *s, int len)
{
    char *str = (char*)s;
    uint32_t b = 378551;
    uint32_t a = 63689;
    uint32_t hash = 0;

    if (len <= 0)
        len = strlen(str);

    int i;
    for (i = 0; i < len; i++) {
        hash = hash * a + (*str++);
        a *= b;
    }

    return (hash & 0x7FFFFFFF);
}

uint32_t 
zc_hash_ap(void *s, int len)
{
    char *str = (char*)s;
    uint32_t hash = 0;

    if (len <= 0)
        len = strlen(str);

    int i;
    for (i = 0; i < len; i++) {
        if ((i & 1) == 0) {
            hash ^= ((hash << 7) ^ (*str++) ^ (hash >> 3));
        }else{
            hash ^= (~((hash << 11) ^ (*str++) ^ (hash >> 5)));
        }
    }

    return (hash & 0x7FFFFFFF);
}

uint32_t 
zc_hash_js(void *s, int len)
{
    char *str = (char*)s;
    uint32_t hash = 1315423911;

    if (len <= 0)
        len = strlen(str);

    int i;
    for (i = 0; i < len; i++) {
        hash ^= ((hash << 5) + (*str++) + (hash >> 2));
    }

    return (hash & 0x7FFFFFFF);
}

uint32_t 
zc_hash_elf(void *s, int len)
{
    char *str = (char*)s;
    uint32_t hash = 0;
    uint32_t x = 0;

    if (len <= 0)
        len = strlen(str);

    int i;
    for (i = 0; i < len; i++) {
        hash = (hash << 4) + (*str++);
        if ((x = hash & 0xF0000000L) != 0) {
            hash ^= (x >> 24);
            hash &= ~x;
        }
    }
    return (hash & 0x7FFFFFFF);
}


int 
zc_format_hex(char *out, const char *data, int len)
{
	int i;
	char *s = out;
	char *map = "0123456789ABCDEF";
	unsigned char n;

	for (i=0; i<len; i++) {
		n = data[i];
		*s = map[n/16];
		s++;
		*s = map[n%16];
		s++;
	
		if (n >= 33 && n <= 126) {
			*s = '/'; 
			s++;
			*s = n;
			s++;
		}

		*s = ' ';
		s++;
	}
	*s = 0;
	return s-out;
}


