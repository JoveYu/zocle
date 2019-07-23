#ifndef ZOCLE_ALLOC_H
#define ZOCLE_ALLOC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#define ZC_MEM_GLIBC            0x01
#define ZC_MEM_TCMALLOC         0x02
#define ZC_MEM_GC               0x04
#define ZC_MEM_DBG_OVERFLOW     0x10
#define ZC_MEM_DBG_LEAK         0x20

#define ZC_MEM_DEBUG_BUNKS  1000000

typedef struct __zocle_mem_debug_item
{
    struct __zocle_mem_debug_item   *next;
    void        *key;
    char        file[16];
    uint16_t    line;
    uint32_t    id;
}zcMemDbgItem;

typedef struct __zocle_mem_debug
{
    uint32_t    flags;
    uint32_t    size;  // all alloced mem size
    uint32_t    count; // count in hashtable
    uint32_t    seqid;
    pthread_mutex_t lock;
    zcMemDbgItem    **bunks; //[ZC_MEM_DEBUG_BUNKS];
}zcMemDbg;

zcMemDbg* zc_memdebug_new();
void      zc_memdebug_delete(void*);
int       zc_memdebug_add(zcMemDbg*, void *key, const char *file, int line);
int       zc_memdebug_remove(zcMemDbg*, void *key);
void      zc_memdebug_clear(zcMemDbg*);
int       zc_memdebug_count(zcMemDbg*, uint32_t startid);
int       zc_memdebug_print_real(zcMemDbg*, const char *file, int line);
uint32_t  zc_memdebug_check_point_real(zcMemDbg*, uint32_t startid, const char *file, int line);

#define   zc_memdebug_print(m)    zc_memdebug_print_(m,__FILE__,__LINE__)
#define   zc_memdebug_check_point(m,sid)  zc_memdebug_check_point_real(m,sid,__FILE__,__LINE__)

extern zcMemDbg    *_zc_mem_dbg;

void  zc_mem_init(uint32_t flags);
void* zc_malloc_real(size_t size, const char *file, int line);
void* zc_calloc_real(size_t size, const char *file, int line);
void* zc_alloca_real(size_t size, const char *file, int line);
void  zc_free_real(void *ptr, const char *file, int line);
int	  zc_check_real(void *ptr, const char *file, int line);
int	  zc_check_exit_real(void *ptr, const char *file, int line);
void  zc_free_func(void *ptr);
void  zc_free_func2(void *ptr, void *obj);
void  zc_free_func4(void *ptr, void *obj, const char *file, int line);
void  zc_nofree_func(void *ptr);

#define zc_malloc(size)		zc_malloc_real(size,__FILE__,__LINE__)
#define zc_malloct(t)		(t*)zc_malloc_real(sizeof(t),__FILE__,__LINE__)
#define zc_calloc(size)		zc_calloc_real(size,__FILE__,__LINE__)
#define zc_calloct(t)		(t*)zc_calloc_real(sizeof(t),__FILE__,__LINE__)
#define zc_free(ptr)		do{zc_free_real(ptr,__FILE__,__LINE__);ptr=NULL;}while(0)
#define zc_free3(ptr,f,n)	do{zc_free_real(ptr,f,n);ptr=NULL;}while(0)
#define zc_check(ptr)		zc_check_real(ptr,__FILE__,__LINE__)
#define zc_check_exit(ptr)	zc_check_exit_real(ptr,__FILE__,__LINE__)
#define zc_mem_print()      zc_memdebug_print_real(_zc_mem_dbg,__FILE__,__LINE__)
#define zc_mem_check_point(sid) zc_memdebug_check_point_real(_zc_mem_dbg,sid,__FILE__,__LINE__)
#define zc_mem_count(sid)      zc_memdebug_count(_zc_mem_dbg,sid)

#define zc_safedel(t,x)     do{zc_##t##_delete(x);x=NULL;}while(0)

#define ZOCLE_EXIT(c)       exit(c)
#define ZOCLE_ABORT()       abort()

#endif
