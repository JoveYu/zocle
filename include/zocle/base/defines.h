#ifndef ZOCLE_BASE_DEFINES_H
#define ZOCLE_BASE_DEFINES_H

#include <stdio.h>

#if !defined(bool)
	#define bool char
#endif

#if !defined(true)
	#define true 1
#endif

#if !defined(false)
	#define false 0
#endif

#if !defined(max)
	#define max(a,b) ((a)>(b))?(a):(b)
#endif

#define ZOCLE_API   

#define ZC_OK       0
#define ZC_SUCC     0
#define ZC_FAILED   -1
#define ZC_TRUE     1
#define ZC_FALSE    0
#define ZC_YES      1
#define ZC_NO       0
#define ZC_SMALL    -1
#define ZC_EQUAL    0
#define ZC_BIG      1
#define ZC_LEFT     -1
#define ZC_RIGHT    1
#define ZC_MIDDLE   0
#define ZC_PTR_FAILED   (void *)(-1)
#define ZC_AGAIN	-91000
#define ZC_STOP		-1

#define ZC_ERR_NULL         -90000
#define ZC_ERR_BIGGER       -90001
#define ZC_ERR_SMALLER      -90002
#define ZC_ERR_RANGE        -90003
#define ZC_ERR_EMPTY        -90004
#define ZC_ERR_NOT_FOUND    -90005
#define ZC_ERR_PARAM        -90006
#define ZC_ERR_NEW          -90007
#define ZC_ERR_ENC          -90008
#define ZC_ERR_EXIST        -90009
#define ZC_ERR              -90010
#define ZC_ERR_SOCKET       -90011
#define ZC_ERR_TIMEOUT      -90012
#define ZC_ERR_BUF			-90013
#define ZC_ERR_MEM			-90014
#define ZC_ERR_MALLOC		-90015
#define ZC_ERR_FULL			-90016

#ifdef _WIN32
#define ZC_ERRNO            WSAGetLastError()*(-1)
#else
#define ZC_ERRNO            -errno
#endif

#define	ZC_EXIT()			exit(-1)

#define	ZC_DS_TYPE_OBJ		1
#define ZC_DS_TYPE_PTR		2
#define ZC_DS_TYPE_STR		2
#define ZC_DS_TYPE_BIN		3

#define ZC_ASSERT(e)  \
    ((void) ((e) ? 0 : ((void)ZCERROR("%s:%u: failed assertion `%s'\n", __FILE__, __LINE__, e), abort()) ))

typedef void         (*zcFuncDel)(void *);
typedef void         (*zcFuncDel2)(void *, void*);
typedef void         (*zcFuncDel4)(void *, void*, const char*, int);
typedef int          (*zcFuncCmp)(void*, void*, int);
typedef void*        (*zcFuncClone)(void*);
typedef unsigned int (*zcFuncHash)(void*, int);
typedef void*        (*zcFuncRun)(void*);
typedef void*        (*zcFuncNew)(void*);

#endif
