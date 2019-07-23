#ifndef ZOCLE_BASE_TYPE_H
#define ZOCLE_BASE_TYPE_H

#include <stdio.h>
#include <stdint.h>

#define ZC_OBJECT_HEAD  \
	uint8_t    __type;

#define ZC_OBJECT_HEAD_FULL  \
	uint8_t    __type;\
	void	  *__funcs; \
	zcFuncDel  __delete;

#define ZC_INT8			1
#define ZC_UINT8		2
#define ZC_INT16		3
#define ZC_UINT16		4
#define ZC_INT32		5
#define ZC_UINT32		6
#define ZC_INT64		7
#define ZC_UINT64		8
#define ZC_DOUBLE		9
#define ZC_BOOL			10
#define ZC_NULL			11
#define ZC_STRING		12
#define ZC_LIST			13
#define ZC_SLIST		14
#define ZC_DICT			15
#define ZC_ARRAY		16
#define ZC_HASHSET		17
#define ZC_HASHTABLE	15
#define ZC_CUSTOM		20

#define ZC_BUFFER		21
#define ZC_STRBUF		22

#define ZC_INT8_INIT(v)		{1,v}
#define ZC_UINT8_INIT(v)	{2,v}
#define ZC_INT16_INIT(v)	{3,v}
#define ZC_UINT16_INIT(v)	{4,v}
#define ZC_INT32_INIT(v)	{5,v}
#define ZC_UINT32_INIT(v)	{6,v}
#define ZC_INT64_INIT(v)	{7,v}
#define ZC_UINT64_INIT(v)	{8,v}
#define ZC_DOUBLE_INIT(v)	{9,v}
#define ZC_BOOL_INIT(v)		{10,v}
#define ZC_NULL_INIT()		{11,0}

#define zc_int8(v)		{1,v}
#define zc_uint8(v)		{2,v}
#define zc_int16(v)		{3,v}
#define zc_uint16(v)	{4,v}
#define zc_int32(v)		{5,v}
#define zc_uint32(v)	{6,v}
#define zc_int64(v)		{7,v}
#define zc_uint64(v)	{8,v}
#define zc_double(v)	{9,v}
#define zc_bool(v)		{10,v}
#define zc_null()		{11,0}




typedef int  (*zcFuncConstruct)(void *, ...);
typedef void (*zcFuncDestruct)(void*);
typedef void (*zcFuncDestroy)(void*);

#define zc_new(t,args...) ({\
	t *_zc_tmp_v = zc_malloc(sizeof(t));\
	memset(_zc_tmp_v, 0, sizeof(t));\
	if (t##_construct(_zc_tmp_v, ##args) != 0){\
		zc_free(_zc_tmp_v);\
		_zc_tmp_v = NULL;\
	}\
	_zc_tmp_v;\
	})

#define zc_newc(t,_zc_tmp_construct,args...) ({\
	t *_zc_tmp_v = zc_malloc(sizeof(t));\
	memset(_zc_tmp_v, 0, sizeof(t));\
	if (_zc_tmp_construct && _zc_tmp_construct(_zc_tmp_v, ##args) != 0){\
		zc_free(_zc_tmp_v);\
		_zc_tmp_v = NULL;\
	}\
	_zc_tmp_v;\
	})

#define zc_delete(v,t)  do{t##_destruct(v);zc_free(v);v=NULL;}while(0)
//#define zc_delete(v) do{v->__destruct(v,v->__dealloc);v=NULL;}while(0)

#endif
