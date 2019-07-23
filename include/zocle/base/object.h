#ifndef ZOCLE_OBJECT_H
#define ZOCLE_OBJECT_H

#include <stdio.h>
#include <stdint.h>
#include <zocle/base/defines.h>
#include <zocle/base/type.h>
#include <zocle/mem/alloc.h>
// #include <zocle/str/string.h>

typedef struct zc_object_t
{
	ZC_OBJECT_HEAD
}zcObject;

typedef struct zc_int8_t
{
	ZC_OBJECT_HEAD
	int8_t v;
}zcInt8;

typedef struct zc_uint8_t
{
	ZC_OBJECT_HEAD
	uint8_t v;
}zcUInt8;

typedef struct zc_int16_t
{
	ZC_OBJECT_HEAD
	int16_t v;
}zcInt16;

typedef struct zc_uint16_t
{
	ZC_OBJECT_HEAD
	uint16_t v;
}zcUInt16;

typedef struct zc_int32_t
{
	ZC_OBJECT_HEAD
	int32_t v;
}zcInt32;

typedef struct zc_uint32_t
{
	ZC_OBJECT_HEAD
	uint32_t v;
}zcUInt32;

typedef struct zc_int64_t
{
	ZC_OBJECT_HEAD
	int64_t v;
}zcInt64;

typedef struct zc_uint64_t
{
	ZC_OBJECT_HEAD
	uint64_t v;
}zcUInt64;

typedef struct zc_double_t
{
	ZC_OBJECT_HEAD
	double v;
}zcDouble;


typedef struct zc_bool_t
{
	ZC_OBJECT_HEAD
	bool v;
}zcBool;

typedef struct zc_null_t
{
	ZC_OBJECT_HEAD
	bool v;
}zcNull;

zcInt8*		zc_int8_new(int8_t val);
zcUInt8*	zc_uint8_new(uint8_t val);
zcInt16*	zc_int16_new(int16_t val);
zcUInt16*	zc_uint16_new(uint16_t val);
zcInt32*	zc_int32_new(int32_t val);
zcUInt32*	zc_uint32_new(uint32_t val);
zcInt64*	zc_int64_new(int64_t val);
zcUInt64*	zc_uint64_new(uint64_t val);
zcDouble*	zc_double_new(double val);
zcBool*		zc_bool_new(double val);
zcNull*		zc_null_new();

#define		zc_obj_new()	zc_new(zcObject)
void		zc_obj_delete(void *obj);

int			zc_obj_init(zcObject *obj);
void		zc_obj_destroy(void *obj);

void		zc_obj_print(zcObject *obj);
// void		zc_obj_format(zcObject *obj, zcString *);
int			zc_obj_tostr(zcObject *obj, char *, int);

int			zcObject_construct(zcObject *obj);
void		zcObject_destruct(void *obj);

#endif
