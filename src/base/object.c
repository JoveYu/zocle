#include <zocle/base/object.h>
#include <zocle/mem/alloc.h>
#include <zocle/base/defines.h>
// #include <zocle/ds/dict.h>
// #include <zocle/ds/hashtable.h>
// #include <zocle/ds/list.h>
// #include <zocle/str/string.h>

int
zcObject_construct(zcObject *obj)
{
    return zc_obj_init(obj);
}

void
zcObject_destruct(void *obj)
{
    zc_obj_destroy(obj);
}

int
zc_obj_init(zcObject *obj)
{
    //obj->__delete = zc_obj_delete;
    return ZC_OK;
}

void
zc_obj_destroy(void *obj)
{
}

void
zc_obj_delete(void *obj)
{
    zc_obj_destroy(obj);
    //zc_free(obj);
    zcObject *x = (zcObject*)obj;
    switch(x->__type) {
    // case ZC_DICT:
    //     zc_dict_delete(x);
    //     break;
    // case ZC_LIST:
    //     zc_list_delete(x);
    //     break;
    // case ZC_STRING:
    //     zc_str_delete(x);
    //     break;
    default:
        zc_free(obj);
        break;
    }
}

/*void
zc_obj_delete_all(void *obj)
{
    switch(obj->__type) {
    case ZC_DICT:
        break;
    case ZC_LIST:
        break;
    default:
        zc_free(obj);
    }
}*/

/*
void
zc_obj_print_internal(zcObject *obj, int level, zcString *s, bool tab)
{
    int i = 0;

    if (tab) {
        for (i=0; i<level; i++) {
            zc_str_append_c(s, ' ');
        }
    }
    if (obj == NULL) {
        zc_str_append(s, "<NULL>\n");
        return;
    }

    switch(obj->__type) {
    case ZC_INT8:
        zc_str_append_format(s, "int8#%d\n", ((zcInt8*)obj)->v);
        break;
    case ZC_UINT8:
        zc_str_append_format(s, "uint8#%d\n", ((zcUInt8*)obj)->v);
        break;
    case ZC_INT16:
        zc_str_append_format(s, "int16#%d\n", ((zcInt16*)obj)->v);
        break;
    case ZC_UINT16:
        zc_str_append_format(s, "uint16#%d\n", ((zcUInt16*)obj)->v);
        break;
    case ZC_INT32:
        zc_str_append_format(s, "int32#%d\n", ((zcInt32*)obj)->v);
        break;
    case ZC_UINT32:
        zc_str_append_format(s, "uint32#%u\n", ((zcUInt32*)obj)->v);
        break;
    case ZC_INT64:
        zc_str_append_format(s, "int64#%lld\n", ((zcInt64*)obj)->v);
        break;
    case ZC_UINT64:
        zc_str_append_format(s, "uint64#%llu\n", ((zcUInt64*)obj)->v);
        break;
    case ZC_DOUBLE:
        zc_str_append_format(s, "double#%f\n", ((zcDouble*)obj)->v);
        break;
    case ZC_BOOL:
        zc_str_append_format(s, "bool#%d\n", ((zcBool*)obj)->v);
        break;
    case ZC_NULL:
        zc_str_append_format(s, "null\n");
        break;
    case ZC_STRING:
        zc_str_append_format(s, "str#%s\n", ((zcString*)obj)->data);
        break;
    case ZC_LIST: {
        zc_str_append_format(s, "[\n");
        zcList *list = (zcList*)obj;
        zcObject *item;
        zcListNode *node;
        zc_list_foreach(list, node) {
            item = (zcObject*)node->data;
            zc_obj_print_internal(item, level+1, s, true);
        }
        if (tab) {
            for (i=0; i<level; i++) {
                zc_str_append_c(s, ' ');
            }
        }

        zc_str_append_format(s, "]\n");
        break;
    }
    case ZC_DICT: {
        zcDict *ht = (zcDict*)obj;
        const char *key;
        zcObject   *value;

        zc_str_append_format(s, "{\n");
        zc_dict_foreach_start(ht, key, value)
            if (tab) {
                for (i=0; i<level; i++) {
                    zc_str_append_c(s, ' ');
                }
            }
            zc_str_append_format(s, "key:%s, value:", key);
            zc_obj_print_internal(value, level+1, s, false);
        zc_dict_foreach_end

        if (tab) {
            for (i=0; i<level; i++) {
                zc_str_append_c(s, ' ');
            }
        }

        zc_str_append_format(s, "}\n");
        break;
    }
    default:
        return; // ZC_ERR;
    }
}
*/


/*
void
zc_obj_print(zcObject *obj)
{
    zcString *s = zc_str_new(1024);
    zc_obj_print_internal(obj, 0, s, true);
    ZCINFO("%s", s->data);
    zc_str_delete(s);
}

void
zc_obj_format(zcObject *obj, zcString *s)
{
    zc_obj_print_internal(obj, 0, s, true);
}
*/

int
zc_obj_tostr(zcObject *obj, char *buf, int len)
{
    switch(obj->__type) {
    case ZC_INT8:
        snprintf(buf, len, "int8");
        break;
    case ZC_UINT8:
        snprintf(buf, len, "uint8");
        break;
    case ZC_INT16:
        snprintf(buf, len, "int16");
        break;
    case ZC_UINT16:
        snprintf(buf, len, "uint16");
        break;
    case ZC_INT32:
        snprintf(buf, len, "int32");
        break;
    case ZC_UINT32:
        snprintf(buf, len, "uint32");
        break;
    case ZC_INT64:
        snprintf(buf, len, "int64");
        break;
    case ZC_UINT64:
        snprintf(buf, len, "uint64");
        break;
    case ZC_DOUBLE:
        snprintf(buf, len, "double");
        break;
    case ZC_BOOL:
        snprintf(buf, len, "bool");
        break;
    case ZC_NULL:
        snprintf(buf, len, "null");
        break;
    case ZC_LIST:
        snprintf(buf, len, "list");
        break;
    case ZC_DICT:
        snprintf(buf, len, "dict");
        break;
    default:
        return ZC_ERR;
    }
    return ZC_OK;
}

zcInt8*
zc_int8_new(int8_t val)
{
	zcInt8* x = zc_calloct(zcInt8);
    x->__type = ZC_INT8;
	x->v = val;
	return x;
}

zcUInt8*
zc_uint8_new(uint8_t val)
{
	zcUInt8* x = zc_calloct(zcUInt8);
    x->__type = ZC_UINT8;
	x->v = val;
	return x;
}

zcInt16*
zc_int16_new(int16_t val)
{
	zcInt16* x = zc_calloct(zcInt16);
    x->__type = ZC_INT16;
	x->v = val;
	return x;
}

zcUInt16*
zc_uint16_new(uint16_t val)
{
	zcUInt16* x = zc_calloct(zcUInt16);
    x->__type = ZC_UINT16;
	x->v = val;
	return x;
}

zcInt32*
zc_int32_new(int32_t val)
{
	zcInt32* x = zc_calloct(zcInt32);
    x->__type = ZC_INT32;
	x->v = val;
	return x;
}

zcUInt32*
zc_uint32_new(uint32_t val)
{
	zcUInt32* x = zc_calloct(zcUInt32);
    x->__type = ZC_UINT32;
	x->v = val;
	return x;
}

zcInt64*
zc_int64_new(int64_t val)
{
	zcInt64* x = zc_calloct(zcInt64);
    x->__type = ZC_INT64;
	x->v = val;
	return x;
}

zcUInt64*
zc_uint64_new(uint64_t val)
{
	zcUInt64* x = zc_calloct(zcUInt64);
    x->__type = ZC_UINT64;
	x->v = val;
	return x;
}

zcDouble*
zc_double_new(double val)
{
	zcDouble* x = zc_calloct(zcDouble);
    x->__type = ZC_DOUBLE;
	x->v = val;
	return x;
}

zcBool*
zc_bool_new(double val)
{
	zcBool* x = zc_calloct(zcBool);
    x->__type = ZC_BOOL;
	x->v = val;
	return x;
}

zcNull*
zc_null_new()
{
	zcNull* x = zc_calloct(zcNull);
    x->__type = ZC_NULL;
	return x;
}
