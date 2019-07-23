#include <zocle/mem/alloc.h>
#include <zocle/log/logfile.h>
#include <zocle/base/defines.h>
#include <string.h>
#include <errno.h>

#ifdef ZOCLE_WITH_GC
#include <gc.h>
#endif

#ifdef ZOCLE_WITH_TCMALLOC
#include <gperftools/tcmalloc.h>
#endif

zcMemDbg    *_zc_mem_dbg;


zcMemDbg*
zc_memdebug_new(unsigned int flags)
{
    zcMemDbg *m = (zcMemDbg*)malloc(sizeof(zcMemDbg));
    memset(m, 0, sizeof(zcMemDbg));
    m->flags = flags;

    if (flags & ZC_MEM_DBG_LEAK) {
        m->bunks = (zcMemDbgItem**)malloc(sizeof(zcMemDbgItem*) * ZC_MEM_DEBUG_BUNKS);
        memset(m->bunks, 0, sizeof(zcMemDbgItem*) * ZC_MEM_DEBUG_BUNKS);
    }
    int ret;
    ret = pthread_mutex_init(&m->lock, NULL);
    if (ret != 0) {
        ZCFATAL("mutex init error! %d\n", ret);
    }
#ifdef ZOCLE_WITH_GC
    if (flags & ZC_MEM_GC) {
        GC_INIT();
    }
#endif
    return m;
}

unsigned int
zc_memdebug_hash(char *str, int len)
{
    //BKDR Hash
    unsigned int seed = 131;
    unsigned int hash = 0;
    int i;

    for (i = 0; i < len; i++) {
        hash = hash * seed + (*str++);
    }
    return (hash & 0x7FFFFFFF) % ZC_MEM_DEBUG_BUNKS;
}

void
zc_memdebug_delete(void *x)
{
    zcMemDbg *m = (zcMemDbg*)x;
    if (m->bunks)
        free(m->bunks);
    free(m);
}

int
zc_memdebug_add(zcMemDbg *m, void *key, const char *file, int line)
{
    if (m->bunks == NULL) {
        ZCERROR("add bunks NULL\n");
        return ZC_FAILED;
    }
    unsigned int h = zc_memdebug_hash((char*)&key, 4);
    zcMemDbgItem *newnode;

    newnode = (zcMemDbgItem*)malloc(sizeof(zcMemDbgItem));
    memset(newnode, 0, sizeof(zcMemDbgItem));
    newnode->key = key;
    strncpy(newnode->file, file, 11);
    newnode->line = line;

    pthread_mutex_lock(&m->lock);
    m->seqid++;
    newnode->id = m->seqid;
    zcMemDbgItem *node = m->bunks[h];
    if (node) {
        newnode->next = node;
    }
    m->bunks[h] = newnode;
    pthread_mutex_unlock(&m->lock);

    return ZC_OK;
}

int
zc_memdebug_remove(zcMemDbg *m, void *key)
{
    unsigned int h = zc_memdebug_hash((char*)&key, 4);

    pthread_mutex_lock(&m->lock);
    zcMemDbgItem *node = m->bunks[h];
    zcMemDbgItem *prev = NULL;
    while (node) {
        if (key == node->key) {
            if (prev) {
                prev->next = node->next;
            }else{
                m->bunks[h] = node->next;
            }
            free(node);
            break;
        }
        prev = node;
        node = node->next;
    }
    pthread_mutex_unlock(&m->lock);

    return ZC_OK;
}

void
zc_memdebug_clear(zcMemDbg *m)
{
    zcMemDbgItem    *node, *tmp;
    int             i;

    for (i = 0; i < ZC_MEM_DEBUG_BUNKS; i++) {
        node = m->bunks[i];
        while (node) {
            tmp = node;
            node = node->next;
            free(tmp);
        }
    }
    memset(m->bunks, 0, ZC_MEM_DEBUG_BUNKS * sizeof(zcMemDbgItem*));
    return;
}

int
zc_memdebug_count(zcMemDbg *m, unsigned int startid)
{
    if ((m->flags & ZC_MEM_DBG_LEAK) == 0)
        return 0;

    if (startid == 0)
        return m->count;

    int i, count = 0;
    zcMemDbgItem    *node;

    pthread_mutex_lock(&m->lock);
    for (i = 0; i < ZC_MEM_DEBUG_BUNKS; i++) {
        node = m->bunks[i];
        while (node) {
            if (node->id > startid) {
                count++;
            }
            node = node->next;
        }
    }
    pthread_mutex_unlock(&m->lock);

    return count;
}

int
zc_memdebug_print_real(zcMemDbg *m, const char *file, int line)
{
    if ((m->flags & ZC_MEM_DBG_LEAK) == 0)
        return 0;

    zcMemDbgItem    *node;
    int is_overflow_check = _zc_mem_dbg->flags & ZC_MEM_DBG_OVERFLOW;

    ZCINFO("==== mem print %d ====\n", m->count);
    int i;
    for (i = 0; i < ZC_MEM_DEBUG_BUNKS; i++) {
        node = m->bunks[i];
        while (node) {
            if (is_overflow_check) {
                ZCINFO("mem %s:%d size:%u id:%u addr:%p\n", node->file, node->line,
                    *(unsigned int*)(node->key - 8), node->id, node->key);
                zc_check_real(node->key, file, line);
            }else{
                ZCINFO("mem %s:%d id:%u addr:%p\n", node->file, node->line,
                        node->id, node->key);
            }
            node = node->next;
        }
    }
    return ZC_OK;
}

unsigned int
zc_memdebug_check_point_real(zcMemDbg *m, unsigned int startid, const char *file, int line)
{
    if ((m->flags & ZC_MEM_DBG_LEAK) == 0)
        return 0;

    if (startid == 0) {
        int id;
        pthread_mutex_lock(&m->lock);
        id = m->seqid;
        pthread_mutex_unlock(&m->lock);
        return id;
    }

    int i, count = 0;
    zcMemDbgItem    *node;
    int is_overflow_check = _zc_mem_dbg->flags & ZC_MEM_DBG_OVERFLOW;

    ZCINFO("==== mem check point start ====\n");
    pthread_mutex_lock(&m->lock);
    for (i = 0; i < ZC_MEM_DEBUG_BUNKS; i++) {
        node = m->bunks[i];
        while (node) {
            if (node->id > startid) {
                ZCWARN("mem %s:%d size:%u id:%u addr:%p\n", node->file, node->line,
                        *(unsigned int*)(node->key - 8), node->id, node->key);
                count++;
            }
            if (is_overflow_check) {
                zc_check_real(node->key, file, line);
            }
            node = node->next;
        }
    }
    pthread_mutex_unlock(&m->lock);
    ZCINFO("==== mem check point end %d ====\n", count);

    return count;
}



void
zc_mem_init(unsigned int flags)
{
    if (flags == 0)
        flags = 1;
    _zc_mem_dbg = zc_memdebug_new(flags);
}


static void*
malloc_real(size_t size)
{
    unsigned int flags;
    if (_zc_mem_dbg == NULL) {
        flags = ZC_MEM_GLIBC;
    }else{
        flags = _zc_mem_dbg->flags;
    }

    switch(flags) {
#ifdef ZOCLE_WITH_GC
        case ZC_MEM_GC:
            return GC_MALLOC(size);
#endif

#ifdef ZOCLE_WITH_TCMALLOC
        case ZC_MEM_TCMALLOC:
            return tc_malloc(size);
#endif
        case ZC_MEM_GLIBC:
            return malloc(size);
        default:
            return malloc(size);
    }

}

void*
zc_malloc_real(size_t size, const char *file, int line)
{
    void *ptr;
    unsigned int flags;
    if (_zc_mem_dbg == NULL) {
        flags = ZC_MEM_GLIBC;
    }else{
        flags = _zc_mem_dbg->flags;
    }


    if (flags & ZC_MEM_DBG_OVERFLOW) {
        ptr = malloc_real(size + 12);

        if (NULL == ptr) {
            ZCFATAL("malloc return NULL %u %s:%d\n", (unsigned int)size, file, line);
        }

        // 内存格式: 内存长度(8字节:len + 0x55555555) + 实际内存 + 0x55555555(4字节)
        *((uint32_t *)ptr) = size;
        *((uint32_t *)(ptr + 4)) = 0x55555555;
        *((uint32_t *)(ptr + size + 8)) = 0x55555555;

        _zc_mem_dbg->size += size + 12;
        ptr += 8;
    }else{
        ptr = malloc_real(size);

        if (NULL == ptr) {
            ZCFATAL("malloc return NULL %u %s:%d\n", (unsigned int)size, file, line);
        }
        if (_zc_mem_dbg != NULL)
            _zc_mem_dbg->size += size;
    }

    if (flags & 0xf0) { // check overflow or leak
        pthread_mutex_lock(&_zc_mem_dbg->lock);
        _zc_mem_dbg->count++;
        pthread_mutex_unlock(&_zc_mem_dbg->lock);

        if (flags & ZC_MEM_DBG_LEAK) {
            zc_memdebug_add(_zc_mem_dbg, ptr, file, line);
        }
    }

    return ptr;
}

void*
zc_calloc_real(size_t size, const char *file, int line)
{
    void *s = zc_malloc_real(size, file, line);
    memset(s, 0, size);
    return s;
}

void*
zc_alloca_real(size_t size, const char *file, int line)
{
    if (size >= 1048576) {
        ZCERROR("alloca size more than 1M: %u\n", (unsigned int)size);
        return NULL;
    }
    void *ptr = alloca(size);
    if (NULL == ptr) {
        ZCFATAL("alloca return NULL %u %s:%d\n", (unsigned int)size, file, line);
    }

    return ptr;
}

static void
free_real(void *ptr)
{
    unsigned int flags;
    if (_zc_mem_dbg == NULL) {
        flags = ZC_MEM_GLIBC;
    }else{
        flags = _zc_mem_dbg->flags;
    }

    switch(flags) {
#ifdef ZOCLE_WITH_GC
        case ZC_MEM_GC:
            return GC_FREE(ptr);
#endif

#ifdef ZOCLE_WITH_TCMALLOC
        case ZC_MEM_TCMALLOC:
            return tc_free(ptr);
#endif
        case ZC_MEM_GLIBC:
            return free(ptr);
        default:
            return free(ptr);
    }
}


void
zc_free_real(void *ptr, const char *file, int line)
{
    unsigned int flags;
    if (_zc_mem_dbg == NULL) {
        flags = ZC_MEM_GLIBC;
    }else{
        flags = _zc_mem_dbg->flags;
    }

    if (NULL == ptr) {
        ZCERROR("free NULL pointer: %p %s:%d\n", ptr, file, line);
        return;
    }
    void *mptr = ptr;
    //ZCINFO("free key:%p\n", ptr);
    if (flags & ZC_MEM_DBG_OVERFLOW) {
        zc_check_exit_real(ptr, file, line);
        ptr -= 8;
    }
    if (flags & ZC_MEM_DBG_LEAK) {
        //ZCINFO("remve key: %p\n",  ptr);
        if (zc_memdebug_remove(_zc_mem_dbg, mptr) != ZC_OK) {
            ZCERROR("free addr error: %p\n", mptr);
            return;
        }
    }

    free_real(ptr);
}

int
zc_check_real(void *ptr, const char *file, int line)
{
    int size = *((uint32_t *)(ptr - 8));
    if (*((uint32_t *)(ptr-4)) != 0x55555555) {
        ZCERROR("[zc_check start failed, %p size:%d, start:0x%x, end:0x%x file:%s line:%d]\n",
                ptr, size, *((uint32_t *)(ptr-4)), *((uint32_t *)(ptr+size)), file, line);
        return ZC_FAILED;
    }
    if (*((uint32_t *)(ptr + size)) != 0x55555555) {
        ZCERROR("[zc_check end failed, %p size:%d, start:0x%x, end:0x%x file:%s line:%d]\n",
                ptr, size, *((uint32_t *)(ptr-4)), *((uint32_t *)(ptr+size)), file, line);
        return ZC_FAILED;
    }

    return ZC_OK;
}

int
zc_check_exit_real(void *ptr, const char *file, int line)
{
    if (zc_check_real(ptr, file, line) != ZC_OK) {
        ZCFATAL("zc_check_exit! %p %s:%d\n", ptr, file, line);
    }
    return ZC_OK;
}

void
zc_free_func(void *ptr)
{
    return zc_free_real(ptr, "", 0);
}

void
zc_free_func2(void *ptr, void *obj)
{
    return zc_free_real(ptr, "", 0);
}

void
zc_free_func4(void *ptr, void *obj, const char *file, int line)
{
    return zc_free_real(ptr, file, line);
}

void
zc_nofree_func(void *ptr)
{
}


