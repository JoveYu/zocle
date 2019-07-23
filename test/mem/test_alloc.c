
#include "check.h"
#include "zocle/zocle.h"

#include "mem/test_alloc.h"

START_TEST(test_mem_alloc) {
    zc_mem_init(ZC_MEM_GLIBC|ZC_MEM_DBG_LEAK|ZC_MEM_DBG_OVERFLOW);
    zc_log_new("stdout", ZC_LOG_ALL);

    unsigned int startid = zc_mem_check_point(0);
    int i;
    int count;
    char *a;
    char *addrs[10];

    count = 10;
    for (i = 0; i < count; i++) {
        a = zc_malloc(10);
        memset(a, 0, 11); // overflow
        ck_assert(a != NULL);
        addrs[i] = a;
    }
    ck_assert(zc_mem_count(startid) == count);
    ck_assert(zc_check(a) != ZC_OK);


    startid = zc_mem_check_point(0);

    count = 5;
    for (i = 0; i < 5; i++) {
        a = zc_malloc(10);
        ck_assert(a != NULL);
    }
    zc_mem_check_point(startid);

    ck_assert(zc_mem_count(startid) == count);
    zc_free(a);
    ck_assert(zc_mem_count(startid) == (count - 1));

}
END_TEST


Suite * mem_alloc_suite(void) {
    Suite *s;
    TCase *tc;

    tc = tcase_create("alloc");
    tcase_add_test(tc, test_mem_alloc);

    s = suite_create("mem");
    suite_add_tcase(s, tc);

    return s;
}
