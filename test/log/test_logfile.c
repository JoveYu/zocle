
#include "check.h"
#include "zocle/zocle.h"

#include "log/test_logfile.h"

START_TEST(test_log_logfile) {
    zc_mem_init(ZC_MEM_GLIBC|ZC_MEM_DBG_LEAK|ZC_MEM_DBG_OVERFLOW);
    zc_log_new("stdout", ZC_LOG_DEBUG);

    int i;
    int count;

    count = 10;
    for (i = 0; i < count; i++) {
        ZCDEBUG("%d",i);
        ZCINFO("%d",i);
        ZCNOTE("%d",i);
        ZCWARN("%d",i);
        ZCERROR("%d",i);
    }

}
END_TEST


Suite * log_logfile_suite(void) {
    Suite *s;
    TCase *tc;

    tc = tcase_create("logfile");
    tcase_add_test(tc, test_log_logfile);

    s = suite_create("log");
    suite_add_tcase(s, tc);

    return s;
}
