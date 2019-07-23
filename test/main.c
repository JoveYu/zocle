
#include "check.h"
#include "stdlib.h"
#include "mem/test_alloc.h"
#include "log/test_logfile.h"

int main(void) {
    int num_fail;
    SRunner *sr;

    sr = srunner_create(mem_alloc_suite());
    srunner_add_suite(sr, log_logfile_suite());

    srunner_run_all(sr, CK_NORMAL);
    num_fail = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (num_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
