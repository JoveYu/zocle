#include <zocle/utils/times.h>
#include <string.h>
#include <zocle/base/defines.h>
#include <zocle/mem/alloc.h>
#include <stdlib.h>
#ifndef _WIN32
#include <alloca.h>
#endif

void 
zc_timer_start(zcTimer *tm)
{
    memset(tm, 0, sizeof(zcTimer));
    gettimeofday(&tm->start, NULL);
}

uint32_t
zc_timer_end(zcTimer *tm)
{
    if (tm->end.tv_sec != 0) {
        tm->start = tm->end;
    }
    gettimeofday(&tm->end, NULL);
    tm->diff = zc_timediff(&tm->start, &tm->end);
    return tm->diff;
}

uint32_t
zc_timediff(struct timeval *start, struct timeval *end)
{
    return 1000000 * (end->tv_sec - start->tv_sec) + (end->tv_usec - start->tv_usec);
}

uint64_t
zc_timenow()
{
    struct timeval tm;

    gettimeofday(&tm, NULL);
    return tm.tv_sec*1000000L + tm.tv_usec;
}
