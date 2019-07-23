#ifndef ZOCLE_UTILS_TIMES_H
#define ZOCLE_UTILS_TIMES_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

uint32_t zc_timediff(struct timeval *start, struct timeval *end);
uint64_t zc_timenow();

typedef struct zc_timer_t
{
	struct timeval start;
	struct timeval end;
	uint32_t	   diff;
}zcTimer;

void	 zc_timer_start(zcTimer *);
uint32_t zc_timer_end(zcTimer *);


#endif
