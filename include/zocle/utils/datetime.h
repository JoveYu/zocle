#ifndef ZOCLE_UTILS_DATETIME_H
#define ZOCLE_UTILS_DATETIME_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>

typedef struct __zc_datetime
{
    time_t    timestamp;
    struct tm t;
    int       millisec;
    int       zone;

	short	  year;
	char	  month;
	char	  day;
	char	  hour;
	char      minute;
	char      second;
}zcDateTime;

void zc_datetime_init_now(zcDateTime *dt);
void zc_datetime_init(zcDateTime *dt, uint32_t sec, int ms);
void zc_datetime_init_format(zcDateTime *dt, const char *format, const char *tm);
int  zc_datetime_init_str(zcDateTime *dt, const char *tm);
void zc_datetime_init_all(zcDateTime *dt, int year, int month, int day, 
			int hour, int minute, int sec, int msec);

int zc_datetime_year(zcDateTime *);
int zc_datetime_month(zcDateTime *);
int zc_datetime_day(zcDateTime *);
int zc_datetime_hour(zcDateTime *);
int zc_datetime_minute(zcDateTime *);
int zc_datetime_second(zcDateTime *);
int zc_datetime_msec(zcDateTime *);
int zc_datetime_weekday(zcDateTime *);
int zc_datetime_yearday(zcDateTime *);
int zc_datetime_daysec(zcDateTime *);

int zc_datetime_rfc822(zcDateTime *,char *buf, int blen);
int zc_datetime_rfc850(zcDateTime *,char *buf, int blen);
int zc_datetime_rfc1036(zcDateTime *,char *buf, int blen);
int zc_datetime_rfc1123(zcDateTime *,char *buf, int blen);
int zc_datetime_rfc2822(zcDateTime *,char *buf, int blen);
int zc_datetime_rfc3339(zcDateTime *,char *buf, int blen);
int zc_datetime_iso8601(zcDateTime *,char *buf, int blen);
int zc_datetime_atom(zcDateTime *,char *buf, int blen);
int zc_datetime_cookie(zcDateTime *,char *buf, int blen);
int zc_datetime_rss(zcDateTime *,char *buf, int blen);
int zc_datetime_w3c(zcDateTime *,char *buf, int blen);

int zc_datetime_format(zcDateTime *,const char *frmt, char *buf, int blen);
int zc_datetime_str(zcDateTime *,char *buf, int blen);

//void zc_datetime_print(zcDateTime *);

#endif
