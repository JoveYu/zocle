#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <ctype.h>
#include <string.h>

#include <zocle/log/logfile.h>
#include <zocle/base/defines.h>
#include <zocle/utils/datetime.h>

static void
zc_datetime_copy_date(zcDateTime *dt)
{
    dt->year   = dt->t.tm_year + 1900;
    dt->month  = dt->t.tm_mon + 1;
    dt->day    = dt->t.tm_mday;
    dt->hour   = dt->t.tm_hour;
    dt->minute = dt->t.tm_min;
    dt->second = dt->t.tm_sec;
}

void
zc_datetime_init_now(zcDateTime *dt)
{
    struct timeb tb;
    ftime(&tb);
    dt->timestamp = tb.time;
    dt->zone = tb.timezone * 60;
    dt->millisec  = tb.millitm;
    localtime_r(&dt->timestamp, &dt->t);

    zc_datetime_copy_date(dt);
}

void
zc_datetime_init(zcDateTime *dt, uint32_t sec, int ms)
{
    memset(dt, 0, sizeof(zcDateTime));
    dt->timestamp = sec;
    localtime_r(&dt->timestamp, &dt->t);
    dt->millisec = ms;

    zc_datetime_copy_date(dt);
}


void
zc_datetime_init_format(zcDateTime *dt, const char *format, const char *tm)
{
    strptime(tm, format, &dt->t);
    dt->timestamp = mktime(&dt->t);
    dt->millisec = 0;

    zc_datetime_copy_date(dt);
}

int
zc_datetime_init_str(zcDateTime *dt, const char *tm)
{
    int tlen = strlen(tm);
    if (tlen == 10) {
        strptime(tm, "%Y-%m-%d", &dt->t);
    }else if (tlen == 19) {
        strptime(tm, "%Y-%m-%d %H:%M:%S", &dt->t);
    }else if (tlen > 19) {
        strptime(tm, "%Y-%m-%d %H:%M:%S %z", &dt->t);
    }else{
        return ZC_ERR;
    }
    dt->timestamp = mktime(&dt->t);
    dt->millisec = 0;

    zc_datetime_copy_date(dt);
    return ZC_OK;
}

void
zc_datetime_init_all(zcDateTime *dt, int year, int month, int day,
			int hour, int minute, int sec, int msec)
{
    memset(&dt->t, 0, sizeof(struct tm));
    dt->t.tm_year = year - 1900;
    dt->t.tm_mon  = month - 1;
    dt->t.tm_mday = day;
    dt->t.tm_hour = hour;
    dt->t.tm_min  = minute;
    dt->t.tm_sec  = sec;

    dt->timestamp = mktime(&dt->t);
    dt->millisec  = msec;

    zc_datetime_copy_date(dt);
}

int
zc_datetime_year(zcDateTime *dt)
{
    return dt->t.tm_year + 1900;
}

int
zc_datetime_month(zcDateTime *dt)
{
    return dt->t.tm_mon + 1;
}

int
zc_datetime_day(zcDateTime *dt)
{
    return dt->t.tm_mday;
}

int
zc_datetime_hour(zcDateTime *dt)
{
    return dt->t.tm_hour;
}

int
zc_datetime_minute(zcDateTime *dt)
{
    return dt->t.tm_min;
}

int
zc_datetime_second(zcDateTime *dt)
{
    return dt->t.tm_sec;
}

int
zc_datetime_msec(zcDateTime *dt)
{
    return dt->millisec;
}

int
zc_datetime_weekday(zcDateTime *dt)
{
    // FIXME: 如果t是赋值来的，可能没有
    return dt->t.tm_wday+1;
}

int
zc_datetime_yearday(zcDateTime *dt)
{
    return dt->t.tm_yday+1;
}
int zc_datetime_daysec(zcDateTime *dt)
{
    return zc_datetime_hour(dt)*3600 + zc_datetime_minute(dt)*60 + zc_datetime_second(dt);
}

int
zc_datetime_rfc822(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%a, %d %b %Y %H:%M:%S %z", buf, blen);
}
int
zc_datetime_rfc850(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%A, %d-%b-%y %H:%M:%S %Z", buf, blen);
}

int
zc_datetime_rfc1036(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%a, %d %b %y %H:%M:%S %z", buf, blen);
}
int
zc_datetime_rfc1123(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%a, %d %b %Y %H:%M:%S %z", buf, blen);
}
int
zc_datetime_rfc2822(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%a, %d %b %Y %H:%M:%S %z", buf, blen);
}

int
zc_datetime_rfc3339(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%Y-%m-%dT%H:%M:%S%z", buf, blen);
}
int
zc_datetime_iso8601(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%Y-%m-%dT%H:%M:%S%z", buf, blen);
}
int
zc_datetime_atom(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%Y-%m-%dT%H:%M:%S%z", buf, blen);
}
int
zc_datetime_cookie(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%A, %d-%b-%y %H:%M:%S %Z", buf, blen);
}
int
zc_datetime_rss(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%a, %d %b %Y %H:%M:%S %z", buf, blen);
}
int
zc_datetime_w3c(zcDateTime *dt,char *buf, int blen)
{
    return zc_datetime_format(dt, "%Y-%m-%dT%H:%M:%S%z", buf, blen);
}

int
zc_datetime_format(zcDateTime *dt,const char *frmt, char *buf, int blen)
{
    size_t sz = strftime(buf, blen, frmt, &dt->t);
    buf[sz] = 0;
    return sz;
}
int
zc_datetime_str(zcDateTime *dt,char *buf, int blen)
{
    return snprintf(buf, blen, "%d-%02d-%02d %02d:%02d:%02d", dt->t.tm_year+1900, dt->t.tm_mon+1,
            dt->t.tm_mday, dt->t.tm_hour, dt->t.tm_min, dt->t.tm_sec);
}

/*void
zc_datetime_print(zcDateTime *dt)
{
    ZCINFO("<DateTime timestamp:%u millisec:%d zone:%d>", (unsigned int)dt->timestamp, dt->millisec, dt->zone);
}
*/

