#include <zocle/log/logfile.h>
#include <zocle/mem/alloc.h>
#include <zocle/base/defines.h>
#include <zocle/utils/datetime.h>
#include <zocle/utils/files.h>

#include <time.h>
#include <sys/timeb.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// static char *_log_level2str[]   = {"NOLOG","FATAL","ERR","WARN","NOTICE","INFO","DEBUG","ALL"};
static char *_log_level2str[]   = {"O","F","E","W","N","I","D","A"};
static char *_log_level2color[] = {"","\33[35m","\33[31m","\33[33m","\33[32m","\33[36m","\33[37m",""};

#define _LOG_STDERR(format,args...) do{\
        fprintf(stderr, format, ##args); \
    }while(0)


static zcLogItem* zc_log_find_item(zcLog *log, int loglevel);
static int zc_log_write_real(zcLog *log, zcLogItem *item, char *buffer, int wlen);
static int zc_log_write_fd(int fd, char *buffer, int len);

static unsigned long
_gettid()
{
#ifdef _WIN32
    return (unsigned long)pthread_self().p;
#else
    #ifdef __linux
        return (unsigned long)syscall(SYS_gettid);
    #else
        return (unsigned long)pthread_self();
    #endif
#endif
}

typedef struct _logfile_item {
    int64_t id[2];
    char    name[128];
}LogFileItem;


zcLog   *_zc_log;


static int
zc_log_openfile(zcLog *log, zcLogItem *item)
{
    char filename[PATH_MAX] = {0};

    if (log->suffix == ZC_LOG_SUFFIX_PID) {
        zcDateTime dt;
        zc_datetime_init_now(&dt);
        snprintf(filename, PATH_MAX, "%s.%d%02d%02d.%02d%02d%02d.%d", item->filename,
                dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, getpid());
    }else{
        strcpy(filename, item->filename);
    }

    item->fd = open(filename, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (item->fd == -1) {
        ZCFATAL("open log %s error! %s\n", item->filename, strerror(errno));
        return -1;
    }
    return 0;
}


static int
zc_logitem_init(zcLogItem *item, zcLog *log, const char *filename, int level, int dup)
{
    memset(item, 0, sizeof(zcLogItem));

    item->last_rotate_time = time(NULL);
    strncpy(item->filename, filename, PATH_MAX-1);
    item->protocol = ZC_LOG_FILE;
    item->level = level;
    item->dup   = dup;

    if (strcmp(filename, "stdout") == 0) {
        item->fd = STDOUT_FILENO;
        return ZC_OK;
    }

    // file://path, syslog://name, tcp://ip:port, udp://ip:port
    if (strstr(filename, "://") == NULL) {
        if (strncmp(filename, "tcp://", 6) == 0) {
            item->protocol = ZC_LOG_TCP;
            return ZC_OK;
        }else if (strncmp(filename, "udp://", 6) == 0) {
            item->protocol = ZC_LOG_UDP;
            return ZC_OK;
        }else if (strncmp(filename, "syslog://", 9) == 0) {
            item->protocol = ZC_LOG_SYSLOG;
            return ZC_OK;
        }else if (strncmp(filename, "file://", 7) == 0) {
            item->protocol = ZC_LOG_FILE;
            strncpy(item->filename, filename+7, PATH_MAX);
        }else{
            item->protocol = ZC_LOG_FILE;
        }
    }

    // file
    strncpy(item->filename, filename, PATH_MAX);
    if (strcmp(filename, "stdout") == 0) {
        item->fd = STDOUT_FILENO;
    }else{
        zc_log_openfile(log, item);
    }
    return ZC_OK;
}

zcLog*
zc_log_new(const char *filename, int loglevel)
{
    zcLog   *log = (zcLog*)zc_malloc(sizeof(zcLog));
    zc_log_init(log, filename, loglevel);

    return log;
}

void
zc_log_delete(void *log)
{
    zc_log_destroy(log);
    zc_free(log);
}


int
zc_log_init(zcLog *log, const char *filename, int loglevel)
{
    if (loglevel > ZC_LOG_ALL || loglevel < 0) {
        ZCFATAL("loglevel error:%d\n", loglevel);
        return ZC_ERR;
    }
    memset(log, 0, sizeof(zcLog));

    log->loglevel = loglevel;
    log->maxsize  = 0;
    log->maxtime  = 0;
    log->logwhole = ZC_FALSE;
    log->suffix   = ZC_LOG_SUFFIX_TIME;
    log->check_interval = 5;

    zcLogItem *item = &log->items[loglevel];
    zc_logitem_init(item, log, filename, loglevel, 0);

    if (pthread_mutex_init(&log->lock, NULL) != 0) {
        char errbuf[1024];
        strerror_r(errno, errbuf, 1024);
        fprintf(stderr, "mutex init error: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    _zc_log = log;

    return ZC_OK;
}

void
zc_log_destroy(void *x)
{
    zcLog   *log = (zcLog*)x;
    int i;
    for (i=0; i<ZC_LOG_ALL; i++) {
        zcLogItem *item = &log->items[i];
        if (item->fd > 2 && item->fd != STDOUT_FILENO) {
            close(item->fd);
        }
    }
}

void
zc_log_whole(zcLog *log, int flag)
{
    log->logwhole = flag;
}

void
zc_log_set_prefix(zcLog *log, char *prefix)
{
    if (NULL == prefix) {
        log->logprefix[0] = 0;
        return;
    }
    snprintf(log->logprefix, sizeof(log->logprefix), "%s", prefix);
}

int
zc_log_rotate_size(zcLog *log, int logsize, int logcount)
{
    log->maxsize = logsize;
    log->count   = logcount % 1000;
    log->rotate_type = ZC_LOG_ROTATE_SIZE;

    return ZC_OK;
}

int
zc_log_rotate_time(zcLog *log, int logtime, int logcount)
{
    log->maxtime = logtime;
    log->count   = logcount % 1000;
    log->rotate_type = ZC_LOG_ROTATE_TIME;
    return ZC_OK;
}

int
zc_log_rotate_timeat(zcLog *log, int day, int hour, int min, int logcount)
{
    log->timeat[0] = day;
    log->timeat[1] = hour;
    log->timeat[2] = min;
    log->count = logcount % 1000;
    log->rotate_type = ZC_LOG_ROTATE_TIMEAT;
    return ZC_OK;
}

int
zc_log_rotate_watch(zcLog *log)
{
    log->rotate_type = ZC_LOG_ROTATE_WATCH;
    return ZC_OK;
}

void
zc_log_rotate_no(zcLog *log)
{
    log->rotate_type = ZC_LOG_ROTATE_NO;
}

static zcLogItem*
zc_log_find_item(zcLog *log, int loglevel)
{
    int i;
    zcLogItem *item = NULL;
    for (i=loglevel; i<=ZC_LOG_ALL; i++) {
        if (log->items[i].fd > 0) {
            item = &log->items[i];
            break;
        }
    }
    return item;
}

static int
zc_log_write_fd(int fd, char *buffer, int wlen)
{
    int rwlen = wlen;
    int wrn   = 0;
    int ret;

    while (rwlen > 0) {
        ret = write(fd, buffer + wrn, rwlen);
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }else{
                break;
            }
        }
        rwlen -= ret;
        wrn   += ret;
    }
    return wrn;
}

static int
zc_log_write_real(zcLog *log, zcLogItem *item, char *buffer, int wlen)
{
    int wrn   = 0;
    if (NULL == item) {
        return ZC_ERR;
    }

    if (item->protocol == ZC_LOG_FILE) {
        wrn = zc_log_write_fd(item->fd, buffer, wlen);
    }else if (item->protocol == ZC_LOG_TCP) {
    }else if (item->protocol == ZC_LOG_UDP) {
    }else if (item->protocol == ZC_LOG_SYSLOG) {
    }else{
        fprintf(stderr, "no protocol:%d", item->protocol);
    }
    return wrn;
}

static int
zc_log_write_real_dup(zcLog *log, int loglevel, char *buf, int len)
{
    int i;
    zcLogItem *item = NULL;
    for (i=loglevel; i<=ZC_LOG_ALL; i++) {
        if (log->items[i].fd > 0) {
            item = &log->items[i];
            zc_log_write_real(log, item, buf, len);
            if (item->dup == 0)
                break;
        }
    }
    return ZC_OK;
}


static int
compare_logfileitem (const void *a, const void *b)
{
    LogFileItem *a1 = (LogFileItem*)a;
    LogFileItem *b1 = (LogFileItem*)b;

    int ret;

    ret = a1->id[0] - b1->id[0];
    if (ret != 0)
        return ret;

    return a1->id[1] - b1->id[1];
}

static int
zc_log_do_rotate(zcLog *log, int index)
{
    zcLogItem *item = &log->items[index];

    if (log->suffix == ZC_LOG_SUFFIX_PID) {
        goto ROTATE;
    }

    int  i;
    char *logname;
    char logdir[PATH_MAX];
    // find logfile directory
    logname = strrchr(item->filename, '/');
    if (logname == NULL) {
        logname = item->filename;
        strcpy(logdir, ".");
    }else{
        i = 0;
        while (&item->filename[i] < logname) {
            logdir[i] = item->filename[i];
            i++;
        }
        logdir[i] = 0;
        logname++;
    }

    char log_prefix[256];
    strcpy(log_prefix, logname);
    strcat(log_prefix, ".");

    int log_prefix_len = strlen(log_prefix);
    LogFileItem logs[1000];
    DIR *mydir;
    struct dirent *nodes;

    memset(logs, 0, sizeof(logs));

    mydir = opendir(logdir);
    if (NULL == mydir) {
        _LOG_STDERR("open dir %s error\n", logdir);
        exit(EXIT_FAILURE);
    }
    i = 0;
    //int64_t logid;
    char buf[32];
    char *s;
    int  blen;
    // find all logfile
    // 查找所有的日志文件，并按时间排序，如果超过了可能保留的日志文件数，则删除最早的日志文件
    while ((nodes = readdir(mydir)) != NULL) {
        if (strncmp(nodes->d_name, log_prefix, log_prefix_len) == 0 && \
            isdigit(nodes->d_name[log_prefix_len])){
            blen = 0;
            s = &nodes->d_name[log_prefix_len];
            int idx = 0;
            while (*s) {
                if (isdigit(*s)) {
                    buf[blen] = *s;
                    blen++;
                }else if (*s == '.') {
                    buf[blen] = 0;
                    logs[i].id[idx] = strtoll(buf, NULL, 10);
                    blen = 0;
                    idx++;
                    if (idx >= 2)
                        break;
                }
                s++;
            }
            if (idx <= 1) {
                buf[blen] = 0;
                logs[i].id[idx] = strtoll(buf, NULL, 10);
            }
            //_LOG_INFO(ZC_LOG_INFO, "name:%s, id:%d %d, size:%ld\n",
            //    nodes->d_name, (int)logs[i].id[0], (int)logs[i].id[1], sizeof(logs[i].name));
            snprintf(logs[i].name, sizeof(logs[i].name), "%s", nodes->d_name);
            i++;
        }
    }
    closedir(mydir);

    //qsort(logs, i, sizeof(int64_t), compare_int64);
    qsort(logs, i, sizeof(LogFileItem), compare_logfileitem);

    char filename[PATH_MAX];
    char newfilename[PATH_MAX];

    //sprintf(filename, "%s.%d%02d%02d.%02d%02d%02d", item->filename, i);
    if (log->suffix == ZC_LOG_SUFFIX_TIME) {
        if (log->count > 0 && i >= log->count) {
            sprintf(filename, "%s", logs[0].name);
            if (unlink(filename) == -1) {
                _LOG_STDERR("unlink %s error\n", filename);
            }
        }
        time_t timenow = time(NULL);
        struct tm timestru;
        localtime_r(&timenow, &timestru);

        sprintf(newfilename, "%s.%d%02d%02d.%02d%02d%02d", item->filename,
                timestru.tm_year+1900, timestru.tm_mon+1, timestru.tm_mday,
                timestru.tm_hour, timestru.tm_min, timestru.tm_sec);

        char newfile2[PATH_MAX] = {0};
        strcpy(newfile2, newfilename);
        int newfilei = 1;
        while (zc_isfile(newfile2)) {
            snprintf(newfile2, sizeof(newfile2), "%s.%d", newfilename, newfilei);
            newfilei++;
        }
        if (rename(item->filename, newfile2) == -1) {
            _LOG_STDERR("rename %s to %s error\n", filename, newfile2);
        }
    }else{
        // 日志后缀是数量
        // 数量的规则是按时间，从大到小排序，时间越长，num越大
        // 所以，所有文件的num + 1
        for (;i > 0; i--) {
            sprintf(filename, "%s.%d", item->filename, i);
            if (i >= log->count) {
                if (unlink(filename) == -1) {
                    _LOG_STDERR("unlink %s error\n", filename);
                    //exit(EXIT_FAILURE);
                }
            }else{
                sprintf(newfilename, "%s.%d", item->filename, i+1);
                if (rename(filename, newfilename) == -1) {
                    _LOG_STDERR("rename %s to %s error\n", filename, newfilename);
                    //exit(EXIT_FAILURE);
                }
            }
        }
        // 新文件num为1
        sprintf(newfilename, "%s.%d", item->filename, 1);
        if (rename(item->filename, newfilename) == -1) {
            _LOG_STDERR("rename %s to %s error\n", filename, newfilename);
            //exit(EXIT_FAILURE);
        }
    }

ROTATE:
    if (item->fd > 2)
        close(item->fd);
    zc_log_openfile(log, item);

    return ZC_OK;
}

int
zc_log_check_rotate(zcLog *log, int loglevel)
{
    zcLogItem *item = zc_log_find_item(log, loglevel);
    if (NULL == item)
        return ZC_ERR;
    //_LOG_INFO("check log ...\n");
    //uint32_t    timenow = time(NULL);
    time_t    timenow = time(NULL);
    if (item->fd <= 2) { // not stdin 0, stdout 1, stderr 2
        return 0;
    }
    if (timenow - item->last_check_time < log->check_interval) {
        //_LOG_INFO("not need check. %u %u %d\n", timenow,
        //    log->last_check_time, log->check_interval);
        return 0;
    }
    //_LOG_INFO(item->level, "rotate type:%d\n", log->rotate_type);
    int ret;
    struct stat fs;

    pthread_mutex_lock(&log->lock);
    switch(log->rotate_type) {
    case ZC_LOG_ROTATE_SIZE:
        //_LOG_INFO("check size.\n");
        ret = fstat(item->fd, &fs);
        if (ret == -1) {
            _LOG_STDERR("fstat error");
        }else{
            //_LOG_INFO("file size:%d, maxsize:%d\n", (int)fs.st_size, log->maxsize);
            if (fs.st_size >= log->maxsize) {
                zc_log_do_rotate(log, item->level);
                item->last_rotate_time = timenow;
            }
        }
        break;
    case ZC_LOG_ROTATE_TIME:
        //_LOG_INFO("check time. %d, %d\n", timenow - log->last_rotate_time, log->maxtime);
        if (timenow - item->last_rotate_time >= log->maxtime) {
            zc_log_do_rotate(log, item->level);
            item->last_rotate_time = timenow;
        }
        break;
    case ZC_LOG_ROTATE_TIMEAT:
        if (timenow - item->last_rotate_time > 60) {
            struct tm timestru;
            localtime_r(&timenow, &timestru);

            int t[3] = {timestru.tm_mday, timestru.tm_hour, timestru.tm_min};
            int i;
            for (i=0; i<3; i++) {
                if (log->timeat[i] < 0) {
                    continue;
                }
                if (log->timeat[i] != t[i])
                    break;
            }
            if (i == 3) {
                zc_log_do_rotate(log, item->level);
                item->last_rotate_time = timenow;
            }
        }
        break;
    case ZC_LOG_ROTATE_WATCH:
        break;
    case ZC_LOG_ROTATE_REOPEN:
        // 1分钟重新打开文件一次
        if (timenow - item->last_rotate_time >= 60) {
            ZCINFO("reopen log file:%s", item->filename);
            if (item->fd > 2)
                close(item->fd);
            /*item->fd = open(item->filename, O_CREAT|O_WRONLY|O_APPEND, 0644);
            if (-1 == item->fd) {
                _LOG_ERROR(item->level, "open log file %s error\n", item->filename);
                exit(EXIT_FAILURE);
            }*/
            zc_log_openfile(log, item);
            item->last_rotate_time = timenow;
        }
        break;
    }
    item->last_check_time = timenow;
    pthread_mutex_unlock(&log->lock);

    return 0;
}


int
zc_log_write(zcLog *log, int level, const char *file, int line, const char *format, ...)
{
    char    buffer[8192];
    //char    color[16] = {0};
    //char    levelstr[16] = {0};
    char    *color = "";
    char    *levelstr = _log_level2str[level];
    va_list arg;
    int     maxsize = sizeof(buffer)-6; // const. 4+1+1
    int     maxlen = sizeof(buffer)-6; // ascii color end
    int     ret, wlen = 0;
    time_t  timenow;

    struct tm   timestru;
    struct timeb tmb;
    time(&timenow);
    localtime_r(&timenow, &timestru);
    ftime(&tmb);

    char *rsp = strrchr(file, '/');
    if (rsp != NULL) {
        file = rsp + 1;
    }

    zcLogItem *item = zc_log_find_item(log, level);
    if (NULL == item) {
        return ZC_ERR;
    }
    if (item->fd == STDOUT_FILENO) {
        color = _log_level2color[level];
    }

    if (color[0] == 0) {
        ret = snprintf(buffer, maxlen, "%d%02d%02d %02d%02d%02d.%03d %d,%lu %s %s:%d %s",
                    timestru.tm_year-100, timestru.tm_mon+1, timestru.tm_mday,
                    timestru.tm_hour, timestru.tm_min, timestru.tm_sec, tmb.millitm,
                    (int)getpid(), _gettid(), levelstr, file, line,  log->logprefix);
    }else{
        ret = snprintf(buffer, maxlen, "%s%d%02d%02d %02d%02d%02d.%03d %d,%lu %s %s:%d %s",
                    color, timestru.tm_year-100, timestru.tm_mon+1, timestru.tm_mday,
                    timestru.tm_hour, timestru.tm_min, timestru.tm_sec, tmb.millitm,
                    (int)getpid(), _gettid(), levelstr, file, line,  log->logprefix);
    }

    maxlen -= ret;
    wlen = ret;

    if (log->logwhole) {
        zc_log_write_real_dup(log, level, buffer, wlen);

        char *wbuf = NULL;
        va_start (arg, format);
        ret = vasprintf (&wbuf, format, arg);
        va_end (arg);

        int wbuflen = 0;
        if (wbuf != NULL) {
            wbuflen = strlen(wbuf);
            zc_log_write_real_dup(log, level, wbuf, wbuflen);

            if (wbuf[wbuflen-1] != '\n') {
                zc_log_write_real_dup(log, level, "\n", 1);
                wbuflen += 1;
            }

            free(wbuf);
        }
        if (color[0] != 0) {
            zc_log_write_real_dup(log, level, "\33[0m", 4);
            wbuflen += 4;
        }

        zc_log_check_rotate(log, level);
        return wlen + wbuflen;
    }else{
        va_start (arg, format);
        ret = vsnprintf (buffer+wlen, maxlen, format, arg);
        wlen += ret;
        va_end (arg);

        if (wlen > maxsize) {
            wlen = maxsize;
            buffer[wlen] = '\n';
            wlen++;
        }else{
            if (buffer[wlen-1] != '\n') {
                buffer[wlen] = '\n';
                wlen += 1;
            }
        }

        if (color[0] != 0) {
            char *endtmp = "\33[0m";
            strcpy(buffer+wlen, endtmp);
            wlen += strlen(endtmp);
        }
        buffer[wlen] = 0;
        //printf("wlen:%d, %s\n", wlen, buffer);
        //ret = zc_log_write_real(log, item, buffer, wlen);
        ret = zc_log_write_real_dup(log, level, buffer, wlen);
        zc_log_check_rotate(log, level);
        return ret;
    }
}

void
zc_log_flush(zcLog *log)
{
    int i;
    for (i=0; i<ZC_LOG_ALL; i++) {
        fsync(log->items[i].fd);
    }
}



