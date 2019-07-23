#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <zocle/base/defines.h>
#include <zocle/utils/files.h>
#include <zocle/log/logfile.h>


int
zc_isfile (const char *path)
{
    struct stat buf;
    if (stat(path, &buf) != 0)
        return ZC_FALSE;
    if (!S_ISREG(buf.st_mode))
        return ZC_FALSE;
    return ZC_TRUE;
}

int
zc_isdir (const char *path)
{
    struct stat buf;
    if (stat(path, &buf) != 0)
        return ZC_FALSE;
    if (!S_ISDIR(buf.st_mode))
        return ZC_FALSE;
    return ZC_TRUE;
}

int
zc_islink (const char *path)
{
    struct stat buf;
    if (stat(path, &buf) != 0)
        return ZC_FALSE;
    if (!S_ISLNK(buf.st_mode))
        return ZC_FALSE;
    return ZC_TRUE;
}

int
zc_isexists (const char *path)
{
    struct stat buf;
    if (stat(path, &buf) != 0)
        return ZC_FALSE;
    if (!S_ISDIR(buf.st_mode) && !S_ISREG(buf.st_mode) && !S_ISLNK(buf.st_mode))
        return ZC_FALSE;
    return ZC_TRUE;
}

int64_t
zc_file_size(const char *path)
{
    struct stat buf;
    if (stat(path, &buf) != 0) {
        return -1;
    }
    if (S_ISREG(buf.st_mode)) {
        return buf.st_size;
    }
    return -1;
}

int
zc_file_path(const char *argv, char *path)
{
    if (argv[0] == '/') {
        strcpy(path, argv);
        return 0;
    }
    const char *start = argv;
    const char *sp;
    int n = 0;

    while ((sp=strchr(start, '/')) != NULL) {
        int len = sp-start;
        if (len > 2)
            break;
        if (len == 1 && *start != '.')
            break;
        if (len == 2 && (*start != '.' || *(start+1) != '.'))
            break;
        if (len == 2)
            n++;
        start = sp + 1;
    }
    char cwd[1024] = {0};
    getcwd(cwd, sizeof(cwd));
    const char *c = cwd + strlen(cwd);
    while (n>0) {
        while (c>cwd && *c != '/') c++;
        if (c == cwd)
            return ZC_ERR;
        c++; // skip /
        n--;
    }
    int len = c-cwd;
    int slen = 0;
    memcpy(path, cwd, c-cwd);
    sp = strrchr(start, '/');
    if (sp != NULL) {
        path[len] = '/';
        len++;
        sp--; // skip /
        slen = sp-start;
        if (slen > 0) memcpy(path+len+1, start, slen);
    }
    path[len+slen] = 0;

    return 0;
}


int
zc_dir_walk(char *path, int dep, int (*func)(char *root, char *name, int mode))
{
	DIR *d;
    struct dirent *file;
    struct stat sb;
	char	filename[256];

	d = opendir(path);
    if (!d) {
        ZCINFO("opendir error: %s %d!", path, errno);
        return ZC_ERR;
    }
    while ((file = readdir(d)) != NULL) {
        if (strncmp(file->d_name, ".", 1) == 0)
            continue;
		snprintf(filename, sizeof(filename), "%s/%s", path, file->d_name);
		if (stat(filename, &sb) < 0) {
            //ZCDEBUG("stat error");
			continue;
        }
        //strcpy(filename[len++], file->d_name);
		func(filename, file->d_name, sb.st_mode);
        if (S_ISDIR(sb.st_mode) && dep <= 100) {
            zc_dir_walk(filename, dep+1, func);
        }
    }
    closedir(d);
    return ZC_OK;
}





