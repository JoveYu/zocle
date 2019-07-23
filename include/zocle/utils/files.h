#ifndef ZOCLE_UTILS_FILES_H
#define ZOCLE_UTILS_FILES_H

#include <stdio.h>
#include <stdint.h>

int zc_isfile (const char *path);
int zc_isdir (const char *path);
int zc_islink (const char *path);
int zc_isexists (const char *path);

int64_t zc_file_size(const char *path);
int     zc_file_path(const char *argv, char *path);

int zc_dir_walk(char *path, int dep, int (*func)(char *root, char *name, int mode));

#endif
