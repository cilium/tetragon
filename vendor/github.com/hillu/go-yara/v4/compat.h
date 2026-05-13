#ifndef _COMPAT_H
#define _COMPAT_H

#ifdef _WIN32
#define fdopen _fdopen
#define dup _dup
#endif

#ifdef _WIN32
int _yr_compiler_add_fd(
    YR_COMPILER* compiler,
    int rules_fd,
    const char* namespace_,
    const char* file_name);
#else
#define _yr_compiler_add_fd yr_compiler_add_fd
#endif

#ifdef _WIN32
int _yr_rules_scan_fd(
    YR_RULES* rules,
    int fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout);
#else
#define _yr_rules_scan_fd yr_rules_scan_fd
#endif

#ifdef _WIN32
#include <stdint.h>
int _yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    int fd);
#else
#define _yr_scanner_scan_fd yr_scanner_scan_fd
#endif

#endif /* _COMPAT_H */
