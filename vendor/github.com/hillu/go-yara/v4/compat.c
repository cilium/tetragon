#include <yara.h>

/* 
   Wrappers functions whose sole purpose is converting uintptr as
   returned by (*os.File).Fd() to HANDLE on Windows systems
*/

#ifdef _WIN32

int _yr_compiler_add_fd(
    YR_COMPILER* compiler,
    int rules_fd,
    const char* namespace_,
    const char* file_name)
{
  return yr_compiler_add_fd(compiler, (YR_FILE_DESCRIPTOR)(intptr_t)rules_fd, namespace_, file_name);
}

int _yr_rules_scan_fd(
    YR_RULES* rules,
    int fd,
    int flags,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int timeout)
{
  return yr_rules_scan_fd(rules, (YR_FILE_DESCRIPTOR)(intptr_t)fd, flags, callback, user_data, timeout);
}

int _yr_scanner_scan_fd(
    YR_SCANNER* scanner,
    int fd)
{
  return yr_scanner_scan_fd(scanner, (YR_FILE_DESCRIPTOR)(intptr_t)fd);
}

#endif
