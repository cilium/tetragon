#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) char *return_string(char *param)
{
    char *tmp = malloc(32);
    snprintf(tmp, 32, "ret %s", param);
    return tmp;
}

// Returns the number of bytes written (including the NUL terminator) so a
// uretprobe with returnCopy can use the return value as the buffer size.
__attribute__((noinline)) int fill_string(char *param)
{
    strcpy(param, "filled");
    // Keep param alive to avoid pagefault.
    printf("%s\n", param);
    return strlen(param) + 1;
}

int main(int argc, char **argv)
{
    // Trigger an uretprobe to catch return value. A return Override can
    // replace the result with NULL, so report that in the exit code.
    char *ret = return_string("input");
    if (!ret)
        return 1;
    free(ret);

    // Trigger an uretprobe to fetch param value from return
    char str[10];
    fill_string(str);

    return 0;
}
