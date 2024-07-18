#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TARGET_PROG "/usr/bin/id"

int main() {
    const char *src = TARGET_PROG;
    const char *dst = "/tmp/id";
    
    if (symlink(src, dst) == -1) {
        perror("Error creating symlink");
        return 1;
    }

    char *const argv[] = {TARGET_PROG, NULL};
    char *const envp[] = {NULL};
    if (execve(dst, argv, envp) == -1) {
        perror("Error executing command");
        unlink(dst);
        return 1;
    }

    if (unlink(dst) == -1) {
        perror("Error deleting symlink");
        return 1;
    }
    
    return 0;
}

