#include <sys/mount.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    char mount_template[] = "/tmp/mnt.XXXXXX";
    char *mount_point = NULL;
    int status = 0;

    // Create a unique mount point directory under /tmp for this run.
    mount_point = mkdtemp(mount_template);
    if (mount_point == NULL) {
        perror("mkdtemp failed");
        return 1;
    }

    // Passing NULL as the first argument (source)
    if (mount(NULL, mount_point, "tmpfs", 0, NULL) == 0) {
        printf("Mount successful\n");

        if (umount(mount_point) == 0) {
            printf("Unmount successful\n");
        } else {
            perror("Unmount failed");
            status = 1;
        }
    } else {
        perror("Mount failed");
        status = 1;
    }

    if (rmdir(mount_point) == 0) {
        printf("Removed mount point\n");
    } else {
        perror("rmdir failed");
        status = 1;
    }

    return status;
}
