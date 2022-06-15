#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define BUFSIZE 9

#define errExit(msg) \
   do { \
      perror(msg); \
      exit(EXIT_FAILURE); \
   } while (0)

void read_with_fd(int fd)
{
    ssize_t retval;
    char buf[BUFSIZE];

    if (lseek(fd, 0, SEEK_SET) != 0)
        errExit("lseek");

    retval = read(fd, buf, BUFSIZE);
    if (retval != BUFSIZE)
        errExit("read");

    buf[BUFSIZE - 1] = '\0';
    printf("%s\n", buf);
}

int main(int argc, char *argv[])
{
    int fd, fd_dup, fd_dup2, fd_dup3;
    const char *pathname = "./strange.txt";

    {
        char *data = "testdata";
        ssize_t retval;

        fd = open(pathname, O_RDWR | O_TRUNC | O_CREAT, S_IRWXU | S_IRWXG);
        if (fd == -1)
            errExit("open");

        retval = write(fd, data, BUFSIZE);
        if (retval != BUFSIZE)
            errExit("write");

        close(fd);
    }

    fd = open(pathname, O_RDONLY);
    if (fd == -1)
        errExit("open");

    read_with_fd(fd);

    fd_dup = dup(fd);
    if (fd_dup == -1)
         errExit("dup");

    read_with_fd(fd_dup);

    fd_dup2 = dup2(fd, 15); // 15 should be an unused file descriptor
    if (fd_dup2 == -1)
        errExit("dup2");

    read_with_fd(fd_dup2);

    fd_dup3 = dup3(fd, 16, 0); // 16 should be an unused file descriptor
    if (fd_dup3 == -1)
        errExit("dup3");

    read_with_fd(fd_dup3);

    close(fd_dup3);
    close(fd_dup2);
    close(fd_dup);
    close(fd);

    {
        if (unlink(pathname) == -1)
            errExit("unlink");
    }

    return 0;
}