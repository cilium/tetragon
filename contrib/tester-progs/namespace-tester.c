// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef MAX_BUF
#define MAX_BUF 200
#endif

#define errExit(msg) \
   do { \
      perror(msg); \
      exit(EXIT_FAILURE); \
   } while (0)

void do_write()
{
   char text[] = "testdata";
   FILE *fptr = fopen("./strange.txt","w");
   if(fptr == NULL) 
      errExit("fopen");
   fwrite(text, 1, sizeof(text), fptr);
   fclose(fptr);
}

void leave_from_rootns()
{
   if (unshare(CLONE_NEWNS) == -1) 
      errExit("unshare");
}

void return_to_rootns()
{
   const char *root_ns = "/proc/1/ns/mnt";
   int fd = open(root_ns, O_RDONLY | O_CLOEXEC);
   if (fd == -1)
      errExit("open");

   if (setns(fd, 0) == -1)
      errExit("setns");

   close(fd);
}

unsigned int my_ns()
{
   pid_t pid;
   char link[128], buf[128];
   ssize_t nbytes;
   unsigned int mnt_ns = 0;

   pid = getpid();
   sprintf(link, "/proc/%d/ns/mnt", pid);

   nbytes = readlink(link, buf, 128);
   if (nbytes == -1) 
      errExit("readlink");

   sscanf(buf, "mnt:[%u]", &mnt_ns);

   return mnt_ns;
}

int main(int argc, char *argv[])
{
   char path[MAX_BUF];

   if (getcwd(path, MAX_BUF) == NULL)
      errExit("getcwd"); 
   
   do_write();

   leave_from_rootns();

   if (chdir(path) == -1)
      errExit("chdir"); 

   do_write();

   return_to_rootns();

   if (chdir(path) == -1)
      errExit("chdir"); 

   do_write();

   return 0;
}
