// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright Authors of Tetragon

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/capability.h>

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

void print_my_cap(cap_value_t c, cap_flag_t ty) 
{
   cap_t cap;
   cap_flag_value_t cap_flags_value;

   cap = cap_get_proc();
	if (cap == NULL)
      errExit("cap_get_proc"); 

   cap_get_flag(cap, c, ty, &cap_flags_value);
   printf("%s\n", (cap_flags_value == CAP_SET) ? "OK" : "NOK");

   cap_free(cap);
}

void clear_my_cap(cap_value_t c, cap_flag_t ty)
{
   cap_t cap;
   cap_value_t cap_list[CAP_LAST_CAP+1];

  	cap = cap_get_proc();
	if (cap == NULL)
      errExit("cap_get_proc"); 

   cap_list[0] = c;
   if (cap_set_flag(cap, ty, 1, cap_list, CAP_CLEAR) == -1)
      errExit("cap_set_flag"); 

   if (cap_set_proc(cap) == -1)
      errExit("cap_set_proc"); 

   cap_free(cap); 
}

void set_my_cap(cap_value_t c, cap_flag_t ty)
{
   cap_t cap;
   cap_value_t cap_list[CAP_LAST_CAP+1];

   cap = cap_get_proc();
	if (cap == NULL)
      errExit("cap_get_proc"); 

   cap_list[0] = c;
   if (cap_set_flag(cap, ty, 1, cap_list, CAP_SET) == -1)
      errExit("cap_set_flag"); 

   if (cap_set_proc(cap) == -1)
      errExit("cap_set_proc"); 

   cap_free(cap);
}

int main(int argc, char *argv[])
{
   // print_my_cap(CAP_MKNOD, CAP_EFFECTIVE);
   do_write();

   clear_my_cap(CAP_MKNOD, CAP_EFFECTIVE);

   // print_my_cap(CAP_MKNOD, CAP_EFFECTIVE);
   do_write();

   set_my_cap(CAP_MKNOD, CAP_EFFECTIVE);

   // print_my_cap(CAP_MKNOD, CAP_EFFECTIVE);
   do_write();

   return 0;
}
