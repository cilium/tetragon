#include <stdio.h>

void uprobe_test_lib(void);

// argument test functions
int uprobe_test_lib_arg1(int a1);
int uprobe_test_lib_arg2(char a1, short a2);
int uprobe_test_lib_arg3(unsigned long a1, unsigned int a2, void *a3);
int uprobe_test_lib_arg4(long a1, int a2, char a3, void *a4);
int uprobe_test_lib_arg5(int a1, char a2, unsigned long a3, short a4, void *a5);

int main(void)
{
	uprobe_test_lib();
	uprobe_test_lib_arg1(123);
	uprobe_test_lib_arg2('a', 4321);
	uprobe_test_lib_arg3(1, 0xdeadbeef, NULL);
	uprobe_test_lib_arg4(-321, -2, 'b', (void *) 1);
	uprobe_test_lib_arg5(1, 'c', 0xcafe, 1234, (void *) 2);
}
