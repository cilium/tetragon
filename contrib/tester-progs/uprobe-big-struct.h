#ifndef UPROBE_BIG_STRUCT_H
#define UPROBE_BIG_STRUCT_H

// Larger than 16 bytes, so it is returned by value through memory: the caller
// passes the address of the result in x8 on arm64 (indirect result location
// register) and in rdi on x86_64 (hidden first argument).
struct uprobe_test_big_struct {
	long a, b, c, d;
};

#endif
