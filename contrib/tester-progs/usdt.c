//go:build ignore
#include <linux/types.h>
#include <stdio.h>
#include "usdt.h"

static volatile int idx = 2;
static volatile __u64 bla = 0xFEDCBA9876543210ULL;
static volatile short nums[] = {-1, -2, -3, -4};

static volatile struct {
        int x;
        signed char y;
} t1 = { 1, -127 };

static void __always_inline trigger_func(int x) {
        long y = 42;

        if (USDT_IS_ACTIVE(test, usdt0))
                USDT_WITH_SEMA(test, usdt0);
        if (USDT_IS_ACTIVE(test, usdt3))
                USDT_WITH_SEMA(test, usdt3, x, y, &bla);
        if (USDT_IS_ACTIVE(test, usdt12)) {
                USDT_WITH_SEMA(test, usdt12,
                             x, x + 1, y, x + y, 5,
                             y / 7, bla, &bla, -9, nums[x],
                             nums[idx], t1.y);
        }
}

int main(int argc, char **argv)
{
	trigger_func(1);
	trigger_func(2);
	trigger_func(3);
	return 0;
}
