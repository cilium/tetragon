// SPDX-License-Identifier: (GPL-2.0-only)
// Copyright Authors of Tetragon

#include <linux/init.h>
#include <linux/module.h>

MODULE_DESCRIPTION("A simple Hello world LKM to test Tetragon!");

static int hello_init(void)
{
    printk(KERN_INFO "Tetragon test kernel module: init Hello world module\n");
    return 0;
}

static void hello_exit(void)
{
    printk(KERN_INFO "Tetragon test kernel module: exit Hello world module\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("Tetragon authors");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");