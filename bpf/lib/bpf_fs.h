// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __BPF_FS_H__
#define __BPF_FS_H__

struct msg_mount {
        char type[8]; /* super_block fs type */
        char subtype[8]; /* super block subtype */
        __u32 s_dev; /* super_block->s_dev */
        __u32 pad;
} __attribute__((packed));

struct msg_inode {
        __u64 i_ino;
        __u32 i_nlink;
        __u32 pad;
} __attribute__((packed));

struct msg_file {
        struct msg_inode inode;
        struct msg_mount mount;
} __attribute__((packed));

#endif
