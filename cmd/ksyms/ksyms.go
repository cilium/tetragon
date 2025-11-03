// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/ksyms"
)

// NB: I should do proper tests but for now, I do something like:
//
// $ perf record -g  -e skb:kfree_skb
// ...
// $ perf script | tail
//        ffffffffa870f925 sock_close+0x15 (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa80dfbdc __fput+0xcc (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa80dfdde ____fput+0xe (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa7ec66df task_work_run+0x8f (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa7e04191 exit_to_usermode_loop+0x131 (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa7e045d3 do_syscall_64+0x163 (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//        ffffffffa8a0008c entry_SYSCALL_64+0x7c (/usr/lib/debug/boot/vmlinux-5.4.0-48-generic)
//            7f78e26f43fb __close+0x3b (/usr/lib/x86_64-linux-gnu/libpthread-2.31.so)
//            7f78d7217fac [unknown] ([unknown])
//
// $ sudo ./ksyms 0xffffffffa870f925
// addr 0xffffffffa870f925: sock_close()+0x15
// $  sudo ./ksyms 0xffffffffa8a0008c
// addr 0xffffffffa8a0008c: entry_SYSCALL_64_after_hwframe()+0x44
// $ sudo ./ksyms 0xffffffffa7e045d3
// addr 0xffffffffa7e045d3: do_syscall_64()+0x163
//
// ... which I guess is close enough for now...

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <addr>\n", os.Args[0])
		os.Exit(1)
	}

	arg := os.Args[1]
	base := 10
	if after, ok := strings.CutPrefix(arg, "0x"); ok {
		arg = after
		base = 16
	}

	addr, err := strconv.ParseUint(arg, base, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing address (base: %d) %s", base, err)
		os.Exit(1)
	}

	ks, err := ksyms.NewKsyms("/proc")
	if err != nil {
		log.Fatal(err)
	}

	fnsym, err := ks.GetFnOffset(addr)
	if err == nil {
		fmt.Printf("addr 0x%x: %s\n", addr, fnsym.ToString())
	} else {
		fmt.Printf("addr 0x%x: error: %s\n", addr, err)
	}
}
