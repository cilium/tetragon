// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

// This program is used to test tracing policies. It can be called in two ways:
//  - with three arguments: it uses the arguments to execute an lseek syscall
//  - with no arguments, it uses three arguments from stdin, and executes itself with them

func readFromStdin(selfBin string) {
	var fd, whence int
	var off int64

	for {
		n, err := fmt.Scanf("%d %d %d\n", &fd, &off, &whence)
		if errors.Is(err, io.EOF) {
			log.Println("got EOF: terminating")
			return
		} else if err != nil {
			log.Fatalf("failed to scan stdin: %v", err)
		} else if n != 3 {
			log.Fatalf("scanned %d args instead of 3", n)
		}
		cmd := exec.Command(selfBin,
			fmt.Sprintf("%d", fd),
			fmt.Sprintf("%d", off),
			fmt.Sprintf("%d", whence),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("err: %v", err)
		}
		fmt.Printf("%s", string(out))
	}
}

func main() {
	args := os.Args[1:]
	switch len(args) {
	case 0:
		readFromStdin(os.Args[0])
	case 3:
		fd, err := strconv.ParseInt(args[0], 10, 32)
		if err != nil {
			log.Fatalf("invalid fd: %s", args[0])
		}
		off, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			log.Fatalf("invalid off: %s", args[1])
		}
		whence, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			log.Fatalf("invalid whence: %s", args[2])
		}
		o, err := unix.Seek(int(fd), off, int(whence))
		fmt.Printf("lseek(%d, %d, %d) -> (%d, %v)\n", fd, off, whence, o, err)
	default:
		log.Fatalf("Invalid number of arguments: expecting 0 (to read from stdin) or 3 (to execute lseek)")
	}
}
