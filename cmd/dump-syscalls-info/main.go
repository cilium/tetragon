// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type SyscallArg struct {
	Name string
	Type string
}

func dumpSyscalls(fname string) {
	f, err := elf.Open(fname)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	elfSyms, err := f.Symbols()
	if err != nil {
		panic(err)
	}

	typs := make(map[string]*elf.Symbol)
	args := make(map[string]*elf.Symbol)

	secDataIdx := -1
	secRodataIdx := -1
	var secData, secRodata *elf.Section
	for idx, s := range f.Sections {
		if s.Name == ".data" {
			secDataIdx = idx
			secData = s
		} else if s.Name == ".rodata" {
			secRodataIdx = idx
			secRodata = s
		}
	}
	if secDataIdx == -1 || secRodataIdx == -1 {
		panic("no .data")
	}
	// fmt.Printf(".data section %+v\n", secData)
	secDataReader := secData.Open()
	// fmt.Printf(".rodata section %+v\n", secData)
	secRodataReader := secRodata.Open()

	for i := range elfSyms {
		s := &elfSyms[i]
		if strings.HasPrefix(s.Name, "types__") {
			syscall := strings.TrimPrefix(s.Name, "types__")
			typs[syscall] = s
		} else if strings.HasPrefix(s.Name, "args__") {
			syscall := strings.TrimPrefix(s.Name, "args__")
			args[syscall] = s
		}
	}

	ReadString := func(dataAddr uint64) string {
		_, err := secDataReader.Seek(int64(dataAddr-secData.Addr), io.SeekStart)
		if err != nil {
			panic(err)
		}

		var v uint64
		err = binary.Read(secDataReader, f.FileHeader.ByteOrder, &v)
		if err != nil {
			panic("read failed")
		}

		_, err = secRodataReader.Seek(int64(v-secRodata.Addr), io.SeekStart)
		if err != nil {
			panic("seek to value failed")
		}
		brd := bufio.NewReader(secRodataReader)
		data, _ := brd.ReadBytes(0)
		return string(data[:len(data)-1])
	}

	info := make(map[string][]SyscallArg, 0)
	for name := range typs {
		typSym := typs[name]
		argSym := args[name]
		if int(typSym.Section) != secDataIdx || int(argSym.Section) != secDataIdx {
			panic("symbols not in .data")
		}
		if (typSym.Size != argSym.Size) || (typSym.Size%8 != 0) {
			panic("invalid symbol size")
		}

		arr := make([]SyscallArg, 0)
		n := typSym.Size / 8
		for i := uint64(0); i < n; i++ {
			typPtr := typSym.Value + (i * 8)
			typStr := ReadString(typPtr)
			argPtr := argSym.Value + (i * 8)
			argStr := ReadString(argPtr)
			arr = append(arr, SyscallArg{
				Name: argStr,
				Type: typStr,
			})
		}
		info[name] = arr

	}

	b, err := json.MarshalIndent(info, "", "   ")
	if err != nil {
		panic(err)
	}
	os.Stdout.Write(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <kernel_image>\n", os.Args[0])
		os.Exit(1)
	}
	dumpSyscalls(os.Args[1])
}
