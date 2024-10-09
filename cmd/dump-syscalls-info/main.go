// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/alecthomas/kong"
)

type cli struct {
	SyscallsInfo SyscallsInfo `cmd:"info" name:"info" help:"dump syscalls info"`
}

type SyscallsInfo struct {
	VmLinux string `name:"vmlinux"`
}

type SyscallArg struct {
	Name string
	Type string
}

func dumpSyscalls(fname string) (map[string][]SyscallArg, error) {
	f, err := elf.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	elfSyms, err := f.Symbols()
	if err != nil {
		return nil, err
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
		return nil, errors.New("no .data")
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

	ReadString := func(dataAddr uint64) (string, error) {
		_, err := secDataReader.Seek(int64(dataAddr-secData.Addr), io.SeekStart)
		if err != nil {
			return "", err
		}

		var v uint64
		err = binary.Read(secDataReader, f.FileHeader.ByteOrder, &v)
		if err != nil {
			return "", errors.New("read failed")
		}

		_, err = secRodataReader.Seek(int64(v-secRodata.Addr), io.SeekStart)
		if err != nil {
			return "", errors.New("seek to value failed")
		}
		brd := bufio.NewReader(secRodataReader)
		data, _ := brd.ReadBytes(0)
		return string(data[:len(data)-1]), nil
	}

	info := make(map[string][]SyscallArg, 0)
	for name := range typs {
		typSym := typs[name]
		argSym := args[name]
		if int(typSym.Section) != secDataIdx || int(argSym.Section) != secDataIdx {
			return nil, errors.New("symbols not in .data")
		}
		if (typSym.Size != argSym.Size) || (typSym.Size%8 != 0) {
			return nil, errors.New("invalid symbol size")
		}

		arr := make([]SyscallArg, 0)
		n := typSym.Size / 8
		for i := uint64(0); i < n; i++ {
			typPtr := typSym.Value + (i * 8)
			typStr, err := ReadString(typPtr)
			if err != nil {
				return nil, err
			}
			argPtr := argSym.Value + (i * 8)
			argStr, err := ReadString(argPtr)
			if err != nil {
				return nil, err
			}
			arr = append(arr, SyscallArg{
				Name: argStr,
				Type: typStr,
			})
		}
		info[name] = arr

	}

	return info, nil
}

func (c *SyscallsInfo) Run() error {
	info, err := dumpSyscalls(c.VmLinux)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(info, "", "   ")
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	return nil
}

func main() {
	cliCnf := &cli{}
	cliCtx := kong.Parse(cliCnf)
	err := cliCtx.Run()
	if err != nil {
		slog.Error("failed to run", "error", err)
		os.Exit(1)
	}
}
