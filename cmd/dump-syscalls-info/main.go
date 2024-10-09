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
	SyscallsInfo SyscallsInfoCmd `cmd:"" name:"info" help:"dump syscalls info"`
}

type SyscallsInfoCmd struct {
	VmLinux  string `name:"vmlinux"`
	JsonFile string `name:"jsonfile" help:"json file to update (or create)"`
	DryRun   bool
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

func updateArgs(l *slog.Logger, oldArgs []SyscallArg, newArgs []SyscallArg) []SyscallArg {
	compatibleTypes := map[string]string{
		"__kernel_old_time_t *":              "time_t *",
		"struct __kernel_old_timeval *":      "struct timeval *",
		"struct __kernel_timespec *":         "struct timespec *",
		"const struct __kernel_timespec *":   "const struct timespec *",
		"struct __kernel_itimerspec *":       "struct itimerspec *",
		"struct __kernel_old_itimerval *":    "struct itimerval *",
		"const struct __kernel_itimerspec *": "const struct itimerspec *",
		"struct __kernel_timex *":            "struct timex *",
	}
	isCompat := func(ty1, ty2 string) bool {
		v, ok := compatibleTypes[ty1]
		return ok && v == ty2
	}

	nArgs := len(oldArgs)
	if len(newArgs) > len(oldArgs) {
		nArgs = len(newArgs)
	}
	args := make([]SyscallArg, 0, nArgs)
	for i := range nArgs {
		li := l.With("i", i)
		if i >= len(oldArgs) {
			li.Info("argument does not exist in old, keeping new",
				"new", newArgs[i])
			args = append(args, newArgs[i])
			continue
		} else if i >= len(newArgs) {
			li.Info("argument does not exist in new, keeping old",
				"old", oldArgs[i])
			args = append(args, oldArgs[i])
			continue
		} else if oldArgs[i] == newArgs[i] {
			args = append(args, oldArgs[i])
			continue
		}

		// arguments differ
		li = li.With("old", oldArgs[i], "new", newArgs[i])
		oldTy := oldArgs[i].Type
		newTy := newArgs[i].Type
		if newTy != oldTy {
			switch {
			case isCompat(newTy, oldTy):
				li.Info("new type is compatible to old, keeping old")
				args = append(args, oldArgs[i])
			case isCompat(oldTy, newTy):
				li.Info("old type is compatible to old, keeping new")
				args = append(args, newArgs[i])
			default:
				li.Warn("¯\\_(ツ)_/¯, keeping old")
				args = append(args, oldArgs[i])
			}
		} else {
			li.Info("arg names differ, keeping old")
			args = append(args, oldArgs[i])
		}
	}

	return args
}

func updateInfo(
	oldInfo map[string][]SyscallArg,
	newInfo map[string][]SyscallArg,
) map[string][]SyscallArg {
	type valTy struct {
		inOld bool
		inNew bool
	}
	allSyscalls := make(map[string]*valTy)
	for k := range oldInfo {
		allSyscalls[k] = &valTy{inOld: true}
	}
	for k := range newInfo {
		if v := allSyscalls[k]; v == nil {
			allSyscalls[k] = &valTy{inNew: true}
		} else {
			v.inNew = true
		}
	}

	ret := make(map[string][]SyscallArg)
	for k, v := range allSyscalls {
		sl := slog.With("syscall", k)
		if v.inOld && v.inNew {
			ret[k] = updateArgs(sl, oldInfo[k], newInfo[k])
		} else if v.inOld {
			ret[k] = oldInfo[k]
		} else if v.inNew {
			sl.Info("new syscall")
			ret[k] = newInfo[k]
		} else {
			panic("!?!?")
		}
	}
	return ret
}

func (c *SyscallsInfoCmd) Run() error {
	info, err := dumpSyscalls(c.VmLinux)
	if err != nil {
		return err
	}

	outF := os.Stdout
	if c.JsonFile != "" {
		var oldInfo map[string][]SyscallArg
		f, err := os.Open(c.JsonFile)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &oldInfo)
		if err != nil {
			return err
		}
		info = updateInfo(oldInfo, info)
		// NB: If we returned an error, the program will terminate so it's not a big deal to
		// leak a file until we exit.
		f.Close()
	}

	if c.JsonFile != "" && !c.DryRun {
		outF, err = os.Create(c.JsonFile)
		if err != nil {
			return err
		}
		defer outF.Close()
	}

	b, err := json.MarshalIndent(info, "", "   ")
	if err != nil {
		return err
	}
	outF.Write(b)

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
