// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
)

type cli struct {
	SyscallsInfo SyscallsInfoCmd `cmd:"" name:"info" help:"dump syscalls info"`
	SyscallsIDs  SyscallsIDsCmd  `cmd:"" name:"ids" help:"dump ids info (using glibc's headers)"`
}

type SyscallsInfoCmd struct {
	VMLinux  string `name:"vmlinux"`
	JSONFile string `name:"jsonfile" help:"json file to update (or create)"`
	DryRun   bool
}

type SyscallsIDsCmd struct {
	ABI       []string `name:"abi"`
	OutputDir string   `name:"outdir" default:"./pkg/syscallinfo"`
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
		switch s.Name {
		case ".data":
			secDataIdx = idx
			secData = s
		case ".rodata":
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
		err = binary.Read(secDataReader, f.ByteOrder, &v)
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
		for i := range n {
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
	info, err := dumpSyscalls(c.VMLinux)
	if err != nil {
		return err
	}

	outF := os.Stdout
	if c.JSONFile != "" {
		var oldInfo map[string][]SyscallArg
		f, err := os.Open(c.JSONFile)
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

	if c.JSONFile != "" && !c.DryRun {
		outF, err = os.Create(c.JSONFile)
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

func parseLibcArchSyscall(fname string) ([]string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ret := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		fs := strings.Fields(l)
		if len(fs) != 3 || fs[0] != "#define" || !strings.HasPrefix(fs[1], "__NR_") {
			continue
		}

		syscall := fs[1][len("__NR_"):]
		id, err := strconv.ParseInt(fs[2], 0, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse: '%s'", l)
			continue
		}

		idx := int(id)
		newLen := idx + 1
		if len(ret) < newLen {
			if cap(ret) < newLen {
				xret := make([]string, len(ret), newLen)
				copy(xret, ret)
				ret = xret
			}
			ret = ret[0:newLen]
		}
		ret[idx] = syscall
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *SyscallsIDsCmd) Run() error {
	glibcLocation := map[string]string{
		"x86_64": "sysdeps/unix/sysv/linux/x86_64/64",
		"i386":   "sysdeps/unix/sysv/linux/i386",
		"arm64":  "sysdeps/unix/sysv/linux/aarch64",
		"arm32":  "sysdeps/unix/sysv/linux/arm",
	}

	tmpDir, err := os.MkdirTemp("", "glibc-tmp")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	for _, abi := range c.ABI {
		glibcLoc, ok := glibcLocation[abi]
		if !ok {
			slog.Warn("unknown abi, ignoring", "abi", abi)
			continue
		}

		abiTmpDir := filepath.Join(tmpDir, abi)
		if err := os.Mkdir(abiTmpDir, 0755); err != nil {
			slog.Warn("error creationg dir", "dir", abiTmpDir, "err", err)
			continue
		}

		shellCmd := strings.Join([]string{
			"git", "archive",
			"--remote=git://sourceware.org/git/glibc.git",
			//"HEAD:sysdeps/unix/sysv/linux/aarch64",
			"HEAD:" + glibcLoc,
			"--", "arch-syscall.h",
			"|",
			"tar", "xv", "-C", abiTmpDir},
			" ")
		cmd := exec.Command("sh", "-c", shellCmd)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run git command '%s': %w", shellCmd, err)
		}

		ids, err := parseLibcArchSyscall(filepath.Join(abiTmpDir, "arch-syscall.h"))
		if err != nil {
			return err
		}

		goFile := filepath.Join(c.OutputDir, abi, "ids.go")
		err = func() error {
			f, err := os.Create(goFile)
			if err != nil {
				return err
			}
			defer f.Close()

			fmt.Fprintf(f, "// SPDX-License-Identifier: Apache-2.0\n")
			fmt.Fprintf(f, "// Copyright Authors of Tetragon\n\n")
			fmt.Fprintf(f, "package %s\n\n", abi)
			fmt.Fprintf(f, "// This file was generated by dump-syscalls-info\n\n")
			fmt.Fprintf(f, "const (\n")
			for id, name := range ids {
				if name == "" {
					continue
				}
				fmt.Fprintf(f, "\tSYS_%s = %d\n", strings.ToUpper(name), id)
			}
			fmt.Fprintf(f, ")\n\n")
			fmt.Fprintf(f, "var Names = map[int]string{\n")
			for _, name := range ids {
				if name == "" {
					continue
				}
				fmt.Fprintf(f, "\tSYS_%s: %q,\n", strings.ToUpper(name), name)
			}
			fmt.Fprintf(f, "}\n\n")

			return nil
		}()
		if err != nil {
			return err
		}

		cmd = exec.Command("go", "fmt", goFile)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run go fmt: %w", err)
		}

	}

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
