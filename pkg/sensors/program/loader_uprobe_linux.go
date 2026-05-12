// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	tetragonelf "github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

type uprobeAttachFunc func(*Program, *ebpf.Program, *ebpf.ProgramSpec, string, ...string) (unloader.Unloader, error)

func procSelfFDPath(f *os.File) string {
	return filepath.Join(option.Config.ProcFS, "self", "fd", strconv.FormatUint(uint64(f.Fd()), 10))
}

func parseSymbol(sym string) (string, uint64, error) {
	parts := strings.Split(sym, "+")
	if len(parts) == 1 {
		return sym, 0, nil
	}
	if len(parts) != 2 {
		return parts[0], 0, fmt.Errorf("wrong symbol %q", sym)
	}
	sym = parts[0]
	str := parts[1]
	offset, err := strconv.ParseUint(str, 0, 0)
	if err != nil {
		return sym, 0, fmt.Errorf("wrong offset %q", str)
	}
	return sym, offset, nil
}

func getAddress(f *os.File, configSymbol string, configAddress, configOffset uint64, addressOffset *uint64, addrType AddressType) (string, uint64, uint64, error) {
	var err error
	var offset uint64
	var address uint64
	var ok bool
	var symbol string

	elfFile, err := tetragonelf.NewSafeELFFile(f)
	if err != nil {
		return "", 0, 0, fmt.Errorf("faild to parse ELF data: %w", err)
	}

	switch addrType {
	case Symbol:
		symbol, offset, err = parseSymbol(configSymbol)
		if err != nil {
			return "", 0, 0, fmt.Errorf("failed to parse symbol '%s': %w", configSymbol, err)
		}

		if elfFile.IsStrippedPureGoBinary() {
			if offset != 0 {
				return "", 0, 0, fmt.Errorf("offset is not supported for Go binaries, but got offset %d for symbol '%s'", offset, symbol)
			}
			tbl, pclnErr := elfFile.Pclntab()
			if pclnErr != nil {
				return "", 0, 0, fmt.Errorf("failed to parse pclntab: %w", pclnErr)
			}
			address, ok = tbl.OffsetByName(symbol)
			if !ok {
				return "", 0, 0, fmt.Errorf("symbol '%s' not found in pclntab", symbol)
			}
			symbol = "" // symbol is not used for Go binaries, as we attach by offset only
		}
	case Offset:
		address = configOffset
		if addressOffset != nil {
			*addressOffset = address
		}
	case Address:
		address, err = elfFile.OffsetFromAddr(configAddress)
		if err != nil {
			return "", 0, 0, fmt.Errorf("failed to get offset from address '%d': %w", configAddress, err)
		}
		if addressOffset != nil {
			*addressOffset = address
		}
	default:
		return "", 0, 0, fmt.Errorf("invalid address type: %d", addrType)
	}

	return symbol, address, offset, nil
}

func getAddresses(f *os.File, attach *MultiUprobeAttachSymbolsCookies) ([]string, []uint64, []uint64, error) {
	var addresses []uint64
	var offsets []uint64
	var symbols []string

	switch attach.AddressType {
	case Symbol:
		for _, sym := range attach.Symbols {
			symbol, address, offset, err := getAddress(f, sym, 0, 0, nil, attach.AddressType)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get address for symbol '%s': %w", sym, err)
			}

			if symbol != "" {
				symbols = append(symbols, symbol)
				offsets = append(offsets, offset)
			} else {
				addresses = append(addresses, address)
				offsets = append(offsets, offset)
			}
		}
	case Address:
		for i, addr := range attach.Addresses {
			var addressOffset *uint64
			if i < len(attach.AddressOffsets) {
				addressOffset = attach.AddressOffsets[i]
			}
			_, address, offset, err := getAddress(f, "", addr, 0, addressOffset, attach.AddressType)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get offset for address '%d': %w", addr, err)
			}
			addresses = append(addresses, address)
			offsets = append(offsets, offset)
		}
	case Offset:
		for i, off := range attach.Offsets {
			var addressOffset *uint64
			if i < len(attach.AddressOffsets) {
				addressOffset = attach.AddressOffsets[i]
			}
			_, address, offset, err := getAddress(f, "", 0, off, addressOffset, attach.AddressType)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to get address for offset '%d': %w", off, err)
			}
			addresses = append(addresses, address)
			offsets = append(offsets, offset)
		}
	default:
		return nil, nil, nil, fmt.Errorf("invalid address type: %d", attach.AddressType)
	}

	return symbols, addresses, offsets, nil
}

// verifyFileDigest verifies that an open file's digest matches the configured digest.
// digestConfig format is "<algo>:<hash>" (e.g., "sha256:abc123..." or "build-id:deadbeef...")
func verifyFileDigest(file *os.File, digestConfig string, fileHashCache map[string]string) error {
	if digestConfig == "" {
		return nil
	}

	parts := strings.SplitN(digestConfig, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid digest format, expected '<algo>:<hash>' but got '%s'", digestConfig)
	}

	algo := strings.ToLower(parts[0])
	expectedHash := strings.ToLower(parts[1])

	if hash, ok := fileHashCache[algo]; ok {
		if hash != expectedHash {
			return fmt.Errorf("digest mismatch: expected %s:%s but got %s:%s", algo, expectedHash, algo, hash)
		}
		logger.GetLogger().Debug(fmt.Sprintf("Digest verified: %s:%s (cached)", algo, hash))
		return nil
	}

	var calculatedHash string

	if algo == "build-id" {
		buildID, err := tetragonelf.ParseBuildId(file)
		if err != nil {
			return fmt.Errorf("failed to extract build ID: %w", err)
		}
		calculatedHash = hex.EncodeToString(buildID)
	} else {
		var hashType crypto.Hash
		switch algo {
		case "sha256":
			hashType = crypto.SHA256
		case "sha384":
			hashType = crypto.SHA384
		case "sha512":
			hashType = crypto.SHA512
		case "sha1":
			hashType = crypto.SHA1
		default:
			return fmt.Errorf("unsupported digest algorithm '%s'", algo)
		}

		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek file: %w", err)
		}

		h := hashType.New()
		if _, err := io.Copy(h, file); err != nil {
			return fmt.Errorf("failed to calculate digest: %w", err)
		}

		calculatedHash = hex.EncodeToString(h.Sum(nil))
	}

	fileHashCache[algo] = calculatedHash

	if calculatedHash != expectedHash {
		return fmt.Errorf("digest mismatch: expected %s:%s but got %s:%s", algo, expectedHash, algo, calculatedHash)
	}

	logger.GetLogger().Debug(fmt.Sprintf("Digest verified: %s:%s", algo, calculatedHash))
	return nil
}

func UprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		if !load.SleepableOffload {
			disableProg(coll, "generic_sleepable_offload")
		}
		if !load.SleepablePreload {
			disableProg(coll, "generic_sleepable_preload")
			disableProg(coll, "generic_sleepable_preload_cleanup")
		}
		return nil
	}
}

func UprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return uprobeAttach(load, bpfDir, coll, collSpec, prog, spec, uprobeAttachSingle)
	}
}

func uprobeAttachSingle(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	data, ok := load.AttachData.(*UprobeAttachData)
	if !ok {
		return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
	}

	linkFn := func() (link.Link, error) {
		// The kernel tracks uprobe targets by inode. When we open a file,
		// its file descriptor points to an inode.
		// The loader API requires that a path is provided. It will not accept
		// a file descriptor directly. But we can use the procfs self/fd/<N> symlink
		// to reference the file descriptor, which is a stable reference to the
		// inode even if the path's inode changes.
		// This trick ensures that the uprobe attachment is not affected by TOCTOU issues
		// with the target file.
		f, err := os.Open(data.Path)
		if err != nil {
			return nil, fmt.Errorf("open executable %s: %w", data.Path, err)
		}
		defer f.Close()

		if len(data.BinaryDigests) > 0 {
			digestCache := make(map[string]string)
			matchFound := false
			for _, digest := range data.BinaryDigests {
				if err := verifyFileDigest(f, digest, digestCache); err == nil {
					matchFound = true
					break
				}
			}
			if !matchFound {
				return nil, errors.New("digest verification failed: no matching digest")
			}
		}

		fdPath := procSelfFDPath(f)
		exec, err := link.OpenExecutable(fdPath)
		if err != nil {
			return nil, err
		}

		symbol, address, offset, err := getAddress(f, data.Symbol, data.Address, data.Offset, data.AddressOffset, data.AddressType)
		if err != nil {
			return nil, fmt.Errorf("failed to get address for path %q: %w", data.Path, err)
		}

		opts := &link.UprobeOptions{
			Address:      address,
			RefCtrOffset: data.RefCtrOffset,
			Offset:       offset,
		}
		if load.RetProbe {
			return exec.Uretprobe(symbol, prog, opts)
		}
		return exec.Uprobe(symbol, prog, opts)
	}

	lnk, err := linkFn()
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}

	err = LinkPin(lnk, bpfDir, load, extra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}

	return &unloader.RelinkUnloader{
		UnloadProg: unloader.ProgUnloader{Prog: prog}.Unload,
		IsLinked:   true,
		Link:       lnk,
		RelinkFn:   linkFn,
	}, nil
}

func MultiUprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return uprobeAttach(load, bpfDir, coll, collSpec, prog, spec, uprobeAttachMulti)
	}
}

func attachMultiUpobeLink(load *Program, prog *ebpf.Program, path string, attach *MultiUprobeAttachSymbolsCookies, digests []string, bpfDir string, idx int, extra ...string) (link.Link, error) {
	// The kernel tracks uprobe targets by inode. When we open a file,
	// its file descriptor points to an inode.
	// The loader API requires that a path is provided. It will not accept
	// a file descriptor directly. But we can use the procfs self/fd/<N> symlink
	// to reference the file descriptor, which is a stable reference to the
	// inode even if the path's inode changes.
	// This trick ensures that the uprobe attachment is not affected by TOCTOU issues
	// with the target file.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", path, err)
	}
	defer f.Close()

	if len(digests) > 0 {
		digestCache := make(map[string]string)
		matchFound := false
		for _, digest := range digests {
			if err := verifyFileDigest(f, digest, digestCache); err == nil {
				matchFound = true
				break
			}
		}
		if !matchFound {
			return nil, errors.New("digest verification failed: no matching digest")
		}
	}

	fdPath := procSelfFDPath(f)
	exec, err := link.OpenExecutable(fdPath)
	if err != nil {
		return nil, err
	}
	symbols, addresses, offsets, err := getAddresses(f, attach)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for path %q: %w", path, err)
	}
	opts := &link.UprobeMultiOptions{
		Addresses:     addresses,
		Offsets:       offsets,
		RefCtrOffsets: attach.RefCtrOffsets,
		Cookies:       attach.Cookies,
	}
	var lnk link.Link
	if load.RetProbe {
		lnk, err = exec.UretprobeMulti(symbols, prog, opts)
	} else {
		lnk, err = exec.UprobeMulti(symbols, prog, opts)
	}
	if err != nil {
		return nil, err
	}
	pinExtra := append(extra, strconv.Itoa(idx))
	err = LinkPin(lnk, bpfDir, load, pinExtra...)
	if err != nil {
		lnk.Close()
		return nil, err
	}
	return lnk, nil
}

func uprobeAttachMulti(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	bpfDir string, extra ...string) (unloader.Unloader, error) {

	data, ok := load.AttachData.(*MultiUprobeAttachData)
	if !ok {
		return nil, fmt.Errorf("attaching '%s' failed: wrong attach data", spec.Name)
	}

	linkFn := func() ([]link.Link, error) {
		var links []link.Link

		idx := 0
		for path, attach := range data.Attach {
			digests := data.BinaryDigests[path]
			lnk, err := attachMultiUpobeLink(load, prog, path, attach, digests, bpfDir, idx, extra...)
			if err != nil {
				return nil, err
			}
			links = append(links, lnk)
			idx++
		}
		return links, nil
	}

	links, err := linkFn()
	if err != nil {
		return nil, fmt.Errorf("attaching '%s' failed: %w", spec.Name, err)
	}

	return &unloader.MultiRelinkUnloader{
		UnloadProg: unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}.Unload,
		IsLinked: true,
		Links:    links,
		RelinkFn: linkFn,
	}, nil
}

func uprobeAttachExtra(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	progName, pin string, attach uprobeAttachFunc) (unloader.Unloader, error) {

	spec, ok := collSpec.Programs[progName]
	if !ok {
		return nil, fmt.Errorf("spec for %s program not found", progName)
	}

	prog, ok := coll.Programs[progName]
	if !ok {
		return nil, fmt.Errorf("program %s not found", progName)
	}

	prog, err := prog.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone %s program: %w", progName, err)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath, fmt.Sprint("prog_", pin))

	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	un, err := attach(load, prog, spec, bpfDir, pin)
	if err != nil {
		prog.Unpin()
	}
	return un, err
}

func uprobeAttach(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
	prog *ebpf.Program, spec *ebpf.ProgramSpec, attach uprobeAttachFunc) (un unloader.Unloader, err error) {

	var (
		main             unloader.Unloader
		sleepableOffload unloader.Unloader
		sleepablePreload unloader.Unloader
		sleepableCleanup unloader.Unloader
	)

	defer func() {
		un = unloader.ChainUnloader{
			main,
			sleepableOffload,
			sleepablePreload,
			sleepableCleanup,
		}
		if err != nil {
			un.Unload(true)
			un = nil
		}
	}()

	if load.SleepableOffload {
		if sleepableOffload, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_offload", "sleepable_offload", attach); err != nil {
			return nil, err
		}
	}

	if load.SleepablePreload {
		if sleepableCleanup, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_preload_cleanup", "sleepable_preload_cleanup", attach); err != nil {
			return nil, err
		}
	}

	if main, err = attach(load, prog, spec, bpfDir); err != nil {
		return nil, err
	}

	if load.SleepablePreload {
		if sleepablePreload, err = uprobeAttachExtra(load, bpfDir, coll, collSpec,
			"generic_sleepable_preload", "sleepable_preload", attach); err != nil {
			return nil, err
		}
	}

	return un, err
}

func LoadUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Open:   UprobeOpen(load),
		Attach: UprobeAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiUprobeProgram(bpfDir string, load *Program, maps []*Map, verbose int) error {
	opts := &LoadOpts{
		Open:   UprobeOpen(load),
		Attach: MultiUprobeAttach(load, bpfDir),
		Maps:   maps,
	}
	return loadProgram(bpfDir, load, opts, verbose)
}
