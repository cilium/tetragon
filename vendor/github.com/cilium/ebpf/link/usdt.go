package link

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

type UsdtSpec struct {
	Off      uint64
	Base     uint64
	Sema     uint64
	Provider string
	Name     string
	Args     string
}

type UsdtTarget struct {
	Spec    *UsdtSpec
	IpAbs   uint64
	IpRel   uint64
	SemaOff uint64
}

func (ex *Executable) UsdtTargets() ([]*UsdtTarget, error) {
	var err error

	ex.cachedUsdtOnce.Do(func() {
		var f *internal.SafeELFFile

		f, err = internal.OpenSafeELFFile(ex.path)
		if err != nil {
			err = fmt.Errorf("parse ELF file: %w", err)
			return
		}
		defer f.Close()
		err = ex.loadUsdt(f)
	})
	if err != nil {
		return nil, fmt.Errorf("lazy load usdt: %w", err)
	}

	return ex.cachedUsdt, nil
}

type usdtAddrs struct {
	Off  uint64
	Base uint64
	Sema uint64
}

type elfNoteHeader struct {
	NameSize int32
	DescSize int32
	Type     int32
}

func getBase(f *internal.SafeELFFile) (uint64, error) {
	sections := f.SectionsByName(".stapsdt.base")
	if len(sections) > 1 {
		return 0, fmt.Errorf("more than 1 .stapsdt.base sections")
	}
	if len(sections) == 1 {
		return sections[0].Addr, nil
	}
	return 0, nil
}

func (ex *Executable) loadUsdt(f *internal.SafeELFFile) error {
	base, err := getBase(f)
	if err != nil {
		return err
	}

	sections := f.SectionsByType(elf.SHT_NOTE)
	if len(sections) == 0 {
		return fmt.Errorf("no note section found in vDSO ELF")
	}

	for _, sec := range sections {
		sr := sec.Open()
		var n elfNoteHeader

		// Read notes until we find one named 'Linux'.
		for {
			if err := binary.Read(sr, f.ByteOrder, &n); err != nil {
				if errors.Is(err, io.EOF) {
					// We looked at all the notes in this section
					break
				}
				return fmt.Errorf("reading note header: %w", err)
			}

			// If a note name is defined, it follows the note header.
			var note string

			if n.NameSize > 0 {
				// Read the note name, aligned to 4 bytes.
				buf := make([]byte, internal.Align(n.NameSize, 4))
				if err := binary.Read(sr, f.ByteOrder, &buf); err != nil {
					return fmt.Errorf("reading note name: %w", err)
				}

				// Read nul-terminated string.
				note = unix.ByteSliceToString(buf[:n.NameSize])
			}

			if note != "stapsdt" || n.Type != 3 {
				// Discard the note descriptor if it exists but we're not interested in it.
				if _, err := io.CopyN(io.Discard, sr, int64(internal.Align(n.DescSize, 4))); err != nil {
					return err
				}
				continue
			}

			var (
				spec  UsdtSpec
				addrs usdtAddrs
			)

			if n.DescSize < int32(unsafe.Sizeof(addrs))+3 {
				return fmt.Errorf("failed to read elf note")
			}

			if err := binary.Read(sr, f.ByteOrder, &addrs); err != nil {
				return fmt.Errorf("reading note descriptor: %w", err)
			}

			size := internal.Align(n.DescSize, 4)
			data := make([]byte, size-int32(unsafe.Sizeof(addrs)))
			if err := binary.Read(sr, f.ByteOrder, &data); err != nil {
				return fmt.Errorf("reading note descriptor: %w", err)
			}

			parse := func(arr []byte) (string, []byte, error) {
				idx := bytes.IndexByte(arr, 0)
				if idx == -1 {
					return "", nil, fmt.Errorf("failed to parse usdt string")
				}
				return string(arr[:idx]), arr[idx+1:], nil
			}

			spec.Provider, data, err = parse(data)
			if err != nil {
				return err
			}
			spec.Name, data, err = parse(data)
			if err != nil {
				return err
			}
			spec.Args, _, err = parse(data)
			if err != nil {
				return err
			}
			spec.Off = addrs.Off
			spec.Base = addrs.Base
			spec.Sema = addrs.Sema

			ipAbs := spec.Off
			if base != 0 && spec.Base != 0 {
				ipAbs += base - spec.Base
			}

			prog := f.ProgByVaddr(ipAbs)
			if prog == nil {
				return fmt.Errorf("failed to find elf program header for %x", ipAbs)
			}

			if prog.Flags&elf.PF_X == 0 {
				return fmt.Errorf("failed to find elf program header for %x with PF_X", ipAbs)
			}

			ipRel := ipAbs - prog.Vaddr + prog.Off

			var semaOff uint64

			if spec.Sema != 0 {
				prog := f.ProgByVaddr(spec.Sema)
				if prog == nil {
					return fmt.Errorf("failed to find elf program header for %x", spec.Sema)
				}

				if prog.Flags&elf.PF_X != 0 {
					return fmt.Errorf("failed to find elf program header for %x without PF_X", spec.Sema)
				}

				semaOff = spec.Sema - prog.Vaddr + prog.Off
			}

			fmt.Printf("KRAVA %s %x/%x/%x/%x %s/%s/%s\n", note,
				spec.Off, spec.Base, spec.Sema, semaOff,
				spec.Provider, spec.Name, spec.Args)

			target := &UsdtTarget{
				Spec:    &spec,
				IpAbs:   ipAbs,
				IpRel:   ipRel,
				SemaOff: semaOff,
			}

			ex.cachedUsdt = append(ex.cachedUsdt, target)
		}
	}
	return nil
}
