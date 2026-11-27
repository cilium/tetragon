// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// elfSpec describes a minimal little-endian ELF file, with just enough
// structure for debug/elf to report its interpreter and dynamic section.
type elfSpec struct {
	class   elf.Class   // defaults to ELFCLASS64
	machine elf.Machine // defaults to EM_X86_64
	typ     elf.Type    // defaults to ET_DYN
	interp  string
	needed  []string
	runpath string
	rpath   string
	flags1  elf.DynFlag1
}

func exe(needed ...string) elfSpec {
	return elfSpec{interp: "/lib64/ld-linux-x86-64.so.2", needed: needed}
}

var lib64 = elfSpec{}

func (s elfSpec) bytes() []byte {
	if s.class == elf.ELFCLASSNONE {
		s.class = elf.ELFCLASS64
	}
	if s.machine == elf.EM_NONE {
		s.machine = elf.EM_X86_64
	}
	if s.typ == elf.ET_NONE {
		s.typ = elf.ET_DYN
	}
	is64 := s.class == elf.ELFCLASS64
	le := binary.LittleEndian

	var (
		ehdrSize, phdrSize, shdrSize, dynSize uint64 = 52, 32, 40, 8
	)
	if is64 {
		ehdrSize, phdrSize, shdrSize, dynSize = 64, 56, 64, 16
	}

	// string tables
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	addStr := func(str string) uint64 {
		off := uint64(dynstr.Len())
		dynstr.WriteString(str)
		dynstr.WriteByte(0)
		return off
	}
	type dyn struct{ tag, val uint64 }
	var dyns []dyn
	for _, n := range s.needed {
		dyns = append(dyns, dyn{uint64(elf.DT_NEEDED), addStr(n)})
	}
	if s.runpath != "" {
		dyns = append(dyns, dyn{uint64(elf.DT_RUNPATH), addStr(s.runpath)})
	}
	if s.rpath != "" {
		dyns = append(dyns, dyn{uint64(elf.DT_RPATH), addStr(s.rpath)})
	}
	if s.flags1 != 0 {
		dyns = append(dyns, dyn{uint64(elf.DT_FLAGS_1), uint64(s.flags1)})
	}
	dyns = append(dyns, dyn{uint64(elf.DT_NULL), 0})

	shstrtab := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")
	const nameDynstr, nameDynamic, nameShstrtab = 1, 9, 18

	// layout
	var phnum uint64
	if s.interp != "" {
		phnum = 1
	}
	interpOff := ehdrSize + phnum*phdrSize
	interp := []byte(s.interp + "\x00")
	dynstrOff := interpOff + uint64(len(interp))
	if s.interp == "" {
		interp = nil
		dynstrOff = interpOff
	}
	dynamicOff := dynstrOff + uint64(dynstr.Len())
	shstrtabOff := dynamicOff + uint64(len(dyns))*dynSize
	shOff := shstrtabOff + uint64(len(shstrtab))

	var buf bytes.Buffer
	w := func(size int, v uint64) {
		switch size {
		case 2:
			buf.Write(le.AppendUint16(nil, uint16(v)))
		case 4:
			buf.Write(le.AppendUint32(nil, uint32(v)))
		case 8:
			buf.Write(le.AppendUint64(nil, v))
		}
	}
	word := 4
	if is64 {
		word = 8
	}

	// ELF header
	ident := [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(s.class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	buf.Write(ident[:])
	w(2, uint64(s.typ))
	w(2, uint64(s.machine))
	w(4, uint64(elf.EV_CURRENT))
	w(word, 0) // entry
	if phnum > 0 {
		w(word, ehdrSize) // phoff
	} else {
		w(word, 0)
	}
	w(word, shOff)
	w(4, 0) // flags
	w(2, ehdrSize)
	w(2, phdrSize)
	w(2, phnum)
	w(2, shdrSize)
	w(2, 4) // shnum
	w(2, 3) // shstrndx

	// program headers
	if phnum > 0 {
		n := uint64(len(interp))
		if is64 {
			w(4, uint64(elf.PT_INTERP))
			w(4, uint64(elf.PF_R))
			w(8, interpOff)
			w(8, interpOff)
			w(8, interpOff)
			w(8, n)
			w(8, n)
			w(8, 1)
		} else {
			w(4, uint64(elf.PT_INTERP))
			w(4, interpOff)
			w(4, interpOff)
			w(4, interpOff)
			w(4, n)
			w(4, n)
			w(4, uint64(elf.PF_R))
			w(4, 1)
		}
	}

	buf.Write(interp)
	buf.Write(dynstr.Bytes())
	for _, d := range dyns {
		w(word, d.tag)
		w(word, d.val)
	}
	buf.Write(shstrtab)

	// section headers
	shdr := func(name uint64, typ elf.SectionType, off, size, link, entsize uint64) {
		w(4, name)
		w(4, uint64(typ))
		w(word, 0) // flags
		w(word, 0) // addr
		w(word, off)
		w(word, size)
		w(4, link)
		w(4, 0) // info
		w(word, 1)
		w(word, entsize)
	}
	shdr(0, elf.SHT_NULL, 0, 0, 0, 0)
	shdr(nameDynstr, elf.SHT_STRTAB, dynstrOff, uint64(dynstr.Len()), 0, 0)
	shdr(nameDynamic, elf.SHT_DYNAMIC, dynamicOff, uint64(len(dyns))*dynSize, 1, dynSize)
	shdr(nameShstrtab, elf.SHT_STRTAB, shstrtabOff, uint64(len(shstrtab)), 0, 0)

	return buf.Bytes()
}

// dirRoot is a Root rooted at a host directory. It does NOT prevent escaping
// the root via absolute symlinks or "..": it's only meant for tests, where
// the tree content is under our control.
type dirRoot string

func (d dirRoot) Open(p string) (*os.File, error) {
	return os.Open(filepath.Join(string(d), p))
}

func (d dirRoot) RealPath(p string) (string, error) {
	realPath, err := filepath.EvalSymlinks(filepath.Join(string(d), p))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(string(d), realPath)
	if err != nil {
		return "", err
	}
	return "/" + rel, nil
}

// rootfs builds a test root filesystem. Values of files are either an elfSpec,
// a []byte with raw content, or a string denoting a (relative) symlink target.
func rootfs(t *testing.T, files map[string]any) dirRoot {
	t.Helper()
	dir := t.TempDir()
	for p, content := range files {
		full := filepath.Join(dir, p)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		switch c := content.(type) {
		case elfSpec:
			require.NoError(t, os.WriteFile(full, c.bytes(), 0o644))
		case []byte:
			require.NoError(t, os.WriteFile(full, c, 0o644))
		case string:
			require.NoError(t, os.Symlink(c, full))
		default:
			t.Fatalf("unsupported content type %T for %q", content, p)
		}
	}
	return dirRoot(dir)
}

func TestElfGen(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS64, elf.ELFCLASS32} {
		t.Run(class.String(), func(t *testing.T) {
			spec := elfSpec{
				class:   class,
				interp:  "/lib/ld.so",
				needed:  []string{"liba.so", "libb.so"},
				runpath: "$ORIGIN/../lib",
				rpath:   "/opt/lib",
				flags1:  elf.DF_1_NODEFLIB,
			}
			f, err := elf.NewFile(bytes.NewReader(spec.bytes()))
			require.NoError(t, err)
			require.Equal(t, class, f.Class)
			require.Equal(t, elf.EM_X86_64, f.Machine)
			require.Equal(t, elf.ET_DYN, f.Type)

			needed, err := f.DynString(elf.DT_NEEDED)
			require.NoError(t, err)
			require.Equal(t, []string{"liba.so", "libb.so"}, needed)
			runpath, err := f.DynString(elf.DT_RUNPATH)
			require.NoError(t, err)
			require.Equal(t, []string{"$ORIGIN/../lib"}, runpath)
			rpath, err := f.DynString(elf.DT_RPATH)
			require.NoError(t, err)
			require.Equal(t, []string{"/opt/lib"}, rpath)
			flags, err := f.DynValue(elf.DT_FLAGS_1)
			require.NoError(t, err)
			require.Equal(t, []uint64{uint64(elf.DF_1_NODEFLIB)}, flags)

			require.Len(t, f.Progs, 1)
			require.Equal(t, elf.PT_INTERP, f.Progs[0].Type)
		})
	}
}
