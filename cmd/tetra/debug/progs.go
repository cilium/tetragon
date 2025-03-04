// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package debug

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/pin"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type prog struct {
	id    uint32
	name  string
	pin   string
	cnt   uint64
	time  time.Duration
	alive bool
}

type overhead struct {
	p    *prog
	pct  float64
	cnt  uint64
	time time.Duration
}

type progsConfig struct {
	all     bool
	lib     string
	bpffs   string
	once    bool
	noclr   bool
	timeout int
}

var (
	initOnce sync.Once
	initErr  error
	initProg *ebpf.Program
	cfg      progsConfig
)

func detectBpffs() (string, error) {
	// Try to read /proc/mounts and find bpf mount
	if lines, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(lines), "\n") {
			parts := strings.Split(line, " ")
			if len(parts) == 6 {
				if parts[2] == "bpf" {
					return parts[1], nil
				}
			}
		}
	}

	// .. if failed, check 2 common mount points
	paths := []string{"/run/cilium/bpffs", "/sys/fs/bpf/"}

	for _, path := range paths {
		var st syscall.Statfs_t

		if err := syscall.Statfs(path, &st); err != nil {
			continue
		}
		if st.Type != unix.BPF_FS_MAGIC {
			continue
		}
		if _, err := os.Stat(filepath.Join(path, "tetragon")); err != nil {
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("bpffs mount not found")
}

func detectLib() (string, error) {
	paths := []string{"/var/lib/tetragon", "./bpf/objs/"}

	for _, path := range paths {
		if _, err := os.Stat(filepath.Join(path, "bpf_prog_iter.o")); err != nil {
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("lib directory mount not found")
}

func NewProgsCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:     "progs",
		Aliases: []string{"top"},
		Short:   "Retrieve information about BPF programs on the host",
		Long: `Retrieve information about BPF programs on the host.

Examples:
- tetragon BPF programs top style
  # tetra debug progs
- all BPF programs top style
  # tetra debug progs --all
- one shot mode (displays one interval data)
  # tetra debug progs --once
- change interval to 10 seconds
  # tetra debug progs  --timeout 10
- change interval to 10 seconds in one shot mode
  # tetra debug progs --once --timeout 10
`,

		Run: func(_ *cobra.Command, _ []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// cfg.timeout is set by user in seconds unit, but let's convert
			// it to nanoseconds, because it will be used like that below
			cfg.timeout = int(time.Second) * cfg.timeout

			var err error

			if cfg.bpffs == "" {
				if cfg.bpffs, err = detectBpffs(); err != nil {
					log.Fatal(err)
				}
			}

			if cfg.lib == "" {
				if cfg.lib, err = detectLib(); err != nil {
					log.Fatal(err)
				}
			}

			if err = runProgs(ctx); err != nil {
				log.Fatal(err)
			}
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&cfg.all, "all", false, "Get all programs")
	flags.StringVar(&cfg.lib, "bpf-lib", "", "Location of Tetragon libs, btf and bpf files (auto detect by default)")
	flags.StringVar(&cfg.bpffs, "bpf-dir", "", "Location of bpffs tetragon directory (auto detect by default)")
	flags.IntVar(&cfg.timeout, "timeout", 1, "Interval in seconds (delay in one shot mode)")
	flags.BoolVar(&cfg.once, "once", false, "Run in one shot mode")
	flags.BoolVar(&cfg.noclr, "no-clear", false, "Do not clear screen between rounds")
	return &cmd
}

func runProgs(ctx context.Context) error {
	// Enable bpf stats
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("failed to enable stats: %v", err)
	}
	defer stats.Close()

	state := make(map[uint32]*prog)

	// Gather initial data
	if err = round(state); err != nil {
		return err
	}

	// and cycle..
	ticker := time.NewTicker(time.Duration(cfg.timeout))
	defer ticker.Stop()

	for ctx.Err() == nil {
		<-ticker.C
		if !cfg.noclr && !cfg.once {
			clearScreen()
		}
		if err = round(state); err != nil {
			return err
		}
		if cfg.once {
			return nil
		}
	}
	return err
}

func round(state map[uint32]*prog) error {
	// Get BPF programs
	progs, err := getProgs(cfg.all, cfg.lib, cfg.bpffs)
	if err != nil {
		return err
	}

	// Get BPF programs overheads
	overheads, err := getOverheads(state, progs)
	if err != nil || len(overheads) == 0 {
		return err
	}

	// Compute overheads
	for _, ovh := range overheads {
		var pct float64

		if ovh.time != 0 {
			pct = float64(ovh.time) / float64(cfg.timeout*runtime.NumCPU()) * 100
		}
		ovh.pct = pct
	}

	// Sort by overhead percentage
	sort.Slice(overheads, func(i, j int) bool {
		return overheads[i].pct > overheads[j].pct
	})

	// And dump it to the terminal, time..
	fmt.Println(time.Now().String())
	fmt.Println("")

	// ..and overhead
	writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, '\t', tabwriter.AlignRight)
	fmt.Fprintln(writer, "Ovh(%)\tId\tCnt\tTime\tName\tPin")

	cnt := 0
	lines := 0

	if !cfg.noclr && !cfg.once {
		// We have 3 header lines, so terminal smaller than that is too
		// small to print anything meaningful
		_, lines, _ = term.GetSize(0)
		if lines < 4 {
			return nil
		}
		lines = lines - 4
	}

	for _, ovh := range overheads {
		p := ovh.p
		fmt.Fprintf(writer, "%6.2f\t%d\t%d\t%d\t%s\t%s",
			ovh.pct, p.id, ovh.cnt, ovh.time, p.name, p.pin)

		if lines != 0 && cnt == lines {
			break
		}
		cnt++
		fmt.Fprintf(writer, "\n")
	}

	writer.Flush()

	// Remove stale programs from state map
	for id, p := range state {
		if p.alive {
			p.alive = false
		} else {
			delete(state, id)
		}
	}
	return nil
}

func clearScreen() {
	fmt.Print("\033[2J")
	fmt.Print("\033[H")
}

func getOverheads(state map[uint32]*prog, progs []*prog) ([]*overhead, error) {
	var overheads []*overhead

	for _, p := range progs {
		old, ok := state[p.id]
		if !ok {
			state[p.id] = p
			continue
		}
		ovh := &overhead{
			p:    p,
			cnt:  p.cnt - old.cnt,
			time: p.time - old.time,
		}
		overheads = append(overheads, ovh)
		*old = *p
	}

	return overheads, nil
}

func getProgs(all bool, libDir, mapDir string) ([]*prog, error) {
	if all {
		return getAllProgs(libDir)
	}

	return getTetragonProgs(mapDir)
}

func getAllProgs(lib string) ([]*prog, error) {
	// Open the object file just once
	initOnce.Do(func() {
		file := path.Join(lib, "bpf_prog_iter.o")
		spec, err := ebpf.LoadCollectionSpec(file)
		if err != nil {
			initErr = err
			return
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			initErr = err
			return
		}
		defer coll.Close()

		prog, ok := coll.Programs["iter"]
		if !ok {
			initErr = fmt.Errorf("can't file iter program")
			return
		}
		initProg, initErr = prog.Clone()
	})

	if initErr != nil {
		return nil, initErr
	}

	// Setup the iterator
	it, err := link.AttachIter(link.IterOptions{
		Program: initProg,
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()

	rd, err := it.Open()
	if err != nil {
		return nil, err
	}
	defer rd.Close()

	var (
		progs []*prog
		id    uint32
	)

	// Read all the IDs
	for {
		err = binary.Read(rd, binary.LittleEndian, &id)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
		}
		p, err := getProg(id)
		if err != nil {
			return nil, err
		}

		progs = append(progs, p)
	}

	return progs, nil
}

func getProg(id uint32) (*prog, error) {
	p, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return nil, err
	}
	defer p.Close()

	info, err := p.Info()
	if err != nil {
		return nil, err
	}

	runTime, _ := info.Runtime()
	runCnt, _ := info.RunCount()

	return &prog{
		id:    id,
		name:  info.Name,
		pin:   "-",
		cnt:   runCnt,
		time:  runTime,
		alive: true,
	}, nil
}

func getTetragonProgs(base string) ([]*prog, error) {
	var progs []*prog

	// Walk bpffs/tetragon and look for programs
	err := pin.WalkDir(base,
		func(path string, finfo fs.DirEntry, obj pin.Pinner, err error) error {
			if err != nil {
				return err
			}
			if finfo.IsDir() {
				return nil
			}

			p, ok := obj.(*ebpf.Program)
			if !ok {
				return nil
			}
			defer p.Close()

			info, err := p.Info()
			if err != nil {
				return err
			}

			id, ok := info.ID()
			if !ok {
				return err
			}

			runTime, _ := info.Runtime()
			runCnt, _ := info.RunCount()

			progs = append(progs, &prog{
				id:    uint32(id),
				name:  getName(p, info),
				pin:   filepath.Join(base, path),
				cnt:   runCnt,
				time:  runTime,
				alive: true,
			})
			return nil
		})
	return progs, err
}

func getName(p *ebpf.Program, info *ebpf.ProgramInfo) string {
	handle, err := p.Handle()
	if err != nil {
		return info.Name
	}

	spec, err := handle.Spec(nil)
	if err != nil {
		return info.Name
	}

	iter := spec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			return fn.Name
		}
	}
	return info.Name
}
