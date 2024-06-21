// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	srvconf "github.com/containerd/containerd/services/server/config"
	"github.com/pelletier/go-toml"
)

type addLine struct {
	pos  toml.Position
	line string
}

type addOCIHookState struct {
	cnf *addOCIHookCmd
	// poor man's patch
	lines []addLine
	log   *slog.Logger
}

// parseRuntime parses a runtime section
func (st *addOCIHookState) parseRuntime(t *toml.Tree) error {
	ty := t.Get("runtime_type")
	if ty != "io.containerd.runc.v2" {
		return nil
	}

	sp := t.Get("base_runtime_spec")
	if sp != nil {
		st.log.Info("base_runtime_spec definition already exists", "spec", sp)
		return nil
	}

	st.lines = append(st.lines, addLine{
		pos:  t.GetPosition("runtime_type"),
		line: fmt.Sprintf("base_runtime_spec = \"%s\"", st.cnf.BaseRuntimeSpec),
	})
	return nil
}

// parseCri parses the "io.containerd.grpc.v1.cri" section of containerd config
func (st *addOCIHookState) parseCri(t *toml.Tree) error {
	pos := t.Position()
	st.log.Info("parsing cri plugin information",
		"line", pos.Line,
		"col", pos.Col)

	runtimes := t.GetPath([]string{"containerd", "runtimes"})
	if runtimes == nil {
		st.log.Info("parseCri: no runtimes found")
	} else if tree, ok := runtimes.(*toml.Tree); ok {
		for _, rt := range tree.Keys() {
			runtime := tree.Get(rt)
			if runtime == nil {
				continue
			}
			st.log.Info("parsing runtime", "runtime", rt)
			if runtimeTree, ok := runtime.(*toml.Tree); ok {
				err := st.parseRuntime(runtimeTree)
				if err != nil {
					return err
				}
			}
		}
	} else {
		st.log.Warn("parseCri: runtimes is not a tree")
	}

	defaultRuntime := t.GetPath([]string{"containerd", "default_runtime"})
	if defaultRuntime == nil {
		st.log.Info("parseCri: no default runtime found")
	} else if tree, ok := defaultRuntime.(*toml.Tree); ok {
		st.log.Info("parsing default_runtime", "runtime", tree)
		err := st.parseRuntime(tree)
		if err != nil {
			return err
		}
	} else {
		st.log.Warn("parseCri: default runtime is not a tree")
	}

	return nil
}

// addOciHook parses a containerd configuration file and returns a set of lines to add
func addOciHook(log *slog.Logger, cnf *addOCIHookCmd) ([]addLine, error) {
	srvConfig := srvconf.Config{}
	file, err := toml.LoadFile(cnf.ContainerdConf)
	if err != nil {
		return nil, err
	}
	if err := file.Unmarshal(&srvConfig); err != nil {
		return nil, err
	}

	p := addOCIHookState{
		cnf: cnf,
		log: log,
	}
	for name, plugin := range srvConfig.Plugins {
		if name == "io.containerd.grpc.v1.cri" {
			err := p.parseCri(&plugin)
			if err != nil {
				return nil, err
			}
		}
	}

	return p.lines, nil
}

func applyChanges(fnameIn, fnameOut string, changes []addLine) error {
	fIn, err := os.Open(fnameIn)
	if err != nil {
		return err
	}
	defer fIn.Close()

	fOut, err := os.Create(fnameOut)
	if err != nil {
		return err
	}
	defer fOut.Close()

	inLine := 0
	inSc := bufio.NewScanner(fIn)
	out := bufio.NewWriter(fOut)
	defer out.Flush()
	for inSc.Scan() {
		inLine++
		out.WriteString(inSc.Text())
		out.WriteString("\r\n")
		for i := range changes {
			ch := &changes[i]
			if ch.pos.Line == inLine {
				line := fmt.Sprintf("%s%s\n", strings.Repeat(" ", ch.pos.Col-1), ch.line)
				out.WriteString(line)
			}
		}
	}

	return nil
}

func (c *addOCIHookCmd) Run(log *slog.Logger) error {
	changes, err := addOciHook(log, c)
	if err != nil {
		return err
	}

	if len(changes) == 0 {
		log.Info("nothing to do")
		return nil
	}

	outFname := c.Output
	if outFname == "" {
		f, err := os.CreateTemp("", "containerd.*.toml")
		if err != nil {
			return err
		}
		outFname = f.Name()
		f.Close()
	}

	err = applyChanges(c.ContainerdConf, outFname, changes)
	if err != nil {
		return err
	}
	log.Info("written output", "filename", outFname)
	return nil
}

type patchContainerdConf struct {
	AddOciHook addOCIHookCmd `cmd:"" help:"add OCI hook to containerd configuration"`
}

type addOCIHookCmd struct {
	ContainerdConf  string `name:"config-file" default:"/etc/containerd/config.toml" help:"containerd configuration file location (input) (${default}))"`
	BaseRuntimeSpec string `name:"runtime-spec" default:"/etc/containerd/base-spec.json" help:"base runtime spec file location (${default})"`
	Output          string `name:"output" help:"output file (if empty, a temporary file will be created)"`
}
