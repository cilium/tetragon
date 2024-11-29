// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"

	srvconf "github.com/containerd/containerd/services/server/config"
	"github.com/pelletier/go-toml"
)

// NB(kkourt): this started as a simple hack, but grew larger than expected. I think a better
// solution would be to modify the config object and just marshall it instead of just doing text
// replacements. TBD.

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

func usesCR(f *os.File) bool {
	rd := bufio.NewReader(f)
	defer f.Seek(0, os.SEEK_SET)

	l, err := rd.ReadSlice('\n')
	if err != nil {
		return false
	}

	ll := len(l)
	if ll > 2 && l[ll-1] == '\n' && l[ll-2] == '\r' {
		return true
	}

	return false
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
	EnableNRI  enableNRICmd  `cmd:"" help:"add NRI section to containerd configuration"`
}

type addOCIHookCmd struct {
	ContainerdConf  string `name:"config-file" default:"/etc/containerd/config.toml" help:"containerd configuration file location (input) (${default}))"`
	BaseRuntimeSpec string `name:"runtime-spec" default:"/etc/containerd/base-spec.json" help:"base runtime spec file location (${default})"`
	Output          string `name:"output" help:"output file (if empty, a temporary file will be created)"`
}

type enableNRICmd struct {
	ContainerdConf string `name:"config-file" default:"/etc/containerd/config.toml" help:"containerd configuration file location (input) (${default}))"`
	Output         string `name:"output" help:"output file (if empty, a temporary file will be created)"`
}

func (c *enableNRICmd) Run(log *slog.Logger) error {
	changes, err := enableNRI(log, c)
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

func parseNRI(t *toml.Tree) ([]addLine, error) {
	ty := t.Get("disable")
	disable := ty.(bool)
	if disable {
		return []addLine{{
			pos:         t.GetPosition("disable"),
			line:        "disable = false",
			replaceLine: true,
		}}, nil
	}
	return nil, nil
}

// enableNRI parses a containerd configuration file and returns a set of lines to add
func enableNRI(log *slog.Logger, cnf *enableNRICmd) ([]addLine, error) {
	srvConfig := srvconf.Config{}
	file, err := toml.LoadFile(cnf.ContainerdConf)
	if err != nil {
		return nil, err
	}
	if err := file.Unmarshal(&srvConfig); err != nil {
		return nil, err
	}

	for name, plugin := range srvConfig.Plugins {
		if name == "io.containerd.nri.v1.nri" {
			return parseNRI(&plugin)
		}
	}

	// no NRI section was found, let's add one

	// first find the last position of all plugins
	pos := toml.Position{appendAtEndLine, 0}
	elemPos := toml.Position{appendAtEndLine, 3}
	for _, v := range srvConfig.Plugins {
		pPos := v.Position()
		if pos.Line < pPos.Line {
			pos = pPos
			lastLine := -1
			elemCol := pPos.Col + 3 // by default, indent by 3
			// find the last line for this plugin by iterating all of its elements
			for _, k := range v.Keys() {
				kPos := v.GetPosition(k)
				if kPos.Line > lastLine {
					lastLine = kPos.Line
					elemCol = kPos.Col
				}
			}
			pos.Line = lastLine
			elemPos = pos
			elemPos.Col = elemCol
		}
	}

	lines := []addLine{}
	if pos.Line == appendAtEndLine {
		lines = append(lines, addLine{pos: pos, line: `[plugins]`})
		pos.Col = 3
		elemPos.Col = 5
	}

	lines = append(lines,
		addLine{pos: pos, line: `[plugins."io.containerd.nri.v1.nri"]`},
		addLine{pos: elemPos, line: `disable = false`},
		addLine{pos: elemPos, line: `disable_connections = false`},
		addLine{pos: elemPos, line: `plugin_config_path = "/etc/nri/conf.d"`},
		addLine{pos: elemPos, line: `plugin_path = "/opt/nri/plugins"`},
		addLine{pos: elemPos, line: `plugin_registration_timeout = "5s"`},
		addLine{pos: elemPos, line: `plugin_request_timeout = "2s"`},
		addLine{pos: elemPos, line: `socket_path = "/var/run/nri/nri.sock"`},
	)

	return lines, nil
}
