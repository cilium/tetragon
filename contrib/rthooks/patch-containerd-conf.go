// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	srvconf "github.com/containerd/containerd/services/server/config"
	"github.com/pelletier/go-toml"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type cmdConf struct {
	containerdConf    string
	baseRuntimeSpec   string
	outContainerdConf string
}

func defaultCmdConf() cmdConf {
	return cmdConf{
		containerdConf:    "/etc/containerd/config.toml",
		baseRuntimeSpec:   "/etc/containerd/base-spec.json",
		outContainerdConf: "",
	}
}

func newCommand() *cobra.Command {
	cmdConf := defaultCmdConf()
	cmd := &cobra.Command{
		Use:   "patch-containerd-conf",
		Short: "Patch containerd.conf to install an OCI hook",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := logrus.New()
			return addHook(log, &cmdConf)
		},
		SilenceUsage: true,
	}
	flags := cmd.Flags()
	flags.StringVar(&cmdConf.containerdConf, "config-file", cmdConf.containerdConf, "containerd configuration file")
	flags.StringVar(&cmdConf.baseRuntimeSpec, "runtime-spec", cmdConf.baseRuntimeSpec, "base runtime spec file location")
	flags.StringVar(&cmdConf.outContainerdConf, "output", cmdConf.outContainerdConf, "output file (if empty, a temporary file will be created)")
	return cmd
}

func main() {
	cmd := newCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

type addLine struct {
	pos  toml.Position
	line string
}

type parseState struct {
	cnf *cmdConf
	// poor man's patch
	lines []addLine
	log   *logrus.Logger
}

// parseRuntime parses a runtime section
func (st *parseState) parseRuntime(t *toml.Tree) error {
	ty := t.Get("runtime_type")
	if ty != "io.containerd.runc.v2" {
		return nil
	}

	sp := t.Get("base_runtime_spec")
	if sp != nil {
		st.log.Infof("base_runtime_spec definition already exists: %s", sp)
		return nil
	}

	st.lines = append(st.lines, addLine{
		pos:  t.GetPosition("runtime_type"),
		line: fmt.Sprintf("base_runtime_spec = \"%s\"", st.cnf.baseRuntimeSpec),
	})
	return nil
}

// parseCri parses the "io.containerd.grpc.v1.cri" section of containerd config
func (st *parseState) parseCri(t *toml.Tree) error {
	pos := t.Position()
	st.log.WithFields(logrus.Fields{
		"line": pos.Line,
		"col":  pos.Col,
	}).Infof("parsing cri plugin information")

	runtimes := t.GetPath([]string{"containerd", "runtimes"})
	if runtimes == nil {
		st.log.Info("parseCri: no runtimes found")
	} else if tree, ok := runtimes.(*toml.Tree); ok {
		for _, rt := range tree.Keys() {
			runtime := tree.Get(rt)
			if runtime == nil {
				continue
			}
			st.log.Infof("parsing runtime %s", rt)
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
		st.log.Infof("parsing default_runtime: %s", tree)
		err := st.parseRuntime(tree)
		if err != nil {
			return err
		}
	} else {
		st.log.Warn("parseCri: default runtime is not a tree")
	}

	return nil
}

// parseConfig parses a containerd configuration file and returns a set of lines to add
func parseConfig(log *logrus.Logger, cnf *cmdConf) ([]addLine, error) {
	srvConfig := srvconf.Config{}
	file, err := toml.LoadFile(cnf.containerdConf)
	if err != nil {
		return nil, err
	}
	if err := file.Unmarshal(&srvConfig); err != nil {
		return nil, err
	}

	p := parseState{
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

func addHook(log *logrus.Logger, cnf *cmdConf) error {
	changes, err := parseConfig(log, cnf)
	if err != nil {
		return err
	}

	if len(changes) == 0 {
		log.Infof("nothing to do")
		return nil
	}

	outFname := cnf.outContainerdConf
	if outFname == "" {
		f, err := os.CreateTemp("", "containerd.*.toml")
		if err != nil {
			return err
		}
		outFname = f.Name()
		f.Close()
	}

	err = applyChanges(cnf.containerdConf, outFname, changes)
	if err != nil {
		return err
	}
	log.Infof("written output to %s", outFname)
	return nil
}
