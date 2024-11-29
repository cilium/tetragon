// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	ociHooks "github.com/containers/common/pkg/hooks/1.0.0"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	logBaseName = "tetragon-oci-hook.log"
)

type Install struct {
	Interface       string `default:"oci-hooks" enum:"oci-hooks,nri-hook" help:"Hooks interface (${enum})"`
	LocalBinary     string `default:"/usr/bin/tetragon-oci-hook" help:"Source binary path (in the container)"`
	LocalInstallDir string `required help:"Installation dir (in the container)."`
	HostInstallDir  string `required help:"Installation dir (in the host). Used for the binary and the hook logfile."`
	Daemonize       bool   `help:"Daemonize install command. If a termination signal is send, the process will remove the files it installed before exiting"`

	OciHooks struct {
		LocalDir string `default:"/hostHooks" help:"oci-hooks drop-in directory (inside the container)"`
	} `embed:"" prefix:"oci-hooks."`

	NriHook struct {
		Index string `name:"index" default:"01" help:"NRI index number"`
		Name  string `name:"name" default:"tetragon" help:"NRI plugin name"`
	} `embed:"" prefix:"nri-hook."`

	HookArgs struct {
		Args []string `arg:"" optional:""`
	} `cmd:"" passthrough:"" help:"Arguments to pass to tetragon-oci-hook."`
}

func ociHooksConfig(binFname string, binArgs ...string) *ociHooks.Hook {
	yes := true
	args := []string{binFname, "createRuntime"}
	args = append(args, binArgs...)
	return &ociHooks.Hook{
		Version: "1.0.0",
		Hook: rspec.Hook{
			Path:    binFname,
			Args:    args,
			Env:     []string{},
			Timeout: nil,
		},
		When: ociHooks.When{
			Always:        &yes,
			Annotations:   map[string]string{},
			Commands:      []string{},
			HasBindMounts: nil,
		},
		Stages: []string{"createRuntime"},
	}
}

func (i *Install) ociHooksInstall(log *slog.Logger) {
	var sigChan chan os.Signal
	if i.Daemonize {
		sigChan = make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	}

	// add .json file to oci hooks dir
	_, binBaseName := path.Split(i.LocalBinary)
	binFname := filepath.Join(i.HostInstallDir, binBaseName)

	logFname := filepath.Join(i.HostInstallDir, logBaseName)
	args := []string{"--log-fname", logFname}
	args = append(args, i.HookArgs.Args...)
	hook := ociHooksConfig(binFname, args...)
	data, err := json.MarshalIndent(hook, "", "   ")
	if err != nil {
		log.Error("failed to unmarshall hook info", "error", err)
		os.Exit(1)
	}

	confDst := filepath.Join(i.OciHooks.LocalDir, fmt.Sprintf("%s.json", binBaseName))
	if err := os.WriteFile(confDst, data, 0755); err != nil {
		log.Error("writing file failed", "conf-dst", confDst)
		os.Exit(1)
	}

	log.Info("written conf", "conf-dst-path", confDst)

	// if --daemonize is set, wait until we receive a signal, and then uninstall hook.
	if i.Daemonize {
		<-sigChan
		u := Uninstall{
			Interface:       i.Interface,
			BinaryName:      path.Base(i.LocalBinary),
			LocalInstallDir: i.LocalInstallDir,
		}
		u.OciHooks.LocalDir = i.OciHooks.LocalDir
		if err := u.Run(log); err != nil {
			log.Error("uninstall failed", "err", err)
		}
	}
}

func (i *Install) Run(log *slog.Logger) error {

	// copy the binary to the host
	i.copyBinary(log)
	switch i.Interface {
	case "oci-hooks":
		i.ociHooksInstall(log)
		return nil
	case "nri-hook":
		i.nriHookStart(log)
		return nil
	}

	log.Error("unknown interface", "interface", i.Interface)
	os.Exit(1)

	return nil
}

func (i *Install) copyBinary(log *slog.Logger) {

	data, err := os.ReadFile(i.LocalBinary)
	if err != nil {
		log.Error("reading hook source failed", "bin-src-path", i.LocalBinary, "error", err)
	}
	_, base := path.Split(i.LocalBinary)

	// write to a temp file first, and then do a rename to avoid issues with an existing binary
	tmpBase := fmt.Sprintf("%s-%s", base, time.Now().Format("20060102.150405000000"))
	tmpFname := filepath.Join(i.LocalInstallDir, tmpBase)
	if err = os.WriteFile(tmpFname, data, 0755); err != nil {
		log.Error("failed to write binary", "bin-tmp-path", tmpFname, "error", err)
		os.Exit(1)
	}

	binDst := filepath.Join(i.LocalInstallDir, base)
	if err := os.Rename(tmpFname, binDst); err != nil {
		log.Error("failed to rename tmp binary to dst",
			"bin-tmp-path", tmpFname,
			"bin-dst-path", binDst,
		)
		os.Exit(1)
	}

	log.Info("written binary", "hook-dst-path", binDst)
}

type Uninstall struct {
	Interface       string `default:"oci-hooks" enum:"oci-hooks" help:"Hooks interface (${enum})"`
	BinaryName      string `default:"tetragon-oci-hook" help:"Binary name"`
	LocalInstallDir string `required help:"Installation dir (in the container)"`

	OciHooks struct {
		LocalDir string `default:"/hostHooks" help:"oci-hooks drop-in directory (inside the container)"`
	} `embed:"" prefix:"oci-hooks."`
}

func (u *Uninstall) removeBinary(log *slog.Logger) {
	binDst := filepath.Join(u.LocalInstallDir, u.BinaryName)
	if err := os.Remove(binDst); err != nil {
		log.Warn("failed to remove binary", "bin-dst-path", binDst, "error", err)
	} else {
		log.Info("binary removed", "bin-dst-path", binDst)
	}
}

func (u *Uninstall) ociHooksUninstall(log *slog.Logger) {
	confDst := filepath.Join(u.OciHooks.LocalDir, fmt.Sprintf("%s.json", u.BinaryName))
	if err := os.Remove(confDst); err != nil {
		log.Warn("failed to remove conf",
			"conf-dst-path", confDst,
			"error", err)
	} else {
		log.Info("removed conf", "conf-dst-path", confDst)
	}
}

func (u *Uninstall) Run(log *slog.Logger) error {
	switch u.Interface {
	case "oci-hooks":
		u.ociHooksUninstall(log)
	default:
		log.Error("unknown interface", "interface", u.Interface)
		os.Exit(1)
	}
	u.removeBinary(log)
	return nil
}

type PrintConfig struct {
	Binary    string `default:"/usr/bin/tetragon-oci-hook" help:"Binary path"`
	Args      []string
	Interface string `default:"oci-hooks" enum:"oci-hooks" help:"Hooks interface (${enum})"`
}

func (c *PrintConfig) Run(log *slog.Logger) error {
	switch c.Interface {
	case "oci-hooks":
		hook := ociHooksConfig(c.Binary, c.Args...)
		data, err := json.MarshalIndent(hook, "", "   ")
		if err != nil {
			log.Error("failed to unmarshall hook info", "error", err)
			os.Exit(1)
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			log.Error("failed to write to stdout", "error", err)
			os.Exit(1)
		}
		fmt.Println("")
		return nil
	default:
		return fmt.Errorf("unknown interface: '%s'", c.Interface)
	}

}

type CLI struct {
	Install             Install             `cmd:"" help:"Install hook"`
	Uninstall           Uninstall           `cmd:"" help:"Uninstall hook"`
	PrintConfig         PrintConfig         `cmd:"" help:"Print config"`
	PatchContainerdConf patchContainerdConf `cmd:"patch containerd configuration"`
	PatchCrioConf       patchCrioConf       `cmd:"patch crio configuration"`

	LogLevel string `name:"log-level" default:"info" help:"log level"`
}

func main() {

	var conf CLI
	ctx := kong.Parse(&conf)

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(conf.LogLevel)); err != nil {
		slog.Error("failed to parse log l evel", "level", conf.LogLevel, "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	err := ctx.Run(logger)
	ctx.FatalIfErrorf(err)
}
