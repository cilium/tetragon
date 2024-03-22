// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
	ociHooks "github.com/containers/common/pkg/hooks/1.0.0"
	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	logBaseName = "tetragon-oci-hook.log"
)

type Install struct {
	Interface       string `default:"oci-hooks" enum:"oci-hooks" help:"Hooks interface (${enum})"`
	LocalBinary     string `default:"/usr/bin/tetragon-oci-hook" help:"Source binary path (in the container)"`
	LocalInstallDir string `required help:"Installation dir (in the container)."`
	HostInstallDir  string `required help:"Installation dir (in the host). Used for the binary and the hook logfile."`

	OciHooks struct {
		LocalDir string `default:"/hostHooks" help:"oci-hooks drop-in directory (inside the container)"`
	} `embed:"" prefix:"oci-hooks."`
}

func ociHooksConfig(binFname string, binArgs ...string) *ociHooks.Hook {
	yes := true
	args := []string{binFname, "createContainer"}
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

func (i *Install) ociHooksInstall(log *logrus.Logger) {

	_, binBaseName := path.Split(i.LocalBinary)
	binFname := filepath.Join(i.HostInstallDir, binBaseName)

	logFname := filepath.Join(i.HostInstallDir, logBaseName)
	hook := ociHooksConfig(binFname, "--log-fname", logFname)
	data, err := json.MarshalIndent(hook, "", "   ")
	if err != nil {
		log.WithError(err).Fatal("failed to unmarshall hook info")
	}

	confDst := filepath.Join(i.OciHooks.LocalDir, fmt.Sprintf("%s.json", binBaseName))
	if err := os.WriteFile(confDst, data, 0755); err != nil {
		log.WithField("conf-dst", confDst).WithError(err).Fatal("writing file failed")
	}

	log.WithFields(logrus.Fields{
		"conf-dst-path": confDst,
	}).Info("written conf")
}

func (i *Install) Run(log *logrus.Logger) error {
	i.copyBinary(log)
	switch i.Interface {
	case "oci-hooks":
		i.ociHooksInstall(log)
	default:
		log.WithField("interface", i.Interface).Fatal("unknown interface")
	}
	return nil
}

func (i *Install) copyBinary(log *logrus.Logger) {

	data, err := os.ReadFile(i.LocalBinary)
	if err != nil {
		log.WithField("bin-src-path", i.LocalBinary).WithError(err).Fatal("reading hook source failed")
	}
	_, base := path.Split(i.LocalBinary)

	// write to a temp file first, and then do a rename to avoid issues with an existing binary
	tmpBase := fmt.Sprintf("%s-%s", base, time.Now().Format("20060102.150405000000"))
	tmpFname := filepath.Join(i.LocalInstallDir, tmpBase)
	if err = os.WriteFile(tmpFname, data, 0755); err != nil {
		log.WithField("bin-tmp-path", tmpFname).WithError(err).Fatal("failed to write binary")
	}

	binDst := filepath.Join(i.LocalInstallDir, base)
	if err := os.Rename(tmpFname, binDst); err != nil {
		log.WithFields(logrus.Fields{
			"bin-tmp-path": tmpFname,
			"bin-dst-path": binDst,
		}).WithError(err).Fatal("failed to rename tmp binary to dst")
	}

	log.WithFields(logrus.Fields{
		"hook-dst-path": binDst,
	}).Info("written binary")
}

type Uninstall struct {
	Interface       string `default:"oci-hooks" enum:"oci-hooks" help:"Hooks interface (${enum})"`
	BinaryName      string `default:"tetragon-oci-hook" help:"Binary name"`
	LocalInstallDir string `required help:"Installation dir (in the container)"`

	OciHooks struct {
		LocalDir string `default:"/hostHooks" help:"oci-hooks drop-in directory (inside the container)"`
	} `embed:"" prefix:"oci-hooks."`
}

func (u *Uninstall) removeBinary(log *logrus.Logger) {
	binDst := filepath.Join(u.LocalInstallDir, u.BinaryName)
	if err := os.Remove(binDst); err != nil {
		log.WithField("bin-dst-path", binDst).WithError(err).Warn("failed to remove binary")
	} else {
		log.WithField("bin-dst-path", binDst).WithError(err).Info("binary removed")
	}
}

func (u *Uninstall) ociHooksUninstall(log *logrus.Logger) {
	confDst := filepath.Join(u.OciHooks.LocalDir, fmt.Sprintf("%s.json", u.BinaryName))
	if err := os.Remove(confDst); err != nil {
		log.WithField("conf-dst-path", confDst).WithError(err).Warn("failed to remove conf")
	} else {
		log.WithField("conf-dst-path", confDst).WithError(err).Info("conf removed")
	}
}

func (u *Uninstall) Run(log *logrus.Logger) error {
	switch u.Interface {
	case "oci-hooks":
		u.ociHooksUninstall(log)
	default:
		log.WithField("interface", u.Interface).Fatal("unknown interface")
	}
	u.removeBinary(log)
	return nil
}

type PrintConfig struct {
	Binary    string `default:"/usr/bin/tetragon-oci-hook" help:"Binary path"`
	Args      []string
	Interface string `default:"oci-hooks" enum:"oci-hooks" help:"Hooks interface (${enum})"`
}

func (c *PrintConfig) Run(log *logrus.Logger) error {
	switch c.Interface {
	case "oci-hooks":
		hook := ociHooksConfig(c.Binary, c.Args...)
		data, err := json.MarshalIndent(hook, "", "   ")
		if err != nil {
			log.WithError(err).Fatal("failed to unmarshall hook info")
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			log.WithError(err).Fatal("writing to stdout failed")
		}
		fmt.Println("")
		return nil
	default:
		return fmt.Errorf("unknown interface: '%s'", c.Interface)
	}

}

type CLI struct {
	Install     Install     `cmd:"" help:"Install hook"`
	Uninstall   Uninstall   `cmd:"" help:"Uninstall hook"`
	PrintConfig PrintConfig `cmd:"" help:"Print config"`
}

func main() {

	log := logrus.New()

	var conf CLI
	ctx := kong.Parse(&conf)

	err := ctx.Run(log)
	ctx.FatalIfErrorf(err)
}
