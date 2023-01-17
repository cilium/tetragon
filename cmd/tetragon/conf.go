// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/spf13/viper"
)

var (
	adminTgConfDir       = "/etc/tetragon/"
	adminTgConfDropIn    = "/etc/tetragon/tetragon.conf.d/"
	packageTgConfDropIns = []string{
		"/usr/lib/tetragon/tetragon.conf.d/",
		"/usr/local/lib/tetragon/tetragon.conf.d/",
	}
)

func readConfigFile(path string, file string) error {
	filePath := filepath.Join(path, file)
	st, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	if st.Mode().IsRegular() == false {
		return fmt.Errorf("failed to read config file '%s' not a regular file", file)
	}

	viper.AddConfigPath(path)
	err = viper.MergeInConfig()
	if err != nil {
		return err
	}

	return nil
}

func readConfigDir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() == false {
		return fmt.Errorf("'%s' is not a directory", path)
	}

	cm, err := option.ReadDirConfig(path)
	if err != nil {
		return err
	}
	if err := viper.MergeConfigMap(cm); err != nil {
		return fmt.Errorf("merge config failed %v", err)
	}

	return nil
}

func readConfigSettings(defaultConfDir string, defaultConfDropIn string, dropInsDir []string) {
	viper.SetEnvPrefix("tetragon")
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	// First set default conf file and format
	viper.SetConfigName("tetragon")
	viper.SetConfigType("yaml")

	// Read default drop-ins directories
	for _, dir := range dropInsDir {
		readConfigDir(dir)
	}

	// Look into cwd first, this is needed for quick development only
	readConfigFile(".", "tetragon.yaml")

	// Look for /etc/tetragon/tetragon.yaml
	readConfigFile(defaultConfDir, "tetragon.yaml")

	// Look into default /etc/tetragon/tetragon.conf.d/ now
	readConfigDir(defaultConfDropIn)

	// Read now the passed key --config-dir
	if viper.IsSet(keyConfigDir) {
		configDir := viper.GetString(keyConfigDir)
		// viper.IsSet could return true on an empty string reset
		if configDir != "" {
			err := readConfigDir(configDir)
			if err != nil {
				log.WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to read config from directory")
			} else {
				log.WithField(keyConfigDir, configDir).Info("Loaded config from directory")
			}
		}
	}
}
