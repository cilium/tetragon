// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
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
		option.ReadConfigDir(dir)
	}

	// Look into cwd first, this is needed for quick development only
	option.ReadConfigFile(".", "tetragon.yaml")

	// Look for /etc/tetragon/tetragon.yaml
	option.ReadConfigFile(defaultConfDir, "tetragon.yaml")

	// Look into default /etc/tetragon/tetragon.conf.d/ now
	option.ReadConfigDir(defaultConfDropIn)

	// Read now the passed key --config-dir
	if viper.IsSet(option.KeyConfigDir) {
		configDir := viper.GetString(option.KeyConfigDir)
		// viper.IsSet could return true on an empty string reset
		if configDir != "" {
			err := option.ReadConfigDir(configDir)
			if err != nil {
				logger.Fatal(log, "Failed to read config from directory", option.KeyConfigDir, configDir, logfields.Error, err)
			} else {
				log.Info("Loaded config from directory", option.KeyConfigDir, configDir)
			}
		}
	}
}
