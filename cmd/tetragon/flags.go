// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/spf13/viper"
)

const (
	keyConfigDir        = "config-dir"
	keyDebug            = "debug"
	keyHubbleLib        = "bpf-lib"
	keyBTF              = "btf"
	keyProcFS           = "procfs"
	keyKernelVersion    = "kernel"
	keyVerbosity        = "verbose"
	keyProcessCacheSize = "process-cache-size"
	keyForceSmallProgs  = "force-small-progs"

	keyLogLevel  = "log-level"
	keyLogFormat = "log-format"

	keyEnableK8sAPI           = "enable-k8s-api"
	keyEnableCiliumAPI        = "enable-cilium-api"
	keyEnableProcessAncestors = "enable-process-ancestors"

	keyMetricsServer     = "metrics-server"
	keyServerAddress     = "server-address"
	keyGopsAddr          = "gops-address"
	keyCiliumBPF         = "cilium-bpf"
	keyEnableProcessCred = "enable-process-cred"
	keyEnableProcessNs   = "enable-process-ns"
	keyConfigFile        = "config-file"

	keyCpuProfile = "cpuprofile"
	keyMemProfile = "memprofile"
	keyPprofAddr  = "pprof-addr"

	keyExportFilename             = "export-filename"
	keyExportFileMaxSizeMB        = "export-file-max-size-mb"
	keyExportFileRotationInterval = "export-file-rotation-interval"
	keyExportFileMaxBackups       = "export-file-max-backups"
	keyExportFileCompress         = "export-file-compress"
	keyExportRateLimit            = "export-rate-limit"

	keyEnableExportAggregation     = "enable-export-aggregation"
	keyExportAggregationWindowSize = "export-aggregation-window-size"
	keyExportAggregationBufferSize = "export-aggregation-buffer-size"

	keyExportAllowlist = "export-allowlist"
	keyExportDenylist  = "export-denylist"

	keyFieldFilters = "field-filters"

	keyNetnsDir = "netns-dir"

	keyDisableKprobeMulti = "disable-kprobe-multi"

	keyRBSize      = "rb-size"
	keyRBSizeTotal = "rb-size-total"

	keyEventQueueSize = "event-queue-size"

	keyReleasePinnedBPF = "release-pinned-bpf"
)

var (
	processCacheSize int

	metricsServer string
	serverAddress string
	configFile    string

	exportFilename             string
	exportFileMaxSizeMB        int
	exportFileRotationInterval time.Duration
	exportFileMaxBackups       int
	exportFileCompress         bool
	exportRateLimit            int

	// Export aggregation options
	enableExportAggregation     bool
	exportAggregationWindowSize time.Duration
	exportAggregationBufferSize uint64

	cpuProfile string
	memProfile string
	pprofAddr  string
)

func readConfigFile(path string, file string) error {
	file = filepath.Join(path, file)
	st, err := os.Stat(file)
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

func readConfigSettings(defaultConfDir string, dropInsDir []string) {
	viper.SetEnvPrefix("tetragon")
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	viper.SetConfigName("tetragon")
	viper.SetConfigType("yaml")

	// Look into cwd first, this is needed for quick development only
	err := readConfigFile(".", "tetragon.yaml")
	if err == nil {
		return
	}
	log.Debugf("Reading configuration: %v", err)

	// Read drop-ins
	for _, dir := range dropInsDir {
		readConfigDir(dir)
	}

	readConfigFile(defaultConfDir, "tetragon.yaml")

	// Read now the passed key config
	if viper.IsSet(keyConfigDir) {
		configDir := viper.GetString(keyConfigDir)
		cm, err := option.ReadDirConfig(configDir)
		if err != nil {
			log.WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to read config from directory")
		}
		if err := viper.MergeConfigMap(cm); err != nil {
			log.WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to merge config from directory")
		}
		log.WithField(keyConfigDir, configDir).Info("Loaded config from directory")
	}
}

func readAndSetFlags() {
	option.Config.HubbleLib = viper.GetString(keyHubbleLib)
	option.Config.BTF = viper.GetString(keyBTF)
	option.Config.ProcFS = viper.GetString(keyProcFS)
	option.Config.KernelVersion = viper.GetString(keyKernelVersion)
	option.Config.Verbosity = viper.GetInt(keyVerbosity)
	option.Config.ForceSmallProgs = viper.GetBool(keyForceSmallProgs)
	option.Config.Debug = viper.GetBool(keyDebug)

	option.Config.EnableProcessCred = viper.GetBool(keyEnableProcessCred)
	option.Config.EnableProcessNs = viper.GetBool(keyEnableProcessNs)
	option.Config.EnableCilium = viper.GetBool(keyEnableCiliumAPI)
	option.Config.EnableK8s = viper.GetBool(keyEnableK8sAPI)

	option.Config.DisableKprobeMulti = viper.GetBool(keyDisableKprobeMulti)

	option.Config.RBSize = viper.GetInt(keyRBSize)
	option.Config.RBSizeTotal = viper.GetInt(keyRBSizeTotal)

	option.Config.GopsAddr = viper.GetString(keyGopsAddr)

	logLevel := viper.GetString(keyLogLevel)
	logFormat := viper.GetString(keyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	processCacheSize = viper.GetInt(keyProcessCacheSize)

	metricsServer = viper.GetString(keyMetricsServer)
	serverAddress = viper.GetString(keyServerAddress)
	option.Config.CiliumDir = viper.GetString(keyCiliumBPF)
	configFile = viper.GetString(keyConfigFile)

	exportFilename = viper.GetString(keyExportFilename)
	exportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	exportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	exportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	exportFileCompress = viper.GetBool(keyExportFileCompress)
	exportRateLimit = viper.GetInt(keyExportRateLimit)

	enableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	exportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	exportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)

	cpuProfile = viper.GetString(keyCpuProfile)
	memProfile = viper.GetString(keyMemProfile)
	pprofAddr = viper.GetString(keyPprofAddr)

	option.Config.EventQueueSize = viper.GetUint(keyEventQueueSize)

	option.Config.ReleasePinned = viper.GetBool(keyReleasePinnedBPF)
}
