// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
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
