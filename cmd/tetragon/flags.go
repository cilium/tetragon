//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

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
	keyHubbleLib        = "hubble-lib"
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
	keyCiliumBPF         = "cilium-bpf"
	keyEnableProcessCred = "enable-process-cred"
	keyEnableProcessNs   = "enable-process-ns"
	keyConfigFile        = "config-file"

	keyRunStandalone      = "run-standalone"
	keyIgnoreMissingProgs = "ignore-missing-progs"

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

	keyNetnsDir = "netns-dir"
)

var (
	processCacheSize int

	enableK8sAPI    bool
	enableCiliumAPI bool

	metricsServer     string
	serverAddress     string
	ciliumBPF         string
	enableProcessCred bool
	enableProcessNs   bool
	configFile        string

	runStandalone bool

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
)

func readAndSetFlags() {
	option.Config.HubbleLib = viper.GetString(keyHubbleLib)
	option.Config.BTF = viper.GetString(keyBTF)
	option.Config.ProcFS = viper.GetString(keyProcFS)
	option.Config.KernelVersion = viper.GetString(keyKernelVersion)
	option.Config.Verbosity = viper.GetInt(keyVerbosity)
	option.Config.IgnoreMissingProgs = viper.GetBool(keyIgnoreMissingProgs)
	option.Config.ForceSmallProgs = viper.GetBool(keyForceSmallProgs)
	option.Config.Debug = viper.GetBool(keyDebug)

	logLevel := viper.GetString(keyLogLevel)
	logFormat := viper.GetString(keyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	processCacheSize = viper.GetInt(keyProcessCacheSize)

	enableK8sAPI = viper.GetBool(keyEnableK8sAPI)
	enableCiliumAPI = viper.GetBool(keyEnableCiliumAPI)

	metricsServer = viper.GetString(keyMetricsServer)
	serverAddress = viper.GetString(keyServerAddress)
	ciliumBPF = viper.GetString(keyCiliumBPF)
	enableProcessCred = viper.GetBool(keyEnableProcessCred)
	enableProcessNs = viper.GetBool(keyEnableProcessNs)
	configFile = viper.GetString(keyConfigFile)

	runStandalone = viper.GetBool(keyRunStandalone)

	exportFilename = viper.GetString(keyExportFilename)
	exportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	exportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	exportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	exportFileCompress = viper.GetBool(keyExportFileCompress)
	exportRateLimit = viper.GetInt(keyExportRateLimit)

	enableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	exportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	exportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)
}
