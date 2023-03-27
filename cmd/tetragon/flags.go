// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
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
	keyDataCacheSize    = "data-cache-size"
	keyForceSmallProgs  = "force-small-progs"
	keyForceLargeProgs  = "force-large-progs"

	keyLogLevel  = "log-level"
	keyLogFormat = "log-format"

	keyEnableK8sAPI           = "enable-k8s-api"
	keyK8sKubeConfigPath      = "k8s-kubeconfig-path"
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

	keyEnablePolicyFilter      = "enable-policy-filter"
	keyEnablePolicyFilterDebug = "enable-policy-filter-debug"
)

func readAndSetFlags() {
	option.Config.HubbleLib = viper.GetString(keyHubbleLib)
	option.Config.BTF = viper.GetString(keyBTF)
	option.Config.ProcFS = viper.GetString(keyProcFS)
	option.Config.KernelVersion = viper.GetString(keyKernelVersion)
	option.Config.Verbosity = viper.GetInt(keyVerbosity)
	option.Config.ForceSmallProgs = viper.GetBool(keyForceSmallProgs)
	option.Config.ForceLargeProgs = viper.GetBool(keyForceLargeProgs)
	option.Config.Debug = viper.GetBool(keyDebug)

	option.Config.EnableProcessCred = viper.GetBool(keyEnableProcessCred)
	option.Config.EnableProcessNs = viper.GetBool(keyEnableProcessNs)
	option.Config.EnableCilium = viper.GetBool(keyEnableCiliumAPI)
	option.Config.EnableK8s = viper.GetBool(keyEnableK8sAPI)
	option.Config.K8sKubeConfigPath = viper.GetString(keyK8sKubeConfigPath)

	option.Config.DisableKprobeMulti = viper.GetBool(keyDisableKprobeMulti)

	option.Config.RBSize = viper.GetInt(keyRBSize)
	option.Config.RBSizeTotal = viper.GetInt(keyRBSizeTotal)

	option.Config.GopsAddr = viper.GetString(keyGopsAddr)

	logLevel := viper.GetString(keyLogLevel)
	logFormat := viper.GetString(keyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	option.Config.ProcessCacheSize = viper.GetInt(keyProcessCacheSize)
	option.Config.DataCacheSize = viper.GetInt(keyDataCacheSize)

	option.Config.MetricsServer = viper.GetString(keyMetricsServer)
	option.Config.ServerAddress = viper.GetString(keyServerAddress)
	option.Config.CiliumDir = viper.GetString(keyCiliumBPF)
	option.Config.ConfigFile = viper.GetString(keyConfigFile)

	option.Config.ExportFilename = viper.GetString(keyExportFilename)
	option.Config.ExportFileMaxSizeMB = viper.GetInt(keyExportFileMaxSizeMB)
	option.Config.ExportFileRotationInterval = viper.GetDuration(keyExportFileRotationInterval)
	option.Config.ExportFileMaxBackups = viper.GetInt(keyExportFileMaxBackups)
	option.Config.ExportFileCompress = viper.GetBool(keyExportFileCompress)
	option.Config.ExportRateLimit = viper.GetInt(keyExportRateLimit)

	option.Config.EnableExportAggregation = viper.GetBool(keyEnableExportAggregation)
	option.Config.ExportAggregationWindowSize = viper.GetDuration(keyExportAggregationWindowSize)
	option.Config.ExportAggregationBufferSize = viper.GetUint64(keyExportAggregationBufferSize)

	option.Config.CpuProfile = viper.GetString(keyCpuProfile)
	option.Config.MemProfile = viper.GetString(keyMemProfile)
	option.Config.PprofAddr = viper.GetString(keyPprofAddr)

	option.Config.EventQueueSize = viper.GetUint(keyEventQueueSize)

	option.Config.ReleasePinned = viper.GetBool(keyReleasePinnedBPF)
	option.Config.EnablePolicyFilter = viper.GetBool(keyEnablePolicyFilter)
	option.Config.EnablePolicyFilterDebug = viper.GetBool(keyEnablePolicyFilterDebug)
}
