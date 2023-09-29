// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/metricsconfig"
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
	keyEnableProcessAncestors = "enable-process-ancestors"

	keyMetricsServer      = "metrics-server"
	keyMetricsLabelFilter = "metrics-label-filter"
	keyServerAddress      = "server-address"
	keyGopsAddr           = "gops-address"
	keyEnableProcessCred  = "enable-process-cred"
	keyEnableProcessNs    = "enable-process-ns"
	keyTracingPolicy      = "tracing-policy"
	keyTracingPolicyDir   = "tracing-policy-dir"

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
	keyRBQueueSize = "rb-queue-size"

	keyEventQueueSize = "event-queue-size"

	keyReleasePinnedBPF = "release-pinned-bpf"

	keyEnablePolicyFilter      = "enable-policy-filter"
	keyEnablePolicyFilterDebug = "enable-policy-filter-debug"

	keyEnablePidSetFilter = "enable-pid-set-filter"

	keyEnableMsgHandlingLatency = "enable-msg-handling-latency"

	keyKmods = "kmods"

	keyEnablePodInfo = "enable-pod-info"

	keyExposeKernelAddresses = "expose-kernel-addresses"
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
	option.Config.EnableK8s = viper.GetBool(keyEnableK8sAPI)
	option.Config.K8sKubeConfigPath = viper.GetString(keyK8sKubeConfigPath)

	option.Config.DisableKprobeMulti = viper.GetBool(keyDisableKprobeMulti)

	option.Config.RBSize = viper.GetInt(keyRBSize)
	option.Config.RBSizeTotal = viper.GetInt(keyRBSizeTotal)
	option.Config.RBQueueSize = viper.GetInt(keyRBQueueSize)

	option.Config.GopsAddr = viper.GetString(keyGopsAddr)

	logLevel := viper.GetString(keyLogLevel)
	logFormat := viper.GetString(keyLogFormat)
	logger.PopulateLogOpts(option.Config.LogOpts, logLevel, logFormat)

	option.Config.ProcessCacheSize = viper.GetInt(keyProcessCacheSize)
	option.Config.DataCacheSize = viper.GetInt(keyDataCacheSize)

	option.Config.MetricsServer = viper.GetString(keyMetricsServer)
	option.Config.MetricsLabelFilter = metricsconfig.ParseMetricsLabelFilter(viper.GetString(keyMetricsLabelFilter))
	option.Config.ServerAddress = viper.GetString(keyServerAddress)

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
	option.Config.EnableMsgHandlingLatency = viper.GetBool(keyEnableMsgHandlingLatency)

	option.Config.EnablePidSetFilter = viper.GetBool(keyEnablePidSetFilter)

	option.Config.TracingPolicyDir = viper.GetString(keyTracingPolicyDir)

	option.Config.KMods = viper.GetStringSlice(keyKmods)

	option.Config.EnablePodInfo = viper.GetBool(keyEnablePodInfo)

	option.Config.TracingPolicy = viper.GetString(keyTracingPolicy)

	option.Config.ExposeKernelAddresses = viper.GetBool(keyExposeKernelAddresses)
}
