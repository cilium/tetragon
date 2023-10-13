// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/spf13/viper"
)

const (
	KeyConfigDir        = "config-dir"
	KeyDebug            = "debug"
	KeyHubbleLib        = "bpf-lib"
	KeyBTF              = "btf"
	KeyProcFS           = "procfs"
	KeyKernelVersion    = "kernel"
	KeyVerbosity        = "verbose"
	KeyProcessCacheSize = "process-cache-size"
	KeyDataCacheSize    = "data-cache-size"
	KeyForceSmallProgs  = "force-small-progs"
	KeyForceLargeProgs  = "force-large-progs"

	KeyLogLevel  = "log-level"
	KeyLogFormat = "log-format"

	KeyEnableK8sAPI           = "enable-k8s-api"
	KeyK8sKubeConfigPath      = "k8s-kubeconfig-path"
	KeyEnableProcessAncestors = "enable-process-ancestors"

	KeyMetricsServer      = "metrics-server"
	KeyMetricsLabelFilter = "metrics-label-filter"
	KeyServerAddress      = "server-address"
	KeyGopsAddr           = "gops-address"
	KeyEnableProcessCred  = "enable-process-cred"
	KeyEnableProcessNs    = "enable-process-ns"
	KeyTracingPolicy      = "tracing-policy"
	KeyTracingPolicyDir   = "tracing-policy-dir"

	KeyCpuProfile = "cpuprofile"
	KeyMemProfile = "memprofile"
	KeyPprofAddr  = "pprof-addr"

	KeyExportFilename             = "export-filename"
	KeyExportFileMaxSizeMB        = "export-file-max-size-mb"
	KeyExportFileRotationInterval = "export-file-rotation-interval"
	KeyExportFileMaxBackups       = "export-file-max-backups"
	KeyExportFileCompress         = "export-file-compress"
	KeyExportRateLimit            = "export-rate-limit"
	KeyExportFilePerm             = "export-file-perm"

	KeyEnableExportAggregation     = "enable-export-aggregation"
	KeyExportAggregationWindowSize = "export-aggregation-window-size"
	KeyExportAggregationBufferSize = "export-aggregation-buffer-size"

	KeyExportAllowlist = "export-allowlist"
	KeyExportDenylist  = "export-denylist"

	KeyFieldFilters = "field-filters"

	KeyNetnsDir = "netns-dir"

	KeyDisableKprobeMulti = "disable-kprobe-multi"

	KeyRBSize      = "rb-size"
	KeyRBSizeTotal = "rb-size-total"
	KeyRBQueueSize = "rb-queue-size"

	KeyEventQueueSize = "event-queue-size"

	KeyReleasePinnedBPF = "release-pinned-bpf"

	KeyEnablePolicyFilter      = "enable-policy-filter"
	KeyEnablePolicyFilterDebug = "enable-policy-filter-debug"

	KeyEnablePidSetFilter = "enable-pid-set-filter"

	KeyEnableMsgHandlingLatency = "enable-msg-handling-latency"

	KeyKmods = "kmods"

	KeyEnablePodInfo = "enable-pod-info"

	KeyExposeKernelAddresses = "expose-kernel-addresses"
)

func ReadAndSetFlags() error {
	Config.HubbleLib = viper.GetString(KeyHubbleLib)
	Config.BTF = viper.GetString(KeyBTF)
	Config.ProcFS = viper.GetString(KeyProcFS)
	Config.KernelVersion = viper.GetString(KeyKernelVersion)
	Config.Verbosity = viper.GetInt(KeyVerbosity)
	Config.ForceSmallProgs = viper.GetBool(KeyForceSmallProgs)
	Config.ForceLargeProgs = viper.GetBool(KeyForceLargeProgs)
	Config.Debug = viper.GetBool(KeyDebug)

	Config.EnableProcessCred = viper.GetBool(KeyEnableProcessCred)
	Config.EnableProcessNs = viper.GetBool(KeyEnableProcessNs)
	Config.EnableK8s = viper.GetBool(KeyEnableK8sAPI)
	Config.K8sKubeConfigPath = viper.GetString(KeyK8sKubeConfigPath)

	Config.DisableKprobeMulti = viper.GetBool(KeyDisableKprobeMulti)

	var err error

	if Config.RBSize, err = strutils.ParseSize(viper.GetString(KeyRBSize)); err != nil {
		return fmt.Errorf("failed to parse rb-size value: %s", err)
	}
	if Config.RBSizeTotal, err = strutils.ParseSize(viper.GetString(KeyRBSizeTotal)); err != nil {
		return fmt.Errorf("failed to parse rb-size-total value: %s", err)
	}
	if Config.RBQueueSize, err = strutils.ParseSize(viper.GetString(KeyRBQueueSize)); err != nil {
		return fmt.Errorf("failed to parse rb-queue-size value: %s", err)
	}

	Config.GopsAddr = viper.GetString(KeyGopsAddr)

	logLevel := viper.GetString(KeyLogLevel)
	logFormat := viper.GetString(KeyLogFormat)
	logger.PopulateLogOpts(Config.LogOpts, logLevel, logFormat)

	Config.ProcessCacheSize = viper.GetInt(KeyProcessCacheSize)
	Config.DataCacheSize = viper.GetInt(KeyDataCacheSize)

	Config.MetricsServer = viper.GetString(KeyMetricsServer)
	Config.MetricsLabelFilter = ParseMetricsLabelFilter(viper.GetString(KeyMetricsLabelFilter))
	Config.ServerAddress = viper.GetString(KeyServerAddress)

	Config.ExportFilename = viper.GetString(KeyExportFilename)
	Config.ExportFileMaxSizeMB = viper.GetInt(KeyExportFileMaxSizeMB)
	Config.ExportFileRotationInterval = viper.GetDuration(KeyExportFileRotationInterval)
	Config.ExportFileMaxBackups = viper.GetInt(KeyExportFileMaxBackups)
	Config.ExportFileCompress = viper.GetBool(KeyExportFileCompress)
	Config.ExportRateLimit = viper.GetInt(KeyExportRateLimit)
	Config.ExportFilePerm = viper.GetString(KeyExportFilePerm)

	Config.EnableExportAggregation = viper.GetBool(KeyEnableExportAggregation)
	Config.ExportAggregationWindowSize = viper.GetDuration(KeyExportAggregationWindowSize)
	Config.ExportAggregationBufferSize = viper.GetUint64(KeyExportAggregationBufferSize)

	Config.CpuProfile = viper.GetString(KeyCpuProfile)
	Config.MemProfile = viper.GetString(KeyMemProfile)
	Config.PprofAddr = viper.GetString(KeyPprofAddr)

	Config.EventQueueSize = viper.GetUint(KeyEventQueueSize)

	Config.ReleasePinned = viper.GetBool(KeyReleasePinnedBPF)
	Config.EnablePolicyFilter = viper.GetBool(KeyEnablePolicyFilter)
	Config.EnablePolicyFilterDebug = viper.GetBool(KeyEnablePolicyFilterDebug)
	Config.EnableMsgHandlingLatency = viper.GetBool(KeyEnableMsgHandlingLatency)

	Config.EnablePidSetFilter = viper.GetBool(KeyEnablePidSetFilter)

	Config.TracingPolicyDir = viper.GetString(KeyTracingPolicyDir)

	Config.KMods = viper.GetStringSlice(KeyKmods)

	Config.EnablePodInfo = viper.GetBool(KeyEnablePodInfo)

	Config.TracingPolicy = viper.GetString(KeyTracingPolicy)

	Config.ExposeKernelAddresses = viper.GetBool(KeyExposeKernelAddresses)

	return nil
}

func ParseMetricsLabelFilter(labels string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, label := range strings.Split(labels, ",") {
		result[label] = nil
	}
	return result
}
