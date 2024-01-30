// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"fmt"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/spf13/pflag"
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
	KeyDisableUprobeMulti = "disable-uprobe-multi"

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

	KeyEnablePodInfo          = "enable-pod-info"
	KeyEnableTracingPolicyCRD = "enable-tracing-policy-crd"

	KeyExposeKernelAddresses = "expose-kernel-addresses"

	KeyGenerateDocs = "generate-docs"
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
	Config.EnableTracingPolicyCRD = viper.GetBool(KeyEnableTracingPolicyCRD)

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

func AddFlags(flags *pflag.FlagSet) {
	flags.String(KeyConfigDir, "", "Configuration directory that contains a file for each option")
	flags.BoolP(KeyDebug, "d", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	flags.String(KeyHubbleLib, defaults.DefaultTetragonLib, "Location of Tetragon libs (btf and bpf files)")
	flags.String(KeyBTF, "", "Location of btf")

	flags.String(KeyProcFS, "/proc/", "Location of procfs to consume existing PIDs")
	flags.String(KeyKernelVersion, "", "Kernel version")
	flags.Int(KeyVerbosity, 0, "set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump")
	flags.Int(KeyProcessCacheSize, 65536, "Size of the process cache")
	flags.Int(KeyDataCacheSize, 1024, "Size of the data events cache")
	flags.Bool(KeyForceSmallProgs, false, "Force loading small programs, even in kernels with >= 5.3 versions")
	flags.Bool(KeyForceLargeProgs, false, "Force loading large programs, even in kernels with < 5.3 versions")
	flags.String(KeyExportFilename, "", "Filename for JSON export. Disabled by default")
	flags.Int(KeyExportFileMaxSizeMB, 10, "Size in MB for rotating JSON export files")
	flags.Duration(KeyExportFileRotationInterval, 0, "Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.Int(KeyExportFileMaxBackups, 5, "Number of rotated JSON export files to retain")
	flags.Bool(KeyExportFileCompress, false, "Compress rotated JSON export files")
	flags.String(KeyExportFilePerm, defaults.DefaultLogsPermission, "Access permissions on JSON export files")
	flags.Int(KeyExportRateLimit, -1, "Rate limit (per minute) for event export. Set to -1 to disable")
	flags.String(KeyLogLevel, "info", "Set log level")
	flags.String(KeyLogFormat, "text", "Set log format")
	flags.Bool(KeyEnableK8sAPI, false, "Access Kubernetes API to associate Tetragon events with Kubernetes pods")
	flags.String(KeyK8sKubeConfigPath, "", "Absolute path of the kubernetes kubeconfig file")
	flags.Bool(KeyEnableProcessAncestors, true, "Include ancestors in process exec events")
	flags.String(KeyMetricsServer, "", "Metrics server address (e.g. ':2112'). Disabled by default")
	flags.String(KeyMetricsLabelFilter, "", "Comma-separated list of enabled metric labels. (e.g. \"namespace,workload,pod,binary\") By default all labels are enabled.")
	flags.String(KeyServerAddress, "localhost:54321", "gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock'")
	flags.String(KeyGopsAddr, "", "gops server address (e.g. 'localhost:8118'). Disabled by default")
	flags.Bool(KeyEnableProcessCred, false, "Enable process_cred events")
	flags.Bool(KeyEnableProcessNs, false, "Enable namespace information in process_exec and process_kprobe events")
	flags.Uint(KeyEventQueueSize, 10000, "Set the size of the internal event queue.")

	// Tracing policy file
	flags.String(KeyTracingPolicy, "", "Tracing policy file to load at startup")

	flags.String(KeyTracingPolicyDir, defaults.DefaultTpDir, "Directory from where to load Tracing Policies")

	// Options for debugging/development, not visible to users
	flags.String(KeyCpuProfile, "", "Store CPU profile into provided file")
	flags.MarkHidden(KeyCpuProfile)

	flags.String(KeyMemProfile, "", "Store MEM profile into provided file")
	flags.MarkHidden(KeyMemProfile)

	flags.String(KeyPprofAddr, "", "Profile via pprof http")
	flags.MarkHidden(KeyPprofAddr)

	// JSON export aggregation options.
	flags.Bool(KeyEnableExportAggregation, false, "Enable JSON export aggregation")
	flags.Duration(KeyExportAggregationWindowSize, 15*time.Second, "JSON export aggregation time window")
	flags.Uint64(KeyExportAggregationBufferSize, 10000, "Aggregator channel buffer size")

	// JSON export filter options
	flags.String(KeyExportAllowlist, "", "JSON export allowlist")
	flags.String(KeyExportDenylist, "", "JSON export denylist")

	// Field filters options for export
	flags.String(KeyFieldFilters, "", "Field filters for event exports")

	// Network namespace options
	flags.String(KeyNetnsDir, "/var/run/docker/netns/", "Network namespace dir")

	// Allow to disable kprobe multi interface
	flags.Bool(KeyDisableKprobeMulti, false, "Allow to disable kprobe multi interface")

	// Allow to specify perf ring buffer size
	flags.String(KeyRBSizeTotal, "0", "Set perf ring buffer size in total for all cpus (default 65k per cpu, allows K/M/G suffix)")
	flags.String(KeyRBSize, "0", "Set perf ring buffer size for single cpu (default 65k, allows K/M/G suffix)")

	// Provide option to remove existing pinned BPF programs and maps in Tetragon's
	// observer dir on startup. Useful for doing upgrades/downgrades. Set to false to
	// disable.
	flags.Bool(KeyReleasePinnedBPF, true, "Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable")

	// Provide option to enable policy filtering. Because the code is new,
	// this is set to false by default.
	flags.Bool(KeyEnablePolicyFilter, false, "Enable policy filter code (beta)")
	flags.Bool(KeyEnablePolicyFilterDebug, false, "Enable policy filter debug messages")

	// Provide option to enable the pidSet export filters.
	flags.Bool(KeyEnablePidSetFilter, false, "Enable pidSet export filters. Not recommended for production use")

	flags.Bool(KeyEnableMsgHandlingLatency, false, "Enable metrics for message handling latency")

	flags.StringSlice(KeyKmods, []string{}, "List of kernel modules to load symbols from")

	flags.String(KeyRBQueueSize, "65535", "Set size of channel between ring buffer and sensor go routines (default 65k, allows K/M/G suffix)")

	flags.Bool(KeyEnablePodInfo, false, "Enable PodInfo custom resource")
	flags.Bool(KeyEnableTracingPolicyCRD, true, "Enable TracingPolicy and TracingPolicyNamespaced custom resources")

	flags.Bool(KeyExposeKernelAddresses, false, "Expose real kernel addresses in events stack traces")

	flags.Bool(KeyGenerateDocs, false, "Generate documentation in YAML format to stdout")
}
