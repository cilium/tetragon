// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/strutils"
)

const (
	KeyConfigDir              = "config-dir"
	KeyDebug                  = "debug"
	KeyHubbleLib              = "bpf-lib"
	KeyBTF                    = "btf"
	KeyProcFS                 = "procfs"
	KeyKernelVersion          = "kernel"
	KeyVerbosity              = "verbose"
	KeyProcessCacheSize       = "process-cache-size"
	KeyDataCacheSize          = "data-cache-size"
	KeyProcessCacheGCInterval = "process-cache-gc-interval"
	KeyForceSmallProgs        = "force-small-progs"
	KeyForceLargeProgs        = "force-large-progs"
	KeyClusterName            = "cluster-name"

	KeyLogLevel  = "log-level"
	KeyLogFormat = "log-format"

	KeyEnableK8sAPI         = "enable-k8s-api"
	KeyK8sKubeConfigPath    = "k8s-kubeconfig-path"
	KeyK8sControlPlaneRetry = "k8s-controlplane-retry"

	KeyEnablePodAnnotations = "enable-pod-annotations"

	KeyMetricsServer      = "metrics-server"
	KeyMetricsLabelFilter = "metrics-label-filter"
	KeyServerAddress      = "server-address"
	KeyGopsAddr           = "gops-address"

	KeyEnableProcessEnvironmentVariables = "enable-process-environment-variables"

	KeyFilterEnvironmentVariables = "filter-environment-variables"

	KeyEnableAncestors   = "enable-ancestors"
	KeyEnableProcessCred = "enable-process-cred"
	KeyEnableProcessNs   = "enable-process-ns"
	KeyTracingPolicy     = "tracing-policy"
	KeyTracingPolicyDir  = "tracing-policy-dir"

	KeyCpuProfile = "cpuprofile"
	KeyMemProfile = "memprofile"
	KeyPprofAddr  = "pprof-address"

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

	KeyFieldFilters     = "field-filters"
	KeyRedactionFilters = "redaction-filters"

	KeyNetnsDir = "netns-dir"

	KeyDisableKprobeMulti = "disable-kprobe-multi"
	KeyDisableUprobeMulti = "disable-uprobe-multi"

	KeyUsePerfRingBuffer = "use-perf-ring-buffer"
	KeyRBSize            = "rb-size"
	KeyRBSizeTotal       = "rb-size-total"
	KeyRBQueueSize       = "rb-queue-size"

	KeyEventQueueSize = "event-queue-size"

	KeyReleasePinnedBPF = "release-pinned-bpf"

	KeyEnablePolicyFilter          = "enable-policy-filter"
	KeyEnablePolicyFilterCgroupMap = "enable-policy-filter-cgroup-map"
	KeyEnablePolicyFilterDebug     = "enable-policy-filter-debug"

	KeyEnablePidSetFilter = "enable-pid-set-filter"

	KeyEnableMsgHandlingLatency = "enable-msg-handling-latency"

	KeyEnablePodInfo          = "enable-pod-info"
	KeyEnableTracingPolicyCRD = "enable-tracing-policy-crd"

	KeyExposeStackAddresses = "expose-stack-addresses"

	KeyGenerateDocs = "generate-docs"

	KeyCgroupRate = "cgroup-rate"

	KeyUsernameMetadata = "username-metadata"

	KeyHealthServerAddress = "health-server-address"
	KeyHealthTimeInterval  = "health-server-interval"

	KeyBpfDir = "bpf-dir"

	KeyKeepSensorsOnExit = "keep-sensors-on-exit"

	KeyEnableCRI   = "enable-cri"
	KeyCRIEndpoint = "cri-endpoint"

	KeyEnableCgIDmap      = "enable-cgidmap"
	KeyEnableCgIDmapDebug = "enable-cgidmap-debug"
	KeyEnableCgTrackerID  = "enable-cgtrackerid"

	KeyEventCacheRetries    = "event-cache-retries"
	KeyEventCacheRetryDelay = "event-cache-retry-delay"

	KeyCompatibilitySyscall64SizeType = "enable-compatibility-syscall64-size-type"

	KeyExecveMapEntries = "execve-map-entries"
	KeyExecveMapSize    = "execve-map-size"

	KeyRetprobesCacheSize = "retprobes-cache-size"
)

type UsernameMetadaCode int

const (
	// Username metadata collection modes
	USERNAME_METADATA_DISABLED UsernameMetadaCode = iota
	USERNAME_METADATA_UNIX     UsernameMetadaCode = 1 // Username from /etc/passwd
)

func (op UsernameMetadaCode) String() string {
	return [...]string{
		USERNAME_METADATA_DISABLED: "disabled",
		USERNAME_METADATA_UNIX:     "unix",
	}[op]
}

func ReadAndSetFlags() error {
	Config.HubbleLib = viper.GetString(KeyHubbleLib)
	Config.BTF = viper.GetString(KeyBTF)
	Config.ProcFS = viper.GetString(KeyProcFS)
	Config.KernelVersion = viper.GetString(KeyKernelVersion)
	Config.Verbosity = viper.GetInt(KeyVerbosity)
	Config.ForceSmallProgs = viper.GetBool(KeyForceSmallProgs)
	Config.ForceLargeProgs = viper.GetBool(KeyForceLargeProgs)
	Config.Debug = viper.GetBool(KeyDebug)
	Config.ClusterName = viper.GetString(KeyClusterName)

	Config.EnableProcessCred = viper.GetBool(KeyEnableProcessCred)
	Config.EnableProcessNs = viper.GetBool(KeyEnableProcessNs)
	Config.EnableK8s = viper.GetBool(KeyEnableK8sAPI)
	Config.K8sKubeConfigPath = viper.GetString(KeyK8sKubeConfigPath)
	Config.K8sControlPlaneRetry = viper.GetInt(KeyK8sControlPlaneRetry)

	Config.DisableKprobeMulti = viper.GetBool(KeyDisableKprobeMulti)

	var err error
	var enableAncestors []string

	Config.UsePerfRingBuffer = viper.GetBool(KeyUsePerfRingBuffer)
	if Config.RBSize, err = strutils.ParseSize(viper.GetString(KeyRBSize)); err != nil {
		return fmt.Errorf("failed to parse rb-size value: %w", err)
	}
	if Config.RBSizeTotal, err = strutils.ParseSize(viper.GetString(KeyRBSizeTotal)); err != nil {
		return fmt.Errorf("failed to parse rb-size-total value: %w", err)
	}
	if Config.RBQueueSize, err = strutils.ParseSize(viper.GetString(KeyRBQueueSize)); err != nil {
		return fmt.Errorf("failed to parse rb-queue-size value: %w", err)
	}
	if err = viper.UnmarshalKey(KeyEnableAncestors, &enableAncestors, viper.DecodeHook(stringToSliceHookFunc(","))); err != nil {
		return fmt.Errorf("failed to parse enable-ancestors value: %w", err)
	}

	if slices.Contains(enableAncestors, "base") {
		Config.EnableProcessAncestors = true
		Config.EnableProcessKprobeAncestors = slices.Contains(enableAncestors, "kprobe")
		Config.EnableProcessTracepointAncestors = slices.Contains(enableAncestors, "tracepoint")
		Config.EnableProcessUprobeAncestors = slices.Contains(enableAncestors, "uprobe")
		Config.EnableProcessLsmAncestors = slices.Contains(enableAncestors, "lsm")
		Config.EnableProcessUsdtAncestors = slices.Contains(enableAncestors, "usdt")
	}

	Config.EnableProcessEnvironmentVariables = viper.GetBool(KeyEnableProcessEnvironmentVariables)

	vars := viper.GetStringSlice(KeyFilterEnvironmentVariables)
	if len(vars) != 0 {
		filter := make(map[string]struct{})
		for _, v := range vars {
			filter[v] = struct{}{}
		}
		Config.FilterEnvironmentVariables = filter
	}

	Config.GopsAddr = viper.GetString(KeyGopsAddr)

	logLevel := viper.GetString(KeyLogLevel)
	logFormat := viper.GetString(KeyLogFormat)
	logger.PopulateLogOpts(Config.LogOpts, logLevel, logFormat)

	Config.ProcessCacheSize = viper.GetInt(KeyProcessCacheSize)
	Config.DataCacheSize = viper.GetInt(KeyDataCacheSize)
	Config.ProcessCacheGCInterval = viper.GetDuration(KeyProcessCacheGCInterval)

	if Config.ProcessCacheGCInterval <= 0 {
		return errors.New("failed to parse process-cache-gc-interval value. Must be >= 0")
	}

	Config.MetricsServer = viper.GetString(KeyMetricsServer)
	Config.MetricsLabelFilter = DefaultLabelFilter().WithEnabledLabels(ParseMetricsLabelFilter(viper.GetString(KeyMetricsLabelFilter)))
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
	Config.EnablePolicyFilterCgroupMap = viper.GetBool(KeyEnablePolicyFilterCgroupMap)
	Config.EnablePolicyFilterDebug = viper.GetBool(KeyEnablePolicyFilterDebug)
	Config.EnableMsgHandlingLatency = viper.GetBool(KeyEnableMsgHandlingLatency)

	Config.EnablePidSetFilter = viper.GetBool(KeyEnablePidSetFilter)

	Config.TracingPolicyDir = viper.GetString(KeyTracingPolicyDir)

	Config.EnablePodInfo = viper.GetBool(KeyEnablePodInfo)
	Config.EnablePodAnnotations = viper.GetBool(KeyEnablePodAnnotations)
	Config.EnableTracingPolicyCRD = viper.GetBool(KeyEnableTracingPolicyCRD)

	Config.TracingPolicy = viper.GetString(KeyTracingPolicy)

	switch o := viper.GetString(KeyUsernameMetadata); o {
	case "unix":
		Config.UsernameMetadata = int(USERNAME_METADATA_UNIX)
	case "disabled":
		Config.UsernameMetadata = int(USERNAME_METADATA_DISABLED)
	default:
		return fmt.Errorf("unknown option for %s: %q", KeyUsernameMetadata, o)
	}

	Config.ExposeStackAddresses = viper.GetBool(KeyExposeStackAddresses)

	Config.CgroupRate = ParseCgroupRate(viper.GetString(KeyCgroupRate))
	Config.HealthServerAddress = viper.GetString(KeyHealthServerAddress)
	Config.HealthServerInterval = viper.GetInt(KeyHealthTimeInterval)

	Config.BpfDir = viper.GetString(KeyBpfDir)

	Config.KeepSensorsOnExit = viper.GetBool(KeyKeepSensorsOnExit)

	Config.EnableCRI = viper.GetBool(KeyEnableCRI)
	Config.CRIEndpoint = viper.GetString(KeyCRIEndpoint)

	Config.EnableCgIDmap = viper.GetBool(KeyEnableCgIDmap)
	Config.EnableCgIDmapDebug = viper.GetBool(KeyEnableCgIDmapDebug)
	if viper.IsSet(KeyEnableCgTrackerID) {
		Config.EnableCgTrackerID = viper.GetBool(KeyEnableCgTrackerID)
	} else {
		// if cgidmap is set, also set cgtrackerid if user left it unset
		Config.EnableCgTrackerID = Config.EnableCgIDmap
	}

	Config.EventCacheNumRetries = viper.GetInt(KeyEventCacheRetries)
	Config.EventCacheRetryDelay = viper.GetInt(KeyEventCacheRetryDelay)

	Config.CompatibilitySyscall64SizeType = viper.GetBool(KeyCompatibilitySyscall64SizeType)

	Config.ExecveMapEntries = viper.GetInt(KeyExecveMapEntries)
	Config.ExecveMapSize = viper.GetString(KeyExecveMapSize)

	Config.RetprobesCacheSize = viper.GetInt(KeyRetprobesCacheSize)
	return nil
}

type CgroupRate struct {
	Events   uint64
	Interval uint64
}

func ParseCgroupRate(rate string) CgroupRate {
	empty := CgroupRate{}

	if rate == "" {
		return empty
	}

	s := strings.Split(rate, ",")
	if len(s) != 2 {
		logger.GetLogger().Warn(fmt.Sprintf("failed to parse cgroup rate '%s'", rate))
		return empty
	}

	var interval time.Duration
	var events int
	var err error

	if len(s[0]) > 0 {
		events, err = strconv.Atoi(s[0])
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("failed to parse cgroup rate '%s' : %s", rate, err))
			return empty
		}
	}

	if len(s[1]) > 0 {
		interval, err = time.ParseDuration(s[1])
		if err != nil {
			logger.GetLogger().Warn(fmt.Sprintf("failed to parse cgroup rate '%s'", rate), logfields.Error, err)
			return empty
		}
	}

	return CgroupRate{
		Events:   uint64(events),
		Interval: uint64(interval),
	}
}

// StringToSliceHookFunc returns a DecodeHookFunc that converts string to []string
// by splitting on the given sep and removing all leading and trailing white spaces.
func stringToSliceHookFunc(sep string) mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data any) (any, error) {
		if f.Kind() != reflect.String || t != reflect.SliceOf(f) {
			return data, nil
		}

		outSlice := []string{}
		for s := range strings.SplitSeq(data.(string), sep) {
			s = strings.TrimSpace(s)
			outSlice = append(outSlice, s)
		}
		return outSlice, nil
	}
}

func AddFlags(flags *pflag.FlagSet) {
	flags.String(KeyConfigDir, "", "Configuration directory that contains a file for each option")
	flags.BoolP(KeyDebug, "d", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	flags.String(KeyHubbleLib, defaults.DefaultTetragonLib, "Location of Tetragon libs (btf and bpf files)")
	flags.String(KeyBTF, "", "Location of btf")
	flags.String(KeyClusterName, "", "Name of the cluster where Tetragon is installed")

	flags.String(KeyProcFS, "/proc/", "Location of procfs to consume existing PIDs")
	flags.String(KeyKernelVersion, "", "Kernel version")
	flags.Int(KeyVerbosity, 0, "set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump")
	flags.Int(KeyProcessCacheSize, 65536, "Size of the process cache")
	flags.Int(KeyDataCacheSize, 1024, "Size of the data events cache")
	flags.Duration(KeyProcessCacheGCInterval, defaults.DefaultProcessCacheGCInterval, "Time between checking the process cache for old entries")
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
	flags.Int(KeyK8sControlPlaneRetry, 1, "Number of attempts for Kubernetes control plane connection (negative for infinite, zero is invalid, positive for max attempts)")
	flags.String(KeyMetricsServer, "", "Metrics server address (e.g. ':2112'). Disabled by default")
	flags.String(KeyMetricsLabelFilter, "namespace,workload,pod,binary", "Comma-separated list of enabled metrics labels. Unknown labels will be ignored.")
	flags.String(KeyServerAddress, "localhost:54321", "gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock'). An empty address disables the gRPC server")
	flags.String(KeyGopsAddr, "", "gops server address (e.g. 'localhost:8118'). Disabled by default")
	flags.Bool(KeyEnableProcessCred, false, "Enable process_cred events")
	flags.Bool(KeyEnableProcessNs, false, "Enable namespace information in process_exec and process_kprobe events")
	flags.Uint(KeyEventQueueSize, 10000, "Set the size of the internal event queue.")
	flags.Bool(KeyEnablePodAnnotations, false, "Add pod annotations field to events.")
	flags.StringSlice(KeyEnableAncestors, []string{}, "Comma-separated list of process event types to enable ancestors for. Supported event types are: base, kprobe, tracepoint, uprobe, lsm, usdt. Unknown event types will be ignored. Type 'base' enables ancestors for process_exec and process_exit events and is required by all other supported event types for correct reference counting. An empty string disables ancestors completely")

	flags.Bool(KeyEnableProcessEnvironmentVariables, false, "Include environment variables in process_exec events. Disabled by default. Note that this option can significantly increase the size of the events and may impact performance, as well as capture sensitive information such as passwords in the events (you can use --redaction-filters to redact the data).")

	// filter option for allowed envs
	flags.StringSliceP(KeyFilterEnvironmentVariables, "", nil, "Filter for specific environment variables")

	// Tracing policy file
	flags.String(KeyTracingPolicy, "", "Tracing policy file to load at startup")

	flags.String(KeyTracingPolicyDir, defaults.DefaultTpDir, "Directory from where to load Tracing Policies")

	// Options for debugging/development, not visible to users
	flags.String(KeyCpuProfile, "", "Store CPU profile into provided file")
	flags.MarkHidden(KeyCpuProfile)

	flags.String(KeyMemProfile, "", "Store MEM profile into provided file")
	flags.MarkHidden(KeyMemProfile)

	flags.String(KeyPprofAddr, "", "Serves runtime profile data via HTTP (e.g. 'localhost:6060'). Disabled by default")

	// JSON export aggregation options.
	flags.Bool(KeyEnableExportAggregation, false, "Enable JSON export aggregation")
	flags.Duration(KeyExportAggregationWindowSize, 15*time.Second, "JSON export aggregation time window")
	flags.Uint64(KeyExportAggregationBufferSize, 10000, "Aggregator channel buffer size")

	// JSON export filter options
	flags.String(KeyExportAllowlist, "", "JSON export allowlist")
	flags.String(KeyExportDenylist, "", "JSON export denylist")

	// Field filters options for export
	flags.String(KeyFieldFilters, "", "Field filters for event exports")

	// Redaction filters
	flags.String(KeyRedactionFilters, "", "Redaction filters for events")

	// Network namespace options
	flags.String(KeyNetnsDir, "/var/run/docker/netns/", "Network namespace dir")

	// Allow to disable kprobe multi interface
	flags.Bool(KeyDisableKprobeMulti, false, "Allow to disable kprobe multi interface")

	// Allow to specify ring buffer
	flags.Bool(KeyUsePerfRingBuffer, false, "Use the perf ring buffer instead of the bpf ring buffer")
	// Allow to specify ring buffer size
	flags.String(KeyRBSizeTotal, "0", "Set ring buffer size in total for all cpus (default 65k per cpu, allows K/M/G suffix)")
	flags.String(KeyRBSize, "0", "Set ring buffer size for single cpu (default 65k, allows K/M/G suffix)")

	// Provide option to remove existing pinned BPF programs and maps in Tetragon's
	// observer dir on startup. Useful for doing upgrades/downgrades. Set to false to
	// disable.
	flags.Bool(KeyReleasePinnedBPF, true, "Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable")

	// Provide option to enable policy filtering. Because the code is new,
	// this is set to false by default.
	flags.Bool(KeyEnablePolicyFilter, false, "Enable policy filter code")
	flags.Bool(KeyEnablePolicyFilterCgroupMap, false, "Enable cgroup mappings for policy filter maps")
	flags.Bool(KeyEnablePolicyFilterDebug, false, "Enable policy filter debug messages")

	// Provide option to enable the pidSet export filters.
	flags.Bool(KeyEnablePidSetFilter, false, "Enable pidSet export filters. Not recommended for production use")

	flags.Bool(KeyEnableMsgHandlingLatency, false, "Enable metrics for message handling latency")

	flags.String(KeyRBQueueSize, "65535", "Set size of channel between ring buffer and sensor go routines (default 65k, allows K/M/G suffix)")

	flags.Bool(KeyEnablePodInfo, false, "Enable PodInfo custom resource")
	flags.Bool(KeyEnableTracingPolicyCRD, true, "Enable TracingPolicy and TracingPolicyNamespaced custom resources")

	flags.Bool(KeyExposeStackAddresses, false, "Expose real linear addresses in events stack traces")

	flags.Bool(KeyGenerateDocs, false, "Generate documentation in YAML format to stdout")

	flags.String(KeyUsernameMetadata, "disabled", "Resolve UIDs to user names for processes running in host namespace")

	flags.String(KeyCgroupRate, "", "Base sensor events cgroup rate <events,interval> disabled by default ('1000,1s' means rate 1000 events per second)")

	flags.String(KeyHealthServerAddress, ":6789", "Health server address (e.g. ':6789')(use '' to disabled it)")
	flags.Int(KeyHealthTimeInterval, 10, "Health server interval in seconds")

	flags.String(KeyBpfDir, defaults.DefaultMapPrefix, "Set tetragon bpf directory (default 'tetragon')")

	flags.Bool(KeyKeepSensorsOnExit, false, "Do not unload sensors on exit")

	flags.Bool(KeyEnableCRI, false, "enable CRI client for tetragon")
	flags.String(KeyCRIEndpoint, "", "CRI endpoint")

	flags.Bool(KeyEnableCgIDmap, false, "enable pod resolution via cgroup ids")
	flags.Bool(KeyEnableCgIDmapDebug, false, "enable cgidmap debugging info")
	flags.Bool(KeyEnableCgTrackerID, true, fmt.Sprintf("enable cgroup tracker id (only used if '%s' is set)", KeyEnableCgIDmap))

	flags.Int(KeyEventCacheRetries, defaults.DefaultEventCacheNumRetries, "Number of retries for event cache")
	flags.Int(KeyEventCacheRetryDelay, defaults.DefaultEventCacheRetryDelay, "Delay in seconds between event cache retries")

	flags.Bool(KeyCompatibilitySyscall64SizeType, false, "syscall64 type will produce output of type size (compatibility flag, will be removed in v1.4)")

	flags.Int(KeyExecveMapEntries, 0, "Set entries for execve_map table (default 32768)")
	flags.String(KeyExecveMapSize, "", "Set size for execve_map table (allows K/M/G suffix)")

	flags.Int(KeyRetprobesCacheSize, defaults.DefaultRetprobesCacheSize, "Set {k,u}retprobes events cache maximum size")
}
