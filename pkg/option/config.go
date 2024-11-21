// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/spf13/viper"
)

type config struct {
	Debug           bool
	ProcFS          string
	KernelVersion   string
	HubbleLib       string
	BTF             string
	Verbosity       int
	ForceSmallProgs bool
	ForceLargeProgs bool
	ClusterName     string

	EnableProcessNs   bool
	EnableProcessCred bool
	EnableK8s         bool
	K8sKubeConfigPath string

	DisableKprobeMulti bool

	GopsAddr string

	// On start used to store bpf prefix for --bpf-dir option,
	// then it's updated to cary the whole path
	BpfDir string

	LogOpts map[string]string

	RBSize      int
	RBSizeTotal int
	RBQueueSize int

	ProcessCacheSize       int
	DataCacheSize          int
	ProcessCacheGCInterval time.Duration

	MetricsServer      string
	MetricsLabelFilter metrics.LabelFilter
	ServerAddress      string
	TracingPolicy      string
	TracingPolicyDir   string

	ExportFilename             string
	ExportFileMaxSizeMB        int
	ExportFileRotationInterval time.Duration
	ExportFileMaxBackups       int
	ExportFileCompress         bool
	ExportRateLimit            int
	ExportFilePerm             string

	// Export aggregation options
	EnableExportAggregation     bool
	ExportAggregationWindowSize time.Duration
	ExportAggregationBufferSize uint64

	CpuProfile string
	MemProfile string
	PprofAddr  string

	EventQueueSize uint

	ReleasePinned bool

	EnablePolicyFilter      bool
	EnablePolicyFilterDebug bool

	EnablePidSetFilter bool

	EnableMsgHandlingLatency bool

	EnablePodInfo          bool
	EnableTracingPolicyCRD bool

	ExposeStackAddresses bool

	CgroupRate CgroupRate

	UsernameMetadata int

	HealthServerAddress  string
	HealthServerInterval int

	KeepSensorsOnExit bool

	EnableCRI   bool
	CRIEndpoint string

	EnableCgIDmap      bool
	EnableCgIDmapDebug bool

	EventCacheNumRetries int
	EventCacheRetryDelay int

	CompatibilitySyscall64SizeType bool
}

var (
	log = logger.GetLogger()

	// Config contains all the configuration used by Tetragon.
	Config = config{
		// Initialize global defaults below.

		// ProcFS defaults to /proc.
		ProcFS: "/proc",

		// LogOpts contains logger parameters
		LogOpts: make(map[string]string),

		// Enable all metrics labels by default
		MetricsLabelFilter: DefaultLabelFilter(),

		// set default valus for the event cache
		// mainly used in the case of testing
		EventCacheNumRetries: defaults.DefaultEventCacheNumRetries,
		EventCacheRetryDelay: defaults.DefaultEventCacheRetryDelay,
	}
)

func CgroupRateEnabled() bool {
	return Config.CgroupRate.Events != 0 && Config.CgroupRate.Interval != 0
}

// ReadDirConfig reads the given directory and returns a map that maps the
// filename to the contents of that file.
func ReadDirConfig(dirName string) (map[string]interface{}, error) {
	m := map[string]interface{}{}
	files, err := os.ReadDir(dirName)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read configuration directory: %s", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		fName := filepath.Join(dirName, f.Name())

		// the file can still be a symlink to a directory
		if f.Type()&os.ModeSymlink == 0 {
			absFileName, err := filepath.EvalSymlinks(fName)
			if err != nil {
				log.WithError(err).Warnf("Unable to read configuration file %q", absFileName)
				continue
			}
			fName = absFileName
		}

		fi, err := os.Stat(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		if fi.Mode().IsDir() {
			continue
		}

		b, err := os.ReadFile(fName)
		if err != nil {
			log.WithError(err).Warnf("Unable to read configuration file %q", fName)
			continue
		}
		m[f.Name()] = string(bytes.TrimSpace(b))
	}
	return m, nil
}

func ReadConfigFile(path string, file string) error {
	filePath := filepath.Join(path, file)
	st, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("failed to read config file '%s' not a regular file", file)
	}

	viper.AddConfigPath(path)
	err = viper.MergeInConfig()
	if err != nil {
		return err
	}

	return nil
}

func ReadConfigDir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("'%s' is not a directory", path)
	}

	cm, err := ReadDirConfig(path)
	if err != nil {
		return err
	}
	if err := viper.MergeConfigMap(cm); err != nil {
		return fmt.Errorf("merge config failed %v", err)
	}

	return nil
}
