// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	tetragonGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/pidfile"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crdwatcher"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var (
	log = logger.GetLogger()
)

func getExportFilters() ([]*tetragon.Filter, []*tetragon.Filter, error) {
	allowList, err := filters.ParseFilterList(viper.GetString(option.KeyExportAllowlist), viper.GetBool(option.KeyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	denyList, err := filters.ParseFilterList(viper.GetString(option.KeyExportDenylist), viper.GetBool(option.KeyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	return allowList, denyList, nil
}

func getFieldFilters() ([]*tetragon.FieldFilter, error) {
	fieldFilters := viper.GetString(option.KeyFieldFilters)

	filters, err := fieldfilters.ParseFieldFilterList(fieldFilters)
	if err != nil {
		return nil, err
	}

	return filters, nil
}

func setRedactionFilters() error {
	var err error
	redactionFilters := viper.GetString(option.KeyRedactionFilters)
	fieldfilters.RedactionFilters, err = fieldfilters.ParseRedactionFilterList(redactionFilters)
	if err == nil {
		log.Info("Configured redaction filters", "redactionFilters", redactionFilters)
	} else {
		log.Error("Error configuring redaction filters", logfields.Error, err)
	}
	return err
}

func absPath(p string) string {
	if len(p) == 0 {
		return p
	}
	ret, err := filepath.Abs(p)
	if err != nil {
		log.Warn("failed to get absolute path", "path", p, logfields.Error, err)
		return p
	}
	return ret
}

// Save daemon information so it is used by client cli but
// also by bugtool
func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: absPath(option.Config.ExportFilename),
		LibDir:      absPath(option.Config.HubbleLib),
		BTFFname:    absPath(option.Config.BTF),
		MetricsAddr: option.Config.MetricsServer,
		ServerAddr:  option.Config.ServerAddress,
		GopsAddr:    option.Config.GopsAddr,
		MapDir:      absPath(bpf.MapPrefixPath()),
		PID:         os.Getpid(),
	}
	return bugtool.SaveInitInfo(&info)
}

func stopProfile() {
	if option.Config.MemProfile != "" {
		log.Info("Stopping mem profiling", "file", option.Config.MemProfile)
		f, err := os.Create(option.Config.MemProfile)
		if err != nil {
			logger.Fatal(log, "could not create memory profile", "file", option.Config.MemProfile, logfields.Error, err)
		}
		defer f.Close()
		// get up-to-date statistics
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			logger.Fatal(log, "could not write memory profile", logfields.Error, err)
		}
	}
	if option.Config.CpuProfile != "" {
		log.Info("Stopping cpu profiling", "file", option.Config.CpuProfile)
		pprof.StopCPUProfile()
	}
}

func getOldBpfDir(path string) (string, error) {
	// sysfs directory will be removed, so we don't care
	if option.Config.ReleasePinned {
		return "", nil
	}
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	old := path + "_old"
	// remove the 'xxx_old' leftover if neded
	if _, err := os.Stat(old); err == nil {
		os.RemoveAll(old)
		log.Info("Found bpf leftover instance, removing: " + old)
	}
	if err := os.Rename(path, old); err != nil {
		return "", err
	}
	log.Info(fmt.Sprintf("Found bpf instance: %s, moved to: %s", path, old))
	return old, nil
}

func deleteOldBpfDir(path string) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		log.Error(fmt.Sprintf("Failed to remove old bpf instance '%s'\n", path), logfields.Error, err)
		return
	}
	log.Info("Removed bpf instance: " + path)
}

func loadInitialSensor(ctx context.Context) error {
	mgr := observer.GetSensorManager()
	initialSensor := base.GetInitialSensor()

	if err := mgr.AddSensor(ctx, initialSensor.Name, initialSensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialSensor.Name)
}

func tetragonExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return tetragonExecuteCtx(ctx, cancel, func() {})
}

func tetragonExecuteCtx(ctx context.Context, cancel context.CancelFunc, ready func()) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		logger.Fatal(log, "Failed to setup logging", logfields.Error, err)
	}

	if !filepath.IsAbs(option.Config.TracingPolicyDir) {
		logger.Fatal(log, fmt.Sprintf("Failed path specified by --tracing-policy-dir '%q' is not absolute", option.Config.TracingPolicyDir))
	}
	option.Config.TracingPolicyDir = filepath.Clean(option.Config.TracingPolicyDir)

	if option.Config.RBSize != 0 && option.Config.RBSizeTotal != 0 {
		logger.Fatal(log, "Can't specify --rb-size and --rb-size-total together")
	}

	if option.Config.ExecveMapEntries != 0 && len(option.Config.ExecveMapSize) != 0 {
		logger.Fatal(log, "Can't specify --execve-map-entries and --execve-map-size together")
	}

	if option.Config.EnableProcessEnvironmentVariables && !config.EnableLargeProgs() {
		logger.Fatal(log, "Can't specify --enable-process-environment-variables on early kernels (<v5.3)")
	}

	// enable extra programs/maps loading debug output
	if logger.GetLogger().Enabled(ctx, slog.LevelDebug) {
		program.KeepCollection = true
	}

	log.Info("Starting tetragon", "version", version.Version)
	log.Info("config settings", "config", viper.AllSettings())

	// Create run dir early
	os.MkdirAll(defaults.DefaultRunDir, 0755)

	// Log early security context in case something fails
	logCurrentSecurityContext()

	// When an instance terminates or restarts it may cleanup bpf programs,
	// having a check here to see if another instance is already running.
	pid, err := pidfile.Create()
	if err != nil {
		// pidfile.Create returns error if creation of pid file failed with error
		// other than pidfile.ErrPidFileAccess and pidfile.ErrPidIsNotAlive.
		// In most cases this will mean that another instance of Tetragon is up
		// and running and may interfere on eBPF programs and/or maps and lead
		// to unpredictable behavior.
		return fmt.Errorf("failed to create pid file '%s', another Tetragon instance seems to be up and running: %w", defaults.DefaultPidFile, err)
	}
	defer pidfile.Delete()

	log.Info("Tetragon pid file creation succeeded", "pid", pid, "pidfile", defaults.DefaultPidFile)

	if option.Config.ForceLargeProgs && option.Config.ForceSmallProgs {
		logger.Fatal(log, "Can't specify --force-small-progs and --force-large-progs together")
	}

	if option.Config.ForceLargeProgs {
		log.Info("Force loading large programs")
	}

	if option.Config.ForceSmallProgs {
		log.Info("Force loading smallprograms")
	}

	if option.Config.KeepSensorsOnExit {
		// The effect of having both --release-pinned-bpf and --keep-sensors-on-exit options
		// enabled is that the previous sysfs instance will be removed early before the new
		// config is set. Not a big problem, but better to warn..
		if option.Config.ReleasePinned {
			log.Warn("Options --release-pinned-bpf and --keep-sensors-on-exit enabled together, we will remove sysfs instance early.")
		}
		log.Info("Not unloading sensors on exit")
	}

	setNetNSDir()

	if err := checkStructAlignments(); err != nil {
		return fmt.Errorf("struct alignment checks failed: %w", err)
	}

	// Initialize namespaces here. On errors fail, there is
	// no point to continue if read/ptrace on /proc/1/ fails.
	// Providing correct information can't be achieved anyway.
	err = initHostNamespaces()
	if err != nil {
		logger.Fatal(log, "Failed to initialize host namespaces", "procfs", option.Config.ProcFS, logfields.Error, err)
	}
	checkProcFS()
	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountTraceFS()
	bpf.CheckOrMountCgroup2()
	bpf.SetMapPrefix(option.Config.BpfDir)

	// We try to detect previous instance, which might be there for legitimate reasons
	// (--keep-sensors-on-exit) and rename to 'tetragon_old'.
	// Then we do the 'best' effort to keep running sensors as long as possible and remove
	// 'tetragon_old' directory when tetragon is started and its policy is loaded.
	// If there's --release-pinned-bpf option enabled, we need to remove previous sysfs
	// instance right away (see check for option.Config.ReleasePinned below), so we don't
	// bother renaming in that case.
	oldBpfDir, err := getOldBpfDir(bpf.MapPrefixPath())
	if err != nil {
		return fmt.Errorf("failed to move old tetragon base directory: %w", err)
	}

	if option.Config.PprofAddr != "" {
		go func() {
			if err := servePprof(option.Config.PprofAddr); err != nil {
				log.Warn("serving pprof via http", logfields.Error, err)
			}
		}()
	}

	// Start profilers first as we have to capture them in signal handling
	if option.Config.MemProfile != "" {
		log.Info("Starting mem profiling", "file", option.Config.MemProfile)
	}

	if option.Config.CpuProfile != "" {
		f, err := os.Create(option.Config.CpuProfile)
		if err != nil {
			logger.Fatal(log, "could not create CPU profile", logfields.Error, err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			logger.Fatal(log, "could not start CPU profile", logfields.Error, err)
		}
		log.Info("Starting cpu profiling", "file", option.Config.CpuProfile)
	}

	defer stopProfile()

	// Raise memory resource
	bpf.ConfigureResourceLimits()

	// Get observer bpf maps and programs directory
	observerDir := getObserverDir()
	option.Config.BpfDir = observerDir

	// Check if option to remove old BPF and maps is enabled.
	if option.Config.ReleasePinned {
		err := os.RemoveAll(observerDir)
		if err != nil {
			log.Warn("BPF: failed to release pinned BPF programs and maps, Consider removing it manually", "bpf-dir", observerDir, logfields.Error, err)
		} else {
			log.Info("BPF: successfully released pinned BPF programs and maps", "bpf-dir", observerDir)
		}
	}

	// Get observer from configFile
	obs := observer.NewObserver()
	defer func() {
		obs.PrintStats()
	}()

	go func() {
		s := <-sigs
		// if we receive a signal, call cancel so that contexts are finalized, which will
		// leads to normally return from tetragonExecute().
		log.Info(fmt.Sprintf("Received signal %s, shutting down...", s))
		cancel()
	}()

	if err := obs.InitSensorManager(); err != nil {
		return err
	}

	if err := initCachedBTF(option.Config.HubbleLib, option.Config.BTF); err != nil {
		return err
	}

	// needs BTF, so caling it after InitCachedBTF
	log.Info("BPF detected features: " + bpf.LogFeatures())

	if err := observer.InitDataCache(option.Config.DataCacheSize); err != nil {
		return err
	}

	if option.Config.MetricsServer != "" {
		go metricsconfig.EnableMetrics(option.Config.MetricsServer)
		metricsconfig.InitAllMetrics(metricsconfig.GetRegistry())
		go metrics.StartPodDeleteHandler()
		// Handler must be registered before the watcher is started
		metrics.RegisterPodDeleteHandler()
	}

	// Probe runtime configuration and do not fail on errors
	obs.UpdateRuntimeConf(option.Config.BpfDir)

	// Initialize a k8s watcher used to retrieve process metadata. This should
	// happen before the sensors are loaded, otherwise events will be stuck
	// waiting for metadata.
	var controllerManager *manager.ControllerManager
	var podAccessor watcher.PodAccessor
	if option.K8SControlPlaneEnabled() {
		log.Info("Enabling Kubernetes API")
		// Start controller-runtime manager.
		controllerManager = manager.Get()
		controllerManager.Start(ctx)
		crds := make(map[string]struct{})
		if option.Config.EnableTracingPolicyCRD {
			crds[v1alpha1.TPName] = struct{}{}
			crds[v1alpha1.TPNamespacedName] = struct{}{}
		}
		if option.Config.EnablePodInfo {
			crds[v1alpha1.PIName] = struct{}{}
		}
		if option.InClusterControlPlaneEnabled() {
			if len(crds) > 0 {
				err = controllerManager.WaitCRDs(ctx, crds)
				if err != nil {
					return err
				}
			}
			podAccessor = controllerManager
			k8sNode, err := controllerManager.GetNode()
			if err != nil {
				log.Warn("Failed to get local Kubernetes node info. node_labels field will be empty", logfields.Error, err)
			} else {
				node.SetNodeLabels(k8sNode.Labels)
			}
		} else {
			podAccessor = watcher.NewFakeK8sWatcher(nil)
		}
	} else {
		log.Info("Disabling Kubernetes API")
		podAccessor = watcher.NewFakeK8sWatcher(nil)
	}

	pcGCInterval := option.Config.ProcessCacheGCInterval
	if pcGCInterval <= 0 {
		pcGCInterval = defaults.DefaultProcessCacheGCInterval
	}

	if err := process.InitCache(podAccessor, option.Config.ProcessCacheSize, pcGCInterval); err != nil {
		return err
	}

	// cleanupWg is needed to ensure that gRPC code cleanly finishes before we exit (e.g,
	// due to a signal). This is needed, for example, so that the exported writes full
	// (uncorrupted) to the file. See: 4b7c8d1c427a46b864763e910e8f3511e1c4eb00.
	var cleanupWg sync.WaitGroup
	defer cleanupWg.Wait()

	// The "defer cleanupWg.Wait()" above, might introduce deadlocks if an error happens.
	// This is because cancel() will not be called until cleanupWg.Wait() returns.
	// But, the code in server/server.go:GetEventsWG() will only call cleanupWg.Done() if ctx.Done()
	// Which causes a deadlock. To fix this, we add a new ctx and we pass that to the rest of the
	// initialization functions. This means that we can cancel them without causing a deadlock
	// using cancel2.
	ctx, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	hookRunner := rthooks.GlobalRunner().WithWatcher(podAccessor)

	err = setRedactionFilters()
	if err != nil {
		return err
	}

	// Load initial sensor before we start the server,
	// so it's there before we allow to load policies.
	if err = loadInitialSensor(ctx); err != nil {
		return err
	}
	observer.GetSensorManager().LogSensorsAndProbes(ctx)
	defer func() {
		observer.RemoveSensors(ctx)
		os.Remove(observerDir)
	}()

	pm, err := tetragonGrpc.NewProcessManager(
		ctx,
		&cleanupWg,
		observer.GetSensorManager(),
		hookRunner)
	if err != nil {
		return err
	}
	if err = Serve(ctx, option.Config.ServerAddress, pm.Server); err != nil {
		return err
	}
	if option.Config.ExportFilename != "" {
		if err = startExporter(ctx, pm.Server); err != nil {
			return err
		}
	}

	if option.Config.HealthServerAddress != "" {
		health.StartHealthServer(ctx, option.Config.HealthServerAddress, option.Config.HealthServerInterval)
	}

	log.Info("Exporter configuration", "enabled", option.Config.ExportFilename != "", "fileName", option.Config.ExportFilename)
	obs.AddListener(pm)
	saveInitInfo()

	// Initialize a k8s watcher used to manage policies. This should happen
	// after the sensors are loaded, otherwise existing policies will fail to
	// load on the first attempt.
	if option.K8SControlPlaneEnabled() && option.Config.EnableTracingPolicyCRD {
		// add informers for all resources
		log.Info("Enabling policy informers")
		err := crdwatcher.AddTracingPolicyInformer(ctx, controllerManager, observer.GetSensorManager())
		if err != nil {
			return err
		}
	}

	obs.LogPinnedBpf(observerDir)

	if err = procevents.GetRunningProcs(); err != nil {
		return err
	}

	if err := cgrouprate.NewCgroupRate(ctx, pm, &option.Config.CgroupRate); err != nil {
		return err
	}
	cgrouprate.Config()

	err = loadTpFromDir(ctx, option.Config.TracingPolicyDir)
	if err != nil {
		return err
	}

	// load sensor from tracing policy file
	if len(option.Config.TracingPolicy) > 0 {
		err = addTracingPolicy(ctx, option.Config.TracingPolicy)
		if err != nil {
			return err
		}
	}

	deleteOldBpfDir(oldBpfDir)

	// k8s should have metrics, so periodically log only in a non k8s
	if !option.Config.EnableK8s {
		go logStatus(ctx, obs)
	}

	return obs.StartReady(ctx, ready)
}

func loadTpFromDir(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); err != nil {
		// Do not fail if the default directory doesn't exist,
		// it might because of developer setup or incomplete installation
		if os.IsNotExist(err) && dir == defaults.DefaultTpDir {
			log.Info("Loading Tracing Policies from directory ignored, directory does not exist", "tracing-policy-dir", dir)
			return nil
		}
		return fmt.Errorf("failed to access tracing policies dir %s: %w", dir, err)
	}

	tpMaxDepth := 1
	tpFS := os.DirFS(dir)

	err := fs.WalkDir(tpFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator)) >= tpMaxDepth {
				return fs.SkipDir
			}
			return nil
		}

		file := filepath.Join(dir, path)
		st, err := os.Stat(file)
		if err != nil {
			return err
		}

		if !st.Mode().IsRegular() {
			return nil
		}

		return addTracingPolicy(ctx, file)
	})

	return err
}

func addTracingPolicy(ctx context.Context, file string) error {
	f, err := filepath.Abs(filepath.Clean(file))
	if err != nil {
		return err
	}

	tp, err := tracingpolicy.FromFile(f)
	if err != nil {
		return err
	}

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	if err != nil {
		return err
	}

	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().Info("Added TracingPolicy with success",
		"TracingPolicy", file,
		"metadata.namespace", namespace,
		"metadata.name", tp.TpName())

	return nil
}

// Periodically log current status every 24 hours. For lost or error
// events we ratelimit statistics to 1 message per every 1hour and
// only if they increase, to inform users that events are being lost.
func logStatus(ctx context.Context, obs *observer.Observer) {
	prevLost := uint64(0)
	prevErrors := uint64(0)
	lostTicker := time.NewTicker(1 * time.Hour)
	defer lostTicker.Stop()
	logTicker := time.NewTicker(24 * time.Hour)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-logTicker.C:
			// We always print stats
			obs.PrintStats()
			// Update lost and errors
			prevLost = obs.ReadLostEvents()
			prevErrors = obs.ReadErrorEvents()
		case <-lostTicker.C:
			lost := obs.ReadLostEvents()
			errors := obs.ReadErrorEvents()
			if lost > prevLost || errors > prevErrors {
				obs.PrintStats()
				prevLost = lost
				prevErrors = errors
			}
		}
	}
}

// getObserverDir returns the path to the observer directory based on the BPF
// map root. This function relies on the map root to be set properly via
// github.com/cilium/tetragon/pkg/bpf.CheckOrMountFS().
func getObserverDir() string {
	return bpf.MapPrefixPath()
}

func startExporter(ctx context.Context, server *server.Server) error {
	allowList, denyList, err := getExportFilters()
	if err != nil {
		return err
	}
	fieldFilters, err := getFieldFilters()
	if err != nil {
		return err
	}
	writer := &lumberjack.Logger{
		Filename:   option.Config.ExportFilename,
		MaxSize:    option.Config.ExportFileMaxSizeMB,
		MaxBackups: option.Config.ExportFileMaxBackups,
		Compress:   option.Config.ExportFileCompress,
	}

	perms, err := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to parse export file permission '%s', failing back to %v",
			option.KeyExportFilePerm, perms), logfields.Error, err)
	}
	writer.FileMode = perms

	finfo, err := os.Stat(filepath.Clean(option.Config.ExportFilename))
	if err == nil && finfo.IsDir() {
		// Error if exportFilename points to a directory
		return errors.New("passed export JSON logs file point to a directory")
	}
	logFile := filepath.Base(option.Config.ExportFilename)
	logsDir, err := filepath.Abs(filepath.Dir(filepath.Clean(option.Config.ExportFilename)))
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to get absolute path of exported JSON logs '%s'", option.Config.ExportFilename), logfields.Error, err)
		// Do not fail; we let lumberjack handle this. We want to
		// log the rotate logs operation.
		logsDir = filepath.Dir(option.Config.ExportFilename)
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.Info("Periodically rotating JSON export files",
			"directory", logsDir,
			"frequency", option.Config.ExportFileRotationInterval.String())
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log.Info("Rotating JSON logs export", "file", logFile, "directory", logsDir)
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.Warn("Failed to rotate JSON export file", "file", option.Config.ExportFilename, logfields.Error, rotationErr)
					}
				}
			}
		}()
	}

	// Track how many bytes are written to the event export location
	encoderWriter := exporter.NewExportedBytesTotalWriter(writer)
	encoder := encoder.NewProtojsonEncoder(encoderWriter)
	var rateLimiter *ratelimit.RateLimiter
	if option.Config.ExportRateLimit >= 0 {
		rateLimiter = ratelimit.NewRateLimiter(ctx, 1*time.Minute, option.Config.ExportRateLimit, encoder)
	}
	var aggregationOptions *tetragon.AggregationOptions
	if option.Config.EnableExportAggregation {
		aggregationOptions = &tetragon.AggregationOptions{
			WindowSize:        durationpb.New(option.Config.ExportAggregationWindowSize),
			ChannelBufferSize: option.Config.ExportAggregationBufferSize,
		}
	}
	req := tetragon.GetEventsRequest{AllowList: allowList, DenyList: denyList, AggregationOptions: aggregationOptions, FieldFilters: fieldFilters}
	log.Info("Configured field filters", "fieldFilters", fieldFilters)
	log.Info("Starting JSON exporter", "logger", writer, "request", &req)
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	return exporter.Start()
}

func Serve(ctx context.Context, listenAddr string, srv *server.Server) error {
	// we use an empty listen address to effectively disable the gRPC server
	if len(listenAddr) == 0 {
		return nil
	}
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, srv)
	proto, addr, err := server.SplitListenAddr(listenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse listen address: %w", err)
	}
	go func(proto, addr string) {
		var listener net.Listener
		var err error
		if proto == "unix" {
			listener, err = unixlisten.ListenWithRename(addr, 0660)
		} else {
			listener, err = net.Listen(proto, addr)
		}
		if err != nil {
			logger.Fatal(log, "Failed to start gRPC server", "protocol", proto, "address", addr, logfields.Error, err)
		}
		log.Info("Starting gRPC server", "protocol", proto, "address", addr)
		if err = grpcServer.Serve(listener); err != nil {
			log.Error("Failed to close gRPC server", logfields.Error, err)
		}
	}(proto, addr)
	go func(proto, addr string) {
		<-ctx.Done()
		grpcServer.Stop()
		// if proto is unix, ListenWithRename() creates the socket
		// then renames it, so explicitly clean it up.
		if proto == "unix" {
			os.Remove(addr)
		}
	}(proto, addr)
	return nil
}

func startGopsServer() error {
	// Empty means no gops
	if option.Config.GopsAddr == "" {
		return nil
	}

	if err := gops.Listen(gops.Options{
		Addr:                   option.Config.GopsAddr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		return err
	}

	log.Info("Starting gops server", "addr", option.Config.GopsAddr)

	return nil
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "tetragon",
		Short: "Tetragon - eBPF-based Security Observability and Runtime Enforcement",
		Run: func(cmd *cobra.Command, _ []string) {
			if viper.GetBool(option.KeyGenerateDocs) {
				if err := doc.GenYaml(cmd, os.Stdout); err != nil {
					logger.Fatal(log, "Failed to generate docs", logfields.Error, err)
				}
				return
			}

			if err := option.ReadAndSetFlags(); err != nil {
				logger.Fatal(log, "Failed to parse command line flags", logfields.Error, err)
			}
			// Override perf ring buffer choice if only the perf ring is available.
			// NB: can't do this in option.ReadAndSetFlags() as it causes an import cycle.
			// It isn't the prettiest, but it is an important and unique part of Tetragon,
			// so maybe we can live with this.
			if !config.EnableV511Progs() {
				option.Config.UsePerfRingBuffer = true
			}
			if err := startGopsServer(); err != nil {
				logger.Fatal(log, "Failed to start gRPC server", logfields.Error, err)
			}

			if err := tetragonExecute(); err != nil {
				logger.Fatal(log, "Failed to execute tetragon", logfields.Error, err)
			}
		},
	}

	cobra.OnInitialize(func() {
		readConfigSettings(adminTgConfDir, adminTgConfDropIn, packageTgConfDropIns)
	})

	flags := rootCmd.PersistentFlags()
	option.AddFlags(flags)
	viper.BindPFlags(flags)
	return rootCmd.Execute()
}

func servePprof(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprofhttp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprofhttp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprofhttp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprofhttp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprofhttp.Trace)
	return http.ListenAndServe(addr, mux)
}
