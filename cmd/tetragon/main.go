// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/checkprocfs"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	tetragonGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/pidfile"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tgsyscall"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/cilium/tetragon/pkg/watcher"
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/cilium/tetragon/pkg/watcher/crd"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logger.GetLogger()
)

func checkStructAlignments() error {
	path := path.Join(option.Config.HubbleLib, "bpf_alignchecker.o")
	return alignchecker.CheckStructAlignments(path)
}

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
		log.WithFields(logrus.Fields{"redactionFilters": redactionFilters}).Info("Configured redaction filters")
	} else {
		log.WithError(err).Error("Error configuring redaction filters")
	}
	return err
}

// Save daemon information so it is used by client cli but
// also by bugtool
func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: option.Config.ExportFilename,
		LibDir:      option.Config.HubbleLib,
		BtfFname:    option.Config.BTF,
		MetricsAddr: option.Config.MetricsServer,
		ServerAddr:  option.Config.ServerAddress,
		GopsAddr:    option.Config.GopsAddr,
		MapDir:      bpf.MapPrefixPath(),
	}
	return bugtool.SaveInitInfo(&info)
}

func stopProfile() {
	if option.Config.MemProfile != "" {
		log.WithField("file", option.Config.MemProfile).Info("Stopping mem profiling")
		f, err := os.Create(option.Config.MemProfile)
		if err != nil {
			log.WithField("file", option.Config.MemProfile).Fatal("Could not create memory profile: ", err)
		}
		defer f.Close()
		// get up-to-date statistics
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
	if option.Config.CpuProfile != "" {
		log.WithField("file", option.Config.CpuProfile).Info("Stopping cpu profiling")
		pprof.StopCPUProfile()
	}
}

func tetragonExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, tgsyscall.SIGRTMIN_20,
		tgsyscall.SIGRTMIN_21, tgsyscall.SIGRTMIN_22)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	if !filepath.IsAbs(option.Config.TracingPolicyDir) {
		log.Fatalf("Failed path specified by --tracing-policy-dir '%q' is not absolute", option.Config.TracingPolicyDir)
	}
	option.Config.TracingPolicyDir = filepath.Clean(option.Config.TracingPolicyDir)

	if option.Config.RBSize != 0 && option.Config.RBSizeTotal != 0 {
		log.Fatalf("Can't specify --rb-size and --rb-size-total together")
	}

	// enable extra programs/maps loading debug output
	if logger.DefaultLogger.IsLevelEnabled(logrus.DebugLevel) {
		program.KeepCollection = true
	}

	log.WithField("version", version.Version).Info("Starting tetragon")
	log.WithField("config", viper.AllSettings()).Info("config settings")

	// Create run dir early
	os.MkdirAll(defaults.DefaultRunDir, 0755)

	// Log early security context in case something fails
	proc.LogCurrentSecurityContext()

	// When an instance terminates or restarts it may cleanup bpf programs,
	// having a check here to see if another instance is already running, can
	// help debug errors.
	pid, err := pidfile.Create()
	if err != nil {
		// Log error but do not fail
		log.WithError(err).WithField("pid", pid).Warn("Tetragon pid file creation failed")
	} else {
		log.WithFields(logrus.Fields{
			"pid":     pid,
			"pidfile": defaults.DefaultPidFile,
		}).Info("Tetragon pid file creation succeeded")
	}
	defer pidfile.Delete()

	log.Info("BPF detected features: ", bpf.LogFeatures())

	if option.Config.ForceLargeProgs && option.Config.ForceSmallProgs {
		log.Fatalf("Can't specify --force-small-progs and --force-large-progs together")
	}

	if option.Config.ForceLargeProgs {
		log.Info("Force loading large programs")
	}

	if option.Config.ForceSmallProgs {
		log.Info("Force loading smallprograms")
	}

	if viper.IsSet(option.KeyNetnsDir) {
		defaults.NetnsDir = viper.GetString(option.KeyNetnsDir)
	}

	if err := checkStructAlignments(); err != nil {
		return fmt.Errorf("struct alignment checks failed: %w", err)
	}

	// Initialize namespaces here. On errors fail, there is
	// no point to continue if read/ptrace on /proc/1/ fails.
	// Providing correct information can't be achieved anyway.
	_, err = namespace.InitHostNamespace()
	if err != nil {
		log.WithField("procfs", option.Config.ProcFS).WithError(err).Fatalf("Failed to initialize host namespaces")
	}

	checkprocfs.Check()

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	if option.Config.PprofAddr != "" {
		go func() {
			if err := servePprof(option.Config.PprofAddr); err != nil {
				log.Warnf("serving pprof via http: %v", err)
			}
		}()
	}

	// Start profilers first as we have to capture them in signal handling
	if option.Config.MemProfile != "" {
		log.WithField("file", option.Config.MemProfile).Info("Starting mem profiling")
	}

	if option.Config.CpuProfile != "" {
		f, err := os.Create(option.Config.CpuProfile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		log.WithField("file", option.Config.CpuProfile).Info("Starting cpu profiling")
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
			log.WithField("bpf-dir", observerDir).WithError(err).Warn("BPF: failed to release pinned BPF programs and maps, Consider removing it manually")
		} else {
			log.WithField("bpf-dir", observerDir).Info("BPF: successfully released pinned BPF programs and maps")
		}
	}

	// Get observer from configFile
	obs := observer.NewObserver()
	defer func() {
		obs.PrintStats()
	}()

	defaultLevel := logger.GetLogLevel()
	go func() {
		for {
			s := <-sigs
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				// if we receive a signal, call cancel so that contexts are finalized, which will
				// leads to normally return from tetragonExecute().
				log.Infof("Received signal %s, shutting down...", s)
				cancel()
				return
			case tgsyscall.SIGRTMIN_20: // SIGRTMIN+20
				currentLevel := logger.GetLogLevel()
				if currentLevel == logrus.DebugLevel {
					log.Infof("Received signal SIGRTMIN+20: LogLevel is already '%s'", currentLevel)
				} else {
					logger.SetLogLevel(logrus.DebugLevel)
					log.Infof("Received signal SIGRTMIN+20: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel())
				}
			case tgsyscall.SIGRTMIN_21: // SIGRTMIN+21
				currentLevel := logger.GetLogLevel()
				if currentLevel == logrus.TraceLevel {
					log.Infof("Received signal SIGRTMIN+21: LogLevel is already '%s'", currentLevel)
				} else {
					logger.SetLogLevel(logrus.TraceLevel)
					log.Infof("Received signal SIGRTMIN+21: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel())
				}
			case tgsyscall.SIGRTMIN_22: // SIGRTMIN+22
				logger.SetLogLevel(defaultLevel)
				log.Infof("Received signal SIGRTMIN+22: resetting original LogLevel '%s'", logger.GetLogLevel())
			}
		}
	}()

	// start sensor manager, and have it wait on sensorMgWait until we load
	// the base sensor. note that this means that calling methods on the
	// manager will block so they will have to either be executed in a
	// goroutine or after we close the sensorMgWait channel to avoid
	// deadlock.
	sensorMgWait := make(chan struct{})
	defer func() {
		// if we fail before closing the channel, close it so that
		// the sensor manager routine is unblocked.
		if sensorMgWait != nil {
			close(sensorMgWait)
		}
	}()
	if err := obs.InitSensorManager(sensorMgWait); err != nil {
		return err
	}

	if err := btf.InitCachedBTF(option.Config.HubbleLib, option.Config.BTF); err != nil {
		return err
	}

	if err := observer.InitDataCache(option.Config.DataCacheSize); err != nil {
		return err
	}

	if option.Config.MetricsServer != "" {
		go metrics.EnableMetrics(option.Config.MetricsServer)
		metricsconfig.InitAllMetrics(metrics.GetRegistry())
		go metrics.StartPodDeleteHandler()
		// Handler must be registered before the watcher is started
		metrics.RegisterPodDeleteHandler()
	}

	// Probe runtime configuration and do not fail on errors
	obs.UpdateRuntimeConf(option.Config.BpfDir)

	var k8sWatcher watcher.K8sResourceWatcher
	if option.Config.EnableK8s {
		log.Info("Enabling Kubernetes API")
		config, err := k8sconf.K8sConfig()
		if err != nil {
			return err
		}

		if err := waitCRDs(config); err != nil {
			return err
		}

		k8sClient := kubernetes.NewForConfigOrDie(config)
		k8sWatcher = watcher.NewK8sWatcher(k8sClient, 60*time.Second)
	} else {
		log.Info("Disabling Kubernetes API")
		k8sWatcher = watcher.NewFakeK8sWatcher(nil)
	}
	k8sWatcher.Start()
	_, err = cilium.InitCiliumState(ctx, option.Config.EnableCilium)
	if err != nil {
		return err
	}

	if err := process.InitCache(k8sWatcher, option.Config.ProcessCacheSize); err != nil {
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

	hookRunner := rthooks.GlobalRunner().WithWatcher(k8sWatcher)

	err = setRedactionFilters()
	if err != nil {
		return err
	}

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

	log.WithField("enabled", option.Config.ExportFilename != "").WithField("fileName", option.Config.ExportFilename).Info("Exporter configuration")
	obs.AddListener(pm)
	saveInitInfo()
	if option.Config.EnableK8s && option.Config.EnableTracingPolicyCRD {
		go crd.WatchTracePolicy(ctx, observer.GetSensorManager())
	}

	obs.LogPinnedBpf(observerDir)

	base.ConfigCgroupRate(&option.Config.CgroupRate)

	// load base sensor
	initialSensor := base.GetInitialSensor()
	if err := initialSensor.Load(observerDir); err != nil {
		return err
	}
	defer func() {
		initialSensor.Unload()
	}()

	cgrouprate.NewCgroupRate(ctx, pm, base.CgroupRateMap, &option.Config.CgroupRate)
	cgrouprate.Config(base.CgroupRateOptionsMap)

	// now that the base sensor was loaded, we can start the sensor manager
	close(sensorMgWait)
	sensorMgWait = nil
	observer.GetSensorManager().LogSensorsAndProbes(ctx)
	defer func() {
		observer.RemoveSensors(ctx)
	}()

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

	// k8s should have metrics, so periodically log only in a non k8s
	if !option.Config.EnableK8s {
		go logStatus(ctx, obs)
	}

	return obs.Start(ctx)
}

func waitCRDs(config *rest.Config) error {
	crds := make(map[string]struct{})

	if option.Config.EnableTracingPolicyCRD {
		crds[v1alpha1.TPName] = struct{}{}
		crds[v1alpha1.TPNamespacedName] = struct{}{}
	}
	if option.Config.EnablePodInfo {
		crds[v1alpha1.PIName] = struct{}{}
	}

	if len(crds) == 0 {
		log.Info("No CRDs are enabled")
		return nil
	}

	log.WithField("crds", crds).Info("Waiting for required CRDs")
	var wg sync.WaitGroup
	wg.Add(1)
	crdClient := apiextensionsclientset.NewForConfigOrDie(config)
	crdInformer := apiextensionsinformer.NewCustomResourceDefinitionInformer(crdClient, 0*time.Second, nil)
	_, err := crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crdObject, ok := obj.(*v1.CustomResourceDefinition)
			if !ok {
				log.WithField("obj", obj).Warn("Received an invalid object")
				return
			}
			if _, ok := crds[crdObject.Name]; ok {
				log.WithField("crd", crdObject.Name).Info("Found CRD")
				delete(crds, crdObject.Name)
				if len(crds) == 0 {
					log.Info("Found all the required CRDs")
					wg.Done()
				}
			}
		},
	})
	if err != nil {
		log.WithError(err).Error("failed to add event handler")
		return err
	}
	stop := make(chan struct{})
	go func() {
		crdInformer.Run(stop)
	}()
	wg.Wait()
	close(stop)
	return nil
}

func loadTpFromDir(ctx context.Context, dir string) error {
	tpMaxDepth := 1
	tpFS := os.DirFS(dir)

	if dir == defaults.DefaultTpDir {
		// If the default directory does not exist then do not fail
		// Probably tetragon not fully installed, developers testing, etc
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.WithField("tracing-policy-dir", dir).Info("Loading Tracing Policies from directory ignored, directory does not exist")
			return nil
		}
	}

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

	logger.GetLogger().WithFields(logrus.Fields{
		"TracingPolicy":      file,
		"metadata.namespace": namespace,
		"metadata.name":      tp.TpName(),
	}).Info("Added TracingPolicy with success")

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
		log.WithError(err).Warnf("Failed to parse export file permission '%s', failing back to %v",
			option.KeyExportFilePerm, perms)
	}
	writer.FileMode = perms

	finfo, err := os.Stat(filepath.Clean(option.Config.ExportFilename))
	if err == nil && finfo.IsDir() {
		// Error if exportFilename points to a directory
		return fmt.Errorf("passed export JSON logs file point to a directory")
	}
	logFile := filepath.Base(option.Config.ExportFilename)
	logsDir, err := filepath.Abs(filepath.Dir(filepath.Clean(option.Config.ExportFilename)))
	if err != nil {
		log.WithError(err).Warnf("Failed to get absolute path of exported JSON logs '%s'", option.Config.ExportFilename)
		// Do not fail; we let lumberjack handle this. We want to
		// log the rotate logs operation.
		logsDir = filepath.Dir(option.Config.ExportFilename)
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.WithFields(logrus.Fields{
			"directory": logsDir,
			"frequency": option.Config.ExportFileRotationInterval.String(),
		}).Info("Periodically rotating JSON export files")
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					log.WithFields(logrus.Fields{
						"file":      logFile,
						"directory": logsDir,
					}).Info("Rotating JSON logs export")
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.WithError(rotationErr).
							WithField("file", option.Config.ExportFilename).
							Warn("Failed to rotate JSON export file")
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
	log.WithFields(logrus.Fields{"fieldFilters": fieldFilters}).Info("Configured field filters")
	log.WithFields(logrus.Fields{"logger": writer, "request": &req}).Info("Starting JSON exporter")
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	return exporter.Start()
}

func Serve(ctx context.Context, listenAddr string, srv *server.Server) error {
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
			log.WithError(err).WithField("protocol", proto).WithField("address", addr).Fatal("Failed to start gRPC server")
		}
		log.WithField("address", addr).WithField("protocol", proto).Info("Starting gRPC server")
		if err = grpcServer.Serve(listener); err != nil {
			log.WithError(err).Error("Failed to close gRPC server")
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

	log.WithField("addr", option.Config.GopsAddr).Info("Starting gops server")

	return nil
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "tetragon",
		Short: "Tetragon - eBPF-based Security Observability and Runtime Enforcement",
		Run: func(cmd *cobra.Command, _ []string) {
			if viper.GetBool(option.KeyGenerateDocs) {
				if err := doc.GenYaml(cmd, os.Stdout); err != nil {
					log.WithError(err).Fatal("Failed to generate docs")
				}
				return
			}

			if err := option.ReadAndSetFlags(); err != nil {
				log.WithError(err).Fatal("Failed to start gops")
			}
			if err := startGopsServer(); err != nil {
				log.WithError(err).Fatal("Failed to start gops")
			}

			if err := tetragonExecute(); err != nil {
				log.WithError(err).Fatal("Failed to start tetragon")
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
