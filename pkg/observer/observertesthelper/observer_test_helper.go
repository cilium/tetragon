// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package observertesthelper

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/exporter"
	tetragonGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/procevents"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/watcher"
)

var (
	metricsAddr    = "localhost:2112"
	metricsEnabled = false
)

type testObserverOptions struct {
	config              string
	lib                 string
	procCacheGCInterval time.Duration
}

type testExporterOptions struct {
	podAccessor watcher.PodAccessor
	allowList   []*tetragon.Filter
	denyList    []*tetragon.Filter
}

type TestOptions struct {
	observer testObserverOptions
	exporter testExporterOptions
}

type TestOption func(*TestOptions)

// Filter for the gotest process and its children in the export
func WithMyPid() TestOption {
	return func(o *TestOptions) {
		o.exporter.allowList = append(o.exporter.allowList, &tetragon.Filter{
			PidSet: []uint32{GetMyPid()},
		})
	}
}

// Filter for a container id by prefix in event export
func WithContainerId(id string) TestOption {
	return func(o *TestOptions) {
		o.exporter.allowList = append(o.exporter.allowList, &tetragon.Filter{
			ContainerId: []string{"^" + id},
		})
	}
}

func WithAllowList(allowList *tetragon.Filter) TestOption {
	return func(o *TestOptions) {
		o.exporter.allowList = append(o.exporter.allowList, allowList)
	}
}

func WithDenyList(denyList *tetragon.Filter) TestOption {
	return func(o *TestOptions) {
		o.exporter.denyList = append(o.exporter.denyList, denyList)
	}
}

func WithConfig(config string) TestOption {
	return func(o *TestOptions) {
		o.observer.config = config
	}
}

func WithProcCacheGCInterval(GCInterval time.Duration) TestOption {
	return func(o *TestOptions) {
		o.observer.procCacheGCInterval = GCInterval
	}
}

func WithLib(lib string) TestOption {
	return func(o *TestOptions) {
		o.observer.lib = lib
	}
}

func testDone(tb testing.TB, obs *observer.Observer) {
	if tb.Failed() {
		bugtoolFname := "/tmp/tetragon-bugtool.tar.gz"
		if err := bugtool.Bugtool(bugtoolFname, "", "", nil, nil); err == nil {
			logger.GetLogger().Info("Dumped bugtool info", "test", tb.Name(), "file", bugtoolFname)
		} else {
			logger.GetLogger().Warn("Failed to dump bugtool info", logfields.Error, err, "test", tb.Name(), "file", bugtoolFname)
		}
	}

	obs.PrintStats()
	obs.Remove()
}

// saveInitInfo saves initial info for subsequent use in bugtool
func saveInitInfo(o *TestOptions, exportFile string) error {
	exportPath, err := filepath.Abs(exportFile)
	if err != nil {
		logger.GetLogger().Warn("Failed to get export path when saving init info", logfields.Error, err)
	}
	btfPath, err := filepath.Abs(btf.GetCachedBTFFile())
	if err != nil {
		logger.GetLogger().Warn("Failed to get BTF path when saving init info", logfields.Error, err)
	}
	libPath, err := filepath.Abs(o.observer.lib)
	if err != nil {
		logger.GetLogger().Warn("Failed to get lib path when saving init info", logfields.Error, err)
	}
	info := bugtool.InitInfo{
		ExportFname: exportPath,
		LibDir:      libPath,
		BTFFname:    btfPath,
		MetricsAddr: metricsAddr,
		ServerAddr:  "",
	}
	return bugtool.SaveInitInfo(&info)
}

func newDefaultTestOptions(opts ...TestOption) *TestOptions {
	// default values
	options := &TestOptions{
		observer: testObserverOptions{
			config: "",
			lib:    "",
		},
		exporter: testExporterOptions{
			podAccessor: watcher.NewFakeK8sWatcher(nil),
			allowList:   []*tetragon.Filter{},
			denyList:    []*tetragon.Filter{},
		},
	}
	// apply user options
	for _, opt := range opts {
		opt(options)
	}

	return options
}

func newDefaultObserver() *observer.Observer {
	option.Config.BpfDir = bpf.MapPrefixPath()
	return observer.NewObserver()
}

func getDefaultObserver(tb testing.TB, ctx context.Context, initialSensor *sensors.Sensor, opts ...TestOption) (*observer.Observer, error) {
	testutils.CaptureLog(tb, logger.GetLogger())

	o := newDefaultTestOptions(opts...)

	option.Config.HubbleLib = os.Getenv("TETRAGON_LIB")
	if option.Config.HubbleLib == "" {
		option.Config.HubbleLib = o.observer.lib
	}
	procfs := os.Getenv("TETRAGON_PROCFS")
	if procfs != "" {
		option.Config.ProcFS = procfs
	}

	obs := newDefaultObserver()
	if testing.Verbose() {
		option.Config.Verbosity = 1
	}

	if err := loadExporter(tb, ctx, obs, &o.exporter, &o.observer); err != nil {
		return nil, err
	}

	var tp tracingpolicy.TracingPolicy
	if o.observer.config != "" {
		var err error
		tp, err = tracingpolicy.FromFile(o.observer.config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tracingpolicy: %w", err)
		}
	}

	if err := loadObserver(tb, ctx, initialSensor, tp); err != nil {
		return nil, err
	}

	cgrouprate.Config()

	exportFname, err := testutils.GetExportFilename(tb)
	if err != nil {
		return nil, err
	}
	saveInitInfo(o, exportFname)

	// There doesn't appear to be a better way to enable the metrics server once and only
	// once at the beginning of the observer tests. My initial thought was to use the init
	// function in this file, however that actually ends up interfering with the Tetragon agent
	// since it get compiled into the observer package.
	//
	// This is horrifically ugly, so we may want to figure out a better way to do this
	// at some point in the future. I just don't see a better way that doesn't involve
	// a lot of code changes in a lot of a files.
	if !metricsEnabled {
		go metricsconfig.EnableMetrics(metricsAddr)
		metricsconfig.InitAllMetrics(metricsconfig.GetRegistry())
		metricsEnabled = true
	}

	tb.Cleanup(func() {
		testDone(tb, obs)
	})

	logger.GetLogger().Info("BPF detected features: " + bpf.LogFeatures())

	obs.PerfConfig = bpf.DefaultPerfEventConfig()
	obs.PerfConfig.MapName = filepath.Join(bpf.MapPrefixPath(), "tcpmon_map")
	obs.RingBufMapPath = filepath.Join(bpf.MapPrefixPath(), bpf.RingBufEventsMapName)
	return obs, nil
}

func GetDefaultObserverWithWatchers(tb testing.TB, ctx context.Context, base *sensors.Sensor, opts ...TestOption) (*observer.Observer, error) {
	return getDefaultObserver(tb, ctx, base, opts...)
}

func GetDefaultObserverWithBase(tb testing.TB, ctx context.Context, b *sensors.Sensor, file, lib string, opts ...TestOption) (*observer.Observer, error) {
	opts = append(opts, WithConfig(file))
	opts = append(opts, WithLib(lib))

	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetDefaultObserverWithFile(tb testing.TB, ctx context.Context, file, lib string, opts ...TestOption) (*observer.Observer, error) {
	opts = append(opts, WithConfig(file))
	opts = append(opts, WithLib(lib))

	b := base.GetInitialSensorTest(tb)
	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetDefaultSensorsWithBase(tb testing.TB, b *sensors.Sensor, file, lib string, opts ...TestOption) ([]*sensors.Sensor, error) {
	opts = append(opts, WithConfig(file))
	opts = append(opts, WithLib(lib))

	return getDefaultSensors(tb, b, opts...)
}

func GetDefaultSensorsWithFile(tb testing.TB, file, lib string, opts ...TestOption) ([]*sensors.Sensor, error) {
	opts = append(opts, WithConfig(file))
	opts = append(opts, WithLib(lib))

	b := base.GetInitialSensorTest(tb)
	return getDefaultSensors(tb, b, opts...)
}

func getDefaultSensors(tb testing.TB, initialSensor *sensors.Sensor, opts ...TestOption) ([]*sensors.Sensor, error) {
	option.Config.BpfDir = bpf.MapPrefixPath()

	testutils.CaptureLog(tb, logger.GetLogger())

	o := newDefaultTestOptions(opts...)

	option.Config.HubbleLib = os.Getenv("TETRAGON_LIB")
	if option.Config.HubbleLib == "" {
		option.Config.HubbleLib = o.observer.lib
	}

	procfs := os.Getenv("TETRAGON_PROCFS")
	if procfs != "" {
		option.Config.ProcFS = procfs
	}

	if testing.Verbose() {
		option.Config.Verbosity = 1
	}

	var tp tracingpolicy.TracingPolicy
	var err error

	if o.observer.config != "" {
		tp, err = tracingpolicy.FromFile(o.observer.config)
		if err != nil {
			return nil, fmt.Errorf("failed to parse tracingpolicy: %w", err)
		}
	}

	var sens []sensors.SensorIface

	if tp != nil {
		sens, err = sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
		if err != nil {
			return nil, err
		}
	}

	if err = loadSensors(tb, initialSensor, sens); err != nil {
		return nil, err
	}

	sens = append(sens, initialSensor)
	ret := make([]*sensors.Sensor, 0, len(sens))
	for _, si := range sens {
		if s, ok := si.(*sensors.Sensor); ok {
			ret = append(ret, s)
		}
	}
	return ret, nil
}

func loadExporter(tb testing.TB, ctx context.Context, obs *observer.Observer, opts *testExporterOptions, oo *testObserverOptions) error {
	k8sWatcher := opts.podAccessor
	processCacheSize := 32768
	dataCacheSize := 1024
	procCacheGCInterval := defaults.DefaultProcessCacheGCInterval

	if err := obs.InitSensorManager(); err != nil {
		return err
	}

	// NB(kkourt): we use the global that was set up by InitSensorManager(). We should clean
	// this up and remove/hide the global variable.
	sensorManager := observer.GetSensorManager()
	tb.Cleanup(func() {
		observer.ResetSensorManager()
	})

	if err := btf.InitCachedBTF(option.Config.HubbleLib, ""); err != nil {
		return err
	}

	if oo.procCacheGCInterval > 0 {
		procCacheGCInterval = oo.procCacheGCInterval
	}

	if err := process.InitCache(k8sWatcher, processCacheSize, procCacheGCInterval); err != nil {
		return err
	}

	if err := observer.InitDataCache(dataCacheSize); err != nil {
		return err
	}

	var cancelWg sync.WaitGroup

	// use an empty hooks runner
	hookRunner := (&rthooks.Runner{}).WithWatcher(k8sWatcher)

	// For testing we disable the eventcache and cilium cache by default. If we
	// enable these then every tests would need to wait for the 1.5 mimutes needed
	// to bounce events through the cache waiting for Cilium to reply with endpoints
	// and K8s cache data to be completed. We currently only stub them enough to
	// report nil or a pre-defined value. So no cache needed.
	option.Config.EnableProcessNs = true
	option.Config.EnableProcessCred = true
	processManager, err := tetragonGrpc.NewProcessManager(ctx, &cancelWg, sensorManager, hookRunner)
	if err != nil {
		return err
	}
	tb.Cleanup(func() {
		// wait until the export file is closed. This ensures that ExportFile::Close() is
		// called before the test terminates.
		cancelWg.Wait()
	})
	outF, err := testutils.CreateExportFile(tb)
	if err != nil {
		return err
	}
	encoder := encoder.NewProtojsonEncoder(outF)

	req := tetragon.GetEventsRequest{AllowList: opts.allowList, DenyList: opts.denyList}
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, encoder, outF, nil)
	logger.GetLogger().Info("Starting JSON exporter")
	if err := exporter.Start(); err != nil {
		return err
	}
	obs.AddListener(processManager)
	tb.Cleanup(func() {
		obs.RemoveListener(processManager)
	})

	return cgrouprate.NewCgroupRate(ctx, processManager, &option.Config.CgroupRate)
}

func loadObserver(tb testing.TB, ctx context.Context, base *sensors.Sensor,
	tp tracingpolicy.TracingPolicy) error {

	if err := base.Load(option.Config.BpfDir); err != nil {
		tb.Fatalf("Load base error: %s\n", err)
	}
	tb.Cleanup(func() {
		base.Unload(true)
	})

	if err := procevents.GetRunningProcs(); err != nil {
		return err
	}

	if tp != nil {
		if err := observer.GetSensorManager().AddTracingPolicy(ctx, tp); err != nil {
			tb.Fatalf("SensorManager.AddTracingPolicy error: %s\n", err)
		}
	}

	tb.Cleanup(func() {
		observer.RemoveSensors(ctx)
	})
	return nil
}

func loadSensors(tb testing.TB, base sensors.SensorIface, sens []sensors.SensorIface) error {
	if err := base.Load(option.Config.BpfDir); err != nil {
		tb.Fatalf("Load base error: %s\n", err)
	}

	if err := procevents.GetRunningProcs(); err != nil {
		tb.Fatalf("procevents.GetRunningProcs: %s", err)
	}

	for _, s := range sens {
		if err := s.Load(option.Config.BpfDir); err != nil {
			tb.Fatalf("LoadConfig error: %s\n", err)
		}
	}
	return nil
}

func LoopEvents(ctx context.Context, tb testing.TB, doneWG, readyWG *sync.WaitGroup, obs *observer.Observer) {
	doneWG.Add(1)
	readyWG.Add(1)
	go func() {
		defer doneWG.Done()

		if err := obs.RunEvents(ctx, func() { readyWG.Done() }); err != nil {
			tb.Errorf("runEvents error: %s", err)
		}
	}()
}

func ExecWGCurl(readyWG *sync.WaitGroup, retries uint, args ...string) error {
	readyWG.Wait()

	var err error
	// retries=0 -> 1 try, retries=1 -> 2 tries, and so on...
	for try := range uint(retries + 1) {
		cmd := exec.Command("/usr/bin/curl", args...)
		err = cmd.Run()
		if err == nil {
			break
		}
		logger.GetLogger().Warn(fmt.Sprintf("%v failed with %v (attempt %d/%d)", cmd, err, try+1, retries))
	}

	return err
}

// Used to wait for a process to start, we do a lookup on PROCFS because this
// may be called before obs is created.
func WaitForProcess(process string) error {
	var b []byte
	b = append(b, 0x00)

	procfs := os.Getenv("TETRAGON_PROCFS")
	if procfs == "" {
		procfs = "/proc/"
	}
	procDir, _ := os.ReadDir(procfs)
	for range 120 {
		for _, d := range procDir {

			cmdline, err := os.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			cmdTokens := bytes.Split([]byte(cmdline), b)
			cmd := string(bytes.Join(cmdTokens, []byte(" ")))
			if strings.Contains(cmd, process) {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("process '%s' did not start", process)
}

func WriteConfigFile(fileName, config string) error {
	out, err := os.Create(fileName)
	if err != nil {
		return err
	}
	if _, err := out.WriteString(config); err != nil {
		return err
	}
	return out.Sync()
}

func GetDefaultObserver(tb testing.TB, ctx context.Context, lib string, opts ...TestOption) (*observer.Observer, error) {
	b := base.GetInitialSensorTest(tb)

	opts = append(opts, WithLib(lib))

	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetDefaultObserverWithConfig(tb testing.TB, ctx context.Context, config, lib string, opts ...TestOption) (*observer.Observer, error) {
	b := base.GetInitialSensorTest(tb)

	opts = append(opts, WithConfig(config))
	opts = append(opts, WithLib(lib))

	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetMyPid() uint32 {
	return namespace.GetMyPidG()
}
