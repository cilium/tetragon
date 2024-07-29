// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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

	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/exporter"
	tetragonGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crd"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

var (
	metricsAddr    = "localhost:2112"
	metricsEnabled = false
)

type testObserverOptions struct {
	crd    bool
	config string
	lib    string
}

type testExporterOptions struct {
	watcher   watcher.K8sResourceWatcher
	allowList []*tetragon.Filter
	denyList  []*tetragon.Filter
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

func withK8sWatcher(w watcher.K8sResourceWatcher) TestOption {
	return func(o *TestOptions) {
		o.exporter.watcher = w
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
		if err := bugtool.Bugtool(bugtoolFname, "", ""); err == nil {
			logger.GetLogger().WithField("test", tb.Name()).
				WithField("file", bugtoolFname).Info("Dumped bugtool info")
		} else {
			logger.GetLogger().WithField("test", tb.Name()).
				WithField("file", bugtoolFname).Warnf("Failed to dump bugtool info: %v", err)
		}
	}

	obs.PrintStats()
	obs.Remove()
}

// saveInitInfo saves initial info for subsequent use in bugtool
func saveInitInfo(o *TestOptions, exportFile string) error {
	exportPath, err := filepath.Abs(exportFile)
	if err != nil {
		logger.GetLogger().Warnf("Failed to get export path when saving init info: %v", err)
	}
	btfPath, err := filepath.Abs(btf.GetCachedBTFFile())
	if err != nil {
		logger.GetLogger().Warnf("Failed to get BTF path when saving init info: %v", err)
	}
	libPath, err := filepath.Abs(o.observer.lib)
	if err != nil {
		logger.GetLogger().Warnf("Failed to get lib path when saving init info: %v", err)
	}
	info := bugtool.InitInfo{
		ExportFname: exportPath,
		LibDir:      libPath,
		BtfFname:    btfPath,
		MetricsAddr: metricsAddr,
		ServerAddr:  "",
	}
	return bugtool.SaveInitInfo(&info)
}

// Create a fake K8s watcher to avoid delayed event due to missing pod info
func createFakeWatcher(testPod, testNamespace string) *fakeK8sWatcher {
	return &fakeK8sWatcher{
		fakePod:       testPod,
		fakeNamespace: testNamespace,
	}
}

func newDefaultTestOptions(opts ...TestOption) *TestOptions {
	// default values
	options := &TestOptions{
		observer: testObserverOptions{
			crd:    false,
			config: "",
			lib:    "",
		},
		exporter: testExporterOptions{
			watcher:   watcher.NewFakeK8sWatcher(nil),
			allowList: []*tetragon.Filter{},
			denyList:  []*tetragon.Filter{},
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
	testutils.CaptureLog(tb, logger.GetLogger().(*logrus.Logger))

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

	cgrouprate.Config(base.CgroupRateOptionsMap)

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

	logger.GetLogger().Info("BPF detected features: ", bpf.LogFeatures())

	obs.PerfConfig = bpf.DefaultPerfEventConfig()
	obs.PerfConfig.MapName = filepath.Join(bpf.MapPrefixPath(), "tcpmon_map")
	return obs, nil
}

func GetDefaultObserverWithWatchers(tb testing.TB, ctx context.Context, base *sensors.Sensor, opts ...TestOption) (*observer.Observer, error) {
	const (
		testPod       = "pod-1"
		testNamespace = "ns-1"
	)

	w := createFakeWatcher(testPod, testNamespace)

	opts = append(opts, withK8sWatcher(w))
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

	b := base.GetInitialSensor()
	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetDefaultSensorsWithFile(tb testing.TB, file, lib string, opts ...TestOption) ([]*sensors.Sensor, error) {
	opts = append(opts, WithConfig(file))
	opts = append(opts, WithLib(lib))

	option.Config.BpfDir = bpf.MapPrefixPath()

	testutils.CaptureLog(tb, logger.GetLogger().(*logrus.Logger))

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

	base := base.GetInitialSensor()

	if err = loadSensors(tb, base, sens); err != nil {
		return nil, err
	}

	sens = append(sens, base)
	ret := make([]*sensors.Sensor, 0, len(sens))
	for _, si := range sens {
		if s, ok := si.(*sensors.Sensor); ok {
			ret = append(ret, s)
		}
	}
	return ret, nil
}

func loadExporter(tb testing.TB, ctx context.Context, obs *observer.Observer, opts *testExporterOptions, oo *testObserverOptions) error {
	watcher := opts.watcher
	processCacheSize := 32768
	dataCacheSize := 1024

	if err := obs.InitSensorManager(nil); err != nil {
		return err
	}

	// NB(kkourt): we use the global that was set up by InitSensorManager(). We should clean
	// this up and remove/hide the global variable.
	sensorManager := observer.GetSensorManager()
	tb.Cleanup(func() {
		sensorManager.StopSensorManager(ctx)
		observer.ResetSensorManager()
	})

	if oo.crd {
		crd.WatchTracePolicy(ctx, sensorManager)
	}

	if err := btf.InitCachedBTF(option.Config.HubbleLib, ""); err != nil {
		return err
	}

	if err := process.InitCache(watcher, processCacheSize); err != nil {
		return err
	}

	if err := observer.InitDataCache(dataCacheSize); err != nil {
		return err
	}

	// Tracks when its safe to close application when write ops are comnpleted.
	// We don't currently track work group or contexts correctly in testing infra
	// its not clear if its even useful considering the test infra doesn't get
	// signals from users.
	var cancelWg sync.WaitGroup

	// use an empty hooks runner
	hookRunner := (&rthooks.Runner{}).WithWatcher(watcher)

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

	cgrouprate.NewCgroupRate(ctx, processManager, base.CgroupRateMap, &option.Config.CgroupRate)
	base.ConfigCgroupRate(&option.Config.CgroupRate)
	return nil
}

func loadObserver(tb testing.TB, ctx context.Context, base *sensors.Sensor,
	tp tracingpolicy.TracingPolicy) error {

	if err := base.Load(option.Config.BpfDir); err != nil {
		tb.Fatalf("Load base error: %s\n", err)
	}

	if tp != nil {
		if err := observer.GetSensorManager().AddTracingPolicy(ctx, tp); err != nil {
			tb.Fatalf("SensorManager.AddTracingPolicy error: %s\n", err)
		}
	}

	tb.Cleanup(func() {
		observer.RemoveSensors(ctx)
		base.Unload()
	})
	return nil
}

func loadSensors(tb testing.TB, base sensors.SensorIface, sens []sensors.SensorIface) error {
	if err := base.Load(option.Config.BpfDir); err != nil {
		tb.Fatalf("Load base error: %s\n", err)
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
	for try := uint(0); try < retries+1; try++ {
		cmd := exec.Command("/usr/bin/curl", args...)
		err = cmd.Run()
		if err == nil {
			break
		}
		logger.GetLogger().Warnf("%v failed with %v (attempt %d/%d)", cmd, err, try+1, retries)
	}

	return err
}

// dockerRun starts a new docker container in the background. The container will
// be killed and removed on test cleanup.
// It returns the containerId on success, or an error if spawning the container failed.
func DockerRun(tb testing.TB, args ...string) (containerId string) {
	// note: we are not using `--rm` so we can choose to wait on the container
	// with `docker wait`. We remove it manually below in t.Cleanup instead
	args = append([]string{"run", "--detach"}, args...)
	id, err := exec.Command("docker", args...).Output()
	if err != nil {
		tb.Fatalf("failed to spawn docker container %v: %s", args, err)
	}

	containerId = strings.TrimSpace(string(id))
	tb.Cleanup(func() {
		err := exec.Command("docker", "rm", "--force", containerId).Run()
		if err != nil {
			tb.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	return containerId
}

type fakeK8sWatcher struct {
	fakePod, fakeNamespace string
}

func (f *fakeK8sWatcher) FindPod(podID string) (*corev1.Pod, error) {
	if podID == "" {
		return nil, fmt.Errorf("empty podID")
	}

	return &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      f.fakePod,
			Namespace: f.fakeNamespace,
			UID:       k8stypes.UID(podID),
		},
	}, nil
}

func (f *fakeK8sWatcher) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if containerID == "" {
		return nil, nil, false
	}

	container := corev1.ContainerStatus{
		Name:        containerID,
		Image:       "image",
		ImageID:     "id",
		ContainerID: "docker://" + containerID,
		State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{
				StartedAt: v1.Time{
					Time: time.Unix(1, 2),
				},
			},
		},
	}
	pod := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      f.fakePod,
			Namespace: f.fakeNamespace,
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				container,
			},
		},
	}

	return &pod, &container, true
}

func (f *fakeK8sWatcher) AddInformers(_ watcher.InternalSharedInformerFactory, _ ...*watcher.InternalInformer) {
}

func (f *fakeK8sWatcher) GetInformer(_ string) cache.SharedIndexInformer {
	return nil
}

func (f *fakeK8sWatcher) Start() {}

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
	for i := 0; i < 120; i++ {
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
	if _, err := out.Write([]byte(config)); err != nil {
		return err
	}
	return out.Sync()
}

func GetDefaultObserver(tb testing.TB, ctx context.Context, lib string, opts ...TestOption) (*observer.Observer, error) {
	b := base.GetInitialSensorTest()

	opts = append(opts, WithLib(lib))

	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetDefaultObserverWithConfig(tb testing.TB, ctx context.Context, config, lib string, opts ...TestOption) (*observer.Observer, error) {
	b := base.GetInitialSensor()

	opts = append(opts, WithConfig(config))
	opts = append(opts, WithLib(lib))

	return GetDefaultObserverWithWatchers(tb, ctx, b, opts...)
}

func GetMyPid() uint32 {
	return namespace.GetMyPidG()
}
