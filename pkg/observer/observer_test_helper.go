// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleCilium "github.com/cilium/hubble/pkg/cilium"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/filters"
	tetragonGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crd"

	hubblev1 "github.com/cilium/hubble/pkg/api/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	observerTestDir = "/sys/fs/bpf/testObserver/"
	metricsAddr     = "localhost:2112"
	metricsEnabled  = false
	jsonRetries     = 20
)

const (
	dfltVerbosity = 0
)

type testObserverOptions struct {
	pretty     bool
	crd        bool
	config     string
	lib        string
	notestfail bool
}

type testExporterOptions struct {
	watcher     watcher.K8sResourceWatcher
	ciliumState *hubbleCilium.State
}

type TestOptions struct {
	observer testObserverOptions
	exporter testExporterOptions
}

type TestOption func(*TestOptions)

func withPretty() TestOption {
	return func(o *TestOptions) {
		o.observer.pretty = true
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

func withCiliumState(s *hubbleCilium.State) TestOption {
	return func(o *TestOptions) {
		o.exporter.ciliumState = s
	}
}

func WithLib(lib string) TestOption {
	return func(o *TestOptions) {
		o.observer.lib = lib
	}
}

func withNotestfail(notestfail bool) TestOption {
	return func(o *TestOptions) {
		o.observer.notestfail = notestfail
	}
}

func testDone(t *testing.T, obs *Observer) {
	if t.Failed() {
		bugtoolFname := "/tmp/tetragon-bugtool.tar.gz"
		if err := bugtool.Bugtool(bugtoolFname); err == nil {
			logger.GetLogger().WithField("test", t.Name()).
				WithField("file", bugtoolFname).Info("Dumped bugtool info")
		} else {
			logger.GetLogger().WithField("test", t.Name()).
				WithField("file", bugtoolFname).Warnf("Failed to dump bugtool info: %v", err)
		}
	}

	obs.RemovePrograms()
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

// Create a fake Cilium state to avoid the events getting delayed due to missing pod info
func createFakeCiliumState(testPod, testNamespace string) *hubbleCilium.State {
	s := cilium.GetFakeCiliumState()
	s.GetEndpointsHandler().UpdateEndpoint(&hubbleV1.Endpoint{
		ID:           1234,
		PodName:      testPod,
		PodNamespace: testNamespace,
	})
	return s
}

// Create a fake K8s watcher to avoid delayed event due to missing pod info
func createFakeWatcher(testPod, testNamespace string) *fakeK8sWatcher {
	return &fakeK8sWatcher{
		OnFindPod: func(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
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
					Name:      testPod,
					Namespace: testNamespace,
				},
				Status: corev1.PodStatus{
					ContainerStatuses: []corev1.ContainerStatus{
						container,
					},
				},
			}

			return &pod, &container, true
		},
		OnGetPodInfo: func(containerID, binary, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
			return nil, nil
		},
	}
}

func newDefaultTestOptions(t *testing.T, opts ...TestOption) *TestOptions {
	ciliumState, _ := cilium.InitCiliumState(context.Background(), false)
	// default values
	options := &TestOptions{
		observer: testObserverOptions{
			pretty: false,
			crd:    false,
			config: "",
			lib:    "",
		},
		exporter: testExporterOptions{
			watcher:     watcher.NewFakeK8sWatcher(nil),
			ciliumState: ciliumState,
		},
	}
	// apply user options
	for _, opt := range opts {
		opt(options)
	}

	return options
}

func newDefaultObserver(t *testing.T, oo *testObserverOptions) *Observer {
	return NewObserver(observerTestDir,
		observerTestDir,
		"",
		oo.config)
}

func getDefaultObserver(t *testing.T, opts ...TestOption) (*Observer, error) {
	o := newDefaultTestOptions(t, opts...)

	option.Config.HubbleLib = os.Getenv("TETRAGON_LIB")
	if option.Config.HubbleLib == "" {
		option.Config.HubbleLib = o.observer.lib
	}
	procfs := os.Getenv("TETRAGON_PROCFS")
	if procfs != "" {
		option.Config.ProcFS = procfs
	}

	obs := newDefaultObserver(t, &o.observer)
	if testing.Verbose() {
		option.Config.Verbosity = dfltVerbosity
	}

	loadExporter(t, obs, &o.exporter, &o.observer)
	if err := loadObserver(t, obs, o.observer.notestfail); err != nil {
		return nil, err
	}

	saveInitInfo(o, testutils.GetExportFilename(t))

	// There doesn't appear to be a better way to enable the metrics server once and only
	// once at the beginning of the observer tests. My initial thought was to use the init
	// function in this file, however that actually ends up interfering with the TETRAGON agent
	// since it get compiled into the observer package.
	//
	// This is horrifically ugly, so we may want to figure out a better way to do this
	// at some point in the future. I just don't see a better way that doesn't involve
	// a lot of code changes in a lot of a files.
	if !metricsEnabled {
		go metrics.EnableMetrics(metricsAddr)
		metricsEnabled = true
	}

	t.Cleanup(func() {
		testDone(t, obs)
	})

	obs.perfConfig = bpf.DefaultPerfEventConfig()
	obs.perfConfig.MapName = filepath.Join(observerTestDir, "tcpmon_map")
	return obs, nil
}

func GetDefaultObserverWithWatchers(t *testing.T, opts ...TestOption) (*Observer, error) {
	const (
		testPod       = "pod-1"
		testNamespace = "ns-1"
	)

	w := createFakeWatcher(testPod, testNamespace)
	s := createFakeCiliumState(testPod, testNamespace)

	opts = append(opts, withK8sWatcher(w))
	opts = append(opts, withCiliumState(s))
	return getDefaultObserver(t, opts...)
}

func GetDefaultObserverWithFile(t *testing.T, file, lib string) (*Observer, error) {
	return GetDefaultObserverWithWatchers(t, WithConfig(file), withPretty(), WithLib(lib))
}

func GetDefaultObserverWithFileNoTest(t *testing.T, file, lib string, fail bool) (*Observer, error) {
	return GetDefaultObserverWithWatchers(t, WithConfig(file), withPretty(), WithLib(lib), withNotestfail(fail))
}

func loadExporter(t *testing.T, obs *Observer, opts *testExporterOptions, oo *testObserverOptions) error {
	watcher := opts.watcher
	ciliumState := opts.ciliumState
	processCacheSize := 32768

	if err := obs.InitSensorManager(); err != nil {
		return err
	}

	if oo.crd {
		crd.WatchTracePolicy(context.Background(), SensorManager)
	}

	if err := btf.InitCachedBTF(context.Background(), option.Config.HubbleLib, ""); err != nil {
		return err
	}

	if err := process.InitCache(context.Background(), watcher, false, processCacheSize); err != nil {
		return err
	}

	// For testing we disable the eventcache and cilium cache by default. If we
	// enable these then every tests would need to wait for the 1.5 mimutes needed
	// to bounce events through the cache waiting for Cilium to reply with endpoints
	// and K8s cache data to be completed. We currently only stub them enough to
	// report nil or a pre-defined value. So no cache needed.
	processManager, err := tetragonGrpc.NewProcessManager(ciliumState, SensorManager, true, true, true, false)
	if err != nil {
		return err
	}
	outF := testutils.CreateExportFile(t)
	encoder := json.NewEncoder(outF)

	// temporarily disable the allow list while we fixup TLS events
	// to include parent reference as well
	f := "" //fmt.Sprintf(`{"pid_set":[%d]}`, GetMyPid())
	allowList, err := filters.ParseFilterList(f)
	if err != nil {
		t.Fatalf("observerLoadExporter: %s\n", err)
	}
	denyList, _ := filters.ParseFilterList("")
	req := tetragon.GetEventsRequest{AllowList: allowList, DenyList: denyList}
	exporter := exporter.NewExporter(context.Background(), &req, processManager.Server, encoder, nil)
	logger.GetLogger().Info("Starting JSON exporter")
	exporter.Start()
	obs.AddListener(processManager)
	t.Cleanup(func() {
		obs.RemoveListener(processManager)
	})
	return nil
}

func loadObserver(t *testing.T, obs *Observer, notestfail bool) error {
	if err := sensors.LoadDefault(
		context.TODO(),
		obs.bpfDir,
		obs.mapDir,
		obs.ciliumDir,
		obs.configFile,
	); err != nil {
		if notestfail {
			return err
		}
		t.Fatalf("LoadDefaultSensor error: %s\n", err)
	}

	if err := sensors.LoadConfig(
		context.TODO(),
		obs.bpfDir,
		obs.mapDir,
		obs.ciliumDir,
		obs.configFile,
	); err != nil {
		if notestfail {
			return err
		}
		t.Fatalf("LoadConfig error: %s\n", err)
	}
	return nil
}

func LoopEvents(ctx context.Context, t *testing.T, doneWG, readyWG *sync.WaitGroup, obs *Observer) {
	doneWG.Add(1)
	readyWG.Add(1)
	go func() {
		defer doneWG.Done()

		if err := obs.runEventsNew(ctx, func() { readyWG.Done() }); err != nil {
			t.Errorf("runEvents error: %s", err)
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
func DockerRun(t *testing.T, args ...string) (containerId string) {
	// note: we are not using `--rm` so we can choose to wait on the container
	// with `docker wait`. We remove it manually below in t.Cleanup instead
	args = append([]string{"run", "--detach"}, args...)
	id, err := exec.Command("docker", args...).Output()
	if err != nil {
		t.Fatalf("failed to spawn docker container %v: %s", args, err)
	}

	containerId = strings.TrimSpace(string(id))
	t.Cleanup(func() {
		err := exec.Command("docker", "rm", "--force", containerId).Run()
		if err != nil {
			t.Logf("failed to remove container %s: %s", containerId, err)
		}
	})

	return containerId
}

type fakeK8sWatcher struct {
	OnFindPod    func(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
	OnGetPodInfo func(containerID, binary, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint)
}

func (f *fakeK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if f.OnFindPod == nil {
		panic("FindPod not implemented")
	}
	return f.OnFindPod(containerID)
}

func (f *fakeK8sWatcher) GetPodInfo(containerID, binary, args string, nspid uint32) (*tetragon.Pod, *hubblev1.Endpoint) {
	if f.OnGetPodInfo == nil {
		panic("GetPodInfo not implemented")
	}
	return f.OnGetPodInfo(containerID, binary, args, nspid)
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
	procDir, _ := ioutil.ReadDir(procfs)
	for i := 0; i < 120; i++ {
		for _, d := range procDir {

			cmdline, err := ioutil.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
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

func GetDefaultObserver(t *testing.T, lib string) (*Observer, error) {
	return GetDefaultObserverWithWatchers(t, withPretty(), WithLib(lib))
}

func GetDefaultObserverWithLib(t *testing.T, config, lib string) (*Observer, error) {
	return GetDefaultObserverWithWatchers(t, WithConfig(config), WithLib(lib))
}

func GetMyPid() uint32 {
	return namespace.GetMyPidG()
}
