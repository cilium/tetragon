// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/watcher"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	_ "github.com/cilium/tetragon/pkg/sensors/base"
	_ "github.com/cilium/tetragon/pkg/sensors/config"
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
	_ "github.com/cilium/tetragon/pkg/sensors/program"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
	_ "github.com/cilium/tetragon/pkg/sensors/unloader"
)

type Arguments struct {
	Trace       string
	Debug       bool
	PrintEvents bool
	JSONEncode  bool
	Baseline    bool
	GoPerf      bool
}

func readConfig(file string) (*config.GenericTracingConf, error) {
	if file == "" {
		return nil, nil
	}

	yamlData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", file, err)
	}
	cnf, err := config.ReadConfigYaml(string(yamlData))
	if err != nil {
		return nil, err
	}

	return cnf, nil
}

func (args *Arguments) String() string {
	return fmt.Sprintf("")
}

func runTetragon(ctx context.Context, configFile string, args *Arguments, summary *Summary, ready chan bool) {
	bpf.ConfigureResourceLimits()
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	if args.Debug {
		option.Config.Verbosity = 5
	}

	if _, err := os.Stat("../../bpf/objs"); err == nil {
		option.Config.HubbleLib = "../../bpf/objs"
	} else {
		exePath, err := os.Executable()
		if err != nil {
			log.Fatal(err)
		}
		option.Config.HubbleLib = path.Join(path.Dir(exePath), "bpf/objs")

		if _, err := os.Stat(option.Config.HubbleLib); err != nil {
			// Running outside the source tree, fall back to default location.
			option.Config.HubbleLib = "/var/lib/hubble-fgs"
		}
	}

	option.Config.BpfDir = bpf.MapPrefixPath()
	option.Config.MapDir = bpf.MapPrefixPath()
	obs := observer.NewObserver(configFile)

	if err := obs.InitSensorManager(); err != nil {
		logger.GetLogger().Fatalf("InitSensorManager failed: %v", err)
	}

	if err := btf.InitCachedBTF(ctx, option.Config.HubbleLib, ""); err != nil {
		log.Fatal(err)
	}

	listener := &benchmarkListener{
		ctx:      ctx,
		observer: obs,
		ready:    ready,
	}
	obs.AddListener(listener)

	if args.JSONEncode {
		if err := startBenchmarkExporter(ctx, obs, summary); err != nil {
			log.Fatalf("Starting exporter failed: %v", err)
		}
	}

	cnf, err := readConfig(configFile)
	if err != nil {
		log.Fatalf("readConfig error: %v", err)
	}
	startSensors, err := sensors.GetSensorsFromParserPolicy(&cnf.Spec)
	if err != nil {
		log.Fatalf("GetSensorsFromParserPolicy error: %v", err)
	}
	startSensors = append(startSensors, base.GetInitialSensor())

	if err := obs.Start(ctx, startSensors); err != nil {
		log.Fatalf("Starting tetragon failed: %v", err)
	}

	<-ctx.Done()
	obs.RemovePrograms()
}

func sigHandler(ctx context.Context, cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		close(sigs)
		return
	case sig := <-sigs:
		log.Printf("Signal '%s' received, stopping...\n", sig)
		cancel()
		return
	}
}

type benchmarkListener struct {
	ready    chan bool
	ctx      context.Context
	observer *observer.Observer
}

func (bl *benchmarkListener) Notify(msg notify.Interface) error {
	switch msg.(type) {
	case *readyapi.MsgTETRAGONReady:
		bl.ready <- true
	}

	return nil
}

func (bl *benchmarkListener) Close() error {
	return nil
}

type timingEncoder struct {
	totalDuration uint64
	inner         exporter.ExportEncoder
}

func (te *timingEncoder) Encode(v interface{}) error {
	t0 := time.Now()
	err := te.inner.Encode(v)
	atomic.AddUint64(&te.totalDuration, uint64(time.Since(t0)))
	return err
}

type CountingDiscardWriter struct {
	nbytes  int64
	nwrites int64
}

func (cw *CountingDiscardWriter) Write(p []byte) (n int, err error) {
	cw.nbytes += int64(len(p))
	cw.nwrites++
	return len(p), nil
}

func (cw *CountingDiscardWriter) String() string {
	return fmt.Sprintf("bytes=%v, writes=%v", cw.nbytes, cw.nwrites)
}

func startBenchmarkExporter(ctx context.Context, obs *observer.Observer, summary *Summary) error {
	var wg sync.WaitGroup

	processCacheSize := 32768
	enableCiliumAPI := false

	if _, err := cilium.InitCiliumState(ctx, enableCiliumAPI); err != nil {
		return err
	}
	if err := process.InitCache(ctx, watcher.NewFakeK8sWatcher(nil), enableCiliumAPI, processCacheSize); err != nil {
		return err
	}

	processManager, err := grpc.NewProcessManager(
		ctx,
		&wg,
		cilium.GetFakeCiliumState(),
		observer.SensorManager)
	if err != nil {
		return err
	}

	var encoder exporter.ExportEncoder
	if summary.Args.PrintEvents {
		encoder = json.NewEncoder(os.Stdout)
	} else {
		encoder = json.NewEncoder(&summary.ExportStats)
	}

	timingEncoder := timingEncoder{inner: encoder}
	go func() {
		// FIXME I'm racy, someone might read summary before this is written.
		// Likely not an issue since we wait for slower things to exit.
		<-ctx.Done()
		summary.JSONEncodingDurationNanos = time.Duration(timingEncoder.totalDuration)
	}()

	req := tetragon.GetEventsRequest{AllowList: nil, DenyList: nil, AggregationOptions: nil}
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, &timingEncoder, nil, nil)
	exporter.Start()
	obs.AddListener(processManager)
	return nil
}
