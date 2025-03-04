// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

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

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/cilium/tetragon/pkg/watcher"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/cilium/tetragon/pkg/sensors/exec"
	_ "github.com/cilium/tetragon/pkg/sensors/tracing"
)

type Arguments struct {
	Trace       string
	Crd         string
	CmdArgs     []string
	Debug       bool
	StoreEvents bool
	PrintEvents bool
	JSONEncode  bool
	Baseline    bool
	RBSize      int
}

func (args *Arguments) String() string {
	return fmt.Sprintf("Trace=%s, Debug=%v, PrintEvents=%v, JSONEncode=%v, Baseline=%v",
		args.Trace, args.Debug, args.PrintEvents, args.JSONEncode, args.Baseline)
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
			option.Config.HubbleLib = defaults.DefaultTetragonLib
		}
	}

	option.Config.RBSize = args.RBSize

	option.Config.BpfDir = bpf.MapPrefixPath()
	obs := observer.NewObserver()

	if err := obs.InitSensorManager(); err != nil {
		logger.GetLogger().Fatalf("InitSensorManager failed: %v", err)
	}

	if err := btf.InitCachedBTF(option.Config.HubbleLib, ""); err != nil {
		log.Fatal(err)
	}

	if err := observer.InitDataCache(1024); err != nil {
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

	tp, err := tracingpolicy.FromFile(configFile)
	if err != nil {
		log.Fatalf("Tracing Policy FromFile: %v", err)
	}

	benchSensors, err := sensors.GetMergedSensorFromParserPolicy(tp)
	if err != nil {
		log.Fatalf("GetMergedSensorFromParserPolicy error: %v", err)
	}

	baseSensors := base.GetInitialSensor()

	if err := baseSensors.Load(option.Config.BpfDir); err != nil {
		log.Fatalf("Load base error: %s\n", err)
	}

	if err := benchSensors.Load(option.Config.BpfDir); err != nil {
		log.Fatalf("Load sensors error: %s\n", err)
	}

	if err := obs.Start(ctx); err != nil {
		log.Fatalf("Starting observer failed: %v", err)
	}

	<-ctx.Done()
	sensors.UnloadSensors([]sensors.SensorIface{benchSensors, baseSensors})
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

func (bl *benchmarkListener) Notify(msg notify.Message) error {
	switch msg.(type) {
	case *readyapi.MsgTetragonReady:
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
	dataCacheSize := 1024

	watcher := watcher.NewFakeK8sWatcher(nil)
	if err := process.InitCache(watcher, processCacheSize, defaults.DefaultProcessCacheGCInterval); err != nil {
		return err
	}

	if err := observer.InitDataCache(dataCacheSize); err != nil {
		return err
	}
	hookRunner := rthooks.GlobalRunner().WithWatcher(watcher)

	processManager, err := grpc.NewProcessManager(
		ctx,
		&wg,
		observer.GetSensorManager(),
		hookRunner)
	if err != nil {
		return err
	}

	var encoder exporter.ExportEncoder
	var writer *lumberjack.Logger

	if summary.Args.StoreEvents {
		writer = &lumberjack.Logger{
			Filename: "output.json",
		}
		encoder = json.NewEncoder(writer)
	} else if summary.Args.PrintEvents {
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
	exporter := exporter.NewExporter(ctx, &req, processManager.Server, &timingEncoder, writer, nil)
	if err := exporter.Start(); err != nil {
		return err
	}
	obs.AddListener(processManager)
	return nil
}
