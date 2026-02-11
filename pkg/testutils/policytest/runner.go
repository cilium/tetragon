// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	grpc "google.golang.org/grpc"
	grpcCodes "google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	cli "github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type LocalRunner struct {
	conf *Conf
	cli  *cli.ClientWithContext
	info *tetragoninfo.Info
	wg   sync.WaitGroup

	fwdCtlChan chan fwdCtl
}

// NewLocalRunner creates a new local runner
//
// For event testing, the local runner uses three goroutines:
//   - receive (runRecv)
//   - forward (runFwd)
//   - check (runCheck)
//
// receive blocks on the event stream and passes all events to the forward goroutine.
// forward either drops receieved events, or forwards them to the check goroutine
// check runs the EventChecker that is part of the test.
//
// When a new scenario starts, a new check goroutine is created and the forwarder is configured to
// forward events to it.
func NewLocalRunner(
	ctx context.Context,
	log *slog.Logger,
	cnf *Conf,
) (*LocalRunner, error) {
	if cnf.GrpcAddr == "" {
		info, err := bugtool.LoadInitInfo()
		if err == nil {
			cnf.GrpcAddr = info.ServerAddr
		}
		if err != nil {
			// best guess for default
			cnf.GrpcAddr = "localhost:54321"
		}
	}

	cli, err := cli.NewClient(ctx, cnf.GrpcAddr, time.Second*20)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	res, err := cli.Client.GetInfo(ctx, &tetragon.GetInfoRequest{})
	if err != nil {
		cli.Close()
		return nil, fmt.Errorf("failed to retrieve info from agent: %w", err)
	}
	info := tetragoninfo.Decode(res)
	ret := &LocalRunner{
		conf: cnf,
		cli:  cli,
		info: info,
	}

	// start two goroutines to handle Tetragon events:
	//  - receiver: to receive tetragon events from the stream
	req := &tetragon.GetEventsRequest{}
	stream, err := cli.Client.GetEvents(cli.Ctx, req)
	if err != nil {
		ret.Close()
		return nil, fmt.Errorf("GetEvents failed: %w", err)
	}

	ret.fwdCtlChan = make(chan fwdCtl)
	fwdChan := make(chan *tetragon.GetEventsResponse, 128)
	ret.wg.Go(func() {
		runFwd(log, fwdChan, ret.fwdCtlChan)
	})
	ret.wg.Go(func() {
		runRecv(cli.Ctx, log, stream, fwdChan)
	})

	return ret, nil
}

func (r *LocalRunner) Close() {
	if r.cli != nil {
		r.cli.Close()
	}

	if r.fwdCtlChan != nil {
		r.fwdCtlChan <- fwdCtl{cmd: fwdCmdExit}
	}
	r.wg.Wait()
}

func (r *LocalRunner) AddPolicy(l *slog.Logger, test *T) (cleanup func() error, err error) {
	// generate policy
	pol, err := test.Policy(&Conf{
		BinsDir: r.conf.BinsDir,
	})
	if err != nil {
		err = fmt.Errorf("failed to create policy for test %q: %w", test.Name, err)
		return
	}

	// allow for tests that do not have a policy
	if len(pol) == 0 {
		return
	}

	// TODO: no need to parse the full policy here. We just need to verify its kind and get the
	// policy name so that we can delete it when done.
	tp, err := tracingpolicy.FromYAML(string(pol))
	if err != nil {
		err = fmt.Errorf("failed to parse policy for test %q: %w", test.Name, err)
		return
	}
	tpName := tp.TpName()

	_, err = r.cli.Client.AddTracingPolicy(r.cli.Ctx, &tetragon.AddTracingPolicyRequest{
		Yaml: string(pol),
	})
	if err != nil {
		err = fmt.Errorf("failed to load policy for test %q: %w", test.Name, err)
		return
	}
	l.Debug("policy loaded", "name", tpName)

	cleanup = func() error {
		_, err = r.cli.Client.DeleteTracingPolicy(r.cli.Ctx, &tetragon.DeleteTracingPolicyRequest{
			Name:      tpName,
			Namespace: "", // NB: should be filled if/when we support namespaced policies
		})
		if err == nil {
			l.Debug("policy unloaded", "name", tpName)
			return nil
		}
		if grpcStatus.Code(err) != grpcCodes.DeadlineExceeded {
			return fmt.Errorf("failed to unload policy for test %q: %w", test.Name, err)
		}

		// deadline exceeded: let's try to reconnect to unload the policy
		cli, err := cli.NewClient(context.Background(), r.conf.GrpcAddr, time.Second*20)
		if err != nil {
			return fmt.Errorf("failed to create a new client to unload policy: %w", err)
		}
		defer cli.Close()

		_, err = cli.Client.DeleteTracingPolicy(cli.Ctx, &tetragon.DeleteTracingPolicyRequest{
			Name:      tpName,
			Namespace: "", // NB: should be filled if/when we support namespaced policies
		})
		if err != nil {
			return fmt.Errorf("failed to unload policy (after reconnecting): %w", err)
		}
		l.Debug("policy unloaded (after reconnecting)", "name", tpName)
		return nil
	}
	return
}

// RunTest runs a policy test
func (r *LocalRunner) RunTest(l *slog.Logger, test *T) *Result {

	if test.ShouldSkip != nil {
		if reason := test.ShouldSkip(&SkipInfo{r.info}); reason != "" {
			return &Result{Skipped: reason}
		}
	}

	cleanupPolicy, err := r.AddPolicy(l, test)
	if err != nil {
		return &Result{Err: err}
	}

	var res Result
	for _, sc := range test.Scenarios {
		scenario := sc(r.conf)
		scRes := r.RunScenario(l, scenario)
		res.ScenariosRes = append(res.ScenariosRes, scRes)
	}

	err = cleanupPolicy()
	if err != nil {
		res.Err = errors.Join(res.Err, fmt.Errorf("failed to cleanup policy: %w", err))
	}
	return &res
}

func (r *LocalRunner) RunScenario(l *slog.Logger, scenario *Scenario) ScenarioRes {
	// set the scenario timeout to 10s
	// TODO: make it configurable
	ctx, cancel := context.WithTimeout(r.cli.Ctx, time.Second*10)
	defer cancel()

	// start the checker
	resChan := make(chan *tetragon.GetEventsResponse, 128)
	retChan := make(chan checkerRet)
	go runCheck(ctx, l, scenario.EventChecker, resChan, retChan)

	// notify the forwarder to forward events to the checker
	r.fwdCtlChan <- fwdCtl{cmd: fwdCmdSetForward, fwd: resChan}

	// run the trigger
	// NB: using the cli context for now
	triggerErr := scenario.Trigger.Trigger(ctx)
	if triggerErr != nil {
		cancel()
	}

	// wait for the checker to return
	checkerRet := <-retChan
	// notify the forwarder to stop forwarding events to the checker
	r.fwdCtlChan <- fwdCtl{cmd: fwdCmdSetForward, fwd: nil}

	return ScenarioRes{
		Name:       scenario.Name,
		TriggerErr: triggerErr,
		CheckerErr: checkerRet.err,
	}
}

type checkerRet struct {
	err error
}

func runCheck(
	ctx context.Context,
	log *slog.Logger,
	checker ec.MultiEventChecker,
	inChan <-chan *tetragon.GetEventsResponse,
	outChan chan<- checkerRet,
) {

	log = log.With("goroutine", "checker")
	log.Debug("goroutine started")
	count := 0
	matched := 0
	var res *tetragon.GetEventsResponse

	// event checker log is chatty, so only log INFO level if debug is enabled
	checkerLog := slog.New(&eventCheckerLogger{handler: log.Handler()})

loop:
	for {
		select {
		case <-ctx.Done():
			log.Debug("goroutine done (ctx done)", "err", ctx.Err(), "count", count, "matched", matched)
			break loop

		case res = <-inChan:
			count++
		}

		// check event
		done, err := ec.NextResponseCheck(checker, res, checkerLog)
		log.Debug("checker: NextResponseCheck", "err", err, "done", done)
		if err == nil {
			matched++
		}
		if done {
			log.Debug("goroutine done (check done)", "err", ctx.Err(), "count", count, "matched", matched)
			break loop
		}
	}

	outChan <- checkerRet{
		err: checker.FinalCheck(checkerLog),
	}

}

// runRecv: starts the receiver which blocks in the gRPC event stream and forwards them to a
// channel.
func runRecv(
	ctx context.Context,
	log *slog.Logger,
	stream grpc.ServerStreamingClient[tetragon.GetEventsResponse],
	outChan chan<- *tetragon.GetEventsResponse,
) {
	log = log.With("goroutine", "receive")
	log.Debug("goroutine started")

	cnt := 0
	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Debug("runRecv: receive returned error", "err", err, "count", cnt)
			return
		}
		outChan <- msg
		cnt++
		if ctx.Err() != nil {
			log.Debug("runRecv: context returned error", "err", err, "count", cnt)
			return
		}
	}
}

type fwdCmd int

const (
	// exit main loop
	fwdCmdExit = iota
	// set forward
	fwdCmdSetForward
)

type fwdCtl struct {
	cmd fwdCmd
	// fwd is only set if cmd == fwdCmdSetForward
	fwd chan<- *tetragon.GetEventsResponse
}

// runFwd implements the forward goroutine
func runFwd(
	log *slog.Logger,
	inChan <-chan *tetragon.GetEventsResponse,
	ctlChan <-chan fwdCtl,
) {
	log = log.With("goroutine", "forward")
	log.Debug("goroutine started")

	cntDropped := 0
	cntForwaded := 0
	var outChan chan<- *tetragon.GetEventsResponse
	for {
		select {
		case res := <-inChan:
			if outChan != nil {
				outChan <- res
				cntForwaded++
			} else {
				cntDropped++
			}

		case ctl := <-ctlChan:
			switch ctl.cmd {
			case fwdCmdExit:
				log.Debug("exiting", "forwaded", cntForwaded, "droppped", cntDropped)
				return
			case fwdCmdSetForward:
				log.Debug("setting output", "out", ctl.fwd)
				outChan = ctl.fwd
			}
		}
	}
}
