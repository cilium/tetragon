// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package helpers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/cilium/tetragon/pkg/multiplexer"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers/grpcbridge"
	"github.com/cilium/tetragon/tests/e2e/state"
)

// PortForwardTetragonPods forwards metrics and gops ports for Tetragon pods and
// connects to the gRPC server via a bridge DaemonSet that relays the Unix socket
// to a TCP port using socat.
func PortForwardTetragonPods(testenv env.Environment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
		if !ok {
			return ctx, errors.New("failed to find Tetragon install options. Did the test setup install Tetragon?")
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(opts.Namespace)

		// Deploy the socat bridge DaemonSet that exposes the Tetragon gRPC Unix
		// socket as a TCP service on each node.
		if err := grpcbridge.Deploy(ctx, r, testenv, opts.Namespace); err != nil {
			return ctx, fmt.Errorf("failed to deploy gRPC bridge: %w", err)
		}

		tetragonPods := &corev1.PodList{}
		if err = r.List(
			ctx,
			tetragonPods,
			resources.WithLabelSelector("app.kubernetes.io/name="+opts.DaemonSetName),
		); err != nil {
			return ctx, err
		}

		bridgePods := &corev1.PodList{}
		if err = r.List(
			ctx,
			bridgePods,
			resources.WithLabelSelector("app.kubernetes.io/name="+grpcbridge.DaemonSetName),
		); err != nil {
			return ctx, err
		}

		// TODO: do we need to make this configurable at some point?
		const (
			promPort = 2112
			gopsPort = 8118
		)

		promPorts := make(map[string]int)
		gopsPorts := make(map[string]int)
		for i, pod := range tetragonPods.Items {
			if ctx, err = PortForwardPod(
				testenv,
				&pod,
				nil,
				os.Stderr,
				30,
				time.Second,
				nil,
				fmt.Sprintf("%d:%d", promPort+i, promPort),
				fmt.Sprintf("%d:%d", gopsPort+i, gopsPort),
			)(ctx, cfg); err != nil {
				return ctx, fmt.Errorf("tetragon portforwarding failed: %w", err)
			}
			promPorts[pod.Name] = promPort + i
			gopsPorts[pod.Name] = gopsPort + i
		}

		grpcPorts := make(map[string]int)
		grpcConns := make(map[string]*grpc.ClientConn)
		for i, pod := range bridgePods.Items {
			localPort := grpcbridge.SocatPort + i
			if ctx, err = PortForwardPod(
				testenv,
				&pod,
				nil,
				os.Stderr,
				30,
				time.Second,
				func() error {
					conn, err := multiplexer.ConnectAttempt(ctx, fmt.Sprintf("localhost:%d", localPort))
					if err == nil {
						grpcConns[pod.Name] = conn
					}
					return err
				},
				fmt.Sprintf("%d:%d", localPort, grpcbridge.SocatPort),
			)(ctx, cfg); err != nil {
				return ctx, fmt.Errorf("gRPC bridge portforwarding failed: %w", err)
			}
			grpcPorts[pod.Name] = localPort
		}

		ctx = context.WithValue(ctx, state.GrpcForwardedPorts, grpcPorts)
		ctx = context.WithValue(ctx, state.GrpcForwardedConns, grpcConns)
		ctx = context.WithValue(ctx, state.PromForwardedPorts, promPorts)
		ctx = context.WithValue(ctx, state.GopsForwardedPorts, gopsPorts)
		testenv.Finish(func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			for _, conn := range grpcConns {
				conn.Close()
			}
			return ctx, nil
		})

		klog.InfoS("Successfully forwarded ports for Tetragon pods",
			"promPorts", promPorts, "gopsPorts", gopsPorts, "grpcPorts", grpcPorts)

		return ctx, nil
	}
}

func doPortForward(
	testenv env.Environment,
	restCfg *rest.Config,
	reqURL *url.URL,
	out, outErr *os.File,
	pod *corev1.Pod,
	testFn func() error,
	ports ...string,
) error {
	stopChan := make(chan struct{})
	readyChan := make(chan struct{})
	pfwd, err := newPortForwarder(restCfg, reqURL, out, outErr, stopChan, readyChan, ports)
	if err != nil {
		return fmt.Errorf("failed to create new port forwarder: %w", err)
	}

	go func() {
		err := pfwd.ForwardPorts()
		klog.InfoS("port forward stopped",
			"pod", pod.Name,
			"namespace", pod.Namespace,
			"ports", ports,
			"err", err)
	}()

	<-readyChan
	if testFn != nil {
		err = testFn()
	}

	if err != nil {
		close(stopChan)
	} else {
		testenv.Finish(func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			klog.InfoS("Test ended, stopping portforward",
				"pod", pod.Name,
				"namespace", pod.Namespace,
				"ports", ports)
			close(stopChan)
			return ctx, nil
		})
	}

	return err
}

// PortForwardPod forwards one or more ports to a given pod. Port forwards are
// automatically cleaned up when the test exits. Ports should be specified in the form
// "src:dst" where "src" and "dst" are port numbers.
//
// out and outErr are pointers to os.File that should be used by the portforwarder for its
// stdout and stderr respectively. These can be set to nil to ignore output.
//
// retries and retryBackoff can be used to configure how many times this function should
// retry on failure to set up the port forward and how long it should wait between retries.
func PortForwardPod(
	testenv env.Environment,
	pod *corev1.Pod,
	out, outErr *os.File,
	retries uint,
	retryBackoff time.Duration,
	testFn func() error,
	ports ...string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		restCfg, err := getRestConfig(cfg)
		if err != nil {
			return ctx, err
		}

		restClient, err := rest.RESTClientFor(restCfg)
		if err != nil {
			return ctx, err
		}

		reqUrl := restClient.Post().
			Resource("pods").
			Name(pod.Name).
			Namespace(pod.Namespace).
			SubResource("portforward").
			URL()

		for i := uint(0); ; i++ {
			err = doPortForward(testenv, restCfg, reqUrl, out, outErr, pod, testFn, ports...)
			if err == nil || i == retries {
				return ctx, err
			}
			time.Sleep(retryBackoff)
		}
	}
}

func newPortForwarder(restCfg *rest.Config, reqUrl *url.URL, out, outErr *os.File, stopChan, readyChan chan struct{}, ports []string) (*portforward.PortForwarder, error) {
	transport, upgrader, err := spdy.RoundTripperFor(restCfg)
	if err != nil {
		return nil, err
	}

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, reqUrl)

	return portforward.New(dialer, ports, stopChan, readyChan, out, outErr)
}

func getRestConfig(cfg *envconf.Config) (*rest.Config, error) {
	client, err := cfg.NewClient()
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("error adding to scheme: %w", err)
	}

	restCfg := *client.RESTConfig()
	restCfg.GroupVersion = &schema.GroupVersion{
		Group:   "api",
		Version: "v1",
	}
	restCfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{
		CodecFactory: serializer.NewCodecFactory(scheme),
	}

	return &restCfg, nil
}
