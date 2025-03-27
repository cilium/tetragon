// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/multiplexer"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/state"
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
)

// PortForwardTetragonPods forwards gRPC and metrics ports for Tetragon pods.
func PortForwardTetragonPods(testenv env.Environment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
		if !ok {
			return ctx, fmt.Errorf("failed to find Tetragon install options. Did the test setup install Tetragon?")
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(opts.Namespace)

		podList := &corev1.PodList{}
		if err = r.List(
			ctx,
			podList,
			resources.WithLabelSelector(fmt.Sprintf("app.kubernetes.io/name=%s", opts.DaemonSetName)),
		); err != nil {
			return ctx, err
		}

		// TODO: do we need to make this configurable at some point?
		const (
			grpcPort = 54321
			promPort = 2112
			gopsPort = 8118
		)

		grpcPorts := make(map[string]int)
		promPorts := make(map[string]int)
		gopsPorts := make(map[string]int)
		grpcConns := make(map[string]*grpc.ClientConn)
		for i, pod := range podList.Items {
			grpcLocalPort := grpcPort + i
			if ctx, err = PortForwardPod(
				testenv,
				&pod,
				nil,
				os.Stderr,
				30,
				time.Second,
				func() error {
					addr := fmt.Sprintf("localhost:%d", grpcLocalPort)
					conn, err := multiplexer.ConnectAttempt(ctx, addr)
					if err == nil {
						grpcConns[pod.Name] = conn
					}
					return err
				},
				fmt.Sprintf("%d:%d", grpcLocalPort, grpcPort),
				fmt.Sprintf("%d:%d", promPort+i, promPort),
				fmt.Sprintf("%d:%d", gopsPort+i, gopsPort),
			)(ctx, cfg); err != nil {
				return ctx, fmt.Errorf("tetragon portfwarding failed: %w", err)
			}
			grpcPorts[pod.Name] = grpcPort + i
			promPorts[pod.Name] = promPort + i
			gopsPorts[pod.Name] = gopsPort + i
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

		klog.InfoS("Successfully forwarded ports for Tetragon pods", "grpcPorts", grpcPorts, "promPorts", promPorts, "gopsPorts", gopsPorts)

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
