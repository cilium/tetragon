// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package manager

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlManager "sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/watcher/conf"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
)

var (
	initOnce, startOnce sync.Once
	manager             *ControllerManager
	_                   watcher.PodAccessor = (*ControllerManager)(nil)
)

// ControllerManager is responsible for running controller-runtime controllers,
// and interacting with Kubernetes API server in general. If you need to interact
// with Kubernetes API server, this is the place to start.
type ControllerManager struct {
	Manager         ctrlManager.Manager
	deletedPodCache *watcher.DeletedPodCache
	podInformer     cache.SharedIndexInformer
}

func Get() *ControllerManager {
	var err error
	initOnce.Do(func() {
		manager, err = newControllerManager()
		if err != nil {
			panic(err)
		}
	})
	return manager
}

// newControllerManager creates a new controller manager. The enableMetrics flag
// is for unit tests so that we can instantiate multiple ControllerManager instances
// without them trying to bind to the same port 8080.
func newControllerManager() (*ControllerManager, error) {
	ctrl.SetLogger(logger.NewLogrFromSlog(logger.GetLogger()))
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
	cacheOptions := cmCache.Options{
		ByObject: map[client.Object]cmCache.ByObject{
			&corev1.Pod{}: {
				Field: fields.OneTermEqualSelector("spec.nodeName", node.GetNodeName()),
			},
			&corev1.Node{}: {
				Field: fields.SelectorFromSet(fields.Set{"metadata.name": node.GetNodeName()}),
			},
		},
	}
	metricsOptions := metricsserver.Options{BindAddress: "0"}
	controllerOptions := ctrl.Options{Scheme: scheme, Cache: cacheOptions, Metrics: metricsOptions}
	cfg, inCluster, err := conf.K8sConfig()
	if err != nil {
		logger.GetLogger().Warn("Unable to get Kubernetes config, using default controller-runtime config", logfields.Error, err)
		cfg = ctrl.GetConfigOrDie()
		inCluster = true
	}
	// Try to initialize the controller manager with retries
	manager, err := newControllerManagerWithRetry(cfg, controllerOptions)
	if err != nil {
		return nil, err
	}
	if inCluster {
		err = manager.addPodInformer()
		if err != nil {
			return nil, err
		}
	}
	return manager, nil
}

func (cm *ControllerManager) Start(ctx context.Context) {
	startOnce.Do(func() {
		go func() {
			if err := cm.Manager.Start(ctx); err != nil {
				panic(err)
			}
		}()
		cm.Manager.GetCache().WaitForCacheSync(ctx)
	})
}

func (cm *ControllerManager) GetNamespace(name string) (*corev1.Namespace, error) {
	ns := corev1.Namespace{}
	if err := cm.Manager.GetCache().Get(context.Background(), types.NamespacedName{Name: name}, &ns); err != nil {
		return nil, err
	}
	return &ns, nil
}

func (cm *ControllerManager) GetNode() (*corev1.Node, error) {
	k8sNode := corev1.Node{}
	if err := cm.Manager.GetCache().Get(context.Background(), types.NamespacedName{Name: node.GetNodeName()}, &k8sNode); err != nil {
		return nil, err
	}
	return &k8sNode, nil
}

func (cm *ControllerManager) ListNamespaces() ([]corev1.Namespace, error) {
	namespaceList := corev1.NamespaceList{}
	if err := cm.Manager.GetCache().List(context.Background(), &namespaceList, &client.ListOptions{}); err != nil {
		return nil, err
	}
	return namespaceList.Items, nil
}

func (cm *ControllerManager) WaitCRDs(ctx context.Context, crds map[string]struct{}) error {
	log := logger.GetLogger()
	log.Info("Waiting for required CRDs", "crds", crds)
	var wg sync.WaitGroup
	wg.Add(1)
	crdInformer, err := cm.Manager.GetCache().GetInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		return err
	}
	_, err = crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crdObject, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				log.Warn("Received an invalid object", "obj", obj)
				return
			}
			if _, ok := crds[crdObject.Name]; ok {
				log.Info("Found CRD", "crd", crdObject.Name)
				delete(crds, crdObject.Name)
				if len(crds) == 0 {
					log.Info("Found all the required CRDs")
					wg.Done()
				}
			}
		},
	})
	if err != nil {
		log.Error("failed to add event handler", logfields.Error, err)
		return err
	}
	wg.Wait()
	err = cm.Manager.GetCache().RemoveInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		log.Warn("failed to remove CRD informer", logfields.Error, err)
	}
	return nil
}

func (cm *ControllerManager) addPodInformer() error {
	// initialize deleted pod cache
	var err error
	deletedPodCache, err := watcher.NewDeletedPodCache()
	if err != nil {
		return fmt.Errorf("failed to initialize deleted pod cache: %w", err)
	}
	cm.deletedPodCache = deletedPodCache

	// Initialize a pod informer.
	podInformer, err := cm.Manager.GetCache().GetInformer(context.Background(), &corev1.Pod{})
	if err != nil {
		return err
	}
	cm.podInformer = podInformer.(cache.SharedIndexInformer)
	err = cm.podInformer.AddIndexers(cache.Indexers{
		watcher.ContainerIdx: watcher.ContainerIndexFunc,
		watcher.PodIdx:       watcher.PodIndexFunc,
	})
	if err != nil {
		return err
	}
	// add event handlers to the informer
	_, err = cm.podInformer.AddEventHandler(cm.deletedPodCache.EventHandler())
	if err != nil {
		return nil
	}
	podhooks.InstallHooks(cm.podInformer)
	return nil
}

func (cm *ControllerManager) FindContainer(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return watcher.FindContainer(containerID, cm.podInformer, cm.deletedPodCache)
}

func (cm *ControllerManager) FindPod(podID string) (*corev1.Pod, error) {
	return watcher.FindPod(podID, cm.podInformer)
}

func (cm *ControllerManager) FindMirrorPod(hash string) (*corev1.Pod, error) {
	return watcher.FindMirrorPod(hash, cm.podInformer)
}

// newControllerManagerWithRetry attempts to create a new ControllerManager instance with retry logic.
// It uses the provided Kubernetes REST config and controller options. The number of retry attempts is
// determined by conf.K8sConfigRetry(): a negative value means infinite retries, zero is invalid, and
// a positive value specifies the maximum number of retries. The function applies exponential backoff
// between retries. If the ControllerManager is created successfully, it returns the instance; otherwise,
// it returns an error after exhausting all retries or encountering a fatal error.
//
// Parameters:
//   - cfg: Kubernetes REST configuration.
//   - controllerOptions: Options for the controller manager.
//
// Returns:
//   - *ControllerManager: The created controller manager instance, or nil on failure.
//   - error: An error if the controller manager could not be created or api_server connectivity failed.
func newControllerManagerWithRetry(cfg *rest.Config, controllerOptions ctrl.Options) (cm *ControllerManager, err error) {

	retryCount := conf.K8sConfigRetry()
	if retryCount < 0 {
		// max int32 retries, until connection succeeds.
		logger.GetLogger().Info("setting retryCount to max int32 retries")
		retryCount = math.MaxInt32
	} else if retryCount == 0 {
		// 1 means no retries, just one connection attempt.
		logger.GetLogger().Info("retryCount is zero, which is invalid. Defaulting to 1")
		retryCount = 1
	}

	var (
		attempts  = 0
		startTime = time.Now()
	)

	defaultRetry := retry.DefaultRetry
	// Create a copy of the default retry with modified steps.
	// This is to ensure that we do not modify the global default retry.
	// We only want to change the number of steps (i.e., retries).
	localRetry := defaultRetry
	localRetry.Steps = retryCount

	defaultBackoff := retry.DefaultBackoff
	// localBackoff is a copy of backoff for retries.
	localBackoff := defaultBackoff
	localBackoff.Steps = localRetry.Steps - 1
	logger.GetLogger().Debug("Using local retry and backoff settings",
		"retrySteps", localRetry.Steps,
		"backoffSteps", localBackoff.Steps,
		"backoffDuration", localBackoff.Duration)

	// Rate limiter for API server connection warnings
	var lastAPILogTime time.Time
	const apiLogInterval = 30 * time.Second

	err = retry.OnError(
		localRetry,
		func(_ error) bool { return true },
		func() error {
			attempts++
			mgr, mgrErr := ctrl.NewManager(cfg, controllerOptions)
			if mgrErr != nil {
				now := time.Now()
				if now.Sub(lastAPILogTime) > apiLogInterval {
					logger.GetLogger().Warn("failed to create controller manager",
						logfields.Error, mgrErr,
						"attempt", attempts)
					lastAPILogTime = now
				}
				// retry upon error
				return mgrErr
			}
			cm = &ControllerManager{
				Manager: mgr,
			}
			// success
			return nil
		},
	)

	duration := time.Since(startTime)
	if err != nil {
		logger.GetLogger().Error("failed to create controller manager", logfields.Error, err,
			"attempts", attempts, "duration", duration.String(), "retryCount", retryCount)
		return nil, err
	}
	logger.GetLogger().Info("created controller manager", "attempts", attempts,
		"duration", duration.String())
	return cm, nil
}
