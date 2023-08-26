package controller

import (
	"context"
	"fmt"
	"github.com/cilium/tetragon/tetragonpod/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"path/filepath"
	"runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"testing"
)

var (
	cfg     *rest.Config
	ctx     context.Context
	cancel  context.CancelFunc
	testEnv *envtest.Environment
)

// here is the workflow
// - Before suite:
//    - Bootstrap test environment
//    - Add the podInfo kind scheme to the default client-go k8s scheme, to ensure the kind will be used in the controller.
//    - Create a client to perform CRUD operations
//    - Create a manager for installing the controller. It will have a separate client, that interacts with cache. so there are two types of clients.

type ControllerTestSuite struct {
	suite.Suite
	k8sClient client.Client
}

func (suite *ControllerTestSuite) SetupSuite() {
	fmt.Println(">>>>>>> Setting up testing Environment")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,

		// The BinaryAssetsDirectory is only required if you want to run the tests directly
		// without call the makefile target test. If not informed it will look for the
		// default path defined in controller-runtime which is /usr/local/kubebuilder/.
		// Note that you must have the required binaries setup under the bin directory to perform
		// the tests directly. When we run make test it will be setup and used automatically.
		BinaryAssetsDirectory: filepath.Join("..", "bin", "k8s",
			fmt.Sprintf("1.27.1-%s-%s", runtime.GOOS, runtime.GOARCH)),
	}

	var err error
	cfg, err = testEnv.Start()
	assert.NoError(suite.T(), err, "Expected No error while starting Test Environment, but error generated")
	assert.NotNil(suite.T(), cfg, "Expected config file to not be nil, but it is not nil")

	// adding the PodInfo scheme to the client-go k8s scheme

	err = v1alpha1.AddToScheme(scheme.Scheme)
	assert.NoError(suite.T(), err, "Expected No error while adding PodInfo, but Error generated")

	suite.k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	assert.NoError(suite.T(), err, "Expected No error While generating the k8s client, but Error generated")
	assert.NotNil(suite.T(), suite.k8sClient, "Expected k8s client to not be nil, but it is Nil")

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
	})
	assert.NoErrorf(suite.T(), err, "Expected No error while creating a new controller-runtime manager")
	assert.NotNil(suite.T(), k8sManager, "Expected k8s manager to be Not Nil, but it is Nil")

	reconciler := &TetragonPodReconciler{
		k8sManager.GetClient(),
		k8sManager.GetScheme(),
	}

	err = reconciler.SetupWithManager(k8sManager)
	assert.NoError(suite.T(), err, "Expected No error while setting up the PodInfo Reconciler with the k8s manager, but error occurred")

	ctx, cancel = context.WithCancel(context.TODO())
	// starting the controller in a separate Go routine.
	go func() {
		defer manageRecovery()
		err = k8sManager.Start(ctx)
		assert.NoError(suite.T(), err, "Expected No error while starting the k8s manager, but error occurred")
	}()

	fmt.Println("Everything working properly so far")
}

func manageRecovery() {
	if r := recover(); r != nil {
		fmt.Println("Recovered from panic", r)
	}
}

func (suite *ControllerTestSuite) TearDownSuite() {
	fmt.Println(">>>>>>> Tearing down the Test environment")
	cancel()
	err := testEnv.Stop()
	assert.NoError(suite.T(), err, "Expected No error while tearing down test environment, but error occurred")
}

func (suite *ControllerTestSuite) TestPodCreation() {
	fmt.Println("Testing if a pod is being created using the client")
	// get a random Pod.
	pod := randomPodGenerator()
	// create it using the k8s client
	err := suite.k8sClient.Create(context.Background(), pod)
	assert.NoError(suite.T(), err, "Expected No Error while creating a pod using k8s client")

	// fetch the pod using the k8s client.
	fetchedPod := &corev1.Pod{}
	podLookUpKey := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}
	err = suite.k8sClient.Get(context.Background(), podLookUpKey, fetchedPod)
	assert.NoError(suite.T(), err, "Expected No Error while fetching the recently created pod using k8s client")

	// Print the pod.
	// Question: Why the pods don't have a pod IP ?
	printPod(fetchedPod)
}

func TestControllerSuite(t *testing.T) {
	fmt.Println("Starting the test suite")
	suite.Run(t, new(ControllerTestSuite))
}
