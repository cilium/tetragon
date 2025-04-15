// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration

package manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type ManagerTestSuite struct {
	suite.Suite
	testEnv *envtest.Environment
	manager *ControllerManager
}

func (suite *ManagerTestSuite) SetupSuite() {
	useExistingCluster := true
	suite.testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}
	_, err := suite.testEnv.Start()
	assert.NoError(suite.T(), err)
	suite.manager = Get()
	suite.manager.Start(context.Background())
}

func (suite *ManagerTestSuite) TestListNamespaces() {
	// List namespaces.
	namespaces, err := suite.manager.ListNamespaces()
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), namespaces)

	// Call GetNamespace on the first namespace in the list.
	namespace, err := suite.manager.GetNamespace(namespaces[0].Name)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), namespaces[0].Name, namespace.Name)
}

func (suite *ManagerTestSuite) TearDownSuite() {
	assert.NoError(suite.T(), suite.testEnv.Stop())
}

func TestControllerSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}
