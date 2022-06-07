// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	operatorOption "github.com/cilium/tetragon/operator/option"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	k8sversion "github.com/cilium/tetragon/pkg/k8s/version"
	"github.com/cilium/tetragon/pkg/version"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apiextclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/rest"
)

var (
	binaryName = filepath.Base(os.Args[0])

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, binaryName)

	rootCmd = &cobra.Command{
		Use:   binaryName,
		Short: "Run " + binaryName,
		Run: func(cmd *cobra.Command, args []string) {
			cmdRefDir := viper.GetString(operatorOption.CMDRef)
			if cmdRefDir != "" {
				genMarkdown(cmd, cmdRefDir)
				os.Exit(0)
			}

			initEnv()
			runOperator()
		},
	}
)

func initEnv() {
	// Prepopulate option.Config with options from CLI.
	operatorOption.Config.Populate()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runOperator() {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s configuration")
	}

	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s client")
	}

	k8sAPIExtClient, err := apiextclientset.NewForConfig(restConfig)
	if err != nil {
		log.WithError(err).Fatal("Unable to create k8s API ext. client")
	}

	err = k8sversion.UpdateK8sServerVersion(k8sClient)
	if err != nil {
		log.WithError(err).Fatal("Unable to check k8s version")
	}

	log.Infof("Tetragon Operator: %s", version.Version)
	capabilities := k8sversion.Capabilities()
	if !capabilities.MinimalVersionMet {
		log.Fatalf("Minimal kubernetes version not met: %s < %s",
			k8sversion.Version(), k8sversion.MinimalVersionConstraint)
	}

	// Register the CRDs after validating that we are running on a supported
	// version of K8s.
	if !operatorOption.Config.SkipCRDCreation {
		if err := client.RegisterCRDs(k8sAPIExtClient); err != nil {
			log.WithError(err).Fatal("Unable to register CRDs")
		}
	} else {
		log.Info("Skipping creation of CRDs")
	}

	log.Info("Initialization complete")
}
