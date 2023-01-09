// Copyright 2020 Authors of Cilium
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
	"strings"

	operatorOption "github.com/cilium/tetragon/operator/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	initializeFlags()
}

func initializeFlags() {
	cobra.OnInitialize(func() {
		replacer := strings.NewReplacer("-", "_", ".", "_")
		viper.SetEnvKeyReplacer(replacer)
		viper.SetEnvPrefix(operatorOption.TetragonOpEnvPrefix)
		viper.AutomaticEnv()
	})

	flags := rootCmd.Flags()

	flags.String(operatorOption.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(operatorOption.CMDRef)

	flags.Bool(operatorOption.SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions (CRDs) will not be created")

	flags.String(operatorOption.KubeCfgPath, "", "Kubeconfig filepath to connect to k8s")

	viper.BindPFlags(flags)
}

// Populate sets all options with the values from viper.
func configPopulate() {
	operatorOption.Config.SkipCRDCreation = viper.GetBool(operatorOption.SkipCRDCreation)
	operatorOption.Config.KubeCfgPath = viper.GetString(operatorOption.KubeCfgPath)
}
