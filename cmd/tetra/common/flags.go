// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

const (
	KeyColor         = "color"          // string
	KeyDebug         = "debug"          // bool
	KeyOutput        = "output"         // string
	KeyTty           = "tty-encode"     // string
	KeyServerAddress = "server-address" // string
	KeyTimeout       = "timeout"        // duration
	KeyRetries       = "retries"        // int
	KeyNamespace     = "namespace"      //string
)

const (
	defaultServerAddress = "localhost:54321"
)

var (
	Debug         bool
	ServerAddress string
	Timeout       time.Duration
	Retries       int
)

func readActiveServerAddressFromFile(fname string) (string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return "", fmt.Errorf("failed to open init info file: %w", err)
	}
	defer f.Close()

	var info struct {
		ServerAddr string `json:"server_address"`
	}
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to decode init info file: %w", err)
	}

	return info.ServerAddr, nil
}

// ResolveServerAdress returns the server address given by the user from the
// command line flag, if not set, try to read from tetragon-info.json, and, if
// the file doesn't exist, returns the default value.
func ResolveServerAddress() string {
	if ServerAddress == "" {
		sa, err := readActiveServerAddressFromFile(defaults.InitInfoFile)

		if err != nil {
			logger.GetLogger().WithError(err).WithField(
				"defaultServerAddress", defaultServerAddress,
			).Debug("failed to resolve server address reading init info file, using default value")
			return defaultServerAddress
		}

		logger.GetLogger().WithFields(logrus.Fields{
			"InitInfoFile":  defaults.InitInfoFile,
			"ServerAddress": sa,
		}).Debug("resolved server address using info file")
		return sa
	}

	return ServerAddress
}
