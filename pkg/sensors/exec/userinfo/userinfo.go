// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package userinfo

import (
	"errors"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/userdb"
)

// Errors
var (
	ErrNotInHostNs = errors.New("process is not in host namespaces")
)

func getAccountUnix(uid uint32, ns *processapi.MsgNamespaces) (string, error) {
	inHost, err := namespace.IsMsgNsInHostMntUser(ns)
	if err != nil {
		return "", err
	}
	if inHost {
		username, err := userdb.UsersCache.LookupUser(uid)
		if err != nil {
			return "", err
		}
		return username, nil
	}
	return "", ErrNotInHostNs
}

func MsgToExecveAccountUnix(unix *processapi.MsgExecveEventUnix) error {
	if option.Config.UsernameMetadata == int(option.USERNAME_METADATA_UNIX) {
		username, err := getAccountUnix(unix.Process.UID, &unix.Msg.Namespaces)
		if err == nil {
			unix.Process.User.Name = username
			return nil
		}

		if errors.Is(err, ErrNotInHostNs) {
			errormetrics.ErrorTotalInc(errormetrics.ProcessMetadataUsernameIgnoredNotInHost)
		} else {
			errormetrics.ErrorTotalInc(errormetrics.ProcessMetadataUsernameFailed)
		}
		return err
	}
	return nil
}
