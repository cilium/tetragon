package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// splitListenAddr splits the user-provided address a to a proto and an address field to be used
// with net.Listen.
//
// addresses can be:
//  unix://absolute_path for unix sockets
//  <host>:<port> for TCP (more specifically, an address that can be passed to net.Listen)
//
// Note that the client (tetra) uses https://github.com/grpc/grpc-go/blob/v1.51.0/clientconn.go#L135
// With the syntax is documented in https://github.com/grpc/grpc/blob/master/doc/naming.md. The
// server uses net.Listen. And so the two are not compatible because the client expects "ipv4" or
// "ipv6" for tcp connections.
// Hence, because we want the same string to work the same way both on the client and the server, we
// only support the two addresses above.
func splitListenAddr(arg string) (string, string, error) {

	if strings.HasPrefix(arg, "unix://") {
		path := strings.TrimPrefix(arg, "unix://")
		if !filepath.IsAbs(path) {
			return "", "", fmt.Errorf("path %s (%s) is not absolute", path, arg)
		}
		return "unix", path, nil
	}

	// assume everything else is TCP to support strings such as "localhost:51234" and let
	// net.Listen figure things out.
	return "tcp", arg, nil
}
