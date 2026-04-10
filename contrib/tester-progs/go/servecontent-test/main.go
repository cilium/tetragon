// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"time"
)

const port = 18765

func main() {
	// Use a path from argv so the test can verify we capture it
	name := "default.txt"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}

	content := bytes.NewReader([]byte("test"))
	modtime := time.Now()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Calls ServeContent(w, r, name, modtime, content)
		http.ServeContent(w, r, name, modtime, content)
	})

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler}
	go srv.ListenAndServe()
	// Give server time to bind
	time.Sleep(100 * time.Millisecond)

	// Trigger our own request so ServeContent is called
	go func() {
		http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	}()

	// Wait for request to complete then exit
	time.Sleep(2 * time.Second)
}
