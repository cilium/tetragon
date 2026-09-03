// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

type getURLRoundTripper struct {
	body   io.ReadCloser
	called bool
}

func (r *getURLRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.called = true
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       r.body,
		Header:     make(http.Header),
	}, nil
}

func TestGetURLClosesResponseBody(t *testing.T) {
	body := &closeTrackingBody{Reader: strings.NewReader("canary response")}
	transport := &getURLRoundTripper{body: body}
	oldTransport := http.DefaultClient.Transport
	http.DefaultClient.Transport = transport
	t.Cleanup(func() { http.DefaultClient.Transport = oldTransport })

	getUrl("http://canary.example")
	require.True(t, transport.called)
	require.True(t, body.closed)
}
