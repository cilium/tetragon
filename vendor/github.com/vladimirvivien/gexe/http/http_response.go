package http

import "io"

// Response stores high level metadata and responses from HTTP request results
type Response struct {
	stat     string
	statCode int
	body     io.ReadCloser
}

// Status returns the standard lib http.Response.Status value from the server
func (res *Response) Status() string {
	return res.stat
}

// StatusCode returns the standard lib http.Response.StatusCode value from the server
func (res *Response) StatusCode() int {
	return res.statCode
}

// Body is io.ReadCloser stream to the content from serve.
// NOTE: ensure to call Close() if used directly.
func (res *Response) Body() io.ReadCloser {
	return res.body
}
