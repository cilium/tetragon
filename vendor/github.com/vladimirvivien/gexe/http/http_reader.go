package http

import (
	"io"
	"net/http"
)

// ResourceReader provides types and methods to read content of resources from a server using HTTP
type ResourceReader struct {
	client *http.Client
	err    error
	url    string
	res    *Response
}

// Get initiates a "GET" operation for the specified resource
func Get(url string) *ResourceReader {
	return &ResourceReader{url: url, client: &http.Client{}}
}

// Err returns the last known error
func (r *ResourceReader) Err() error {
	return r.err
}

// Response returns the server's response info
func (r *ResourceReader) Response() *Response {
	return r.res
}

// Bytes returns the server response as a []byte
func (b *ResourceReader) Bytes() []byte {
	if err := b.Do().Err(); err != nil {
		b.err = err
		return nil
	}
	return b.read()
}

// String returns the server response as a string
func (b *ResourceReader) String() string {
	if err := b.Do().Err(); err != nil {
		b.err = err
		return ""
	}
	return string(b.read())
}

// Body returns an io.ReadCloser to stream the server response.
// NOTE: ensure to close the stream when finished.
func (r *ResourceReader) Body() io.ReadCloser {
	if err := r.Do().Err(); err != nil {
		r.err = err
		return nil
	}
	return r.res.body
}

// Do invokes the client.Get to "GET" the content from server
func (r *ResourceReader) Do() *ResourceReader {
	res, err := r.client.Get(r.url)
	if err != nil {
		r.err = err
		r.res = &Response{}
		return r
	}
	r.res = &Response{stat: res.Status, statCode: res.StatusCode, body: res.Body}
	return r
}

// read reads the content of the response body and returns a []byte
func (r *ResourceReader) read() []byte {
	if r.res.body == nil {
		return nil
	}

	data, err := io.ReadAll(r.res.body)
	defer r.res.body.Close()
	if err != nil {
		r.err = err
		return nil
	}
	return data
}
