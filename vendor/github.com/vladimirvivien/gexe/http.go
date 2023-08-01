package gexe

import "github.com/vladimirvivien/gexe/http"

// Get creates a *http.ResourceReader to read resource content from HTTP server
func (e *Echo) Get(url string) *http.ResourceReader {
	return http.Get(url)
}

// Post creates a *http.ResourceWriter to write content to an HTTP server
func (e *Echo) Post(url string) *http.ResourceWriter {
	return http.Post(url)
}
