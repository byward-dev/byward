// Package fakeupstream is a test HTTP upstream: it records every request it receives (method,
// path, query, headers, body) and echoes the body back, so tests can assert what the proxy
// forwarded.
package fakeupstream

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

// Request is one recorded request.
type Request struct {
	Method, Path, RawQuery, Host string
	Header                       http.Header
	Body                         []byte
	// Trailer is the request's trailer section, as the upstream read it after the body.
	Trailer http.Header
}

// Server is a running fake upstream.
type Server struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Request
	// Handler, if set, answers instead of the echo (after recording).
	Handler http.HandlerFunc
}

// New starts a fake upstream; close it with t.Cleanup(s.Close).
func New() *Server {
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Host: r.Host, Header: r.Header.Clone(), Body: body, Trailer: r.Trailer.Clone()})
	h := s.Handler
	s.mu.Unlock()
	if h != nil {
		h(w, r)
		return
	}
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	_, _ = w.Write(body)
}

// Requests returns a copy of what was received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Last returns the most recent request; it fails the test helper's caller by returning ok=false
// when none arrived.
func (s *Server) Last() (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return Request{}, false
	}
	return s.requests[len(s.requests)-1], true
}
