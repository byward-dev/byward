// Package fakeenvproxy is a stand-in environment proxy for tests: a loopback listener that reads
// each request whole, then answers byte for byte, so a test can end a response as a misbehaving
// proxy does. With no proxy setting, it stands in for the upstream the same way.
package fakeenvproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// Proxy is a running fake environment proxy.
type Proxy struct {
	// Addr is the host:port it listens on.
	Addr string
	stop func()
}

// Close stops it listening; the requests already read are still answered. It is safe to call more
// than once and from any goroutine.
func (p *Proxy) Close() { p.stop() }

// Start listens on loopback for requests connections. It reads each request whole, body included,
// so a reset can only hit the response (#272). Once all have arrived, or the listener closed first,
// it calls answer with each connection in turn and then closes it; a nil answer closes it unanswered.
//
// When t ends, the listener and every connection are closed, and t fails if the proxy has not
// finished within 5 s.
func Start(t testing.TB, requests int, answer func(net.Conn)) *Proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	var ended bool // the test has ended: a connection accepted from now on is closed at once
	done := make(chan struct{})
	go func() {
		defer close(done)
		var arrived []net.Conn
		for len(arrived) < requests {
			c, err := ln.Accept()
			if err != nil {
				break // answer the requests already here
			}
			mu.Lock()
			if ended {
				mu.Unlock()
				_ = c.Close()
				break
			}
			conns = append(conns, c)
			mu.Unlock()
			if req, err := http.ReadRequest(bufio.NewReader(c)); err == nil {
				_, _ = io.Copy(io.Discard, req.Body)
			}
			requestRead()
			arrived = append(arrived, c)
		}
		for _, c := range arrived {
			if answer != nil {
				answer(c)
			}
			_ = c.Close()
		}
	}()
	p := &Proxy{Addr: ln.Addr().String(), stop: sync.OnceFunc(func() { _ = ln.Close() })}
	t.Cleanup(func() {
		p.Close()
		mu.Lock()
		ended = true
		for _, c := range conns {
			_ = c.Close() // an answer still waiting on its connection returns
		}
		mu.Unlock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the fake environment proxy never finished")
		}
	})
	return p
}

// requestRead is called after each request is read; a test of this package waits on it.
var requestRead = func() {}

// Reset closes c with a TCP reset, so the peer's read error names both addresses.
func Reset(c net.Conn) {
	_ = c.(*net.TCPConn).SetLinger(0)
	_ = c.Close()
}
