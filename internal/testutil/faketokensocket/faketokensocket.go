// Package faketokensocket holds Token socket fakes for tests. Dir serves any Token socket test, of
// the real socket or of a scripted one; Scripted and Silent are scripted sockets for tests of the
// client side (the stdio upstream's AskDownstreamToken and `byward downstream-token`).
package faketokensocket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// connWait bounds a scripted socket's own reads and writes on its one connection.
const connWait = 10 * time.Second

// requestSize is the most a scripted socket reads of a request.
const requestSize = 64

// Dir is a temporary directory short enough for a socket path inside it. A test's own t.TempDir()
// on macOS can be longer than a socket path may be there: Go's syscall package refuses a path of
// 104 bytes or more, the size of darwin's sun_path including its NUL, so 103 bytes are usable.
func Dir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// Socket is a listening scripted Token socket.
type Socket struct {
	// Path is the socket's path, in a new Dir.
	Path string
	// Connected is closed once a connection is accepted, before its request is read.
	Connected <-chan struct{}
	// Request receives the first read from that connection, at most 64 bytes, before any answer.
	Request <-chan string
}

// Scripted listens on a Token socket that answers one connection's request with answer, then closes
// the connection.
func Scripted(t testing.TB, answer string) Socket {
	t.Helper()
	return listen(t, func(c net.Conn) { _, _ = c.Write([]byte(answer)) })
}

// Silent listens on a Token socket that reads one connection's request and never answers; it holds
// the connection open until the test ends.
func Silent(t testing.TB) Socket {
	t.Helper()
	ended := make(chan struct{})
	t.Cleanup(func() { close(ended) })
	return listen(t, func(net.Conn) { <-ended })
}

// listen accepts one connection on a new socket, reads its request, then hands it to respond and
// closes it.
func listen(t testing.TB, respond func(net.Conn)) Socket {
	path := filepath.Join(Dir(t), "token.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	connected := make(chan struct{})
	reqs := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		close(connected)
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(connWait))
		b := make([]byte, requestSize)
		n, _ := c.Read(b)
		reqs <- string(b[:n])
		respond(c)
	}()
	return Socket{Path: path, Connected: connected, Request: reqs}
}
