package server

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/logging"
)

// Through the whole chain in front of the relay (here without authentication; mcpsession's own test
// covers its writer), over HTTP/1: an upstream that starts its stream before the MCP client has sent
// all of the request body still gets the rest of it, and the stream reaches the MCP client whole
// (#527). The relay keeps the body flowing with full duplex, which reaches the server's writer only
// if every writer in front of it unwraps to the next; with one that does not, the server holds the
// response to drain a body the MCP client sends only once the stream has started, and the relay
// logs an error.
func TestAStreamTheUpstreamStartsBeforeTheRequestBodyEndsReachesTheMCPClientWholeThroughTheWholeChain(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	bodies := make(chan string, 1)
	go func() { // the upstream: answers on the request's headers, then waits for its whole body
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			bodies <- "no request: " + err.Error()
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n")
		b, err := io.ReadAll(req.Body)
		if err != nil {
			bodies <- "body cut: " + err.Error()
			return
		}
		bodies <- string(b)
		_, _ = io.WriteString(c, "9\r\ndata: 2\n\n\r\n0\r\n\r\n")
	}()
	var logs bytes.Buffer
	s, err := New(loadNoAuthConfig(t, "http://"+ln.Addr().String()+"/mcp"), logging.New(&logs, "json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Public.Handler) // HTTP/1, which closes an unread body unless told not to
	t.Cleanup(srv.Close)
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(c, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body[:10])
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no response before the body ended: %v", err)
	}
	events := bufio.NewReader(res.Body)
	if first, err := events.ReadString('\n'); res.StatusCode != http.StatusOK || first != "data: 1\n" {
		t.Fatalf("status %d, first line %q, error %v; want the stream's first event", res.StatusCode, first, err)
	}
	_, _ = io.WriteString(c, body[10:]) // the rest of the body, once the stream has started
	rest, err := io.ReadAll(events)
	if err != nil || string(rest) != "\ndata: 2\n\n" {
		t.Fatalf("after the first event %q, error %v; want the second event and the stream's end", rest, err)
	}
	if got := <-bodies; got != body {
		t.Fatalf("the upstream got the body %q; want all of it", got)
	}
	srv.Close() // waits for the handler, so the log is complete
	if l := logs.String(); strings.Contains(l, `"level":"WARN"`) || strings.Contains(l, `"level":"ERROR"`) {
		t.Fatalf("log %s; want no warning and no error", l)
	}
}
