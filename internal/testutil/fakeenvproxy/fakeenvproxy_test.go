package fakeenvproxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// onRead makes requestRead signal for the rest of t, and returns a wait for the next request read:
// it fails t if none is read within 5 s, as when the request failed before the proxy read it.
func onRead(t *testing.T) func() {
	read := make(chan struct{}, 8)
	saved := requestRead
	requestRead = func() { read <- struct{}{} }
	t.Cleanup(func() { requestRead = saved }) // registered before Start's, so it runs after the proxy has finished
	return func() {
		t.Helper()
		select {
		case <-read:
		case <-time.After(5 * time.Second):
			t.Fatal("the request never reached the proxy")
		}
	}
}

// The proxy answers only once every expected request has arrived, then in the order they came.
func TestTheProxyAnswersOnceEveryRequestHasArrivedInTheOrderTheyCame(t *testing.T) {
	awaitRead := onRead(t)
	var mu sync.Mutex
	var answered int
	p := Start(t, 2, func(c net.Conn) {
		mu.Lock()
		answered++
		n := answered
		mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"+strconv.Itoa(n))
	})
	type answer struct{ client, body string }
	answers := make(chan answer, 2)
	post := func(client string) {
		res, err := http.Post("http://"+p.Addr+"/", "text/plain", strings.NewReader("a body"))
		if err != nil {
			t.Error(err)
			answers <- answer{client, ""}
			return
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		answers <- answer{client, string(b)}
	}
	go post("first")
	awaitRead() // the first request is read: the second comes after it
	select {
	case a := <-answers:
		t.Fatalf("the first request was answered (%q) before the second arrived", a.body)
	case <-time.After(100 * time.Millisecond):
	}
	go post("second")
	got := map[string]string{}
	for range 2 {
		a := <-answers
		got[a.client] = a.body
	}
	if got["first"] != "1" || got["second"] != "2" {
		t.Fatalf("answers %v; want the first request answered first", got)
	}
}

// Each request is read whole, body included, before it is answered: nothing of an 8 MiB body is
// left on the connection, so a reset can only hit the response (#272).
func TestEachRequestIsReadWholeBeforeItIsAnswered(t *testing.T) {
	leftover := make(chan int, 1)
	p := Start(t, 1, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _ := c.Read(make([]byte, 1))
		leftover <- n
		_ = c.SetReadDeadline(time.Time{})
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	res, err := http.Post("http://"+p.Addr+"/", "application/octet-stream", bytes.NewReader(make([]byte, 8<<20)))
	if err != nil {
		t.Fatalf("an 8 MiB request: %v; want it read whole and answered", err)
	}
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil || string(b) != "ok" {
		t.Fatalf("answer %q, %v; want ok", b, err)
	}
	if n := <-leftover; n != 0 {
		t.Fatal("the request body was still on the connection when it was answered")
	}
}

// Close stops the listener: a request already read is answered, and a later dial is refused.
func TestCloseAnswersTheRequestsAlreadyHereAndRefusesNewOnes(t *testing.T) {
	awaitRead := onRead(t)
	p := Start(t, 2, func(c net.Conn) {
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
	})
	res := make(chan error, 1)
	go func() {
		r, err := http.Get("http://" + p.Addr + "/")
		if err == nil {
			_ = r.Body.Close()
		}
		res <- err
	}()
	awaitRead()
	p.Close()
	p.Close() // a second Close is harmless
	if err := <-res; err != nil {
		t.Fatalf("the request already here was not answered: %v", err)
	}
	if c, err := net.Dial("tcp", p.Addr); err == nil {
		_ = c.Close()
		t.Fatal("a dial after Close was accepted")
	}
}

// When the test ends, the proxy is released: a proxy still waiting for requests that never came, and
// an answer still holding its connection, return at once instead of waiting out the bound.
func TestTheEndOfTheTestReleasesTheProxy(t *testing.T) {
	t.Run("waiting for requests that never came", func(t *testing.T) {
		start := time.Now()
		t.Run("proxy", func(t *testing.T) { Start(t, 2, nil) })
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("the cleanup took %v; want the listener closed at once", d)
		}
	})
	t.Run("an answer holding its connection", func(t *testing.T) {
		awaitRead := onRead(t)
		returned := make(chan struct{})
		var client net.Conn
		start := time.Now()
		t.Run("proxy", func(t *testing.T) {
			p := Start(t, 1, func(c net.Conn) {
				defer close(returned)
				_, _ = io.Copy(io.Discard, c) // until the connection closes
				// Still busy a moment after, so only a cleanup that waits for the proxy sees it return.
				time.Sleep(100 * time.Millisecond)
			})
			var err error
			if client, err = net.Dial("tcp", p.Addr); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			awaitRead()
		}) // the client is still open here: only the proxy's own cleanup can release the answer
		if client != nil {
			defer func() { _ = client.Close() }()
		}
		select {
		case <-returned:
		default:
			t.Fatal("the answer still held its connection after the test ended")
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("the cleanup took %v; want the connection released at once", d)
		}
	})
}
