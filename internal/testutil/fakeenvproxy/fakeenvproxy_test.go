package fakeenvproxy

import (
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The proxy answers only once every expected request has arrived, each read whole, in the order
// they came.
func TestTheProxyAnswersOnceEveryRequestHasArrived(t *testing.T) {
	var mu sync.Mutex
	var answered int
	p := Start(t, 2, func(c net.Conn) {
		mu.Lock()
		answered++
		n := answered
		mu.Unlock()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"+strconv.Itoa(n))
	})
	bodies := make(chan string, 2)
	get := func() {
		res, err := http.Post("http://"+p.Addr+"/", "text/plain", strings.NewReader("a body"))
		if err != nil {
			t.Error(err)
			bodies <- ""
			return
		}
		b, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		bodies <- string(b)
	}
	go get()
	select {
	case b := <-bodies:
		t.Fatalf("the first request was answered (%q) before the second arrived", b)
	case <-time.After(200 * time.Millisecond):
	}
	go get()
	got := []string{<-bodies, <-bodies}
	slices.Sort(got)
	if !slices.Equal(got, []string{"1", "2"}) {
		t.Fatalf("answers %q; want one each, numbered in turn", got)
	}
}

// Close stops the listener: the requests already read are answered, and a later dial is refused.
func TestCloseAnswersTheRequestsAlreadyHereAndRefusesNewOnes(t *testing.T) {
	answered := make(chan struct{})
	p := Start(t, 2, func(c net.Conn) {
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		close(answered)
	})
	res := make(chan error, 1)
	go func() {
		r, err := http.Get("http://" + p.Addr + "/")
		if err == nil {
			_ = r.Body.Close()
		}
		res <- err
	}()
	time.Sleep(100 * time.Millisecond) // the request is read before Close
	p.Close()
	p.Close() // a second Close is harmless
	if err := <-res; err != nil {
		t.Fatalf("the request already here was not answered: %v", err)
	}
	<-answered
	if c, err := net.Dial("tcp", p.Addr); err == nil {
		_ = c.Close()
		t.Fatal("a dial after Close was accepted")
	}
}

// An answer still holding its connection when the test ends is released, so the proxy finishes
// and the cleanup does not wait out its bound.
func TestTheEndOfTheTestReleasesAnAnswerStillHoldingItsConnection(t *testing.T) {
	var p *Proxy
	start := time.Now()
	t.Run("holder", func(t *testing.T) {
		p = Start(t, 1, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }) // waits until the connection closes
		c, err := net.Dial("tcp", p.Addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		time.Sleep(50 * time.Millisecond) // the request is read and the answer holds the connection
	})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("the cleanup took %v; want the held connection released at once", d)
	}
}
