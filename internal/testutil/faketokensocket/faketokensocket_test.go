package faketokensocket

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// wait bounds every wait on a socket, so a hang fails the test instead of the run.
const wait = 10 * time.Second

// dial connects to s and fails the test once Connected has not closed within wait.
func dial(t *testing.T, s Socket) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", s.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(wait))
	select {
	case <-s.Connected:
	case <-time.After(wait):
		t.Fatal("Connected did not close on connect")
	}
	return c
}

// ask sends req on c and fails the test unless s's Request receives exactly req.
func ask(t *testing.T, s Socket, c net.Conn, req string) {
	t.Helper()
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-s.Request:
		if got != req {
			t.Fatalf("Request %q, want %q", got, req)
		}
	case <-time.After(wait):
		t.Fatal("Request received nothing")
	}
}

// Connected stays open until a client connects.
func TestConnectedIsOpenBeforeAConnection(t *testing.T) {
	s := Scripted(t, "answer\n")
	select {
	case <-s.Connected:
		t.Fatal("Connected closed with no connection")
	default:
	}
}

// A scripted socket hands over the request, writes its answer and closes the connection.
func TestScriptedAnswersTheRequest(t *testing.T) {
	s := Scripted(t, `{"access_token":"tok"}`+"\n")
	c := dial(t, s)
	ask(t, s, c, "GET\n")
	got, err := io.ReadAll(c)
	if err != nil || string(got) != `{"access_token":"tok"}`+"\n" {
		t.Fatalf("answer %q, %v; want the scripted answer, then end of file", got, err)
	}
}

// A silent socket hands over the request and never answers, holding the connection open.
func TestSilentNeverAnswers(t *testing.T) {
	s := Silent(t)
	c := dial(t, s)
	ask(t, s, c, "GET\n")
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read %d bytes, %v; want no answer and the connection still open", n, err)
	}
}
