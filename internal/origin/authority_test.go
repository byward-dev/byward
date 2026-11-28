package origin

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Over HTTP/2 a client chooses the host the public Host check reads: Go's server takes :authority
// as r.Host with no host check (net/http/internal/http2 runs only ValidHeaderFieldValue on it, and
// refuses an "@"), where HTTP/1.1 answers 400 to a Host with any byte outside the ASCII host bytes
// (net/http/server.go, httpguts.ValidHostHeader). So each value below reaches the check as sent, and
// the check refuses every one but the Kelvin sign's spelling of a listed host, which strings.ToLower
// folds onto it (#656). That is kept: the check stops browsers, and a browser maps U+212A to k
// (UTS #46) before it sends a host, while any other client can send the listed host itself. The two
// values Go refuses are pinned too, so a Go version that checks :authority differently fails here
// by name.
func TestAnHTTP2AuthorityReachesThePublicHostCheckAsSent(t *testing.T) {
	for _, tc := range []struct {
		authority string
		want      string // the status the check answers, or the stream error Go answers before it
	}{
		{"xn--bcher-Kva.example", "204"},
		{"evİl.example", "421"},
		{"localhoſt", "421"},
		{"faſſ.example", "421"},
		{"0\xb6\xb6.example", "421"},
		{"mcp.example.com\xff", "421"},
		{"mcp\xc0\xaeexample.com", "421"},
		{"a\xc3.example", "421"},
		{"a b", "421"},
		{"a\tb", "421"},
		{"a/b", "421"},
		{"[::1%eth0]", "421"},
		{"[::1%eth0]:8080", "421"},
		{"a\x7fb", "PROTOCOL_ERROR"},
		{"u@mcp.example.com", "PROTOCOL_ERROR"},
	} {
		t.Run(strconv.Quote(tc.authority), func(t *testing.T) {
			hosts := make(chan string, 2) // the Host of each request that reached the handler
			rec, _ := recording()
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hosts <- r.Host
				Hosts(rec, decisionHosts, ok).ServeHTTP(w, r)
			}))
			srv.EnableHTTP2 = true
			srv.StartTLS()
			got := answerOverHTTP2(t, srv.Listener.Addr().String(), tc.authority)
			srv.Close() // waits for the handler, so hosts holds every request that reached it
			close(hosts)
			var reached []string
			for h := range hosts {
				reached = append(reached, h)
			}
			if got != tc.want {
				t.Errorf("an HTTP/2 request with :authority %q was answered %s, want %s", tc.authority, got, tc.want)
			}
			if tc.want == "PROTOCOL_ERROR" {
				if len(reached) != 0 {
					t.Errorf("Go refused :authority %q, but the handler saw Host %q", tc.authority, reached)
				}
				return
			}
			if len(reached) != 1 || reached[0] != tc.authority {
				t.Errorf("the handler saw Host %q, want :authority %q as sent", reached, tc.authority)
			}
			// The public Host column judges the same Host header the same way.
			if pass, reason := hostColumns(t)[0].Judge(tc.authority); pass != (tc.want == "204") || !pass && reason != tc.want {
				t.Errorf("the public Host column judges %q as pass %v (%s); over HTTP/2 it was answered %s", tc.authority, pass, reason, tc.want)
			}
		})
	}
}

// answerOverHTTP2 sends one GET over a fresh HTTP/2 connection to addr, with :authority as given:
// written into the HEADERS frame by hand, since Go's client punycodes a host and refuses one that
// fails httpguts.ValidHostHeader. It returns the response's status, or the error code of the stream
// or connection error the server answers instead.
func answerOverHTTP2(t *testing.T, addr, authority string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) //nolint:gosec // G402: a test server's own certificate
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", authority}, {":path", "/"}} {
		if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndStream: true, EndHeaders: true}); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read the answer to :authority %q: %v", authority, err)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID == 1 {
				return f.PseudoValue("status")
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 {
				return f.ErrCode.String()
			}
		case *http2.GoAwayFrame:
			return f.ErrCode.String()
		}
	}
}
