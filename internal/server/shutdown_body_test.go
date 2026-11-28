//go:build linux || darwin

package server

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/testutil/lifecycle"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// cutBound is how soon after a shutdown starts a request it ends must be answered: well under
// ShutdownTimeout, which is what a stalled body read waited out before #697.
const cutBound = 2 * time.Second

// shutdownTransport is a way the MCP client reaches the proxy: its client, the proxy's public URL,
// and whether the proxy serves TLS.
type shutdownTransport struct {
	name   string
	public string // the public URL's origin; a request's Host is its host
	tls    bool
	proto  int
	client func(*tls.Config) *http.Transport
}

// The two over TLS are TestASignInAndMCPCallsWorkOverTheProxysTLS's clients (tls_test.go).
var shutdownTransports = []shutdownTransport{
	{"HTTP/1.1", "http://127.0.0.1:8080", false, 1, func(*tls.Config) *http.Transport { return &http.Transport{} }},
	{"HTTP/1.1 over TLS", "https://localhost:8443", true, 1, func(c *tls.Config) *http.Transport {
		return &http.Transport{TLSClientConfig: c, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	}},
	{"HTTP/2 over TLS", "https://localhost:8443", true, 2, func(c *tls.Config) *http.Transport {
		return &http.Transport{TLSClientConfig: c, ForceAttemptHTTP2: true}
	}},
}

// shutdownProxy is the running proxy, and its MCP client, of a test that shuts it down.
type shutdownProxy struct {
	runningProxy
	client *http.Client
}

// runShutdownProxy runs the proxy without authentication over tr. Its upstream is in args (the
// stdio command after --) or in settings (BYWARD_UPSTREAM_URL).
func runShutdownProxy(t *testing.T, tr shutdownTransport, args []string, settings ...string) *shutdownProxy {
	t.Helper()
	settings = append(settings, "BYWARD_INSECURE_NO_AUTH=true", "BYWARD_PUBLIC_URL="+tr.public+"/mcp", "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=")
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if tr.tls {
		cert := testcert.Issue(t, testcert.Options{Hosts: []string{"localhost"}, Leaf: testcert.Valid(time.Now(), 90)})
		settings = append(settings, tlsSettings(t, cert)...)
		tlsConfig.RootCAs, tlsConfig.ServerName = cert.Roots, "localhost"
	}
	cfg, _, err := config.Load(args, settings, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	logs := newTLSLog()
	p := &shutdownProxy{runningProxy: startRun(t, started(t, cfg, logging.New(logs, "json")), logs)}
	transport := tr.client(tlsConfig)
	transport.ExpectContinueTimeout = time.Minute // the body waits for the proxy's 100 Continue (send)
	p.client = &http.Client{Transport: transport}
	t.Cleanup(p.client.CloseIdleConnections)
	return p
}

// send starts a POST /mcp whose body is body, and returns its answer, or its error, on a channel.
func (p *shutdownProxy) send(t *testing.T, tr shutdownTransport, body io.Reader) <-chan answer {
	t.Helper()
	scheme := "http"
	if tr.tls {
		scheme = "https"
	}
	req, err := http.NewRequest(http.MethodPost, scheme+"://"+p.addr+"/mcp", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = strings.TrimPrefix(strings.TrimPrefix(tr.public, "https://"), "http://")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// The proxy asks for the body only once its handler reads it, so a first write that returns
	// means the handler is reading.
	req.Header.Set("Expect", "100-continue")
	answers := make(chan answer, 1)
	go func() {
		res, err := p.client.Do(req)
		answers <- answer{res, err}
	}()
	return answers
}

// answer is a request's response, or why it has none.
type answer struct {
	res *http.Response
	err error
}

// got is a's response, failing t if it has none.
func (a answer) got(t *testing.T) *http.Response {
	t.Helper()
	if a.err != nil {
		t.Fatalf("no answer: %v", a.err)
	}
	t.Cleanup(func() { _ = a.res.Body.Close() })
	return a.res
}

// shutDown starts the shutdown and waits up to cutBound for answer.
func (p *shutdownProxy) shutDown(t *testing.T, answers <-chan answer) *http.Response {
	t.Helper()
	p.cancel()
	select {
	case a := <-answers:
		return a.got(t)
	case <-time.After(cutBound):
		t.Fatalf("no answer within %v of the shutdown", cutBound)
	}
	return nil
}

// #697: a shutdown ends a request whose body is still being read, over HTTP/1.1, over TLS and over
// HTTP/2, to an HTTP upstream (the relay copies the body) and to a stdio one (the bridge reads it
// first): the MCP client, still there, gets 503 on a connection that closes, well within the
// shutdown's grace, and nothing is logged as a failure.
func TestAShutdownEndsAStalledRequestBodyWith503(t *testing.T) {
	bin, err := fakeStdio()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	t.Cleanup(upstream.Close)
	for _, tr := range shutdownTransports {
		for _, up := range []struct {
			name     string
			args     []string
			settings []string
		}{
			{"to an HTTP upstream", nil, []string{"BYWARD_UPSTREAM_URL=" + upstream.URL + "/mcp"}},
			{"to a stdio upstream", []string{"--", bin, "-mcp"}, nil},
		} {
			t.Run(tr.name+" "+up.name, func(t *testing.T) {
				p := runShutdownProxy(t, tr, up.args, up.settings...)
				body := lifecycle.NewCutBody(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
				t.Cleanup(body.Stop)
				answers := p.send(t, tr, body)
				select { // the proxy asks for the body (100 Continue) once its handler reads it
				case <-body.Started():
				case a := <-answers:
					t.Fatalf("answered before the body was read: %v", a.err)
				case <-time.After(5 * time.Second):
					t.Fatal("the proxy never read the body")
				}
				res := p.shutDown(t, answers)
				got, _ := io.ReadAll(res.Body)
				if res.StatusCode != http.StatusServiceUnavailable || string(got) != "the proxy is shutting down\n" || res.ProtoMajor != tr.proto {
					t.Fatalf("answer %s %d %q; want HTTP/%d 503 %q", res.Proto, res.StatusCode, got, tr.proto, "the proxy is shutting down\n")
				}
				if tr.proto == 1 && !res.Close {
					t.Error("the connection is kept open; want Connection: close")
				}
				logs := p.finished(t)
				if !strings.Contains(logs, `"status":503`) || failureLogged(logs) {
					t.Errorf("want a request line with status 503, and no failure logged:\n%s", logs)
				}
			})
		}
	}
}

// #697: the cut changes only a body still being read. A request whose body was read whole ends at a
// shutdown as it did before, over each transport: one waiting for its upstream's answer gets 503,
// and a stream that has started is cut, its request line recording the shutdown, never a read
// timeout.
func TestAShutdownLeavesARequestWhoseBodyWasReadAsItWas(t *testing.T) {
	const event = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
	read := make(chan struct{}, 1) // the upstream has read a whole body
	hold := func(stream bool) *httptest.Server {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			read <- struct{}{}
			if stream {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, event)
				_ = http.NewResponseController(w).Flush()
			}
			<-r.Context().Done()
		}))
		t.Cleanup(up.Close)
		return up
	}
	waiting, streaming := hold(false), hold(true)
	for _, tr := range shutdownTransports {
		t.Run(tr.name+" waiting for the upstream's answer", func(t *testing.T) {
			p := runShutdownProxy(t, tr, nil, "BYWARD_UPSTREAM_URL="+waiting.URL+"/mcp")
			answers := p.send(t, tr, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			select { // the upstream has the whole body
			case <-read:
			case a := <-answers:
				t.Fatalf("answered before the upstream had the body: %v", a.err)
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream never had the body")
			}
			res := p.shutDown(t, answers)
			got, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusServiceUnavailable || string(got) != "the proxy is shutting down\n" {
				t.Fatalf("answer %d %q; want 503 %q", res.StatusCode, got, "the proxy is shutting down\n")
			}
			logs := p.finished(t)
			if !strings.Contains(logs, `"status":503`) || strings.Contains(logs, "upstream error") || strings.Contains(logs, "timeout") {
				t.Errorf("want a request line with status 503, and no upstream error or timeout:\n%s", logs)
			}
		})
		t.Run(tr.name+" streaming", func(t *testing.T) {
			p := runShutdownProxy(t, tr, nil, "BYWARD_UPSTREAM_URL="+streaming.URL+"/mcp")
			answers := p.send(t, tr, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			select { // the upstream has the whole body
			case <-read:
			case a := <-answers:
				t.Fatalf("answered before the upstream had the body: %v", a.err)
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream never had the body")
			}
			var res *http.Response
			select {
			case a := <-answers:
				res = a.got(t)
			case <-time.After(5 * time.Second):
				t.Fatal("the stream never started")
			}
			first := make([]byte, len(event))
			if _, err := io.ReadFull(res.Body, first); err != nil || string(first) != event {
				t.Fatalf("first event %q, %v; want %q", first, err, event)
			}
			p.cancel()
			ended := make(chan struct{})
			go func() { defer close(ended); _, _ = io.ReadAll(res.Body) }() // ends cut or at EOF: the log tells which
			select {
			case <-ended:
			case <-time.After(cutBound):
				t.Fatalf("the stream was not cut within %v of the shutdown", cutBound)
			}
			logs := p.finished(t)
			if !strings.Contains(logs, `"status":200`) || !strings.Contains(logs, `"error_type":"shutdown"`) || strings.Contains(logs, "timeout") {
				t.Errorf("want a request line with status 200 cut by the shutdown, and no timeout:\n%s", logs)
			}
		})
	}
}
