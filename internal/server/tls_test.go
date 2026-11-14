package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/servingcert"
	"github.com/byward-dev/byward/internal/testutil/fakeidp"
	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// tlsSettings writes b into a new directory and returns the settings that serve it.
func tlsSettings(t *testing.T, b testcert.Bundle) []string {
	t.Helper()
	cert, key := b.Write(t, t.TempDir())
	return []string{"BYWARD_TLS_CERT_FILE=" + cert, "BYWARD_TLS_KEY_FILE=" + key}
}

// tlsLog is a log sink a test can wait on for a line.
type tlsLog struct {
	syncBuffer
	wrote chan struct{} // signalled after each write
}

func newTLSLog() *tlsLog { return &tlsLog{wrote: make(chan struct{}, 1)} }

func (l *tlsLog) Write(p []byte) (int, error) {
	n, err := l.syncBuffer.Write(p)
	select {
	case l.wrote <- struct{}{}:
	default:
	}
	return n, err
}

// waitFor waits up to 5s for a line that matches, and returns the log so far.
func (l *tlsLog) waitFor(t *testing.T, re *regexp.Regexp) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if text := l.String(); re.MatchString(text) {
			return text
		}
		select {
		case <-l.wrote:
		case <-deadline:
			t.Fatalf("no log line matching %s within 5s:\n%s", re, l.String())
		}
	}
}

// runPublic runs s, logging to logs, until the test ends, and returns the public listener's
// address.
func runPublic(t *testing.T, s *Servers, logs *tlsLog) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s, logging.New(logs, "json")) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	for !listenLine.MatchString(logs.String()) {
		select {
		case <-logs.wrote:
		case err := <-done:
			done <- err // for the cleanup, which waits for Run
			t.Fatalf("Run returned before listening: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not log its listening address within 5s")
		}
	}
	return listenLine.FindStringSubmatch(logs.String())[1]
}

// tlsModes are the two modes TLS works in: authenticated, and without authentication on the
// loopback URL that mode allows. host is the public URL's host.
var tlsModes = []struct {
	name, host string
	load       func(t *testing.T, settings ...string) *config.Config
}{
	{"authenticated", "mcp.example.com", func(t *testing.T, settings ...string) *config.Config {
		return loadConfig(t, "https://mcp.example.com/mcp", settings...)
	}},
	{"without authentication", "localhost", anonymous},
}

// fakeEntra is an IdP for doctor's checks, so they answer at once.
func fakeEntra(t *testing.T) *http.Client {
	t.Helper()
	return fakeidp.New(t, fakeidp.Entra, fakeidp.WithTenantID(fixtureTenant),
		fakeidp.WithClient(fakeidp.Client{ID: fixtureClientID, Secrets: []string{"s3cret-entra"}})).HTTPClient()
}

// streamingUpstream answers a tools/call with an event stream of three events, sending each only
// once the test has read the one before; anything else gets an empty result.
type streamingUpstream struct{ next chan struct{} }

func (u streamingUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct{ ID any }
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &req)
	if !strings.Contains(string(body), `"tools/call"`) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{}})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for i := range 3 {
		if i > 0 {
			select {
			case <-u.next:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":%d}}\n\n", i)
		_ = http.NewResponseController(w).Flush()
	}
}

// #183 end to end over TLS at the proxy, with HTTP/2 and with HTTP/1.1: a user signs in, the
// client calls the upstream, and an event stream stays open across several events. The public URL
// is what the client uses; the listener is reached by its address under that name.
func TestASignInAndMCPCallsWorkOverTheProxysTLS(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport func(*tls.Config) *http.Transport
		proto     int
	}{
		{"HTTP/2", func(c *tls.Config) *http.Transport {
			return &http.Transport{TLSClientConfig: c, ForceAttemptHTTP2: true}
		}, 2},
		{"HTTP/1.1", func(c *tls.Config) *http.Transport {
			return &http.Transport{TLSClientConfig: c, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const public = "https://mcp.example.com"
			cert := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(time.Now(), 90)})
			up := streamingUpstream{next: make(chan struct{})}
			upstream := httptest.NewServer(up)
			t.Cleanup(upstream.Close)
			app := fakeidp.Client{ID: fakeidp.NewGUID(), Secrets: []string{"s3cret"}, RedirectURIs: []string{public + "/callback/oidc"}}
			fake := fakeidp.New(t, fakeidp.Generic, fakeidp.WithClient(app))
			// --dev only for the fake IdP's http issuer.
			cfg, _, err := config.Load([]string{"--dev"}, append(append(oidcEnv(t, "oidc", fake.Issuer(), app.ID, "s3cret"),
				"BYWARD_PUBLIC_URL="+public+"/mcp", "BYWARD_UPSTREAM_URL="+upstream.URL+"/mcp", "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN="),
				tlsSettings(t, cert)...), os.ReadFile)
			if err != nil {
				t.Fatal(err)
			}
			logs := newTLSLog()
			s, err := New(cfg, logging.New(logs, "json"))
			if err != nil {
				t.Fatal(err)
			}
			addr := runPublic(t, s, logs)
			client := &http.Client{Transport: tc.transport(&tls.Config{RootCAs: cert.Roots, ServerName: "mcp.example.com", MinVersion: tls.VersionTLS12}),
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			t.Cleanup(client.CloseIdleConnections)
			b := &testBrowser{t: t, base: "https://" + addr, public: public, c: client}
			proto := func(what string, res *http.Response) {
				t.Helper()
				if res.ProtoMajor != tc.proto {
					t.Fatalf("%s answered over %s, want HTTP/%d", what, res.Proto, tc.proto)
				}
			}

			const verifier = "verifier-0123456789-0123456789-0123456789-abc"
			q := url.Values{"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "response_type": {"code"}, "scope": {"mcp"},
				"code_challenge": {pkce(verifier)}, "code_challenge_method": {"S256"}}
			page := b.send(http.MethodGet, "/authorize?"+q.Encode(), nil, nil)
			proto("the consent page", page)
			if page.Header.Get("Strict-Transport-Security") == "" {
				t.Error("no Strict-Transport-Security over the proxy's TLS")
			}
			allow := b.allow(page, readAll(t, page))
			_ = allow.Body.Close()
			idpRes, err := fake.HTTPClient().Get(allow.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			_ = idpRes.Body.Close()
			cb, err := url.Parse(idpRes.Header.Get("Location"))
			if err != nil || cb.Path != "/callback/oidc" {
				t.Fatalf("the IdP sent the browser to %q (%v)", idpRes.Header.Get("Location"), err)
			}
			back := b.send(http.MethodGet, cb.Path+"?"+cb.RawQuery, nil, allow.Cookies())
			_ = back.Body.Close()
			proto("the callback", back)
			done, err := url.Parse(back.Header.Get("Location"))
			if err != nil || done.Query().Get("code") == "" {
				t.Fatalf("the callback sent the browser to %q (%v)", back.Header.Get("Location"), err)
			}
			res := b.send(http.MethodPost, "/token", url.Values{"grant_type": {"authorization_code"}, "code": {done.Query().Get("code")},
				"client_id": {"test-app"}, "redirect_uri": {"http://127.0.0.1/callback"}, "code_verifier": {verifier}}, nil)
			var tokens struct {
				AccessToken string `json:"access_token"`
			}
			err = json.NewDecoder(res.Body).Decode(&tokens)
			_ = res.Body.Close()
			if err != nil || tokens.AccessToken == "" {
				t.Fatalf("token: %d %v", res.StatusCode, err)
			}

			mcp := func(body string) *http.Response {
				t.Helper()
				r, err := http.NewRequest(http.MethodPost, b.base+"/mcp", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				r.Host = "mcp.example.com"
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json, text/event-stream")
				r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
				res, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = res.Body.Close() })
				proto("the MCP endpoint", res)
				if res.StatusCode != http.StatusOK {
					t.Fatalf("MCP request: %d %s", res.StatusCode, readAll(t, res))
				}
				return res
			}
			if body := readAll(t, mcp(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); !strings.Contains(body, `"result"`) {
				t.Fatalf("ping: %s", body)
			}
			stream := bufio.NewReader(mcp(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"slow"}}`).Body)
			for i := range 3 {
				if i > 0 {
					select {
					case up.next <- struct{}{}:
					case <-time.After(5 * time.Second):
						t.Fatalf("the upstream stopped streaming before event %d", i)
					}
				}
				line, err := stream.ReadString('\n')
				for err == nil && !strings.HasPrefix(line, "data:") {
					line, err = stream.ReadString('\n')
				}
				if err != nil || !strings.Contains(line, fmt.Sprintf(`"progress":%d`, i)) {
					t.Fatalf("event %d: %q %v", i, line, err)
				}
			}
		})
	}
}

// started is New(cfg) that closes its store when the test ends.
func started(t *testing.T, cfg *config.Config, log *slog.Logger) *Servers {
	t.Helper()
	s, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if s.closeStore != nil {
		t.Cleanup(func() { _ = s.closeStore() })
	}
	return s
}

// anonymous loads the settings without authentication, on the loopback https URL that mode allows.
func anonymous(t *testing.T, settings ...string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load(nil, append([]string{"BYWARD_PUBLIC_URL=https://localhost:8443/mcp", "BYWARD_UPSTREAM_URL=http://u/mcp",
		"BYWARD_INSECURE_NO_AUTH=true"}, settings...), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// tlsListener is a running proxy serving TLS, with its certificate files.
type tlsListener struct {
	addr      string
	cert, key string
	logs      *tlsLog
}

// tlsServer runs the proxy serving cert on a TLS listener, loaded by load.
func tlsServer(t *testing.T, cert testcert.Bundle, load func(*testing.T, ...string) *config.Config) tlsListener {
	t.Helper()
	certFile, keyFile := cert.Write(t, t.TempDir())
	cfg := load(t, "BYWARD_TLS_CERT_FILE="+certFile, "BYWARD_TLS_KEY_FILE="+keyFile, "BYWARD_LISTEN=127.0.0.1:0", "BYWARD_INTERNAL_LISTEN=")
	l := tlsListener{cert: certFile, key: keyFile, logs: newTLSLog()}
	l.addr = runPublic(t, started(t, cfg, logging.New(l.logs, "json")), l.logs)
	return l
}

// handshake completes a TLS handshake with the listener as a client trusting roots, and returns the
// leaf it was served.
func (l tlsListener) handshake(t *testing.T, roots *x509.CertPool, host string) *x509.Certificate {
	t.Helper()
	c, err := tls.Dial("tcp", l.addr, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return c.ConnectionState().PeerCertificates[0]
}

// renew writes b beside the listener's files and renames them over, as an operator should.
func (l tlsListener) renew(t *testing.T, b testcert.Bundle) {
	t.Helper()
	cert, key := b.Write(t, t.TempDir())
	for from, to := range map[string]string{cert: l.cert, key: l.key} {
		if err := os.Rename(from, to); err != nil {
			t.Fatal(err)
		}
	}
}

// leaf is the leaf certificate of a bundle.
func leaf(t *testing.T, b testcert.Bundle) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b.Cert)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// #183: the running listener serves a renewed certificate from the next connection on, with no
// restart, in both modes, and warns about it as startup would.
func TestTheRunningListenerServesARenewedCertificateWithoutARestart(t *testing.T) {
	for _, mode := range tlsModes {
		t.Run(mode.name, func(t *testing.T) {
			first := testcert.Issue(t, testcert.Options{Hosts: []string{mode.host}, Leaf: testcert.Valid(time.Now(), 90)})
			l := tlsServer(t, first, mode.load)
			if !l.handshake(t, first.Roots, mode.host).Equal(leaf(t, first)) {
				t.Fatal("the first certificate is not served")
			}
			// Renewed for 10 days, so the renewal is warned about.
			renewed := testcert.Issue(t, testcert.Options{Hosts: []string{mode.host}, Leaf: testcert.Valid(time.Now(), 10)})
			l.renew(t, renewed)
			if !l.handshake(t, renewed.Roots, mode.host).Equal(leaf(t, renewed)) {
				t.Fatal("the renewed certificate is not served at the next connection")
			}
			logs := l.logs.waitFor(t, regexp.MustCompile(`(?s)serving a new TLS certificate.*the certificate \(CN=Test Leaf\) expires on`))
			for _, field := range []string{`"cert_file":"` + l.cert + `"`, `"subject":"CN=Test Leaf"`,
				`"not_after":"` + leaf(t, renewed).NotAfter.UTC().Format(time.RFC3339) + `"`} {
				if !strings.Contains(logs, field) {
					t.Errorf("the reload does not log %s:\n%s", field, logs)
				}
			}
		})
	}
}

// #183: a renewed key that other users can read is not served: the running proxy keeps its
// certificate and warns, as a restart would refuse it.
func TestTheRunningListenerRefusesARenewedKeyOtherUsersCanRead(t *testing.T) {
	first := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(time.Now(), 90)})
	l := tlsServer(t, first, tlsModes[0].load)
	renewed := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(time.Now(), 90)})
	l.renew(t, renewed)
	if err := os.Chmod(l.key, 0o644); err != nil { //nolint:gosec // G302: a key others can read, on purpose
		t.Fatal(err)
	}
	if !l.handshake(t, first.Roots, "mcp.example.com").Equal(leaf(t, first)) {
		t.Fatal("a key other users can read was served")
	}
	if logs := l.logs.waitFor(t, regexp.MustCompile(`cannot be served`)); !strings.Contains(logs, "has mode 0644") || !strings.Contains(logs, `"key_file":"`+l.key+`"`) {
		t.Errorf("the warning does not name the key and say why:\n%s", logs)
	}
}

// #183: the TLS listener answers plain HTTP with 400, says at startup that it serves TLS, and the
// least it accepts is TLS 1.2.
func TestTheTLSListenerRefusesPlainHTTPAndVersionsBelowTLS12(t *testing.T) {
	cert := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(time.Now(), 90)})
	l := tlsServer(t, cert, tlsModes[0].load)
	if listening := regexp.MustCompile(`"msg":"listening",[^\n]*"tls":true`); !listening.MatchString(l.logs.String()) {
		t.Errorf("the listening line does not say TLS is on:\n%s", l.logs.String())
	}
	res, err := http.Get("http://" + l.addr + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain HTTP got %d, want 400", res.StatusCode)
	}
	// Go's own server refuses TLS 1.1 by default too, so the setting itself is checked as well.
	cfg, err := servingTLS(loadConfig(t, "https://mcp.example.com/mcp", tlsSettings(t, cert)...), discard, time.Now)
	if err != nil || cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion %v (%v), want TLS 1.2", cfg, err)
	}
	for _, tc := range []struct {
		name    string
		max     uint16
		refused bool
	}{
		{"TLS 1.1 is refused", tls.VersionTLS11, true},
		{"TLS 1.2 is accepted", tls.VersionTLS12, false},
		{"TLS 1.3 is accepted", tls.VersionTLS13, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			//nolint:gosec // G402: the test offers an old version on purpose
			c, err := tls.Dial("tcp", l.addr, &tls.Config{RootCAs: cert.Roots, ServerName: "mcp.example.com", MinVersion: tls.VersionTLS10, MaxVersion: tc.max})
			if err == nil {
				_ = c.Close()
			}
			if (err != nil) != tc.refused || (tc.refused && !strings.Contains(err.Error(), "protocol version")) {
				t.Fatalf("handshake error %v, want refused %v for its version", err, tc.refused)
			}
		})
	}
}

// #183: a TCP health probe of the TLS port (connect, then close) is not logged; a handshake that
// fails is.
func TestATCPProbeOfTheTLSPortIsNotLoggedButAFailedHandshakeIs(t *testing.T) {
	cert := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(time.Now(), 90)})
	l := tlsServer(t, cert, tlsModes[0].load)
	// The server handles each connection on its own goroutine, so its log lines are not in the
	// order of the connections. The probes go first and a failed handshake after: once the
	// handshake is logged, the probes have had their chance to be.
	for range 3 {
		c, err := net.Dial("tcp", l.addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	//nolint:gosec // G402: an old version on purpose
	if c, err := tls.Dial("tcp", l.addr, &tls.Config{ServerName: "mcp.example.com", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		_ = c.Close()
	}
	if logs := l.logs.waitFor(t, regexp.MustCompile(`TLS handshake error`)); strings.Contains(logs, ": EOF") {
		t.Fatalf("a probe was logged:\n%s", logs)
	}
}

// #183: the proxy does not start, check --offline fails, and doctor stops with a configuration
// error, on TLS files it cannot read; an expired certificate stops startup and check, and is a
// failure in doctor's report. The error names the settings. --dev relaxes only the key's
// permission check.
func TestTLSFilesThatCannotBeServedFailStartupCheckAndDoctorAndDevRelaxesOnlyTheKeyMode(t *testing.T) {
	day := 24 * time.Hour
	now := time.Now()
	good := testcert.Issue(t, testcert.Options{Hosts: []string{"localhost", "mcp.example.com"}, Leaf: testcert.Valid(now, 90)})
	other := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	expired := testcert.Issue(t, testcert.Options{Leaf: testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}})
	for _, tc := range []struct {
		name        string
		bundle      testcert.Bundle
		keyMode     os.FileMode // 0 leaves the written 0600
		missingCert bool
		dev         bool
		want        string // "" when it starts
		doctorFails bool   // doctor reports a failure instead of stopping
	}{
		{name: "the key of another certificate", bundle: testcert.Bundle{Cert: good.Cert, Key: other.Key}, want: "BYWARD_TLS_CERT_FILE / BYWARD_TLS_KEY_FILE: "},
		{name: "an expired certificate", bundle: expired, want: "the certificate (CN=Test Leaf) expired on", doctorFails: true},
		{name: "no certificate file", bundle: good, missingCert: true, want: "missing.crt"},
		{name: "a key other users can read", bundle: good, keyMode: 0o644, want: "BYWARD_TLS_KEY_FILE: secret file"},
		{name: "a key other users can read is accepted in --dev", bundle: good, keyMode: 0o644, dev: true},
		{name: "an expired certificate is refused in --dev", bundle: expired, dev: true, want: "the certificate (CN=Test Leaf) expired on", doctorFails: true},
	} {
		for _, mode := range tlsModes {
			t.Run(tc.name+", "+mode.name, func(t *testing.T) {
				settings := tlsSettings(t, tc.bundle)
				if tc.missingCert {
					settings[0] = "BYWARD_TLS_CERT_FILE=" + filepath.Join(t.TempDir(), "missing.crt")
				}
				if tc.keyMode != 0 {
					if err := os.Chmod(strings.TrimPrefix(settings[1], "BYWARD_TLS_KEY_FILE="), tc.keyMode); err != nil {
						t.Fatal(err)
					}
				}
				if tc.dev {
					settings = append(settings, "BYWARD_DEV=true")
				}
				cfg := mode.load(t, settings...)
				s, startErr := New(cfg, discard)
				if s != nil && s.closeStore != nil {
					t.Cleanup(func() { _ = s.closeStore() })
				}
				_, checkErr := CheckOffline(cfg)
				rep, doctorErr := Doctor(context.Background(), cfg, DoctorOptions{IdP: fakeEntra(t), Proxy: &http.Client{Transport: refuse{}}})
				errs := map[string]error{"startup": startErr, "check --offline": checkErr, "doctor": doctorErr}
				if tc.doctorFails {
					delete(errs, "doctor")
					if c := checkNamed(t, rep, "TLS certificate expiry"); doctorErr != nil || c.Status != doctor.Fail || !strings.Contains(c.Message, tc.want) {
						t.Errorf("doctor: %v, %s %q; want a failure with %q", doctorErr, c.Status, c.Message, tc.want)
					}
				}
				for what, err := range errs {
					switch {
					case tc.want == "" && err != nil:
						t.Errorf("%s: %v", what, err)
					case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
						t.Errorf("%s: error %v, want one with %q", what, err, tc.want)
					}
				}
			})
		}
	}
}

// #183: a certificate that needs the operator (expiring soon, issued for another name) is warned
// about at startup, by check --offline and by doctor, in both modes, each warning on its own.
func TestACertificateNeedingTheOperatorIsWarnedAboutAtStartupCheckAndDoctor(t *testing.T) {
	now := time.Now()
	const expiryWarning, namesWarning = "the certificate (CN=Test Leaf) expires on", "the TLS certificate covers neither the public URL's host"
	for _, tc := range []struct {
		name          string
		days          int
		forPublicHost bool
		expiry, names doctor.Status
	}{
		{"valid for long, for the public host", 90, true, doctor.Pass, doctor.Pass},
		{"expiring soon, for the public host", 10, true, doctor.Warn, doctor.Pass},
		{"valid for long, for another name", 90, false, doctor.Pass, doctor.Warn},
		{"expiring soon, for another name", 10, false, doctor.Warn, doctor.Warn},
	} {
		for _, mode := range tlsModes {
			t.Run(tc.name+", "+mode.name, func(t *testing.T) {
				hosts := []string{"byward.ns.svc"}
				if tc.forPublicHost {
					hosts = []string{mode.host}
				}
				cfg := mode.load(t, tlsSettings(t, testcert.Issue(t, testcert.Options{Hosts: hosts, Leaf: testcert.Valid(now, tc.days)}))...)
				var logs syncBuffer
				started(t, cfg, logging.New(&logs, "json"))
				warnings, err := CheckOffline(cfg)
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range warnings {
					if strings.Contains(w.Message, namesWarning) || strings.Contains(w.Message, expiryWarning) {
						if w.Setting != "BYWARD_TLS_CERT_FILE" || w.Fix == "" {
							t.Errorf("the warning %+v does not name BYWARD_TLS_CERT_FILE and a fix", w)
						}
					}
				}
				rep, err := Doctor(context.Background(), cfg, DoctorOptions{Now: func() time.Time { return now }, IdP: fakeEntra(t), Proxy: &http.Client{Transport: refuse{}}})
				if err != nil {
					t.Fatal(err)
				}
				expiry, names := checkNamed(t, rep, "TLS certificate expiry"), checkNamed(t, rep, "TLS certificate names")
				if expiry.Status != tc.expiry || names.Status != tc.names {
					t.Errorf("doctor: expiry %s %q, names %s %q; want %s, %s", expiry.Status, expiry.Message, names.Status, names.Message, tc.expiry, tc.names)
				}
				sources := map[string]string{"startup": logs.String(), "check": fmt.Sprint(warnings), "doctor": expiry.Message + "\n" + names.Message}
				for w, want := range map[string]bool{expiryWarning: tc.expiry == doctor.Warn, namesWarning: tc.names == doctor.Warn} {
					for what, text := range sources {
						if strings.Contains(text, w) != want {
							t.Errorf("%s warns %q: %v, want %v:\n%s", what, w, !want, want, text)
						}
					}
					if n := strings.Count(sources["startup"], w); want && n != 1 {
						t.Errorf("startup warns %q %d times, want once:\n%s", w, n, sources["startup"])
					}
				}
			})
		}
	}
}

// #183: doctor judges the TLS files as they are now, at its own clock, in both modes: startup
// accepted the original pair, and doctor fails one replaced by an expired pair, says when a running
// proxy will serve one replaced by a pair not valid yet, and fails the original once its clock is
// past its end.
func TestDoctorJudgesTheTLSFilesAsTheyAreNowAtItsClock(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	for _, tc := range []struct {
		name      string
		leaf      testcert.Validity // the pair written over the started one; zero leaves it
		doctorNow time.Time
		want      string
	}{
		{"unchanged, expired by doctor's clock", testcert.Validity{}, now.Add(100 * day), "the certificate (CN=Test Leaf) expired on"},
		{"replaced by an expired pair", testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}, now, "the certificate (CN=Test Leaf) expired on"},
		{"replaced by a pair not valid yet", testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)}, now,
			"a running proxy serves them from " + now.Add(day-5*time.Minute).UTC().Format(time.RFC3339)},
	} {
		for _, mode := range tlsModes {
			t.Run(tc.name+", "+mode.name, func(t *testing.T) {
				cfg := mode.load(t, tlsSettings(t, testcert.Issue(t, testcert.Options{Hosts: []string{mode.host}, Leaf: testcert.Valid(now, 90)}))...)
				started(t, cfg, discard)
				if !tc.leaf.NotAfter.IsZero() {
					testcert.Issue(t, testcert.Options{Hosts: []string{mode.host}, Leaf: tc.leaf}).Write(t, filepath.Dir(cfg.TLSCertFile))
				}
				rep, err := Doctor(context.Background(), cfg, DoctorOptions{Now: func() time.Time { return tc.doctorNow }, IdP: fakeEntra(t), Proxy: &http.Client{Transport: refuse{}}})
				if err != nil {
					t.Fatal(err)
				}
				if c := checkNamed(t, rep, "TLS certificate expiry"); c.Status != doctor.Fail || !strings.Contains(c.Message+" "+c.Fix, tc.want) {
					t.Fatalf("doctor: %s %q %q, want a failure with %q", c.Status, c.Message, c.Fix, tc.want)
				}
			})
		}
	}
}

// pairFor reads a pair issued for o.
func pairFor(t *testing.T, o testcert.Options) *servingcert.Pair {
	t.Helper()
	cert, key := testcert.Issue(t, o).Write(t, t.TempDir())
	p, err := servingcert.Read(servingcert.Files{Cert: cert, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// #183: the expiry check warns from 30 days before the chain's first expiry and fails a pair that
// cannot be served; its wording counts the days left.
func TestTheTLSExpiryCheckWarnsFrom30DaysAndFailsAPairItCannotServe(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for _, tc := range []struct {
		name   string
		leaf   testcert.Validity
		status doctor.Status
		says   string
	}{
		{"31 days left", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(31 * day)}, doctor.Pass, "valid until 2026-12-14"},
		{"exactly 30 days left", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(30 * day)}, doctor.Warn, "expires on 2026-12-13, in 30 days"},
		{"a day left", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(day)}, doctor.Warn, "expires on 2026-11-14, in 1 day"},
		{"a day and some hours left, on tomorrow's date", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(day + 2*time.Hour)}, doctor.Warn, "expires on 2026-11-14, in 1 day"},
		{"under two days left, on the date after tomorrow", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(2*day - 2*time.Hour)}, doctor.Warn, "expires on 2026-11-15, in 2 days"},
		{"a minute under a day left", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(day - time.Minute)}, doctor.Warn, "in less than a day"},
		{"hours left", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(2 * time.Hour)}, doctor.Warn, "in less than a day"},
		{"expired", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now.Add(-time.Hour)}, doctor.Fail, "cannot be served"},
		{"not valid yet", testcert.Validity{NotBefore: now.Add(time.Hour), NotAfter: now.Add(90 * day)}, doctor.Fail, "serves them from 2026-11-13T12:55:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := servingCertExpiry(pairFor(t, testcert.Options{Leaf: tc.leaf}), now)
			if r.Status != tc.status || !regexp.MustCompile(regexp.QuoteMeta(tc.says)+`\b`).MatchString(r.Message+" "+r.Fix) {
				t.Fatalf("%s %q %q, want %s with %q", r.Status, r.Message, r.Fix, tc.status, tc.says)
			}
		})
	}
}

// #183: the names check passes when the certificate covers the public URL's host or any allowed
// host, however the allowed host is written, and warns otherwise.
func TestTheTLSNamesCheckPassesThePublicHostOrAnyAllowedHostAndWarnsOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sans    []string
		allowed string
		status  doctor.Status
	}{
		{"the public host", []string{"mcp.example.com"}, "", doctor.Pass},
		{"an allowed host with a port", []string{"mcp.internal.example"}, "mcp.internal.example:8443", doctor.Pass},
		{"an allowed host without a port", []string{"mcp.internal.example"}, "mcp.internal.example", doctor.Pass},
		{"an allowed IPv6 address with a port", []string{"::1"}, "[::1]:8443", doctor.Pass},
		{"an allowed IPv6 address in brackets", []string{"::1"}, "[::1]", doctor.Pass},
		{"another name", []string{"byward.ns.svc"}, "mcp.internal.example:8443", doctor.Warn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var extra []string
			if tc.allowed != "" {
				extra = append(extra, "BYWARD_ALLOWED_HOSTS="+tc.allowed)
			}
			cfg := loadConfig(t, "https://mcp.example.com/mcp", extra...)
			if r := servingCertNames(cfg, pairFor(t, testcert.Options{Hosts: tc.sans, Leaf: testcert.Valid(time.Now(), 90)})); r.Status != tc.status {
				t.Fatalf("%s %q, want %s", r.Status, r.Message, tc.status)
			}
		})
	}
}

// #183: the servers' error log keeps every line as a warning except a TLS handshake the client
// closed or reset before it began, as a TCP probe does.
func TestTheServerErrorLogDropsOnlyATLSHandshakeClosedBeforeItBegan(t *testing.T) {
	for line, kept := range map[string]bool{
		"http: TLS handshake error from 10.0.0.1:5555: EOF\n":                                                                   false,
		"http: TLS handshake error from 10.0.0.1:5555: read tcp 10.0.0.2:8443->10.0.0.1:5555: read: connection reset by peer\n": false,
		"http: proxy error: read tcp 10.0.0.2:8443->10.0.0.1:5555: read: connection reset by peer\n":                            true,
		"http: TLS handshake error from 10.0.0.1:5555: tls: client offered only unsupported versions\n":                         true,
		"http: proxy error: EOF\n": true,
		"http: Accept error: accept tcp: too many open files; retrying in 5ms\n": true,
	} {
		var logs syncBuffer
		if _, err := (serverErrors{logging.New(&logs, "json")}).Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		want := `"level":"WARN","msg":"` + strings.TrimSuffix(line, "\n") + `"`
		if got := strings.Contains(logs.String(), want); got != kept {
			t.Errorf("%q kept %v, want %v:\n%s", line, got, kept, logs.String())
		}
	}
}

// #183: a renewed certificate is judged at the time it is served, not at startup: a renewal
// months later that expires in 20 days is warned about.
func TestARenewalIsWarnedAboutAtTheTimeItIsServed(t *testing.T) {
	start := time.Now()
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	life := testcert.Validity{NotBefore: start.Add(-time.Hour), NotAfter: start.Add(90 * 24 * time.Hour)}
	cert, key := testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: life}).Write(t, t.TempDir())
	cfg := loadConfig(t, "https://mcp.example.com/mcp", "BYWARD_TLS_CERT_FILE="+cert, "BYWARD_TLS_KEY_FILE="+key)
	logs := newTLSLog()
	tlsConfig, err := servingTLS(cfg, logging.New(logs, "json"), now)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "expires on") {
		t.Fatalf("a certificate valid for 90 days is warned about:\n%s", logs.String())
	}
	clock.Store(start.Add(70 * 24 * time.Hour).UnixNano())
	l := tlsListener{cert: cert, key: key}
	l.renew(t, testcert.Issue(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: life}))
	if _, err := tlsConfig.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`expires on \d{4}-\d\d-\d\d, in 2[01] days`).MatchString(logs.String()) {
		t.Fatalf("the renewal is not warned about at the time it is served:\n%s", logs.String())
	}
}
