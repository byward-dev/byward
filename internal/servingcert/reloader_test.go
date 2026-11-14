package servingcert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/testcert"
)

// clock is an injected time.Now that a test moves.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// served is the leaf the reloader answers the next handshake with.
func served(t *testing.T, r *Reloader) *x509.Certificate {
	t.Helper()
	c, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// leafOf is the leaf in a bundle's certificate file.
func leafOf(t *testing.T, b testcert.Bundle) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b.Cert)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// syncBuffer is a log sink handshakes on several goroutines may write to.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *syncBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }

// othersCanRead stands in for the secret-file check: it refuses a key other users can read.
func othersCanRead(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: other users can read it", path)
	}
	return nil
}

// load loads f with the clock c and othersCanRead as the key check. Its logs also record each
// pair the Served hook is told of, as a "served <serial>" line.
func load(t *testing.T, f Files, c *clock) (*Reloader, *syncBuffer) {
	t.Helper()
	logs := new(syncBuffer)
	r, err := Load(f, Options{Now: c.now, Log: slog.New(slog.NewJSONHandler(logs, nil)), CheckKey: othersCanRead,
		Served: func(p *Pair) { _, _ = fmt.Fprintf(logs, "served %s\n", p.chain[0].SerialNumber) }})
	if err != nil {
		t.Fatal(err)
	}
	return r, logs
}

// mtimes are the modification times the tests give the files they change: strictly increasing and
// far from the time a file is written, so no change goes unseen on a file system with coarse
// timestamps.
var mtimes atomic.Int64

// touch gives the file at p the next modification time.
func touch(t *testing.T, p string) {
	t.Helper()
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(mtimes.Add(1)) * time.Second)
	if err := os.Chtimes(p, time.Time{}, at); err != nil {
		t.Fatal(err)
	}
}

// replace writes b over f's files in place, as an operator's cp does, and touches them.
func replace(t *testing.T, f Files, b testcert.Bundle) {
	t.Helper()
	for p, content := range map[string][]byte{f.Cert: b.Cert, f.Key: b.Key} {
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		touch(t, p)
	}
}

// kubeletVolume lays out a secret volume as the kubelet does: the files are symlinks through ..data
// to a timestamped directory.
type kubeletVolume struct {
	dir string
	n   int
}

func newKubeletVolume(t *testing.T, b testcert.Bundle) (*kubeletVolume, Files) {
	t.Helper()
	v := &kubeletVolume{dir: t.TempDir()}
	v.publish(t, b)
	for _, name := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", name), filepath.Join(v.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	return v, Files{Cert: filepath.Join(v.dir, "tls.crt"), Key: filepath.Join(v.dir, "tls.key")}
}

// publish writes b into a new timestamped directory and swaps ..data to it atomically: a ..data_tmp
// symlink renamed over ..data.
func (v *kubeletVolume) publish(t *testing.T, b testcert.Bundle) {
	t.Helper()
	v.n++
	ts := fmt.Sprintf("..2026_11_13_12_00_00.%d", v.n)
	if err := os.Mkdir(filepath.Join(v.dir, ts), 0o700); err != nil {
		t.Fatal(err)
	}
	b.Write(t, filepath.Join(v.dir, ts))
	tmp := filepath.Join(v.dir, "..data_tmp")
	if err := os.Symlink(ts, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(v.dir, "..data")); err != nil {
		t.Fatal(err)
	}
}

// #183: a renewed pair is served from the next handshake on, with no restart, whether the files are
// replaced in place or a Kubernetes secret volume swaps its ..data link (the files' own symlinks
// stay; the reloader stats through them).
func TestARenewedPairIsServedAtTheNextHandshake(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, first testcert.Bundle) (Files, func(testcert.Bundle))
	}{
		{"replaced in place", func(t *testing.T, first testcert.Bundle) (Files, func(testcert.Bundle)) {
			cert, key := first.Write(t, t.TempDir())
			f := Files{Cert: cert, Key: key}
			return f, func(b testcert.Bundle) { replace(t, f, b) }
		}},
		{"a kubelet ..data swap", func(t *testing.T, first testcert.Bundle) (Files, func(testcert.Bundle)) {
			v, f := newKubeletVolume(t, first)
			return f, func(b testcert.Bundle) { v.publish(t, b) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			f, renew := tc.setup(t, first)
			r, logs := load(t, f, &clock{t: now})
			if !served(t, r).Equal(leafOf(t, first)) {
				t.Fatal("the loaded pair is not served")
			}
			second := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			renew(second)
			if !served(t, r).Equal(leafOf(t, second)) {
				t.Fatal("the renewed pair is not served at the next handshake")
			}
			if n := strings.Count(logs.String(), "serving a new TLS certificate"); n != 1 {
				t.Errorf("logged the reload %d times, want once:\n%s", n, logs)
			}
			if want := `"not_after":"` + leafOf(t, second).NotAfter.UTC().Format(time.RFC3339) + `"`; !strings.Contains(logs.String(), want) {
				t.Errorf("the reload does not log %s:\n%s", want, logs)
			}
			if want := "served " + leafOf(t, second).SerialNumber.String() + "\n"; strings.Count(logs.String(), "served ") != 1 || !strings.Contains(logs.String(), want) {
				t.Errorf("the Served hook was not told of the renewed pair, once:\n%s", logs)
			}
		})
	}
}

// padded is b with its certificate file grown to n bytes by trailing newlines, which PEM
// parsing skips: two pairs of the same size, whatever their serial numbers.
func padded(t *testing.T, b testcert.Bundle, n int) testcert.Bundle {
	t.Helper()
	if len(b.Cert) > n {
		t.Fatalf("the certificate has %d bytes, more than %d", len(b.Cert), n)
	}
	b.Cert = append(append([]byte{}, b.Cert...), bytes.Repeat([]byte("\n"), n-len(b.Cert))...)
	return b
}

// #183: a change is seen by the file's identity and size, not only its modification time: a
// kubelet swap to files of the same size and times, and a rewrite in place that keeps the times.
func TestAChangeIsSeenWhenTheModificationTimeStaysTheSame(t *testing.T) {
	issued := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	first := padded(t, issued, len(issued.Cert)+64)
	for _, tc := range []struct {
		name string
		// change replaces the pair in files laid out with first, and returns the new pair.
		change func(t *testing.T, f Files, v *kubeletVolume) testcert.Bundle
	}{
		{"a kubelet swap to files of the same size", func(t *testing.T, f Files, v *kubeletVolume) testcert.Bundle {
			second := padded(t, testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)}), len(first.Cert))
			if len(second.Key) != len(first.Key) {
				t.Fatalf("keys of %d and %d bytes", len(first.Key), len(second.Key))
			}
			times := modTimes(t, f)
			v.publish(t, second)
			setModTimes(t, f, times)
			return second
		}},
		{"a rewrite in place of another size", func(t *testing.T, f Files, _ *kubeletVolume) testcert.Bundle {
			second := padded(t, testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)}), len(first.Cert)+1)
			times := modTimes(t, f)
			for p, content := range map[string][]byte{f.Cert: second.Cert, f.Key: second.Key} {
				if err := os.WriteFile(p, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			setModTimes(t, f, times)
			return second
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, f := newKubeletVolume(t, first)
			r, _ := load(t, f, &clock{t: now})
			second := tc.change(t, f, v)
			if !served(t, r).Equal(leafOf(t, second)) {
				t.Fatal("the change is not served")
			}
		})
	}
}

// modTimes are the modification times of f's files, symlinks followed.
func modTimes(t *testing.T, f Files) [2]time.Time {
	t.Helper()
	var at [2]time.Time
	for i, p := range []string{f.Cert, f.Key} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		at[i] = fi.ModTime()
	}
	return at
}

// setModTimes gives f's files the modification times at.
func setModTimes(t *testing.T, f Files, at [2]time.Time) {
	t.Helper()
	for i, p := range []string{f.Cert, f.Key} {
		if err := os.Chtimes(p, time.Time{}, at[i]); err != nil {
			t.Fatal(err)
		}
	}
}

// #183: a replaced pair that cannot be served (a half-written rotation, a key that does not
// match or that other users can read, an expired certificate, a missing file) never is: the
// previous pair stays, and the failure is logged once for that state of the files, not at every
// handshake. Fixing the files is served at once, a key's mode too, though a chmod leaves its size
// and time as they were.
func TestAPairThatCannotBeServedKeepsThePreviousOneAndIsLoggedOnce(t *testing.T) {
	day := 24 * time.Hour
	other := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	expired := testcert.Issue(t, testcert.Options{Leaf: testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}})
	for _, tc := range []struct {
		name   string
		break_ func(t *testing.T, f Files, first testcert.Bundle)
		want   string
		// fix makes the files servable and returns the pair they then hold; nil writes a new pair.
		fix func(t *testing.T, f Files) testcert.Bundle
	}{
		{"the key of another certificate", func(t *testing.T, f Files, first testcert.Bundle) {
			replace(t, f, testcert.Bundle{Cert: other.Cert, Key: first.Key})
		}, "private key does not match public key", nil},
		{"a half-written certificate", func(t *testing.T, f Files, _ testcert.Bundle) {
			replace(t, f, testcert.Bundle{Cert: other.Cert[:len(other.Cert)/2], Key: other.Key})
		}, "failed to find any PEM data in certificate input", nil},
		{"an expired certificate", func(t *testing.T, f Files, _ testcert.Bundle) {
			replace(t, f, expired)
		}, "expired on", nil},
		{"the key removed", func(t *testing.T, f Files, _ testcert.Bundle) {
			if err := os.Remove(f.Key); err != nil {
				t.Fatal(err)
			}
		}, "no such file or directory", nil},
		{"a key other users can read, fixed by chmod", func(t *testing.T, f Files, _ testcert.Bundle) {
			replace(t, f, other)
			if err := os.Chmod(f.Key, 0o644); err != nil { //nolint:gosec // G302: on purpose
				t.Fatal(err)
			}
		}, "other users can read it", func(t *testing.T, f Files) testcert.Bundle {
			times := modTimes(t, f)
			if err := os.Chmod(f.Key, 0o600); err != nil {
				t.Fatal(err)
			}
			setModTimes(t, f, times)
			return other
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, first := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			r, logs := load(t, f, &clock{t: now})
			tc.break_(t, f, first)
			for range 3 {
				if !served(t, r).Equal(leafOf(t, first)) {
					t.Fatal("a pair that cannot be served replaced the previous one")
				}
			}
			if n := strings.Count(logs.String(), "cannot be served"); n != 1 {
				t.Fatalf("logged the failure %d times over three handshakes, want once:\n%s", n, logs)
			}
			if !strings.Contains(logs.String(), `"error":"`) || !strings.Contains(logs.String(), tc.want) || !strings.Contains(logs.String(), `"cert_file":"`+f.Cert+`"`) {
				t.Errorf("the warning does not say %q and name the files:\n%s", tc.want, logs)
			}
			if strings.Contains(logs.String(), "PRIVATE KEY") {
				t.Errorf("the warning quotes a key:\n%s", logs)
			}
			fix := tc.fix
			if fix == nil {
				fix = func(t *testing.T, f Files) testcert.Bundle {
					fixed := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
					replace(t, f, fixed)
					return fixed
				}
			}
			if fixed := fix(t, f); !served(t, r).Equal(leafOf(t, fixed)) {
				t.Fatal("the fixed pair is not served")
			}
		})
	}
}

// #183: handshakes racing a change of the files log the failure once: each compares the files
// with the state the last reload saw, under the same lock.
func TestConcurrentHandshakesLogAFailedChangeOnce(t *testing.T) {
	f, first := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	other := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	r, logs := load(t, f, &clock{t: now})
	stop := make(chan struct{})
	var calls atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = r.GetCertificate(nil)
					calls.Add(1)
				}
			}
		}()
	}
	// One change of state, while the handshakes run: a certificate for another key, renamed over
	// the file.
	tmp := filepath.Join(filepath.Dir(f.Cert), "tls.crt.new")
	if err := os.WriteFile(tmp, other.Cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, f.Cert); err != nil {
		t.Fatal(err)
	}
	// Until some handshake has seen it, and then many more.
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "cannot be served") && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	for after := calls.Load() + 16*200; calls.Load() < after && time.Now().Before(deadline); {
		runtime.Gosched()
	}
	close(stop)
	wg.Wait()
	if !served(t, r).Equal(leafOf(t, first)) {
		t.Fatal("a mismatched pair was served")
	}
	if n := strings.Count(logs.String(), "cannot be served"); n != 1 {
		t.Fatalf("logged one change %d times, want once:\n%s", n, logs)
	}
}

// #183: a renewed certificate whose NotBefore is more than five minutes ahead of our clock is not
// served yet, and is served once it becomes servable although the files do not change again; one
// within five minutes is served at once. With an intermediate not valid yet either, the later
// start counts.
func TestARenewedCertificateNotValidYetIsServedOnceItIs(t *testing.T) {
	life := 90 * 24 * time.Hour
	for _, tc := range []struct {
		name         string
		leaf         time.Duration  // NotBefore, from now
		intermediate *time.Duration // NotBefore, from now; nil for none
		servable     time.Duration  // from now
	}{
		{"within the leeway", leeway, nil, 0},
		{"beyond the leeway", time.Hour, nil, time.Hour - leeway},
		{"with an intermediate starting later", time.Hour, new(2 * time.Hour), 2*time.Hour - leeway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{t: now}
			f, first := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			r, logs := load(t, f, c)
			o := testcert.Options{Leaf: testcert.Validity{NotBefore: now.Add(tc.leaf), NotAfter: now.Add(life)}}
			if tc.intermediate != nil {
				o.Intermediate = &testcert.Validity{NotBefore: now.Add(*tc.intermediate), NotAfter: now.Add(life)}
			}
			renewed := testcert.Issue(t, o)
			replace(t, f, renewed)
			if tc.servable > 0 {
				c.set(now.Add(tc.servable - time.Second))
				if !served(t, r).Equal(leafOf(t, first)) {
					t.Fatal("served a second before it is servable")
				}
			}
			c.set(now.Add(tc.servable))
			for range 3 { // and no reload after
				if !served(t, r).Equal(leafOf(t, renewed)) {
					t.Fatal("the renewed certificate is not served once it is servable")
				}
			}
			if n := strings.Count(logs.String(), "serving a new TLS certificate"); n != 1 {
				t.Errorf("logged %d reloads, want one:\n%s", n, logs)
			}
		})
	}
}

// #183: a pair not valid yet that has expired too by the time it would be served is not served,
// and its failure is not logged again: the files have not changed.
func TestAPairThatExpiresBeforeItIsServableIsLoggedOnce(t *testing.T) {
	c := &clock{t: now}
	f, first := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	r, logs := load(t, f, c)
	replace(t, f, testcert.Issue(t, testcert.Options{Leaf: testcert.Validity{NotBefore: now.Add(time.Hour), NotAfter: now.Add(time.Hour + time.Minute)}}))
	served(t, r)
	c.set(now.Add(2 * time.Hour))
	for range 2 {
		if !served(t, r).Equal(leafOf(t, first)) {
			t.Fatal("served a pair that has expired")
		}
	}
	if n := strings.Count(logs.String(), "cannot be served"); n != 1 {
		t.Fatalf("logged the unchanged files %d times, want once:\n%s", n, logs)
	}
}

// #183: startup refuses a pair it cannot serve, so the proxy never starts without a certificate.
func TestLoadRefusesAPairItCannotServe(t *testing.T) {
	day := 24 * time.Hour
	issued := func(v testcert.Validity) func(t *testing.T) Files {
		return func(t *testing.T) Files { f, _ := write(t, testcert.Options{Leaf: v}); return f }
	}
	for _, tc := range []struct {
		name  string
		files func(t *testing.T) Files
		want  string
	}{
		{"expired", issued(testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}), "expired on"},
		{"not valid yet", issued(testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)}), "is not valid until"},
		{"a key other users can read", func(t *testing.T) Files {
			f, _ := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			if err := os.Chmod(f.Key, 0o644); err != nil { //nolint:gosec // G302: on purpose
				t.Fatal(err)
			}
			return f
		}, "other users can read it"},
		{"missing files", func(*testing.T) Files {
			return Files{Cert: "/nonexistent/tls.crt", Key: "/nonexistent/tls.key"}
		}, "/nonexistent/tls."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.files(t), Options{Now: func() time.Time { return now }, Log: slog.New(slog.DiscardHandler), CheckKey: othersCanRead})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("load: %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// #183: a touch or a chmod that leaves the files' contents as they were reloads the same pair,
// which is served without announcing a new certificate or warning about it again.
func TestTheSamePairReloadedIsNotAnnouncedAsNew(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, f Files)
	}{
		{"a touch", func(t *testing.T, f Files) { touch(t, f.Cert) }},
		{"a chmod", func(t *testing.T, f Files) {
			if err := os.Chmod(f.Key, 0o400); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, first := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
			r, logs := load(t, f, &clock{t: now})
			tc.change(t, f)
			if !served(t, r).Equal(leafOf(t, first)) {
				t.Fatal("the pair changed")
			}
			if strings.Contains(logs.String(), "serving a new TLS certificate") || strings.Contains(logs.String(), "served ") {
				t.Fatalf("an unchanged pair was announced:\n%s", logs)
			}
		})
	}
}

// #183: without a key check or a Served hook, a reloader checks no key and tells no one, and still
// serves a renewed pair.
func TestAReloaderWithoutHooksStillServesARenewedPair(t *testing.T) {
	f, _ := write(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	if err := os.Chmod(f.Key, 0o644); err != nil { //nolint:gosec // G302: no check is configured
		t.Fatal(err)
	}
	r, err := Load(f, Options{Now: func() time.Time { return now }, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	renewed := testcert.Issue(t, testcert.Options{Leaf: testcert.Valid(now, 90)})
	replace(t, f, renewed)
	if !served(t, r).Equal(leafOf(t, renewed)) {
		t.Fatal("the renewed pair is not served")
	}
}

// #183: a renewal that keeps the leaf but changes the rest of the chain is a new certificate: the
// intermediate can decide the chain's first expiry, so it is announced and warned about.
func TestANewIntermediateBehindTheSameLeafIsAnnounced(t *testing.T) {
	life := testcert.Valid(now, 90)
	f, first := write(t, testcert.Options{Leaf: life, Intermediate: &life})
	r, logs := load(t, f, &clock{t: now})
	// Read does not verify the chain's signatures, so the same leaf can sit in front of another
	// intermediate.
	other := testcert.Issue(t, testcert.Options{Leaf: life, Intermediate: &testcert.Validity{NotBefore: life.NotBefore, NotAfter: now.Add(20 * 24 * time.Hour)}})
	end := []byte("-----END CERTIFICATE-----\n")
	leafEnd := bytes.Index(first.Cert, end) + len(end)
	intermediateStart := bytes.Index(other.Cert, end) + len(end)
	replace(t, f, testcert.Bundle{Cert: append(slices.Clone(first.Cert[:leafEnd]), other.Cert[intermediateStart:]...), Key: first.Key})
	if !served(t, r).Equal(leafOf(t, first)) {
		t.Fatal("the leaf changed")
	}
	if !strings.Contains(logs.String(), "serving a new TLS certificate") || !strings.Contains(logs.String(), "served ") {
		t.Fatalf("a new intermediate was not announced:\n%s", logs)
	}
}
