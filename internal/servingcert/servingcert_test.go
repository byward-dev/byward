package servingcert

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/testutil/testcert"
)

var now = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// write issues a certificate for o and writes it into a new directory.
func write(t *testing.T, o testcert.Options) (Files, testcert.Bundle) {
	t.Helper()
	b := testcert.Issue(t, o)
	cert, key := b.Write(t, t.TempDir())
	return Files{Cert: cert, Key: key}, b
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pemFile writes a PEM block into a new file.
func pemFile(t *testing.T, b *pem.Block) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(b), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A pair that cannot be read or does not match is refused, and the error names the file at fault
// without quoting the key it read.
func TestAnUnreadableOrMismatchedPairIsRefusedNamingTheFileWithoutQuotingTheKey(t *testing.T) {
	good, _ := write(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(now, 90)})
	other, _ := write(t, testcert.Options{Hosts: []string{"mcp.example.com"}, Leaf: testcert.Valid(now, 90)})
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "missing.pem")
	pkcs8 := pemFile(t, &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("ciphertext")})
	legacy := pemFile(t, &pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"}, Bytes: []byte("ciphertext")})
	// openssl ecparam -genkey writes the curve's parameters before the key.
	afterParams := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(afterParams, append(pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}}),
		mustRead(t, legacy)...), 0o600); err != nil {
		t.Fatal(err)
	}
	// tls.X509KeyPair parses only the leaf; a chain certificate that does not parse must still fail.
	badChain := filepath.Join(t.TempDir(), "chain.pem")
	if err := os.WriteFile(badChain, append(mustRead(t, good.Cert), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})...), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		files Files
		names string
		says  string
	}{
		{"no certificate file", Files{Cert: missing, Key: good.Key}, missing, "no such file"},
		{"no key file", Files{Cert: good.Cert, Key: missing}, missing, "no such file"},
		{"the key of another certificate", Files{Cert: good.Cert, Key: other.Key}, other.Key, "private key does not match public key"},
		{"no PEM in the certificate file", Files{Cert: garbage, Key: good.Key}, garbage, "failed to find any PEM data"},
		{"no PEM in the key file", Files{Cert: good.Cert, Key: garbage}, garbage, "failed to find any PEM data"},
		{"an encrypted PKCS#8 key", Files{Cert: good.Cert, Key: pkcs8}, pkcs8, "the private key is encrypted"},
		{"an encrypted legacy key", Files{Cert: good.Cert, Key: legacy}, legacy, "the private key is encrypted"},
		{"an encrypted key after its curve's parameters", Files{Cert: good.Cert, Key: afterParams}, afterParams, "the private key is encrypted"},
		{"a chain certificate that does not parse", Files{Cert: badChain, Key: good.Key}, badChain, "x509:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(c.files)
			if err == nil {
				t.Fatal("read")
			}
			if !strings.Contains(err.Error(), c.names) || !strings.Contains(err.Error(), c.says) {
				t.Errorf("the error does not name %s and say %q: %v", c.names, c.says, err)
			}
			if key, rerr := os.ReadFile(c.files.Key); rerr == nil {
				for _, line := range strings.Split(string(key), "\n") {
					if len(line) > 16 && !strings.HasPrefix(line, "-----") && strings.Contains(err.Error(), line) {
						t.Errorf("the error quotes the key file: %v", err)
					}
				}
			}
		})
	}
}

// Every certificate in the chain must be valid at now: an expired one anywhere is refused, and so
// is one not valid for more than five minutes yet; a few minutes of issuer clock skew is accepted.
// Only a pair whose sole fault is a start in the future becomes servable later.
func TestEveryCertificateInTheChainMustBeValidAndOnlyAFutureStartIsServableLater(t *testing.T) {
	day := 24 * time.Hour
	valid := testcert.Valid(now, 90)
	for _, c := range []struct {
		name         string
		leaf         testcert.Validity
		intermediate *testcert.Validity
		want         string // "" for valid
		servableAt   time.Time
	}{
		{"valid", valid, nil, "", time.Time{}},
		{"expiring this very second", testcert.Validity{NotBefore: now.Add(-day), NotAfter: now}, nil, "", time.Time{}},
		{"both expired", testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}, &testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)},
			"the certificate (CN=Test Leaf) expired on 2026-11-12T12:00:00Z\nchain certificate 2 (CN=Test Intermediate) expired on", time.Time{}},
		{"valid with its intermediate", valid, &valid, "", time.Time{}},
		{"expired leaf", testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-time.Second)}, nil, "the certificate (CN=Test Leaf) expired on 2026-11-13T11:59:59Z", time.Time{}},
		{"expired intermediate", valid, &testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}, "chain certificate 2 (CN=Test Intermediate) expired on 2026-11-12T12:00:00Z", time.Time{}},
		{"issued a few minutes ahead of our clock", testcert.Validity{NotBefore: now.Add(leeway), NotAfter: now.Add(90 * day)}, nil, "", time.Time{}},
		{"not valid yet", testcert.Validity{NotBefore: now.Add(leeway + time.Second), NotAfter: now.Add(90 * day)}, nil, "the certificate (CN=Test Leaf) is not valid until 2026-11-13T12:05:01Z", now.Add(time.Second)},
		{"intermediate not valid yet", valid, &testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)}, "chain certificate 2 (CN=Test Intermediate) is not valid until", now.Add(day - leeway)},
		{"both not valid yet, the intermediate later", testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)}, &testcert.Validity{NotBefore: now.Add(2 * day), NotAfter: now.Add(90 * day)},
			"is not valid until", now.Add(2*day - leeway)},
		{"both not valid yet, the leaf later", testcert.Validity{NotBefore: now.Add(2 * day), NotAfter: now.Add(90 * day)}, &testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)},
			"is not valid until", now.Add(2*day - leeway)},
		{"expired, and its intermediate not valid yet", testcert.Validity{NotBefore: now.Add(-90 * day), NotAfter: now.Add(-day)}, &testcert.Validity{NotBefore: now.Add(day), NotAfter: now.Add(90 * day)}, "expired on", time.Time{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, _ := write(t, testcert.Options{Leaf: c.leaf, Intermediate: c.intermediate})
			p, err := Read(f)
			if err != nil {
				t.Fatal(err)
			}
			err = p.Validity(now)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("validity = %v, want %q", err, c.want)
			}
			at, ok := ServableAt(err)
			if ok != !c.servableAt.IsZero() || !at.Equal(c.servableAt) {
				t.Errorf("servable at %v (%v), want %v", at, ok, c.servableAt)
			}
		})
	}
}

// The expiry an operator is warned about is the chain's earliest: an intermediate can expire
// before the leaf.
func TestTheFirstExpiryIsTheChainsEarliest(t *testing.T) {
	for _, c := range []struct {
		name               string
		leaf, intermediate time.Duration
		want               string
	}{
		{"the leaf", 30 * 24 * time.Hour, 300 * 24 * time.Hour, "the certificate (CN=Test Leaf)"},
		{"the intermediate", 300 * 24 * time.Hour, 30 * 24 * time.Hour, "chain certificate 2 (CN=Test Intermediate)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, _ := write(t, testcert.Options{Leaf: testcert.Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(c.leaf)},
				Intermediate: &testcert.Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(c.intermediate)}})
			p, err := Read(f)
			if err != nil {
				t.Fatal(err)
			}
			name, notAfter := p.FirstExpiry()
			if want := now.Add(min(c.leaf, c.intermediate)); name != c.want || !notAfter.Equal(want) {
				t.Errorf("first expiry = %s on %v, want %s on %v", name, notAfter, c.want, want)
			}
		})
	}
}

// The SANs decide which hosts the certificate covers: DNS names, wildcards and IP addresses.
func TestACertificateCoversOnlyTheHostsInItsSANs(t *testing.T) {
	// With an intermediate, so the leaf is not also the chain's last certificate.
	f, _ := write(t, testcert.Options{Hosts: []string{"mcp.example.com", "*.apps.example.com", "10.0.0.7"}, Leaf: testcert.Valid(now, 90), Intermediate: &testcert.Validity{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)}})
	p, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{"mcp.example.com": true, "x.apps.example.com": true, "10.0.0.7": true,
		"example.com": false, "byward.ns.svc": false, "10.0.0.8": false} {
		if got := p.Covers(host); got != want {
			t.Errorf("covers %s = %v, want %v", host, got, want)
		}
	}
}
