// Package assertion mints the identity assertion: the RFC 9068 access token the proxy sends the
// upstream in place of the client's token, saying who the user is (ADR-0016). It holds the
// assertion signing keys and serves their public half as a JWKS.
package assertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/byward-dev/byward/internal/logging"
	"github.com/byward-dev/byward/internal/secretfile"
)

// maxKeyFile bounds what is read from a key file; a PEM P-256 key is about 250 bytes.
const maxKeyFile = 16 << 10

// keyIDPattern limits key IDs (file names) to characters that need no escaping in a JWT header.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Keys are the assertion signing keys (ADR-0006 §8: separate from every other key). The key
// whose ID sorts last signs; the others stay in the JWKS, so verifiers holding a cached JWKS keep
// accepting assertions across a rotation.
type Keys struct {
	signing *signingKey
	all     []*signingKey // sorted by ID
}

type signingKey struct {
	id  string
	key *ecdsa.PrivateKey
}

// LoadKeys reads every key file in dir: a PEM P-256 private key (PKCS#8 "PRIVATE KEY", or the
// "EC PRIVATE KEY" that `openssl ecparam -genkey` writes), its file name the key ID. Dotfiles and
// directories are skipped (Kubernetes secret volumes hold `..data` entries). check is the secret
// file permission check (ADR-0018 §11), run on each file before it is read. As with the sealing
// keys, a world-writable key file is refused, and so is a world-writable directory unless it is on
// a read-only mount; --dev relaxes neither. Any bad file fails the whole load, naming the file by its
// key ID, never the directory's path (security invariant 2); check's error must be a *fs.PathError
// or name no path.
func LoadKeys(dir string, check func(path string) error) (*Keys, error) {
	di, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("assertion key directory: %w", logging.FileError(err))
	}
	// A Kubernetes secret volume is a read-only tmpfs whose root is mode 1777; nobody can add a
	// key to it.
	if worldWritable(di) && !readOnlyFS(dir) {
		return nil, errors.New("assertion key directory is world-writable; anyone could add a key")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("assertion key directory: %w", logging.FileError(err))
	}
	k := &Keys{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(dir, name)
		fi, err := os.Stat(path) // follows symlinks
		if err != nil {
			return nil, fmt.Errorf("assertion key file %q: %w", name, logging.FileError(err))
		}
		if fi.IsDir() {
			continue
		}
		if worldWritable(fi) {
			return nil, fmt.Errorf("assertion key file %q is world-writable", name)
		}
		if !keyIDPattern.MatchString(name) {
			return nil, fmt.Errorf("assertion key file %q: the name is the key ID and must match %s", name, keyIDPattern)
		}
		if err := check(path); err != nil {
			return nil, fmt.Errorf("assertion key file %q: %w", name, logging.FileError(err))
		}
		key, err := readKey(path, name)
		if err != nil {
			return nil, err
		}
		k.all = append(k.all, &signingKey{id: name, key: key})
	}
	if len(k.all) == 0 {
		return nil, errors.New("assertion key directory has no key files")
	}
	sort.Slice(k.all, func(i, j int) bool { return k.all[i].id < k.all[j].id })
	k.signing = k.all[len(k.all)-1]
	return k, nil
}

// readOnlyFS is secretfile.ReadOnlyFS; tests replace it.
var readOnlyFS = secretfile.ReadOnlyFS

// worldWritable is the permission refused whatever the check allows: anyone could replace the key.
func worldWritable(fi os.FileInfo) bool { return fi.Mode().Perm()&0o002 != 0 }

var errNotP256 = errors.New("want an ECDSA P-256 private key (ES256)")

func readKey(path, name string) (*ecdsa.PrivateKey, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's key directory
	if err != nil {
		return nil, fmt.Errorf("assertion key file %q: %w", name, logging.FileError(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("assertion key file %q: %w", name, logging.FileError(err))
	}
	if len(raw) > maxKeyFile {
		return nil, fmt.Errorf("assertion key file %q: larger than %d bytes", name, maxKeyFile)
	}
	key, err := parseKey(raw)
	if err != nil {
		// The error never quotes the file's content: it is a private key.
		return nil, fmt.Errorf("assertion key file %q: %w", name, err)
	}
	return key, nil
}

func parseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not PEM; create one with: openssl ecparam -name prime256v1 -genkey -noout")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("PEM block %q: %w", block.Type, errNotP256)
	}
	if err != nil {
		return nil, errNotP256
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errNotP256
	}
	return ec, nil
}

// SigningKeyID is the ID of the key that signs new assertions.
func (k *Keys) SigningKeyID() string { return k.signing.id }

// KeyIDs lists every loaded key ID, sorted.
func (k *Keys) KeyIDs() []string {
	ids := make([]string, len(k.all))
	for i, s := range k.all {
		ids[i] = s.id
	}
	return ids
}
