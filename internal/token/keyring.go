package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// KeySize is the length of a sealing key: AES-256.
const KeySize = 32

// maxKeyFile bounds what is read from a key file; a valid one is 44 base64 characters plus a
// newline.
const maxKeyFile = 1 << 10

// keyIDPattern limits key IDs (file names) to characters that need no escaping anywhere and to a
// length that fits the token header.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// KeyRing holds the sealing keys loaded from a directory (ADR-0007 §5, ADR-0020 §3). Every key
// opens tokens; the key whose ID sorts last seals new ones, so adding a newer file and restarting
// rotates while older tokens stay valid.
type KeyRing struct {
	signing *key
	byID    map[string]*key
}

type key struct {
	id   string
	aead cipher.AEAD
}

// LoadKeyRing reads every key file in dir. The file name is the key ID; the content is the
// standard base64 encoding of KeySize random bytes, for example from
// `openssl rand -base64 32`. Dotfiles and directories are skipped (Kubernetes secret volumes hold
// `..data` entries). Any bad file fails the whole load, naming the file.
func LoadKeyRing(dir string) (*KeyRing, error) {
	di, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("token: key directory: %w", err)
	}
	if worldWritable(di) {
		return nil, fmt.Errorf("token: key directory %s is world-writable; anyone could add a key", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("token: key directory: %w", err)
	}
	r := &KeyRing{byID: map[string]*key{}}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(dir, name)
		fi, err := os.Stat(path) // follows symlinks
		if err != nil {
			return nil, fmt.Errorf("token: key file %s: %w", path, err)
		}
		if fi.IsDir() {
			continue
		}
		if worldWritable(fi) {
			return nil, fmt.Errorf("token: key file %s is world-writable", path)
		}
		if !keyIDPattern.MatchString(name) {
			return nil, fmt.Errorf("token: key file %s: the name is the key ID and must match %s", path, keyIDPattern)
		}
		k, err := readKey(path, name)
		if err != nil {
			return nil, err
		}
		r.byID[name] = k
		ids = append(ids, name)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("token: key directory %s has no key files", dir)
	}
	sort.Strings(ids)
	r.signing = r.byID[ids[len(ids)-1]]
	return r, nil
}

// worldWritable is the one permission rejected: group- and other-readable files are normal on
// Kubernetes secret volumes (mode 0644).
func worldWritable(fi os.FileInfo) bool { return fi.Mode().Perm()&0o002 != 0 }

func readKey(path, id string) (*key, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's key directory
	if err != nil {
		return nil, fmt.Errorf("token: key file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("token: key file %s: cannot read: %w", path, err)
	}
	material, err := decodeKey(raw)
	if err != nil {
		return nil, fmt.Errorf("token: key file %s: %w", path, err)
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("token: key file %s: %w", path, err)
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("token: key file %s: %w", path, err)
	}
	return &key{id: id, aead: aead}, nil
}

// SigningKeyID is the ID of the key that seals new tokens.
func (r *KeyRing) SigningKeyID() string { return r.signing.id }

// KeyIDs lists every loaded key ID, sorted.
func (r *KeyRing) KeyIDs() []string {
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

var errUnknownKey = errors.New("token: unknown key ID")

func (r *KeyRing) lookup(id string) (*key, error) {
	if k, ok := r.byID[id]; ok {
		return k, nil
	}
	return nil, errUnknownKey
}

// decodeKey parses the content of a key file into key material.
func decodeKey(raw []byte) ([]byte, error) {
	if len(raw) > maxKeyFile {
		return nil, errors.New("too large for a key")
	}
	material, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("not base64 (want `openssl rand -base64 %d`)", KeySize)
	}
	if len(material) != KeySize {
		return nil, fmt.Errorf("%d bytes, want %d (`openssl rand -base64 %d`)", len(material), KeySize, KeySize)
	}
	if bytes.Count(material, material[:1]) == KeySize {
		return nil, errors.New("every byte is the same; generate a random key")
	}
	return material, nil
}
