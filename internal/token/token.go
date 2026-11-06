// Package token mints and opens the broker's proxy tokens (ADR-0006, ADR-0014).
//
// Access tokens and authorization codes are sealed: AES-256-GCM with a random 96-bit nonce, the
// key chosen by the key ID in the token header, and the format version, token type, key ID and
// resource URL bound as associated data. They carry only a grant ID, a subject, iat and exp.
// Refresh tokens are opaque random strings stored as a SHA-256 hash (ADR-0006 §4).
//
// Wire format of a sealed token:
//
//	prefix || base64url( version(1) || len(kid)(1) || kid || nonce(12) || ciphertext || tag(16) )
//
// A key must not seal more than 2^32 tokens (the random-nonce collision bound of
// cipher.NewGCMWithRandomNonce); rotating to a new key resets the count.
package token

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Type is a sealed token type. It selects the prefix and is part of the associated data, so a
// token of one type never opens as another.
type Type byte

// Sealed token types.
const (
	Access Type = 1
	Code   Type = 2
)

// Prefixes make tokens recognisable to secret scanners and reject foreign strings before any
// cryptography (ADR-0006 §8). The prefix is not a security boundary: the type is also sealed.
const (
	AccessPrefix  = "mcpap_at_"
	CodePrefix    = "mcpap_ac_"
	RefreshPrefix = "mcpap_rt_"
)

func (t Type) prefix() string {
	switch t {
	case Access:
		return AccessPrefix
	case Code:
		return CodePrefix
	}
	return ""
}

// formatVersion is the only wire format so far; a new one (for example with a `cnf` claim for
// DPoP) gets a new number.
const formatVersion = 1

// MaxLen bounds a token before it is decoded.
const MaxLen = 2048

// maxResource bounds the resource URL bound into every token.
const maxResource = 8 << 10

const adLabel = "mcp-authproxy token\x00"

// Claims are what a sealed token carries.
type Claims struct {
	GrantID   string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// wireClaims is the sealed JSON; short names keep tokens small.
type wireClaims struct {
	GrantID   string `json:"gid"`
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var (
	errMalformed = errors.New("token: malformed")
	errWrongType = errors.New("token: wrong token type")
	errVersion   = errors.New("token: unknown format version")
	errOpen      = errors.New("token: cannot open")
	errClaims    = errors.New("token: invalid claims")
	errTooLong   = errors.New("token: claims too large for a token")
)

// Sealer seals and opens tokens for one resource URL with one key ring.
type Sealer struct {
	ring     *KeyRing
	resource string
}

// NewSealer binds ring to resource, the proxy's public MCP URL. A token sealed for one resource
// never opens for another.
func NewSealer(ring *KeyRing, resource string) (*Sealer, error) {
	if ring == nil || resource == "" || len(resource) > maxResource {
		return nil, errors.New("token: a sealer needs a key ring and a resource URL of at most 8 KiB")
	}
	return &Sealer{ring: ring, resource: resource}, nil
}

// Seal returns a token of type t carrying c, sealed with the signing key.
func (s *Sealer) Seal(t Type, c Claims) (string, error) {
	if t.prefix() == "" {
		return "", errWrongType
	}
	// Tokens carry whole seconds; check what Open will see, not what was passed in.
	c.IssuedAt, c.ExpiresAt = c.IssuedAt.Truncate(time.Second), c.ExpiresAt.Truncate(time.Second)
	if err := c.validate(); err != nil {
		return "", err
	}
	plain, err := json.Marshal(wireClaims{GrantID: c.GrantID, Subject: c.Subject, IssuedAt: c.IssuedAt.Unix(), ExpiresAt: c.ExpiresAt.Unix()})
	if err != nil {
		return "", err
	}
	k := s.ring.signing
	header := append([]byte{formatVersion, byte(len(k.id))}, k.id...) //nolint:gosec // G115: key IDs are at most 64 bytes (keyIDPattern)
	sealed := k.aead.Seal(header, nil, plain, s.ad(t, k.id))          //nolint:gosec // G407: NewGCMWithRandomNonce makes the nonce; nil is required
	tok := t.prefix() + base64.RawURLEncoding.EncodeToString(sealed)
	if len(tok) > MaxLen {
		return "", errTooLong
	}
	return tok, nil
}

// Open checks a token of type t in the order of ADR-0014: prefix, then the AEAD open with the key
// named in the header, then the format version and the claims. It does not check time; Validator
// does.
func (s *Sealer) Open(t Type, tok string) (Claims, error) {
	p := t.prefix()
	if p == "" {
		return Claims{}, errWrongType
	}
	if len(tok) > MaxLen {
		return Claims{}, errMalformed
	}
	body, ok := strings.CutPrefix(tok, p)
	if !ok {
		return Claims{}, errWrongType
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) < 2 {
		return Claims{}, errMalformed
	}
	// The version selects the layout, so it is read first; it is also sealed (associated data),
	// so a changed version fails the open below.
	if raw[0] != formatVersion {
		return Claims{}, errVersion
	}
	n := int(raw[1])
	if n == 0 || len(raw) < 2+n {
		return Claims{}, errMalformed
	}
	kid := string(raw[2 : 2+n])
	k, err := s.ring.lookup(kid)
	if err != nil {
		return Claims{}, err
	}
	plain, err := k.aead.Open(nil, nil, raw[2+n:], s.ad(t, kid))
	if err != nil {
		return Claims{}, errOpen
	}
	var w wireClaims
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Claims{}, errClaims
	}
	c := Claims{GrantID: w.GrantID, Subject: w.Subject, IssuedAt: time.Unix(w.IssuedAt, 0), ExpiresAt: time.Unix(w.ExpiresAt, 0)}
	if err := c.validate(); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// ad is the associated data: everything that must not be swapped between tokens. Fields are
// length-prefixed so no two inputs share an encoding.
func (s *Sealer) ad(t Type, kid string) []byte {
	b := []byte(adLabel)
	b = append(b, formatVersion, byte(t))
	b = binary.BigEndian.AppendUint16(b, uint16(len(kid))) //nolint:gosec // G115: at most 64 (keyIDPattern)
	b = append(b, kid...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(s.resource))) //nolint:gosec // G115: at most maxResource (NewSealer)
	return append(b, s.resource...)
}

func (c Claims) validate() error {
	if c.GrantID == "" || c.Subject == "" || c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return errClaims
	}
	return nil
}
