package servingcert

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"
)

// Reloader serves the certificate in Files and picks up a replaced pair at the next handshake. At
// every handshake it stats both files, following symlinks, so a Kubernetes volume update (an
// atomic swap of the ..data link) counts as a change. A pair that fails to load or is outside its
// validity is never served: the previous one stays, and the failure is logged once per state of
// the files. A pair refused only because it is not valid yet is tried again once it is.
type Reloader struct {
	files Files
	o     Options

	mu      sync.Mutex
	current *Pair
	seen    state     // the files as they were at the last attempt, served or not
	retryAt time.Time // when a pair refused as not yet valid becomes servable; zero for none
}

// Options are what a Reloader needs besides its files.
type Options struct {
	Now func() time.Time
	Log *slog.Logger
	// CheckKey refuses a key file the proxy must not use, such as one other users can read; nil
	// checks nothing. A replaced key that fails it is not served.
	CheckKey func(path string) error
	// Served is told of each pair served after a change, to warn about it as startup does; nil for
	// none.
	Served func(*Pair)
}

// Load reads and checks f at o.Now(): an error is a pair the proxy must not start with.
func Load(f Files, o Options) (*Reloader, error) {
	seen := stat(f)
	p, err := o.load(f)
	if err != nil {
		return nil, err
	}
	return &Reloader{files: f, o: o, current: p, seen: seen}, nil
}

// load is the pair in f if it may be served now.
func (o Options) load(f Files) (*Pair, error) {
	if o.CheckKey != nil {
		if err := o.CheckKey(f.Key); err != nil {
			return nil, err
		}
	}
	p, err := Read(f)
	if err != nil {
		return nil, err
	}
	if err := p.Validity(o.Now()); err != nil {
		return nil, err
	}
	return p, nil
}

// Current is the pair being served.
func (r *Reloader) Current() *Pair {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// GetCertificate is tls.Config.GetCertificate: the current pair, reloaded first if the files
// changed. The files are stat'ed under the lock, so a handshake never compares a state older than
// the one another handshake has just loaded.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := stat(r.files); s != r.seen || (!r.retryAt.IsZero() && !r.o.Now().Before(r.retryAt)) {
		r.reload(s)
	}
	return r.current.cert, nil
}

// reload tries the files, which were in state s before they were read; r.mu is held.
func (r *Reloader) reload(s state) {
	changed := s != r.seen
	r.seen, r.retryAt = s, time.Time{}
	p, err := r.o.load(r.files)
	if err != nil {
		if at, ok := ServableAt(err); ok {
			r.retryAt = at
		}
		if changed {
			r.o.Log.Warn("the TLS certificate files changed but cannot be served; serving the previous certificate",
				"cert_file", r.files.Cert, "key_file", r.files.Key, "error", err.Error())
		}
		return
	}
	same := slices.EqualFunc(p.cert.Certificate, r.current.cert.Certificate, bytes.Equal)
	r.current = p
	if same { // a touch or a chmod: the same certificate, so nothing new to say
		return
	}
	_, notAfter := p.FirstExpiry()
	r.o.Log.Info("serving a new TLS certificate", "cert_file", r.files.Cert, "subject", p.chain[0].Subject.String(),
		"not_after", notAfter.UTC().Format(time.RFC3339))
	if r.o.Served != nil {
		r.o.Served(p)
	}
}

// state identifies both files' contents without reading them: an unchanged state means an
// unchanged pair.
type state struct{ cert, key fileState }

func stat(f Files) state { return state{statFile(f.Cert), statFile(f.Key)} }

// fileState is what stat(2) says about a file, symlinks followed: its identity (device and inode
// where the system has them), size, modification time and mode, or the error. The mode counts
// because a key refused for its permissions is served once they are fixed, which a chmod does
// without touching the time.
type fileState struct {
	id      fileID
	size    int64
	modTime int64 // in nanoseconds; a time.Time does not compare with ==
	mode    os.FileMode
	err     string
}

func statFile(path string) fileState {
	fi, err := os.Stat(path)
	if err != nil {
		return fileState{err: err.Error()}
	}
	return fileState{id: idOf(fi), size: fi.Size(), modTime: fi.ModTime().UnixNano(), mode: fi.Mode()}
}
