//go:build linux || darwin

package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// AskDownstreamToken asks the token socket at path for a downstream token, as an upstream process or
// one of its descendants does (byward downstream-token, #181). An answer is the token or its error
// code; err is set only when there is no answer: the socket cannot be reached, it closed or ctx ended
// before it answered, or what it sent is not an answer. ctx bounds the whole exchange.
func AskDownstreamToken(ctx context.Context, path string) (DownstreamToken, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: %w", err)
	}
	defer func() { _ = c.Close() }()
	// The end of ctx, by its deadline or a cancel, ends a write or read still waiting on the socket.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	if _, err := c.Write([]byte("{}\n")); err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: %w", ended(ctx, err))
	}
	line, err := bufio.NewReaderSize(c, maxTokenAnswer).ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return DownstreamToken{}, errLongAnswer
	}
	if err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: no answer: %w", ended(ctx, err))
	}
	return parseTokenAnswer(line)
}

// ended is ctx's error once ctx has ended, which is why the socket's deadline passed, or else err.
func ended(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// maxTokenAnswer bounds the answer line the client reads. It holds the whole access token, whose
// size the IdP decides, so it is far above maxTokenRequest, which bounds only the request.
const maxTokenAnswer = 64 << 10

// errLongAnswer is an answer line longer than maxTokenAnswer.
var errLongAnswer = fmt.Errorf("token socket: the answer is longer than %d KiB", maxTokenAnswer>>10)

// errBadAnswer is a line from the token socket that is neither a token nor an error code. Its text
// never includes the line, which may hold a token.
var errBadAnswer = errors.New("token socket: the answer is neither a token nor an error code")

// parseTokenAnswer reads one answer line of the token socket. The error code and the token are
// printed as they are (byward downstream-token), so a code must be lowercase letters and _, and a
// token printable ASCII without spaces: a line break or a terminal escape is a bad answer.
func parseTokenAnswer(line []byte) (DownstreamToken, error) {
	var a tokenAnswer
	if json.Unmarshal(line, &a) != nil {
		return DownstreamToken{}, errBadAnswer
	}
	switch {
	case a.Error != "" && a.AccessToken == "" && only(a.Error, isCodeByte):
		return DownstreamToken{Error: a.Error}, nil
	case a.Error != "" || a.AccessToken == "" || !only(a.AccessToken, isTokenByte):
		return DownstreamToken{}, errBadAnswer
	}
	exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return DownstreamToken{}, errBadAnswer
	}
	return DownstreamToken{AccessToken: a.AccessToken, ExpiresAt: exp}, nil
}

// only reports whether every byte of s passes ok.
func only(s string, ok func(byte) bool) bool {
	for i := range len(s) {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func isCodeByte(b byte) bool  { return b >= 'a' && b <= 'z' || b == '_' }
func isTokenByte(b byte) bool { return b > ' ' && b < 0x7f }
