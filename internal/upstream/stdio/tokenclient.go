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
// code; err is set only when there is no answer: the socket cannot be reached, it closed, or what it
// sent is not an answer. ctx bounds the whole exchange.
func AskDownstreamToken(ctx context.Context, path string) (DownstreamToken, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: %w", err)
	}
	defer func() { _ = c.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	// A cancelled ctx without a deadline ends a read that would otherwise wait for the socket.
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	defer stop()
	if _, err := c.Write([]byte("{}\n")); err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: %w", err)
	}
	line, err := bufio.NewReaderSize(c, maxTokenRequest).ReadSlice('\n')
	if err != nil {
		return DownstreamToken{}, fmt.Errorf("token socket: no answer: %w", err)
	}
	return parseTokenAnswer(line)
}

// errBadAnswer is a line from the token socket that is neither a token nor an error code. Its text
// never includes the line, which may hold a token.
var errBadAnswer = errors.New("token socket: the answer is neither a token nor an error code")

// parseTokenAnswer reads one answer line of the token socket.
func parseTokenAnswer(line []byte) (DownstreamToken, error) {
	var a struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		Error       string `json:"error"`
	}
	if json.Unmarshal(line, &a) != nil {
		return DownstreamToken{}, errBadAnswer
	}
	switch {
	case a.Error != "" && a.AccessToken == "":
		return DownstreamToken{Error: a.Error}, nil
	case a.Error != "" || a.AccessToken == "":
		return DownstreamToken{}, errBadAnswer
	}
	exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return DownstreamToken{}, errBadAnswer
	}
	return DownstreamToken{AccessToken: a.AccessToken, ExpiresAt: exp}, nil
}
