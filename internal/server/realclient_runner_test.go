package server

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The client runner of the integration lane: no build tag, so its behaviour is checked in `test`
// without Docker (TestRunSigningIn…), and the container tests only add the real clients.

// Per-client budgets. Three clients in sequence stay inside the lane's `go test -timeout 11m`, so
// a slow registry fails the client it slowed, with that client's output.
const (
	installBudget = 90 * time.Second
	runBudget     = 90 * time.Second
)

// runSigningIn runs a client and plays its browser: on a line of its output (stdout and stderr
// together) that holds an authorization URL starting with authorize, it signs in with browse and
// requests the client's callback. A failed step cancels the client, so the test fails at once with
// the client's output. It returns the client's stdout alone, for its answer, and the merged output.
func runSigningIn(t *testing.T, ctx context.Context, cancel context.CancelFunc, browse func(string) (string, error), authorize string, cmd *exec.Cmd) (stdout, output string) {
	t.Helper()
	pr, pw := io.Pipe()
	var stdoutBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.MultiWriter(&stdoutBuf, pw), pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var merged bytes.Buffer
	var signIns int
	var stepErr, scanErr error
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		callback := &http.Client{Timeout: 30 * time.Second}
		seen := map[string]bool{} // a client may print the same URL twice (e.g. after a failed browser open)
		lines := bufio.NewScanner(pr)
		lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for lines.Scan() {
			line := lines.Text()
			merged.WriteString(line + "\n")
			i := strings.Index(line, authorize)
			if i < 0 || stepErr != nil {
				continue
			}
			u := strings.Fields(line[i:])[0]
			if seen[u] {
				continue
			}
			seen[u] = true
			signIns++
			if stepErr = signIn(callback, browse, u); stepErr != nil {
				cancel()
			}
		}
		scanErr = lines.Err()
		_, _ = io.Copy(io.Discard, pr) // keep the client writable after a scan error
	}()
	waitErr := cmd.Wait()
	_ = pw.Close()
	<-scanned
	output = merged.String()
	switch {
	case stepErr != nil:
		t.Fatalf("sign-in: %v\noutput:\n%s", stepErr, output)
	case scanErr != nil:
		t.Fatalf("reading the client's output: %v\noutput:\n%s", scanErr, output)
	case waitErr != nil:
		t.Fatalf("client: %v%s\noutput:\n%s", waitErr, budgetNote(ctx, runBudget), output)
	case signIns != 1:
		t.Fatalf("sign-ins: %d, want exactly 1\noutput:\n%s", signIns, output)
	}
	return stdoutBuf.String(), output
}

// signIn plays the browser for one authorization URL and delivers the redirect to the client.
func signIn(callback *http.Client, browse func(string) (string, error), authorize string) error {
	redirect, err := browse(authorize)
	if err != nil {
		return fmt.Errorf("scripted browser: %w", err)
	}
	res, err := callback.Get(redirect) //nolint:gosec // G107: the client's own loopback callback
	if err != nil {
		return fmt.Errorf("the client's callback %s: %w", redirect, err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode >= http.StatusBadRequest {
		return errors.New("the client's callback answered " + res.Status)
	}
	return nil
}

// budgetNote names an expired budget, so a hang is not read as a crash ("signal: killed").
func budgetNote(ctx context.Context, budget time.Duration) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Sprintf(" (its %s budget ran out)", budget)
	}
	return ""
}

// runSigningIn finds the authorization URL on either stream, signs in once however often it is
// printed, and returns stdout apart from the merged output (the clients' answer check reads stdout).
func TestRunSigningInReadsBothStreamsAndSignsInOnce(t *testing.T) {
	var callbacks int
	callback := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { callbacks++ }))
	t.Cleanup(callback.Close)
	const authorize = "http://127.0.0.1:1/authorize?"
	var browsed []string
	browse := func(u string) (string, error) {
		browsed = append(browsed, u)
		return callback.URL + "/callback?code=c", nil
	}
	script := `echo "Please navigate to: ` + authorize + `x=1" >&2; echo "` + authorize + `x=1"; ` +
		`echo "again: ` + authorize + `x=1 (could not open a browser)" >&2; echo answer`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stdout, output := runSigningIn(t, ctx, cancel, browse, authorize, exec.CommandContext(ctx, "sh", "-c", script))
	if len(browsed) != 1 || browsed[0] != authorize+"x=1" || callbacks != 1 {
		t.Errorf("browsed %q with %d callbacks, want the URL once", browsed, callbacks)
	}
	if want := authorize + "x=1\nanswer\n"; stdout != want {
		t.Errorf("stdout %q, want only the client's stdout %q", stdout, want)
	}
	if !strings.Contains(output, "Please navigate to:") || !strings.Contains(output, "answer") {
		t.Errorf("merged output %q lacks one of the streams", output)
	}
}
