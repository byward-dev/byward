package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/config"
)

func TestThePtraceWarningIsGivenWhenTheHostLetsProcessesReadEachOther(t *testing.T) {
	for _, tc := range []struct {
		name, goos, scope string
		missing           bool
		want              string // in the message; empty: no warning
	}{
		{name: "ptrace_scope 0 warns", goos: "linux", scope: "0\n", want: "kernel.yama.ptrace_scope is 0"},
		{name: "no Yama warns", goos: "linux", missing: true, want: "the kernel has no Yama"},
		{name: "ptrace_scope 1 is quiet", goos: "linux", scope: "1\n"},
		{name: "ptrace_scope 3 is quiet", goos: "linux", scope: "3"},
		{name: "macOS is quiet", goos: "darwin", scope: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if path != ptraceScopeFile {
					t.Fatalf("read %s, want %s", path, ptraceScopeFile)
				}
				if tc.missing {
					return nil, errors.New("no such file")
				}
				return []byte(tc.scope), nil
			}
			w := ptraceWarning(tc.goos, read)
			if tc.want == "" {
				if w != nil {
					t.Fatalf("warned %q, want no warning", w.Message)
				}
				return
			}
			if w == nil || !strings.Contains(w.Message, tc.want) || !strings.Contains(w.Fix, "kernel.yama.ptrace_scope=1") {
				t.Fatalf("warning %+v, want one saying %q with the sysctl fix", w, tc.want)
			}
		})
	}
}

// Only stdio processes holding downstream tokens make the host's ptrace setting matter.
func TestThePtraceWarningIsGivenOnlyForOnBehalfOfWithAStdioUpstream(t *testing.T) {
	warn := &Warning{Message: "the host lets processes read each other"}
	for _, tc := range []struct {
		name      string
		cfg       config.Config
		hostWarns bool
		want      bool
	}{
		{name: "On-Behalf-Of with a stdio upstream warns", cfg: config.Config{OBOScopes: []string{graphUserRead}, UpstreamCommand: []string{"/bin/server"}}, hostWarns: true, want: true},
		{name: "On-Behalf-Of with an HTTP upstream is quiet", cfg: config.Config{OBOScopes: []string{graphUserRead}}, hostWarns: true},
		{name: "a stdio upstream without On-Behalf-Of is quiet", cfg: config.Config{UpstreamCommand: []string{"/bin/server"}}, hostWarns: true},
		{name: "a host that restricts ptrace is quiet", cfg: config.Config{OBOScopes: []string{graphUserRead}, UpstreamCommand: []string{"/bin/server"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := func() *Warning {
				if tc.hostWarns {
					return warn
				}
				return nil
			}
			if got := isolationWarning(&tc.cfg, host); (got != nil) != tc.want {
				t.Fatalf("warning %v, want one %v", got, tc.want)
			}
		})
	}
}
