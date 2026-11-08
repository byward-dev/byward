package server

import (
	"os"

	"runtime"
	"strings"

	"github.com/byward-dev/byward/internal/config"
)

// ptraceScopeFile is the host's Yama setting. It is host-wide: a container sees the host's value.
const ptraceScopeFile = "/proc/sys/kernel/yama/ptrace_scope"

// ptraceWarning is the warning for On-Behalf-Of with a stdio upstream on a Linux host that lets a
// process attach to any other of its uid: every upstream process runs as byward's uid, so one
// user's process could read another's memory, and with it the downstream token it holds. nil when
// the host restricts ptrace, or off Linux. byward warns and does not refuse: the operator may
// isolate processes by other means (docs/how-to/harden-a-deployment.md §10).
func ptraceWarning(goos string, read func(string) ([]byte, error)) *Warning {
	if goos != "linux" {
		return nil
	}
	b, err := read(ptraceScopeFile)
	scope := strings.TrimSpace(string(b))
	var why string
	switch {
	case err != nil:
		why = "the kernel has no Yama (" + ptraceScopeFile + " cannot be read)"
	case scope == "0":
		why = "kernel.yama.ptrace_scope is 0"
	default:
		return nil
	}
	return &Warning{Message: "stdio upstream processes can read each other's memory: " + why + ", and every process runs as byward's uid, so one user's process could read another user's downstream token",
		Setting: "BYWARD_OBO_SCOPES",
		Fix:     "set kernel.yama.ptrace_scope=1 on the host, or isolate the upstream processes by other means (docs/how-to/harden-a-deployment.md §10)"}
}

// isolationWarning is host's ptrace warning when On-Behalf-Of hands downstream tokens to stdio
// processes, which then hold them in memory; nil for an HTTP upstream or without On-Behalf-Of.
func isolationWarning(cfg *config.Config, host func() *Warning) *Warning {
	if len(cfg.OBOScopes) == 0 || cfg.UpstreamCommand == nil {
		return nil
	}
	return host()
}

// hostPtraceWarning is ptraceWarning for this host; tests replace it.
var hostPtraceWarning = func() *Warning { return ptraceWarning(runtime.GOOS, os.ReadFile) }
