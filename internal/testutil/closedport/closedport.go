// Package closedport gives a test a local address nothing listens on, so every dial to it fails at
// once, with no DNS lookup and nothing leaving the machine.
package closedport

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// lowest is the first port that is not privileged.
const lowest = 1024

// darwinFirst is macOS's documented first ephemeral port, for when sysctl cannot say.
const darwinFirst = 49152

// Addr is a loopback host:port nothing listens on. The port lies below the host's ephemeral range,
// from which a listen on port 0 takes its port, so no other test can start listening on it while
// this one runs (#388): a port freed a moment ago can be handed out again. With no unprivileged port
// below that range, t is skipped.
func Addr(t testing.TB) string {
	t.Helper()
	first, err := ephemeralFirst()
	if err != nil {
		t.Fatalf("the ephemeral port range: %v", err)
	}
	if first <= lowest {
		t.Skipf("no unprivileged port lies below the ephemeral range, which starts at %d", first)
	}
	for range 100 {
		port := lowest + rand.IntN(first-lowest) //nolint:gosec // G404: a test port, not a secret
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue // in use
		}
		addr := ln.Addr().String()
		_ = ln.Close() // never accepted a connection, so nothing lingers and a dial is refused
		return addr
	}
	t.Fatalf("no free port below %d after 100 tries", first)
	return ""
}

// ephemeralFirst is the first port of the host's ephemeral range, read once per process.
var ephemeralFirst = sync.OnceValues(func() (int, error) {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if err != nil {
			return 0, err
		}
		return parseLinuxRange(string(b))
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "net.inet.ip.portrange.first").Output()
		if err != nil {
			return darwinFirst, nil //nolint:nilerr // the documented default when sysctl cannot say
		}
		first, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			return darwinFirst, nil //nolint:nilerr // the documented default when sysctl's answer is not a port
		}
		return first, nil
	}
	return 0, fmt.Errorf("unknown on %s", runtime.GOOS)
})

// parseLinuxRange reads ip_local_port_range, "first<tab>last", and returns first.
func parseLinuxRange(s string) (int, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, fmt.Errorf("ip_local_port_range %q: want two ports", s)
	}
	first, err := strconv.Atoi(f[0])
	if err != nil || first < 1 || first > 65535 {
		return 0, fmt.Errorf("ip_local_port_range %q: the first is not a port", s)
	}
	return first, nil
}
