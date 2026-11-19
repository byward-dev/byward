// Package closedport gives a test a local address nothing listens on, so every dial to it fails at
// once, with no DNS lookup and nothing leaving the machine.
package closedport

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
		_ = ln.Close() // never accepted a connection, so nothing lingers
		// On macOS a listener on the wildcard address shares a port the loopback bind just took, and
		// would accept the dial: keep only a port that refuses it.
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = c.Close()
			continue
		} else if !errors.Is(err, syscall.ECONNREFUSED) {
			continue
		}
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

// parseLinuxRange reads ip_local_port_range, "first<tab>last", two ports with first at most last,
// and returns first.
func parseLinuxRange(s string) (int, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, fmt.Errorf("ip_local_port_range %q: want two ports", s)
	}
	var ports [2]int
	for i, field := range f {
		p, err := strconv.Atoi(field)
		if err != nil || p < 1 || p > 65535 {
			return 0, fmt.Errorf("ip_local_port_range %q: %q is not a port", s, field)
		}
		ports[i] = p
	}
	if ports[0] > ports[1] {
		return 0, fmt.Errorf("ip_local_port_range %q: the first port is past the last", s)
	}
	return ports[0], nil
}
