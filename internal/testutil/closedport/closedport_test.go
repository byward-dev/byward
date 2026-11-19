package closedport

import (
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestLinuxsPortRangeIsReadAsItsFirstPort(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     int
		ok       bool
	}{
		{"the default, as the kernel writes it", "32768\t60999\n", 32768, true},
		{"a widened range", "1024\t65535\n", 1024, true},
		{"spaces instead of a tab", "  40000   50000  ", 40000, true},
		{"the lowest port", "1\t60999", 1, true},
		{"the last port alone", "65535\t65535", 65535, true},
		{"one port only", "32768\n", 0, false},
		{"three fields", "1 2 3", 0, false},
		{"not a number", "low\t60999", 0, false},
		{"a last that is not a number", "32768\thigh", 0, false},
		{"zero", "0\t60999", 0, false},
		{"one past the last port", "65536\t65536", 0, false},
		{"a last past the last port", "32768\t65536", 0, false},
		{"the first past the last", "40000\t30000", 0, false},
		{"empty", "", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLinuxRange(tc.in)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("parseLinuxRange(%q) = %d, %v; want %d, ok %v", tc.in, got, err, tc.want, tc.ok)
			}
		})
	}
}

// Each address is an unprivileged loopback port below the ephemeral range, and a dial to it is
// refused at once. The port is random, so many are drawn.
func TestTheAddressIsBelowTheEphemeralRangeAndRefusesADial(t *testing.T) {
	first, err := ephemeralFirst()
	if err != nil {
		t.Fatal(err)
	}
	for range 200 {
		addr := Addr(t)
		host, p, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(p)
		if host != "127.0.0.1" || port < lowest || port >= first {
			t.Fatalf("address %s; want 127.0.0.1 with a port in [%d, %d)", addr, lowest, first)
		}
	}
	addr := Addr(t)
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = c.Close()
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("a dial to %s: %v; want it refused", addr, err)
	}
}

// The address is a port in [lo, first) that refuses a dial: with none in the range the test is
// skipped, and a port that a listener on every address holds is never it. A loopback bind to that
// port succeeds on macOS, where the dial would be accepted; on Linux the bind fails already. The
// ports are random, so overlapping runs of this test do not take each other's.
func TestTheAddressIsAPortInTheRangeThatRefusesADial(t *testing.T) {
	for _, tc := range []struct {
		name string
		span int  // first - lo
		held bool // a wildcard listener holds lo
		want int  // the port as lo+want; -1: skipped
	}{
		{"no port in the range skips the test", 0, false, -1},
		{"the only free port is the address", 1, false, 0},
		{"a port a wildcard listener holds is never the address", 2, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo := freePair(t)
			if tc.held {
				w, err := net.Listen("tcp", ":"+strconv.Itoa(lo))
				if err != nil {
					t.Skipf("port %d was taken: %v", lo, err)
				}
				t.Cleanup(func() { _ = w.Close() })
			}
			want := ""
			if tc.want >= 0 {
				want = "127.0.0.1:" + strconv.Itoa(lo+tc.want)
			}
			for range 20 {
				var addr string
				var skipped bool
				t.Run("addrIn", func(t *testing.T) { // a skip ends only this subtest
					defer func() { skipped = t.Skipped() }()
					addr = addrIn(t, lo, lo+tc.span)
				})
				if addr != want || skipped != (want == "") {
					t.Fatalf("address %q, skipped %v; want %q", addr, skipped, want)
				}
			}
		})
	}
}

// freePair is a random unprivileged port below the ephemeral range such that it and the next both
// refuse a dial now.
func freePair(t *testing.T) int {
	t.Helper()
	first, err := ephemeralFirst()
	if err != nil {
		t.Fatal(err)
	}
	if first-lowest < 2 {
		t.Skipf("fewer than two unprivileged ports lie below the ephemeral range, which starts at %d", first)
	}
	for range 100 {
		lo := lowest + rand.IntN(first-lowest-1) //nolint:gosec // G404: a test port, not a secret
		if refused(addrOf(lo)) && refused(addrOf(lo+1)) {
			return lo
		}
	}
	t.Skipf("no two free ports below %d", first)
	return 0
}

func addrOf(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

// refused tells a held port from a free one, as Addr must.
func TestRefusedTellsAHeldPortFromAFreeOne(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if refused(ln.Addr().String()) {
		t.Errorf("%s, which a listener holds, counts as refused", ln.Addr())
	}
	if free := Addr(t); !refused(free) {
		t.Errorf("%s, a closed port, does not count as refused", free)
	}
}

// refused reports whether addr is free to bind and a dial to it is refused, as Addr requires.
func refused(addr string) bool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = ln.Close()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = c.Close()
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}
