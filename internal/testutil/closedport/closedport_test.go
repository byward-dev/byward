package closedport

import (
	"errors"
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

// With no unprivileged port below the ephemeral range the test is skipped; with one, that port is
// the address.
func TestNoGapBelowTheEphemeralRangeSkipsTheTest(t *testing.T) {
	saved := ephemeralFirst
	t.Cleanup(func() { ephemeralFirst = saved })
	for _, tc := range []struct {
		name    string
		first   int
		skipped bool
	}{
		{"a range that starts at the lowest unprivileged port", lowest, true},
		{"a range that starts one above it", lowest + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.skipped {
				ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(lowest))
				if err != nil {
					t.Skipf("port %d is in use on this host: %v", lowest, err)
				}
				_ = ln.Close()
			}
			ephemeralFirst = func() (int, error) { return tc.first, nil }
			var addr string
			t.Run("Addr", func(t *testing.T) { addr = Addr(t) }) // a skip ends only this subtest
			if tc.skipped != (addr == "") {
				t.Fatalf("address %q; want skipped %v", addr, tc.skipped)
			}
			if !tc.skipped && addr != "127.0.0.1:"+strconv.Itoa(lowest) {
				t.Fatalf("address %q; want the only port below the range, %d", addr, lowest)
			}
		})
	}
}
