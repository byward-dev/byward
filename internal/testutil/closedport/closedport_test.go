package closedport

import (
	"net"
	"strconv"
	"testing"
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
		{"one port only", "32768\n", 0, false},
		{"three fields", "1 2 3", 0, false},
		{"not a number", "low\t60999", 0, false},
		{"zero", "0\t60999", 0, false},
		{"past the last port", "70000\t80000", 0, false},
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

// The address is an unprivileged loopback port below the ephemeral range, and a dial to it is
// refused at once.
func TestTheAddressIsBelowTheEphemeralRangeAndRefusesADial(t *testing.T) {
	first, err := ephemeralFirst()
	if err != nil {
		t.Fatal(err)
	}
	addr := Addr(t)
	host, p, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(p)
	if host != "127.0.0.1" || port < lowest || port >= first {
		t.Fatalf("address %s; want 127.0.0.1 with a port in [%d, %d)", addr, lowest, first)
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		_ = c.Close()
		t.Fatalf("a dial to %s was accepted", addr)
	}
}
