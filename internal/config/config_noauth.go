package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// inContainer reports whether the proxy runs in a container (Docker or Podman marker file) that
// has its own network namespace. With host networking (`--network host`) a 0.0.0.0 listener binds
// the host's interfaces, so that does not count.
func inContainer(readFile readFileFunc) bool {
	if readFile == nil {
		return false
	}
	for _, p := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := readFile(p); err == nil {
			return ownNetwork(readFile)
		}
	}
	return false
}

// ownNetwork reports whether every network interface is one a container's own namespace has:
// lo, ethN, and the kernel's tunnel placeholders. Anything else (docker0, bond0, wlan0, br-…) or
// an unreadable list means host networking, and the answer is no: the check fails closed.
// Measured 2026-11-06 on Docker 28.4: bridge shows lo, eth0 and the placeholders; host adds
// docker0, bond0, dummy0, teql0 and services1.
func ownNetwork(readFile readFileFunc) bool {
	b, err := readFile("/proc/self/net/dev")
	if err != nil {
		return false
	}
	placeholders := map[string]bool{"lo": true, "tunl0": true, "gre0": true, "gretap0": true, "erspan0": true,
		"ip_vti0": true, "ip6_vti0": true, "sit0": true, "ip6tnl0": true, "ip6gre0": true}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 3 {
		return false
	}
	for _, l := range lines[2:] {
		name, _, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if placeholders[name] {
			continue
		}
		if rest, isEth := strings.CutPrefix(name, "eth"); isEth && rest != "" && strings.Trim(rest, "0123456789") == "" && virtual(readFile, name) {
			continue
		}
		return false
	}
	return true
}

// virtual reports whether an interface has a peer (veth, macvlan, ipvlan: iflink differs from
// ifindex). A host's physical NIC, as seen with host networking, has iflink == ifindex; that, or
// an unreadable value, answers no. Measured on Docker 28.4: bridge eth0 ifindex=11 iflink=25,
// host-network eth0 ifindex=4 iflink=4.
func virtual(readFile readFileFunc, name string) bool {
	index, err1 := readFile("/sys/class/net/" + name + "/ifindex")
	link, err2 := readFile("/sys/class/net/" + name + "/iflink")
	i, l := strings.TrimSpace(string(index)), strings.TrimSpace(string(link))
	return err1 == nil && err2 == nil && i != "" && l != "" && i != l
}

// checkNoAuth fences --insecure-no-auth in (ADR-0027): the public URL is loopback, the listen
// address is loopback unless the proxy runs in a container, the Host and Origin allowlists stay
// loopback-only, and no authentication setting is present.
func checkNoAuth(c *Config, v *Values) []error {
	const env = "BYWARD_INSECURE_NO_AUTH"
	var errs []error
	if !isLoopback(c.PublicURL.Hostname()) {
		errs = append(errs, errorf("%s: BYWARD_PUBLIC_URL must be a loopback URL, e.g. http://localhost:8080/mcp", env))
	}
	host, port, err := net.SplitHostPort(c.Listen)
	switch {
	case err != nil:
		errs = append(errs, errorf("%s: BYWARD_LISTEN must be a loopback host:port such as 127.0.0.1:8080", env))
	case isLoopback(host):
	case c.InContainer:
		// The host port is the public URL's; the container port is the listen address's.
		hostPort := c.PublicURL.Port()
		if hostPort == "" {
			hostPort = map[string]string{"http": "80", "https": "443"}[c.PublicURL.Scheme]
		}
		c.Relaxations = append(c.Relaxations, fmt.Sprintf(
			"listening on %s inside a container: publish the port on loopback only, e.g. docker run -p 127.0.0.1:%s:%s; anyone who can reach the published port can use the upstream", c.Listen, hostPort, port))
	default:
		errs = append(errs, errorf("%s: BYWARD_LISTEN must be a loopback address such as 127.0.0.1:8080 (non-loopback only inside a container with its own network, not --network host)", env))
	}
	for _, h := range c.AllowedHosts {
		if !isLoopback(Hostname(h)) {
			errs = append(errs, errorf("%s: BYWARD_ALLOWED_HOSTS may only list loopback hosts, got %q", env, h))
		}
	}
	for _, o := range c.AllowedOrigins {
		if u, err := url.Parse(o); err != nil || !isLoopback(u.Hostname()) {
			errs = append(errs, errorf("%s: BYWARD_ALLOWED_ORIGINS may only list loopback origins, got %q", env, o))
		}
	}
	for _, val := range v.Effective() {
		if val.Setting.Auth && val.Source != SourceDefault {
			errs = append(errs, errorf("%s cannot be combined with %s: remove one of them", env, val.Setting.Env()))
		}
	}
	if len(errs) == 0 {
		c.Relaxations = append(c.Relaxations, "AUTHENTICATION IS OFF: anyone who can reach "+c.PublicURL.String()+" can use the upstream, and the upstream receives no identity")
	}
	return errs
}
