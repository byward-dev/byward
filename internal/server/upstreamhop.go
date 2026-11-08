package server

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/byward-dev/byward/internal/config"
	"github.com/byward-dev/byward/internal/doctor"
)

// inClear names the secrets every request to the HTTP upstream carries: what a plain-http hop
// exposes to anyone on the path.
func inClear(cfg *config.Config) []string {
	var s []string
	if !cfg.NoAuth {
		s = append(s, "the identity assertion")
	}
	if cfg.UpstreamCredential != "" {
		s = append(s, "the upstream credential")
	}
	if len(cfg.OBOScopes) > 0 {
		s = append(s, "an On-Behalf-Of token for a downstream API")
	}
	return s
}

// plainHTTPUpstream is a warning when the HTTP upstream is reached over plain http at a public
// address while requests carry secrets. A host that does not resolve gets none: whether it is public
// cannot be told, and an upstream often starts after the proxy.
func plainHTTPUpstream(ctx context.Context, cfg *config.Config, resolve func(context.Context, string) ([]netip.Addr, error)) (Warning, bool) {
	secrets := inClear(cfg)
	if cfg.UpstreamCommand != nil || cfg.UpstreamURL.Scheme != "http" || len(secrets) == 0 {
		return Warning{}, false
	}
	host := cfg.UpstreamURL.Hostname()
	addrs := []netip.Addr{}
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a)
	} else {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		if addrs, err = resolve(ctx, host); err != nil {
			return Warning{}, false
		}
	}
	fix := "use https, a service mesh, or a private network the upstream alone is on (docs/how-to/harden-a-deployment.md, \"Protect the upstream hop\")"
	if !cfg.NoAuth {
		fix += "; with https the assertion's aud becomes the new URL"
	}
	for _, a := range addrs {
		if a = a.Unmap(); !notPublic(a) {
			return Warning{Setting: "BYWARD_UPSTREAM_URL", Fix: fix,
				Message: fmt.Sprintf("the upstream is reached over plain http at the public address %s (%s), so these travel in clear: %s", a, host, strings.Join(secrets, ", "))}, true
		}
	}
	return Warning{}, false
}

// upstreamHopResult is plainHTTPUpstream for doctor; nil when there is nothing to warn about.
func upstreamHopResult(ctx context.Context, cfg *config.Config, resolve func(context.Context, string) ([]netip.Addr, error)) []doctor.Result {
	w, ok := plainHTTPUpstream(ctx, cfg, resolve)
	if !ok {
		return nil
	}
	return []doctor.Result{{Class: doctor.ClassProxy, Name: "upstream hop", Status: doctor.Warn, Message: w.Message, Fix: warningFix(w)}}
}
