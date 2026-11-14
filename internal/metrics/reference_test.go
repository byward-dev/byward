package metrics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/byward-dev/byward/internal/testutil/reftable"
)

// metric is one metric metrics.go declares: its name and Prometheus type.
type metric struct{ name, kind string }

// declaredMetrics is every metric metrics.go declares, in source order: each prometheus
// CounterOpts, GaugeOpts or HistogramOpts literal and its Name.
func declaredMetrics(t *testing.T) []metric {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "metrics.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var out []metric
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, _ := sel.X.(*ast.Ident); pkg == nil || pkg.Name != "prometheus" || !strings.HasSuffix(sel.Sel.Name, "Opts") {
			return true
		}
		kind := strings.ToLower(strings.TrimSuffix(sel.Sel.Name, "Opts"))
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if k, _ := kv.Key.(*ast.Ident); !ok || k == nil || k.Name != "Name" {
				continue
			}
			v, ok := kv.Value.(*ast.BasicLit)
			if !ok || v.Kind != token.STRING {
				t.Fatalf("a metric name that is not a string literal: %#v", kv.Value)
			}
			name, err := strconv.Unquote(v.Value)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, metric{name: name, kind: kind})
		}
		return true
	})
	return out
}

// The metrics table in the observability reference lists every metric with its type, in the order
// metrics.go declares them; the labels are written by hand.
func TestTheMetricsReferenceIsCurrent(t *testing.T) {
	declared := declaredMetrics(t)
	if len(declared) < 10 {
		t.Fatalf("found %d metrics in metrics.go, want every one", len(declared))
	}
	names := make([]string, 0, len(declared))
	kind := map[string]string{}
	for _, m := range declared {
		names = append(names, m.name)
		kind[m.name] = m.kind
	}
	reftable.Sync(t, "../../docs/reference/observability.md", "## Metrics", 0, names, func(name string, old []string) []string {
		labels := reftable.Todo
		if len(old) > 2 {
			labels = old[2]
		}
		return []string{"`" + name + "`", kind[name], labels}
	})
}
