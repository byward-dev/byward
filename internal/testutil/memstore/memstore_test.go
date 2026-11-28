package memstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/byward-dev/byward/internal/store"
	"github.com/byward-dev/byward/internal/store/storetest"
)

var errBoom = errors.New("errBoom")

// call invokes store.Store method name on s with zero arguments (a live context) and returns the
// error it returns last.
func call(s *Store, name string) error { return callIn(s, context.Background(), name) }

// callIn is call with ctx as the method's context.
func callIn(s *Store, ctx context.Context, name string) error {
	m := reflect.ValueOf(s).MethodByName(name)
	args := make([]reflect.Value, m.Type().NumIn())
	for i := range args {
		in := m.Type().In(i)
		if in == reflect.TypeFor[context.Context]() {
			args[i] = reflect.ValueOf(ctx)
		} else {
			args[i] = reflect.Zero(in)
		}
	}
	out := m.Call(args)
	err, _ := out[len(out)-1].Interface().(error)
	return err
}

// Every store.Store method honours Fail (and only its own) and Down, so a method added to the
// interface but left unwrapped, or a wrapper checking the wrong name, fails here.
func TestEveryMethodHonoursFailAndDown(t *testing.T) {
	iface := reflect.TypeFor[store.Store]()
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		t.Run(name, func(t *testing.T) {
			s := New()
			s.Fail(errBoom, name)
			if err := call(s, name); !errors.Is(err, errBoom) {
				t.Errorf("Fail(%s): %v, want errBoom", name, err)
			}
			other := "Grant"
			if name == other {
				other = "Consent"
			}
			if err := call(s, other); errors.Is(err, errBoom) {
				t.Errorf("Fail(%s) also failed %s", name, other)
			}
			s.Fail(nil, name)
			s.Down(errBoom)
			if err := call(s, name); !errors.Is(err, errBoom) {
				t.Errorf("Down: %s returned %v, want errBoom", name, err)
			}
		})
	}
}

// AfterCall refuses a name that is not a store.Store method, so a typo cannot hook nothing.
func TestAfterCallRefusesAnUnknownMethod(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("AfterCall with an unknown method name did not panic")
		}
	}()
	New().AfterCall("Grnat", func(context.Context) {})
}

// A name that is not a store.Store method is refused, so a typo cannot silently inject nothing.
func TestFailRefusesAnUnknownMethod(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Fail with an unknown method name did not panic")
		}
	}()
	New().Fail(errBoom, "Grnat")
}

// The embedded store bypasses every failure; OnCreateGrant sees each grant before it is stored;
// GrantIDs records what was created.
func TestTheEmbeddedStoreBypassesFailuresAndHooksSeeGrants(t *testing.T) {
	ctx, s := context.Background(), New()
	var hooked []string
	s.OnCreateGrant(func(g *store.Grant) { hooked = append(hooked, g.ID); g.Subject = "rewritten" })
	now := time.Now()
	if _, err := s.CreateGrant(ctx, store.Grant{ID: "g1", ClientID: "c", Subject: "s", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s.Down(errBoom)
	g, err := s.Store.Grant(ctx, "g1")
	if err != nil {
		t.Fatalf("the embedded store while down: %v, want no failure", err)
	}
	if g.Subject != "rewritten" || len(hooked) != 1 {
		t.Fatalf("hook ran %v, stored subject %q; want it to see and rewrite g1", hooked, g.Subject)
	}
	if ids := s.GrantIDs(); len(ids) != 1 || ids[0] != "g1" {
		t.Fatalf("GrantIDs %v, want [g1]", ids)
	}
}

// Every store.Store method fails under an ended context, as the SQL stores do, and runs its own
// AfterCall hook (and no other method's) once it returns, so a wrapper that passes the wrong
// context, or names the wrong method, fails here (#693).
func TestEveryMethodFailsUnderAnEndedContextAndRunsItsAfterCall(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	iface := reflect.TypeFor[store.Store]()
	for i := range iface.NumMethod() {
		name := iface.Method(i).Name
		t.Run(name, func(t *testing.T) {
			s := New()
			if err := callIn(s, ended, name); !errors.Is(err, context.Canceled) {
				t.Errorf("%s under an ended context: %v, want context.Canceled", name, err)
			}
			other := "Grant"
			if name == other {
				other = "Consent"
			}
			own, others := 0, 0
			s.AfterCall(name, func(context.Context) { own++ })
			s.AfterCall(other, func(context.Context) { others++ })
			s.Fail(errBoom, name)
			_ = call(s, name)
			if own != 0 {
				t.Errorf("AfterCall: %s ran its hook although Fail failed the call first", name)
			}
			s.Fail(nil, name)
			_ = call(s, name)
			if own != 1 || others != 0 {
				t.Errorf("AfterCall: %s ran its own hook %d times and %s's %d times, want 1 and 0", name, own, other, others)
			}
		})
	}
}

// The store keeps every contract of store.Store, the one for an ended context included (storetest):
// the broker tests that use it see what a SQL store would do.
func TestTheStoreKeepsEveryStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Store { return New() })
}
