package logging

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestLimiterAllowsABurstPerSourceThenReportsTheSuppressedCount(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := NewLimiter(2, time.Minute, 100, c.now)
	for i, want := range []bool{true, true, false, false, false} {
		if ok, n := l.Allow("192.0.2.1"); ok != want || n != 0 {
			t.Fatalf("event %d: ok=%v suppressed=%d, want ok=%v suppressed=0", i, ok, n, want)
		}
	}
	if ok, _ := l.Allow("192.0.2.2"); !ok {
		t.Fatal("another source was limited by the first one")
	}
	c.advance(time.Minute)
	if ok, n := l.Allow("192.0.2.1"); !ok || n != 3 {
		t.Fatalf("after the window: ok=%v suppressed=%d, want true and 3", ok, n)
	}
	if ok, n := l.Allow("192.0.2.1"); !ok || n != 0 {
		t.Fatalf("the suppressed count was reported twice: ok=%v suppressed=%d", ok, n)
	}
}

func TestLimiterBoundsTheNumberOfSources(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	l := NewLimiter(1, time.Minute, 2, c.now)
	l.Allow("a")
	l.Allow("b")
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("a third source was tracked beyond maxKeys while the others' windows were open")
	}
	c.advance(time.Minute)
	if ok, _ := l.Allow("c"); !ok {
		t.Fatal("sources whose windows ended were not dropped to make room")
	}
	if ok, _ := l.Allow("d"); !ok {
		t.Fatal("after the old windows ended, a second new source must fit (a and b were dropped)")
	}
	if ok, _ := l.Allow("e"); ok {
		t.Fatal("a third live source was admitted beyond maxKeys")
	}
}
