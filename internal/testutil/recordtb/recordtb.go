// Package recordtb runs a test helper against a testing.TB that records what the helper reports
// instead of failing the test, so a test can check that a helper fails, and how.
package recordtb

import (
	"fmt"
	"runtime"
	"testing"
)

// Report is what a helper reported: its errors, which it carried on after, and its fatals, of which
// there is at most one, since a fatal ends the helper.
type Report struct {
	Errors, Fatals []string
}

// Failed says whether the helper reported anything.
func (r Report) Failed() bool { return len(r.Errors)+len(r.Fatals) > 0 }

// Run runs check against a recorder on its own goroutine, so that a fatal can end it with
// runtime.Goexit as testing does, and returns what it reported. Everything a recorder does not
// record (TempDir, Name, Cleanup, ...) goes to t.
func Run(t testing.TB, check func(testing.TB)) Report {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		check(r)
	}()
	<-done
	return r.rep
}

// recorder records Error, Fail and their kin as errors, and Fatal, FailNow and Skip and their kin
// as fatals, each fatal ending the goroutine. None of them reaches the real test: its FailNow and
// SkipNow must run on the test's own goroutine, and Run's is not it.
type recorder struct {
	testing.TB
	rep Report
}

func (r *recorder) Helper() {}

func (r *recorder) Error(args ...any)                 { r.error(fmt.Sprint(args...)) }
func (r *recorder) Errorf(format string, args ...any) { r.error(fmt.Sprintf(format, args...)) }
func (r *recorder) Fail()                             { r.error("Fail") }

func (r *recorder) Fatal(args ...any)                 { r.fatal(fmt.Sprint(args...)) }
func (r *recorder) Fatalf(format string, args ...any) { r.fatal(fmt.Sprintf(format, args...)) }
func (r *recorder) FailNow()                          { r.fatal("FailNow") }
func (r *recorder) Skip(args ...any)                  { r.fatal("skipped: " + fmt.Sprint(args...)) }
func (r *recorder) Skipf(format string, args ...any) {
	r.fatal("skipped: " + fmt.Sprintf(format, args...))
}
func (r *recorder) SkipNow() { r.fatal("skipped") }

func (r *recorder) error(msg string) { r.rep.Errors = append(r.rep.Errors, msg) }

func (r *recorder) fatal(msg string) {
	r.rep.Fatals = append(r.rep.Fatals, msg)
	runtime.Goexit()
}
