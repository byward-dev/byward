//go:build linux || darwin

package stdio

import "time"

// Clock is the time source for idle and kill timers, injectable for tests.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is the subset of *time.Timer the package uses.
type Timer interface {
	Reset(d time.Duration) bool
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time                            { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }
