package agent

import "time"

// Clock is the agent framework's only source of time: certificate validity,
// the main-loop tick, liveness and the stop drain all read it, so tests drive
// them with a manual clock instead of sleeping. It has the same shape as the
// fake agents' clock (internal/fake) and is a superset of the ledger's.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// NewTimer returns a timer that delivers the time on C once d has passed.
	NewTimer(d time.Duration) Timer
	// AfterFunc calls f once d has passed. The returned Timer's C is nil.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending event on a Clock.
type Timer interface {
	// C delivers the fire time; nil for AfterFunc timers.
	C() <-chan time.Time
	// Stop prevents the timer from firing. It reports whether the call
	// stopped the timer.
	Stop() bool
}

// SystemClock returns a Clock backed by the time package.
func SystemClock() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

func (systemClock) AfterFunc(d time.Duration, f func()) Timer {
	return systemTimer{time.AfterFunc(d, f)}
}

type systemTimer struct{ t *time.Timer }

func (s systemTimer) C() <-chan time.Time { return s.t.C }
func (s systemTimer) Stop() bool          { return s.t.Stop() }
