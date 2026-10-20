package fuzzer

import (
	"testing"
	"time"
)

// TestConfigureMaxRate verifies the global rate limiter paces requests: a run
// of throttle calls at N req/sec should take at least a few tick intervals.
func TestConfigureMaxRate(t *testing.T) {
	const maxRate = 50 // 20ms per tick
	Configure(0, maxRate)
	defer Configure(0, 0) // reset shared state for other tests

	start := time.Now()
	for i := 0; i < 5; i++ {
		throttle()
	}
	elapsed := time.Since(start)

	// Five ticks at 20ms is ~100ms; require at least three intervals to prove
	// pacing happened, with a generous ceiling to stay non-flaky under load.
	if min := 3 * (time.Second / maxRate); elapsed < min {
		t.Errorf("5 throttled calls took %s, expected at least %s", elapsed, min)
	}
	if elapsed > 2*time.Second {
		t.Errorf("5 throttled calls took %s, far longer than expected", elapsed)
	}
}

// TestConfigureUnlimited verifies that with no rate/delay configured, throttle
// is effectively free.
func TestConfigureUnlimited(t *testing.T) {
	Configure(0, 0)

	start := time.Now()
	for i := 0; i < 1000; i++ {
		throttle()
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("1000 unthrottled calls took %s, expected near-instant", elapsed)
	}
}

// TestConfigureDelay verifies the per-request delay is applied.
func TestConfigureDelay(t *testing.T) {
	Configure(10*time.Millisecond, 0)
	defer Configure(0, 0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		throttle()
	}
	if min := 5 * 10 * time.Millisecond; time.Since(start) < min {
		t.Errorf("5 delayed calls took %s, expected at least %s", time.Since(start), min)
	}
}
