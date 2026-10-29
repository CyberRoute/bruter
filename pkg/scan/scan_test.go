package scan

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CyberRoute/bruter/pkg/xss"
)

// withScanner swaps the package scanner for the duration of a test.
func withScanner(fn func(context.Context, string, xss.Options) (*xss.Result, error)) func() {
	prev := scanner
	scanner = fn
	return func() { scanner = prev }
}

func waitFor(t *testing.T, j *Job, want State) JobView {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		v := j.Snapshot()
		if v.State == want {
			return v
		}
		select {
		case <-deadline:
			t.Fatalf("job did not reach %q (last=%q done=%d/%d)", want, v.State, v.Done, v.Total)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestManagerRunAggregatesFindings(t *testing.T) {
	defer withScanner(func(_ context.Context, target string, _ xss.Options) (*xss.Result, error) {
		// One finding for the first target, none for the second.
		if target == "http://a/?q=1" {
			return &xss.Result{Count: 1, PoCs: []xss.PoC{{Param: "q", Severity: "High"}}}, nil
		}
		return &xss.Result{Count: 0, PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job := m.Start([]string{"http://a/?q=1", "http://b/?p=2"}, xss.Options{}, 2)

	v := waitFor(t, job, Done)
	if v.Total != 2 || v.Done != 2 {
		t.Fatalf("want 2/2 done, got %d/%d", v.Done, v.Total)
	}
	if len(v.Findings) != 1 || v.Findings[0].Param != "q" {
		t.Fatalf("want 1 aggregated finding for q, got %+v", v.Findings)
	}
	// Both targets should be marked done.
	for _, ts := range v.Targets {
		if ts.State != "done" {
			t.Fatalf("target %q not done: %q", ts.URL, ts.State)
		}
	}

	if _, ok := m.Get(job.ID()); !ok {
		t.Fatal("job should be retrievable by id")
	}
}

func TestManagerPerTargetError(t *testing.T) {
	defer withScanner(func(_ context.Context, target string, _ xss.Options) (*xss.Result, error) {
		if target == "http://bad/" {
			return nil, errors.New("boom")
		}
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job := m.Start([]string{"http://ok/?q=1", "http://bad/"}, xss.Options{}, 1)
	v := waitFor(t, job, Done)

	var gotErr bool
	for _, ts := range v.Targets {
		if ts.URL == "http://bad/" {
			if ts.State != "error" || ts.Error == "" {
				t.Fatalf("bad target should be error with message, got %+v", ts)
			}
			gotErr = true
		}
	}
	if !gotErr {
		t.Fatal("expected the bad target to be recorded as error")
	}
}

func TestManagerErrNotInstalledIsFatal(t *testing.T) {
	defer withScanner(func(_ context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		return nil, xss.ErrNotInstalled
	})()

	m := NewManager()
	job := m.Start([]string{"http://a/?q=1", "http://b/?q=2"}, xss.Options{}, 2)
	v := waitFor(t, job, Errored)
	if v.Error == "" {
		t.Fatal("expected a job-level error message when dalfox is not installed")
	}
}

func TestManagerStop(t *testing.T) {
	var started int32
	release := make(chan struct{})
	defer withScanner(func(ctx context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		atomic.AddInt32(&started, 1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return &xss.Result{PoCs: []xss.PoC{}}, nil
		}
	})()

	m := NewManager()
	job := m.Start([]string{"http://a/", "http://b/", "http://c/"}, xss.Options{}, 1)

	// Let at least one target start, then stop.
	time.Sleep(20 * time.Millisecond)
	if !m.Stop(job.ID()) {
		t.Fatal("Stop returned false for an existing job")
	}
	close(release)

	v := waitFor(t, job, Stopped)
	if v.State != Stopped {
		t.Fatalf("want Stopped, got %q", v.State)
	}
}
