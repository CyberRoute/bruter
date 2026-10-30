package scan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
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

// toTargets wraps plain URLs as targets with no per-target overrides.
func toTargets(urls []string) []Target {
	out := make([]Target, len(urls))
	for i, u := range urls {
		out[i] = Target{URL: u}
	}
	return out
}

// mustStart starts a job or fails the test.
func mustStart(t *testing.T, m *Manager, targets []string, opt xss.Options, workers int) *Job {
	t.Helper()
	j, err := m.Start(toTargets(targets), opt, workers)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	return j
}

// withLimits temporarily overrides the manager's retention/concurrency limits.
func withLimits(t *testing.T, concurrent, retained int, retention time.Duration) {
	t.Helper()
	prevConcurrent, prevRetained, prevRetention := maxConcurrentJobs, maxRetainedJobs, jobRetention
	maxConcurrentJobs, maxRetainedJobs, jobRetention = concurrent, retained, retention
	t.Cleanup(func() {
		maxConcurrentJobs, maxRetainedJobs, jobRetention = prevConcurrent, prevRetained, prevRetention
	})
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
	job := mustStart(t, m, []string{"http://a/?q=1", "http://b/?p=2"}, xss.Options{}, 2)

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
	job := mustStart(t, m, []string{"http://ok/?q=1", "http://bad/"}, xss.Options{}, 1)
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
	job := mustStart(t, m, []string{"http://a/?q=1", "http://b/?q=2"}, xss.Options{}, 2)
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
	job := mustStart(t, m, []string{"http://a/", "http://b/", "http://c/"}, xss.Options{}, 1)

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

func TestManagerStopMarksPendingTargetsStopped(t *testing.T) {
	release := make(chan struct{})
	defer withScanner(func(ctx context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		<-release
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job := mustStart(t, m, []string{"http://a/", "http://b/", "http://c/"}, xss.Options{}, 1)
	time.Sleep(20 * time.Millisecond) // let the first target start
	if !m.Stop(job.ID()) {
		t.Fatal("Stop returned false for an existing job")
	}
	close(release)

	v := waitFor(t, job, Stopped)
	for _, ts := range v.Targets {
		if ts.State == "error" {
			t.Fatalf("a deliberate stop must not be reported as an error: %+v", ts)
		}
	}
}

func TestManagerRejectsTooManyJobs(t *testing.T) {
	withLimits(t, 1, 50, time.Minute)
	release := make(chan struct{})
	defer withScanner(func(ctx context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return &xss.Result{PoCs: []xss.PoC{}}, nil
		}
	})()

	m := NewManager()
	first := mustStart(t, m, []string{"http://a/"}, xss.Options{}, 1)
	if _, err := m.Start(toTargets([]string{"http://b/"}), xss.Options{}, 1); !errors.Is(err, ErrTooManyJobs) {
		t.Fatalf("want ErrTooManyJobs while a job is running, got %v", err)
	}
	m.Stop(first.ID())
	close(release)
	waitFor(t, first, Stopped)

	last := mustStart(t, m, []string{"http://b/"}, xss.Options{}, 1)
	waitFor(t, last, Done) // do not leak a running job into the next test
}

func TestManagerEvictsFinishedJobs(t *testing.T) {
	withLimits(t, 4, 50, 20*time.Millisecond)
	defer withScanner(func(_ context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	first := mustStart(t, m, []string{"http://a/"}, xss.Options{}, 1)
	waitFor(t, first, Done)
	time.Sleep(50 * time.Millisecond) // past the retention window

	second := mustStart(t, m, []string{"http://b/"}, xss.Options{}, 1)
	waitFor(t, second, Done)
	if _, ok := m.Get(first.ID()); ok {
		t.Fatal("an expired finished job should have been evicted")
	}
	if _, ok := m.Get(second.ID()); !ok {
		t.Fatal("the fresh job should still be retained")
	}
}

func TestManagerEvictsOldestFinishedJobsAtCapacity(t *testing.T) {
	withLimits(t, 4, 1, time.Hour)
	defer withScanner(func(_ context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	first := mustStart(t, m, []string{"http://a/"}, xss.Options{}, 1)
	waitFor(t, first, Done)
	second := mustStart(t, m, []string{"http://b/"}, xss.Options{}, 1)
	waitFor(t, second, Done)

	if _, ok := m.Get(first.ID()); ok {
		t.Fatal("the oldest finished job should have been evicted at capacity")
	}
	if _, ok := m.Get(second.ID()); !ok {
		t.Fatal("the newest job should be retained")
	}
}

func TestManagerDedupesTargets(t *testing.T) {
	defer withScanner(func(_ context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job := mustStart(t, m, []string{"http://a/", "http://a/", "http://b/"}, xss.Options{}, 1)
	v := waitFor(t, job, Done)
	if v.Total != 2 {
		t.Fatalf("duplicate targets should be scanned once, got %d targets", v.Total)
	}
}

func TestManagerSanitizesOptions(t *testing.T) {
	var seen xss.Options
	defer withScanner(func(_ context.Context, _ string, opt xss.Options) (*xss.Result, error) {
		seen = opt
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job := mustStart(t, m, []string{"http://a/"}, xss.Options{
		Workers: 100000, ScanTimeoutSecs: 10_000_000, RateLimit: 1_000_000,
	}, 1)
	waitFor(t, job, Done)
	if seen.Workers > 200 || seen.ScanTimeoutSecs > 900 || seen.RateLimit > 1000 {
		t.Fatalf("options must be clamped before reaching the scanner: %+v", seen)
	}
	if j := job.targetTimeout(); j > 16*time.Minute {
		t.Fatalf("a hostile scan-timeout must not pin a job for hours: %v", j)
	}
}

func TestManagerFlagsTruncatedFindings(t *testing.T) {
	defer withScanner(func(_ context.Context, _ string, _ xss.Options) (*xss.Result, error) {
		return &xss.Result{PoCs: make([]xss.PoC, maxFindingsPerJob+10)}, nil
	})()

	m := NewManager()
	job := mustStart(t, m, []string{"http://a/"}, xss.Options{}, 1)
	v := waitFor(t, job, Done)
	if !v.Truncated {
		t.Fatal("findings past the cap must be flagged as truncated")
	}
	if len(v.Findings) != maxFindingsPerJob {
		t.Fatalf("findings should be capped at %d, got %d", maxFindingsPerJob, len(v.Findings))
	}
}

func TestManagerAppliesPerTargetOptions(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]xss.Options{}
	defer withScanner(func(_ context.Context, target string, opt xss.Options) (*xss.Result, error) {
		mu.Lock()
		seen[target] = opt
		mu.Unlock()
		return &xss.Result{PoCs: []xss.PoC{}}, nil
	})()

	m := NewManager()
	job, err := m.Start([]Target{
		{URL: "http://a/post", Method: "POST", Data: "msg=", ReflectURL: "http://a/page"},
		{URL: "http://a/get?q=1"},
	}, xss.Options{StoredXSS: true}, 2)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	v := waitFor(t, job, Done)

	post := seen["http://a/post"]
	if post.Method != "POST" || post.Data != "msg=" || post.SXSSURL != "http://a/page" {
		t.Fatalf("POST target should carry its own method, body and reflection URL: %+v", post)
	}
	get := seen["http://a/get?q=1"]
	if get.Method != "" || get.Data != "" || get.SXSSURL != "" {
		t.Fatalf("one target's overrides must not leak into another: %+v", get)
	}
	if v.Targets[0].Method != "POST" {
		t.Fatalf("target status should report the method, got %+v", v.Targets[0])
	}
}

func TestManagerExplicitSXSSURLWins(t *testing.T) {
	opt := Target{URL: "http://a/", ReflectURL: "http://a/page"}.optionsFor(xss.Options{StoredXSS: true, SXSSURL: "http://a/explicit"})
	if opt.SXSSURL != "http://a/explicit" {
		t.Fatalf("an explicit sxss-url must not be replaced, got %q", opt.SXSSURL)
	}
	// A form target carrying a reflection page must enable stored-XSS mode on
	// its own: without it dalfox scans the (redirecting) write endpoint and
	// reports "clean", missing a stored XSS entirely.
	opt = Target{URL: "http://a/add", Method: "POST", ReflectURL: "http://a/page"}.optionsFor(xss.Options{})
	if !opt.StoredXSS || opt.SXSSURL != "http://a/page" {
		t.Fatalf("a form with a reflection page must scan in stored-XSS mode against it, got %+v", opt)
	}
}

func TestTargetUnmarshalAcceptsStringOrObject(t *testing.T) {
	var got []Target
	body := `["http://a/", {"url":"http://b/","method":"POST","data":"x=","reflect_url":"http://b/page"}]`
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []Target{
		{URL: "http://a/"},
		{URL: "http://b/", Method: "POST", Data: "x=", ReflectURL: "http://b/page"},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if err := json.Unmarshal([]byte(`[42]`), &got); err == nil {
		t.Fatal("a target that is neither a string nor an object should be rejected")
	}
}

func TestDedupeKeepsDistinctMethods(t *testing.T) {
	got := dedupeTargets([]Target{
		{URL: "http://a/"},
		{URL: "http://a/", Method: "POST", Data: "x="},
		{URL: "http://a/"},
	})
	if len(got) != 2 {
		t.Fatalf("GET and POST of one URL are distinct scans, got %+v", got)
	}
}

// TestIntegrationStoredXSSFormIsDetected drives the real dalfox binary through
// the manager against a loopback store-and-reflect server that mimics the shape
// of a stored-XSS page: a POST form whose write endpoint redirects and never
// reflects, while the submitted value renders as raw HTML on another page.
//
// This is the regression guard for the failure where such a target was scanned
// in the default (non-stored) mode and always came back "clean": a form target
// carrying a ReflectURL must scan in stored-XSS mode on its own.
func TestIntegrationStoredXSSFormIsDetected(t *testing.T) {
	if !xss.Installed() {
		t.Skip("dalfox not installed")
	}

	var mu sync.Mutex
	var stored []string
	mux := http.NewServeMux()
	mux.HandleFunc("/xss", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		mu.Lock()
		msgs := append([]string(nil), stored...)
		mu.Unlock()
		_, _ = w.Write([]byte("<html><body><h2>Messages</h2>"))
		for _, m := range msgs {
			_, _ = w.Write([]byte("<div>" + m + "</div>")) // raw HTML, deliberately unescaped
		}
		_, _ = w.Write([]byte("</body></html>"))
	})
	mux.HandleFunc("/xss/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			mu.Lock()
			stored = append(stored, r.PostFormValue("message"))
			mu.Unlock()
		}
		http.Redirect(w, r, "/xss", http.StatusFound) // write endpoint never reflects
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	m := NewManager()
	// The crawler produces exactly this: a POST form target whose ReflectURL is
	// the page it was found on. No job-wide stored_xss flag is set.
	job, err := m.Start([]Target{{
		URL:        srv.URL + "/xss/add",
		Method:     http.MethodPost,
		Data:       "message=",
		ReflectURL: srv.URL + "/xss",
	}}, xss.Options{SkipMining: true, SkipAST: true, OnlyPoC: "v", ScanTimeoutSecs: 90}, 1)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	deadline := time.Now().Add(2 * time.Minute)
	for {
		v := job.Snapshot()
		if v.State == Done {
			if len(v.Findings) == 0 {
				t.Fatalf("stored XSS via a POST form was not detected: %+v (meta=%+v)", v, v.Targets)
			}
			return
		}
		if v.State == Errored || v.State == Stopped || time.Now().After(deadline) {
			t.Fatalf("scan did not complete: %+v", v)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
