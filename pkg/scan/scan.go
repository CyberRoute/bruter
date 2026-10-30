// Package scan runs XSS scans across many targets as a background job with a
// bounded worker pool, exposing live progress and findings for a polling UI.
// It drives pkg/xss per target; the per-target scanner is a package var so
// tests can inject a fake instead of shelling out to dalfox.
package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/CyberRoute/bruter/pkg/xss"
)

// State is the lifecycle state of a scan job.
type State string

const (
	Queued  State = "queued"
	Running State = "running"
	Done    State = "done"
	Stopped State = "stopped"
	Errored State = "error"
)

// ErrTooManyJobs is returned by Start when the maximum number of concurrent
// jobs is already running, so a caller cannot fork an unbounded number of
// scanner processes.
var ErrTooManyJobs = errors.New("too many scan jobs are already running")

// Defaults bound a job's fan-out and each target's scan.
const (
	defaultWorkers    = 5
	perTargetTimeout  = 5 * time.Minute // hard cap when no scan-timeout is set
	gracefulMargin    = 30 * time.Second
	maxFindingsPerJob = 5000 // guard against an unbounded findings buffer

	// maxTargetsPerJob caps how much work one job may accumulate.
	maxTargetsPerJob = 500
)

// Retention limits are vars so tests can shrink them. A finished job is kept
// for jobRetention, and at most maxRetainedJobs finished jobs are retained;
// without this the manager grows without bound for the lifetime of the
// process.
var (
	jobRetention      = 30 * time.Minute
	maxRetainedJobs   = 50
	maxConcurrentJobs = 4
)

// scanner is the per-target scan function; overridable in tests.
var scanner = xss.Scan

// Target is one scannable endpoint. Method and Data optionally override the
// job's dalfox options for this target alone, which is how a POST form found by
// the crawler gets scanned as a POST with its own body instead of as a GET with
// the fields moved into the query string.
type Target struct {
	URL        string `json:"url"`
	Method     string `json:"method,omitempty"`
	Data       string `json:"data,omitempty"`
	ReflectURL string `json:"reflect_url,omitempty"`
}

// UnmarshalJSON accepts either a bare URL string or a full target object, so
// API callers with nothing to override can keep posting plain URLs.
func (t *Target) UnmarshalJSON(b []byte) error {
	var u string
	if err := json.Unmarshal(b, &u); err == nil {
		*t = Target{URL: u}
		return nil
	}
	type plain Target
	return json.Unmarshal(b, (*plain)(t))
}

// optionsFor returns the job's dalfox options adjusted for one target.
func (t Target) optionsFor(base xss.Options) xss.Options {
	if t.Method != "" {
		base.Method = t.Method
	}
	if t.Data != "" {
		base.Data = t.Data
	}
	// A form whose submission renders on another page is a stored-XSS shape:
	// its write endpoint (e.g. /Xss/Add) typically redirects and never reflects
	// in its own response, so a plain scan of it reports "clean" even when the
	// payload is stored and executes on the page the form lives on. The crawler
	// records that page as ReflectURL precisely so the scan can run in
	// stored-XSS mode against it — which is the only mode dalfox can detect this
	// with. An explicit job SXSSURL still wins.
	if t.ReflectURL != "" {
		base.StoredXSS = true
		if base.SXSSURL == "" {
			base.SXSSURL = t.ReflectURL
		}
	}
	return base
}

// TargetStatus is the per-target progress record.
type TargetStatus struct {
	URL      string   `json:"url"`
	Method   string   `json:"method,omitempty"`
	State    string   `json:"state"` // pending | running | done | error | stopped
	Findings int      `json:"findings"`
	Error    string   `json:"error,omitempty"`
	Meta     xss.Meta `json:"meta"`
}

// JobView is a JSON-friendly snapshot of a Job, safe to marshal while the job
// keeps running.
type JobView struct {
	ID         string         `json:"id"`
	State      State          `json:"state"`
	Total      int            `json:"total"`
	Done       int            `json:"done"`
	Findings   []xss.PoC      `json:"findings"`
	Targets    []TargetStatus `json:"targets"`
	Truncated  bool           `json:"truncated"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// Job is a running or finished scan over a set of targets.
type Job struct {
	id      string
	opt     xss.Options
	workers int
	cancel  context.CancelFunc

	mu         sync.Mutex
	state      State
	done       int
	findings   []xss.PoC
	specs      []Target
	targets    []TargetStatus
	truncated  bool
	startedAt  time.Time
	finishedAt *time.Time
	err        string
}

// ID returns the job's identifier.
func (j *Job) ID() string { return j.id }

// targetTimeout is the hard context cap for one target. When the caller sets a
// dalfox scan-timeout, we give dalfox that long to stop gracefully plus a
// margin before the context kills it; otherwise we use the package default.
func (j *Job) targetTimeout() time.Duration {
	if j.opt.ScanTimeoutSecs > 0 {
		return time.Duration(j.opt.ScanTimeoutSecs)*time.Second + gracefulMargin
	}
	return perTargetTimeout
}

// Snapshot returns a deep-enough copy for JSON encoding without data races.
func (j *Job) Snapshot() JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	findings := make([]xss.PoC, len(j.findings))
	copy(findings, j.findings)
	targets := make([]TargetStatus, len(j.targets))
	copy(targets, j.targets)
	var fin *time.Time
	if j.finishedAt != nil {
		t := *j.finishedAt
		fin = &t
	}
	return JobView{
		ID:         j.id,
		State:      j.state,
		Total:      len(j.targets),
		Done:       j.done,
		Findings:   findings,
		Targets:    targets,
		Truncated:  j.truncated,
		StartedAt:  j.startedAt,
		FinishedAt: fin,
		Error:      j.err,
	}
}

// Manager holds scan jobs in memory, keyed by id.
type Manager struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

// NewManager returns an empty job manager.
func NewManager() *Manager {
	return &Manager{jobs: make(map[string]*Job)}
}

// Start registers a job over the given targets and launches it in the
// background, returning immediately. workers <= 0 uses the default. It returns
// ErrTooManyJobs when maxConcurrentJobs are already running, so a caller cannot
// spawn an unbounded number of scanner processes.
func (m *Manager) Start(targets []Target, opt xss.Options, workers int) (*Job, error) {
	if workers <= 0 {
		workers = defaultWorkers
	}
	targets = dedupeTargets(targets)
	if len(targets) > maxTargetsPerJob {
		// Defence in depth: the HTTP handler already rejects oversized lists,
		// so a direct caller cannot bypass the cap either.
		targets = targets[:maxTargetsPerJob]
	}

	m.mu.Lock()
	m.evictLocked(time.Now())
	running := m.runningLocked()
	if running >= maxConcurrentJobs {
		m.mu.Unlock()
		return nil, ErrTooManyJobs
	}

	statuses := make([]TargetStatus, len(targets))
	for i, t := range targets {
		statuses[i] = TargetStatus{URL: t.URL, Method: t.Method, State: "pending"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{
		id:        newID(),
		opt:       xss.Sanitize(opt),
		workers:   workers,
		cancel:    cancel,
		state:     Queued,
		specs:     targets,
		targets:   statuses,
		startedAt: time.Now(),
	}
	m.jobs[j.id] = j
	m.mu.Unlock()

	go j.run(ctx)
	return j, nil
}

// dedupeTargets drops repeated endpoints while preserving the caller's order.
// Two targets sharing a URL but differing in method or body are distinct scans.
func dedupeTargets(targets []Target) []Target {
	seen := make(map[string]bool, len(targets))
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		key := t.URL + "\x00" + t.Method + "\x00" + t.Data
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
	}
	return out
}

// runningLocked counts jobs that have not reached a terminal state.
func (m *Manager) runningLocked() int {
	n := 0
	for _, j := range m.jobs {
		j.mu.Lock()
		live := j.state == Queued || j.state == Running
		j.mu.Unlock()
		if live {
			n++
		}
	}
	return n
}

// evictLocked drops finished jobs past their retention window, then, if the map
// is still at capacity, the oldest finished jobs. Running jobs are never
// dropped. Callers must hold m.mu.
func (m *Manager) evictLocked(now time.Time) {
	type finished struct {
		id string
		at time.Time
	}
	var done []finished
	for id, j := range m.jobs {
		j.mu.Lock()
		at := j.finishedAt
		j.mu.Unlock()
		if at == nil {
			continue
		}
		if now.Sub(*at) > jobRetention {
			delete(m.jobs, id)
			continue
		}
		done = append(done, finished{id: id, at: *at})
	}
	if len(m.jobs) < maxRetainedJobs {
		return
	}
	sort.Slice(done, func(i, k int) bool { return done[i].at.Before(done[k].at) })
	for _, f := range done {
		if len(m.jobs) < maxRetainedJobs {
			return
		}
		delete(m.jobs, f.id)
	}
}

// Get returns the job with the given id.
func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}

// Stop cancels a running job. The job settles into the Stopped state once its
// in-flight targets return.
func (m *Manager) Stop(id string) bool {
	j, ok := m.Get(id)
	if !ok {
		return false
	}
	j.cancel()
	return true
}

// run executes the scan with a bounded worker pool.
func (j *Job) run(ctx context.Context) {
	j.mu.Lock()
	specs := make([]Target, len(j.specs))
	copy(specs, j.specs)
	j.state = Running
	j.startedAt = time.Now()
	j.mu.Unlock()

	type job struct {
		idx  int
		spec Target
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	var fatal struct {
		sync.Mutex
		err error
	}

	for w := 0; w < j.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if ctx.Err() != nil {
					j.finishTarget(t.idx, "stopped", nil, "")
					continue
				}
				j.setTargetState(t.idx, "running")

				tctx, cancel := context.WithTimeout(ctx, j.targetTimeout())
				res, err := scanner(tctx, t.spec.URL, t.spec.optionsFor(j.opt))
				cancel()

				if err != nil {
					if ctx.Err() != nil {
						// The job was stopped (or the process is shutting
						// down): this is a cancellation, not a failure.
						j.finishTarget(t.idx, "stopped", nil, "")
						continue
					}
					if errors.Is(err, xss.ErrNotInstalled) {
						fatal.Lock()
						fatal.err = err
						fatal.Unlock()
						j.cancel() // abort the whole job: dalfox is unavailable
					}
					j.finishTarget(t.idx, "error", nil, err.Error())
					continue
				}
				j.appendFindings(res.PoCs)
				j.finishTarget(t.idx, "done", res, "")
			}
		}()
	}

	for i, s := range specs {
		jobs <- job{idx: i, spec: s}
	}
	close(jobs)
	wg.Wait()

	// Settle the terminal state.
	final := Done
	fatal.Lock()
	if fatal.err != nil {
		final = Errored
		j.setErr(fatal.err.Error())
	}
	fatal.Unlock()
	if final == Done && ctx.Err() != nil {
		final = Stopped
	}
	j.finish(final)
}

func (j *Job) setErr(msg string) {
	j.mu.Lock()
	if j.err == "" {
		j.err = msg
	}
	j.mu.Unlock()
}

func (j *Job) setTargetState(idx int, state string) {
	j.mu.Lock()
	if idx >= 0 && idx < len(j.targets) {
		j.targets[idx].State = state
	}
	j.mu.Unlock()
}

func (j *Job) finishTarget(idx int, state string, res *xss.Result, errMsg string) {
	j.mu.Lock()
	if idx >= 0 && idx < len(j.targets) {
		ts := &j.targets[idx]
		ts.State = state
		ts.Error = errMsg
		if res != nil {
			ts.Findings = len(res.PoCs)
			ts.Meta = res.Meta
		}
	}
	j.done++
	j.mu.Unlock()
}

func (j *Job) appendFindings(pocs []xss.PoC) {
	j.mu.Lock()
	for _, p := range pocs {
		if len(j.findings) >= maxFindingsPerJob {
			j.truncated = true
			break
		}
		j.findings = append(j.findings, p)
	}
	j.mu.Unlock()
}

func (j *Job) finish(state State) {
	j.mu.Lock()
	j.state = state
	now := time.Now()
	j.finishedAt = &now
	j.mu.Unlock()
}

// newID returns a short random hex id for a job.
func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is effectively impossible; fall back to time.
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000")))
	}
	return hex.EncodeToString(b)
}
