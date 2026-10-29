// Package scan runs XSS scans across many targets as a background job with a
// bounded worker pool, exposing live progress and findings for a polling UI.
// It drives pkg/xss per target; the per-target scanner is a package var so
// tests can inject a fake instead of shelling out to dalfox.
package scan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

// Defaults bound a job's fan-out and each target's scan.
const (
	defaultWorkers    = 5
	perTargetTimeout  = 5 * time.Minute // hard cap when no scan-timeout is set
	gracefulMargin    = 30 * time.Second
	maxFindingsPerJob = 5000 // guard against an unbounded findings buffer
)

// scanner is the per-target scan function; overridable in tests.
var scanner = xss.Scan

// TargetStatus is the per-target progress record.
type TargetStatus struct {
	URL      string `json:"url"`
	State    string `json:"state"` // pending | running | done | error
	Findings int    `json:"findings"`
	Error    string `json:"error,omitempty"`
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
	targets    []TargetStatus
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
// background, returning immediately. workers <= 0 uses the default.
func (m *Manager) Start(targets []string, opt xss.Options, workers int) *Job {
	if workers <= 0 {
		workers = defaultWorkers
	}
	statuses := make([]TargetStatus, len(targets))
	for i, t := range targets {
		statuses[i] = TargetStatus{URL: t, State: "pending"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	j := &Job{
		id:        newID(),
		opt:       opt,
		workers:   workers,
		cancel:    cancel,
		state:     Queued,
		targets:   statuses,
		startedAt: time.Now(),
	}

	m.mu.Lock()
	m.jobs[j.id] = j
	m.mu.Unlock()

	go j.run(ctx)
	return j
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
	j.setState(Running)

	type job struct {
		idx int
		url string
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
					j.finishTarget(t.idx, "error", 0, ctx.Err().Error())
					continue
				}
				j.setTargetState(t.idx, "running")

				tctx, cancel := context.WithTimeout(ctx, j.targetTimeout())
				res, err := scanner(tctx, t.url, j.opt)
				cancel()

				if err != nil {
					if errors.Is(err, xss.ErrNotInstalled) {
						fatal.Lock()
						fatal.err = err
						fatal.Unlock()
						j.cancel() // abort the whole job: dalfox is unavailable
					}
					j.finishTarget(t.idx, "error", 0, err.Error())
					continue
				}
				j.appendFindings(res.PoCs)
				j.finishTarget(t.idx, "done", len(res.PoCs), "")
			}
		}()
	}

	for i := range j.targets {
		jobs <- job{idx: i, url: j.targets[i].URL}
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

func (j *Job) setState(s State) {
	j.mu.Lock()
	j.state = s
	j.mu.Unlock()
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

func (j *Job) finishTarget(idx int, state string, findings int, errMsg string) {
	j.mu.Lock()
	if idx >= 0 && idx < len(j.targets) {
		j.targets[idx].State = state
		j.targets[idx].Findings = findings
		j.targets[idx].Error = errMsg
	}
	j.done++
	j.mu.Unlock()
}

func (j *Job) appendFindings(pocs []xss.PoC) {
	j.mu.Lock()
	for _, p := range pocs {
		if len(j.findings) >= maxFindingsPerJob {
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
