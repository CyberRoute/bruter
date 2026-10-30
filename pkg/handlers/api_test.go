package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/scan"
	"github.com/CyberRoute/bruter/pkg/xss"
	"github.com/rs/zerolog"
)

// testRepo returns a Repository with the dependencies the API handlers need.
func testRepo() *Repository {
	logger := zerolog.Nop()
	return &Repository{
		App:   &config.AppConfig{ZeroLog: &logger},
		Scans: scan.NewManager(),
	}
}

func postJSON(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestScanStartRequiresTargets(t *testing.T) {
	rec := postJSON(t, testRepo().ScanStartAPI, `{"targets":[],"options":{}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty target list should be 400, got %d", rec.Code)
	}
}

func TestScanStartRejectsTooManyTargets(t *testing.T) {
	// Build a list above the cap: the handler must refuse rather than silently
	// scanning only the first maxScanTargets entries.
	var b strings.Builder
	b.WriteString(`{"targets":[`)
	for i := 0; i <= maxScanTargets; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"http://example.com/?q=1"`)
	}
	b.WriteString(`],"options":{}}`)

	rec := postJSON(t, testRepo().ScanStartAPI, b.String())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-cap target list should be 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too many targets") {
		t.Fatalf("response should explain the cap, got %s", rec.Body.String())
	}
}

func TestScanStartRejectsInvalidBody(t *testing.T) {
	rec := postJSON(t, testRepo().ScanStartAPI, `not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON should be 400, got %d", rec.Code)
	}
}

func TestWriteAPIErrorTruncatesLongMessages(t *testing.T) {
	m := testRepo()
	rec := httptest.NewRecorder()
	m.writeAPIError(rec, http.StatusBadGateway, strings.Repeat("x", 5000))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := len(rec.Body.String()); got > 600 {
		t.Fatalf("a child process's stderr must not flood the response: %d bytes", got)
	}
}

// TestScanStartScansPostTargetEndToEnd drives the real dalfox binary through the
// handler against a loopback server: the parameter exists only in the POST body,
// so it is found only if the target's method and data survive the whole path.
func TestScanStartScansPostTargetEndToEnd(t *testing.T) {
	if !xss.Installed() {
		t.Skip("dalfox not installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><div>" + r.PostFormValue("msg") + "</div></body></html>"))
	}))
	defer srv.Close()

	m := testRepo()
	body, err := json.Marshal(map[string]any{
		"targets": []any{map[string]string{"url": srv.URL + "/", "method": "POST", "data": "msg=test"}},
		"options": map[string]any{"skip_mining": true, "skip_ast": true, "only_poc": "v", "scan_timeout": 60},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, m.ScanStartAPI, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("start = %d: %s", rec.Code, rec.Body.String())
	}
	var started struct {
		JobID string `json:"job_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	job, ok := m.Scans.Get(started.JobID)
	if !ok {
		t.Fatalf("job %q not found", started.JobID)
	}

	deadline := time.Now().Add(2 * time.Minute)
	for {
		v := job.Snapshot()
		if v.State == scan.Done {
			if len(v.Findings) == 0 {
				t.Fatalf("expected a finding for the body parameter, got %+v", v)
			}
			if v.Targets[0].Method != "POST" {
				t.Fatalf("target status lost its method: %+v", v.Targets[0])
			}
			return
		}
		if v.State == scan.Errored || v.State == scan.Stopped || time.Now().After(deadline) {
			t.Fatalf("scan did not complete: %+v", v)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
