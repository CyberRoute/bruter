package xss

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestFilterByType(t *testing.T) {
	pocs := []PoC{
		{Type: "V", Param: "q"},
		{Type: "R", Param: "s"},
		{Type: "A", Param: "paged"},
		{Type: "I", Param: "query"},
	}

	// Verified-only drops the reflected/AST/informational noise.
	got := filterByType(pocs, "v")
	if len(got) != 1 || got[0].Type != "V" {
		t.Fatalf("only_poc=v should keep just the V finding, got %+v", got)
	}

	// Verified + reflected keeps two.
	if got := filterByType(pocs, "v,r"); len(got) != 2 {
		t.Fatalf("only_poc=v,r should keep 2 findings, got %d", len(got))
	}

	// Empty filter is a pass-through (but never nil).
	if got := filterByType(pocs, ""); len(got) != 4 {
		t.Fatalf("empty filter should pass all through, got %d", len(got))
	}
	if got := filterByType(nil, ""); got == nil {
		t.Fatalf("nil findings with empty filter should return non-nil slice")
	}
}

func TestBuildArgs(t *testing.T) {
	const target = "http://localhost:8081/vulnerabilities/xss_r/?name=test"

	indexOf := func(args []string, flag string) int {
		return slices.Index(args, flag)
	}

	t.Run("uses v3 scan subcommand with target", func(t *testing.T) {
		args := buildArgs(target, Options{})
		if args[0] != "scan" || args[1] != target {
			t.Fatalf("expected [scan target ...], got: %v", args[:2])
		}
	})

	t.Run("no cookie omits flag", func(t *testing.T) {
		args := buildArgs(target, Options{})
		if indexOf(args, "--cookies") != -1 {
			t.Fatalf("expected no --cookies flag, got args: %v", args)
		}
	})

	t.Run("cookie passed as distinct arg after --cookies", func(t *testing.T) {
		const cookie = "PHPSESSID=abc123; security=low"
		args := buildArgs(target, Options{Cookie: cookie})
		i := indexOf(args, "--cookies")
		if i == -1 {
			t.Fatalf("expected --cookies flag, got args: %v", args)
		}
		if i+1 >= len(args) || args[i+1] != cookie {
			t.Fatalf("expected cookie value after --cookies, got args: %v", args)
		}
	})

	t.Run("blank cookie trimmed and omitted", func(t *testing.T) {
		args := buildArgs(target, Options{Cookie: "   "})
		if indexOf(args, "--cookies") != -1 {
			t.Fatalf("expected whitespace-only cookie omitted, got args: %v", args)
		}
	})

	t.Run("skip mining flag toggles", func(t *testing.T) {
		with := buildArgs(target, Options{SkipMining: true})
		if indexOf(with, "--skip-mining") == -1 {
			t.Fatalf("expected --skip-mining, got args: %v", with)
		}
		without := buildArgs(target, Options{})
		if indexOf(without, "--skip-mining") != -1 {
			t.Fatalf("expected no --skip-mining, got args: %v", without)
		}
	})

	t.Run("skip-ast-analysis flag toggles", func(t *testing.T) {
		with := buildArgs(target, Options{SkipAST: true})
		if indexOf(with, "--skip-ast-analysis") == -1 {
			t.Fatalf("expected --skip-ast-analysis, got args: %v", with)
		}
		if indexOf(buildArgs(target, Options{}), "--skip-ast-analysis") != -1 {
			t.Fatalf("expected no --skip-ast-analysis by default")
		}
	})

	t.Run("only-poc validated and canonicalised", func(t *testing.T) {
		args := buildArgs(target, Options{OnlyPoC: " V , r , bogus , r "})
		i := indexOf(args, "--only-poc")
		if i == -1 || i+1 >= len(args) {
			t.Fatalf("expected --only-poc with a value, got args: %v", args)
		}
		if args[i+1] != "v,r" {
			t.Fatalf("expected normalised \"v,r\", got %q", args[i+1])
		}
		// A value with no valid types omits the flag entirely.
		if indexOf(buildArgs(target, Options{OnlyPoC: "x,y"}), "--only-poc") != -1 {
			t.Fatalf("expected --only-poc omitted when no valid types remain")
		}
	})

	t.Run("defaults applied for non-positive fields", func(t *testing.T) {
		args := buildArgs(target, Options{Workers: 0, TimeoutSecs: -5, DelayMillis: -1})
		joined := strings.Join(args, " ")
		for _, want := range []string{"--workers 40", "--timeout 10", "--delay 0"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected default %q in args: %v", want, args)
			}
		}
	})

	t.Run("no removed v2 flags leak through", func(t *testing.T) {
		args := buildArgs(target, Options{SkipMining: true, Cookie: "a=b"})
		for _, gone := range []string{"url", "--no-spinner", "--worker", "--skip-mining-all", "--cookie"} {
			if indexOf(args, gone) != -1 {
				t.Fatalf("v2 flag %q should not appear in v3 args: %v", gone, args)
			}
		}
	})
}

func TestBuildArgsComprehensiveOptions(t *testing.T) {
	const target = "https://example.com/?q=1"
	args := buildArgs(target, Options{
		Headers:         []string{"Authorization: Bearer x", "  "}, // blank dropped
		UserAgent:       "bruter/1",
		Method:          "post", // lower-cased, whitelisted
		SkipMiningDict:  true,
		SkipMiningDOM:   true,
		BlindURL:        "https://oob.example/cb",
		RateLimit:       20,
		FollowRedirects: true,
		DeepScan:        true,
		WAFEvasion:      true,
		StoredXSS:       true,
		SXSSURL:         "https://example.com/view",
	})
	joined := strings.Join(args, " ")
	wants := []string{
		"-H Authorization: Bearer x",
		"--user-agent bruter/1",
		"-X POST",
		"--skip-mining-dict",
		"--skip-mining-dom",
		"-b https://oob.example/cb",
		"--rate-limit 20",
		"--follow-redirects",
		"--deep-scan",
		"--waf-evasion",
		"--sxss",
		"--sxss-url https://example.com/view",
	}
	for _, w := range wants {
		if !strings.Contains(joined, w) {
			t.Errorf("expected %q in args: %v", w, args)
		}
	}
	// Exactly one -H (the blank header was dropped).
	if n := strings.Count(joined, "-H "); n != 1 {
		t.Errorf("expected 1 -H flag, got %d in %v", n, args)
	}
}

func TestBuildArgsRejectsUnsafeValues(t *testing.T) {
	const target = "https://example.com/?q=1"
	args := buildArgs(target, Options{
		Method:   "EVIL",                // not a known verb → dropped
		BlindURL: "ftp://x",             // not http(s) → dropped
		SXSSURL:  "javascript:alert(1)", // not http(s) → dropped (and no --sxss)
	})
	joined := strings.Join(args, " ")
	for _, gone := range []string{"-X", "EVIL", "-b", "ftp://x", "--sxss-url", "javascript"} {
		if strings.Contains(joined, gone) {
			t.Errorf("unsafe value %q should have been dropped: %v", gone, args)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"empty", "", true},
		{"no scheme", "example.com/?q=1", true},
		{"ftp scheme", "ftp://example.com", true},
		{"file scheme", "file:///etc/passwd", true},
		{"flag-looking", "-o/tmp/x", true},
		{"no host", "http://", true},
		{"valid http", "http://example.com/?q=FUZZ", false},
		{"valid https", "https://example.com/search?q=1&p=2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateTarget(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateTarget(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
		})
	}
}

func TestParseReport(t *testing.T) {
	t.Run("empty output is a clean report", func(t *testing.T) {
		rep, err := parseReport(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.Findings == nil || len(rep.Findings) != 0 {
			t.Fatalf("want non-nil empty findings, got %#v", rep.Findings)
		}
	})

	t.Run("v3 object with no findings", func(t *testing.T) {
		in := `{"findings":[],"meta":{"dalfox_version":"3.2.4","findings_count":0}}`
		rep, err := parseReport([]byte(in))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 0 {
			t.Fatalf("want 0 findings, got %d", len(rep.Findings))
		}
		if rep.Meta.DalfoxVersion != "3.2.4" {
			t.Fatalf("want meta version parsed, got %q", rep.Meta.DalfoxVersion)
		}
	})

	t.Run("v3 object with a real finding", func(t *testing.T) {
		in := `{"findings":[{"confidence":"high","cwe":"CWE-79",` +
			`"data":"http://x/?name=<svg onload=alert(1)>","detection_method":"reflection",` +
			`"inject_type":"inHTML","location":"Query","method":"GET","param":"name",` +
			`"payload":"<svg onload=alert(1)>","severity":"High","type":"V",` +
			`"type_description":"Vulnerable"}],` +
			`"meta":{"dalfox_version":"3.2.4","failed_requests":0,"total_requests":42}}`
		rep, err := parseReport([]byte(in))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rep.Findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(rep.Findings))
		}
		f := rep.Findings[0]
		if f.Param != "name" || f.Severity != "High" || f.Type != "V" ||
			f.Confidence != "high" || f.Location != "Query" {
			t.Fatalf("unexpected finding parse: %+v", f)
		}
		if rep.Meta.TotalRequests != 42 {
			t.Fatalf("want meta total_requests=42, got %d", rep.Meta.TotalRequests)
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		if _, err := parseReport([]byte(`not json`)); err == nil {
			t.Fatal("want error on invalid json, got nil")
		}
	})
}

func TestScanFailureDetectsSkippedTarget(t *testing.T) {
	// Real dalfox v3 output for an unreachable target: exit 2, valid JSON, zero
	// findings and meta.failed_requests = 0. Parseability is not success.
	meta := Meta{TargetSummary: []TargetSummary{{
		Target: "http://127.0.0.1:9/?q=1", Status: "skipped", ErrorCode: "CONNECTION_FAILED",
	}}}
	err := scanFailure(nil, meta)
	if err == nil || !strings.Contains(err.Error(), "CONNECTION_FAILED") {
		t.Fatalf("a skipped target must be an error carrying the dalfox reason, got %v", err)
	}
}

func TestScanFailureAcceptsScannedTargets(t *testing.T) {
	for _, status := range []string{"clean", "findings"} {
		meta := Meta{TargetSummary: []TargetSummary{{Target: "http://x/", Status: status}}}
		if err := scanFailure(nil, meta); err != nil {
			t.Fatalf("status %q should be a successful scan, got %v", status, err)
		}
	}
}

func TestScanFailureUsesExitCodeWithoutSummary(t *testing.T) {
	for _, tc := range []struct {
		status  int
		wantErr bool
	}{
		{0, false}, // clean
		{1, false}, // findings
		{2, true},  // scan error
	} {
		runErr := exec.Command("sh", "-c", "exit "+strconv.Itoa(tc.status)).Run()
		if got := scanFailure(runErr, Meta{}) != nil; got != tc.wantErr {
			t.Fatalf("exit %d: wantErr=%v, got %v", tc.status, tc.wantErr, runErr)
		}
	}
}

func TestLimitedBufferBoundsMemory(t *testing.T) {
	b := &limitedBuffer{limit: 16}
	if _, err := b.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if b.overflow {
		t.Fatal("should not overflow below the limit")
	}
	if _, err := b.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	if !b.overflow {
		t.Fatal("expected overflow to be recorded")
	}
	if got := len(b.Bytes()); got > 16 {
		t.Fatalf("buffer kept growing past the limit: %d bytes", got)
	}
	// Writes after the overflow are still accepted (and discarded) so the child
	// process never blocks on a full pipe.
	n, err := b.Write([]byte("more"))
	if err != nil || n != 4 {
		t.Fatalf("post-overflow write = (%d, %v)", n, err)
	}
}

func TestSanitizeClampsHostileOptions(t *testing.T) {
	o := Sanitize(Options{
		Workers: 10_000_000, TimeoutSecs: 10_000_000, DelayMillis: 10_000_000,
		ScanTimeoutSecs: 10_000_000, RateLimit: 10_000_000,
	})
	if o.Workers != maxWorkers || o.TimeoutSecs != maxTimeoutSecs ||
		o.DelayMillis != maxDelayMillis || o.ScanTimeoutSecs != maxScanTimeoutSecs ||
		o.RateLimit != maxRateLimit {
		t.Fatalf("expected every numeric option clamped, got %+v", o)
	}
	// Zero means "use the default" and must survive.
	if z := Sanitize(Options{}); z.Workers != 0 || z.ScanTimeoutSecs != 0 {
		t.Fatalf("zero-value options must pass through untouched: %+v", z)
	}
}

func TestBriefErrorCompactsStderr(t *testing.T) {
	long := strings.Repeat("trace line with /private/path\n", 100)
	got := briefError(long)
	if strings.Contains(got, "\n") {
		t.Fatal("stderr must be compacted to one line")
	}
	if len(got) > 303 { // 300 bytes plus the UTF-8 ellipsis
		t.Fatalf("stderr should be truncated, got %d bytes", len(got))
	}
	if briefError("   ") != "" {
		t.Fatal("blank stderr should stay empty")
	}
}

// fakeDalfox installs a stub dalfox binary on PATH that prints stdout and exits
// with status, so Scan's real exit-code/report handling is exercised.
func fakeDalfox(t *testing.T, stdout string, status int) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'REPORT'\n" + stdout + "\nREPORT\nexit " + strconv.Itoa(status) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "dalfox"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
}

func TestScanSurfacesFailedTarget(t *testing.T) {
	fakeDalfox(t, `{"findings":[],"meta":{"dalfox_version":"3.2.4",`+
		`"target_summary":[{"target":"http://example.com/","status":"skipped","error_code":"CONNECTION_FAILED"}]}}`, 2)
	res, err := Scan(context.Background(), "http://example.com/?q=1", Options{})
	if err == nil || !strings.Contains(err.Error(), "CONNECTION_FAILED") {
		t.Fatalf("an unreachable target must not look clean, got res=%+v err=%v", res, err)
	}
}

func TestScanAcceptsFindingsExitStatus(t *testing.T) {
	fakeDalfox(t, `{"findings":[{"type":"V","param":"q","severity":"High"}],`+
		`"meta":{"target_summary":[{"target":"http://example.com/","status":"findings","findings_count":1}]}}`, 1)
	res, err := Scan(context.Background(), "http://example.com/?q=1", Options{})
	if err != nil {
		t.Fatalf("exit 1 with findings is a successful scan, got %v", err)
	}
	if res.Count != 1 || len(res.Meta.TargetSummary) != 1 {
		t.Fatalf("expected one finding and the target summary to be parsed, got %+v", res)
	}
}

func TestScanRejectsOversizedOutput(t *testing.T) {
	// More than the 8 MiB report cap: the run must fail loudly rather than
	// truncating the JSON and discarding the findings.
	fakeDalfox(t, strings.Repeat("x", maxOutputBytes+1024), 0)
	_, err := Scan(context.Background(), "http://example.com/?q=1", Options{})
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized output must be an explicit error, got %v", err)
	}
}
