// Package xss drives the external `dalfox` scanner to test a single URL for
// cross-site scripting. Bruter shells out to the dalfox binary (rather than
// embedding it) so the heavy scanner stays an optional, independently updated
// dependency; when it is not installed the caller gets ErrNotInstalled so the
// UI can show an install hint instead of a generic failure.
//
// This is an ACTIVE check: dalfox sends live XSS payloads to the target. Only
// run it against systems you are authorised to test.
package xss

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
)

// binary is the dalfox executable name resolved on PATH.
const binary = "dalfox"

// ErrNotInstalled is returned when the dalfox binary cannot be found on PATH.
var ErrNotInstalled = errors.New("dalfox is not installed or not on PATH")

// defaults bound a scan so a single request cannot run away. They are modest
// because the scan runs synchronously behind an HTTP handler.
const (
	defaultWorkers       = 40
	defaultTimeoutSecs   = 10
	maxOutputBytes       = 8 << 20 // cap dalfox stdout to 8 MiB
	defaultDelayMillisec = 0
)

// PoC mirrors one object in the `findings` array dalfox v3 emits with
// `--format json`. Unknown fields are ignored; fields absent in a given
// finding decode to their zero value.
type PoC struct {
	Type             string `json:"type"`              // "V" vulnerable, "R" reflected, "A" AST DOM XSS, "I" informational
	TypeDescription  string `json:"type_description"`  // human-readable gloss of Type
	InjectType       string `json:"inject_type"`       // where the payload landed, e.g. "inHTML"
	DetectionMethod  string `json:"detection_method"`  // e.g. "reflection"
	Confidence       string `json:"confidence"`        // e.g. "high"
	ConfidenceReason string `json:"confidence_reason"` // why dalfox assigned that confidence
	Location         string `json:"location"`          // where the param lives, e.g. "Query"
	Method           string `json:"method"`
	Data             string `json:"data"`     // the PoC URL/request
	Param            string `json:"param"`    // vulnerable parameter
	Payload          string `json:"payload"`  // injected payload
	Evidence         string `json:"evidence"` // matched evidence snippet
	CWE              string `json:"cwe"`
	Severity         string `json:"severity"`
	MessageID        int    `json:"message_id"`
	MessageStr       string `json:"message_str"`
}

// Meta is the subset of dalfox v3's report `meta` block worth surfacing so the
// UI can distinguish "clean scan" from "scan hit errors / was incomplete".
type Meta struct {
	DalfoxVersion  string `json:"dalfox_version"`
	FailedRequests int    `json:"failed_requests"`
	TotalRequests  int    `json:"total_requests"`
	ScanDurationMs int64  `json:"scan_duration_ms"`
	Incomplete     bool   `json:"incomplete"`
}

// report is the top-level shape of dalfox v3 JSON output: { findings, meta }.
type report struct {
	Findings []PoC `json:"findings"`
	Meta     Meta  `json:"meta"`
}

// Result is the scan outcome returned to the API layer.
type Result struct {
	Target string `json:"target"`
	Count  int    `json:"count"`
	PoCs   []PoC  `json:"pocs"`
	Meta   Meta   `json:"meta"`
}

// Options tunes a scan. The zero value uses the package defaults. Each field
// maps to a dalfox v3 flag; buildArgs validates values that could be confused
// for flags (URLs, HTTP method) and drops anything unsafe rather than passing
// it through.
type Options struct {
	Workers     int
	TimeoutSecs int // per-request network timeout (--timeout)
	DelayMillis int
	// ScanTimeoutSecs caps dalfox's payload-injection stage per target
	// (--scan-timeout). Unlike a hard context kill, dalfox stops gracefully and
	// still emits the findings it has. 0 leaves dalfox's default (no cap).
	ScanTimeoutSecs int

	// Cookie, when set, is passed to dalfox as --cookies so authenticated
	// targets (e.g. a login-gated app) can be reached. Format is a raw Cookie
	// header value, e.g. "PHPSESSID=abc; security=low".
	Cookie string
	// Headers are extra request headers, each "Name: value" → one -H flag.
	Headers []string
	// UserAgent overrides the request User-Agent (--user-agent).
	UserAgent string
	// Method overrides the HTTP method (-X); ignored unless a known verb.
	Method string

	// Mining toggles. SkipMining skips all parameter mining (--skip-mining);
	// the two narrower flags skip only dictionary / DOM mining.
	SkipMining     bool
	SkipMiningDict bool
	SkipMiningDOM  bool

	// SkipAST disables dalfox's AST-based DOM-XSS detection
	// (--skip-ast-analysis): the source→sink static analysis of JavaScript
	// that emits the noisy, unverified "[A]" DOM-XSS findings. Note that
	// --skip-mining-dom does NOT silence those — only this flag does.
	SkipAST bool

	// OnlyPoC filters which finding types dalfox reports (--only-poc), as a
	// comma-separated subset of v (verified), r (reflected), a (AST DOM), i
	// (informational), e.g. "v" or "v,r". Values outside that set are dropped.
	// Scan also enforces the same filter on the parsed findings, so the API
	// never surfaces a type the caller excluded regardless of dalfox's output.
	OnlyPoC string

	// BlindURL is an out-of-band callback for blind XSS (-b); must be http(s).
	BlindURL string

	// RateLimit caps global requests/second (-r); 0 = unlimited.
	RateLimit int
	// FollowRedirects enables -F.
	FollowRedirects bool
	// DeepScan lifts the per-parameter payload cap (--deep-scan).
	DeepScan bool
	// WAFEvasion enables adaptive WAF evasion (--waf-evasion).
	WAFEvasion bool

	// StoredXSS enables stored-XSS mode (--sxss); SXSSURL optionally sets the
	// reflection-check URL (--sxss-url) and must be http(s).
	StoredXSS bool
	SXSSURL   string

	// CustomPayloadFile is a path to a payloads file (--custom-payload). The
	// caller is responsible for creating it (e.g. the handler writes a temp
	// file from inline payloads).
	CustomPayloadFile string
}

// knownMethods bounds -X to real HTTP verbs so an arbitrary string cannot be
// smuggled onto the command line as a method.
var knownMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// isHTTPURL reports whether s parses as an absolute http(s) URL with a host.
func isHTTPURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// Installed reports whether the dalfox binary is resolvable on PATH.
func Installed() bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// validateTarget ensures the target is a well-formed absolute http(s) URL. This
// both rejects nonsense early and prevents a target that looks like a flag
// (e.g. "-o/etc/passwd") from reaching dalfox: a valid http(s) URL cannot begin
// with a dash. exec.Command already avoids shell interpretation, so there is no
// shell-injection surface — this guards only against argument confusion.
func validateTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("target URL is required")
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("target URL must use http or https")
	}
	if u.Host == "" {
		return "", errors.New("target URL must include a host")
	}
	return u.String(), nil
}

// Scan runs dalfox against a single URL and returns the parsed findings. It
// returns ErrNotInstalled when the binary is missing so the caller can respond
// distinctly. A non-zero dalfox exit is tolerated as long as it still produced
// parseable JSON (dalfox can exit non-zero on partial failures).
func Scan(ctx context.Context, target string, opt Options) (*Result, error) {
	clean, err := validateTarget(target)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, ErrNotInstalled
	}

	cmd := exec.CommandContext(ctx, binary, buildArgs(clean, opt)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// Context cancellation (timeout) is a definitive failure regardless of any
	// partial output.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("dalfox scan timed out: %w", ctxErr)
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) > maxOutputBytes {
		out = out[:maxOutputBytes]
	}

	rep, parseErr := parseReport(out)
	if parseErr != nil {
		// No parseable JSON: surface dalfox's own stderr if any, else the run
		// error, so the failure is legible in the UI.
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && runErr != nil {
			msg = runErr.Error()
		}
		if msg == "" {
			msg = parseErr.Error()
		}
		return nil, fmt.Errorf("dalfox produced no parseable output: %s", msg)
	}

	pocs := filterByType(rep.Findings, opt.OnlyPoC)
	return &Result{
		Target: clean,
		Count:  len(pocs),
		PoCs:   pocs,
		Meta:   rep.Meta,
	}, nil
}

// pocTypes is the set of finding-type codes dalfox emits (and --only-poc / the
// server-side filter accept), case-insensitive.
var pocTypes = map[string]bool{"v": true, "r": true, "a": true, "i": true}

// normalizeOnlyPoC validates and canonicalises an --only-poc value into a
// comma-separated list of known lower-case type codes, dropping anything
// unrecognised. It returns "" when nothing valid remains, so buildArgs omits
// the flag rather than passing dalfox a malformed value.
func normalizeOnlyPoC(s string) string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(s, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if pocTypes[p] && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

// filterByType enforces an OnlyPoC filter on parsed findings so the API never
// surfaces a type the caller excluded, independent of how dalfox honours
// --only-poc in its JSON. An empty/invalid filter returns the findings as-is.
func filterByType(pocs []PoC, onlyPoC string) []PoC {
	norm := normalizeOnlyPoC(onlyPoC)
	if norm == "" {
		if pocs == nil {
			return []PoC{}
		}
		return pocs
	}
	keep := map[string]bool{}
	for _, t := range strings.Split(norm, ",") {
		keep[t] = true
	}
	out := make([]PoC, 0, len(pocs))
	for _, p := range pocs {
		if keep[strings.ToLower(strings.TrimSpace(p.Type))] {
			out = append(out, p)
		}
	}
	return out
}

// buildArgs assembles the dalfox v3 command line for a validated target.
// Defaults fill in any non-positive Options field. --silence + --no-color keep
// stdout to clean JSON only (v3 writes the report object to stdout).
func buildArgs(clean string, opt Options) []string {
	workers := opt.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}
	timeout := opt.TimeoutSecs
	if timeout <= 0 {
		timeout = defaultTimeoutSecs
	}
	delay := opt.DelayMillis
	if delay < 0 {
		delay = defaultDelayMillisec
	}

	args := []string{
		"scan", clean,
		"--format", "json",
		"--silence",
		"--no-color",
		"--workers", strconv.Itoa(workers),
		"--timeout", strconv.Itoa(timeout),
		"--delay", strconv.Itoa(delay),
	}
	if opt.RateLimit > 0 {
		args = append(args, "--rate-limit", strconv.Itoa(opt.RateLimit))
	}
	if opt.ScanTimeoutSecs > 0 {
		args = append(args, "--scan-timeout", strconv.Itoa(opt.ScanTimeoutSecs))
	}

	// Mining toggles.
	if opt.SkipMining {
		args = append(args, "--skip-mining")
	}
	if opt.SkipMiningDict {
		args = append(args, "--skip-mining-dict")
	}
	if opt.SkipMiningDOM {
		args = append(args, "--skip-mining-dom")
	}
	if opt.SkipAST {
		args = append(args, "--skip-ast-analysis")
	}
	if p := normalizeOnlyPoC(opt.OnlyPoC); p != "" {
		args = append(args, "--only-poc", p)
	}

	// Boolean switches.
	if opt.FollowRedirects {
		args = append(args, "--follow-redirects")
	}
	if opt.DeepScan {
		args = append(args, "--deep-scan")
	}
	if opt.WAFEvasion {
		args = append(args, "--waf-evasion")
	}
	if opt.StoredXSS {
		args = append(args, "--sxss")
	}

	// String/value flags. Each value is a distinct arg after its flag, so a
	// leading dash cannot be read as another flag; no shell interpretation
	// occurs. URLs and the method are validated to reject obvious misuse.
	if c := strings.TrimSpace(opt.Cookie); c != "" {
		args = append(args, "--cookies", c)
	}
	for _, h := range opt.Headers {
		if h = strings.TrimSpace(h); h != "" {
			args = append(args, "-H", h)
		}
	}
	if ua := strings.TrimSpace(opt.UserAgent); ua != "" {
		args = append(args, "--user-agent", ua)
	}
	if m := strings.ToUpper(strings.TrimSpace(opt.Method)); knownMethods[m] {
		args = append(args, "-X", m)
	}
	if isHTTPURL(opt.BlindURL) {
		args = append(args, "-b", strings.TrimSpace(opt.BlindURL))
	}
	if opt.StoredXSS && isHTTPURL(opt.SXSSURL) {
		args = append(args, "--sxss-url", strings.TrimSpace(opt.SXSSURL))
	}
	if p := strings.TrimSpace(opt.CustomPayloadFile); p != "" {
		args = append(args, "--custom-payload", p)
	}
	return args
}

// parseReport decodes dalfox v3's JSON report object ({ findings, meta }). An
// empty output is treated as a clean, no-findings report.
func parseReport(out []byte) (report, error) {
	if len(out) == 0 {
		return report{Findings: []PoC{}}, nil
	}
	var rep report
	if err := json.Unmarshal(out, &rep); err != nil {
		return report{}, err
	}
	if rep.Findings == nil {
		rep.Findings = []PoC{}
	}
	return rep, nil
}
