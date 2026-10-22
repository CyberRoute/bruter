package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<html><head><TITLE>  Hello\n World </TITLE></head>": "Hello World",
		"<title>only</title>":                                "only",
		"no title here":                                      "",
	}
	for body, want := range cases {
		if got := extractTitle(body); got != want {
			t.Errorf("extractTitle(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestClassifyCORS(t *testing.T) {
	mk := func(acao, acac string) http.Header {
		h := http.Header{}
		if acao != "" {
			h.Set("Access-Control-Allow-Origin", acao)
		}
		if acac != "" {
			h.Set("Access-Control-Allow-Credentials", acac)
		}
		return h
	}
	if got := classifyCORS(mk(corsProbeOrigin, "true")); got != "reflects arbitrary origin with credentials" {
		t.Errorf("reflect+creds = %q", got)
	}
	if got := classifyCORS(mk("*", "")); got != "wildcard" {
		t.Errorf("wildcard = %q", got)
	}
	if got := classifyCORS(mk("https://legit.example.com", "")); got != "" {
		t.Errorf("specific origin should not flag, got %q", got)
	}
}

func TestMissingSecurityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'")
	missing := missingSecurityHeaders(h)
	// CSP present; the other three should be reported missing.
	if len(missing) != 3 {
		t.Fatalf("missing = %v, want 3 entries", missing)
	}
	for _, m := range missing {
		if m == "Content-Security-Policy" {
			t.Errorf("CSP present but reported missing")
		}
	}
}

func TestCheckTakeover(t *testing.T) {
	if FingerprintCount() == 0 {
		t.Fatal("no fingerprints loaded")
	}

	t.Run("cname + signature -> vulnerable", func(t *testing.T) {
		tk := checkTakeover("myapp.github.io.", "Blah blah There isn't a GitHub Pages site here. blah")
		if tk == nil || !tk.Vulnerable {
			t.Fatalf("expected vulnerable takeover, got %+v", tk)
		}
		if tk.Service != "GitHub Pages" {
			t.Errorf("service = %q, want GitHub Pages", tk.Service)
		}
	})

	t.Run("cname match but no signature -> match, not vulnerable", func(t *testing.T) {
		tk := checkTakeover("myapp.github.io", "a normal live page")
		if tk == nil {
			t.Fatal("expected a non-nil match for the service CNAME")
		}
		if tk.Vulnerable {
			t.Error("should not be vulnerable without the signature")
		}
		if tk.Service != "GitHub Pages" {
			t.Errorf("service = %q, want GitHub Pages", tk.Service)
		}
	})

	t.Run("unknown cname -> nil", func(t *testing.T) {
		if tk := checkTakeover("something.example.com", "body"); tk != nil {
			t.Errorf("expected nil for unknown CNAME, got %+v", tk)
		}
	})
}

func TestProbeHostsLive(t *testing.T) {
	// Spin up a local server that reflects an attacker Origin and omits every
	// security header, then probe it to exercise the full path end-to-end.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Server", "test-server")
		_, _ = w.Write([]byte("<html><head><title>Probe Target</title></head><body>wp-content</body></html>"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	// Point the probe at the test server's host:port via http scheme by using
	// the loopback hostname; ProbeHosts tries https first (fails fast) then http.
	host := u.Host

	// The host here is "127.0.0.1:port"; ProbeHosts requires a dotted name,
	// which an IP:port satisfies. Resolution of a bare IP is a no-op.
	results := ProbeHosts(context.Background(), []string{host}, 2)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 (err=%q)", r.Status, r.Error)
	}
	if r.Title != "Probe Target" {
		t.Errorf("title = %q, want %q", r.Title, "Probe Target")
	}
	if !strings.Contains(r.CORS, "reflects arbitrary origin") {
		t.Errorf("CORS = %q, want reflective flag", r.CORS)
	}
	if len(r.MissingHeaders) == 0 {
		t.Errorf("expected missing security headers to be reported")
	}
	containsTech := false
	for _, tch := range r.Tech {
		if tch == "WordPress" {
			containsTech = true
		}
	}
	if !containsTech {
		t.Errorf("tech = %v, want WordPress detected from body marker", r.Tech)
	}
}
