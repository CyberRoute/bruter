package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrawlDiscoversSurface(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<html><body>
			  <a href="/page?id=1">param link</a>
			  <a href="/about">plain link</a>
			  <a href="http://external.example/evil?x=1">offsite</a>
			  <form action="/search" method="get">
			    <input name="q"><input name="lang">
			  </form>
			  <script src="/app.js"></script>
			  <script>var u = "/inline?token=zzz";</script>
			</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/data?auth=abc").then(r=>r.json());`))
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>about</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Crawl(ctx, srv.URL, Options{MaxDepth: 1, MaxPages: 20})
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	// Index targets by a "url|params|source" key for assertions.
	have := map[string]bool{}
	for _, tg := range res.Targets {
		have[tg.Source+":"+strings.TrimPrefix(tg.URL, srv.URL)+"?"+strings.Join(tg.Params, ",")] = true
	}

	wantContains := []struct{ substr string }{
		{"link:/page?id"},      // parameterised link
		{"form:/search?lang"},  // form action with encoded input names (?lang=&q=)
		{"js:/api/data?auth"},  // endpoint + param from external script
		{"js:/inline?token"},   // endpoint + param from inline script
	}
	for _, w := range wantContains {
		found := false
		for k := range have {
			if strings.HasPrefix(k, w.substr) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected target %q in %v", w.substr, keys(have))
		}
	}

	// Offsite target must never be scanned.
	for _, tg := range res.Targets {
		if strings.Contains(tg.URL, "external.example") {
			t.Errorf("offsite target leaked into results: %s", tg.URL)
		}
	}
}

func TestCrawlRejectsBadSeed(t *testing.T) {
	for _, seed := range []string{"", "ftp://x", "notaurl", "http://"} {
		if _, err := Crawl(context.Background(), seed, Options{}); err == nil {
			t.Errorf("expected error for seed %q", seed)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
