// Package crawl performs a bounded, same-host crawl of a web target and a
// lightweight static analysis of its JavaScript to discover the attack surface
// a scanner cares about: URLs that carry parameters, form actions and their
// input names, and endpoints/parameters referenced from scripts.
//
// It is an ACTIVE operation — it fetches pages and scripts from the target —
// so it stays strictly on the seed host and is bounded by depth, page count
// and a context deadline. Only run it against systems you are authorised to
// test.
package crawl

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// errInvalidSeed is returned when the seed is not a usable http(s) URL.
var errInvalidSeed = errors.New("seed must be an absolute http(s) URL with a host")

// Defaults bound a crawl so it cannot run away on a large or hostile site.
const (
	defaultMaxDepth   = 2
	defaultMaxPages   = 100
	defaultWorkers    = 10
	maxBodyRead       = 2 << 20 // 2 MiB per page/script
	maxScriptsPerPage = 25      // bound script fetching so one page cannot eat the crawl budget
	requestTimeout    = 10 * time.Second
)

// client mirrors pkg/probe's client: pooled connections, certs not verified
// (crawling untrusted hosts by design). Redirects are followed so a crawl that
// starts at "/" reaches the real landing page.
var client = &http.Client{
	Timeout: requestTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // crawling untrusted hosts by design
		MaxIdleConnsPerHost: 8,
	},
}

// Target is one discovered piece of attack surface.
type Target struct {
	URL    string   `json:"url"`
	Params []string `json:"params"`
	Source string   `json:"source"` // "link" | "form" | "js"

	// Method and Data describe how to scan a non-GET form. A POST form cannot
	// be scanned by putting its fields in the query string, so its action URL
	// is kept clean and its fields become the request body instead.
	Method string `json:"method,omitempty"`
	Data   string `json:"data,omitempty"`
	// ReflectURL is the page a form was found on. Stored-XSS payloads submitted
	// to a form action typically render on that page, so it is the natural
	// candidate for dalfox's --sxss-url.
	ReflectURL string `json:"reflect_url,omitempty"`
}

// Options tunes a crawl. The zero value uses the package defaults.
type Options struct {
	MaxDepth  int
	MaxPages  int
	Workers   int
	Cookie    string // raw Cookie header value, forwarded on every request
	UserAgent string
}

// Result is the outcome of a crawl.
type Result struct {
	Seed    string   `json:"seed"`
	Pages   int      `json:"pages"`
	Targets []Target `json:"targets"`
}

// logoutRe matches links that would end the crawler's own session (logging it
// out), matched case-insensitively against the URL path. Following such a link
// during an authenticated crawl (e.g. DVWA's /logout.php) destroys the session
// server-side and makes every subsequent page redirect to login, so these
// links are discovered but never fetched or queued.
var logoutRe = regexp.MustCompile(`(?i)(log[-_]?out|sign[-_]?out|log[-_]?off)`)

// destroysSession reports whether following u would likely end the session.
func destroysSession(u *url.URL) bool {
	return logoutRe.MatchString(u.Path)
}

// jsURLRe matches quoted absolute URLs and root-relative paths inside scripts.
var jsURLRe = regexp.MustCompile(`["'` + "`" + `]((?:https?:)?//[^"'` + "`" + `\s]+|/[A-Za-z0-9_][A-Za-z0-9_./\-]*(?:\?[^"'` + "`" + `\s]*)?)["'` + "`" + `]`)

// Crawl walks the seed host breadth-first and returns the discovered targets,
// de-duplicated and sorted with parameterised URLs first (the richer surface).
func Crawl(ctx context.Context, seed string, opt Options) (*Result, error) {
	base, err := normalizeSeed(seed)
	if err != nil {
		return nil, err
	}
	maxDepth := opt.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	maxPages := opt.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	workers := opt.Workers
	if workers <= 0 {
		workers = defaultWorkers
	}

	// Confine the crawl to the seed's directory: a seed of
	// "/vulnerabilities/xss_r/" stays under that path instead of following the
	// site-wide nav to every other page. A root seed ("/") yields the prefix
	// "/", i.e. the whole host, preserving the previous behaviour.
	scopePrefix := scopeDir(base.Path)
	inScope := func(u *url.URL) bool {
		return sameHost(base, u) && strings.HasPrefix(u.Path, scopePrefix)
	}

	visited := map[string]bool{base.String(): true}
	targetSet := map[string]Target{} // key: url + "\x00" + params
	frontier := []string{base.String()}
	pages := 0

	addTarget := func(t Target) {
		if t.URL == "" {
			return
		}
		// Keep only targets within the crawl scope (same host + path prefix);
		// e.g. a login form action discovered on an in-scope page is dropped.
		if u, err := url.Parse(t.URL); err != nil || !inScope(u) {
			return
		}
		// Always emit a (possibly empty) array, never a nil slice: Go marshals
		// nil as JSON null, and the UI calls params.join() on it and crashes.
		if t.Params == nil {
			t.Params = []string{}
		}
		sort.Strings(t.Params)
		key := t.URL + "\x00" + strings.Join(t.Params, ",") + "\x00" + t.Method + "\x00" + t.Data
		if _, ok := targetSet[key]; !ok {
			targetSet[key] = t
		}
	}

	for depth := 0; depth <= maxDepth && len(frontier) > 0 && pages < maxPages; depth++ {
		remaining := maxPages - pages
		if len(frontier) > remaining {
			frontier = frontier[:remaining]
		}
		pages += len(frontier)

		pageResults := fetchLevel(ctx, frontier, base, opt, workers)

		var next []string
		for _, pr := range pageResults {
			for _, t := range pr.targets {
				addTarget(t)
			}
			for _, link := range pr.links {
				lu, err := url.Parse(link)
				if err != nil || !inScope(lu) {
					continue
				}
				// Never follow a logout/sign-out link: it would end an
				// authenticated crawl's session and send the rest to login.
				if destroysSession(lu) {
					continue
				}
				clean := canonical(lu)
				if visited[clean] {
					continue
				}
				visited[clean] = true
				if len(lu.Query()) > 0 {
					addTarget(Target{URL: clean, Params: paramKeys(lu), Source: "link"})
				}
				if depth < maxDepth {
					next = append(next, clean)
				}
			}
		}
		frontier = next
		if ctx.Err() != nil {
			break
		}
	}

	targets := make([]Target, 0, len(targetSet))
	for _, t := range targetSet {
		targets = append(targets, t)
	}
	sortTargets(targets)

	return &Result{Seed: base.String(), Pages: pages, Targets: targets}, nil
}

// pageResult carries what one fetched page yielded.
type pageResult struct {
	links   []string // absolute URLs to consider for further crawling
	targets []Target // forms + JS-derived targets on this page
}

// fetchLevel fetches every URL in urls concurrently (bounded by workers) and
// returns the parsed result for each.
func fetchLevel(ctx context.Context, urls []string, base *url.URL, opt Options, workers int) []pageResult {
	type job struct {
		idx int
		url string
	}
	results := make([]pageResult, len(urls))
	jobs := make(chan job)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.idx] = fetchPage(ctx, j.url, base, opt)
			}
		}()
	}
	for i, u := range urls {
		jobs <- job{idx: i, url: u}
	}
	close(jobs)
	wg.Wait()
	return results
}

// fetchPage fetches one URL, parses HTML for links/forms, and statically
// analyses any same-host scripts it references and inlines.
func fetchPage(ctx context.Context, pageURL string, base *url.URL, opt Options) pageResult {
	body, ctype := get(ctx, pageURL, opt)
	if body == nil {
		return pageResult{}
	}
	pu, err := url.Parse(pageURL)
	if err != nil {
		return pageResult{}
	}

	// A directly-fetched script (e.g. the seed is a .js) is analysed as JS.
	if isScriptContentType(ctype) {
		return pageResult{targets: extractFromJS(base, body)}
	}

	links, forms, scripts, inline := parseHTML(pu, body)
	res := pageResult{links: links, targets: forms}
	for i, s := range scripts {
		if i >= maxScriptsPerPage {
			break
		}
		su, err := url.Parse(s)
		if err != nil || !sameHost(base, su) {
			continue
		}
		if js, _ := get(ctx, su.String(), opt); js != nil {
			res.targets = append(res.targets, extractFromJS(base, js)...)
		}
	}
	for _, code := range inline {
		res.targets = append(res.targets, extractFromJS(base, []byte(code))...)
	}
	return res
}

// isScriptContentType reports whether a response body should be analysed as
// JavaScript rather than HTML.
func isScriptContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// get fetches a URL and returns its (bounded) body and content-type, or nil on
// any error or non-2xx status.
func get(ctx context.Context, u string, opt Options) ([]byte, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, ""
	}
	if opt.Cookie != "" {
		req.Header.Set("Cookie", opt.Cookie)
	}
	if opt.UserAgent != "" {
		req.Header.Set("User-Agent", opt.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, ""
	}
	return body, resp.Header.Get("Content-Type")
}

// parseHTML extracts absolute links, form targets, external script srcs and
// inline script bodies from an HTML document fetched at pageURL.
func parseHTML(pageURL *url.URL, body []byte) (links []string, forms []Target, scripts []string, inline []string) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href := attr(n, "href"); href != "" {
					if abs := resolve(pageURL, href); abs != "" {
						links = append(links, abs)
					}
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					if abs := resolve(pageURL, src); abs != "" {
						scripts = append(scripts, abs)
					}
				} else if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					inline = append(inline, n.FirstChild.Data)
				}
			case "form":
				forms = append(forms, formTarget(pageURL, n))
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	// Drop a possible empty form target.
	cleaned := forms[:0]
	for _, f := range forms {
		if f.URL != "" {
			cleaned = append(cleaned, f)
		}
	}
	return links, cleaned, scripts, inline
}

// formTarget builds a Target from a <form>: its resolved action URL plus the
// names of its input/select/textarea controls.
func formTarget(pageURL *url.URL, form *html.Node) Target {
	action := attr(form, "action")
	actionURL := pageURL.String()
	if action != "" {
		if abs := resolve(pageURL, action); abs != "" {
			actionURL = abs
		}
	}
	var params []string
	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
			// Skip submit/button controls — they are not injectable params.
			if t := strings.ToLower(attr(n, "type")); t == "submit" || t == "button" || t == "reset" {
				return
			}
			if name := attr(n, "name"); name != "" && !seen[name] {
				seen[name] = true
				params = append(params, name)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)

	// A non-GET form is scanned with its own method and body: putting the
	// fields in the query string would test an endpoint the application does
	// not read (and usually miss the injection entirely). The page the form
	// lives on is kept as the candidate reflection URL for stored XSS.
	method := strings.ToUpper(strings.TrimSpace(attr(form, "method")))
	base := stripQuery(actionURL)
	vals := url.Values{}
	for _, p := range params {
		vals.Set(p, "")
	}
	if method != "" && method != http.MethodGet {
		return Target{
			URL:        base,
			Params:     params,
			Source:     "form",
			Method:     method,
			Data:       vals.Encode(),
			ReflectURL: pageURL.String(),
		}
	}

	// GET form: encode the discovered parameters into the action URL so the
	// target is directly scannable. dalfox tests the params present in the
	// URL, so a GET form must carry "?a=&b=" or a mining-skipped scan finds
	// nothing.
	if len(params) == 0 {
		return Target{URL: base, Source: "form"}
	}
	return Target{URL: base + "?" + vals.Encode(), Params: params, Source: "form"}
}

// extractFromJS pulls candidate same-host URLs/paths out of a script and turns
// any that carry query parameters into targets.
func extractFromJS(base *url.URL, js []byte) []Target {
	var out []Target
	seen := map[string]bool{}
	for _, m := range jsURLRe.FindAllStringSubmatch(string(js), -1) {
		raw := m[1]
		if strings.HasPrefix(raw, "//") {
			raw = base.Scheme + ":" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(u)
		if !sameHost(base, abs) || len(abs.Query()) == 0 {
			continue
		}
		clean := canonical(abs)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, Target{URL: clean, Params: paramKeys(abs), Source: "js"})
	}
	return out
}

// --- small helpers ---------------------------------------------------------

func normalizeSeed(seed string) (*url.URL, error) {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return nil, errInvalidSeed
	}
	u, err := url.Parse(seed)
	if err != nil {
		return nil, errInvalidSeed
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errInvalidSeed
	}
	if u.Host == "" {
		return nil, errInvalidSeed
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u, nil
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// resolve turns a possibly-relative href into an absolute URL string, dropping
// non-navigational schemes (mailto:, javascript:, tel:, #fragments).
func resolve(base *url.URL, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "#") {
		return ""
	}
	low := strings.ToLower(href)
	for _, bad := range []string{"mailto:", "javascript:", "tel:", "data:"} {
		if strings.HasPrefix(low, bad) {
			return ""
		}
	}
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	abs.Fragment = ""
	return abs.String()
}

func sameHost(base, u *url.URL) bool {
	return u != nil && strings.EqualFold(u.Host, base.Host)
}

// scopeDir returns the directory prefix a crawl is confined to: the seed path
// itself when it ends in "/", otherwise the directory containing the seed file.
// A root or empty path yields "/", i.e. the whole host.
func scopeDir(p string) string {
	if p == "" {
		return "/"
	}
	if strings.HasSuffix(p, "/") {
		return p
	}
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i+1]
	}
	return "/"
}

// canonical returns a comparable URL string: fragment stripped, query kept.
func canonical(u *url.URL) string {
	c := *u
	c.Fragment = ""
	return c.String()
}

func stripQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func paramKeys(u *url.URL) []string {
	var keys []string
	for k := range u.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortTargets orders parameterised targets first, then by URL, for a stable,
// useful presentation.
func sortTargets(ts []Target) {
	sort.Slice(ts, func(i, j int) bool {
		pi, pj := len(ts[i].Params) > 0, len(ts[j].Params) > 0
		if pi != pj {
			return pi
		}
		if ts[i].URL != ts[j].URL {
			return ts[i].URL < ts[j].URL
		}
		return ts[i].Source < ts[j].Source
	})
}
