// Package web embeds the built React single-page app (web/dist) into the Go
// binary and serves it. Run `npm --prefix web run build` before `go build` so
// the dist directory exists; the Makefile and Dockerfile wire this up.
package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"embed"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded SPA. Requests for
// real assets are served directly; any other path falls back to index.html so
// client-side routes (/ssl, /whois) resolve on reload and deep links.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, statErr := fs.Stat(sub, p); statErr != nil {
			// Not a bundled file — let the SPA entrypoint handle routing.
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}
