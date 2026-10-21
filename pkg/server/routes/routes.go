package routes

import (
	"net/http"

	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/web"
	"github.com/go-chi/chi/v5"
)

// Routes wires the JSON API consumed by the embedded React UI and serves the
// SPA itself for every other path. The legacy server-rendered template routes
// have been replaced by the React dashboard.
func Routes(mux *chi.Mux, homeArgs models.HomeArgs) {
	// JSON API.
	mux.Get("/api/host", handlers.Repo.HostAPI(homeArgs))
	mux.Get("/api/ssl", handlers.Repo.SSLAPI)
	mux.Get("/api/dns", handlers.Repo.DNSAPI)
	mux.Get("/api/subdomains/brute", handlers.Repo.SubdomainBruteAPI)
	mux.Get("/api/reverseip", handlers.Repo.ReverseIPAPI)
	mux.Get("/api/robtex", handlers.Repo.RobtexAPI)
	mux.Get("/api/whois", handlers.Repo.WhoisAPI)

	// Live directory-fuzzing feed (polled by the dashboard).
	mux.Get("/consumer", handlers.Repo.Consumer)

	// Embedded React single-page app (serves "/", "/ssl", "/whois", assets).
	spa := web.Handler()
	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		spa.ServeHTTP(w, r)
	})
	mux.Handle("/*", spa)
}
