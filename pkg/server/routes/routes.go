package routes

import (
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/go-chi/chi/v5"
	"net/http"
)

func Routes(mux *chi.Mux, homeArgs models.HomeArgs, sslArgs, whoIsArgs models.TemplateData) {
	mux.Get("/", handlers.Repo.Home(homeArgs))
	mux.Get("/ssl", handlers.Repo.SSLInfo(sslArgs))
	mux.Get("/whois", handlers.Repo.WhoisInfo(whoIsArgs))
	mux.Get("/consumer", handlers.Repo.Consumer)
	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/*", http.StripPrefix("/static", fileServer))
}
