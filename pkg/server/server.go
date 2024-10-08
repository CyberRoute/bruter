package server

import (
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/server/routes"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewServer(app *config.AppConfig) *chi.Mux {
	mux := chi.NewRouter()

	mux.Use(middleware.Recoverer)
	mux.Use(app.Session.LoadAndSave)

	sc := NewConfigServer(app)

	homeArgs, sslArgs, whoIsArgs := sc.RunConfiguration(app)

	routes.Routes(mux, homeArgs, sslArgs, whoIsArgs)

	return mux
}
