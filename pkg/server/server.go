package server

import (
	"github.com/CyberRoute/bruter/pkg/config"
	servermiddleware "github.com/CyberRoute/bruter/pkg/server/middleware"
	"github.com/CyberRoute/bruter/pkg/server/routes"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func NewServer(app *config.AppConfig) *chi.Mux {
	mux := chi.NewRouter()

	mux.Use(middleware.Recoverer)
	// Reject non-loopback Host headers and non-JSON API mutations before any
	// handler can start an active scan.
	mux.Use(servermiddleware.Guard(app.BindAddr, app.AllowRemote))
	mux.Use(app.Session.LoadAndSave)

	sc := NewConfigServer(app)

	homeArgs := sc.RunConfiguration(app)

	routes.Routes(mux, homeArgs)

	return mux
}
