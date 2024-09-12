package middleware

import (
	"net/http"
	"github.com/CyberRoute/bruter/pkg/config"
)

// SessionLoad loads and saves the session on every request
func SessionLoad(app *config.AppConfig, next http.Handler) http.Handler {
	return app.Session.LoadAndSave(next)
}
