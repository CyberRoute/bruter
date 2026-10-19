package middleware

import (
	"github.com/CyberRoute/bruter/pkg/config"
	"net/http"
)

// SessionLoad loads and saves the session on every request
func SessionLoad(app *config.AppConfig, next http.Handler) http.Handler {
	return app.Session.LoadAndSave(next)
}
