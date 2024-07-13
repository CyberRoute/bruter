package middleware

import (
	"github.com/alexedwards/scs/v2"
	"net/http"
)

var session *scs.SessionManager

// SessionLoad loads and saves the session on every request
func SessionLoad(next http.Handler) http.Handler {
	return session.LoadAndSave(next)
}
