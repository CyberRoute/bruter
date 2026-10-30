package config

import (
	"github.com/rs/zerolog"
	"sync"

	"github.com/alexedwards/scs/v2"
)

// AppConfig holds the application config
type AppConfig struct {
	ZeroLog      *zerolog.Logger
	InProduction bool
	Session      *scs.SessionManager
	Domain       string
	// Target is the authority (host[:port]) used for the HTTP path-fuzzing
	// probes. Unlike Domain it preserves an explicit port and is not stripped
	// of a "www." prefix, so a target on a non-standard port (e.g. a local
	// DVWA on :8081) is probed exactly as the user named it. Domain stays the
	// bare host used for DNS, subdomain and certificate enumeration.
	Target       string
	Scheme       string
	ShodanAPIKey string
	// BindAddr is the interface the UI listens on. AllowRemote must be set
	// before a non-loopback bind is accepted, because the UI has no
	// authentication and its scan endpoints make live requests.
	BindAddr    string
	AllowRemote bool
	Mu          sync.Mutex
}
