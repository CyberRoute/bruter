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
	Scheme       string
	ShodanAPIKey string
	Mu           sync.Mutex
}
