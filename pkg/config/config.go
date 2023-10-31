package config

import (
	"github.com/rs/zerolog"
	"html/template"
	"sync"

	"github.com/alexedwards/scs/v2"
)

// AppConfig holds the application config
type AppConfig struct {
	UseCache      bool
	TemplateCache map[string]*template.Template
	ZeroLog       *zerolog.Logger
	InProduction  bool
	Session       *scs.SessionManager
	Domain        string
	ShodanAPIKey  string
	Mu            sync.Mutex
}
