package config

import (
	"html/template"
	"log"
	"sync"

	"github.com/alexedwards/scs/v2"
)

// AppConfig holds the application config
type AppConfig struct {
	UseCache      bool
	TemplateCache map[string]*template.Template
	InfoLog       *log.Logger
	InProduction  bool
	Session       *scs.SessionManager
	Domain        string
	ShodanAPIKey  string
	Mu            sync.Mutex
}
