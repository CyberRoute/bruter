package handlers

import (
	"encoding/json"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/scan"
	"io"
	"net/http"
	"os"
)

// Repo used by the handlers
var Repo *Repository

// Repository is the repository type
type Repository struct {
	App   *config.AppConfig
	Scans *scan.Manager
}

// NewRepo creates a new repository
func NewRepo(a *config.AppConfig) *Repository {
	return &Repository{
		App:   a,
		Scans: scan.NewManager(),
	}
}

// NewHandlers sets the repository for the handlers
func NewHandlers(r *Repository) {
	Repo = r
}

func (m *Repository) Consumer(w http.ResponseWriter, r *http.Request) {
	// acquire lock
	m.App.Mu.Lock()
	defer m.App.Mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	session_file := m.App.Domain + ".json"
	file, err := os.OpenFile(session_file, os.O_CREATE|os.O_RDWR, 0644)
	m.checkError(err)
	defer file.Close()

	b, err := io.ReadAll(file)
	m.checkError(err)
	var allUrls models.AllUrls
	if len(b) > 0 {
		err = json.Unmarshal(b, &allUrls.Urls)
		m.checkError(err)
	}

	err = json.NewEncoder(w).Encode(allUrls)
	m.checkError(err)
}

func (m *Repository) checkError(err error) {
	if err != nil {
		m.App.ZeroLog.Error().Err(err).Msg("")
	}
}
