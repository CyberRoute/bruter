package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/render"
	"github.com/CyberRoute/bruter/pkg/ssl"
	"io"
	"net/http"
	"os"
	"strings"
)

// Repo used by the handlers
var Repo *Repository

// Repository is the repository type
type Repository struct {
	App *config.AppConfig
}

// NewRepo creates a new repository
func NewRepo(a *config.AppConfig) *Repository {
	return &Repository{
		App: a,
	}
}

// NewHandlers sets the repository for the handlers
func NewHandlers(r *Repository) {
	Repo = r
}

func (m *Repository) Home(args models.HomeArgs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stringMap := make(map[string]string)
		uint16Map := make(map[string]interface{})
		headersMap := make(map[string]interface{})
		stringMap["ipv4_address"] = args.Ipv4
		stringMap["ipv6_address"] = args.Ipv6
		stringMap["domain"] = m.App.Domain
		stringMap["asn"] = args.Host.Asn
		stringMap["city"] = args.Host.City
		stringMap["country"] = args.Host.CountryName
		stringMap["isp"] = args.Host.Isp
		stringMap["org"] = args.Host.Org
		stringMap["region_code"] = args.Host.RegionCode
		stringMap["ports"] = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(args.Host.Ports)), ",\n"), "[]")
		uint16Map["mx"] = args.Mx
		headersMap["headers"] = args.Headers
		stringMap["banner_ftp"] = args.Ftp
		stringMap["banner_ssh"] = args.Ssh
		stringMap["banner_mysql"] = args.Mysql
		stringMap["banner_smtp"] = args.Smtp
		stringMap["banner_pop"] = args.Pop
		stringMap["banner_irc"] = args.Irc

		render.RenderTemplate(w, "home.page.html", &models.TemplateData{
			StringMap:  stringMap,
			Data:       uint16Map,
			HeadersMap: headersMap,
		})
	}
}

func (m *Repository) SSLInfo(args models.TemplateData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var templateData models.TemplateData
		sslInfo, err := ssl.FetchCrtData(m.App.Domain)
		m.checkError(err)
		templateData.SSLInfo = sslInfo
		render.RenderTemplate(w, "ssl.page.html", &templateData)
	}
}

func (m *Repository) WhoisInfo(args models.TemplateData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var templateData models.TemplateData
		whoisInfo, err := network.WhoisLookup(m.App.Domain)
		m.checkError(err)
		templateData.WhoisInfo = whoisInfo
		render.RenderTemplate(w, "whois.page.html", &templateData)
	}
}

func (m *Repository) Consumer(w http.ResponseWriter, r *http.Request) {
	// acquire lock
	m.App.Mu.Lock()
	defer m.App.Mu.Unlock()

	w.WriteHeader(http.StatusOK)
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
