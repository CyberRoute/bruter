package handlers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/grabber"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/render"
	"github.com/CyberRoute/bruter/pkg/shodan"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func (m *Repository) Home(w http.ResponseWriter, r *http.Request) {
	stringMap := make(map[string]string)
	uint16Map := make(map[string]interface{})
	headersMap := make(map[string]interface{})
	IPv4, err := network.ResolveByName(m.App.Domain)
	checkError(err)
	IPv6, err := network.ResolveByNameipv6(m.App.Domain)
	checkError(err)
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: customTransport}
	shodan := shodan.NewClient(client, IPv4, m.App.ShodanAPIKey)
	host, err := shodan.HostInfo()
	checkError(err)
	stringMap["ipv4_address"] = IPv4
	stringMap["ipv6_address"] = IPv6
	stringMap["domain"] = m.App.Domain
	stringMap["asn"] = host.Asn
	stringMap["city"] = host.City
	stringMap["country"] = host.CountryName
	stringMap["isp"] = host.Isp
	stringMap["org"] = host.Org
	stringMap["region_code"] = host.RegionCode
	stringMap["ports"] = strings.Trim(strings.Join(strings.Fields(fmt.Sprint(host.Ports)), ",\n"), "[]")
	mx_records, _ := network.FindMX(m.App.Domain)
	uint16Map["mx"] = mx_records
	info, err := shodan.Head("http://" + m.App.Domain)
	checkError(err)
	headersMap["headers"] = info
	mysql, err := grabber.GrabMysqlBanner(m.App.Domain, host.Ports)
	checkError(err)
	ssh, err := grabber.GrabSSHBanner(m.App.Domain, host.Ports)
	checkError(err)
	ftp, err := grabber.GrabFTPBanner(m.App.Domain, host.Ports)
	checkError(err)
	smtp, err := grabber.GrabSMTPBanner(m.App.Domain, host.Ports)
	checkError(err)
	pop, err := grabber.GrabPOPBanner(m.App.Domain, host.Ports)
	checkError(err)
	irc, err := grabber.GrabIRCBanner(m.App.Domain, host.Ports)
	checkError(err)
	stringMap["banner_ftp"] = ftp
	stringMap["banner_ssh"] = ssh
	stringMap["banner_mysql"] = mysql
	stringMap["banner_smtp"] = smtp
	stringMap["banner_pop"] = pop
	stringMap["banner_irc"] = irc

	render.RenderTemplate(w, "home.page.tmpl", &models.TemplateData{
		StringMap:  stringMap,
		Data:       uint16Map,
		HeadersMap: headersMap,
	})
}

var mu sync.Mutex

func (m *Repository) Consumer(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	file, err := os.OpenFile(m.App.Domain+".json", os.O_RDWR, 0644)
	checkError(err)
	defer file.Close()
	b, err := io.ReadAll(file)
	checkError(err)
	var allUrls models.AllUrls
	err = json.Unmarshal(b, &allUrls.Urls)
	checkError(err)
	err = json.NewEncoder(w).Encode(allUrls)
	checkError(err)
}

func checkError(err error) {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if err != nil {
		log.Error().Err(err).Msg("")
	}
}
