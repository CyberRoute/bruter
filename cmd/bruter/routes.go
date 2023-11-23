package main

import (
	"crypto/tls"
	"html/template"
	"net/http"

	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/grabber"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/shodan"
	"github.com/CyberRoute/bruter/pkg/ssl"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func checkError(err error) {
	if err != nil {
		app.ZeroLog.Error().Err(err).Msg("")
	}
}

func routes(app *config.AppConfig) http.Handler {
	mux := chi.NewRouter()

	mux.Use(middleware.Recoverer)
	mux.Use(SessionLoad)

	ipv4, err := network.ResolveByName(app.Domain)
	checkError(err)
	ipv6, err := network.ResolveByNameipv6(app.Domain)
	checkError(err)
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: customTransport}
	sh := shodan.NewClient(client, ipv4, app.ShodanAPIKey)

	var (
		hostinfo   shodan.Response
		headers    map[string]interface{}
		mx_records map[string]uint16
		whoisinfo  template.HTML
		mysql      string
		ssh        string
		ftp        string
		smtp       string
		pop        string
		irc        string
		sslinfo    []map[string]interface{}
	)

	// Step 1: Execute functions that don't depend on hostinfo.Ports
	RunConcurrently(
		func() {
			hostinfo, err = sh.HostInfo(app)
			checkError(err)
		},
		func() {
			headers, err = sh.Head("https://" + app.Domain)
			checkError(err)
		},
		func() {
			mx_records, err = network.FindMX(app.Domain)
			checkError(err)
		},
		func() {
			whoisinfo, err = network.WhoisLookup(app.Domain)
			checkError(err)
		},
		func() {
			sslinfo, err = ssl.FetchCrtData(app.Domain)
			checkError(err)
		},
	)

	// Step 2: Execute functions that depend on hostinfo.Ports
	RunConcurrently(
		func() {
			mysql, err = grabber.GrabMysqlBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
		func() {
			ssh, err = grabber.GrabSSHBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
		func() {
			ftp, err = grabber.GrabFTPBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
		func() {
			smtp, err = grabber.GrabSMTPBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
		func() {
			pop, err = grabber.GrabPOPBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
		func() {
			irc, err = grabber.GrabIRCBanner(app.Domain, hostinfo.Ports)
			checkError(err)
		},
	)
	homeargs := models.HomeArgs{
		Ipv4:    ipv4,
		Ipv6:    ipv6,
		Host:    hostinfo,
		Headers: headers,
		Mx:      mx_records,
		Mysql:   mysql,
		Ssh:     ssh,
		Ftp:     ftp,
		Smtp:    smtp,
		Pop:     pop,
		Irc:     irc,
	}

	sslargs := models.TemplateData{
		SSLInfo: sslinfo,
	}

	whoisargs := models.TemplateData{
		WhoisInfo: whoisinfo,
	}

	mux.Get("/", handlers.Repo.Home(homeargs))
	mux.Get("/ssl", handlers.Repo.SSLInfo(sslargs))
	mux.Get("/whois", handlers.Repo.WhoisInfo(whoisargs))
	mux.Get("/consumer", handlers.Repo.Consumer)
	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/*", http.StripPrefix("/static", fileServer))

	return mux
}
