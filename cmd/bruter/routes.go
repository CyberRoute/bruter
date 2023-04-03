package main

import (
	"crypto/tls"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/grabber"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/shodan"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
	"net/http"
)

func checkError(err error) {
	if err != nil {
		log.Error().Err(err).Msg("")
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
	shodan := shodan.NewClient(client, ipv4, app.ShodanAPIKey)
	hostinfo, err := shodan.HostInfo()
	checkError(err)
	headers, err := shodan.Head("http://" + app.Domain)
	checkError(err)
	mx_records, err := network.FindMX(app.Domain)
	checkError(err)
	mysql, err := grabber.GrabMysqlBanner(app.Domain, hostinfo.Ports)
	checkError(err)
	ssh, err := grabber.GrabSSHBanner(app.Domain, hostinfo.Ports)
	checkError(err)
	ftp, err := grabber.GrabFTPBanner(app.Domain, hostinfo.Ports)
	checkError(err)
	smtp, err := grabber.GrabSMTPBanner(app.Domain, hostinfo.Ports)
	checkError(err)
	pop, err := grabber.GrabPOPBanner(app.Domain, hostinfo.Ports)
	checkError(err)
	irc, err := grabber.GrabIRCBanner(app.Domain, hostinfo.Ports)
	checkError(err)
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
	mux.Get("/", handlers.Repo.Home(homeargs))
	mux.Get("/consumer", handlers.Repo.Consumer)
	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/*", http.StripPrefix("/static", fileServer))

	return mux
}
