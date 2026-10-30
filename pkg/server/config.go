package server

import (
	"crypto/tls"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/grabber"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/shodan"
	"net/http"
)

type ConfigServer struct {
	App *config.AppConfig
}

func NewConfigServer(app *config.AppConfig) *ConfigServer {
	return &ConfigServer{
		App: app,
	}
}

func (sc *ConfigServer) checkError(err error) {
	if err != nil {
		sc.App.ZeroLog.Error().Err(err).Msg("")
	}
}

// RunConfiguration runs for NewServer
func (sc *ConfigServer) RunConfiguration(app *config.AppConfig) models.HomeArgs {
	ipv4, err := network.ResolveByName(app.Domain)
	sc.checkError(err)

	ipv6, err := network.ResolveByNameipv6(app.Domain)
	if err != nil {
		// Missing AAAA record is common and not an error worth alarming about.
		sc.App.ZeroLog.Debug().Msgf("no IPv6 address for %s", app.Domain)
		ipv6 = "not found"
	}

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: customTransport}
	sh := shodan.NewClient(client, ipv4, app.ShodanAPIKey)

	var (
		hostinfo   shodan.Response
		headers    map[string]interface{}
		mx_records map[string]uint16
		mysql      string
		ssh        string
		ftp        string
		smtp       string
		pop        string
		irc        string
	)

	// Step 1: Execute functions that don't depend on hostinfo.Ports
	RunConcurrently(
		func() {
			hostinfo, err = sh.HostInfo(app)
			sc.checkError(err)
		},
		func() {
			var herr error
			// Use Target (host[:port]) not Domain, so the header probe hits the
			// port the user named rather than the default 80/443.
			authority := app.Target
			if authority == "" {
				authority = app.Domain
			}
			headers, herr = sh.Head(app.Scheme + "://" + authority)
			if herr != nil {
				sc.App.ZeroLog.Warn().Err(herr).Msg("could not grab HTTP headers from target")
			}
		},
		func() {
			var mxErr error
			mx_records, mxErr = network.FindMX(app.Domain)
			if mxErr != nil {
				// Most hosts (non-mail subdomains) have no MX records; not alarming.
				sc.App.ZeroLog.Debug().Msgf("no MX records for %s", app.Domain)
			}
		},
	)
	// Note: SSL (crt.sh) and WHOIS data are fetched lazily by their handlers on
	// each request, so they are intentionally not gathered here — doing so would
	// block the UI from starting while those external services are queried.

	// Step 2: Execute functions that depend on hostinfo.Ports
	RunConcurrently(
		func() {
			mysql, err = grabber.GrabMysqlBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
		func() {
			ssh, err = grabber.GrabSSHBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
		func() {
			ftp, err = grabber.GrabFTPBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
		func() {
			smtp, err = grabber.GrabSMTPBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
		func() {
			pop, err = grabber.GrabPOPBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
		func() {
			irc, err = grabber.GrabIRCBanner(app.Domain, hostinfo.Ports)
			sc.checkError(err)
		},
	)

	homeArgs := models.HomeArgs{
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

	// SSL and WHOIS data are fetched lazily by their API handlers per request,
	// so they are not gathered here.
	return homeArgs
}
