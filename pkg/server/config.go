package server

import (
	"crypto/tls"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/grabber"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/shodan"
	"github.com/CyberRoute/bruter/pkg/ssl"
	"html/template"
	"net/http"
)

var app config.AppConfig

func checkError(err error) {
	if err != nil {
		app.ZeroLog.Error().Err(err).Msg("")
	}
}

// RunConfiguration runs for NewServer
func RunConfiguration(app *config.AppConfig) (models.HomeArgs, models.TemplateData, models.TemplateData) {
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
			headers, err = sh.Head("http://" + app.Domain)
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

	sslArgs := models.TemplateData{
		SSLInfo: sslinfo,
	}

	whoIsArgs := models.TemplateData{
		WhoisInfo: whoisinfo,
	}

	return homeArgs, sslArgs, whoIsArgs
}
