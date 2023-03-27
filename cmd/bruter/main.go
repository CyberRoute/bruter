package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/fuzzer"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/render"
	"github.com/alexedwards/scs/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"net/http"
	"os"
	"strings"
	"time"
)

const portNumber = ":8080"

var app config.AppConfig
var session *scs.SessionManager

var doneThread = make(chan bool)
var activeThread = 0
var maxThread = 20

var (
	Domain  = flag.String("domain", "", "domain to scan")
	Apikey  = flag.String("shodan", "", "shadan api key")
	Address = flag.String("address", "127.0.0.1", "IP address to bind the web ui server to.")
	Verbose = flag.Bool("verbose", false, "Verbosity")
)

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func main() {

	flag.Parse()
	if *Domain == "" {
		fmt.Println("No domain specified.")
		flag.Usage()
		os.Exit(1)
	}

	IP, _ := network.ResolveByName(*Domain)
	log.Info().Msg(fmt.Sprintf("Scanning IP %s %s", IP, "OK"))

	app.InProduction = false

	session = scs.New()
	session.Lifetime = 24 * time.Hour
	session.Cookie.Persist = true
	session.Cookie.SameSite = http.SameSiteLaxMode
	session.Cookie.Secure = app.InProduction

	app.Session = session

	tc, err := render.CreateTemplateCache()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create template cache")
	}

	app.TemplateCache = tc
	app.UseCache = false
	app.Domain = *Domain
	app.ShodanAPIKey = *Apikey

	repo := handlers.NewRepo(&app)
	handlers.NewHandlers(repo)

	render.NewTemplates(&app)

	srv := &http.Server{
		Addr:    portNumber,
		Handler: routes(&app),
	}

	go func() {
		log.Info().Msg(fmt.Sprintf("UI running on http://%s%s/", *Address, portNumber))
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	buffer := make([]byte, 500000) // 500K(almost)
	file, err := os.Open("pkg/fuzzer/apache-list")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}
	defer file.Close()

	EOB, err := file.Read(buffer)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	list := strings.Split(string(buffer[:EOB]), "\n")
	total := len(list)
	shift := 1
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: customTransport}
	for index, payload := range list {
		index += shift
		progress := 100 * float32(index) / float32(total)
		go fuzzer.Auth(client, &app.Mu, *Domain, payload, progress, doneThread, *Verbose)

		activeThread++
		if activeThread >= maxThread {
			<-doneThread
			activeThread -= 1
		}
	}

	for activeThread > 0 {
		<-doneThread
		activeThread -= 1
	}
	fmt.Println("\nAll tasks completed, press Ctrl-C to quit.")
	select {}
}
