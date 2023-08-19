package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/fuzzer"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/render"
	"github.com/alexedwards/scs/v2"
	"github.com/evilsocket/islazy/async"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type workerContext struct {
	Mu       *sync.Mutex
	Domain   string
	Path     string
	Progress float32
	Verbose  bool
}

const portNumber = ":8080"

var app config.AppConfig
var session *scs.SessionManager

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
	file, err := os.Open("db/dict.txt")
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

	queue := async.NewQueue(0, func(arg async.Job) {
		ctx := arg.(*workerContext)
		fuzzer.Get(ctx.Mu, ctx.Domain, ctx.Path, ctx.Progress, ctx.Verbose)
	})

	for index, payload := range list {
		index += shift

		// Replace %EXT% with extensions
		payload = strings.ReplaceAll(payload, "%EXT%", "php")
		payload = strings.ReplaceAll(payload, "%EXT%", "html")
		payload = strings.ReplaceAll(payload, "%EXT%", "js")

		progress := 100 * float32(index) / float32(total)
		queue.Add(async.Job(&workerContext{
			Mu:       &app.Mu,
			Domain:   *Domain,
			Path:     payload,
			Progress: progress,
			Verbose:  *Verbose,
		}))
	}

	queue.WaitDone()

	fmt.Println("\nAll tasks completed, press Ctrl-C to quit.")
	select {}
}
