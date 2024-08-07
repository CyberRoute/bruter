package main

import (
	"flag"
	"fmt"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/fuzzer"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/render"
	"github.com/CyberRoute/bruter/pkg/server"
	"github.com/alexedwards/scs/v2"
	"github.com/evilsocket/islazy/async"
	"github.com/fatih/color"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type workerContext struct {
	Mu       *sync.Mutex
	Domain   string
	Path     string
	Progress float32
	Verbose  bool
}

type Statistics struct {
	Inputs uint64
}

const portNumber = ":8080"

var app config.AppConfig
var session *scs.SessionManager
var stats Statistics

var (
	Domain     = flag.String("domain", "", "Domain to scan")
	Apikey     = flag.String("shodan", "", "Dhodan API key")
	Address    = flag.String("address", "127.0.0.1", "IP address to bind the web UI server to.")
	Extension  = flag.String("extension", "js", "File extension.")
	Dictionary = flag.String("dictionary", "db/apache-list", "File to use for enumeration.")
	Workers    = flag.Int("workers", 0, "Default is 0, if workers is less than or equal than zero, it will be auto scaled to the number of logical CPUs usable by the current process.")
	Verbose    = flag.Bool("verbose", false, "Verbosity")
)

func main() {
	flag.Parse()
	if *Domain == "" {
		fmt.Println("No domain specified.")
		flag.Usage()
		os.Exit(1)
	}
	r := color.New(color.FgRed)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		r.Println("\nINTERRUPTING ...")
		fmt.Printf("Wordlist of %d paths\n", stats.Inputs)
		os.Exit(0)
	}()

	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	app.ZeroLog = &logger
	IP, err := network.ResolveByName(*Domain)
	if err != nil {
		logger.Fatal().Msg(fmt.Sprintf("Unable to resolve %s", *Domain))
	}
	logger.Info().Msg(fmt.Sprintf("Scanning IP %s %s", IP, "OK"))

	app.InProduction = false
	session = scs.New()
	session.Lifetime = 24 * time.Hour
	session.Cookie.Persist = true
	session.Cookie.SameSite = http.SameSiteLaxMode
	session.Cookie.Secure = app.InProduction
	app.Session = session

	tc, err := render.CreateTemplateCache()
	if err != nil {
		logger.Fatal().Err(err).Msg("cannot create template cache")
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
		Handler: server.NewServer(&app),
	}

	go func() {
		logger.Info().Msg(fmt.Sprintf("UI running on http://%s%s/", *Address, portNumber))
		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	file, err := os.Open(*Dictionary)
	if err != nil {
		logger.Fatal().Err(err).Msg("")
	}
	defer file.Close()

	linesChan, _, err := fuzzer.Reader(file.Name(), 0)
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	list := make([]string, 0)
	for line := range linesChan {
		stats.Inputs++
		list = append(list, line)
	}

	total := len(list)
	shift := 1
	queue := createQueue(&app.Mu, *Domain, list, shift, total, *Verbose)

	queue.WaitDone()

	logger.Info().Msg(fmt.Sprintf("Wordlist of %d paths", stats.Inputs))
	logger.Info().Msg("All tasks completed, press Ctrl-C to quit.")
	select {}
}

func createQueue(mu *sync.Mutex, domain string, list []string, shift, total int, verbose bool) *async.WorkQueue {
	queue := async.NewQueue(*Workers, func(arg async.Job) {
		ctx := arg.(*workerContext)
		fuzzer.Dirsearch(ctx.Mu, &app, ctx.Domain, ctx.Path, ctx.Progress, ctx.Verbose)
	})

	for index, payload := range list {
		modifiedIndex := index + shift
		payload = strings.ReplaceAll(payload, "%EXT%", *Extension)
		progress := 100 * float32(modifiedIndex) / float32(total)
		progress = float32(math.Round(float64(progress)))
		queue.Add(async.Job(&workerContext{
			Mu:       mu,
			Domain:   domain,
			Path:     payload,
			Progress: progress,
			Verbose:  verbose,
		}))
	}
	return queue
}
