package main

import (
	"flag"
	"fmt"
	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/fuzzer"
	"github.com/CyberRoute/bruter/pkg/handlers"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/server"
	"github.com/alexedwards/scs/v2"
	"github.com/evilsocket/islazy/async"
	"github.com/fatih/color"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"math"
	"net"
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

const port = "8080"

var app config.AppConfig
var session *scs.SessionManager
var stats Statistics

var (
	Domain      = flag.String("domain", "", "Domain to scan")
	Apikey      = flag.String("shodan", "", "Dhodan API key")
	Address     = flag.String("address", "127.0.0.1", "IP address to bind the web UI server to.")
	AllowRemote = flag.Bool("allow-remote", false, "Allow the UI to be reached from non-loopback addresses. The UI has no authentication and its scan endpoints make live requests, so only use this on a trusted network.")
	Extension   = flag.String("extension", "js", "File extension.")
	Dictionary  = flag.String("dictionary", "db/apache-list", "File to use for enumeration.")
	Workers     = flag.Int("workers", 0, "Default is 0, if workers is less than or equal than zero, it will be auto scaled to the number of logical CPUs usable by the current process.")
	Delay       = flag.Duration("delay", 0, "Delay before each request, per worker (e.g. 100ms). Default 0 (no delay).")
	MaxRate     = flag.Int("max-rate", 0, "Global cap on requests per second across all workers. Default 0 (unlimited).")
	Verbose     = flag.Bool("verbose", false, "Verbosity")
)

func main() {
	flag.Parse()
	if *Domain == "" {
		fmt.Println("No domain specified.")
		flag.Usage()
		os.Exit(1)
	}
	// Accept a full URL (e.g. http://host:8081/path). Keep the scheme and the
	// host[:port] authority for the HTTP probes, and separately reduce the
	// input to a bare host for DNS / subdomain / certificate enumeration.
	explicitScheme, target := network.ParseTarget(*Domain)
	*Domain = network.NormalizeDomain(*Domain)
	if target == "" {
		target = *Domain
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

	// Refuse to expose the UI before doing any work: it has no authentication,
	// and the crawl/scan endpoints make live requests on the caller's behalf.
	app.BindAddr = *Address
	app.AllowRemote = *AllowRemote
	if !network.IsLoopbackAddr(*Address) && !*AllowRemote {
		logger.Fatal().Msgf("Refusing to listen on %q without -allow-remote: the UI has no authentication and its scan endpoints make live requests.", *Address)
	}
	if *AllowRemote {
		logger.Warn().Msg("Remote UI access enabled (-allow-remote): anyone who can reach this port can run scans.")
	}

	IP, err := network.ResolveByName(*Domain)
	if err != nil {
		logger.Fatal().Msg(fmt.Sprintf("Unable to resolve %s", *Domain))
	}
	logger.Info().Msg(fmt.Sprintf("Scanning IP %s %s", IP, "OK"))

	app.Target = target
	// Honour a scheme the user gave explicitly; only probe for one when the
	// target was a bare host. DetectScheme probes the authority (including any
	// port), so a non-standard port is tested rather than the default 80/443.
	if explicitScheme == "http" || explicitScheme == "https" {
		app.Scheme = explicitScheme
	} else {
		app.Scheme = network.DetectScheme(target)
	}
	logger.Info().Msgf("Using %s:// to probe %s", app.Scheme, target)

	app.InProduction = false
	session = scs.New()
	session.Lifetime = 24 * time.Hour
	session.Cookie.Persist = true
	session.Cookie.SameSite = http.SameSiteLaxMode
	session.Cookie.Secure = app.InProduction
	app.Session = session

	app.Domain = *Domain
	app.ShodanAPIKey = *Apikey
	repo := handlers.NewRepo(&app)
	handlers.NewHandlers(repo)

	listenAddr := net.JoinHostPort(*Address, port)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: server.NewServer(&app),
	}

	go func() {
		logger.Info().Msg(fmt.Sprintf("UI running on http://%s/", listenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server failed")
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
	fuzzer.Configure(*Delay, *MaxRate)
	queue := createQueue(&app.Mu, app.Target, list, shift, total, *Verbose)

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
