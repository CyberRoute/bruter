[![go build](https://github.com/CyberRoute/bruter/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/CyberRoute/bruter/actions/workflows/go.yml)
[![golangci-lint](https://github.com/CyberRoute/bruter/actions/workflows/golangci-lint.yml/badge.svg?branch=main)](https://github.com/CyberRoute/bruter/actions/workflows/golangci-lint.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/CyberRoute/bruter)](https://goreportcard.com/report/github.com/CyberRoute/bruter)

<div align="center">
    <img src="img/bruter-logo-transparent.png" width="400px"/>
</div>
# Bruter
Bruter is a simple app that was built as an experiment while learning Go. It is indeed very much inspired by [Xray](https://github.com/evilsocket/xray) git  (but hey not copied ;)). The tooling can be used to test webservers and validate webservers configurations, but not just!

What does it do?
- It grabs HostInfo data from Shodan APIs, so you will need a Token to try this out
- It collects banners for various services FTP, SSH, MYSQL, IRC, SMTP
- It collects HTTP headers
- It collects WHOIS query information
- It brute force directories on WebServers and reports results (200)
- It provides info from crt.sh about SSL certificates
- DNS enumeration — A, AAAA, NS, TXT, CNAME, MX, SOA and reverse-DNS (PTR) records
- Zone-transfer (AXFR) check — attempts a full zone transfer against each authoritative name server and flags any that leak the zone
- Email-spoofing posture — parses SPF and DMARC and reports whether the domain is spoofable
- Subdomain discovery — passive sources (crt.sh and fallbacks) plus an active, wildcard-aware brute-force of common labels
- Reverse IP — other host names sharing the target's IP ("neighbours")
- Comprehensive IP info (Robtex) — owning network (ASN/route/whois) and active/passive DNS history
- It supports custom wordlists
- It produces a Web UI for presentation

> **Note on active checks.** Zone-transfer attempts and subdomain brute-force
> send live DNS queries to the target's infrastructure, and the reverse-IP and
> Robtex lookups query third-party services. Only run Bruter against systems you
> are authorised to test.

## Usage
```
   -address string
    	IP address to bind the web UI server to. (default "127.0.0.1")
  -delay duration
    	Delay before each request, per worker (e.g. 100ms). Default 0 (no delay).
  -dictionary string
    	File to use for enumeration. (default "db/apache-list")
  -domain string
    	Domain to scan
  -extension string
    	File extension. (default "js")
  -max-rate int
    	Global cap on requests per second across all workers. Default 0 (unlimited).
  -shodan string
    	Dhodan API key
  -verbose
    	Verbosity
  -workers int
    	Default is 0, if workers is less than or equal than zero, it will be auto scaled to the number of logical CPUs usable by the current process.
```

## Web UI
The presentation layer is a React single-page app (Vite + TypeScript + Tailwind)
that lives in [`web/`](web/) and is **embedded into the Go binary** via `go:embed`.
It presents the scan as tabs — **Dashboard** (host/network, ports, banners,
headers), **Subdomains** (passive + active brute-force), **DNS** (records, zone
transfer, SPF/DMARC, reverse-IP and Robtex), and **WHOIS** — backed by a small
JSON API that the SPA consumes:

| Endpoint | Description |
| --- | --- |
| `GET /api/host` | Host/network info, open ports, MX records, grabbed banners, HTTP headers |
| `GET /api/ssl` | Certificate-transparency records (crt.sh and fallbacks) |
| `GET /api/dns` | DNS records (A, AAAA, NS, TXT, CNAME, MX, SOA, reverse-DNS PTR) plus a zone-transfer (AXFR) check against each name server and an SPF/DMARC email-spoofing verdict |
| `GET /api/subdomains/brute` | Active brute-force of common subdomain labels (wildcard-aware), returning resolved hosts and their IPs |
| `GET /api/reverseip` | Reverse-IP lookup — other host names sharing the domain's IP ("neighbours"), via an external source |
| `GET /api/robtex` | Robtex comprehensive IP view — owning network (ASN/route/whois) and active/passive DNS history, via an external source |
| `GET /api/whois` | Raw WHOIS record |
| `GET /consumer` | Live directory-fuzzing feed (polled by the dashboard) |

Because the UI is embedded, you must build `web/dist` before building the Go
binary. The `Makefile` and `Dockerfile` do this for you:

```
make ui        # build only the web UI (web/dist)
make           # build the UI, then test/lint/build the Go binary
```

Building by hand:
```
npm --prefix web ci
npm --prefix web run build
go build -o build/bruter ./cmd/bruter
```

### UI development
For hot-reload while developing the UI, run the Go server (which serves the API)
and the Vite dev server side by side — Vite proxies `/api` and `/consumer` to
`127.0.0.1:8080`:
```
go run cmd/bruter/* -domain example.com -shodan [TOKEN]   # API on :8080
npm --prefix web run dev                                  # UI on :5173
```

## Running in Docker
The Docker build compiles the UI in a Node stage and embeds it into the binary,
so no extra steps are needed:
```
docker build -t bruter .
docker run --rm -it -p 8080:8080 bruter -domain example.com -shodan [shodanapikey] -verbose
```


## Example
    go run cmd/bruter/* -domain example.com -shodan [SHODANTOKEN] -verbose
    12:41PM INF Scanning IP 93.184.216.34 OK
    12:41PM INF UI running on http://127.0.0.1:8080/
    12:41PM INF http://example.com/.htaccess.bak => 404 Not Found
    12:41PM INF http://example.com/httpd/logs/access_log => 404 Not Found
    12:41PM INF http://example.com/logs/error.log => 404 Not Found
    12:41PM INF http://example.com/cgi => 404 Not Found
    12:41PM INF http://example.com/apache/logs/access_log => 404 Not Found
    12:41PM INF http://example.com/apache/logs/access.log => 404 Not Found
    12:41PM INF http://example.com/logs/access.log => 404 Not Found
    12:41PM INF http://example.com/logs/error_log => 404 Not Found
    12:41PM INF http://example.com/httpd/logs/error.log => 404 Not Found
    12:41PM INF http://example.com/logs/access.log => 404 Not Found
    12:41PM INF http://example.com/cgi-bin => 404 Not Found
    12:41PM INF http://example.com/httpd/logs/error_log => 404 Not Found
    12:41PM INF http://example.com/.web => 404 Not Found
    12:41PM INF http://example.com/httpd/logs/access.log => 404 Not Found
    12:41PM INF http://example.com/.meta => 404 Not Found
    12:41PM INF http://example.com/apache/logs/error.log => 404 Not Found
    12:41PM INF http://example.com/apache/logs/error_log => 404 Not Found   

## Contribute
Fork the repo and send PRs

```
make all

Cleaning up
rm -rf build
Running tests...
go test ./... -v -cover -race
?   	github.com/CyberRoute/bruter/cmd/bruter	[no test files]
?   	github.com/CyberRoute/bruter/pkg/config	[no test files]
?   	github.com/CyberRoute/bruter/pkg/grabber	[no test files]
?   	github.com/CyberRoute/bruter/pkg/handlers	[no test files]
?   	github.com/CyberRoute/bruter/pkg/models	[no test files]
?   	github.com/CyberRoute/bruter/pkg/render	[no test files]
?   	github.com/CyberRoute/bruter/pkg/shodan	[no test files]
=== RUN   TestUrlJoin
--- PASS: TestUrlJoin (0.00s)
=== RUN   TestAuth
{"level":"info","time":"2023-03-10T14:25:36+01:00","message":"http://127.0.0.1:36983/ => 200 OK"}
{"level":"info","time":"2023-03-10T14:25:36+01:00","message":"http://127.0.0.1:44337/ => 403 Forbidden"}
{"level":"info","time":"2023-03-10T14:25:36+01:00","message":"http://127.0.0.1:45357/ => 500 Internal Server Error"}
--- PASS: TestAuth (0.01s)
PASS
	github.com/CyberRoute/bruter/pkg/fuzzer	coverage: 71.0% of statements
ok  	github.com/CyberRoute/bruter/pkg/fuzzer	0.044s	coverage: 71.0% of statements
=== RUN   TestResolveByName
=== RUN   TestResolveByName/valid_domain
=== RUN   TestResolveByName/invalid_domain
--- PASS: TestResolveByName (0.14s)
    --- PASS: TestResolveByName/valid_domain (0.00s)
    --- PASS: TestResolveByName/invalid_domain (0.13s)
PASS
	github.com/CyberRoute/bruter/pkg/network	coverage: 26.7% of statements
ok  	github.com/CyberRoute/bruter/pkg/network	0.165s	coverage: 26.7% of statements
Running lint...
go list ./... | golangci-lint run 
Formatting...
gofmt -s -w .
Building...
go build -o build/bruter cmd/bruter/*.go

```



## License
Bruter is developed by Alessandro Bresciani with some help from various projects and released with GPL license.

## Acknowledgments
[DB file](https://github.com/CyberRoute/bruter/blob/main/db/dict.txt) has been borrowed from [dirsearch](https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt)