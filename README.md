[![go build](https://github.com/CyberRoute/bruter/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/CyberRoute/bruter/actions/workflows/go.yml)
[![golangci-lint](https://github.com/CyberRoute/bruter/actions/workflows/golangci-lint.yml/badge.svg?branch=main)](https://github.com/CyberRoute/bruter/actions/workflows/golangci-lint.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/CyberRoute/bruter)](https://goreportcard.com/report/github.com/CyberRoute/bruter)

# Bruter
Bruter is a simple app that was built as an experiment while learning Go. It is indeed very much inspired by [Xray](https://github.com/evilsocket/xray) git  (but hey not copied ;)). The tooling can be used to test webservers and validate webservers configurations, but not just!

What does it do?
- It grabs HostInfo data from Shodan APIs, so you will need a Token to try this out
- It collects banners for various services FTP, SSH, MYSQL, IRC, SMTP
- It collects HTTP headers
- It collects WHOIS query information
- It brute force directories on WebServers and reports results (200)
- It provides info from crt.sh about SSL certificates
- It supports custom wordlists
- It produces a Web UI for presentation

## Usage
```
   Usage of /tmp/go-build2863756334/b001/exe/main:
   
  -address string
    	IP address to bind the web ui server to. (default "127.0.0.1")
  -dictionary string
    	File to use for enumeration. (default "db/apache-list")
  -domain string
    	domain to scan
  -shodan string
    	shadan api key
  -verbose
    	Verbosity
```

## Running in Docker
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

## Example of the Web UI
<div align="center">
    <img src="/img/bruter.png" width="800px"</img> 
</div>

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