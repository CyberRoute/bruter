package models

import "github.com/CyberRoute/bruter/pkg/shodan"

type HomeArgs struct {
	Ipv4    string
	Ipv6    string
	Host    shodan.Response
	Headers map[string]interface{}
	Mx      map[string]uint16
	Ftp     string
	Ssh     string
	Mysql   string
	Smtp    string
	Pop     string
	Irc     string
}
