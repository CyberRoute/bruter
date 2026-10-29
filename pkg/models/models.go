package models

import (
	"github.com/CyberRoute/bruter/pkg/shodan"
)

// Homargs holds data to be sent to the home page
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

// Urls holds data to be sent to the consumer api endpoint
type Url struct {
	Id           int     `json:"id"`
	Path         string  `json:"path"`
	Status       float64 `json:"status"`
	Progress     float32 `json:"progress"`
	Data         string  `json:"data"`
	RedirectPath string  `json:"redirectpath"`
}

type AllUrls struct {
	Urls []*Url
}
