package models

import (
	"html/template"
)

// Template data holds data sent from handlers to templates
type TemplateData struct {
	StringMap           map[string]string
	IntMap              map[string]int
	FloatMap            map[string]float32
	Data                map[string]interface{}
	HeadersMap          map[string]interface{}
	FtpBannerGrabberMap map[string]interface{}
	SSLInfo             []map[string]interface{}
	WhoisInfo           template.HTML
	CSRFToken           string
	Flash               string
	Warning             string
	Error               string
}
