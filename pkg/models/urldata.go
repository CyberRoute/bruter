package models

type Url struct {
	Id       int     `json:"id"`
	Path     string  `json:"path"`
	Status   float64 `json:"status"`
	Progress float32 `json:"progress"`
}

type AllUrls struct {
	Urls []*Url
}
