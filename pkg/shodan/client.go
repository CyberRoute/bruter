package shodan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/CyberRoute/bruter/pkg/config"
)

type Response struct {
	RegionCode  string   `json:"region_code"`
	City        string   `json:"city"`
	Org         string   `json:"org"`
	CountryName string   `json:"country_name"`
	Asn         string   `json:"asn"`
	Isp         string   `json:"isp"`
	Ports       []int    `json:"ports"`
	Domains     []string `json:"domains"`
}

const (
	baseURL = "https://api.shodan.io"
	path    = "/shodan/host/%s?key=%s"
)

type ErrorHandler func(*http.Response) error

// Client represents Shodan HTTP client
type Client struct {
	Token   string
	BaseURL string
	Path    string
	Client  *http.Client
	IPv4    string
}

// NewClient creates new Shodan client
func NewClient(client *http.Client, ipv4, token string) *Client {
	if client == nil {
		client = http.DefaultClient
	}

	return &Client{
		Token:   token,
		BaseURL: baseURL,
		IPv4:    ipv4,
		Path:    path,
		Client:  client,
	}
}

func (c *Client) HostInfo(app *config.AppConfig) (Response, error) {
	url := fmt.Sprintf(c.BaseURL+c.Path, c.IPv4, c.Token)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %v", err)
	}

	// Add timeout to client
	c.Client.Timeout = time.Second * 10

	// Retry logic
	var resp *http.Response
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err = c.Client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return Response{}, fmt.Errorf("failed to retrieve data after %d retries: %v", maxRetries, err)
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		app.ZeroLog.Info().Msg(fmt.Sprintf("status code from shodan %d => %s", resp.StatusCode, "OK"))
	case 401:
		return Response{}, fmt.Errorf("unauthorized response")
	case 404:
		return Response{}, fmt.Errorf("not Found")
	case 500:
		return Response{}, fmt.Errorf("internal Server Error")
	case 403:
		return Response{}, fmt.Errorf("requires membership or higher to access")
	default:
		return Response{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return Response{}, fmt.Errorf("failed to decode request: %v", err)
	}

	return response, nil
}

func (c *Client) Head(website string) (map[string]interface{}, error) {

	headers := make(map[string]interface{})

	req, err := http.NewRequest("HEAD", website, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	res, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve data: %v", err)
	}

	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned error: %s", res.Status)
	}
	for name, header := range res.Header {
		headers[name] = header
	}
	return headers, nil
}
