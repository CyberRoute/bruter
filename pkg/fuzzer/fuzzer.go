package fuzzer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/CyberRoute/bruter/pkg/config"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
)

func checkError(err error) {
	if err != nil {
		log.Error().Err(err).Msg("FUZZER")
	}
}

var (
	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)
)

func Dirsearch(Mu *sync.Mutex, app *config.AppConfig, domain, path string, progress float32, verbose bool) {
	urjoin := domain + path
	url, err := NormalizeURL(urjoin)
	if err != nil {
		app.ZeroLog.Error().Err(err).Msgf("Error parsing URL: %s", urjoin)
		return
	}

	head, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		app.ZeroLog.Error().Err(err).Msgf("Error creating request for URL: %s", url)
		return
	}
	head.Header.Set("User-Agent", GetRandomUserAgent())

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Do not verify certificates, do not follow redirects.
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	var resp *http.Response

	// Exponential backoff parameters
	maxRetries := 5
	backoff := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = client.Do(head)
		if err != nil {
			app.ZeroLog.Error().Err(err).Msgf("Error performing request for URL: %s", url)
			return
		}

		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			retryDelay, _ := time.ParseDuration(fmt.Sprintf("%ss", retryAfter))
			if retryDelay == 0 {
				retryDelay = backoff
			}
			app.ZeroLog.Warn().Msgf("Rate limit exceeded. Retrying after %s", retryDelay)
			time.Sleep(retryDelay)
			backoff *= 2
			continue
		} else {
			break
		}
	}

	if resp == nil {
		app.ZeroLog.Error().Msg("Failed to get a valid response")
		return
	}

	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound { //status codes 301 302
		// Add the RedirectPath field to the payload
		redirectPath := resp.Header.Get("Location")
		payload := &models.Url{Path: url, Progress: progress, Status: float64(resp.StatusCode), RedirectPath: redirectPath}
		payloadBuf := new(bytes.Buffer)
		err = json.NewEncoder(payloadBuf).Encode(payload)
		checkError(err)

		dfileHandler(Mu, domain, url, float64(resp.StatusCode), progress, redirectPath)
	} else {
		// For other status codes
		payload := &models.Url{Path: url, Progress: progress, Status: float64(resp.StatusCode)}
		payloadBuf := new(bytes.Buffer)
		err = json.NewEncoder(payloadBuf).Encode(payload)
		checkError(err)

		dfileHandler(Mu, domain, url, float64(resp.StatusCode), progress, "")
	}

	if verbose {

		switch {
		// 2xx
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			app.ZeroLog.Info().Msg(g.Sprintf("%s => %s", url, resp.Status))
		// 3xx
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			app.ZeroLog.Info().Msg(b.Sprintf("%s => %s", url, resp.Header.Get("Location")))
		// 4xx
		case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 404:
			app.ZeroLog.Info().Msg(y.Sprintf("%s => %s", url, resp.Status))
		// 5xx
		case resp.StatusCode >= 500 && resp.StatusCode < 600:
			app.ZeroLog.Info().Msg(r.Sprintf("%s => %s", url, resp.Status))
		}

	}
}

func dfileHandler(Mu *sync.Mutex, domain, path string, status float64, progress float32, redirectPath string) {
	Mu.Lock()
	defer Mu.Unlock()

	sessionFile := domain + ".json"
	allUrls, err := readUrlsFromFile(sessionFile)
	checkError(err)

	newUrl := &models.Url{
		Path:         path,
		Status:       status,
		Progress:     progress,
		RedirectPath: redirectPath,
	}

	id := generateNewId(allUrls)
	newUrl.Id = id

	data, err := GetFileSizeString(sessionFile, domain)
	checkError(err)
	newUrl.Data = data

	allUrls.Urls = append(allUrls.Urls, newUrl)
	err = writeUrlsToFile(sessionFile, allUrls)
	checkError(err)
}

func readUrlsFromFile(filename string) (models.AllUrls, error) {
	var allUrls models.AllUrls

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return allUrls, err
	}
	defer file.Close()

	b, err := io.ReadAll(file)
	if err != nil {
		return allUrls, err
	}

	if len(b) > 0 {
		err = json.Unmarshal(b, &allUrls.Urls)
		if err != nil {
			return allUrls, err
		}
	}

	return allUrls, nil
}

func writeUrlsToFile(filename string, allUrls models.AllUrls) error {
	// Sort the URLs based on the Progress field in ascending order
	sort.Slice(allUrls.Urls, func(i, j int) bool {
		return allUrls.Urls[i].Progress < allUrls.Urls[j].Progress
	})

	// Marshal and write the sorted URLs to the file
	newUserBytes, err := json.Marshal(allUrls.Urls)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename, newUserBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func generateNewId(allUrls models.AllUrls) int {
	max := 0
	for _, usr := range allUrls.Urls {
		if usr.Id > max {
			max = usr.Id
		}
	}
	return max + 1
}

func GetFileSizeString(filePath string, domain string) (string, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}

	fileSize := fileInfo.Size()
	return fmt.Sprintf("%s.json file: %d bytes", domain, fileSize), nil
}
