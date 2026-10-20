package fuzzer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"syscall"
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
	// requestDelay is slept before every request (per worker). Zero disables it.
	requestDelay time.Duration
	// rateTicker, when non-nil, paces requests to a global ceiling: every worker
	// draws from the same tick stream, so the combined rate across all workers
	// is capped regardless of the worker count.
	rateTicker *time.Ticker
)

// Configure sets request pacing before scanning starts. delay is a per-request
// sleep; maxRate is a global ceiling in requests per second (0 = unlimited).
// It is not safe to call once workers are running.
func Configure(delay time.Duration, maxRate int) {
	requestDelay = delay
	if rateTicker != nil {
		rateTicker.Stop()
		rateTicker = nil
	}
	if maxRate > 0 {
		rateTicker = time.NewTicker(time.Second / time.Duration(maxRate))
	}
}

// throttle blocks until the next request is allowed under the configured global
// rate limit, then applies the per-request delay. With neither configured it
// returns immediately.
func throttle() {
	if rateTicker != nil {
		<-rateTicker.C
	}
	if requestDelay > 0 {
		time.Sleep(requestDelay)
	}
}

var (
	g = color.New(color.FgGreen)
	y = color.New(color.FgYellow)
	r = color.New(color.FgRed)
	b = color.New(color.FgBlue)
)

// client is shared across all Dirsearch calls so that connections are pooled
// and reused. Certificates are not verified (scanning use case) and redirects
// are not followed. A request timeout is set so a host that accepts the
// connection but never responds cannot hang a worker indefinitely (dirsearch
// uses 7.5s by default; we allow a little more for slow TLS handshakes).
var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes untrusted hosts by design
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// isTransient reports whether a request error is worth retrying: timeouts and
// connection resets/EOFs, which happen when a host or its CDN sheds load under
// a burst of requests. Permanent errors (DNS failure, connection refused) are
// not transient and are failed fast so a dead host does not burn the full
// retry schedule on every path.
func isTransient(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF)
}

// parseRetryAfter interprets a Retry-After header value, which may be either a
// number of seconds or an HTTP-date. It returns 0 if the value is absent or
// unparseable.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := time.ParseDuration(v + "s"); err == nil {
		return secs
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func Dirsearch(Mu *sync.Mutex, app *config.AppConfig, domain, path string, progress float32, verbose bool) {
	urjoin := domain + path
	url, err := NormalizeURL(urjoin, app.Scheme)
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

	// Pace this request under the configured delay / global rate limit so we
	// do not overrun a target (and its CDN) into shedding connections.
	throttle()

	var resp *http.Response

	// Exponential backoff parameters
	maxRetries := 5
	backoff := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = client.Do(head)
		if err != nil {
			// Retry transient failures (timeouts, connection resets/EOF) with
			// backoff, matching dirsearch's behaviour under load. Permanent
			// errors (connection refused, DNS failures) will not recover, so
			// fail fast for this path instead of burning the full backoff
			// schedule on a dead host.
			if isTransient(err) && attempt < maxRetries {
				app.ZeroLog.Warn().Err(err).Msgf("Transient error for URL: %s, retrying (attempt %d/%d)", url, attempt, maxRetries)
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			app.ZeroLog.Error().Err(err).Msgf("Error performing request for URL: %s", url)
			return
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryDelay := parseRetryAfter(resp.Header.Get("Retry-After"))
			if retryDelay == 0 {
				retryDelay = backoff
			}
			// Drain and close the body before retrying so the connection can be reused.
			_ = resp.Body.Close()
			resp = nil
			app.ZeroLog.Warn().Msgf("Rate limit exceeded. Retrying after %s", retryDelay)
			time.Sleep(retryDelay)
			backoff *= 2
			continue
		}
		break
	}

	if resp == nil {
		app.ZeroLog.Error().Msgf("Failed to get a valid response for URL: %s", url)
		return
	}
	defer resp.Body.Close()

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
