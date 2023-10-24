package fuzzer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"

	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/rs/zerolog/log"
)

func checkError(err error) {
	if err != nil {
		log.Error().Err(err).Msg("FUZZER")
	}
}

func Get(Mu *sync.Mutex, domain, path string, progress float32, verbose bool) {
	urjoin := "https://" + domain + path
	url, err := url.Parse(urjoin)
	if err != nil {
		log.Error().Err(err).Msgf("Error parsing URL: %s", urjoin)
	}

	get, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		log.Error().Err(err).Msgf("Error creating request for URL: %s", urjoin)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(get)
	if err != nil {
		log.Error().Err(err).Msgf("Error performing request for URL: %s", urjoin)
	}

	statusCode := float64(resp.StatusCode)
	payload := &models.Url{Path: urjoin, Progress: progress, Status: statusCode}
	payloadBuf := new(bytes.Buffer)
	err = json.NewEncoder(payloadBuf).Encode(payload)
	checkError(err)

	dfileHandler(Mu, domain, urjoin, statusCode, progress)
	if verbose {
		log.Info().Msg(fmt.Sprintf("%s => %s", urjoin, resp.Status))
	}
}

func dfileHandler(Mu *sync.Mutex, domain, path string, status float64, progress float32) {
	Mu.Lock()
	defer Mu.Unlock()

	sessionFile := domain + ".json"
	allUrls, err := readUrlsFromFile(sessionFile)
	checkError(err)

	newUrl := &models.Url{
		Path:     path,
		Status:   status,
		Progress: progress,
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
	newUserBytes, err := json.MarshalIndent(allUrls.Urls, "", " ")
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
