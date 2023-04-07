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
	"sync"

	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/rs/zerolog/log"
)

func UrlJoin(uri, urj string) (string, error) {
	urparse, err := url.Parse(uri)
	if err != nil {
		return uri, err
	}
	rel, err := urparse.Parse(urj)
	if err != nil {
		return uri, err
	}
	return rel.String(), err
}

func checkError(err error) {
	if err != nil {
		log.Error().Err(err).Msg("")
	}
}

func Auth(Mu *sync.Mutex, domain, path string, progress float32, verbose bool) {
	urjoin, err := UrlJoin("http://"+domain, path)
	if err != nil {
		fmt.Println(err)
		return
	}
	get, err := http.NewRequest("GET", urjoin, nil)
	if err != nil {
		log.Error().Err(err).Msg("")
		return
	}

	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: customTransport}

	resp, err := client.Do(get)
	if err != nil {
		log.Error().Err(err).Msg("")
		return
	}

	payload := &models.Url{Path: urjoin, Progress: progress, Status: float64(resp.StatusCode)}
	payloadBuf := new(bytes.Buffer)
	err = json.NewEncoder(payloadBuf).Encode(payload)
	checkError(err)
	if resp.StatusCode == 200 && urjoin != "" {
		dfileHandler(Mu, domain, urjoin, float64(resp.StatusCode), progress)
		if verbose {
			log.Info().Msg(fmt.Sprintf("%s => %s", urjoin, resp.Status))
		}

	} else {
		dfileHandler(Mu, domain, urjoin, float64(resp.StatusCode), progress)
		if verbose {
			log.Info().Msg(fmt.Sprintf("%s => %s", urjoin, resp.Status))
		}
	}
}

func dfileHandler(Mu *sync.Mutex, domain, path string, status float64, progress float32) {

	Mu.Lock()
	defer Mu.Unlock()
	newUrl := &models.Url{}

	newUrl.Path = path
	newUrl.Status = status
	newUrl.Progress = progress

	session_file := domain + ".json"

	//open file
	file, err := os.OpenFile(session_file, os.O_CREATE|os.O_RDWR, 0644)
	checkError(err)
	defer file.Close()

	//read file and unmarshall json file to slice of urls
	b, err := io.ReadAll(file)
	checkError(err)
	var allUrls models.AllUrls
	if len(b) > 0 {
		err = json.Unmarshal(b, &allUrls.Urls)
		checkError(err)
		max := 0

		//generation of id(last id at the json file+1)
		for _, usr := range allUrls.Urls {
			if usr.Id > max {
				max = usr.Id
			}
		}
		id := max + 1
		newUrl.Id = id

		//appending NewUrl to slice of all Urls and rewrite json file
		allUrls.Urls = append(allUrls.Urls, newUrl)
		newUserBytes, err := json.MarshalIndent(&allUrls.Urls, "", " ")
		checkError(err)
		err = os.WriteFile(session_file, newUserBytes, 0666)
		checkError(err)
	} else {
		allUrls.Urls = append(allUrls.Urls, newUrl)
		newUserBytes, err := json.MarshalIndent(&allUrls.Urls, "", " ")
		checkError(err)
		err = os.WriteFile(session_file, newUserBytes, 0666)
		checkError(err)
	}
}
