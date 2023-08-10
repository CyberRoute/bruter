package ssl

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func FetchCrtData(domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var data []map[string]interface{}
	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
