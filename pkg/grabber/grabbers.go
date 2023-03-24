package grabber

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func GrabMysqlBanner(ip_address string, ports []int) (string, error) {

	for _, port := range ports {
		if port == 3306 {
			req, err := net.DialTimeout("tcp", ip_address+":"+strconv.Itoa(port), 1*time.Second)
			if err != nil {
				return "", err
			}
			defer req.Close()
			buf := make([]byte, 1024)

			re := regexp.MustCompile(".+\x0a([^\x00]+)\x00.+")
			read, err := req.Read(buf)

			if err != nil {
				return "", err
			}
			service_banner := string(buf[:read])
			match := re.FindStringSubmatch(service_banner)

			if len(match) > 0 {
				return match[1], nil
			}
		}
	}
	return "", nil
}

func GrabBanner(ip_address string, ports []int, service string) (string, error) {
	var targetPort int
	switch service {
	case "ssh":
		targetPort = 22
	case "ftp":
		targetPort = 21
	case "smtp":
		targetPort = 25
	case "pop":
		targetPort = 110
	case "irc":
		targetPort = 6667
	default:
		return "", fmt.Errorf("unsupported service: %s", service)
	}

	for _, port := range ports {
		if port == targetPort {
			req, err := net.DialTimeout("tcp", ip_address+":"+strconv.Itoa(port), 1*time.Second)
			if err != nil {
				return "", err
			}
			defer req.Close()

			read, err := bufio.NewReader(req).ReadString('\n')
			if err != nil {
				return "", err
			}

			service_banner := strings.Trim(read, "\r\n\t ")
			return service_banner, nil
		}
	}
	return "", nil
}

func GrabSSHBanner(ip_address string, ports []int) (string, error) {
	return GrabBanner(ip_address, ports, "ssh")
}

func GrabFTPBanner(ip_address string, ports []int) (string, error) {
	return GrabBanner(ip_address, ports, "ftp")
}

func GrabSMTPBanner(ip_address string, ports []int) (string, error) {
	return GrabBanner(ip_address, ports, "smtp")
}

func GrabPOPBanner(ip_address string, ports []int) (string, error) {
	return GrabBanner(ip_address, ports, "pop")
}

func GrabIRCBanner(ip_address string, ports []int) (string, error) {
	return GrabBanner(ip_address, ports, "irc")
}
