package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"
)

const CLIENT_IP_HEADER = "X-Real-Ip"

type Decision struct {
	Id        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

func main() {
	// TODO: Verifying env vars
	router := gin.Default()
	router.GET("/api/v1/ping", ping)
	router.GET("/api/v1/forwardAuth", forwardAuth)
	err := router.Run()
	if err != nil {
		println("An error occurred while starting server: ", err)
		return
	}

}

func ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func forwardAuth(c *gin.Context) {
	// Getting and verifying ip from header
	realIP := c.Request.Header.Get(CLIENT_IP_HEADER)
	parsedRealIP := net.ParseIP(realIP)
	if parsedRealIP == nil {
		remedyError(fmt.Errorf("the header %q isn't a valid IP adress", CLIENT_IP_HEADER), c)
		return
	}

	// Call crowdsec API
	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}
	client := &http.Client{Transport: tr}
	decisionUrl := url.URL{
		Scheme:   "http",
		Host:     "localhost:8083",
		Path:     "v1/decisions",
		RawQuery: fmt.Sprintf("type=ban&ip=%s", realIP),
	}

	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		remedyError(fmt.Errorf("can't create a new http request : %w", err), c)
		return
	}
	req.Header.Add("X-Api-Key", `40796d93c2958f9e58345514e67740e5`) // TODO extract from env var
	resp, err := client.Do(req)
	if err != nil {
		remedyError(fmt.Errorf("error while requesting crowdsec API : %w", err), c)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			remedyError(err, c)
		}
	}(resp.Body)
	reqBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		remedyError(fmt.Errorf("error while parsing crowdsec response body : %w", err), c)
		return
	}

	var decisions []Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		remedyError(fmt.Errorf("error while unmarshalling crowdsec response body : %w", err), c)
		return
	}

	// Authorization logic
	if len(decisions) > 0 {
		c.Status(http.StatusUnauthorized)
	} else {
		c.Status(http.StatusOK)
	}
}

func remedyError(err error, c *gin.Context) {
	_ = c.Error(err) // nil err should be handled earlier
	c.Status(http.StatusUnauthorized)
}
