package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net"
	"net/http"
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

	// TODO use Url instead of string
	//decisionApiUrl := url.URL{
	//	Host: "localhost",
	//	Path: "/v1/decisions",
	//}
	//decisionApiUrl := "http://localhost:8083/v1/decisions?ip="
	decisionApiUrl := fmt.Sprintf("http://localhost:8083/v1/decisions?type=ban&ip=%s", realIP)

	req, err := http.NewRequest(http.MethodGet, decisionApiUrl, nil)
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
	defer resp.Body.Close()
	reqBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		remedyError(fmt.Errorf("error while parsing crowdsec response body : %w", err), c)
		return
	}

	var decisions []Decision
	json.Unmarshal(reqBody, &decisions)

	// Authorization logic
	if len(decisions) > 0 {
		c.Status(http.StatusUnauthorized)
	} else {
		c.Status(http.StatusOK)
	}
}

func remedyError(err error, c *gin.Context) {
	c.Error(err)
	c.Status(http.StatusUnauthorized)
}
