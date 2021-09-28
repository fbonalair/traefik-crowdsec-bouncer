package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
	"time"
)

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
	// TODO in case of error, default reject request
	println("Authorising request") // FIXME debug

	// get headers
	realIP := c.Request.Header.Get("X-Real-Ip") // TODO sanitized ip
	//forwardedFor = c.Request.Header.Get("X-Forwarded-For")

	// Call crowsec API
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
	decisionApiUrl := fmt.Sprintf("http://localhost:8083/v1/decisions?ip=%s", realIP)

	req, err := http.NewRequest(http.MethodGet, decisionApiUrl, nil)
	if err != nil {
		fmt.Printf("error %s", err)
		return
	}
	req.Header.Add("X-Api-Key", `40796d93c2958f9e58345514e67740e5`) // TODO extract from env var
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("error %s", err)
		return
	}
	defer resp.Body.Close()
	reqBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("error %s", err)
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
