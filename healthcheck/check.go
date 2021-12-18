package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

/**
  Simple binary to query bouncer health check route and allow use of docker container health check
  https://docs.docker.com/engine/reference/builder/#healthcheck
*/
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Calling bouncer health check
	healthCheckUrl := fmt.Sprintf("http://127.0.0.1:%s/api/v1/ping", port)
	resp, err := http.Get(healthCheckUrl)
	if err != nil {
		log.Fatal("error while requesting bouncer's health check route :", err)
	}

	log.Print(resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		os.Exit(0)
	}

	os.Exit(1)
}
