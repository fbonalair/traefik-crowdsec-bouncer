package controler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	clientIpHeader       = "X-Real-Ip"
	crowdsecAuthHeader   = "X-Api-Key"
	crowdsecBouncerRoute = "v1/decisions"
	healthCheckIp        = "127.0.0.1"
)

var crowdsecBouncerApiKey = RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerScheme = OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")

var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	},
	Timeout: 5 * time.Second,
}

/**
Call Crowdsec local IP and with realIP and return true if IP does NOT have a ban decisions.
*/
func isIpAuthorized(c *gin.Context, realIP string) (bool, error) {
	// Calling crowdsec API
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", realIP),
	}

	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	// verifying access
	if resp.StatusCode == http.StatusForbidden {
		return false, err
	}

	// Parsing response
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Err(err).Msg("An error occurred while closing body reader")
		}
	}(resp.Body)
	reqBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if bytes.Equal(reqBody, []byte("null")) {
		log.Debug().Msgf("No decision for IP %q. Accepting", realIP)
		return true, nil
	}

	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, err
	}

	// Authorization logic
	return len(decisions) < 0, nil
}

/*
	Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	// Getting and verifying ip from header
	realIP := c.Request.Header.Get(clientIpHeader)

	isAuthorized, err := isIpAuthorized(c, realIP)
	if err != nil {
		log.Warn().Err(err).Msgf("An error occurred while checking IP %q", realIP)
		c.String(http.StatusForbidden, "Forbidden")
	} else if !isAuthorized {
		c.String(http.StatusForbidden, "Forbidden")
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	isHealthy, err := isIpAuthorized(c, healthCheckIp)
	if err != nil || !isHealthy {
		log.Warn().Err(err).Msgf("The health check did not pass. Check error if present and if the IP %q is authorized", healthCheckIp)
		c.Status(http.StatusForbidden)
	} else {
		c.Status(http.StatusOK)
	}
}

/*
	Simple route responding pong to every request. Mainly use for Kubernetes liveliness probe
*/
func Ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func Metrics(c *gin.Context) {
	handler := promhttp.Handler()
	handler.ServeHTTP(c.Writer, c.Request)
}
