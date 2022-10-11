package controler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/fbonalair/traefik-crowdsec-bouncer/caches"
	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var crowdsecBouncerCacheMode = OptionalEnv("CROWDSEC_BOUNCER_CACHE_MODE", "none") // Validated via ValidateEnv()
var crowdsecBouncerDefaultCacheDuration, _ = time.ParseDuration(OptionalEnv("CROWDSEC_DEFAULT_CACHE_DURATION", "5m")) // Validated via ValidateEnv()
var crowdsecBouncerApiKey = RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerScheme = OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")
var crowdsecBanResponseCode, _ = strconv.Atoi(OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "403")) // Validated via ValidateEnv()
var crowdsecBanResponseMsg = OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", "Forbidden")

var ipProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "crowdsec_traefik_bouncer_processed_ip_total",
	Help: "The total number of processed IP",
})
var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	},
	Timeout: 5 * time.Second,
}

/**
Call Crowdsec local IP and with realIP and return the number of seconds the IP is banned, -1 means no ban, 0 means some problem during the function, more than 0 means ban.
*/
func getBanDuration(clientIP string) (int, error) {
	// Generating crowdsec API request
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     CrowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add(CrowdsecAuthHeader, crowdsecBouncerApiKey)
	log.Debug().
		Str("method", http.MethodGet).
		Str("url", decisionUrl.String()).
		Msg("Request Crowdsec's decision Local API")

	// Calling crowdsec API
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode == http.StatusForbidden {
		return 0, err
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
		return 0, err
	}
	if bytes.Equal(reqBody, []byte("null")) {
		log.Debug().Msgf("No decision for IP %q. Accepting", clientIP)
		return -1, nil
	}

	log.Debug().RawJSON("decisions", reqBody).Msg("Found Crowdsec's decision(s), evaluating ...")
	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return 0, err
	}
	if len(decisions) == 0 {
		return -1, nil
	}
	// Authorization logic
	duration, err := time.ParseDuration(decisions[0].Duration)
	if err != nil {
		return -1, err
	}
	return int(duration.Seconds()), nil
}

/*
Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	ipProcessed.Inc()
	clientIP := c.ClientIP()

	log.Debug().
		Str("ClientIP", clientIP).
		Str("RemoteAddr", c.Request.RemoteAddr).
		Str(ForwardHeader, c.Request.Header.Get(ForwardHeader)).
		Str(RealIpHeader, c.Request.Header.Get(RealIpHeader)).
		Msg("Handling forwardAuth request")

	if crowdsecBouncerCacheMode != "none" {
		isBanned, err := caches.GetDecision(clientIP)
		log.Warn().
			Str("isBanned", fmt.Sprintf("%v", isBanned)).
			Err(err).
			Msg("Reading cache")
		if err == nil {
			if isBanned {
				c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
			} else {
				c.Status(http.StatusOK)
			}
			return
		}
		if crowdsecBouncerCacheMode == "stream" {
			if caches.IsHealthy {
				c.Status(http.StatusOK)
			} else {
				c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
			}
			return
		}
	}

	// Getting and verifying ip using ClientIP function
	duration, err := getBanDuration(clientIP)
	if err != nil {
		log.Warn().Err(err).Msgf("An error occurred while checking IP %q", c.Request.Header.Get(clientIP))
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		return
	}
	if duration >= 0 {
		if crowdsecBouncerCacheMode == "live" && duration != 0 {
			caches.SetDecision(clientIP, true, duration)
		}
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
	} else {
		if crowdsecBouncerCacheMode == "live" {
			caches.SetDecision(clientIP, false, int(crowdsecBouncerDefaultCacheDuration.Seconds()))
		}
		c.Status(http.StatusOK)
	}
}

/*
Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	duration, err := getBanDuration(HealthCheckIp)
	if crowdsecBouncerCacheMode == "stream" && !caches.IsHealthy {
		log.Warn().Err(err).Msgf("The health check did not pass. Check error if present and if the Crowdsec LAPI is available")
		c.Status(http.StatusServiceUnavailable)
	} else if err != nil || duration >= 0 {
		log.Warn().Err(err).Msgf("The health check did not pass. Check error if present and if the IP %q is authorized", HealthCheckIp)
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
