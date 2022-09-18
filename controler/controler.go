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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/coocood/freecache"
	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	realIpHeader                = "X-Real-Ip"
	forwardHeader               = "X-Forwarded-For"
	crowdsecAuthHeader          = "X-Api-Key"
	crowdsecBouncerRoute        = "v1/decisions"
	crowdsecBouncerStreamRoute  = "v1/decisions/stream"
	healthCheckIp               = "127.0.0.1"
)

var crowdsecBouncerApiKey = RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerCacheMode = OptionalEnv("CROWDSEC_BOUNCER_CACHE_MODE", "none") // Validated via ValidateEnv()
var crowdsecBouncerCacheStreamInterval, _ = time.ParseDuration(OptionalEnv("CROWDSEC_BOUNCER_CACHE_STREAM_INTERVAL", "1m")) // Validated via ValidateEnv()
var crowdsecBouncerDefaultCacheDuration, _ = time.ParseDuration(OptionalEnv("CROWDSEC_DEFAULT_CACHE_DURATION", "5m")) // Validated via ValidateEnv()
var crowdsecBouncerScheme = OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")
var crowdsecBanResponseCode, _ = strconv.Atoi(OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "403")) // Validated via ValidateEnv()
var crowdsecBanResponseMsg = OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", "Forbidden")

var cache = freecache.NewCache(100 * 1024 * 1024)
var ipProcessed = promauto.NewCounter(prometheus.CounterOpts{
	Name: "crowdsec_traefik_bouncer_processed_ip_total",
	Help: "The total number of processed IP",
})
var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	},
	Timeout: 10 * time.Second,
}

/**
Call Crowdsec local IP and with realIP and return true if IP does NOT have a ban decisions.
*/
func isIpAuthorized(clientIP string) (int, error) {
	// Generating crowdsec API request
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
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

func HandleStreamCache(initialized string) {
	time.AfterFunc(crowdsecBouncerCacheStreamInterval, func () {
		HandleStreamCache("false")
	})
	streamUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerStreamRoute,
		RawQuery: fmt.Sprintf("startup=%s", initialized),
	}
	req, err := http.NewRequest(http.MethodGet, streamUrl.String(), nil)
	if err != nil {
		return
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
	log.Debug().
		Str("method", http.MethodGet).
		Str("url", streamUrl.String()).
		Msg("Request Crowdsec's decision Local API")

	// Calling crowdsec API
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode == http.StatusForbidden {
		return
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
		return
	}
	log.Debug().RawJSON("stream", reqBody).Msg("Found Crowdsec's decision(s), evaluating ...")
	var stream model.Stream
	err = json.Unmarshal(reqBody, &stream)
	if err != nil {
		return
	}
	for i := 0; i < len(stream.New); i++ {
		duration, err := time.ParseDuration(stream.New[i].Duration)
		if err == nil {
			cache.Set([]byte(stream.New[i].Value), []byte("t"), int(duration.Seconds()))
			log.Warn().Str("decision", stream.New[i].Value).Msg("Add")
		}
	}
	for i := 0; i < len(stream.Deleted); i++ {
		cache.Del([]byte(stream.Deleted[i].Value))
		log.Warn().Str("decision", stream.Deleted[i].Value).Msg("Delete")
	}
}

/*
Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	ipProcessed.Inc()
	clientIP := c.ClientIP()
	key := []byte(clientIP)

	log.Debug().
		Str("ClientIP", clientIP).
		Str("RemoteAddr", c.Request.RemoteAddr).
		Str(forwardHeader, c.Request.Header.Get(forwardHeader)).
		Str(realIpHeader, c.Request.Header.Get(realIpHeader)).
		Msg("Handling forwardAuth request")

	if crowdsecBouncerCacheMode != "none" {
		entry, err := cache.Get(key)
		log.Warn().Str("entry", string(entry)).Str("key", string(key)).Msg("Entry")

		if err == nil && len(entry) > 0 {
			log.Info().Str("Banned", string(string(entry)[0])).Msg("Reading cache")
			if string(entry)[0] == 'f' {
				c.Status(http.StatusOK)
			} else {
				c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
			}
			return
		}

		if crowdsecBouncerCacheMode == "stream" {
			c.Status(http.StatusOK)
			return;
		}
	}

	// Getting and verifying ip using ClientIP function
	duration, err := isIpAuthorized(clientIP)
	if err != nil {
		log.Warn().Err(err).Msgf("An error occurred while checking IP %q", c.Request.Header.Get(clientIP))
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		return
	}
	if duration >= 0 {
		if crowdsecBouncerCacheMode == "live" && duration != 0 {
			cache.Set(key, []byte("t"), duration)
		}
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
	} else {
		if crowdsecBouncerCacheMode == "live" {
			cache.Set(key, []byte("f"), int(crowdsecBouncerDefaultCacheDuration.Seconds()))
		}
		c.Status(http.StatusOK)
	}
}

/*
Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	duration, err := isIpAuthorized(healthCheckIp)
	if err != nil || duration >= 0 {
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
