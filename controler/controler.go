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

	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	realIpHeader         = "X-Real-Ip"
	forwardHeader        = "X-Forwarded-For"
	crowdsecAuthHeader   = "X-Api-Key"
	crowdsecBouncerRoute = "v1/decisions"
	healthCheckIp        = "127.0.0.1"
)

var crowdsecBouncerApiKey = RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerScheme = OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")
var crowdsecBanResponseCode, _ = strconv.Atoi(OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "403")) // Validated via ValidateEnv()
var crowdsecBanResponseMsg = OptionalEnv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", "Forbidden")
var (
	ipProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "crowdsec_traefik_bouncer_processed_ip_total",
		Help: "The total number of processed IP",
	})
)

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
func isIpAuthorized(clientIP string, lc *cache.Cache) (bool, error) {
	// Generating crowdsec API request
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", clientIP),
	}
	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
	log.Info().
		Str("method", http.MethodGet).
		Str("url", decisionUrl.String()).
		Msg("Request Crowdsec's decision Local API")

	// Calling crowdsec API
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
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
		log.Info().Msgf("No decision for IP %q. Accepting", clientIP)
		cacheCleanIP(lc, clientIP)
		return true, nil
	}

	log.Info().RawJSON("decisions", reqBody).Msg("Found Crowdsec's decision(s), evaluating ...")
	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, err
	}

	// Authorization logic
	if len(decisions) > 0 {
		cacheDecisionResult(lc, decisions)
		return false, nil
	} else {
		cacheCleanIP(lc, clientIP)
		return true, nil
	}

}

func cacheDecisionResult(lc *cache.Cache, decisions []model.Decision) {
	for _, d := range decisions {
		addToCache(lc, d)
	}
}

func cacheCleanIP(lc *cache.Cache, clientIP string) {
	d := model.Decision{}
	d.Value = clientIP
	// use configuration value here
	d.Duration = "4h00m00.00000000s"
	addToCache(lc, d)
}

func addToCache(lc *cache.Cache, d model.Decision) {
	// TODO: test if localCache is in use
	log.Info().Msg("Add IP to local cache")
	lc.Set(d.Value, d, cache.DefaultExpiration)
}

/*
   Get Local cache result for the IP
*/
func getLocalCache(lc *cache.Cache, clientIP string) (lcFound bool, lcBan bool) {
	log.Info().
		Msg("Request IP in local cache")
	if cachedIP, found := lc.Get(clientIP); found {
		value := cachedIP.(model.Decision)
		log.Info().
			Str("ClientIP", value.Value).
			Msg("IP was found in local cache")
		// check if the result is positiv
		return true, false
	} else {
		log.Info().
			Str("ClientIP", clientIP).
			Msg("IP was not found in local cache")
		return false, false
	}

}

/*
	Main route used by Traefik to verify authorization for a request
*/
func ForwardAuth(c *gin.Context) {
	ipProcessed.Inc()
	clientIP := c.ClientIP()

	log.Info().
		Str("ClientIP", clientIP).
		Str("RemoteAddr", c.Request.RemoteAddr).
		Str(forwardHeader, c.Request.Header.Get(forwardHeader)).
		Str(realIpHeader, c.Request.Header.Get(realIpHeader)).
		Msg("Handling forwardAuth request")

	// check local cache
	lc := c.MustGet("lc").(cache.Cache)
	lcFound, lcBan := getLocalCache(&lc, clientIP)
	log.Info().Bool("lcFound", lcFound).Bool("lcBan", lcBan).Msg("Works")
	if lcBan {
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
	} else if lcFound {
		c.Status(http.StatusOK)
	} else {
		// Getting and verifying ip using ClientIP function
		isAuthorized, err := isIpAuthorized(clientIP, &lc)
		if err != nil {
			log.Warn().Err(err).Msgf("An error occurred while checking IP %q", c.Request.Header.Get(clientIP))
			c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		} else if !isAuthorized {
			c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		} else {
			c.Status(http.StatusOK)
		}
	}
}

/*
	Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	isHealthy, err := isIpAuthorized(healthCheckIp, nil)
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
