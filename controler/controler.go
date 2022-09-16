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
func isIpAuthorized(clientIP string) (bool, error) {
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
	log.Debug().
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
		log.Debug().Msgf("No decision for IP %q. Accepting", clientIP)
		return true, nil
	}

	log.Debug().RawJSON("decisions", reqBody).Msg("Found Crowdsec's decision(s), evaluating ...")
	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		return false, err
	}

	// Authorization logic
	if len(decisions) > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

/*
	Add to the cache information about the IP
*/
func addToCache(lc *cache.Cache, clientIP string, authorized bool) {
	if lc != nil {
		d := model.Decision{}
		d.Value = clientIP
		// use configuration value here
		d.Duration = cache.DefaultExpiration.String()
		d.Authorized = authorized
		log.Debug().Msg("Add IP to local cache")
		duration, err := time.ParseDuration(d.Duration)
		if err != nil {
			log.Warn().Str("Duration", duration.String()).Msg("Error parsing duration provided")
			duration, _ = time.ParseDuration(cache.DefaultExpiration.String())
		}
		lc.Set(d.Value, d, duration)
	}
}

/*
   Get Local cache result for the IP, return if we found it and if it is authorized
*/
func getLocalCache(lc *cache.Cache, clientIP string) (lcFound bool, lcAuthorized bool) {
	log.Debug().
		Msg("Check if IP is in the local cache")
	if lc != nil {
		if cachedIP, found := lc.Get(clientIP); found {
			value := cachedIP.(model.Decision)
			log.Debug().
				Str("ClientIP", value.Value).
				Msg("IP was found in local cache")

			// check if the result is lcAuthorized
			return true, value.Authorized
		} else {
			log.Debug().
				Str("ClientIP", clientIP).
				Msg("IP was not found in local cache")
			return false, false
		}
	}
	return false, false
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
		Str(forwardHeader, c.Request.Header.Get(forwardHeader)).
		Str(realIpHeader, c.Request.Header.Get(realIpHeader)).
		Msg("Handling forwardAuth request")

	// check local cache
	lc := c.MustGet("lc").(*cache.Cache)

	lcFound, lcAuthorized := getLocalCache(lc, clientIP)
	log.Debug().Bool("lcFound", lcFound).Bool("lcAuthorized", lcAuthorized).Msg("Result of cache")
	// the IP was banned and found in the cache
	if !lcAuthorized {
		c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		// The IP has been found in the cache but was not banned before
	} else if lcFound {
		c.Status(http.StatusOK)
	} else {
		// Getting and verifying ip using ClientIP function
		// We should look at the cache in the isIPAuthorized
		isAuthorized, err := isIpAuthorized(clientIP)
		if err != nil {
			log.Warn().Err(err).Msgf("An error occurred while checking IP %q", c.Request.Header.Get(clientIP))
			c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		} else if !isAuthorized {
			addToCache(lc, clientIP, false)
			c.String(crowdsecBanResponseCode, crowdsecBanResponseMsg)
		} else {
			addToCache(lc, clientIP, true)
			c.Status(http.StatusOK)
		}
	}
}

/*
	Route to check bouncer connectivity with Crowdsec agent. Mainly use for Kubernetes readiness probe
*/
func Healthz(c *gin.Context) {
	isHealthy, err := isIpAuthorized(healthCheckIp)
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
