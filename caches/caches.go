package caches

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/coocood/freecache"
	"github.com/rs/zerolog/log"
)

const (
	cacheBannedValue            = "t"
	cacheNoBannedValue          = "f"
)

var crowdsecBouncerApiKey = RequiredEnv("CROWDSEC_BOUNCER_API_KEY")
var crowdsecBouncerHost = RequiredEnv("CROWDSEC_AGENT_HOST")
var crowdsecBouncerScheme = OptionalEnv("CROWDSEC_BOUNCER_SCHEME", "http")
var crowdsecBouncerCacheMode = OptionalEnv("CROWDSEC_BOUNCER_CACHE_MODE", "none") // Validated via ValidateEnv()
var crowdsecBouncerCacheStreamInterval, _ = time.ParseDuration(OptionalEnv("CROWDSEC_BOUNCER_CACHE_STREAM_INTERVAL", "1m")) // Validated via ValidateEnv()
var cache = freecache.NewCache(100 * 1024 * 1024)
var client = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	},
	Timeout: 5 * time.Second,
}

var IsHealthy = false

func HandleStreamCache(initialized string) {
	time.AfterFunc(crowdsecBouncerCacheStreamInterval, func () {
		HandleStreamCache("false")
	})
	streamUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     CrowdsecBouncerStreamRoute,
		RawQuery: fmt.Sprintf("startup=%s", initialized),
	}
	req, err := http.NewRequest(http.MethodGet, streamUrl.String(), nil)
	if err != nil {
		IsHealthy = false
		return
	}
	req.Header.Add(CrowdsecAuthHeader, crowdsecBouncerApiKey)
	log.Debug().
		Str("method", http.MethodGet).
		Str("url", streamUrl.String()).
		Msg("Request Crowdsec's decision Local API")

	// Calling crowdsec API
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode == http.StatusForbidden {
		IsHealthy = false
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
		IsHealthy = false
		return
	}
	log.Debug().RawJSON("stream", reqBody).Msg("Found Crowdsec's decision(s), evaluating ...")
	var stream model.Stream
	err = json.Unmarshal(reqBody, &stream)
	if err != nil {
		IsHealthy = false
		return
	}
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			cache.Set([]byte(decision.Value), []byte("t"), int(duration.Seconds()))
			log.Debug().Str("decision", decision.Value).Msg("Add")
		}
	}
	for _, decision := range stream.Deleted {
		cache.Del([]byte(decision.Value))
		log.Debug().Str("decision", decision.Value).Msg("Delete")
	}
	IsHealthy = true
	return
}

func GetDecision(clientIP string) (bool, error) {
	key := []byte(clientIP)
	isBanned, err := cache.Get(key)
	if err == nil && len(isBanned) > 0 {
		log.Info().Str("isBanned", string(isBanned)).Msg("Reading cache")
		if string(isBanned) == cacheNoBannedValue {
			return false, nil
		} else {
			return true, nil
		}
	}
	return false, err
}

func SetDecision(clientIP string, isBanned bool, duration int) {
	key := []byte(clientIP)
	if isBanned {
		cache.Set(key, []byte(cacheBannedValue), duration)
	} else {
		cache.Set(key, []byte(cacheNoBannedValue), duration)
	}
}