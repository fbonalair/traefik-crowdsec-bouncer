package main

import (
	"fmt"
	"os"
	"time"

	"strings"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/controler"
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logLevel = OptionalEnv("CROWDSEC_BOUNCER_LOG_LEVEL", "1")
var trustedProxiesList = strings.Split(OptionalEnv("TRUSTED_PROXIES", "0.0.0.0/0"), ",")
var crowdsecDefaultCacheDuration = OptionalEnv("CROWDSEC_BOUNCER_DEFAULT_CACHE_DURATION", "15m00s")
var crowdsecDefaultStreamModeInterval = OptionalEnv("CROWDSEC_LAPI_STREAM_MODE_INTERVAL", "1m")
var crowdsecEnableLocalCache = OptionalEnv("CROWDSEC_BOUNCER_ENABLE_LOCAL_CACHE", "false")
var crowdsecEnableStreamMode = OptionalEnv("CROWDSEC_LAPI_ENABLE_STREAM_MODE", "true")
var cr *cron.Cron
var lc *cache.Cache

func main() {
	ValidateEnv()
	router, err := setupRouter()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting webserver")
		return
	}

	err = router.Run()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
		return
	}

}

func cacheMiddleware(lc *cache.Cache) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("lc", lc)
		c.Next()
	}
}

func cronMiddleware(cr *cron.Cron) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("cr", cr)
		c.Next()
	}
}

func setupRouter() (*gin.Engine, error) {
	// logger framework
	if gin.IsDebugging() {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(
			zerolog.ConsoleWriter{
				Out:        os.Stderr,
				NoColor:    false,
				TimeFormat: zerolog.TimeFieldFormat,
			},
		)
	}
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}
	zerolog.SetGlobalLevel(level)

	// local go-cache
	if crowdsecEnableLocalCache == "true" || crowdsecEnableStreamMode == "true" {
		duration, err := time.ParseDuration(crowdsecDefaultCacheDuration)
		if err != nil {
			log.Warn().Msg("Duration provided is not valid, defaulting to 15m00s")
			duration, _ = time.ParseDuration("15m")
		}
		lc = cache.New(duration, 5*time.Minute)
		if crowdsecEnableStreamMode == "true" {
			duration, err := time.ParseDuration(crowdsecDefaultStreamModeInterval)
			var strD string
			if err != nil {
				log.Warn().Msg("Duration provided is not valid, defaulting to 1m")
				duration, _ = time.ParseDuration("1m")
				strD = duration.String()
				strD = fmt.Sprintf("@every %v", strD)
			} else {
				strD = duration.String()
				strD = fmt.Sprintf("@every %v", strD)
			}
			go func() {
				log.Debug().Msg("Streaming mode enabled")
				cr = cron.New()
				cr.Start()
				cr.AddFunc(strD, func() {
					controler.CallLAPIStream(lc, false)
				})
				log.Debug().Msg("Start polling initial stream")
				controler.CallLAPIStream(lc, true)
				log.Debug().Msg("Finish polling initial stream")
			}()
		} else {
			cr = nil
		}

	} else {
		lc = nil
		cr = nil
	}

	// Web framework
	router := gin.New()
	err = router.SetTrustedProxies(trustedProxiesList)
	if err != nil {
		return nil, err
	}
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	router.Use(cacheMiddleware(lc))
	router.Use(cronMiddleware(cr))
	router.GET("/api/v1/ping", controler.Ping)
	router.GET("/api/v1/healthz", controler.Healthz)
	router.GET("/api/v1/forwardAuth", controler.ForwardAuth)
	router.GET("/api/v1/metrics", controler.Metrics)
	return router, nil
}
