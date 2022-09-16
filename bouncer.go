package main

import (
	"os"
	"time"

	"strings"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/controler"
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logLevel = OptionalEnv("CROWDSEC_BOUNCER_LOG_LEVEL", "1")
var trustedProxiesList = strings.Split(OptionalEnv("TRUSTED_PROXIES", "0.0.0.0/0"), ",")

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

func CacheMiddleware(lc cache.Cache) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("lc", lc)
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
	lc := cache.New(5*time.Minute, 10*time.Minute)

	// Web framework
	router := gin.New()
	err = router.SetTrustedProxies(trustedProxiesList)
	if err != nil {
		return nil, err
	}
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	router.Use(CacheMiddleware(*lc))
	router.GET("/api/v1/ping", controler.Ping)
	router.GET("/api/v1/healthz", controler.Healthz)
	router.GET("/api/v1/forwardAuth", controler.ForwardAuth)
	router.GET("/api/v1/metrics", controler.Metrics)
	return router, nil
}
