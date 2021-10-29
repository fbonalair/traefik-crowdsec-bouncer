package main

import (
	"context"
	"os"

	"github.com/fbonalair/traefik-crowdsec-bouncer/controler"
	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	stdout "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var tracer = otel.Tracer("gin-server")

func main() {
	tp := initTracer()
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Warn().Msgf("Error shutting down tracer provider: %v", err)
		}
	}()
	router := setupRouter()
	err := router.Run()
	if err != nil {
		log.Fatal().Err(err).Msgf("An error occurred while starting bouncer")
		return
	}

}

func setupRouter() *gin.Engine {
	// logger framework
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
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

	// Web framework
	router := gin.New()
	router.Use(logger.SetLogger(
		logger.WithSkipPath([]string{"/api/v1/ping", "/api/v1/healthz"}),
	))
	router.Use(otelgin.Middleware("crowdsec_traefik_bouncer"))
	router.GET("/api/v1/ping", controler.Ping)
	router.GET("/api/v1/healthz", controler.Healthz)
	router.GET("/api/v1/forwardAuth", controler.ForwardAuth)
	router.GET("/api/v1/metrics", controler.Metrics)
	return router
}

func initTracer() *sdktrace.TracerProvider {
	exporter, err := stdout.New(stdout.WithPrettyPrint())
	if err != nil {
		log.Fatal().Err(err).Msg("Error while creating exporter")
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp
}
