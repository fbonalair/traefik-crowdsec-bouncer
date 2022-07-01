package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPing(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/ping", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "pong", w.Body.String())
}
func TestHealthz(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/healthz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}
func TestMetrics(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/metrics", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "go_info")
	assert.Contains(t, w.Body.String(), "crowdsec_traefik_bouncer_processed_ip_total")
}

func TestForwardAuthInvalidIp(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "Forbidden", w.Body.String())
}
func TestForwardAuthBannedIp(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.RemoteAddr = "1.2.3.4:48328"
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "Forbidden", w.Body.String())
}
func TestForwardAuthValidIp(t *testing.T) {
	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.RemoteAddr = "127.0.0.1:48328"
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
}

/**
FIXME Since we are using var in module, they are loaded before tests. So changing their values with environment variables have no effect.
*/
func testForwardAuthBannedIpCustomResponse(t *testing.T) {
	// Setup
	expectedResponseMsg := "Not Found"
	t.Setenv("CROWDSEC_BOUNCER_BAN_RESPONSE_CODE", "404")
	t.Setenv("CROWDSEC_BOUNCER_BAN_RESPONSE_MSG", expectedResponseMsg)

	router, _ := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/forwardAuth", nil)
	req.RemoteAddr = "1.2.3.4:48328"
	router.ServeHTTP(w, req)

	assert.Equal(t, 404, w.Code)
	assert.Equal(t, expectedResponseMsg, w.Body.String())
}
