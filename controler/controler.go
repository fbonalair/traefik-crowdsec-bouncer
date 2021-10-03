package controler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	. "github.com/fbonalair/traefik-crowdsec-bouncer/config"
	"github.com/fbonalair/traefik-crowdsec-bouncer/model"
	"github.com/gin-gonic/gin"
)

const (
	clientIpHeader       = "X-Real-Ip"
	crowdsecAuthHeader   = "X-Api-Key"
	crowdsecBouncerRoute = "v1/decisions"
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

func callSecApi(c *gin.Context, realIP string) {
	// Calling crowdsec API
	decisionUrl := url.URL{
		Scheme:   crowdsecBouncerScheme,
		Host:     crowdsecBouncerHost,
		Path:     crowdsecBouncerRoute,
		RawQuery: fmt.Sprintf("type=ban&ip=%s", realIP),
	}

	req, err := http.NewRequest(http.MethodGet, decisionUrl.String(), nil)
	if err != nil {
		remedyError(fmt.Errorf("can't create a new http request : %w", err), c)
		return
	}
	req.Header.Add(crowdsecAuthHeader, crowdsecBouncerApiKey)
	resp, err := client.Do(req)
	if err != nil {
		remedyError(fmt.Errorf("error while requesting crowdsec API : %w", err), c)
		return
	}

	// verifying access
	if resp.StatusCode == http.StatusForbidden {
		remedyError(errors.New("access to crowdsec api is forbidden, please verify API KEY"), c)
		return
	}

	// Parsing response
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			remedyError(err, c)
		}
	}(resp.Body)
	reqBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		remedyError(fmt.Errorf("error while parsing crowdsec response body : %w", err), c)
		return
	}

	var decisions []model.Decision
	err = json.Unmarshal(reqBody, &decisions)
	if err != nil {
		remedyError(fmt.Errorf("error while unmarshalling crowdsec response body : %w", err), c)
		return
	}

	// Authorization logic
	if len(decisions) > 0 {
		c.String(http.StatusForbidden, "Forbidden")
	} else {
		c.Status(http.StatusOK)
	}
}

func ForwardAuth(c *gin.Context) {
	// Getting and verifying ip from header
	realIP := c.Request.Header.Get(clientIpHeader)
	parsedRealIP := net.ParseIP(realIP)
	if parsedRealIP == nil {
		remedyError(fmt.Errorf("the header %q isn't a valid IP address", clientIpHeader), c)
		return
	}

	callSecApi(c, realIP)
}

func Healthz(c *gin.Context) {
	callSecApi(c, "127.0.0.1")
	// TODO log warn if api not joinable
}

func Ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func remedyError(err error, c *gin.Context) {
	_ = c.Error(err) // nil err should be handled earlier
	c.String(http.StatusForbidden, "Forbidden")
}
