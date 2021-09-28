package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	// TODO: Verifying env vars
	router := gin.Default()
	router.GET("/api/v1/ping", ping)
	router.GET("/api/v1/forwardAuth", forwardAuth)
	err := router.Run()
	if err != nil {
		println("An error occurred while starting server: ", err)
		return
	}

}

func ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}

func forwardAuth(c *gin.Context) {
	println("Authorising request") // FIXME debug

	// TODO get headers
	// TODO call crowsec API
	// TODO business logic
	c.Status(http.StatusOK)
}
