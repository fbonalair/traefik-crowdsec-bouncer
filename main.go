package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	router := gin.Default()
	router.GET("/api/v1/ping", Ping)
	err := router.Run()
	if err != nil {
		println("An error occurred while starting server", err)
		return
	}

}

func Ping(c *gin.Context) {
	c.String(http.StatusOK, "pong")
}
