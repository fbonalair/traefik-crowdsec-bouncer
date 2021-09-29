package main

import (
	. "github.com/fbonalair/traefik-crowdsec-bouncer/controler"
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.GET("/api/v1/ping", Ping)
	router.GET("/api/v1/forwardAuth", ForwardAuth)
	err := router.Run()
	if err != nil {
		println("An error occurred while starting bouncer: ", err)
		return
	}

}
