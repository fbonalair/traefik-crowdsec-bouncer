module github.com/fbonalair/traefik-crowdsec-bouncer

go 1.17

require (
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/gin-gonic/gin v1.7.4
	golang.org/x/net v0.0.0-20210928044308-7d9f5e0b762b
)

require (
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.13.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/go-playground/validator/v10 v10.4.1 // indirect
	github.com/golang/protobuf v1.3.3 // indirect
	github.com/json-iterator/go v1.1.9 // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v0.0.0-20180701023420-4b7aa43c6742 // indirect
	github.com/ugorji/go/codec v1.1.7 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	golang.org/x/sys v0.0.0-20210423082822-04245dca01da // indirect
	gopkg.in/yaml.v2 v2.2.8 // indirect
)

replace github.com/fbonalair/traefik-crowdsec-bouncer/config => ../config

replace github.com/fbonalair/traefik-crowdsec-bouncer/model => ../model

replace github.com/fbonalair/traefik-crowdsec-bouncer/controler => ../controler
