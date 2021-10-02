# traefik-crowdsec-bouncer
A http service to verify request and bounce them according to decisions made by CrowdSec.

# Description
This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer for the router [Traefik](https://doc.traefik.io/traefik/) to block malicious IP to access your services.
For this it leverages [Traefik v2 ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) and query CrowdSec with client IP.
If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual.

# Demo
## Prerequisites 
[Docker](https://docs.docker.com/get-docker/) and [Docker-compose](https://docs.docker.com/compose/install/) installed.   
You can use the docker-compose in the examples' folder as a starting point.
Through traefik it exposes the whoami countainer on port 80, with the bouncer accepting and rejecting client IP.   
Launch your all services except the bouncer with the follow commands:
```
git clone https://github.com/fbonalair/traefik-crowdsec-bouncer.git
cd examples
docker-compose up -d traefik crowdsec whoami 
```

## Procedure
1. Get an bouncer API key from CrowdSec with command `docker exec crowdsec-example cscli bouncers add traefik-bouncer`
2. Copy the API key printed. You **_WON'T_** be able the get it again.
3. Past this key as the value for bouncer environment variable CROWDSEC_BOUNCER_API_KEY, instead of "MyApiKey"
4. Start bouncer in attach mode with `docker-compose up bouncer`
5. Start a browser and visit `http://localhost/`. You will see the container whoami page, copy your IP address from X-Real-Ip line (i.e. 192.168.128.1).  
In your console, you will see lines showing your authorized request (i.e. "status":200).
6. In another console, ban your IP with command `docker exec crowdsec-example cscli decisions add --ip 192.168.128.1`, modify the IP with your address.
7. Visit `http://localhost/` again, in your browser you will see "Forbidden" since this time since you've been banned.
Though the console you will see "status":403.
8. Unban yourself with `docker exec crowdsec-example cscli decisions delete --ip 192.168.128.1`
9. Visit `http://localhost/` one last time, you will have access to the container whoami.  

Enjoy!

# Usage
For now, this web service is mainly fought to be used as a container.

## Prerequisites
You should have Traefik v2 and a CrowdSec instance running.   
The container is available on docker as image `fbonalair/traefik-crowdsec-bouncer`. Host it as you see fit, though it must have access to CrowdSec and be accessible by Traefik.   
Follow  [traefik v2 ForwardAuth middleware](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) documentation to create a forwardAuth middle pointing to your bouncer host.   
Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add)

## Configuration
The webservice configuration is made via environment variables:

* `CROWDSEC_BOUNCER_API_KEY`            - CrowdSec bouncer API key required to be authorized to request local API (required)`
* `CROWDSEC_AGENT_HOST`                 - Host and port of CrowdSec agent. i.e crowdsec-agent:8080 (required)`
* `CROWDSEC_BOUNCER_SCHEME`             - Scheme to query CrowdSec agent. Expected value: http, https. Default to http`
* `PORT`                                - Change listening port of web server. Default listen on 8080
* `GIN_MODE`                            - By default, run app in "debug" mode. Set it to "release" in production

## Exposed routes
The webservice exposes 3 routes:

* `/api/v1/forwardAuth`             - Main route to be used by Traefik: query CrowdSec agent with the header `X-Real-Ip` as client IP`
* `/api/v1/ping`                    - Simple health route that respond pong with http 200`
* `/api/v1/healthz`                 - Another health route that query CrowdSec agent with localhost (127.0.0.1)`

# Contribution
TBD