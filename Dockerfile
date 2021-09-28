FROM golang:1.17 as build-env

WORKDIR /go/src/app
COPY . /go/src/app

RUN go get -d -v ./...

RUN go build -o /go/bin/app

FROM gcr.io/distroless/base
#FROM gcr.io/distroless/base:nonroot
COPY --from=build-env /go/bin/app /
#COPY --from=build-env --chown=nonroot:nonroot /go/bin/app /
CMD ["/app"]

# Run as a non root user.
USER nonroot