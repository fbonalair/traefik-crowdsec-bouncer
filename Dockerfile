# 1.17-alpine bug : standard_init_linux.go:228: exec user process caused: no such file or directory
FROM golang:1.17 as build-env

WORKDIR /go/src/app
COPY . /go/src/app

RUN go get -d -v ./...

RUN go build -o /go/bin/app

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env --chown=nonroot:nonroot /go/bin/app /

# Run as a non root user.
USER nonroot

ARG BUSYBOX_VERSION=1.31.0-i686-uclibc
ADD https://busybox.net/downloads/binaries/$BUSYBOX_VERSION/busybox_WGET /wget
RUN chmod a+x /wget

# Run app
CMD ["/app"]
