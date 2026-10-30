# syntax=docker/dockerfile:1
#
# Pin both base images by digest in production (docker buildx imagetools
# inspect <image> shows the current digest).

ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod ./
# go.sum is absent while the module has no third-party dependencies.
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" \
      -o /out/diode-upload ./cmd/diode-upload

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/diode-upload /usr/local/bin/diode-upload
USER 65532:65532
EXPOSE 8080 9100
# start-period covers clamd loading its signatures on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10m --retries=3 \
  CMD ["/usr/local/bin/diode-upload", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/diode-upload"]
