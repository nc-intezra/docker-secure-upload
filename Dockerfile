# syntax=docker/dockerfile:1
#
# Pin both base images by digest in production (docker buildx imagetools
# inspect <image> shows the current digest).

ARG GO_VERSION=1.27

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod VERSION ./
# go.sum is absent while the module has no third-party dependencies.
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -buildid= -X main.version=$(cat VERSION)" \
      -o /out/diode-upload ./cmd/diode-upload
# Mount points owned by the runtime user. Docker copies a directory's
# ownership into a new, empty named volume the first time it is mounted, so
# the state volume starts out writable by uid 65532 instead of root.
RUN mkdir -p /out/state /out/data && chmod 0750 /out/state && chmod 0755 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/diode-upload /usr/local/bin/diode-upload
COPY --from=build --chown=65532:65532 /out/state /state
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080 9100
# start-period covers clamd loading its signatures on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10m --retries=3 \
  CMD ["/usr/local/bin/diode-upload", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/diode-upload"]
