# Build stage.
FROM golang:1.27-alpine AS builder
WORKDIR /app

# Download modules first so the layer caches until go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version is stamped into main.version the same way task go:build does it. It
# comes in as a build arg rather than from `git describe` because .dockerignore
# excludes .git, so describe inside the build would always fall back. Pass the
# real value with `docker build --build-arg VERSION=$(git describe --tags --always --dirty)`
# or via `task image:build`; a bare build harmlessly reports "docker".
ARG VERSION=docker
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" -o panos-mcp-go .

# Final stage. Pin the minor release rather than :latest so the image is
# reproducible; the docker Dependabot ecosystem keeps it current.
FROM alpine:3.24
WORKDIR /app

# ca-certificates lets the server verify the firewall's TLS chain against the
# system trust store. A private CA is supplied at runtime through PANOS_CA_CERT.
RUN apk add --no-cache ca-certificates

# Run as a non-root user. --chown on the copy avoids a second layer that would
# duplicate the binary just to change its ownership.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --chown=appuser:appgroup --from=builder /app/panos-mcp-go .
USER appuser

# config.go defaults MCP_HTTP_HOST to 127.0.0.1 so a developer machine never
# exposes the server to the LAN by accident. Inside a container loopback makes a
# published port unreachable from the host, so bind the container interface. A
# non-loopback bind requires MCP_HTTP_TOKEN: the server refuses to start on
# 0.0.0.0 without one, so pass MCP_HTTP_TOKEN when running the http transport.
ENV MCP_HTTP_HOST=0.0.0.0

ENTRYPOINT ["./panos-mcp-go"]
