# syntax=docker/dockerfile:1.6

FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS builder
WORKDIR /app
COPY main.go .
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o galactic-exchange main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/galactic-exchange .
EXPOSE 8080
CMD ["./galactic-exchange"]
