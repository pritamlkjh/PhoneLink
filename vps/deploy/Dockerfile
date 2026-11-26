# Build stage
FROM golang:1.26-alpine AS builder

ARG TARGETARCH
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build -ldflags="-w -s" -o /app/phonelink-relay ./cmd/relay && \
    mkdir -p /app/apk && \
    if [ -f /app/PhoneLink.apk ]; then cp /app/PhoneLink.apk /app/apk/PhoneLink.apk; fi

# Production runtime stage: minimal alpine container
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/phonelink-relay /app/phonelink-relay
COPY --from=builder /app/apk/ /app/
RUN mkdir -p /app/data && chown -R nobody:nobody /app/data

# Run as unprivileged user
USER nobody:nobody

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8443/healthz || exit 1

ENTRYPOINT ["/app/phonelink-relay"]
