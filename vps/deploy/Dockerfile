# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/phonelink-relay ./cmd/relay

# Production runtime stage: scratch container (minimal attack surface, ~15MB)
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/phonelink-relay /app/phonelink-relay

# Run as unprivileged user
USER nobody:nobody

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8443/healthz || exit 1

ENTRYPOINT ["/app/phonelink-relay"]
