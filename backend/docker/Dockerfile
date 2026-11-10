# Build context: repo root (set by root docker-compose.yml)
FROM golang:1.25.7-alpine AS builder

WORKDIR /build/backend
COPY backend/go.mod backend/go.sum* ./
RUN go mod download 2>/dev/null || true
COPY backend/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=mod -ldflags="-s -w" -o /backend-server ./cmd/server

FROM alpine:3.19
RUN echo "https://mirror.csclub.uwaterloo.ca/alpine/v3.19/main" > /etc/apk/repositories \
    && echo "https://mirror.csclub.uwaterloo.ca/alpine/v3.19/community" >> /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata wget \
    || (echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/main" > /etc/apk/repositories \
    && echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/community" >> /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata wget)
WORKDIR /app
COPY --from=builder /backend-server ./server
COPY backend/configs/server.yaml .
RUN mkdir -p certs
EXPOSE 8443
ENTRYPOINT ["./server", "-config", "server.yaml"]
