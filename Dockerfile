FROM golang:1.23-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/redhands ./cmd/redhands

FROM alpine:3.20

RUN apk add --no-cache nmap nmap-scripts

COPY --from=builder /bin/redhands /usr/local/bin/redhands

USER nobody:nobody
ENTRYPOINT ["redhands"]
