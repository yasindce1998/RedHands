FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /redhands ./cmd/redhands

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan tshark hashcat john nikto whatweb \
    python3 python3-pip python3-venv \
    wget curl unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN python3 -m pip install --break-system-packages \
    impacket \
    certipy-ad \
    crackmapexec

# Install Go-based tools
ENV GOPATH=/tmp/go
RUN wget -q https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz && \
    /usr/local/go/bin/go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    /usr/local/go/bin/go install github.com/ffuf/ffuf/v2@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    /usr/local/go/bin/go install github.com/OJ/gobuster/v3@latest && \
    /usr/local/go/bin/go install github.com/lc/gau/v2/cmd/gau@latest && \
    cp /tmp/go/bin/* /usr/local/bin/ && \
    rm -rf /usr/local/go /tmp/go

# Install chisel
RUN wget -q https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz && \
    gunzip chisel_1.9.1_linux_amd64.gz && \
    chmod +x chisel_1.9.1_linux_amd64 && \
    mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel

# Install ligolo-ng
RUN wget -q https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz && \
    tar -xzf ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    rm -f ligolo-ng_proxy_0.6.2_linux_amd64.tar.gz

COPY --from=builder /redhands /usr/local/bin/redhands

RUN mkdir -p /opt/redhands/plugins
WORKDIR /opt/redhands

ENV REDHANDS_TRANSPORT=stdio
ENV REDHANDS_PLUGINS_DIR=/opt/redhands/plugins

EXPOSE 8080 8081

ENTRYPOINT ["redhands"]
