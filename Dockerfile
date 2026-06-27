FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /redhands ./cmd/redhands

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan tshark hashcat john whatweb \
    python3 python3-pip python3-venv perl libnet-ssleay-perl \
    wget curl unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install nikto from source (not in bookworm repos)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install Python security tools (netexec/crackmapexec requires Python 3.12+, install separately if needed)
RUN python3 -m pip install --break-system-packages \
    impacket \
    certipy-ad

# Install Go-based tools
ENV GOPATH=/tmp/go
RUN wget -q https://go.dev/dl/go1.26.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz && \
    rm go1.26.0.linux-amd64.tar.gz && \
    /usr/local/go/bin/go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    /usr/local/go/bin/go install github.com/ffuf/ffuf/v2@latest && \
    /usr/local/go/bin/go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    /usr/local/go/bin/go install github.com/OJ/gobuster/v3@latest && \
    /usr/local/go/bin/go install github.com/lc/gau/v2/cmd/gau@latest && \
    cp /tmp/go/bin/* /usr/local/bin/ && \
    rm -rf /usr/local/go /tmp/go

# Install chisel (resolve latest version dynamically)
RUN CHISEL_VER=$(curl -fsSL https://api.github.com/repos/jpillora/chisel/releases/latest | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4 | tr -d 'v') && \
    curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}/chisel_${CHISEL_VER}_linux_amd64.gz" -o chisel.gz && \
    gunzip chisel.gz && \
    chmod +x chisel && \
    mv chisel /usr/local/bin/chisel

# Install ligolo-ng (resolve latest version dynamically)
RUN LIGOLO_VER=$(curl -fsSL https://api.github.com/repos/nicocha30/ligolo-ng/releases/latest | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4 | tr -d 'v') && \
    curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}/ligolo-ng_proxy_${LIGOLO_VER}_linux_amd64.tar.gz" -o ligolo.tar.gz && \
    tar -xzf ligolo.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    rm -f ligolo.tar.gz

COPY --from=builder /redhands /usr/local/bin/redhands

RUN mkdir -p /opt/redhands/plugins
WORKDIR /opt/redhands

ENV REDHANDS_TRANSPORT=stdio
ENV REDHANDS_PLUGINS_DIR=/opt/redhands/plugins

EXPOSE 8080 8081

ENTRYPOINT ["redhands"]
