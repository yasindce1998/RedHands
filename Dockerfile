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

# Install chisel
RUN curl -fsSL "https://github.com/jpillora/chisel/releases/download/v1.11.5/chisel_1.11.5_linux_amd64.gz" -o chisel.gz && \
    gunzip chisel.gz && \
    chmod +x chisel && \
    mv chisel /usr/local/bin/chisel

# Install ligolo-ng
RUN curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.3/ligolo-ng_proxy_0.8.3_linux_amd64.tar.gz" -o ligolo.tar.gz && \
    tar -xzf ligolo.tar.gz && \
    mv proxy /usr/local/bin/ligolo-proxy && \
    rm -f ligolo.tar.gz

# Install KubeDagger (eBPF-based Kubernetes offensive toolkit)
RUN curl -fsSL "https://github.com/yasindce1998/KubeDagger/releases/download/v0.1.0/kubedagger-client-linux-amd64" -o /usr/local/bin/kubedagger-client && \
    curl -fsSL "https://github.com/yasindce1998/KubeDagger/releases/download/v0.1.0/kubedagger-operator-linux-amd64" -o /usr/local/bin/kubedagger-operator && \
    chmod +x /usr/local/bin/kubedagger-client /usr/local/bin/kubedagger-operator

# Install Barzakh (UEFI bootkit adversary simulation toolkit)
RUN curl -fsSL "https://github.com/yasindce1998/Barzakh/releases/download/v0.1.1/barzakh-adversary-linux-x86_64" -o /usr/local/bin/barzakh-adversary && \
    curl -fsSL "https://github.com/yasindce1998/Barzakh/releases/download/v0.1.1/barzakh-scanner-linux-x86_64" -o /usr/local/bin/barzakh-scanner && \
    chmod +x /usr/local/bin/barzakh-adversary /usr/local/bin/barzakh-scanner

COPY --from=builder /redhands /usr/local/bin/redhands

RUN mkdir -p /opt/redhands/plugins
WORKDIR /opt/redhands

ENV REDHANDS_TRANSPORT=stdio
ENV REDHANDS_PLUGINS_DIR=/opt/redhands/plugins

EXPOSE 8080 8081

ENTRYPOINT ["redhands"]
