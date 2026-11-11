FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /redhands ./cmd/redhands && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /redhands-cli ./cmd/redhands-cli && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /redhands-creds ./cmd/redhands-creds

# Build pinned Go tools with the image toolchain instead of downloading an
# unchecked, hard-coded amd64 Go archive in the runtime image.
FROM golang:1.26-alpine AS go-tools
RUN apk add --no-cache git python3
COPY scripts/dependencies.json scripts/dependencies.py /locks/
RUN mkdir -p /out && \
    for tool in subfinder httpx nuclei ffuf katana gobuster gau waybackurls; do \
      CGO_ENABLED=0 GOBIN=/out go install "$(python3 /locks/dependencies.py go "$tool")" || exit 1; \
    done

FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nmap masscan tshark hashcat john whatweb \
    python3 python3-pip python3-venv perl libnet-ssleay-perl \
    curl unzip git ca-certificates && rm -rf /var/lib/apt/lists/*

COPY scripts/dependencies.json scripts/dependencies.py /opt/redhands/install/
RUN git init /opt/nikto && \
    git -C /opt/nikto remote add origin https://github.com/sullo/nikto.git && \
    git -C /opt/nikto fetch --depth 1 origin "$(python3 /opt/redhands/install/dependencies.py source nikto)" && \
    git -C /opt/nikto checkout --detach FETCH_HEAD && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Top-level Python versions are pinned; transitive wheel hashes remain release work.
RUN python3 -m pip install --break-system-packages \
    "$(python3 /opt/redhands/install/dependencies.py python impacket)" \
    "$(python3 /opt/redhands/install/dependencies.py python certipy)"

COPY --from=go-tools /out/ /usr/local/bin/
RUN for tool in chisel ligolo-proxy kubedagger-client kubedagger-operator barzakh-adversary barzakh-scanner; do \
      python3 /opt/redhands/install/dependencies.py install "$tool" --output /usr/local/bin || exit 1; \
    done

COPY --from=builder /redhands /redhands-cli /redhands-creds /usr/local/bin/
RUN groupadd --system redhands && useradd --system --gid redhands --home-dir /opt/redhands redhands && \
    mkdir -p /opt/redhands/plugins /opt/redhands/data && \
    chown -R redhands:redhands /opt/redhands
WORKDIR /opt/redhands
ENV REDHANDS_TRANSPORT=stdio
ENV REDHANDS_PLUGINS_DIR=/opt/redhands/plugins
EXPOSE 8080 8081
USER redhands
ENTRYPOINT ["redhands"]
