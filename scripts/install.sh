#!/usr/bin/env bash
set -euo pipefail

# RedHands Quick Installer
# One-line install: curl -fsSL https://raw.githubusercontent.com/yasindce1998/redhands/main/scripts/install.sh | bash
#
# This script:
#   1. Downloads the latest redhands binary
#   2. Installs it to /usr/local/bin (or ~/bin if not root)
#   3. Optionally installs tool dependencies (--with-tools)
#   4. Prints MCP configuration snippet

VERSION="${REDHANDS_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
WITH_TOOLS=false
PROFILE="minimal"
REPO="yasindce1998/redhands"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

for arg in "$@"; do
    case "$arg" in
        --with-tools) WITH_TOOLS=true ;;
        --profile=*) PROFILE="${arg#*=}" ;;
        --dir=*) INSTALL_DIR="${arg#*=}" ;;
        --help|-h)
            echo "RedHands Quick Installer"
            echo ""
            echo "Usage: curl -fsSL .../install.sh | bash -s -- [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --with-tools       Also install security tool dependencies"
            echo "  --profile=NAME     Tool profile: minimal, web, network, ad, all (default: minimal)"
            echo "  --dir=PATH         Install directory (default: /usr/local/bin)"
            echo ""
            echo "Examples:"
            echo "  curl -fsSL .../install.sh | bash"
            echo "  curl -fsSL .../install.sh | bash -s -- --with-tools --profile=web"
            exit 0
            ;;
    esac
done

# Use ~/bin if not root
if [[ "$EUID" -ne 0 ]] && [[ "$INSTALL_DIR" == "/usr/local/bin" ]]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       RedHands Quick Installer                   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

log_info "Platform: ${OS}/${ARCH}"
log_info "Install dir: ${INSTALL_DIR}"

# Download redhands binary
if [[ "$VERSION" == "latest" ]]; then
    log_info "Fetching latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/' || echo "")
    if [[ -z "$VERSION" ]]; then
        log_warn "Could not fetch latest version from GitHub. Building from source..."
        if command -v go &>/dev/null; then
            log_info "Installing via go install..."
            go install "github.com/${REPO}/cmd/redhands@latest"
            GOBIN=$(go env GOPATH)/bin
            if [[ -f "$GOBIN/redhands" ]]; then
                cp "$GOBIN/redhands" "$INSTALL_DIR/redhands"
                chmod +x "$INSTALL_DIR/redhands"
                log_ok "RedHands installed to $INSTALL_DIR/redhands (built from source)"
            fi
        else
            log_error "Go not found. Install Go 1.26+ or download a release binary manually."
            exit 1
        fi
    fi
fi

if [[ -n "$VERSION" ]]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/redhands_${VERSION}_${OS}_${ARCH}.tar.gz"
    log_info "Downloading RedHands v${VERSION}..."

    if curl -fsSL "$DOWNLOAD_URL" -o /tmp/redhands.tar.gz 2>/dev/null; then
        tar -xzf /tmp/redhands.tar.gz -C /tmp redhands 2>/dev/null || tar -xzf /tmp/redhands.tar.gz -C /tmp
        mv /tmp/redhands "$INSTALL_DIR/redhands"
        chmod +x "$INSTALL_DIR/redhands"
        rm -f /tmp/redhands.tar.gz
        log_ok "RedHands v${VERSION} installed to $INSTALL_DIR/redhands"
    else
        log_warn "Release binary not available. Building from source..."
        if command -v go &>/dev/null; then
            go install "github.com/${REPO}/cmd/redhands@latest"
            GOBIN=$(go env GOPATH)/bin
            if [[ -f "$GOBIN/redhands" ]]; then
                cp "$GOBIN/redhands" "$INSTALL_DIR/redhands"
                chmod +x "$INSTALL_DIR/redhands"
                log_ok "RedHands installed to $INSTALL_DIR/redhands (built from source)"
            fi
        else
            log_error "Neither release binary nor Go compiler available."
            log_error "Install Go 1.26+ from https://go.dev/dl/ and retry."
            exit 1
        fi
    fi
fi

# Ensure install dir is on PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    log_warn "$INSTALL_DIR is not on your PATH."
    echo ""
    echo "  Add to your shell profile:"
    echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
fi

# Install tool dependencies if requested
if $WITH_TOOLS; then
    echo ""
    log_info "Installing tool dependencies (profile: $PROFILE)..."
    SCRIPT_URL="https://raw.githubusercontent.com/${REPO}/main/scripts/install-tools.sh"
    if curl -fsSL "$SCRIPT_URL" -o /tmp/install-tools.sh 2>/dev/null; then
        chmod +x /tmp/install-tools.sh
        sudo /tmp/install-tools.sh --profile "$PROFILE" --yes
        rm -f /tmp/install-tools.sh
    else
        log_warn "Could not download tool installer. Run manually after cloning the repo:"
        echo "  git clone https://github.com/${REPO}.git && cd redhands"
        echo "  sudo ./scripts/install-tools.sh --profile $PROFILE"
    fi
fi

# Print MCP config
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              Setup Complete!                     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}MCP Configuration${NC}"
echo ""
echo "Add to your MCP config file:"
echo ""
echo "  Claude Code (~/.claude/claude_desktop_config.json):"
echo "  Cursor (.cursor/mcp.json):"
echo "  VS Code (.vscode/mcp.json):"
echo ""
cat <<EOF
  {
    "mcpServers": {
      "redhands": {
        "command": "$INSTALL_DIR/redhands"
      }
    }
  }
EOF
echo ""
echo -e "${GREEN}Quick test:${NC}"
echo "  redhands  # starts in stdio mode (for MCP clients)"
echo ""
if ! $WITH_TOOLS; then
    echo -e "${YELLOW}Tip:${NC} Install security tools with:"
    echo "  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | bash -s -- --with-tools --profile=web"
    echo ""
fi
