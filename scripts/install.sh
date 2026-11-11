#!/usr/bin/env bash
set -euo pipefail

# RedHands Quick Installer
# One-line install: curl -fsSL https://raw.githubusercontent.com/yasindce1998/redhands/main/scripts/install.sh | bash
#
# This script:
#   1. Downloads the latest redhands binary
#   2. Installs it to /usr/local/bin (or ~/.local/bin if not root)
#   3. Optionally prints locked tool installation instructions (--with-tools)
#   4. Prints MCP configuration snippet

VERSION="${REDHANDS_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
WITH_TOOLS=false
PROFILE="minimal"
REPO="yasindce1998/redhands"
TEMP_DIR=$(mktemp -d)
trap 'rm -f "$TEMP_DIR/redhands.tar.gz" "$TEMP_DIR/redhands" "$TEMP_DIR/SHA256SUMS"; rmdir "$TEMP_DIR" 2>/dev/null || true' EXIT
INSTALLED=false

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
            echo "  --with-tools       Print instructions for installing locked tool dependencies"
            echo "  --profile=NAME     Tool profile: minimal, web, network, ad, all (default: minimal)"
            echo "  --dir=PATH         Install directory (default: /usr/local/bin)"
            echo ""
            echo "Examples:"
            echo "  curl -fsSL .../install.sh | bash"
            echo "  curl -fsSL .../install.sh | bash -s -- --with-tools --profile=web"
            exit 0
            ;;
        *) log_error "Unknown option: $arg"; exit 1 ;;
    esac
done

# Use ~/.local/bin if not root
if [[ "$EUID" -ne 0 ]] && [[ "$INSTALL_DIR" == "/usr/local/bin" ]]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi
mkdir -p "$INSTALL_DIR"

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
            GOBIN="$TEMP_DIR" go install "github.com/${REPO}/cmd/redhands@latest"
            install -m 755 "$TEMP_DIR/redhands" "$INSTALL_DIR/redhands"
            log_ok "RedHands installed to $INSTALL_DIR/redhands (built from source)"
            INSTALLED=true
        else
            log_error "Go not found. Install Go 1.26.11+ (or 1.27.4+) or download a release binary manually."
            exit 1
        fi
    fi
fi

if [[ -n "$VERSION" ]] && ! $INSTALLED; then
    VERSION="${VERSION#v}"
    [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][a-zA-Z0-9.-]+)?$ ]] || { log_error "Invalid release version"; exit 1; }
    ASSET="redhands_${VERSION}_${OS}_${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/redhands_${VERSION}_${OS}_${ARCH}.tar.gz"
    log_info "Downloading RedHands v${VERSION}..."

    if curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_DIR/redhands.tar.gz" 2>/dev/null; then
        curl -fsSL "https://github.com/${REPO}/releases/download/v${VERSION}/SHA256SUMS" -o "$TEMP_DIR/SHA256SUMS"
        EXPECTED=$(awk -v asset="$ASSET" '$2 == asset {print $1}' "$TEMP_DIR/SHA256SUMS")
        [[ "$EXPECTED" =~ ^[a-fA-F0-9]{64}$ ]] || { log_error "No valid release checksum for $ASSET"; exit 1; }
        if command -v sha256sum &>/dev/null; then
            ACTUAL=$(sha256sum "$TEMP_DIR/redhands.tar.gz" | awk '{print $1}')
        else
            ACTUAL=$(shasum -a 256 "$TEMP_DIR/redhands.tar.gz" | awk '{print $1}')
        fi
        [[ "$ACTUAL" == "$EXPECTED" ]] || { log_error "Release checksum mismatch"; exit 1; }
        # Read only the expected executable; never extract arbitrary archive paths.
        tar -xOzf "$TEMP_DIR/redhands.tar.gz" redhands > "$TEMP_DIR/redhands"
        install -m 755 "$TEMP_DIR/redhands" "$INSTALL_DIR/redhands"
        chmod +x "$INSTALL_DIR/redhands"
        log_ok "RedHands v${VERSION} installed to $INSTALL_DIR/redhands"
    else
        log_warn "Release binary not available. Building from source..."
        if command -v go &>/dev/null; then
            GOBIN="$TEMP_DIR" go install "github.com/${REPO}/cmd/redhands@v${VERSION}"
            install -m 755 "$TEMP_DIR/redhands" "$INSTALL_DIR/redhands"
            log_ok "RedHands installed to $INSTALL_DIR/redhands (built from source)"
        else
            log_error "Neither release binary nor Go compiler available."
            log_error "Install Go 1.26.11+ (or 1.27.4+) from https://go.dev/dl/ and retry."
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

# Print tool dependency instructions if requested
if $WITH_TOOLS; then
    echo ""
    log_info "Tool dependency installation instructions (profile: $PROFILE)..."
    log_warn "Tool installation now requires a reviewed checkout with its dependency lock; no downloaded root script will be executed."
    echo "  git clone https://github.com/${REPO}.git && cd redhands"
    echo "  sudo ./scripts/install-tools.sh --profile $PROFILE"
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
