#!/usr/bin/env bash
set -euo pipefail

# RedHands Tool Installer
# Installs security tool dependencies for non-Docker usage.
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch Linux, macOS (Homebrew)
#
# Usage:
#   ./install-tools.sh                  # Install all tools
#   ./install-tools.sh --profile web    # Install only web assessment tools
#   ./install-tools.sh --profile ad     # Install AD/internal assessment tools
#   ./install-tools.sh --list           # List available profiles
#   ./install-tools.sh --check          # Check what's already installed

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

PROFILE="all"
CHECK_ONLY=false
LIST_PROFILES=false
SKIP_CONFIRM=false
GO_VERSION="1.26.0"

usage() {
    cat <<EOF
${CYAN}RedHands Tool Installer${NC}

Usage: $0 [OPTIONS]

Options:
  --profile <name>   Install tools for a specific profile (default: all)
  --list             List available profiles and their tools
  --check            Check which tools are installed (no installation)
  --yes              Skip confirmation prompts
  --help             Show this help message

Profiles:
  all        All tools (full pentest toolkit)
  web        Web application assessment (nmap, recon, web, fuzz, vuln)
  network    Network assessment (nmap, scan, tshark, tunnel)
  ad         Active Directory (nmap, impacket, crackmapexec, certipy, crack)
  k8s        Kubernetes (nmap, kubedagger-client, kubedagger-operator)
  uefi       UEFI bootkit simulation (barzakh-adversary, barzakh-scanner)
  recon      Reconnaissance only (subfinder, amass, dns, wayback, gau, arjun)
  minimal    Just the essentials (nmap, nuclei, httpx, subfinder)

Examples:
  $0                          # Full install
  $0 --profile web --yes      # Web tools, no prompts
  $0 --check                  # See what's missing
EOF
}

log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "${CYAN}[→]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile) PROFILE="$2"; shift 2 ;;
        --list) LIST_PROFILES=true; shift ;;
        --check) CHECK_ONLY=true; shift ;;
        --yes|-y) SKIP_CONFIRM=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) log_error "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# Tool definitions by category
TOOLS_NMAP="nmap"
TOOLS_RECON="subfinder amass dig waybackurls gau arjun"
TOOLS_WEB="httpx katana nikto whatweb testssl.sh"
TOOLS_FUZZ="ffuf gobuster feroxbuster"
TOOLS_SCAN="masscan rustscan"
TOOLS_VULN="nuclei"
TOOLS_EXPLOIT="sqlmap"
TOOLS_IMPACKET="impacket-secretsdump impacket-psexec impacket-wmiexec impacket-smbclient impacket-dcomexec impacket-getTGT impacket-getST impacket-ntlmrelayx"
TOOLS_SLIVER="sliver-client"
TOOLS_TUNNEL="chisel ligolo-proxy"
TOOLS_CRACK="hashcat john"
TOOLS_CME="crackmapexec"
TOOLS_CERTIPY="certipy"
TOOLS_TSHARK="tshark"
TOOLS_KUBEDAGGER="kubedagger-client kubedagger-operator"
TOOLS_BARZAKH="barzakh-adversary barzakh-scanner"

get_profile_tools() {
    case "$1" in
        all)
            echo "$TOOLS_NMAP $TOOLS_RECON $TOOLS_WEB $TOOLS_FUZZ $TOOLS_SCAN $TOOLS_VULN $TOOLS_EXPLOIT $TOOLS_IMPACKET $TOOLS_TUNNEL $TOOLS_CRACK $TOOLS_CME $TOOLS_CERTIPY $TOOLS_TSHARK $TOOLS_KUBEDAGGER $TOOLS_BARZAKH"
            ;;
        web)
            echo "$TOOLS_NMAP $TOOLS_RECON $TOOLS_WEB $TOOLS_FUZZ $TOOLS_SCAN $TOOLS_VULN $TOOLS_EXPLOIT"
            ;;
        network)
            echo "$TOOLS_NMAP $TOOLS_SCAN $TOOLS_TSHARK $TOOLS_TUNNEL"
            ;;
        ad)
            echo "$TOOLS_NMAP $TOOLS_IMPACKET $TOOLS_CME $TOOLS_CERTIPY $TOOLS_CRACK"
            ;;
        recon)
            echo "$TOOLS_RECON $TOOLS_WEB"
            ;;
        k8s)
            echo "$TOOLS_NMAP $TOOLS_KUBEDAGGER"
            ;;
        uefi)
            echo "$TOOLS_BARZAKH"
            ;;
        minimal)
            echo "nmap nuclei httpx subfinder"
            ;;
        *)
            log_error "Unknown profile: $1"
            exit 1
            ;;
    esac
}

list_profiles() {
    echo -e "${CYAN}Available Profiles${NC}"
    echo ""
    echo -e "  ${GREEN}all${NC}        Full pentest toolkit (all 125+ tools)"
    echo "             nmap, recon, web, fuzz, scan, vuln, exploit, impacket,"
    echo "             tunnel, crack, crackmapexec, certipy, tshark"
    echo ""
    echo -e "  ${GREEN}web${NC}        Web application assessment"
    echo "             nmap, subfinder, amass, httpx, katana, nikto, ffuf,"
    echo "             gobuster, feroxbuster, nuclei, sqlmap, masscan"
    echo ""
    echo -e "  ${GREEN}network${NC}    Network assessment & tunneling"
    echo "             nmap, masscan, rustscan, tshark, chisel, ligolo-ng"
    echo ""
    echo -e "  ${GREEN}ad${NC}         Active Directory attacks"
    echo "             nmap, impacket suite, crackmapexec, certipy, hashcat, john"
    echo ""
    echo -e "  ${GREEN}k8s${NC}        Kubernetes offensive (eBPF-powered)"
    echo "             nmap, kubedagger-client, kubedagger-operator"
    echo ""
    echo -e "  ${GREEN}uefi${NC}       UEFI bootkit adversary simulation"
    echo "             barzakh-adversary, barzakh-scanner"
    echo ""
    echo -e "  ${GREEN}recon${NC}      Reconnaissance"
    echo "             subfinder, amass, dig, waybackurls, gau, arjun, httpx,"
    echo "             katana, whatweb"
    echo ""
    echo -e "  ${GREEN}minimal${NC}    Just the essentials"
    echo "             nmap, nuclei, httpx, subfinder"
    echo ""
    echo "Usage: $0 --profile <name>"
}

if $LIST_PROFILES; then
    list_profiles
    exit 0
fi

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/fedora-release ]]; then
        echo "fedora"
    elif [[ -f /etc/arch-release ]]; then
        echo "arch"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

check_root() {
    if [[ "$EUID" -ne 0 ]] && [[ "$(detect_os)" != "macos" ]]; then
        log_error "This script requires root privileges on Linux. Run with sudo."
        exit 1
    fi
}

check_tool() {
    command -v "$1" &>/dev/null
}

check_all_tools() {
    local tools
    tools=$(get_profile_tools "$PROFILE")
    local installed=0
    local missing=0
    local total=0

    echo -e "${CYAN}Tool Status (profile: ${PROFILE})${NC}"
    echo ""
    printf "  %-25s %s\n" "TOOL" "STATUS"
    printf "  %-25s %s\n" "----" "------"

    for tool in $tools; do
        total=$((total + 1))
        if check_tool "$tool"; then
            printf "  %-25s ${GREEN}installed${NC} (%s)\n" "$tool" "$(command -v "$tool")"
            installed=$((installed + 1))
        else
            printf "  %-25s ${RED}missing${NC}\n" "$tool"
            missing=$((missing + 1))
        fi
    done

    echo ""
    echo -e "  ${GREEN}Installed:${NC} $installed/$total"
    if [[ $missing -gt 0 ]]; then
        echo -e "  ${RED}Missing:${NC}   $missing/$total"
        echo ""
        echo "  Run '$0 --profile $PROFILE' to install missing tools."
    else
        echo -e "  ${GREEN}All tools available!${NC}"
    fi
}

if $CHECK_ONLY; then
    check_all_tools
    exit 0
fi

OS=$(detect_os)
log_info "Detected OS: $OS"
log_info "Profile: $PROFILE"

if [[ "$OS" == "unknown" ]]; then
    log_error "Unsupported OS. Supported: Debian/Ubuntu, Fedora/RHEL, Arch, macOS"
    exit 1
fi

TOOLS=$(get_profile_tools "$PROFILE")
TOOL_COUNT=$(echo "$TOOLS" | wc -w | tr -d ' ')
log_info "Tools to install: $TOOL_COUNT"

if ! $SKIP_CONFIRM; then
    echo ""
    echo -e "The following tools will be installed for profile '${GREEN}${PROFILE}${NC}':"
    echo "  $TOOLS" | fold -s -w 70 | sed 's/^/  /'
    echo ""
    read -rp "Continue? [Y/n] " response
    if [[ "$response" =~ ^[Nn] ]]; then
        log_info "Aborted."
        exit 0
    fi
fi

check_root

# ─── Package Manager Install ───────────────────────────────────────────────────

install_apt_packages() {
    log_step "Updating apt cache..."
    apt-get update -qq

    local pkgs=()
    [[ "$TOOLS" == *"nmap"* ]] && pkgs+=(nmap)
    [[ "$TOOLS" == *"masscan"* ]] && pkgs+=(masscan)
    [[ "$TOOLS" == *"tshark"* ]] && pkgs+=(tshark)
    [[ "$TOOLS" == *"hashcat"* ]] && pkgs+=(hashcat)
    [[ "$TOOLS" == *"john"* ]] && pkgs+=(john)
    [[ "$TOOLS" == *"whatweb"* ]] && pkgs+=(whatweb)
    [[ "$TOOLS" == *"sqlmap"* ]] && pkgs+=(sqlmap)
    [[ "$TOOLS" == *"dig"* ]] && pkgs+=(dnsutils)
    [[ "$TOOLS" == *"amass"* ]] && pkgs+=(amass)

    # Dependencies for building/running tools
    pkgs+=(python3 python3-pip python3-venv git wget curl unzip ca-certificates)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        log_step "Installing apt packages: ${pkgs[*]}"
        apt-get install -y --no-install-recommends "${pkgs[@]}"
    fi
}

install_dnf_packages() {
    local pkgs=()
    [[ "$TOOLS" == *"nmap"* ]] && pkgs+=(nmap)
    [[ "$TOOLS" == *"masscan"* ]] && pkgs+=(masscan)
    [[ "$TOOLS" == *"tshark"* ]] && pkgs+=(wireshark-cli)
    [[ "$TOOLS" == *"hashcat"* ]] && pkgs+=(hashcat)
    [[ "$TOOLS" == *"john"* ]] && pkgs+=(john)
    [[ "$TOOLS" == *"sqlmap"* ]] && pkgs+=(sqlmap)
    [[ "$TOOLS" == *"dig"* ]] && pkgs+=(bind-utils)

    pkgs+=(python3 python3-pip git wget curl unzip ca-certificates)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        log_step "Installing dnf packages: ${pkgs[*]}"
        dnf install -y "${pkgs[@]}"
    fi
}

install_pacman_packages() {
    local pkgs=()
    [[ "$TOOLS" == *"nmap"* ]] && pkgs+=(nmap)
    [[ "$TOOLS" == *"masscan"* ]] && pkgs+=(masscan)
    [[ "$TOOLS" == *"tshark"* ]] && pkgs+=(wireshark-cli)
    [[ "$TOOLS" == *"hashcat"* ]] && pkgs+=(hashcat)
    [[ "$TOOLS" == *"john"* ]] && pkgs+=(john)
    [[ "$TOOLS" == *"sqlmap"* ]] && pkgs+=(sqlmap)
    [[ "$TOOLS" == *"whatweb"* ]] && pkgs+=(whatweb)
    [[ "$TOOLS" == *"dig"* ]] && pkgs+=(bind)
    [[ "$TOOLS" == *"amass"* ]] && pkgs+=(amass)

    pkgs+=(python python-pip git wget curl unzip ca-certificates)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        log_step "Installing pacman packages: ${pkgs[*]}"
        pacman -Sy --noconfirm "${pkgs[@]}"
    fi
}

install_brew_packages() {
    if ! check_tool brew; then
        log_error "Homebrew not found. Install from https://brew.sh"
        exit 1
    fi

    local pkgs=()
    [[ "$TOOLS" == *"nmap"* ]] && pkgs+=(nmap)
    [[ "$TOOLS" == *"masscan"* ]] && pkgs+=(masscan)
    [[ "$TOOLS" == *"tshark"* ]] && pkgs+=(wireshark)
    [[ "$TOOLS" == *"hashcat"* ]] && pkgs+=(hashcat)
    [[ "$TOOLS" == *"john"* ]] && pkgs+=(john)
    [[ "$TOOLS" == *"sqlmap"* ]] && pkgs+=(sqlmap)
    [[ "$TOOLS" == *"dig"* ]] && pkgs+=(bind)
    [[ "$TOOLS" == *"amass"* ]] && pkgs+=(amass)

    pkgs+=(python3 git wget curl)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        log_step "Installing brew packages: ${pkgs[*]}"
        brew install "${pkgs[@]}" 2>/dev/null || true
    fi
}

# ─── Python Tools ──────────────────────────────────────────────────────────────

install_python_tools() {
    local pip_pkgs=()

    if [[ "$TOOLS" == *"impacket"* ]]; then
        pip_pkgs+=(impacket)
    fi
    if [[ "$TOOLS" == *"certipy"* ]]; then
        pip_pkgs+=(certipy-ad)
    fi
    if [[ "$TOOLS" == *"crackmapexec"* ]]; then
        pip_pkgs+=(crackmapexec)
    fi

    if [[ ${#pip_pkgs[@]} -gt 0 ]]; then
        log_step "Installing Python tools: ${pip_pkgs[*]}"
        python3 -m pip install --break-system-packages "${pip_pkgs[@]}" 2>/dev/null || \
        python3 -m pip install "${pip_pkgs[@]}"
    fi
}

# ─── Go Tools ──────────────────────────────────────────────────────────────────

ensure_go() {
    if check_tool go; then
        log_ok "Go already installed: $(go version)"
        return
    fi

    log_step "Installing Go $GO_VERSION..."
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    local os_name
    os_name=$(uname -s | tr '[:upper:]' '[:lower:]')

    wget -q "https://go.dev/dl/go${GO_VERSION}.${os_name}-${arch}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    log_ok "Go $GO_VERSION installed"
}

install_go_tools() {
    local go_tools=()

    [[ "$TOOLS" == *"subfinder"* ]] && go_tools+=("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    [[ "$TOOLS" == *"httpx"* ]] && go_tools+=("github.com/projectdiscovery/httpx/cmd/httpx@latest")
    [[ "$TOOLS" == *"nuclei"* ]] && go_tools+=("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    [[ "$TOOLS" == *"ffuf"* ]] && go_tools+=("github.com/ffuf/ffuf/v2@latest")
    [[ "$TOOLS" == *"katana"* ]] && go_tools+=("github.com/projectdiscovery/katana/cmd/katana@latest")
    [[ "$TOOLS" == *"gobuster"* ]] && go_tools+=("github.com/OJ/gobuster/v3@latest")
    [[ "$TOOLS" == *"gau"* ]] && go_tools+=("github.com/lc/gau/v2/cmd/gau@latest")

    if [[ ${#go_tools[@]} -gt 0 ]]; then
        ensure_go
        export GOPATH="${GOPATH:-/tmp/redhands-go}"
        export GOBIN="/usr/local/bin"

        for tool in "${go_tools[@]}"; do
            local name
            name=$(basename "${tool%%@*}")
            if check_tool "$name"; then
                log_ok "$name already installed"
            else
                log_step "Installing $name..."
                go install "$tool" 2>/dev/null && log_ok "$name installed" || log_warn "Failed to install $name"
            fi
        done
    fi
}

# ─── Binary Releases ──────────────────────────────────────────────────────────

install_binary_releases() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
    esac

    local os_name
    os_name=$(uname -s | tr '[:upper:]' '[:lower:]')

    # Chisel
    if [[ "$TOOLS" == *"chisel"* ]] && ! check_tool chisel; then
        log_step "Installing chisel..."
        local chisel_ver="1.11.5"
        curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${chisel_ver}/chisel_${chisel_ver}_${os_name}_${arch}.gz" -o /tmp/chisel.gz && \
            gunzip -f /tmp/chisel.gz && chmod +x /tmp/chisel && mv /tmp/chisel /usr/local/bin/chisel && \
            log_ok "chisel $chisel_ver installed" || log_warn "Failed to install chisel"
    fi

    # Ligolo-ng
    if [[ "$TOOLS" == *"ligolo-proxy"* ]] && ! check_tool ligolo-proxy; then
        log_step "Installing ligolo-ng..."
        local ligolo_ver="0.8.3"
        curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${ligolo_ver}/ligolo-ng_proxy_${ligolo_ver}_${os_name}_${arch}.tar.gz" -o /tmp/ligolo.tar.gz && \
            tar -xzf /tmp/ligolo.tar.gz -C /tmp && mv /tmp/proxy /usr/local/bin/ligolo-proxy && \
            rm -f /tmp/ligolo.tar.gz && \
            log_ok "ligolo-ng $ligolo_ver installed" || log_warn "Failed to install ligolo-ng"
    fi

    # KubeDagger
    if [[ "$TOOLS" == *"kubedagger-client"* ]] && ! check_tool kubedagger-client; then
        log_step "Installing kubedagger-client..."
        curl -fsSL "https://github.com/yasindce1998/KubeDagger/releases/download/v0.1.0/kubedagger-client-${os_name}-${arch}" \
            -o /usr/local/bin/kubedagger-client && chmod +x /usr/local/bin/kubedagger-client && \
            log_ok "kubedagger-client installed" || log_warn "Failed to install kubedagger-client"
    fi

    if [[ "$TOOLS" == *"kubedagger-operator"* ]] && ! check_tool kubedagger-operator; then
        log_step "Installing kubedagger-operator..."
        curl -fsSL "https://github.com/yasindce1998/KubeDagger/releases/download/v0.1.0/kubedagger-operator-${os_name}-${arch}" \
            -o /usr/local/bin/kubedagger-operator && chmod +x /usr/local/bin/kubedagger-operator && \
            log_ok "kubedagger-operator installed" || log_warn "Failed to install kubedagger-operator"
    fi

    # Barzakh
    if [[ "$TOOLS" == *"barzakh-adversary"* ]] && ! check_tool barzakh-adversary; then
        log_step "Installing barzakh-adversary..."
        local barzakh_os="linux"
        local barzakh_arch="x86_64"
        [[ "$OS" == "macos" ]] && barzakh_os="macos"
        [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]] && barzakh_arch="aarch64"
        curl -fsSL "https://github.com/yasindce1998/Barzakh/releases/download/v0.1.1/barzakh-adversary-${barzakh_os}-${barzakh_arch}" \
            -o /usr/local/bin/barzakh-adversary && chmod +x /usr/local/bin/barzakh-adversary && \
            log_ok "barzakh-adversary installed" || log_warn "Failed to install barzakh-adversary"
    fi

    if [[ "$TOOLS" == *"barzakh-scanner"* ]] && ! check_tool barzakh-scanner; then
        log_step "Installing barzakh-scanner..."
        local barzakh_os="linux"
        local barzakh_arch="x86_64"
        [[ "$OS" == "macos" ]] && barzakh_os="macos"
        [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]] && barzakh_arch="aarch64"
        curl -fsSL "https://github.com/yasindce1998/Barzakh/releases/download/v0.1.1/barzakh-scanner-${barzakh_os}-${barzakh_arch}" \
            -o /usr/local/bin/barzakh-scanner && chmod +x /usr/local/bin/barzakh-scanner && \
            log_ok "barzakh-scanner installed" || log_warn "Failed to install barzakh-scanner"
    fi

    # RustScan
    if [[ "$TOOLS" == *"rustscan"* ]] && ! check_tool rustscan; then
        log_step "Installing rustscan..."
        if [[ "$OS" == "debian" ]]; then
            curl -fsSL "https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.3.0_amd64.deb" -o /tmp/rustscan.deb && \
                dpkg -i /tmp/rustscan.deb && rm /tmp/rustscan.deb && \
                log_ok "rustscan installed" || log_warn "Failed to install rustscan (try: cargo install rustscan)"
        elif [[ "$OS" == "macos" ]]; then
            brew install rustscan 2>/dev/null && log_ok "rustscan installed" || log_warn "Failed to install rustscan"
        else
            log_warn "rustscan: install manually or via cargo install rustscan"
        fi
    fi

    # Feroxbuster
    if [[ "$TOOLS" == *"feroxbuster"* ]] && ! check_tool feroxbuster; then
        log_step "Installing feroxbuster..."
        if [[ "$OS" == "macos" ]]; then
            brew install feroxbuster 2>/dev/null && log_ok "feroxbuster installed" || log_warn "Failed to install feroxbuster"
        else
            curl -fsSL "https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh" | bash -s /usr/local/bin 2>/dev/null && \
                log_ok "feroxbuster installed" || log_warn "Failed to install feroxbuster"
        fi
    fi

    # Nikto
    if [[ "$TOOLS" == *"nikto"* ]] && ! check_tool nikto; then
        log_step "Installing nikto..."
        if [[ ! -d /opt/nikto ]]; then
            git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto 2>/dev/null
            ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto
            log_ok "nikto installed"
        fi
    fi

    # Arjun
    if [[ "$TOOLS" == *"arjun"* ]] && ! check_tool arjun; then
        log_step "Installing arjun..."
        python3 -m pip install --break-system-packages arjun 2>/dev/null || \
        python3 -m pip install arjun 2>/dev/null
        log_ok "arjun installed"
    fi

    # Waybackurls
    if [[ "$TOOLS" == *"waybackurls"* ]] && ! check_tool waybackurls; then
        log_step "Installing waybackurls..."
        if check_tool go; then
            go install github.com/tomnomnom/waybackurls@latest 2>/dev/null && \
                log_ok "waybackurls installed" || log_warn "Failed to install waybackurls"
        fi
    fi

    # testssl.sh
    if [[ "$TOOLS" == *"testssl.sh"* ]] && ! check_tool testssl.sh; then
        log_step "Installing testssl.sh..."
        if [[ "$OS" == "macos" ]]; then
            brew install testssl 2>/dev/null && log_ok "testssl.sh installed" || true
        else
            git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl 2>/dev/null
            ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
            log_ok "testssl.sh installed"
        fi
    fi
}

# ─── Main Installation Flow ───────────────────────────────────────────────────

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         RedHands Tool Installer                  ║${NC}"
echo -e "${CYAN}║         Profile: $(printf '%-28s' "$PROFILE")   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Step 1: System packages
log_info "Step 1/4: Installing system packages..."
case "$OS" in
    debian) install_apt_packages ;;
    fedora) install_dnf_packages ;;
    rhel) install_dnf_packages ;;
    arch) install_pacman_packages ;;
    macos) install_brew_packages ;;
esac
echo ""

# Step 2: Python tools
log_info "Step 2/4: Installing Python tools..."
install_python_tools
echo ""

# Step 3: Go tools
log_info "Step 3/4: Installing Go tools..."
install_go_tools
echo ""

# Step 4: Binary releases
log_info "Step 4/4: Installing binary releases..."
install_binary_releases
echo ""

# ─── Summary ──────────────────────────────────────────────────────────────────

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║              Installation Complete               ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
check_all_tools
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Build RedHands:  make build"
echo "  2. Run health check: ./bin/redhands  (then call redhands_health)"
echo "  3. Configure MCP:   Add to your claude_desktop_config.json or .cursor/mcp.json"
echo ""
