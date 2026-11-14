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
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPENDENCIES="$SCRIPT_DIR/dependencies.py"

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
  k8s        Kubernetes (nmap, kubedagger-client, kubedagger-operator, kubedagger-server)
  uefi       UEFI bootkit simulation (barzakh-adversary, barzakh-scanner, barzakh-server)
  telecom    Telecom research (staticzero-defense, staticzero-offense, modem-firmware, sdr-bridge)
  aegis      Linux eBPF research (aegis-shadow-defense, aegis-shadow-offense, aegis-c2)
  sbom       SBOM generation and vulnerability scanning (syft, grype)
  recon      Reconnaissance only (subfinder, amass, dns, wayback, gau, arjun)
  minimal    Just the essentials (nmap, nuclei, httpx, subfinder)

Note: Sliver and Metasploit are not installed by any profile; install sliver-client
and metasploit-framework (msfconsole/msfvenom) manually from a
trusted release if you need the sliver toolset.

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
# Sliver (sliver-client) is deliberately not installed by any profile; install it
# manually from a trusted release if the sliver toolset is needed.
TOOLS_TUNNEL="chisel ligolo-proxy"
TOOLS_CRACK="hashcat john"
TOOLS_CME="crackmapexec"
TOOLS_CERTIPY="certipy"
TOOLS_TSHARK="tshark"
TOOLS_KUBEDAGGER="kubedagger-client kubedagger-operator kubedagger-server"
TOOLS_BARZAKH="barzakh-adversary barzakh-scanner barzakh-server"
TOOLS_TELECOM="staticzero-defense staticzero-offense modem-firmware sdr-bridge"
TOOLS_AEGIS="aegis-shadow-defense aegis-shadow-offense aegis-c2"
TOOLS_SBOM="syft grype"

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
        telecom)
            echo "$TOOLS_TELECOM"
            ;;
        aegis)
            echo "$TOOLS_AEGIS"
            ;;
        sbom)
            echo "$TOOLS_SBOM"
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
    echo -e "  ${GREEN}all${NC}        Full pentest toolkit (all registered tools)"
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
    echo "             nmap, kubedagger-client, kubedagger-operator, kubedagger-server"
    echo ""
    echo -e "  ${GREEN}uefi${NC}       UEFI bootkit adversary simulation"
    echo "             barzakh-adversary, barzakh-scanner, barzakh-server"
    echo ""
    echo -e "  ${GREEN}telecom${NC}    Telecom security research (eBPF, Linux only)"
    echo "             staticzero-defense, staticzero-offense,"
    echo "             modem-firmware, sdr-bridge"
    echo ""
    echo -e "  ${GREEN}aegis${NC}      Linux eBPF security research"
    echo "             aegis-shadow-defense, aegis-shadow-offense, aegis-c2"
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
    command -v "$1" &>/dev/null || { [[ "$1" == impacket-* ]] && command -v "${1#impacket-}.py" &>/dev/null; }
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
            printf "  %-25s ${GREEN}installed${NC} (%s)\n" "$tool" "$(command -v "$tool" || command -v "${tool#impacket-}.py")"
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
if [[ ! -f "$DEPENDENCIES" || ! -f "$SCRIPT_DIR/dependencies.json" ]]; then
    log_error "Run this installer from a complete checkout containing dependencies.py and dependencies.json."
    exit 1
fi

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
        brew install "${pkgs[@]}"
    fi
}

# ─── Python Tools ──────────────────────────────────────────────────────────────

install_python_tools() {
    local pip_pkgs=()

    if [[ "$TOOLS" == *"impacket"* ]]; then
        pip_pkgs+=("$(python3 "$DEPENDENCIES" python impacket)")
    fi
    if [[ "$TOOLS" == *"certipy"* ]]; then
        pip_pkgs+=("$(python3 "$DEPENDENCIES" python certipy)")
    fi
    if [[ "$TOOLS" == *"crackmapexec"* ]]; then
        log_warn "crackmapexec is no longer available from PyPI; install a reviewed compatible version manually."
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

    log_step "Installing the verified Go toolchain from the dependency manifest..."
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    local os_name
    os_name=$(uname -s | tr '[:upper:]' '[:lower:]')

    local tmp
    tmp=$(mktemp -d)
    python3 "$DEPENDENCIES" fetch go --platform "${os_name}-${arch}" --output "$tmp/go.tar.gz"
    if [[ -e /usr/local/go ]]; then
        log_error "Refusing to overwrite /usr/local/go; repair PATH or install Go manually."
        return 1
    fi
    tar -C /usr/local -xzf "$tmp/go.tar.gz"
    rm -f "$tmp/go.tar.gz"
    rmdir "$tmp"
    export PATH="/usr/local/go/bin:$PATH"
    log_ok "Verified Go toolchain installed"
}

install_go_tools() {
    local go_tools=()

    local name
    for name in subfinder httpx nuclei ffuf katana gobuster gau waybackurls; do
        [[ "$TOOLS" == *"$name"* ]] && go_tools+=("$(python3 "$DEPENDENCIES" go "$name")")
    done

    if [[ ${#go_tools[@]} -gt 0 ]]; then
        ensure_go
        export GOPATH="${GOPATH:-/tmp/redhands-go}"
        export GOBIN="/usr/local/bin"

        local tool
        for tool in "${go_tools[@]}"; do
            name=$(basename "${tool%%@*}")
            [[ "$name" == "v2" ]] && name=ffuf
            [[ "$name" == "v3" ]] && name=gobuster
            if check_tool "$name"; then
                log_ok "$name already installed"
            else
                log_step "Installing $name..."
                go install "$tool"
                log_ok "$name installed"
            fi
        done
    fi
}

# ─── Binary Releases ──────────────────────────────────────────────────────────

install_binary_releases() {
    local tool
    for tool in chisel ligolo-proxy kubedagger-client kubedagger-operator kubedagger-server barzakh-adversary barzakh-scanner barzakh-server staticzero-defense staticzero-offense modem-firmware sdr-bridge aegis-shadow-defense feroxbuster; do
        if [[ "$TOOLS" == *"$tool"* ]] && ! check_tool "$tool"; then
            log_step "Installing checksum-verified $tool..."
            python3 "$DEPENDENCIES" install "$tool" --output /usr/local/bin
        fi
    done
    if [[ "$TOOLS" == *"nikto"* ]] && ! check_tool nikto; then
        if [[ -e /opt/nikto ]]; then
            log_warn "Existing /opt/nikto left untouched; configure its executable manually."
        else
            git init /opt/nikto
            git -C /opt/nikto remote add origin https://github.com/sullo/nikto.git
            git -C /opt/nikto fetch --depth 1 origin "$(python3 "$DEPENDENCIES" source nikto)"
            git -C /opt/nikto checkout --detach FETCH_HEAD
            ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
        fi
    fi
    if [[ "$TOOLS" == *"arjun"* ]] && ! check_tool arjun; then
        python3 -m pip install --break-system-packages "$(python3 "$DEPENDENCIES" python arjun)" || \
        python3 -m pip install "$(python3 "$DEPENDENCIES" python arjun)"
    fi
    for tool in rustscan testssl.sh; do
        if [[ "$TOOLS" == *"$tool"* ]] && ! check_tool "$tool"; then
            log_warn "$tool has no reviewed locked artifact yet; install it manually from a trusted package manager."
        fi
    done
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
python3 "$DEPENDENCIES" validate
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
