#!/usr/bin/env bash
set -euo pipefail

# RedHands Dependency Checker
# Checks which security tools are available and provides install guidance.
# No root required — just reports status.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# Tool categories with install hints
declare -A TOOL_CATEGORY
declare -A TOOL_INSTALL_HINT

# Nmap
TOOL_CATEGORY[nmap]="nmap"
TOOL_INSTALL_HINT[nmap]="apt: nmap | brew: nmap | choco: nmap"

# Recon
TOOL_CATEGORY[subfinder]="recon"
TOOL_INSTALL_HINT[subfinder]="sudo ./scripts/install-tools.sh --profile minimal (locked version)"
TOOL_CATEGORY[amass]="recon"
TOOL_INSTALL_HINT[amass]="apt: amass | brew: amass (review compatibility)"
TOOL_CATEGORY[dig]="recon"
TOOL_INSTALL_HINT[dig]="apt: dnsutils | brew: bind | dnf: bind-utils"
TOOL_CATEGORY[waybackurls]="recon"
TOOL_INSTALL_HINT[waybackurls]="sudo ./scripts/install-tools.sh --profile recon (locked version)"
TOOL_CATEGORY[gau]="recon"
TOOL_INSTALL_HINT[gau]="sudo ./scripts/install-tools.sh --profile recon (locked version)"
TOOL_CATEGORY[arjun]="recon"
TOOL_INSTALL_HINT[arjun]="sudo ./scripts/install-tools.sh --profile recon (locked version)"

# Web
TOOL_CATEGORY[httpx]="web"
TOOL_INSTALL_HINT[httpx]="sudo ./scripts/install-tools.sh --profile minimal (locked version)"
TOOL_CATEGORY[katana]="web"
TOOL_INSTALL_HINT[katana]="sudo ./scripts/install-tools.sh --profile web (locked version)"
TOOL_CATEGORY[nikto]="web"
TOOL_INSTALL_HINT[nikto]="sudo ./scripts/install-tools.sh --profile web (pinned source)"
TOOL_CATEGORY[whatweb]="web"
TOOL_INSTALL_HINT[whatweb]="apt: whatweb | brew: whatweb"
TOOL_CATEGORY[testssl.sh]="web"
TOOL_INSTALL_HINT[testssl.sh]="Install manually from a reviewed package/source release"

# Fuzz
TOOL_CATEGORY[ffuf]="fuzz"
TOOL_INSTALL_HINT[ffuf]="sudo ./scripts/install-tools.sh --profile web (locked version)"
TOOL_CATEGORY[gobuster]="fuzz"
TOOL_INSTALL_HINT[gobuster]="sudo ./scripts/install-tools.sh --profile web (locked version)"
TOOL_CATEGORY[feroxbuster]="fuzz"
TOOL_INSTALL_HINT[feroxbuster]="sudo ./scripts/install-tools.sh --profile web (checksum verified)"

# Scan
TOOL_CATEGORY[masscan]="scan"
TOOL_INSTALL_HINT[masscan]="apt: masscan | brew: masscan"
TOOL_CATEGORY[rustscan]="scan"
TOOL_INSTALL_HINT[rustscan]="cargo install rustscan | brew: rustscan"

# Vuln
TOOL_CATEGORY[nuclei]="vuln"
TOOL_INSTALL_HINT[nuclei]="sudo ./scripts/install-tools.sh --profile minimal (locked version)"

# Exploit
TOOL_CATEGORY[sqlmap]="exploit"
TOOL_INSTALL_HINT[sqlmap]="apt: sqlmap | brew: sqlmap | pip install sqlmap"
TOOL_CATEGORY[impacket-secretsdump]="impacket"
TOOL_INSTALL_HINT[impacket-secretsdump]="pip install impacket"
TOOL_CATEGORY[impacket-psexec]="impacket"
TOOL_INSTALL_HINT[impacket-psexec]="pip install impacket"
TOOL_CATEGORY[impacket-wmiexec]="impacket"
TOOL_INSTALL_HINT[impacket-wmiexec]="pip install impacket"
TOOL_CATEGORY[impacket-smbclient]="impacket"
TOOL_INSTALL_HINT[impacket-smbclient]="pip install impacket"
TOOL_CATEGORY[impacket-dcomexec]="impacket"
TOOL_INSTALL_HINT[impacket-dcomexec]="pip install impacket"
TOOL_CATEGORY[impacket-getTGT]="impacket"
TOOL_INSTALL_HINT[impacket-getTGT]="pip install impacket"
TOOL_CATEGORY[impacket-getST]="impacket"
TOOL_INSTALL_HINT[impacket-getST]="pip install impacket"
TOOL_CATEGORY[impacket-ntlmrelayx]="impacket"
TOOL_INSTALL_HINT[impacket-ntlmrelayx]="pip install impacket"

# C2
TOOL_CATEGORY[sliver-client]="sliver"
TOOL_INSTALL_HINT[sliver-client]="https://github.com/BishopFox/sliver/wiki/Getting-Started"

# Tunnel
TOOL_CATEGORY[chisel]="tunnel"
TOOL_INSTALL_HINT[chisel]="https://github.com/jpillora/chisel/releases"
TOOL_CATEGORY[ligolo-proxy]="tunnel"
TOOL_INSTALL_HINT[ligolo-proxy]="https://github.com/nicocha30/ligolo-ng/releases"

# Crack
TOOL_CATEGORY[hashcat]="crack"
TOOL_INSTALL_HINT[hashcat]="apt: hashcat | brew: hashcat | choco: hashcat"
TOOL_CATEGORY[john]="crack"
TOOL_INSTALL_HINT[john]="apt: john | brew: john | choco: john"

# CME / Certipy
TOOL_CATEGORY[crackmapexec]="crackmapexec"
TOOL_INSTALL_HINT[crackmapexec]="Unavailable on PyPI; install a reviewed compatible version manually"
TOOL_CATEGORY[certipy]="certipy"
TOOL_INSTALL_HINT[certipy]="pip install certipy-ad"

# tshark
TOOL_CATEGORY[tshark]="tshark"
TOOL_INSTALL_HINT[tshark]="apt: tshark | brew: wireshark | choco: wireshark"

# KubeDagger
TOOL_CATEGORY[kubedagger-client]="kubedagger"
TOOL_INSTALL_HINT[kubedagger-client]="https://github.com/yasindce1998/KubeDagger/releases"
TOOL_CATEGORY[kubedagger-operator]="kubedagger"
TOOL_INSTALL_HINT[kubedagger-operator]="https://github.com/yasindce1998/KubeDagger/releases"

# Barzakh
TOOL_CATEGORY[barzakh-adversary]="barzakh"
TOOL_INSTALL_HINT[barzakh-adversary]="https://github.com/yasindce1998/Barzakh/releases"
TOOL_CATEGORY[barzakh-scanner]="barzakh"
TOOL_INSTALL_HINT[barzakh-scanner]="https://github.com/yasindce1998/Barzakh/releases"

# ─── Main ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       RedHands Dependency Check                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

installed=0
missing=0
total=0
missing_tools=()
current_category=""

resolve_tool() {
    if command -v "$1" &>/dev/null; then command -v "$1"; return; fi
    case "$1" in
        impacket-*) command -v "${1#impacket-}.py" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

# Sort tools by category for display
for tool in $(echo "${!TOOL_CATEGORY[@]}" | tr ' ' '\n' | sort); do
    cat="${TOOL_CATEGORY[$tool]}"
    if [[ "$cat" != "$current_category" ]]; then
        if [[ -n "$current_category" ]]; then echo ""; fi
        echo -e "  ${CYAN}[$cat]${NC}"
        current_category="$cat"
    fi

    total=$((total + 1))
    if path=$(resolve_tool "$tool"); then
        printf "    %-25s ${GREEN}%-10s${NC} ${DIM}%s${NC}\n" "$tool" "OK" "$path"
        installed=$((installed + 1))
    else
        printf "    %-25s ${RED}%-10s${NC} ${DIM}%s${NC}\n" "$tool" "MISSING" "${TOOL_INSTALL_HINT[$tool]}"
        missing=$((missing + 1))
        missing_tools+=("$tool")
    fi
done

echo ""
echo -e "  ─────────────────────────────────────────────────"
printf "  ${GREEN}Installed:${NC} %d/%d\n" "$installed" "$total"
if [[ $missing -gt 0 ]]; then
    printf "  ${RED}Missing:${NC}   %d/%d\n" "$missing" "$total"
fi
echo ""

if [[ $missing -gt 0 ]]; then
    echo -e "${YELLOW}Quick fix:${NC}"
    echo ""

    # Check which categories have missing tools
    declare -A missing_categories
    for tool in "${missing_tools[@]}"; do
        missing_categories[${TOOL_CATEGORY[$tool]}]=1
    done

    # Suggest the best profile
    if [[ ${#missing_categories[@]} -le 3 ]]; then
        echo "  Install missing tools:"
        echo "    sudo ./scripts/install-tools.sh --profile all"
    else
        echo "  Install a specific profile:"
        echo "    sudo ./scripts/install-tools.sh --profile minimal   # nmap, nuclei, httpx, subfinder"
        echo "    sudo ./scripts/install-tools.sh --profile web       # web assessment tools"
        echo "    sudo ./scripts/install-tools.sh --profile ad        # AD attack tools"
        echo "    sudo ./scripts/install-tools.sh --profile all       # everything"
    fi
    echo ""
    echo "  Or install individual tools using the hints shown above."
    echo ""
else
    echo -e "${GREEN}All tools available! RedHands is ready to go.${NC}"
    echo ""
fi

# Show RedHands binary status
echo -e "  ${CYAN}[redhands server]${NC}"
if command -v redhands &>/dev/null; then
    printf "    %-25s ${GREEN}%-10s${NC} ${DIM}%s${NC}\n" "redhands" "OK" "$(command -v redhands)"
elif [[ -f "./bin/redhands" ]]; then
    printf "    %-25s ${GREEN}%-10s${NC} ${DIM}%s${NC}\n" "redhands" "OK" "./bin/redhands (local build)"
else
    printf "    %-25s ${YELLOW}%-10s${NC} ${DIM}%s${NC}\n" "redhands" "NOT BUILT" "Run: make build"
fi
echo ""
