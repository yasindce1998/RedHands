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
TOOL_INSTALL_HINT[subfinder]="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
TOOL_CATEGORY[amass]="recon"
TOOL_INSTALL_HINT[amass]="apt: amass | brew: amass | go install github.com/owasp-amass/amass/v4/...@master"
TOOL_CATEGORY[dig]="recon"
TOOL_INSTALL_HINT[dig]="apt: dnsutils | brew: bind | dnf: bind-utils"
TOOL_CATEGORY[waybackurls]="recon"
TOOL_INSTALL_HINT[waybackurls]="go install github.com/tomnomnom/waybackurls@latest"
TOOL_CATEGORY[gau]="recon"
TOOL_INSTALL_HINT[gau]="go install github.com/lc/gau/v2/cmd/gau@latest"
TOOL_CATEGORY[arjun]="recon"
TOOL_INSTALL_HINT[arjun]="pip install arjun"

# Web
TOOL_CATEGORY[httpx]="web"
TOOL_INSTALL_HINT[httpx]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
TOOL_CATEGORY[katana]="web"
TOOL_INSTALL_HINT[katana]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
TOOL_CATEGORY[nikto]="web"
TOOL_INSTALL_HINT[nikto]="git clone https://github.com/sullo/nikto /opt/nikto && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto"
TOOL_CATEGORY[whatweb]="web"
TOOL_INSTALL_HINT[whatweb]="apt: whatweb | brew: whatweb"
TOOL_CATEGORY[testssl.sh]="web"
TOOL_INSTALL_HINT[testssl.sh]="git clone https://github.com/drwetter/testssl.sh /opt/testssl && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh"

# Fuzz
TOOL_CATEGORY[ffuf]="fuzz"
TOOL_INSTALL_HINT[ffuf]="go install github.com/ffuf/ffuf/v2@latest"
TOOL_CATEGORY[gobuster]="fuzz"
TOOL_INSTALL_HINT[gobuster]="go install github.com/OJ/gobuster/v3@latest"
TOOL_CATEGORY[feroxbuster]="fuzz"
TOOL_INSTALL_HINT[feroxbuster]="curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash"

# Scan
TOOL_CATEGORY[masscan]="scan"
TOOL_INSTALL_HINT[masscan]="apt: masscan | brew: masscan"
TOOL_CATEGORY[rustscan]="scan"
TOOL_INSTALL_HINT[rustscan]="cargo install rustscan | brew: rustscan"

# Vuln
TOOL_CATEGORY[nuclei]="vuln"
TOOL_INSTALL_HINT[nuclei]="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

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
TOOL_INSTALL_HINT[crackmapexec]="pip install crackmapexec"
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

# Sort tools by category for display
for tool in $(echo "${!TOOL_CATEGORY[@]}" | tr ' ' '\n' | sort); do
    cat="${TOOL_CATEGORY[$tool]}"
    if [[ "$cat" != "$current_category" ]]; then
        if [[ -n "$current_category" ]]; then echo ""; fi
        echo -e "  ${CYAN}[$cat]${NC}"
        current_category="$cat"
    fi

    total=$((total + 1))
    if command -v "$tool" &>/dev/null; then
        path=$(command -v "$tool")
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
