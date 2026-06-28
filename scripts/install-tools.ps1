#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RedHands Tool Installer for Windows
.DESCRIPTION
    Installs security tool dependencies for RedHands MCP server.
    Supports: Chocolatey, Scoop, and direct downloads.
.PARAMETER Profile
    Installation profile: all, web, network, ad, recon, minimal
.PARAMETER Check
    Only check which tools are installed (no installation)
.PARAMETER List
    List available profiles
.PARAMETER PackageManager
    Preferred package manager: auto, choco, scoop
.EXAMPLE
    .\install-tools.ps1
    .\install-tools.ps1 -Profile web
    .\install-tools.ps1 -Check
#>

param(
    [ValidateSet("all", "web", "network", "ad", "recon", "minimal")]
    [string]$Profile = "all",
    [switch]$Check,
    [switch]$List,
    [ValidateSet("auto", "choco", "scoop")]
    [string]$PackageManager = "auto",
    [switch]$Yes
)

$ErrorActionPreference = "Continue"

# ─── Colors and Output ─────────────────────────────────────────────────────────

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Blue }
function Write-Ok { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Step { param($msg) Write-Host "[>] $msg" -ForegroundColor Cyan }

# ─── Profile Definitions ───────────────────────────────────────────────────────

$ToolProfiles = @{
    all     = @("nmap", "masscan", "rustscan", "tshark", "hashcat", "john",
                "subfinder", "httpx", "nuclei", "ffuf", "katana", "gobuster", "gau",
                "nikto", "whatweb", "sqlmap", "testssl.sh", "arjun", "amass",
                "chisel", "ligolo-proxy", "feroxbuster", "waybackurls",
                "impacket-secretsdump", "crackmapexec", "certipy")
    web     = @("nmap", "subfinder", "httpx", "nuclei", "ffuf", "katana", "gobuster",
                "gau", "nikto", "whatweb", "sqlmap", "testssl.sh", "arjun",
                "feroxbuster", "waybackurls", "masscan", "rustscan", "amass")
    network = @("nmap", "masscan", "rustscan", "tshark", "chisel", "ligolo-proxy")
    ad      = @("nmap", "impacket-secretsdump", "crackmapexec", "certipy", "hashcat", "john")
    recon   = @("subfinder", "httpx", "katana", "whatweb", "arjun", "gau", "waybackurls", "amass")
    minimal = @("nmap", "nuclei", "httpx", "subfinder")
}

if ($List) {
    Write-Host ""
    Write-Host "Available Profiles" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  all        Full pentest toolkit" -ForegroundColor Green
    Write-Host "  web        Web application assessment" -ForegroundColor Green
    Write-Host "  network    Network assessment & tunneling" -ForegroundColor Green
    Write-Host "  ad         Active Directory attacks" -ForegroundColor Green
    Write-Host "  recon      Reconnaissance tools" -ForegroundColor Green
    Write-Host "  minimal    Just the essentials" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\install-tools.ps1 -Profile <name>"
    exit 0
}

# ─── Tool Check ────────────────────────────────────────────────────────────────

function Test-Tool {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Show-ToolStatus {
    $tools = $ToolProfiles[$Profile]
    $installed = 0
    $missing = 0

    Write-Host ""
    Write-Host "Tool Status (profile: $Profile)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  {0,-25} {1}" -f "TOOL", "STATUS")
    Write-Host ("  {0,-25} {1}" -f "----", "------")

    foreach ($tool in $tools) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Host ("  {0,-25} " -f $tool) -NoNewline
            Write-Host "installed" -ForegroundColor Green -NoNewline
            Write-Host " ($($cmd.Source))"
            $installed++
        } else {
            Write-Host ("  {0,-25} " -f $tool) -NoNewline
            Write-Host "missing" -ForegroundColor Red
            $missing++
        }
    }

    $total = $tools.Count
    Write-Host ""
    Write-Host "  Installed: $installed/$total" -ForegroundColor Green
    if ($missing -gt 0) {
        Write-Host "  Missing:   $missing/$total" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Run '.\install-tools.ps1 -Profile $Profile' to install missing tools."
    } else {
        Write-Host "  All tools available!" -ForegroundColor Green
    }
}

if ($Check) {
    Show-ToolStatus
    exit 0
}

# ─── Package Manager Detection ─────────────────────────────────────────────────

function Ensure-PackageManager {
    if ($PackageManager -eq "auto") {
        if (Test-Tool "choco") {
            $script:PM = "choco"
        } elseif (Test-Tool "scoop") {
            $script:PM = "scoop"
        } else {
            Write-Info "No package manager found. Installing Chocolatey..."
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            $script:PM = "choco"
        }
    } else {
        $script:PM = $PackageManager
    }
    Write-Ok "Using package manager: $script:PM"
}

# ─── Installation Functions ────────────────────────────────────────────────────

function Install-ChocoPackage {
    param([string]$Name, [string]$Package)
    if (-not (Test-Tool $Name)) {
        Write-Step "Installing $Name via Chocolatey..."
        choco install $Package -y --no-progress 2>$null
        if ($?) { Write-Ok "$Name installed" } else { Write-Warn "Failed to install $Name" }
    } else {
        Write-Ok "$Name already installed"
    }
}

function Install-ScoopPackage {
    param([string]$Name, [string]$Package, [string]$Bucket = "")
    if (-not (Test-Tool $Name)) {
        if ($Bucket -and -not (scoop bucket list | Select-String $Bucket)) {
            scoop bucket add $Bucket 2>$null
        }
        Write-Step "Installing $Name via Scoop..."
        scoop install $Package 2>$null
        if ($?) { Write-Ok "$Name installed" } else { Write-Warn "Failed to install $Name" }
    } else {
        Write-Ok "$Name already installed"
    }
}

function Install-SystemPackages {
    $tools = $ToolProfiles[$Profile]

    if ($script:PM -eq "choco") {
        if ($tools -contains "nmap") { Install-ChocoPackage "nmap" "nmap" }
        if ($tools -contains "tshark") { Install-ChocoPackage "tshark" "wireshark" }
        if ($tools -contains "hashcat") { Install-ChocoPackage "hashcat" "hashcat" }
        if ($tools -contains "john") { Install-ChocoPackage "john" "john" }
        if ($tools -contains "sqlmap") { Install-ChocoPackage "sqlmap" "sqlmap" }
        if ($tools -contains "amass") { Install-ChocoPackage "amass" "amass" }
    } elseif ($script:PM -eq "scoop") {
        if ($tools -contains "nmap") { Install-ScoopPackage "nmap" "nmap" "extras" }
        if ($tools -contains "hashcat") { Install-ScoopPackage "hashcat" "hashcat" }
        if ($tools -contains "john") { Install-ScoopPackage "john" "john-the-ripper" }
    }
}

function Install-GoTools {
    $tools = $ToolProfiles[$Profile]

    if (-not (Test-Tool "go")) {
        Write-Step "Installing Go..."
        if ($script:PM -eq "choco") {
            choco install golang -y --no-progress
        } elseif ($script:PM -eq "scoop") {
            scoop install go
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }

    if (-not (Test-Tool "go")) {
        Write-Warn "Go not available after install attempt. Skipping Go tools."
        return
    }

    Write-Ok "Go available: $(go version)"

    $goTools = @{}
    $goTools["subfinder"] = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    $goTools["httpx"] = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    $goTools["nuclei"] = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    $goTools["ffuf"] = "github.com/ffuf/ffuf/v2@latest"
    $goTools["katana"] = "github.com/projectdiscovery/katana/cmd/katana@latest"
    $goTools["gobuster"] = "github.com/OJ/gobuster/v3@latest"
    $goTools["gau"] = "github.com/lc/gau/v2/cmd/gau@latest"
    $goTools["waybackurls"] = "github.com/tomnomnom/waybackurls@latest"

    foreach ($tool in $goTools.Keys) {
        if ($tools -contains $tool) {
            if (-not (Test-Tool $tool)) {
                Write-Step "Installing $tool..."
                go install $goTools[$tool] 2>$null
                if ($?) { Write-Ok "$tool installed" } else { Write-Warn "Failed to install $tool" }
            } else {
                Write-Ok "$tool already installed"
            }
        }
    }
}

function Install-PythonTools {
    $tools = $ToolProfiles[$Profile]

    if (-not (Test-Tool "python") -and -not (Test-Tool "python3")) {
        Write-Step "Installing Python..."
        if ($script:PM -eq "choco") {
            choco install python3 -y --no-progress
        } elseif ($script:PM -eq "scoop") {
            scoop install python
        }
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    }

    $pipPkgs = @()
    if ($tools -contains "impacket-secretsdump") { $pipPkgs += "impacket" }
    if ($tools -contains "certipy") { $pipPkgs += "certipy-ad" }
    if ($tools -contains "crackmapexec") { $pipPkgs += "crackmapexec" }
    if ($tools -contains "arjun") { $pipPkgs += "arjun" }

    if ($pipPkgs.Count -gt 0) {
        Write-Step "Installing Python tools: $($pipPkgs -join ', ')"
        $pipCmd = "python -m pip install $($pipPkgs -join ' ')"
        Invoke-Expression $pipCmd 2>$null
        if ($?) { Write-Ok "Python tools installed" } else { Write-Warn "Some Python tools may have failed" }
    }
}

function Install-BinaryReleases {
    $tools = $ToolProfiles[$Profile]
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

    # Chisel
    if ($tools -contains "chisel" -and -not (Test-Tool "chisel")) {
        Write-Step "Installing chisel..."
        $chiselVer = "1.11.5"
        $url = "https://github.com/jpillora/chisel/releases/download/v$chiselVer/chisel_${chiselVer}_windows_${arch}.gz"
        $outPath = "$env:TEMP\chisel.gz"
        try {
            Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
            # Extract gzip - PowerShell native
            $inStream = [System.IO.File]::OpenRead($outPath)
            $gzStream = New-Object System.IO.Compression.GZipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
            $outStream = [System.IO.File]::Create("C:\Windows\System32\chisel.exe")
            $gzStream.CopyTo($outStream)
            $outStream.Close(); $gzStream.Close(); $inStream.Close()
            Remove-Item $outPath -Force
            Write-Ok "chisel installed"
        } catch {
            Write-Warn "Failed to install chisel: $_"
        }
    }

    # Ligolo-ng
    if ($tools -contains "ligolo-proxy" -and -not (Test-Tool "ligolo-proxy")) {
        Write-Step "Installing ligolo-ng..."
        $ligoloVer = "0.8.3"
        $url = "https://github.com/nicocha30/ligolo-ng/releases/download/v$ligoloVer/ligolo-ng_proxy_${ligoloVer}_windows_${arch}.zip"
        $outPath = "$env:TEMP\ligolo.zip"
        try {
            Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing
            Expand-Archive -Path $outPath -DestinationPath "$env:TEMP\ligolo" -Force
            Move-Item "$env:TEMP\ligolo\proxy.exe" "C:\Windows\System32\ligolo-proxy.exe" -Force
            Remove-Item $outPath -Force
            Remove-Item "$env:TEMP\ligolo" -Recurse -Force
            Write-Ok "ligolo-ng installed"
        } catch {
            Write-Warn "Failed to install ligolo-ng: $_"
        }
    }

    # RustScan
    if ($tools -contains "rustscan" -and -not (Test-Tool "rustscan")) {
        Write-Step "Installing rustscan..."
        if ($script:PM -eq "scoop") {
            scoop install rustscan 2>$null
        } elseif ($script:PM -eq "choco") {
            choco install rustscan -y --no-progress 2>$null
        }
        if (Test-Tool "rustscan") { Write-Ok "rustscan installed" } else { Write-Warn "rustscan: install manually from GitHub releases" }
    }

    # Masscan
    if ($tools -contains "masscan" -and -not (Test-Tool "masscan")) {
        Write-Step "Installing masscan..."
        if ($script:PM -eq "choco") {
            choco install masscan -y --no-progress 2>$null
        }
        if (Test-Tool "masscan") { Write-Ok "masscan installed" } else { Write-Warn "masscan: install manually" }
    }

    # Feroxbuster
    if ($tools -contains "feroxbuster" -and -not (Test-Tool "feroxbuster")) {
        Write-Step "Installing feroxbuster..."
        if ($script:PM -eq "choco") {
            choco install feroxbuster -y --no-progress 2>$null
        }
        if (Test-Tool "feroxbuster") { Write-Ok "feroxbuster installed" } else { Write-Warn "feroxbuster: install manually from GitHub releases" }
    }

    # Nikto
    if ($tools -contains "nikto" -and -not (Test-Tool "nikto")) {
        Write-Warn "nikto: requires Perl on Windows. Consider using WSL or Docker for nikto."
    }

    # testssl.sh
    if ($tools -contains "testssl.sh" -and -not (Test-Tool "testssl.sh")) {
        Write-Warn "testssl.sh: requires bash. Use WSL or Git Bash to run testssl.sh"
    }
}

# ─── Main ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== RedHands Tool Installer (Windows) ===" -ForegroundColor Cyan
Write-Host "    Profile: $Profile" -ForegroundColor Cyan
Write-Host ""

$tools = $ToolProfiles[$Profile]
Write-Info "Tools to install: $($tools.Count)"
Write-Host ""

if (-not $Yes) {
    Write-Host "The following tools will be installed:" -ForegroundColor Yellow
    Write-Host "  $($tools -join ', ')" | Out-Host
    Write-Host ""
    $response = Read-Host "Continue? [Y/n]"
    if ($response -match '^[Nn]') {
        Write-Info "Aborted."
        exit 0
    }
}

Write-Host ""
Write-Info "Step 1/4: Setting up package manager..."
Ensure-PackageManager
Write-Host ""

Write-Info "Step 2/4: Installing system packages..."
Install-SystemPackages
Write-Host ""

Write-Info "Step 3/4: Installing Go tools..."
Install-GoTools
Write-Host ""

Write-Info "Step 4/4: Installing Python + binary tools..."
Install-PythonTools
Install-BinaryReleases
Write-Host ""

Write-Host "=== Installation Complete ===" -ForegroundColor Cyan
Write-Host ""
Show-ToolStatus
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1. Build RedHands:  go build -o redhands.exe ./cmd/redhands"
Write-Host "  2. Or use pre-built: bin\redhands.exe"
Write-Host "  3. Add to MCP config (Claude Code / Cursor / VS Code)"
Write-Host ""
