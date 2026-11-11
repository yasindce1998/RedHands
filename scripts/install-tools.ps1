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
    [ValidateSet("all", "web", "network", "ad", "k8s", "uefi", "recon", "minimal")]
    [string]$Profile = "all",
    [switch]$Check,
    [switch]$List,
    [ValidateSet("auto", "choco", "scoop")]
    [string]$PackageManager = "auto",
    [switch]$Yes
)

$ErrorActionPreference = "Continue"
$DependencyLock = Get-Content (Join-Path $PSScriptRoot "dependencies.json") -Raw | ConvertFrom-Json
if ($DependencyLock.schema_version -ne 1) { throw "Unsupported dependency manifest version" }

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
                "impacket-secretsdump", "crackmapexec", "certipy",
                "kubedagger-client", "kubedagger-operator",
                "barzakh-adversary", "barzakh-scanner")
    web     = @("nmap", "subfinder", "httpx", "nuclei", "ffuf", "katana", "gobuster",
                "gau", "nikto", "whatweb", "sqlmap", "testssl.sh", "arjun",
                "feroxbuster", "waybackurls", "masscan", "rustscan", "amass")
    network = @("nmap", "masscan", "rustscan", "tshark", "chisel", "ligolo-proxy")
    ad      = @("nmap", "impacket-secretsdump", "crackmapexec", "certipy", "hashcat", "john")
    k8s     = @("nmap", "kubedagger-client", "kubedagger-operator")
    uefi    = @("barzakh-adversary", "barzakh-scanner")
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
    Write-Host "  k8s        Kubernetes offensive (eBPF-powered)" -ForegroundColor Green
    Write-Host "  uefi       UEFI bootkit adversary simulation" -ForegroundColor Green
    Write-Host "  recon      Reconnaissance tools" -ForegroundColor Green
    Write-Host "  minimal    Just the essentials" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage: .\install-tools.ps1 -Profile <name>"
    exit 0
}

# ─── Tool Check ────────────────────────────────────────────────────────────────

function Test-Tool {
    param([string]$Name)
    if ($null -ne (Get-Command $Name -ErrorAction SilentlyContinue)) { return $true }
    if ($Name.StartsWith("impacket-")) { return $null -ne (Get-Command ($Name.Substring(9) + ".py") -ErrorAction SilentlyContinue) }
    return $false
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
        if (-not $cmd -and $tool.StartsWith("impacket-")) { $cmd = Get-Command ($tool.Substring(9) + ".py") -ErrorAction SilentlyContinue }
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
            throw "Install Chocolatey or Scoop from its trusted instructions first; downloaded scripts are not executed automatically."
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
    foreach ($entry in $DependencyLock.go.PSObject.Properties) { $goTools[$entry.Name] = $entry.Value }

    foreach ($tool in $goTools.Keys) {
        if ($tools -contains $tool) {
            if (-not (Test-Tool $tool)) {
                Write-Step "Installing $tool..."
                $module = $goTools[$tool]
                go install $module
                if ($LASTEXITCODE -eq 0) { Write-Ok "$tool installed" } else { throw "Failed to install pinned $tool" }
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
    if ($tools -contains "impacket-secretsdump") { $pipPkgs += $DependencyLock.python.impacket }
    if ($tools -contains "certipy") { $pipPkgs += $DependencyLock.python.certipy }
    if ($tools -contains "crackmapexec") { Write-Warn "crackmapexec is unavailable from PyPI; install a reviewed compatible version manually." }
    if ($tools -contains "arjun") { $pipPkgs += $DependencyLock.python.arjun }

    if ($pipPkgs.Count -gt 0) {
        Write-Step "Installing Python tools: $($pipPkgs -join ', ')"
        $python = if (Test-Tool "python") { "python" } else { "python3" }
        & $python -m pip install @pipPkgs
        if ($?) { Write-Ok "Python tools installed" } else { Write-Warn "Some Python tools may have failed" }
    }
}

function Install-BinaryReleases {
    $tools = $ToolProfiles[$Profile]
    # Reuse the same checksum-verifying installer as Linux/Docker.
    $python = if (Test-Tool "python") { "python" } elseif (Test-Tool "python3") { "python3" } else { $null }
    if (-not $python) { throw "Python 3 is required for verified binary installation" }
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } elseif ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    foreach ($name in @("chisel", "ligolo-proxy", "kubedagger-client", "kubedagger-operator", "barzakh-adversary", "barzakh-scanner", "feroxbuster")) {
        if (($tools -contains $name) -and -not (Test-Tool $name)) {
            $variants = $DependencyLock.artifacts.$name
            if (-not $variants."windows-$arch") {
                Write-Warn "No verified $name release for windows-$arch; install manually."
                continue
            }
            & $python (Join-Path $PSScriptRoot "dependencies.py") install $name --platform "windows-$arch" --output "$env:ProgramFiles\RedHands\bin"
            if ($LASTEXITCODE -ne 0) { throw "Verified installation failed for $name" }
        }
    }
    $env:Path = "$env:ProgramFiles\RedHands\bin;" + $env:Path
    Write-Info "Verified binaries are in $env:ProgramFiles\RedHands\bin; add this directory to your persistent PATH."
    foreach ($name in @("rustscan", "masscan", "testssl.sh", "nikto")) {
        if (($tools -contains $name) -and -not (Test-Tool $name)) { Write-Warn "${name}: install manually from a trusted package manager." }
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
