# install-blnq.ps1 — drop the blnq CLI on Windows, instantly.
#
# Usage (from any PowerShell):
#   iwr -useb https://blnq.org/install-blnq.ps1 | iex
#   iwr -useb https://blnq.org/install-blnq.ps1 | iex; Install-Blnq -Prefix $env:USERPROFILE\.local -NoPath
#   iwr -useb https://blnq.org/install-blnq.ps1 | iex; Install-Blnq -Uninstall
#
# Flags:
#   -Prefix DIR     install root (default: $env:USERPROFILE\.local)
#   -NoPath         don't print "add to PATH" if missing
#   -Yes            don't prompt for PATH changes
#   -WithLlm        also install Ollama + a model recommended for your hardware
#   -NoLlm          skip the Ollama/model prompt (default = prompt if interactive)
#   -Uninstall      remove what we installed
#   -Quiet          less output
#   -Help           this help
#
# Requires PowerShell 5+ (ships with Windows 10 / 11) and a python3 on PATH.

[CmdletBinding()]
param(
    [string]$Prefix = "",
    [switch]$NoPath,
    [switch]$Yes,
    [switch]$WithLlm,
    [switch]$NoLlm,
    [switch]$Uninstall,
    [switch]$Quiet,
    [switch]$Help
)

$App = "blnq"
$Hub = "https://blnq.org"

# ── brand colors ───────────────────────────────────────────────────────
$ColorReset     = [ConsoleColor]::Gray
$ColorBold      = [ConsoleColor]::White
$ColorDim       = [ConsoleColor]::DarkGray
$ColorBrand     = [ConsoleColor]::Cyan          # blnq = electric cyan
$ColorBrand2    = [ConsoleColor]::DarkCyan
$ColorAccent    = [ConsoleColor]::Cyan
$ColorSuccess   = [ConsoleColor]::Green
$ColorWarn      = [ConsoleColor]::Yellow
$ColorError     = [ConsoleColor]::Red

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full | Out-String
    exit 0
}

function _Say([string]$m)   { if (-not $Quiet) { Write-Host "  ✓ $m" -ForegroundColor $ColorSuccess } }
function _Log([string]$m)   { if (-not $Quiet) { Write-Host "  $m" -ForegroundColor $ColorAccent } }
function _Warn([string]$m)  { Write-Host "  ! $m" -ForegroundColor $ColorWarn }
function _Die([string]$m)  { Write-Host "  ✗ $m" -ForegroundColor $ColorError; exit 1 }

# ── banner ─────────────────────────────────────────────────────────────
function Show-Banner {
    Write-Host ""
    Write-Host "      ██████╗ ██╗     ██╗███╗   ██╗ ██████╗" -ForegroundColor $ColorBrand
    Write-Host "      ██╔══██╗██║     ██║████╗  ██║██╔════╝" -ForegroundColor $ColorBrand
    Write-Host "      ██████╔╝██║     ██║██╔██╗ ██║██║  ███╗" -ForegroundColor $ColorBrand
    Write-Host "      ██╔══██╗██║     ██║██║╚██╗██║██║   ██║" -ForegroundColor $ColorBrand
    Write-Host "      ██████╔╝███████╗██║██║ ╚████║╚██████╔╝" -ForegroundColor $ColorBrand
    Write-Host "      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝" -ForegroundColor $ColorBrand
    Write-Host ""
    Write-Host "  ⌨️  run code in the cloud, safely" -ForegroundColor $ColorBrand2
    Write-Host "  scripts scanned · secrets stripped · output streamed back" -ForegroundColor $ColorDim
    Write-Host ""
}

# ── paths ──────────────────────────────────────────────────────────────
if (-not $Prefix) {
    $Prefix = Join-Path $env:USERPROFILE ".local"
}
$BinDir     = Join-Path $Prefix "bin"
$LibDir     = Join-Path $Prefix "lib\$App"
$ClientFile = Join-Path $LibDir  "$App-cli.py"
$Wrapper    = Join-Path $BinDir "$App.cmd"

if ($Uninstall) {
    Write-Host "  uninstalling" -ForegroundColor $ColorAccent
    foreach ($p in @($Wrapper, $ClientFile)) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
    if (Test-Path -LiteralPath $LibDir) {
        Remove-Item -LiteralPath $LibDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    _Say "removed $Wrapper and $ClientFile"
    _Log "(your data in ~\.config\$App\ and ~\.local\share\$App\ was kept)"
    exit 0
}

# ── preflight ──────────────────────────────────────────────────────────
$py = $null
foreach ($candidate in @("python", "python3", "py")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) { $py = $candidate; break }
}
if (-not $py) {
    _Die "python not found on PATH. Install Python 3 and reopen PowerShell:"
    Write-Host "    winget install Python.Python.3.12" -ForegroundColor $ColorAccent
    Write-Host "    or download from https://python.org/downloads/" -ForegroundColor $ColorAccent
}

$pyVersion = & $py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>$null
if (-not $pyVersion) { $pyVersion = "unknown" }

Show-Banner

Write-Host "  environment" -ForegroundColor $ColorBold
Write-Host "  ✓ python     $pyVersion" -ForegroundColor $ColorSuccess
Write-Host "  ✓ os         $($env:OS) $($env:PROCESSOR_ARCHITECTURE)" -ForegroundColor $ColorSuccess
Write-Host "  ✓ prefix     $Prefix" -ForegroundColor $ColorSuccess
Write-Host ""

# ── ensure dirs ────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $BinDir, $LibDir | Out-Null

# ── download client + wrapper ──────────────────────────────────────────
function Fetch([string]$url, [string]$dest, [string]$label) {
    Write-Host "  ↓ downloading $label ..." -NoNewline -ForegroundColor $ColorAccent
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
        Write-Host "`r  ✓ $label                    " -ForegroundColor $ColorSuccess
    } catch {
        Write-Host ""
        _Die "download failed: $url`n    $($_.Exception.Message)"
    }
}

Fetch "$Hub/$App-cli.py" $ClientFile "$App-cli.py"
Fetch "$Hub/$App.cmd"    $Wrapper    "$App.cmd"

# ── success card ──────────────────────────────────────────────────────
$Bar = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
Write-Host "  $Bar" -ForegroundColor $ColorSuccess
Write-Host "  ✓ $App CLI installed" -ForegroundColor $ColorBold
Write-Host "  $Bar" -ForegroundColor $ColorSuccess
Write-Host ""

Write-Host "  location" -ForegroundColor $ColorBold
Write-Host "    wrapper   $Wrapper" -ForegroundColor $ColorAccent
Write-Host "    client    $ClientFile" -ForegroundColor $ColorAccent
Write-Host "    config    ~\.config\$App\" -ForegroundColor $ColorDim
Write-Host "    state     ~\.local\share\$App\" -ForegroundColor $ColorDim
Write-Host ""

Write-Host "  try it now" -ForegroundColor $ColorBold
Write-Host "    `$$App --help               list every subcommand" -ForegroundColor $ColorDim
Write-Host "    `$$App hi                   friendly first-run greeter" -ForegroundColor $ColorDim
Write-Host "    `$$App submissions list    community-submitted free tools" -ForegroundColor $ColorDim
Write-Host "    `$$App graph stats         knowledge graph snapshot" -ForegroundColor $ColorDim
Write-Host "    `$$App graph search `"x`"   semantic search the graph" -ForegroundColor $ColorDim
Write-Host "    `$$App start                launch the local agent" -ForegroundColor $ColorDim
Write-Host "    `$$App doctor               full health report (pasteable)" -ForegroundColor $ColorDim
Write-Host ""

Write-Host "  bonus" -ForegroundColor $ColorBold
Write-Host "    `> echo `"print(1+1)`" | Out-File `$env:TEMP\x.py" -ForegroundColor $ColorDim
Write-Host "    `> `$App `$env:TEMP\x.py     (scan → upload → run → stream output)" -ForegroundColor $ColorDim
Write-Host "    `> `$App scan `$env:TEMP\x.py  just scan, no upload" -ForegroundColor $ColorDim
Write-Host ""

# ── optional: install Ollama + a recommended model ───────────────────
# Prompts the user at the end of the install unless -WithLlm / -NoLlm
# is set. Uses the just-installed `${App} llm suggest --json` as the source
# of truth for which model to pull — PowerShell doesn't re-implement tier logic.
$shouldInstallLlm = $false
if ($WithLlm)                              { $shouldInstallLlm = $true }
elseif (-not $NoLlm -and [Environment]::UserInteractive) {
    $ans = Read-Host " Install Ollama + a model recommended for your hardware? [y/N]"
    if ($ans -match '^[Yy]') { $shouldInstallLlm = $true }
}

if ($shouldInstallLlm) {
    # Put the just-installed bin first so a stale `$App` shadowing it on PATH
    # doesn't break the just-installed `${App} llm suggest` call.
    if (($env:Path -split ';') -notcontains $BinDir) {
        $env:Path = "$BinDir;$env:Path"
    }

    Write-Host ""
    Write-Host "  ⌨️  $App llm setup" -ForegroundColor $ColorBold
    Write-Host ""

    $haveOllama = $null -ne (Get-Command ollama -ErrorAction SilentlyContinue)
    if ($haveOllama) {
        _Say "ollama already installed — skipping install"
    } else {
        _Log "ollama not found — installing..."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            & winget install --id Ollama.Ollama --accept-source-agreements --accept-package-agreements | Out-Host
        } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
            & choco install ollama -y | Out-Host
        } else {
            _Warn "install winget or chocolatey, or download from https://ollama.com/download"
        }
        $haveOllama = $null -ne (Get-Command ollama -ErrorAction SilentlyContinue)
    }

    if ($haveOllama) {
        # Ask the just-installed CLI to recommend — falls back to gemma4:e2b
        # if JSON parse fails for any reason.
        $picked = & $App llm suggest --json 2>$null | & $py -c "import json,sys; print(json.load(sys.stdin).get('primary','gemma4:e2b'))" 2>$null
        if (-not $picked) { $picked = 'gemma4:e2b' }

        Write-Host ""
        Write-Host "  recommended model: $picked" -ForegroundColor $ColorAccent
        Write-Host ""
        & ollama pull $picked | Out-Host
        if ($LASTEXITCODE -eq 0) {
            _Say "pulled $picked"
        } else {
            _Warn "pull failed — you can retry with: ollama pull $picked"
        }
        Write-Host ""
        Write-Host "  ✓ try it:     ${App} chat `"hello`" --local" -ForegroundColor $ColorSuccess
        Write-Host "  ✓ more info:  ${App} llm status" -ForegroundColor $ColorSuccess
        Write-Host ""
    } else {
        _Warn "ollama not on PATH after install — reopen PowerShell and run ``ollama --version``"
    }
}

# ── PATH advice ──────────────────────────────────────────────────────
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathDirs = if ($userPath) { $userPath -split ";" } else { @() }
$needsPath = $pathDirs -notcontains $BinDir

if ($needsPath) {
    if ($NoPath) {
        :
    } elseif ($Yes) {
        $newUserPath = if ($userPath) { "$BinDir;$userPath" } else { $BinDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        _Say "added $BinDir to user PATH"
        Write-Host "       (restart your PowerShell window to pick up)" -ForegroundColor $ColorDim
    } else {
        Write-Host "  note" -ForegroundColor $ColorWarn
        Write-Host "    $BinDir is not on your PATH" -ForegroundColor $ColorWarn
        Write-Host "    Add it for this user (reopen terminal after):" -ForegroundColor $ColorDim
        Write-Host "      `$env:Path = `"$BinDir;`$env:Path`"" -ForegroundColor $ColorAccent
        Write-Host "      [Environment]::SetEnvironmentVariable('Path', `"$BinDir;`" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')" -ForegroundColor $ColorAccent
        Write-Host ""
        Write-Host "    Or invoke directly while you're here:" -ForegroundColor $ColorDim
        Write-Host "      & `"$Wrapper`" --help" -ForegroundColor $ColorAccent
    }
}

# ── footer ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ⚡  github.com/$App  ·  ${App}.org  ·  support@${App}.org" -ForegroundColor $ColorBrand2
Write-Host ""
