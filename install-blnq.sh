#!/usr/bin/env bash
# install-blnq.sh — drop the blnq CLI anywhere, instantly.
#
# Usage:
#   curl -sSL https://blnq.org/install-blnq.sh | bash
#   curl -sSL https://blnq.org/install-blnq.sh | bash -s -- --prefix=$HOME/.local
#   curl -sSL https://blnq.org/install-blnq.sh | bash -s -- --uninstall
#
# Flags:
#   --prefix=DIR     install location (default /usr/local — use $HOME/.local for user)
#   --no-path        skip the "add to PATH" message if prefix is non-standard
#   --yes            skip the "auto-add to PATH?" prompt (don't touch rc files)
#   --with-llm       also install Ollama + a model recommended for your hardware
#   --no-llm         skip the Ollama/model prompt (default = prompt if interactive)
#   --no-service     skip installing the background service (runs by default with sudo)
#   --with-sandbox   install a sandbox (bubblewrap) without prompting
#   --no-sandbox     skip the sandbox install prompt entirely
#   --uninstall      remove what we installed
#   --quiet          less output
#   -h, --help       this help

set -euo pipefail

# ── colors ─────────────────────────────────────────────────────────────
if [[ -t 1 ]] && command -v tput >/dev/null 2>&1 && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]]; then
    RST=$'\033[0m'; BLD=$'\033[1m'; DIM=$'\033[2m'; UND=$'\033[4m'
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLU=$'\033[34m'
    MAG=$'\033[35m'; CYN=$'\033[36m'; WHT=$'\033[37m'
    # brand: blnq = cyan/electric
    BLNQ=$'\033[38;5;51m'; ACCENT=$'\033[38;5;45m'
else
    RST=""; BLD=""; DIM=""; UND=""; RED=""; GRN=""; YLW=""; BLU=""; MAG=""; CYN=""; WHT=""
    BLNQ=""; ACCENT=""
fi

# ── globals ────────────────────────────────────────────────────────────
APP="blnq"
HUB="https://blnq.org"
PREFIX="/usr/local"
DO_UNINSTALL=0
NO_PATH=0
ASSUME_YES=0
QUIET=0
WITH_LLM=0   # 0 = auto-prompt if interactive, 1 = yes, -1 = no
WITH_SERVICE=1  # 1 = install service by default when sudo available, 0 = skip
WITH_SANDBOX=0  # 0 = prompt if interactive, 1 = yes, -1 = no
LLM_MODEL=""

# ── arg parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix=*) PREFIX="${1#*=}"   ; shift ;;
        --prefix)   PREFIX="$2"       ; shift 2 ;;
        --no-path)  NO_PATH=1         ; shift ;;
        --yes|-y)   ASSUME_YES=1      ; shift ;;
        --with-llm) WITH_LLM=1        ; shift ;;
        --no-llm)   WITH_LLM=-1       ; shift ;;
        --no-service)  WITH_SERVICE=0  ; shift ;;
        --with-sandbox) WITH_SANDBOX=1  ; shift ;;
        --no-sandbox)   WITH_SANDBOX=-1 ; shift ;;
        --quiet|-q) QUIET=1           ; shift ;;
        --uninstall) DO_UNINSTALL=1   ; shift ;;
        -h|--help)
            sed -n '2,/^set -e/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'
            exit 0
            ;;
        *) printf '%s%s%s\n' "$RED" "unknown flag: $1 (try --help)" "$RST" >&2; exit 1 ;;
    esac
done

# ── tiny output helpers ───────────────────────────────────────────────
_log()  { [[ "$QUIET" -eq 1 ]] || printf '  %s%s%s\n' "$BLU" "$*" "$RST"; }
_say()  { printf '  %s✓%s %s\n' "$GRN" "$RST" "$*"; }
_warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$*" >&2; }
_die()  { printf '  %s✗%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

# ── spinner (runs in foreground while $1 sleeps) ──────────────────────
_spin() {
    local msg="$1"; shift
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    "$@" >/dev/null 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  %s%s%s %s' "$BLNQ" "${frames:i++%${#frames}:1}" "$RST" "$msg"
        sleep 0.08
    done
    wait $pid
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        printf '\r  %s✗%s %s failed%s\n' "$RED" "$RST" "$msg" "$RST"
        printf '  %scheck your network connection and try again%s\n' "$DIM" "$RST"
        exit 1
    fi
    printf '\r  %s✓%s %s\n' "$GRN" "$RST" "$msg"
}

# ── banner ─────────────────────────────────────────────────────────────
banner() {
    printf '\n'
    printf '  %s%s' "$BLNQ" "$BLD"
    cat <<'BANNER'

      ██████╗ ██╗     ██╗███╗   ██╗ ██████╗
      ██╔══██╗██║     ██║████╗  ██║██╔════╝
      ██████╔╝██║     ██║██╔██╗ ██║██║  ███╗
      ██╔══██╗██║     ██║██║╚██╗██║██║   ██║
      ██████╔╝███████╗██║██║ ╚████║╚██████╔╝
      ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

BANNER
    printf '%s' "$RST"
    printf '\n'
    printf '  %s⌨️  run code in the cloud, safely%s\n' "$ACCENT" "$RST"
    printf '  %sscripts scanned · secrets stripped · output streamed back%s\n\n' "$DIM" "$RST"
}

# ── uninstall path ────────────────────────────────────────────────────
if [[ "$DO_UNINSTALL" == "1" ]]; then
    BIN_DIR="$PREFIX/bin"
    LIB_DIR="$PREFIX/lib/$APP"
    _log "${BLD}uninstalling${RST}"
    rm -f "$BIN_DIR/$APP" "$LIB_DIR/${APP}-cli.py"
    rmdir "$LIB_DIR" 2>/dev/null || true
    _say "removed ${DIM}$BIN_DIR/$APP${RST} and ${DIM}$LIB_DIR/${APP}-cli.py${RST}"
    # Check for sudo needed to remove service
    UNINSTALL_SUDO=""
    if [[ ! -w "$BIN_DIR" ]] || [[ ! -w "$(dirname "$LIB_DIR")" ]]; then
        if need sudo; then UNINSTALL_SUDO="sudo"
        fi
    fi
    if [[ -n "$UNINSTALL_SUDO" ]] && [[ -f "/etc/systemd/system/${APP}-website.service" ]]; then
        $UNINSTALL_SUDO systemctl disable --now ${APP}-website 2>/dev/null || true
        $UNINSTALL_SUDO rm -f /etc/systemd/system/${APP}-website.service
        _say "removed systemd service"
    fi
    _log "${DIM}(your data in ~/.config/$APP/ and ~/.local/share/$APP/ was kept)${RST}"
    exit 0
fi

# ── preflight ─────────────────────────────────────────────────────────
need() { command -v "$1" >/dev/null 2>&1; }

# Windows shell → suggest PowerShell installer
case "${OSTYPE:-$(uname -s 2>/dev/null)}" in
    msys*|cygwin*|mingw*|win32)
        _die "Windows shell detected (${OSTYPE:-Windows}). Use the PowerShell installer instead:"
        printf '         iwr -useb %s/install-%s.ps1 | iex\n' "$HUB" "$APP" >&2
        ;;
esac

PYTHON_BIN=""
for p in python3 python; do
    if need "$p"; then PYTHON_BIN="$p"; break; fi
done
[[ -n "$PYTHON_BIN" ]] || _die "python3 not found. install it first (apt install python3 / brew install python3)"
PY_VER="$("$PYTHON_BIN" -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo unknown)"

if ! need curl && ! need wget; then
    _die "need curl or wget to download the client"
fi

# print banner + env
banner
printf '  %senvironment%s\n' "$BLD" "$RST"
printf '  %s✓%s python     %s\n' "$GRN" "$RST" "$PY_VER"
printf '  %s✓%s downloader %s%s%s\n' "$GRN" "$RST" "$DIM" "$(need curl && echo curl || echo wget)" "$RST"
printf '  %s✓%s os         %s\n' "$GRN" "$RST" "$(uname -srm 2>/dev/null || echo unknown)"
printf '  %s✓%s prefix     %s%s%s\n' "$GRN" "$RST" "$BLU" "$PREFIX" "$RST"

# ── sandbox detection (protects this PC from other people's code) ──────
# Volunteer mode runs foreign code on this machine. Without a jail
# (bubblewrap/docker) that code would have full network + filesystem access,
# so `blnq volunteer on` refuses until one exists — detect it up front.
_bwrap_probe() {
    command -v bwrap >/dev/null 2>&1 &&
        bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
              --unshare-all --die-with-parent true >/dev/null 2>&1
}
_docker_probe() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }
SANDBOX="none"
if _bwrap_probe; then SANDBOX="bwrap"
elif _docker_probe; then SANDBOX="docker"
fi
printf '  %s✓%s sandbox    %s%s%s\n' "$GRN" "$RST" "$BLU" "$SANDBOX" "$RST"
if [[ "$SANDBOX" == "none" ]]; then
    printf '  %s!%s no jail found — YOUR code runs fine, but volunteer mode\n' "$YLW" "$RST"
    printf '    (other people'\''s code here) will be refused until one exists\n'
fi
printf '\n'

# ── install ───────────────────────────────────────────────────────────
BIN_DIR="$PREFIX/bin"
LIB_DIR="$PREFIX/lib/$APP"
CLIENT_FILE="$LIB_DIR/${APP}-cli.py"
WRAPPER="$BIN_DIR/$APP"

# Use sudo only if we need it (gated by writability)
SUDO=""
_can_sudo() { sudo -n true 2>/dev/null; }

# Create a user-owned target BEFORE testing whether it is writable: a
# writability test against a directory that does not exist yet always fails, so
# on a genuinely fresh machine (no ~/.local/bin yet — common, because /etc/profile
# only adds it to PATH *if it exists at login*) the installer died with
# "can't write to …" instead of installing. That also explains why the bin dir
# then never appeared on PATH.
if [[ "$PREFIX" == "$HOME"/* ]]; then
    mkdir -p "$BIN_DIR" "$LIB_DIR" 2>/dev/null || true
fi

if [[ ! -w "$BIN_DIR" ]] || [[ ! -w "$(dirname "$LIB_DIR")" ]]; then
    if _can_sudo; then
        printf '  %s⚡ sudo available — system-wide install (helps everyone on this machine)%s\n' "$BLD" "$RST"
        printf '    · installs for ALL users on this computer\n'
        printf '    · sets up background service that runs on boot\n'
        printf '    · no sudo password needed — you already have access\n\n'
        SUDO="sudo"
        WITH_SERVICE=1
    elif [[ "$PREFIX" != "$HOME/.local" ]] && [[ "$PREFIX" != "$HOME"/* ]]; then
        printf '  %s!%s can'\''t write to %s — switching to user-local install (no sudo needed)%s\n' "$YLW" "$RST" "$BIN_DIR" "$RST"
        printf '    · you can try it without sudo — just for you\n'
        printf '    · to install system-wide for everyone later:\n'
        printf '      %ssudo curl -sSL %s/install-%s.sh | bash%s\n\n' "$CYN" "$HUB" "$APP" "$RST"
        PREFIX="$HOME/.local"
        BIN_DIR="$PREFIX/bin"
        LIB_DIR="$PREFIX/lib/$APP"
        CLIENT_FILE="$LIB_DIR/${APP}-cli.py"
        WRAPPER="$BIN_DIR/$APP"
        WITH_SERVICE=0
    fi
fi

if [[ -z "$SUDO" ]]; then
    if [[ ! -w "$BIN_DIR" ]] || [[ ! -w "$(dirname "$LIB_DIR")" ]]; then
        _die "can't write to $BIN_DIR — run with sudo or use --prefix=\$HOME/.local"
    fi
    printf '  %s✓%s user-local install — just for you (no sudo needed)%s\n' "$GRN" "$RST" "$RST"
    printf '    · no sudo password needed — try it risk-free\n'
    printf '    · to help others on this machine later, run with sudo:\n'
    printf '      %ssudo curl -sSL %s/install-%s.sh | bash%s\n\n' "$CYN" "$HUB" "$APP" "$RST"
fi

$SUDO mkdir -p "$BIN_DIR" "$LIB_DIR"

dl() {
    local url="$1" out="$2"
    if need curl; then
        curl -fsSL --connect-timeout 10 --max-time 60 "$url" -o "$out"
    else
        wget -q --timeout=60 -O "$out" "$url"
    fi
}

_spin "downloading ${BLNQ}${APP}-cli.py${RST}"      dl "$HUB/${APP}-cli.py" "$CLIENT_FILE"
_spin "downloading ${BLNQ}${APP}${RST} wrapper"      dl "$HUB/$APP"          "$WRAPPER"

_spin "installing" bash -c "chmod 0755 '$CLIENT_FILE' '$WRAPPER'"

# ── sandbox provisioning (volunteer-mode protection) ────────────────────
# Bubblewrap on Linux is tiny and unprivileged — offer it (default yes) so a
# fresh install can volunteer safely. macOS needs a docker runtime (VM-based);
# too heavy to surprise-install, so print the supported routes instead.
_install_sandbox() {
    if [[ "$(uname -s)" == "Linux" ]]; then
        local pkg=""
        if   need apt-get; then pkg="apt-get install -y bubblewrap"
        elif need dnf;      then pkg="dnf install -y bubblewrap"
        elif need pacman;   then pkg="pacman -S --noconfirm bubblewrap"
        elif need zypper;   then pkg="zypper -n install bubblewrap"
        fi
        if [[ -z "$pkg" ]]; then
            _warn "no supported package manager found for bubblewrap"
            printf '    manual: https://github.com/containers/bubblewrap\n'
            return 1
        fi
        printf '  %sinstalling bubblewrap — the jail for volunteer jobs%s\n' "$BLD" "$RST"
        # sudo asks for a password on the tty; never hide that prompt
        if sudo $pkg; then
            if _bwrap_probe; then
                SANDBOX="bwrap"
                _say "bubblewrap installed — sandbox: bwrap"
                return 0
            fi
            _warn "bubblewrap installed but the probe failed (unprivileged user namespaces disabled?)"
            return 1
        fi
        _warn "could not install bubblewrap — volunteer mode stays refused"
        return 1
    fi
    # macOS: a docker runtime is a VM — print the routes, never surprise-install
    printf '  %son macOS, volunteer mode needs a docker runtime — run when ready:\n' "$DIM" "$RST"
    printf '    %sbrew install colima docker && colima start%s\n' "$CYN" "$RST"
    printf '    %s…or install OrbStack (orbstack.dev) / Docker Desktop (docker.com)%s\n' "$DIM" "$RST"
    return 1
}

if [[ "$SANDBOX" == "none" && "$WITH_SANDBOX" -ne -1 ]]; then
    if [[ "$(uname -s)" == "Linux" ]]; then
        _do_sb=0
        if [[ "$WITH_SANDBOX" -eq 1 ]]; then
            _do_sb=1
        else
            printf '  %sInstall bubblewrap now? protects this PC when volunteering [Y/n] %s' "$BLD" "$RST"
            _ans=""
            read -r _ans </dev/tty || _ans=""
            [[ "$_ans" =~ ^[Nn] ]] || _do_sb=1
        fi
        if [[ "$_do_sb" -eq 1 ]]; then
            _install_sandbox || true
        else
            printf '  %sskipped — `blnq volunteer on` will be refused until a sandbox exists%s\n' "$DIM" "$RST"
        fi
    else
        _install_sandbox || true   # macOS: prints the routes only
    fi
fi

# docker tier: pre-pull the default image so the first job isn't a cold pull
if [[ "$SANDBOX" == "docker" ]] && ! docker image inspect python:3.12-alpine >/dev/null 2>&1; then
    printf '  %spulling python:3.12-alpine for the docker sandbox…%s\n' "$DIM" "$RST"
    docker pull python:3.12-alpine >/dev/null 2>&1 || _warn "image pull failed — the agent will retry on first job"
fi

# ── systemd service (runs by default when sudo is available) ────────────
if [[ "$WITH_SERVICE" -eq 1 ]]; then
    if [[ -n "$SUDO" ]]; then
        _log "setting up background service"
        SERVICE_FILE="$LIB_DIR/${APP}-website.service"
        dl "$HUB/${APP}-website.service" "$SERVICE_FILE"
        $SUDO tee /etc/systemd/system/${APP}-website.service < "$SERVICE_FILE" > /dev/null
        $SUDO systemctl daemon-reload
        $SUDO systemctl enable --now ${APP}-website
        _say "background service active"
    fi
fi

# ── PATH handling ─────────────────────────────────────────────────────
NEEDS_PATH=0
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then NEEDS_PATH=1; fi

RC_FILE=""
if [[ "$NEEDS_PATH" -eq 1 ]] && [[ "$NO_PATH" -eq 0 ]]; then
    case "${SHELL:-/bin/bash}" in
        */zsh)  RC_FILE="$HOME/.zshrc" ;;
        */fish) RC_FILE="$HOME/.config/fish/config.fish" ;;
        *)      RC_FILE="$HOME/.bashrc" ;;
    esac
fi

# ── success card ──────────────────────────────────────────────────────
SUCCESS_BAR="${GRN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
printf '\n  %s\n' "$SUCCESS_BAR"
printf '  %s%s✓ %s CLI installed%s\n' "$BLD" "$GRN" "$APP" "$RST"
printf '  %s\n\n' "$SUCCESS_BAR"

printf '  %slocation%s\n' "$BLD" "$RST"
printf '    wrapper   %s%s%s\n' "$CYN" "$WRAPPER" "$RST"
printf '    client    %s%s%s\n' "$CYN" "$CLIENT_FILE" "$RST"
printf '    config    %s%s/%s/%s%s\n' "$DIM" "$HOME" ".config" "$APP" "$RST"
printf '    state     %s%s/%s/share/%s%s\n' "$DIM" "$HOME" ".local" "$APP" "$RST"
printf '\n'

printf '  %stry it now%s\n' "$BLD" "$RST"
printf '    %s$%s %s%s --help%s               list every subcommand\n'              "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s hi%s                   friendly first-run greeter\n'      "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s review FILE%s         scan + collect validator signatures\n' "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s verify FILE%s         check signatures locally (exit 0 = ok)\n' "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s graph stats%s         knowledge graph snapshot\n'        "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s graph search "x"%s    semantic search the graph\n'       "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s start%s                launch the local agent\n'          "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '    %s$%s %s%s doctor%s               full health report (pasteable)\n' "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '\n'

printf '  %sbonus%s\n' "$BLD" "$RST"
printf '    %s$%s echo "print(1+1)" > /tmp/x.py && %s%s /tmp/x.py%s\n' "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '      %s(scan → upload → run → stream output)%s\n' "$DIM" "$RST"
printf '    %s$%s %s%s scan /tmp/x.py%s         just scan, no upload\n'           "$DIM" "$RST" "$BLD" "$APP" "$RST"
printf '\n'

# ── optional: install LLM backend (llama.cpp preferred, ollama alternative) ─
should_install_llm() {
  [[ "$WITH_LLM" -eq  1 ]] && return 0
  [[ "$WITH_LLM" -eq -1 ]] && return 1
  [[ -t 0 ]] || return 1
  printf '  %sAlso install a local LLM backend? [y/N] %s' "$BLD" "$RST"
  local ans=""
  read -r ans </dev/tty || return 1
  [[ "$ans" =~ ^[Yy] ]]
}

if should_install_llm; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) export PATH="$BIN_DIR:$PATH" ;;
  esac

  printf '\n  %s%s⌨️  %s local LLM setup%s\n\n' "$BLD" "$BLNQ" "$APP" "$RST"
  printf '  %schoose your backend:%s\n' "$BLD" "$RST"
  printf '    %s1)%s llama.cpp  %s← preferred%s\n' "$GRN" "$RST" "$DIM" "$RST"
  printf '       · handles many concurrent requests efficiently\n'
  printf '       · lower memory usage than full Ollama\n'
  printf '       · Ollama runs llama.cpp internally anyway\n'
  printf '    %s2)%s Ollama      %s← alternative, runs one instance at a time%s\n\n' "$CYN" "$RST" "$DIM" "$RST"

  HAVE_LLAMA=0
  HAVE_OLLAMA=0
  LLAMA_BIN=""

  if command -v llama-cli >/dev/null 2>&1 || command -v llama-server >/dev/null 2>&1 || command -v llama >/dev/null 2>&1; then
    HAVE_LLAMA=1
    _say "llama.cpp already installed"
  fi

  if command -v ollama >/dev/null 2>&1; then
    HAVE_OLLAMA=1
    _say "ollama already installed"
  fi

  if [[ "$HAVE_LLAMA" -eq 0 ]] && [[ "$HAVE_OLLAMA" -eq 0 ]]; then
    printf '  %s📦%s installing llama.cpp for ${ACCENT}$(uname -s)${RST}...\n\n' "$BLD" "$BLNQ" "$RST"
    ARCH=$(uname -m)
    case "$(uname -s)" in
      Linux)
        case "$ARCH" in
          x86_64)  ASSET="llama-linux-x64.tar.gz" ;;
          aarch64|arm64) ASSET="llama-linux-arm64.tar.gz" ;;
          *) _warn "unsupported arch: $ARCH — download from https://github.com/ggerganov/llama.cpp/releases";;
        esac
        if [[ -n "$ASSET" ]]; then
          _spin "downloading llama.cpp" curl -fsSL "https://github.com/ggerganov/llama.cpp/releases/latest/download/$ASSET" -o /tmp/llama.tar.gz
          _spin "extracting" tar -xzf /tmp/llama.tar.gz -C /tmp
          LLAMA_BIN=$(find /tmp -name 'llama-cli' -o -name 'llama-server' 2>/dev/null | head -1)
          if [[ -n "$LLAMA_BIN" ]] && [[ -f "$LLAMA_BIN" ]]; then
            cp "$LLAMA_BIN" "$BIN_DIR/llama"
            chmod +x "$BIN_DIR/llama"
            _say "installed ${ACCENT}llama.cpp${RST} → ${ACCENT}$BIN_DIR/llama${RST}"
            HAVE_LLAMA=1
          fi
          rm -f /tmp/llama.tar.gz
        fi
        ;;
      Darwin)
        if need brew && brew list llama 2>/dev/null; then
          HAVE_LLAMA=1
          _say "llama.cpp via homebrew"
        else
          _warn "on macOS: brew install llama.cpp  %sor download from https://github.com/ggerganov/llama.cpp/releases"
        fi
        ;;
      *)
        _warn "unsupported platform — download from https://github.com/ggerganov/llama.cpp/releases"
        ;;
    esac
  fi

  LLM_MODEL=$("$APP" llm suggest --json 2>/dev/null \
    | "$PYTHON_BIN" -c 'import json,sys; print(json.load(sys.stdin).get("primary","gemma4:e2b"))' 2>/dev/null \
    || echo "gemma4:e2b")

  if [[ "$HAVE_LLAMA" -eq 1 ]]; then
    printf '\n  %s📦%s downloading model %s%s%s via huggingface%s\n\n' "$BLD" "$BLNQ" "$ACCENT" "$LLM_MODEL" "$RST" "$RST"
    MODEL_DIR="${HOME}/.local/share/${APP}/models"
    $SUDO mkdir -p "$MODEL_DIR" 2>/dev/null || mkdir -p "$MODEL_DIR"
    HF_URL="https://huggingface.co/$LLM_MODEL/resolve/main/$LLM_MODEL.gguf"
    if _spin "downloading ${ACCENT}${LLM_MODEL}.gguf${RST}" curl -fsSL --connect-timeout 30 --max-time 600 "$HF_URL" -o "${MODEL_DIR}/${LLM_MODEL}.gguf" 2>/dev/null; then
      _say "model saved to ${ACCENT}${MODEL_DIR}/${LLM_MODEL}.gguf${RST}"
      printf '\n  %s✓%s run locally:  %s%s chat "hello" --local%s\n' "$GRN" "$RST" "$CYN" "$APP" "$RST"
    else
      _warn "download failed — check your internet connection or try manually:"
      printf '    curl -fsSL %s -o %s\n' "$HF_URL" "${MODEL_DIR}/${LLM_MODEL}.gguf"
    fi
    printf '  %s✓%s more info:  %s%s llm status%s\n\n' "$GRN" "$RST" "$CYN" "$APP" "$RST"

  elif [[ "$HAVE_OLLAMA" -eq 1 ]]; then
    printf '\n  %s📦%s pulling model %s%s%s via ollama%s\n\n' "$BLD" "$CYN" "$ACCENT" "$LLM_MODEL" "$RST" "$RST"
    if ollama pull "$LLM_MODEL" 2>/dev/null; then
      _say "pulled ${ACCENT}${LLM_MODEL}${RST}"
    else
      _warn "pull failed — retry with: ollama pull ${LLM_MODEL}"
    fi
    printf '\n  %s✓%s run locally:  %s%s chat "hello" --local%s\n' "$GRN" "$RST" "$CYN" "$APP" "$RST"
    printf '  %s✓%s more info:  %s%s llm status%s\n\n' "$GRN" "$RST" "$CYN" "$APP" "$RST"
  else
    _warn "no LLM backend installed — ${APP} will use the API gateway"
    printf '    %sto install later:%s curl -sSL %s/install-%s.sh | bash -s -- --with-llm\n' "$DIM" "$RST" "$HUB" "$APP"
    printf '    %sor manually:%s https://ollama.com/download  ·  https://github.com/ggerganov/llama.cpp/releases\n\n'
  fi
fi

# ── PATH advice ──────────────────────────────────────────────────────
# `curl | bash` runs in a subshell: any `export PATH` here dies with it. The only
# way to make `blnq` findable is to PERSIST the change, then say how to load it.
# This wrote to the rc file only under --yes, so a plain `curl -sSL … | bash`
# printed advice, declared success, and left `blnq` unfindable.
PATH_STATE="already on PATH"
if [[ "$NEEDS_PATH" -eq 1 ]]; then
    PATH_STATE="NOT on PATH"
    if [[ "$NO_PATH" -eq 0 ]] && [[ -n "$RC_FILE" ]]; then
        mkdir -p "$(dirname "$RC_FILE")" 2>/dev/null || true
        if grep -qF "$BIN_DIR" "$RC_FILE" 2>/dev/null; then
            PATH_STATE="added earlier"
        else
            case "$RC_FILE" in
                */config.fish) _pline="fish_add_path $BIN_DIR" ;;
                *) _pline=$(printf 'case ":$PATH:" in *":%s:"*) ;; *) export PATH="%s:$PATH" ;; esac' "$BIN_DIR" "$BIN_DIR") ;;
            esac
            if printf '\n# blnq CLI - added by the installer\n%s\n' "$_pline" >> "$RC_FILE" 2>/dev/null; then
                PATH_STATE="added to $RC_FILE"
            fi
        fi
    fi
fi
printf '  %spaths   %s %s\n' "$BLD" "$RST" "$PATH_STATE"
if [[ "$NEEDS_PATH" -eq 1 && "$PATH_STATE" == "NOT on PATH" ]]; then
    printf '    %sadd it for this shell:\n' "$DIM"
    printf '      %sexport PATH="%s:$PATH"%s\n' "$CYN" "$BIN_DIR" "$RST"
    printf '    %s\n' "$RST"
fi

# ── post-install verification ──────────────────────────────────────────
printf '\n'
printf '  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLNQ" "$RST"
printf '  %s  ⚡ VERIFICATION — making sure everything is connected ⚡%s\n' "$BLD" "$RST"
printf '  %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$BLNQ" "$RST"

HUB_OK=0
if need curl; then
    if curl -fsSL --connect-timeout 5 --max-time 10 "$HUB/api/health" > /dev/null 2>&1; then
        HUB_OK=1
    fi
elif need wget; then
    if wget -q --timeout=10 -O - "$HUB/api/health" > /dev/null 2>&1; then
        HUB_OK=1
    fi
fi

# ── verify the CLI is actually runnable ────────────────────────────────
# The old verification probed only the HUB over the network, then declared
# "blnq is live on your machine!" — without ever checking the command was on
# PATH. It wasn't, which is how a fresh install ends in "blnq: command not found".
CLI_OK=0; CLI_WHY=""
if command -v blnq >/dev/null 2>&1; then
    CLI_OK=1
elif [[ -x "$WRAPPER" ]]; then
    CLI_WHY="$WRAPPER exists but its directory is not on PATH"
elif [[ -x "$BIN_DIR/blnq" ]]; then
    CLI_WHY="$BIN_DIR exists but is not on PATH"
else
    CLI_WHY="wrapper missing at $WRAPPER"
fi

if [[ "$CLI_OK" -eq 1 ]]; then
    printf '  %s✓%s blnq is on your PATH — run it in a moment\n' "$GRN" "$RST"
else
    printf '  %s✗%s blnq is NOT runnable yet — %s\n' "$YLW" "$RST" "$CLI_WHY"
    printf '  %sto fix it right now, run one of these:\n' "$BLD" "$RST"
    if [[ -n "$RC_FILE" && -f "$RC_FILE" ]]; then
        printf '      %ssource %s%s          # then: blnq --help\n' "$CYN" "$RC_FILE" "$RST"
    fi
    printf '      %sexport PATH="%s:$PATH"%s\n' "$CYN" "$BIN_DIR" "$RST"
    printf '      %s# …or simply open a new terminal\n' "$DIM"
fi

if [[ "$HUB_OK" -eq 1 ]]; then
    printf '  %s✓%s %s is reachable — the network is alive!\n' "$GRN" "$RST" "$HUB"
    if [[ -n "$SUDO" ]]; then
        printf '  %s✓%s system-wide install — you are helping ALL users on this machine\n' "$GRN" "$RST"
        printf '  %s✓%s background service is running — blnq works even while you sleep\n' "$GRN" "$RST"
        printf '\n'
        printf '  %s⚡ WOW! system-wide install — your computer is now part of the distributed compute network!%s\n' "$BLNQ$BLD" "$RST"
        printf '  %severyone on this machine benefits · your CPU is contributing to solving real problems!%s\n\n' "$ACCENT" "$RST"
    else
        printf '  %s✓%s you are now connected — ready to help on this machine\n' "$GRN" "$RST"
        printf '\n'
        printf '  %s⚡ you'\''re connected — blnq is live on your machine! ⚡%s\n' "$BLNQ$BLD" "$RST"
        printf '  %supgrade anytime to system-wide (helps everyone) with: sudo curl -sSL %s/install-%s.sh | bash%s\n\n' "$DIM" "$HUB" "$APP" "$RST"
    fi
    printf '  %s🌐 see your node on the network:%s\n' "$BLD" "$RST"
    printf '    %shttps://blnq.org%s\n\n' "$CYN" "$RST"
else
    printf '  %s!%s %s not reachable — check your internet connection\n' "$YLW" "$RST" "$HUB"
    printf '  %sblnq is installed and ready — it will connect automatically when online%s\n' "$DIM" "$RST"
    printf '\n'
fi

# ── footer ────────────────────────────────────────────────────────────
printf '\n'
printf '  %s⚡%s  github.com/htmlfarmer/blnq  ·  %s  ·  support@%s%s\n' \
    "$ACCENT" "$RST" "${APP}.org" "${APP}.org" "$RST"
printf '\n'
