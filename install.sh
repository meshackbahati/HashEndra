#!/usr/bin/env bash
#
# HashEndra installer — fetches a prebuilt release binary when one exists
# for your OS, otherwise builds from source.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
#   bash install.sh [--version 2.0.0] [--prefix /usr/local] [--keep] [--from-source] [--uninstall]
#
# Options:
#   --version VER   Install a specific release (default: latest)
#   --prefix DIR    Install binary to DIR/bin (default: /usr/local, ~/.local fallback)
#   --keep          Keep downloaded/cloned files after installation
#   --from-source   Skip prebuilt binaries; clone and cargo build instead
#   --uninstall     Remove HashEndra binary and exit
#
set -eo pipefail

REPO="meshackbahati/HashEndra"
VERSION=""
INSTALL_PREFIX=""
KEEP_FILES=false
FROM_SOURCE=false
DO_UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --keep) KEEP_FILES=true; shift ;;
        --from-source) FROM_SOURCE=true; shift ;;
        --uninstall) DO_UNINSTALL=true; shift ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]:-$0}"; exit 0 ;;
        *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
    esac
done

log()  { printf '%s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ----- Uninstall -----------------------------------------------------------
if $DO_UNINSTALL; then
    for dir in /usr/local/bin "$HOME/.local/bin" "$HOME/bin" "$HOME/.cargo/bin"; do
        for bin in "$dir/hashendra" "$dir/hashendra.exe"; do
            if [[ -f "$bin" ]]; then
                rm -f "$bin"
                log "[+] Removed $bin"
            fi
        done
    done
    log "[+] HashEndra uninstalled."
    exit 0
fi

cat << "EOF"
  ___ ___  __  __  __ _  _ __   __ _  __ _  ___   ___
 / _ \ _ \/  \|  \|  \| |/ _ \ / _| |/ _| |/ _ \ / _ \
| (_)  __/ () | |) | |) | (_) | (_| | (_| | (_) | (_) |
 \___\___|\__/|___/|___/ \___/ \__,_|\__,_|\___/ \___/
          identify hashes - decode strings - carve files
EOF

# ----- Detect platform -----------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"
log "[*] Detected: $OS $ARCH"

EXT="tar.gz"
case "$OS" in
    Linux)  TRIPLE_OS="unknown-linux-gnu" ;;
    Darwin) TRIPLE_OS="apple-darwin" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        TRIPLE_OS="pc-windows-msvc"
        EXT="zip"
        ;;
    *)
        log "[!] Unsupported OS for prebuilt binaries: $OS"
        TRIPLE_OS=""
        ;;
esac

case "$ARCH" in
    x86_64|amd64) TRIPLE_ARCH="x86_64" ;;
    arm64|aarch64) TRIPLE_ARCH="aarch64" ;;
    *)
        log "[!] Unsupported architecture for prebuilt binaries: $ARCH"
        TRIPLE_ARCH=""
        ;;
esac

ASSET=""
if [[ -n "$TRIPLE_OS" && -n "$TRIPLE_ARCH" ]]; then
    # If an older release lacks this asset the download 404s and we fall
    # back to a source build automatically.
    ASSET="hashendra-${TRIPLE_ARCH}-${TRIPLE_OS}.${EXT}"
fi
# Windows binary name inside the archive.
BIN_NAME="hashendra"
[[ "$EXT" == "zip" ]] && BIN_NAME="hashendra.exe"

# ----- Resolve version -----------------------------------------------------
if [[ -z "$VERSION" ]]; then
    if have curl; then
        VERSION="$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/')"
    elif have wget; then
        VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/')"
    fi
    if [[ -z "$VERSION" ]]; then
        log "[!] Could not determine latest release (need curl or wget). Falling back to source build."
        FROM_SOURCE=true
    else
        log "[*] Latest release: v${VERSION}"
    fi
else
    # Accept "2.0.0" or "v2.0.0".
    VERSION="${VERSION#v}"
    log "[*] Requested release: v${VERSION}"
fi

# ----- Install locations ---------------------------------------------------
case "$OS" in
    Linux|Darwin) DEFAULT_PREFIX="/usr/local" ;;
    *)            DEFAULT_PREFIX="$HOME/.local" ;;
esac
INSTALL_PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"
INSTALL_DIR="$INSTALL_PREFIX/bin"
mkdir -p "$INSTALL_DIR" 2>/dev/null || {
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    log "[!] Cannot write to $INSTALL_PREFIX/bin, using $INSTALL_DIR"
}

install_binary() {
    # $1 = file to install
    local src="$1" dest="$INSTALL_DIR/hashendra"
    [[ "$EXT" == "zip" ]] && dest="$INSTALL_DIR/hashendra.exe"
    cp "$src" "$dest"
    chmod +x "$dest" 2>/dev/null || true
    log "[+] Installed to $dest"
}

verify_binary() {
    if [[ -x "$INSTALL_DIR/hashendra" ]]; then
        "$INSTALL_DIR/hashendra" --version 2>/dev/null || true
    elif [[ -x "$INSTALL_DIR/hashendra.exe" ]]; then
        "$INSTALL_DIR/hashendra.exe" --version 2>/dev/null || true
    fi
}

advise_path() {
    if [[ ":$PATH:" == *":$INSTALL_DIR:"* ]]; then
        return
    fi
    log ""
    log "[!] $INSTALL_DIR is not in your PATH."
    log "    Add this to ~/.bashrc or ~/.zshrc:"
    log "    export PATH=\"\$PATH:$INSTALL_DIR\""
}

# ----- Try prebuilt binary -------------------------------------------------
download_asset() {
    # $1 = url, $2 = output file. Returns 0 on success.
    if have curl; then
        curl -fSL --retry 2 -o "$2" "$1"
    elif have wget; then
        wget -O "$2" "$1"
    else
        return 1
    fi
}

WORKDIR="$(mktemp -d)"
cleanup() {
    if ! $KEEP_FILES; then
        rm -rf "$WORKDIR"
    else
        log "[*] Kept working files in $WORKDIR"
    fi
}
trap cleanup EXIT

INSTALLED=false
if ! $FROM_SOURCE && [[ -n "$ASSET" && -n "$VERSION" ]]; then
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"
    ARCHIVE="$WORKDIR/$ASSET"
    log "[*] Downloading $ASSET ..."
    if download_asset "$URL" "$ARCHIVE"; then
        if [[ "$EXT" == "zip" ]]; then
            if have unzip; then
                unzip -o -q "$ARCHIVE" -d "$WORKDIR/pkg"
            elif have 7z; then
                7z x -y -o"$WORKDIR/pkg" "$ARCHIVE" >/dev/null
            elif have powershell.exe; then
                powershell.exe -NoProfile -Command "Expand-Archive -Force '$ARCHIVE' '$WORKDIR/pkg'"
            else
                log "[!] No unzip tool found (need unzip, 7z, or PowerShell)."
            fi
        else
            tar -xzf "$ARCHIVE" -C "$WORKDIR"
            mkdir -p "$WORKDIR/pkg" && mv "$WORKDIR"/hashendra-*/hashendra "$WORKDIR/pkg/" 2>/dev/null \
                || mv "$WORKDIR"/hashendra "$WORKDIR/pkg/" 2>/dev/null || true
        fi
        FOUND="$(find "$WORKDIR/pkg" -name "$BIN_NAME" 2>/dev/null | head -n 1)"
        if [[ -n "$FOUND" ]]; then
            install_binary "$FOUND"
            INSTALLED=true
        else
            log "[!] Archive did not contain $BIN_NAME. Falling back to source build."
        fi
    else
        log "[!] No prebuilt binary for this platform/release (or no network). Falling back to source build."
    fi
fi

# ----- Fallback: build from source -----------------------------------------
if ! $INSTALLED; then
    if ! $FROM_SOURCE; then
        log "[*] Building from source instead."
    fi
    for dep in git cargo rustc; do
        if ! have "$dep"; then
            if [[ "$dep" == "git" ]]; then
                log "[!] git is required for source builds. Install git and rerun."; exit 1
            fi
            log "[!] Rust ($dep) not found. Installing rustup..."
            if have curl; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            elif have wget; then
                wget -qO- https://sh.rustup.rs | sh -s -- -y
            else
                log "[!] Need curl or wget to install Rust."; exit 1
            fi
            # shellcheck disable=SC1091
            [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        fi
    done
    export PATH="$HOME/.cargo/bin:$PATH"
    SRC="$WORKDIR/src"
    git clone --depth 1 --branch "v${VERSION:-main}" "https://github.com/${REPO}.git" "$SRC" 2>/dev/null \
        || git clone --depth 1 "https://github.com/${REPO}.git" "$SRC"
    BIN_NAME="hashendra"
    EXT="tar.gz"
    (cd "$SRC" && cargo build --release --locked)
    install_binary "$SRC/target/release/hashendra"
    INSTALLED=true
fi

# ----- Finish ---------------------------------------------------------------
if $INSTALLED; then
    verify_binary
    advise_path
    log ""
    log "[*] Try: hashendra \"5d41402abc4b2a76b9719d911017c592\""
    log "[+] Done."
else
    log "[!] Installation failed."
    exit 1
fi
