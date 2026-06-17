#!/usr/bin/env bash
#
# HashEndra Installation Script
# Author: Meshack Bahati
# GitHub: https://github.com/meshackbahati/HashEndra
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/meshackbahati/HashEndra/main/install.sh | bash
#   bash install.sh [--keep] [--prefix /usr/local] [--uninstall]
#
# Options:
#   --keep          Keep the cloned repository after installation
#   --prefix DIR    Install binary to DIR/bin (default: /usr/local)
#   --uninstall     Remove HashEndra binary and exit

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

KEEP_REPO=false
INSTALL_PREFIX=""
DO_UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep) KEEP_REPO=true; shift ;;
        --prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --uninstall) DO_UNINSTALL=true; shift ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# ----- Uninstall -----------------------------------------------------------
if $DO_UNINSTALL; then
    for dir in /usr/local/bin "$HOME/.local/bin" "$HOME/bin"; do
        if [[ -f "$dir/hashendra" ]]; then
            rm -f "$dir/hashendra"
            echo -e "${GREEN}[+] Removed hashendra from $dir${NC}"
        fi
    done
    echo -e "${GREEN}[+] HashEndra uninstalled.${NC}"
    exit 0
fi

# ----- Banner --------------------------------------------------------------
cat << "EOF"
  ___ ___  __  __  __ _  _ __   __ _  __ _  ___   ___
 / _ \ _ \/  \|  \|  \| |/ _ \ / _| |/ _| |/ _ \ / _ \
| (_)  __/ () | |) | |) | (_) | (_| | (_| | (_) | (_) |
 \___\___|\__/|___/|___/ \___/ \__,_|\__,_|\___/ \___/
              Universal Forensic Decryption Engine
EOF
echo -e "${BLUE}------------------------------------------------------------------${NC}"
echo -e "${BLUE}                     Installing HashEndra                         ${NC}"
echo -e "${BLUE}              The Universal Forensic Decryption Engine            ${NC}"
echo -e "${BLUE}                 Author: Meshack Bahati                           ${NC}"
echo -e "${BLUE}------------------------------------------------------------------${NC}"

# ----- OS Detection --------------------------------------------------------
OS="$(uname -s)"
ARCH="$(uname -m)"

echo -e "${BLUE}[*] Detected: $OS $ARCH${NC}"

case "$OS" in
    Linux)
        DEFAULT_PREFIX="/usr/local"
        SH_PATH_BASHRC="$HOME/.bashrc"
        SH_PATH_ZSH="$HOME/.zshrc"
        SUDO="sudo"
        ;;
    Darwin)
        DEFAULT_PREFIX="/usr/local"
        SH_PATH_BASHRC="$HOME/.bash_profile"
        SH_PATH_ZSH="$HOME/.zshrc"
        SUDO="sudo"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo -e "${YELLOW}[!] Windows detected (MSYS2/MinGW). Installing to %USERPROFILE%\\.cargo\\bin${NC}"
        DEFAULT_PREFIX="$HOME/.cargo"
        SH_PATH_BASHRC="$HOME/.bashrc"
        SUDO=""
        ;;
    *)
        echo -e "${YELLOW}[!] Unknown OS: $OS. Falling back to user install.${NC}"
        DEFAULT_PREFIX="$HOME/.local"
        SH_PATH_BASHRC="$HOME/.bashrc"
        SH_PATH_ZSH="$HOME/.zshrc"
        SUDO=""
        ;;
esac

INSTALL_PREFIX="${INSTALL_PREFIX:-$DEFAULT_PREFIX}"
INSTALL_DIR="$INSTALL_PREFIX/bin"

# ----- Locate source directory -------------------------------------------
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != bash ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
fi
IN_REPO=false
if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Cargo.toml" ]] && grep -q 'name = "hashendra"' "$SCRIPT_DIR/Cargo.toml" 2>/dev/null; then
    IN_REPO=true
    REPO_DIR="$SCRIPT_DIR"
fi

TEMP_DIR=""
if ! $IN_REPO; then
    echo -e "${BLUE}[*] Cloning from GitHub...${NC}"
    if ! command -v git &>/dev/null; then
        echo -e "${RED}[!] Git is required. Please install git first.${NC}"
        exit 1
    fi
    TEMP_DIR="$(mktemp -d)"
    git clone --depth 1 https://github.com/meshackbahati/HashEndra.git "$TEMP_DIR" 2>&1
    REPO_DIR="$TEMP_DIR"
    cd "$REPO_DIR"
else
    echo -e "${GREEN}[+] Found local repository at $REPO_DIR${NC}"
    cd "$REPO_DIR"
fi

# ----- Install Rust if missing --------------------------------------------
if ! command -v rustc &>/dev/null; then
    echo -e "${YELLOW}[!] Rust is not installed. Installing rustup (non-interactive)...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>&1
    # Source it for this script
    if [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    elif [[ -f "$HOME/.cargo/env" ]]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    fi
    echo -e "${GREEN}[+] Rust installed: $(rustc --version)${NC}"
else
    echo -e "${GREEN}[+] Rust $(rustc --version)${NC}"
fi

if ! command -v cargo &>/dev/null; then
    echo -e "${RED}[!] Cargo not found. Ensure ~/.cargo/bin is in your PATH.${NC}"
    echo -e "${YELLOW}[*] Run: source \$HOME/.cargo/env${NC}"
    exit 1
fi

# ----- Build ---------------------------------------------------------------
echo -e "${BLUE}[*] Building HashEndra (release mode)...${NC}"
cargo build --release 2>&1
echo -e "${GREEN}[+] Build successful.${NC}"

# ----- Install binary ------------------------------------------------------
mkdir -p "$INSTALL_DIR"

if cp target/release/hashendra "$INSTALL_DIR/hashendra"; then
    echo -e "${GREEN}[+] Installed to $INSTALL_DIR/hashendra${NC}"

    # Try system-wide symlink if we used sudo and prefix is /usr/local
    if [[ "$INSTALL_PREFIX" == "/usr/local" ]] && command -v sudo &>/dev/null; then
        # Already installed directly there via cp above
        true
    fi

    # ----- PATH advice ------------------------------------------------------
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        echo -e "${YELLOW}[!] $INSTALL_DIR is not in your PATH.${NC}"
        echo -e "${BLUE}[*] Add one of the following lines to your shell profile:${NC}"
        case "$OS" in
            Linux|Darwin)
                echo -e "    export PATH=\"\$PATH:$INSTALL_DIR\"  # add to ${CYAN}~/.bashrc${NC} or ${CYAN}~/.zshrc${NC}"
                ;;
            MINGW*|MSYS*|CYGWIN*)
                echo -e "    export PATH=\"\$PATH:$INSTALL_DIR\"  # add to ${CYAN}~/.bashrc${NC}"
                ;;
        esac
        echo ""
        # Offer to add it automatically
        if [[ -t 0 ]]; then
            echo -ne "${BLUE}[?] Automatically add to PATH? [Y/n] ${NC}"
            read -r answer
            if [[ -z "$answer" || "$answer" =~ ^[Yy] ]]; then
                for rc in "$SH_PATH_BASHRC" "$SH_PATH_ZSH"; do
                    if [[ -f "$rc" ]]; then
                        echo "" >> "$rc"
                        echo "# Added by HashEndra installer" >> "$rc"
                        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$rc"
                        echo -e "${GREEN}[+] Added to $rc${NC}"
                    fi
                done
            fi
        fi
    fi

    echo ""
    echo -e "${BLUE}[*] Quick test: ${GREEN}hashendra --help${NC}"
    echo -e "${BLUE}[*] Example:    ${GREEN}hashendra \"5d41402abc4b2a76b9719d911017c592\"${NC}"
    echo ""
else
    echo -e "${RED}[!] Failed to copy binary. Trying without sudo...${NC}"
    if cp target/release/hashendra "$HOME/.local/bin/hashendra" 2>/dev/null; then
        INSTALL_DIR="$HOME/.local/bin"
        echo -e "${GREEN}[+] Installed to $INSTALL_DIR/hashendra${NC}"
    else
        mkdir -p "$HOME/bin"
        cp target/release/hashendra "$HOME/bin/hashendra"
        INSTALL_DIR="$HOME/bin"
        echo -e "${GREEN}[+] Installed to $INSTALL_DIR/hashendra${NC}"
    fi
fi

# ----- Cleanup -------------------------------------------------------------
if [[ -n "$TEMP_DIR" ]] && ! $KEEP_REPO; then
    echo -e "${BLUE}[*] Cleaning up temporary files...${NC}"
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}[+] Temporary repository removed.${NC}"
elif $IN_REPO && ! $KEEP_REPO; then
    echo ""
    echo -e "${YELLOW}[!] You ran the installer from inside the repository.${NC}"
    echo -e "${YELLOW}[!] The source files were NOT deleted. Delete them manually if desired:${NC}"
    echo -e "    rm -rf \"$REPO_DIR\""
fi

echo -e "${GREEN}Installation Complete!${NC}"
