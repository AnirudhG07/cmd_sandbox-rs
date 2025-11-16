#!/bin/bash
# curl_sandbox-rs standalone installer
# Can be run directly via: curl -fsSL https://raw.githubusercontent.com/.../install.sh | bash
# Or downloaded and run locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository info
GITHUB_REPO="AnirudhG07/curl_sandbox-rs"
GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
GITHUB_RELEASES_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     cmd_sandbox-rs Standalone Installer                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to ask for permission
ask_permission() {
    local prompt="$1"
    echo -e "${YELLOW}${prompt}${NC}"
    read -p "Continue? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    return 0
}

# Check if running on Linux
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" != "Linux" ]; then
    echo -e "${RED}Error: This installer only works on Linux${NC}"
    echo -e "${YELLOW}Detected OS: $OS_TYPE${NC}"
    echo ""
    echo "This project requires:"
    echo "  - Linux kernel 5.7+ with BPF LSM support"
    echo "  - cgroup v2"
    echo "  - eBPF capabilities"
    echo ""
    echo "These features are only available on Linux."
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        echo -e "${GREEN}✓ Detected architecture: x86_64${NC}"
        ARCH_SUFFIX="x86_64"
        ;;
    aarch64|arm64)
        echo -e "${GREEN}✓ Detected architecture: ARM64 (aarch64)${NC}"
        ARCH_SUFFIX="aarch64"
        ;;
    *)
        echo -e "${YELLOW}⚠ Detected architecture: $ARCH${NC}"
        echo -e "${YELLOW}  Pre-built binaries may not be available.${NC}"
        echo -e "${YELLOW}  Will attempt to build from source.${NC}"
        ARCH_SUFFIX="unknown"
        ;;
esac

# Display kernel version early
KERNEL_VERSION=$(uname -r)
echo -e "${BLUE}Kernel version: $KERNEL_VERSION${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this installer as root${NC}"
   echo -e "${YELLOW}The installer will ask for sudo when needed${NC}"
   exit 1
fi

# Installation mode selection
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Installation Mode${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Choose installation method:"
echo ""
echo "  1) ${GREEN}Download pre-built binaries${NC} (fastest, recommended)"
echo "     - Quick installation (~5 seconds)"
echo "     - No build tools required"
echo "     - Available for x86_64 and ARM64"
echo ""
echo "  2) ${YELLOW}Build from source${NC} (full control)"
echo "     - Requires Rust toolchain"
echo "     - Takes 10-20 minutes"
echo "     - Best for development"
echo ""

read -p "Select option (1 or 2): " -n 1 -r INSTALL_MODE
echo ""
echo ""

if [[ $INSTALL_MODE == "1" ]]; then
    # ===================================================================
    # OPTION 1: Download pre-built binaries
    # ===================================================================
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Downloading Pre-built Binaries${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check for required tools
    if ! command_exists curl && ! command_exists wget; then
        echo -e "${RED}Error: Neither curl nor wget found${NC}"
        echo "Please install curl or wget first"
        exit 1
    fi
    
    if ! command_exists tar; then
        echo -e "${RED}Error: tar command not found${NC}"
        echo "Please install tar first"
        exit 1
    fi
    
    # Try to get latest release info
    echo -e "${BLUE}Fetching latest release information...${NC}"
    
    if command_exists curl; then
        RELEASE_INFO=$(curl -sL "$GITHUB_RELEASES_URL" 2>/dev/null || echo "")
    else
        RELEASE_INFO=$(wget -qO- "$GITHUB_RELEASES_URL" 2>/dev/null || echo "")
    fi
    
    if [ -z "$RELEASE_INFO" ]; then
        echo -e "${YELLOW}⚠ Could not fetch release information from GitHub${NC}"
        echo -e "${YELLOW}  This might be because:${NC}"
        echo -e "${YELLOW}  - No releases have been published yet${NC}"
        echo -e "${YELLOW}  - Network connectivity issues${NC}"
        echo ""
        echo -e "${YELLOW}Falling back to build from source...${NC}"
        INSTALL_MODE="2"
    else
        # Extract download URL for the appropriate architecture
        DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o "https://.*cmd-sandbox-${ARCH_SUFFIX}.*\.tar\.gz" | head -1)
        
        if [ -z "$DOWNLOAD_URL" ]; then
            echo -e "${YELLOW}⚠ No pre-built binary found for architecture: ${ARCH}${NC}"
            echo -e "${YELLOW}  Falling back to build from source...${NC}"
            INSTALL_MODE="2"
        else
            RELEASE_TAG=$(echo "$RELEASE_INFO" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
            
            echo -e "${GREEN}✓ Found release: $RELEASE_TAG${NC}"
            echo -e "${BLUE}Download URL: $DOWNLOAD_URL${NC}"
            echo ""
            
            # Create temporary directory
            TEMP_DIR=$(mktemp -d)
            cd "$TEMP_DIR"
            
            echo -e "${BLUE}Downloading binaries...${NC}"
            if command_exists curl; then
                curl -fsSL "$DOWNLOAD_URL" -o cmd-sandbox.tar.gz
            else
                wget -q "$DOWNLOAD_URL" -O cmd-sandbox.tar.gz
            fi
            
            echo -e "${BLUE}Extracting...${NC}"
            tar -xzf cmd-sandbox.tar.gz
            
            # Install binaries
            INSTALL_DIR="$HOME/.local/bin"
            mkdir -p "$INSTALL_DIR"
            
            echo -e "${BLUE}Installing binaries to $INSTALL_DIR...${NC}"
            cp cmd-sandbox "$INSTALL_DIR/"
            cp cmd-sandbox-tests "$INSTALL_DIR/"
            chmod +x "$INSTALL_DIR/cmd-sandbox" "$INSTALL_DIR/cmd-sandbox-tests"
            
            # Install test helpers if they exist
            if [ -d "test_helpers" ]; then
                mkdir -p "$HOME/.local/share/cmd-sandbox/test_helpers"
                cp -r test_helpers/* "$HOME/.local/share/cmd-sandbox/test_helpers/"
            fi
            
            # Create wrapper script
            cat > "$INSTALL_DIR/cmd_sandbox" << 'WRAPPER_EOF'
#!/bin/bash
# cmd_sandbox - Wrapper for curl_sandbox-rs

# Colors for output
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

INSTALL_DIR="$HOME/.local/bin"

case "$1" in
    run)
        shift
        if [ "$EUID" -ne 0 ]; then
            echo "Note: Running sandbox requires root privileges"
            exec sudo -E RUST_LOG="${RUST_LOG:-info}" "$INSTALL_DIR/cmd-sandbox" "$@"
        else
            exec "$INSTALL_DIR/cmd-sandbox" "$@"
        fi
        ;;
    test)
        shift
        if ! pgrep -f "cmd-sandbox" > /dev/null 2>&1; then
            echo -e "${RED}Error: Sandbox is not running!${NC}"
            echo ""
            echo "Please start the sandbox first in another terminal:"
            echo -e "  ${BLUE}cmd_sandbox run${NC}"
            echo ""
            echo "Then run tests in this terminal:"
            echo -e "  ${BLUE}cmd_sandbox test${NC}"
            exit 1
        fi
        exec "$INSTALL_DIR/cmd-sandbox-tests" "$@"
        ;;
    build)
        echo -e "${RED}Error: Cannot rebuild - installed from pre-built binaries${NC}"
        echo ""
        echo "To build from source, clone the repository:"
        echo "  git clone https://github.com/AnirudhG07/curl_sandbox-rs.git"
        echo "  cd curl_sandbox-rs"
        echo "  cargo build --release"
        exit 1
        ;;
    help|--help|-h)
        cat << EOF
cmd_sandbox - curl/wget security sandbox

USAGE:
    cmd_sandbox <COMMAND> [OPTIONS]

COMMANDS:
    run         Run the sandbox (requires root)
                Environment: RUST_LOG=info for verbose output
    
    test        Run all policy tests
                Note: Sandbox must be running first (use 'cmd_sandbox run' in another terminal)
    
    help        Show this help message

EXAMPLES:
    # Terminal 1: Start the sandbox
    cmd_sandbox run
    
    # Terminal 2: Run tests
    cmd_sandbox test
    
    # Start with debug logging
    RUST_LOG=debug cmd_sandbox run

For more information, visit:
https://github.com/AnirudhG07/curl_sandbox-rs
EOF
        ;;
    *)
        echo "cmd_sandbox: unknown command '$1'"
        echo "Run 'cmd_sandbox help' for usage information"
        exit 1
        ;;
esac
WRAPPER_EOF
            
            chmod +x "$INSTALL_DIR/cmd_sandbox"
            
            # Cleanup
            cd /
            rm -rf "$TEMP_DIR"
            
            echo ""
            echo -e "${GREEN}✓ Installation complete!${NC}"
        fi
    fi
fi

if [[ $INSTALL_MODE == "2" ]]; then
    # ===================================================================
    # OPTION 2: Build from source
    # ===================================================================
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Building from Source${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Download the full install script from GitHub and execute
    echo -e "${BLUE}Downloading build installer...${NC}"
    
    TEMP_INSTALL_SCRIPT=$(mktemp)
    
    if command_exists curl; then
        curl -fsSL "${GITHUB_RAW_URL}/install-build.sh" -o "$TEMP_INSTALL_SCRIPT"
    elif command_exists wget; then
        wget -qO "$TEMP_INSTALL_SCRIPT" "${GITHUB_RAW_URL}/install-build.sh"
    else
        echo -e "${RED}Error: Neither curl nor wget found${NC}"
        exit 1
    fi
    
    chmod +x "$TEMP_INSTALL_SCRIPT"
    
    echo -e "${BLUE}Running build installer...${NC}"
    echo ""
    
    exec bash "$TEMP_INSTALL_SCRIPT"
    
    # Cleanup happens via exec, script ends here
fi

# Final instructions (only reached if pre-built binary install succeeded)
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}⚠ $HOME/.local/bin is not in your PATH${NC}"
    echo -e "${YELLOW}  Add this line to your ~/.bashrc or ~/.zshrc:${NC}"
    echo -e "${YELLOW}  export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
    echo -e "${YELLOW}  Then run: source ~/.bashrc (or ~/.zshrc)${NC}"
    echo ""
fi

echo -e "${BLUE}The 'cmd_sandbox' command is now available!${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
echo -e "  ${GREEN}cmd_sandbox run${NC}      # Start the sandbox"
echo -e "  ${GREEN}cmd_sandbox test${NC}     # Run all tests"
echo -e "  ${GREEN}cmd_sandbox help${NC}     # Show help"
echo ""
echo -e "${BLUE}Quick start:${NC}"
echo -e "  1. Terminal 1: ${GREEN}cmd_sandbox run${NC}"
echo -e "  2. Terminal 2: ${GREEN}curl https://example.com${NC}"
echo -e "  3. Or run tests: ${GREEN}cmd_sandbox test${NC}"
echo ""
echo -e "${YELLOW}Note: Sandbox requires BPF LSM enabled in your kernel${NC}"
echo -e "${YELLOW}Check with: cat /sys/kernel/security/lsm | grep bpf${NC}"
echo ""
