#!/bin/bash
# cmd_sandbox-rs installer
# Downloads and installs pre-built binaries from GitHub releases
# Can be run directly via: curl -fsSL https://raw.githubusercontent.com/AnirudhG07/cmd_sandbox-rs/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub repository info
GITHUB_REPO="AnirudhG07/cmd_sandbox-rs"
GITHUB_RELEASES_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/nightly"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     cmd_sandbox-rs Installer                                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running on Linux
OS_TYPE=$(uname -s)
if [ "$OS_TYPE" != "Linux" ]; then
    echo -e "${RED}Error: This installer only works on Linux${NC}"
    echo -e "${YELLOW}Detected OS: $OS_TYPE${NC}"
    echo ""
    echo "This project requires Linux kernel 5.7+ with BPF LSM support."
    exit 1
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this installer as root${NC}"
   echo -e "${YELLOW}The installer will ask for sudo when needed${NC}"
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
        echo -e "${RED}✗ Unsupported architecture: $ARCH${NC}"
        echo -e "${YELLOW}Pre-built binaries are only available for x86_64 and ARM64${NC}"
        echo ""
        echo "To build from source:"
        echo "  git clone https://github.com/AnirudhG07/cmd_sandbox-rs.git"
        echo "  cd cmd_sandbox-rs"
        echo "  cargo build --release"
        exit 1
        ;;
esac

KERNEL_VERSION=$(uname -r)
echo -e "${BLUE}Kernel version: $KERNEL_VERSION${NC}"
echo ""

# Check for REQUIRED dependencies
echo -e "${BLUE}[1/3] Checking required dependencies...${NC}"

MISSING_DEPS=()

if ! command_exists curl && ! command_exists wget; then
    MISSING_DEPS+=("curl or wget")
fi

if ! command_exists tar; then
    MISSING_DEPS+=("tar")
fi

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "${RED}✗ Missing required dependencies:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo -e "  ${RED}✗${NC} $dep"
    done
    echo ""
    echo -e "${YELLOW}Please install the missing dependencies and try again.${NC}"
    echo ""
    echo "On Debian/Ubuntu:"
    echo "  sudo apt update && sudo apt install -y curl tar"
    echo ""
    echo "On Fedora/RHEL:"
    echo "  sudo dnf install -y curl tar"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ All required dependencies found${NC}"
echo ""

# Download pre-built binaries
echo -e "${BLUE}[2/3] Downloading pre-built binaries from GitHub (nightly release)...${NC}"

# Try to get nightly release info
if command_exists curl; then
    RELEASE_INFO=$(curl -sL "$GITHUB_RELEASES_URL" 2>/dev/null || echo "")
else
    RELEASE_INFO=$(wget -qO- "$GITHUB_RELEASES_URL" 2>/dev/null || echo "")
fi

if [ -z "$RELEASE_INFO" ]; then
    echo -e "${RED}✗ Could not fetch nightly release information from GitHub${NC}"
    echo -e "${YELLOW}This might be because:${NC}"
    echo -e "${YELLOW}  - Nightly build hasn't been published yet${NC}"
    echo -e "${YELLOW}  - Network connectivity issues${NC}"
    echo ""
    echo "Please check: https://github.com/${GITHUB_REPO}/releases/tag/nightly"
    exit 1
fi

# Extract download URL for the appropriate architecture
DOWNLOAD_URL=$(echo "$RELEASE_INFO" | grep -o "https://.*cmd-sandbox-${ARCH_SUFFIX}.*\.tar\.gz" | head -1)

if [ -z "$DOWNLOAD_URL" ]; then
    echo -e "${RED}✗ No pre-built binary found for architecture: ${ARCH}${NC}"
    echo ""
    echo "Please check: https://github.com/${GITHUB_REPO}/releases/tag/nightly"
    echo ""
    echo "Or build from source:"
    echo "  git clone https://github.com/${GITHUB_REPO}.git"
    echo "  cd cmd_sandbox-rs"
    echo "  cargo build --release"
    exit 1
fi

RELEASE_TAG=$(echo "$RELEASE_INFO" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')

echo -e "${GREEN}✓ Found nightly build${NC}"
echo -e "${BLUE}  Release: $RELEASE_TAG${NC}"
echo -e "${BLUE}  URL: $DOWNLOAD_URL${NC}"
echo ""

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo -e "${BLUE}Downloading...${NC}"
if command_exists curl; then
    curl -fsSL "$DOWNLOAD_URL" -o cmd-sandbox.tar.gz
else
    wget -q "$DOWNLOAD_URL" -O cmd-sandbox.tar.gz
fi

echo -e "${BLUE}Extracting...${NC}"
tar -xzf cmd-sandbox.tar.gz

echo -e "${GREEN}✓ Download complete${NC}"
echo ""

# Install binaries
echo -e "${BLUE}[3/3] Installing binaries...${NC}"

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

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
# cmd_sandbox - Wrapper for cmd_sandbox-rs

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
https://github.com/AnirudhG07/cmd_sandbox-rs
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

echo -e "${GREEN}✓ Binaries installed successfully!${NC}"
echo ""

# Check kernel requirements (NECESSARY)
echo -e "${BLUE}[Checking System Requirements]${NC}"
echo ""

KERNEL_ISSUES=()

# Check kernel version
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 7 ]); then
    echo -e "${RED}✗ Kernel version: $KERNEL_VERSION (requires 5.7+)${NC}"
    KERNEL_ISSUES+=("Kernel version too old (need 5.7+)")
else
    echo -e "${GREEN}✓ Kernel version: $KERNEL_VERSION${NC}"
fi

# Check BPF LSM
BPF_LSM_ENABLED=false
if [ -f /proc/cmdline ]; then
    if grep -q "lsm=.*bpf" /proc/cmdline || grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        echo -e "${GREEN}✓ BPF LSM is enabled${NC}"
        BPF_LSM_ENABLED=true
    else
        echo -e "${RED}✗ BPF LSM is NOT enabled${NC}"
        KERNEL_ISSUES+=("BPF LSM not enabled in kernel")
    fi
fi

# Check cgroup v2
if mount | grep -q "cgroup2"; then
    echo -e "${GREEN}✓ cgroup v2 is mounted${NC}"
else
    echo -e "${YELLOW}⚠ cgroup v2 is NOT mounted${NC}"
    KERNEL_ISSUES+=("cgroup v2 not mounted")
fi

echo ""

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

# If there are kernel issues, offer to fix them
if [ ${#KERNEL_ISSUES[@]} -ne 0 ]; then
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  System Configuration Required${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    for issue in "${KERNEL_ISSUES[@]}"; do
        echo -e "  ${RED}✗${NC} $issue"
    done
    echo ""
    
    if [ "$BPF_LSM_ENABLED" = false ]; then
        echo -e "${RED}BPF LSM is NOT enabled - this is CRITICAL!${NC}"
        echo ""
        echo "The sandbox will NOT work without BPF LSM enabled."
        echo ""
        echo "Actions that will be performed:"
        echo "  1. Backup your current GRUB configuration"
        echo "  2. Edit /etc/default/grub to add BPF LSM"
        echo "  3. Update GRUB bootloader"
        echo "  4. You will need to REBOOT your system"
        echo ""
        echo -e "${YELLOW}Current LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null || echo 'unknown')${NC}"
        echo ""
        echo "We will add 'bpf' to your existing LSM configuration."
        echo ""
        
        if ask_permission "Configure BPF LSM now? (requires sudo and REBOOT)"; then
            echo ""
            echo -e "${BLUE}Configuring BPF LSM...${NC}"
            
            # Backup GRUB config
            echo -e "${BLUE}Creating backup of /etc/default/grub...${NC}"
            sudo cp /etc/default/grub /etc/default/grub.backup.$(date +%Y%m%d_%H%M%S)
            echo -e "${GREEN}✓ Backup created${NC}"
            
            # Get current LSM setting
            CURRENT_LSM=$(cat /sys/kernel/security/lsm 2>/dev/null || echo "")
            
            if [ -n "$CURRENT_LSM" ]; then
                # Add bpf to existing LSMs
                NEW_LSM="${CURRENT_LSM},bpf"
            else
                # Default LSM configuration with bpf
                NEW_LSM="lockdown,yama,integrity,apparmor,bpf"
            fi
            
            echo -e "${BLUE}Adding BPF LSM to kernel parameters...${NC}"
            
            # Check if lsm= already exists in GRUB_CMDLINE_LINUX
            if sudo grep -q 'GRUB_CMDLINE_LINUX.*lsm=' /etc/default/grub; then
                # Replace existing lsm= parameter
                sudo sed -i "s/lsm=[^ \"]*/lsm=${NEW_LSM}/" /etc/default/grub
            else
                # Add lsm= parameter
                sudo sed -i "s/GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"lsm=${NEW_LSM} /" /etc/default/grub
            fi
            
            echo -e "${GREEN}✓ GRUB configuration updated${NC}"
            echo ""
            
            # Update GRUB
            echo -e "${BLUE}Updating GRUB bootloader...${NC}"
            if [ -f /etc/debian_version ]; then
                sudo update-grub
            elif [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
                sudo grub2-mkconfig -o /boot/grub2/grub.cfg
            else
                echo -e "${YELLOW}Unknown distribution. Please run update-grub manually.${NC}"
            fi
            echo -e "${GREEN}✓ GRUB updated${NC}"
            echo ""
            
            echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}  BPF LSM Configuration Complete!${NC}"
            echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${RED}IMPORTANT: You MUST reboot your system for changes to take effect.${NC}"
            echo ""
            echo "After reboot, verify with:"
            echo -e "  ${YELLOW}cat /sys/kernel/security/lsm${NC}"
            echo ""
            echo "It should include 'bpf' in the output."
            echo ""
            
            read -p "Reboot now? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${BLUE}Rebooting in 5 seconds... (Ctrl+C to cancel)${NC}"
                sleep 5
                sudo reboot
            else
                echo -e "${YELLOW}Please reboot manually for changes to take effect.${NC}"
                echo ""
                echo "After reboot, run 'cmd_sandbox run' to start the sandbox."
                exit 0
            fi
        else
            echo -e "${YELLOW}Skipping BPF LSM configuration.${NC}"
            echo ""
            echo "To enable BPF LSM manually:"
            echo ""
            echo "  1. Edit GRUB configuration:"
            echo -e "     ${YELLOW}sudo nano /etc/default/grub${NC}"
            echo ""
            echo "  2. Add/modify GRUB_CMDLINE_LINUX to include:"
            echo -e "     ${YELLOW}lsm=lockdown,yama,integrity,apparmor,bpf${NC}"
            echo "     (adjust based on your current LSMs)"
            echo ""
            echo "  3. Update GRUB:"
            echo -e "     ${YELLOW}sudo update-grub${NC}  # Debian/Ubuntu"
            echo -e "     ${YELLOW}sudo grub2-mkconfig -o /boot/grub2/grub.cfg${NC}  # Fedora/RHEL"
            echo ""
            echo "  4. Reboot:"
            echo -e "     ${YELLOW}sudo reboot${NC}"
            echo ""
        fi
    fi
    
    # Check cgroup v2
    if ! mount | grep -q "cgroup2"; then
        echo -e "${YELLOW}⚠ cgroup v2 is not mounted.${NC}"
        echo ""
        echo "Most modern distributions enable this by default."
        echo "Check your distribution documentation for enabling cgroup v2."
        echo ""
        echo -e "${YELLOW}This is required for memory and CPU limits.${NC}"
        echo ""
    fi
    
    # Check kernel version
    if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 7 ]); then
        echo -e "${RED}Your kernel version is too old.${NC}"
        echo "Please upgrade to kernel 5.7 or newer."
        echo ""
    fi
fi

echo ""

# Final instructions
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}⚠ $HOME/.local/bin is not in your PATH${NC}"
    echo -e "${YELLOW}  Add this line to your ~/.bashrc or ~/.zshrc:${NC}"
    echo ""
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
