#!/bin/bash
# curl_sandbox-rs installer
# Builds the project and creates a convenient cmd_sandbox wrapper

# Don't exit on error initially - we want to collect all issues
# set -e will be enabled after prerequisite checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  curl_sandbox-rs Installer${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this installer as root${NC}"
   echo -e "${YELLOW}The installer will ask for sudo when needed${NC}"
   exit 1
fi

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Arrays to track missing dependencies
MISSING_DEPS=()
MISSING_TOOLS=()
KERNEL_ISSUES=()

# Check prerequisites
echo -e "${BLUE}[1/6] Checking prerequisites...${NC}"

if ! command_exists rustc; then
    echo -e "${RED}✗ Rust is not installed${NC}"
    MISSING_DEPS+=("Rust toolchain")
else
    echo -e "${GREEN}✓ Rust installed: $(rustc --version)${NC}"
fi

if ! command_exists cargo; then
    echo -e "${RED}✗ Cargo is not installed${NC}"
    MISSING_DEPS+=("Cargo")
else
    echo -e "${GREEN}✓ Cargo installed: $(cargo --version)${NC}"
fi

if command_exists rustc && ! rustup toolchain list | grep -q nightly; then
    echo -e "${YELLOW}⚠ Nightly toolchain not found, installing...${NC}"
    rustup toolchain install nightly --component rust-src
fi
if command_exists rustc && rustup toolchain list | grep -q nightly; then
    echo -e "${GREEN}✓ Nightly toolchain installed${NC}"
fi

if command_exists cargo && ! command_exists bpf-linker; then
    echo -e "${YELLOW}⚠ bpf-linker not found, installing...${NC}"
    cargo install bpf-linker
fi
if command_exists bpf-linker; then
    echo -e "${GREEN}✓ bpf-linker installed${NC}"
fi

if ! command_exists gcc; then
    echo -e "${YELLOW}⚠ GCC not found (optional, needed for test helpers)${NC}"
    MISSING_TOOLS+=("gcc")
else
    echo -e "${GREEN}✓ GCC installed${NC}"
fi

echo ""

# Check kernel requirements
echo -e "${BLUE}[2/6] Checking kernel requirements...${NC}"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 7 ]); then
    echo -e "${RED}✗ Kernel version: $KERNEL_VERSION (requires 5.7+)${NC}"
    KERNEL_ISSUES+=("Kernel version too old (need 5.7+)")
else
    echo -e "${GREEN}✓ Kernel version: $KERNEL_VERSION${NC}"
fi

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

if mount | grep -q "cgroup2"; then
    echo -e "${GREEN}✓ cgroup v2 is mounted${NC}"
else
    echo -e "${RED}✗ cgroup v2 is NOT mounted${NC}"
    KERNEL_ISSUES+=("cgroup v2 not mounted")
fi

echo ""

# If there are missing dependencies or kernel issues, show them all
if [ ${#MISSING_DEPS[@]} -ne 0 ] || [ ${#KERNEL_ISSUES[@]} -ne 0 ]; then
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  MISSING REQUIREMENTS${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
        echo -e "${YELLOW}Required Software:${NC}"
        for dep in "${MISSING_DEPS[@]}"; do
            echo -e "  ${RED}✗${NC} $dep"
        done
        echo ""
        echo -e "${BLUE}To install Rust:${NC}"
        echo -e "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo -e "  source \$HOME/.cargo/env"
        echo ""
    fi
    
    if [ ${#KERNEL_ISSUES[@]} -ne 0 ]; then
        echo -e "${YELLOW}Kernel Configuration:${NC}"
        for issue in "${KERNEL_ISSUES[@]}"; do
            echo -e "  ${RED}✗${NC} $issue"
        done
        echo ""
        
        if [ "$BPF_LSM_ENABLED" = false ]; then
            echo -e "${BLUE}To enable BPF LSM:${NC}"
            echo -e "  1. Edit GRUB configuration:"
            echo -e "     ${YELLOW}sudo nano /etc/default/grub${NC}"
            echo ""
            echo -e "  2. Add/modify GRUB_CMDLINE_LINUX to include:"
            echo -e "     ${YELLOW}lsm=lockdown,yama,integrity,apparmor,bpf${NC}"
            echo -e "     (adjust based on your current LSMs, keep existing ones)"
            echo ""
            echo -e "  3. Update GRUB and reboot:"
            echo -e "     ${YELLOW}sudo update-grub${NC}  # Debian/Ubuntu"
            echo -e "     ${YELLOW}sudo grub2-mkconfig -o /boot/grub2/grub.cfg${NC}  # Fedora/RHEL"
            echo -e "     ${YELLOW}sudo reboot${NC}"
            echo ""
            echo -e "  4. After reboot, verify with:"
            echo -e "     ${YELLOW}cat /sys/kernel/security/lsm${NC}"
            echo ""
        fi
    fi
    
    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        echo -e "${YELLOW}Optional Tools (for test helpers):${NC}"
        for tool in "${MISSING_TOOLS[@]}"; do
            echo -e "  ${YELLOW}○${NC} $tool"
        done
        echo -e "  Install with: ${YELLOW}sudo apt install gcc${NC}  (Debian/Ubuntu)"
        echo -e "            or: ${YELLOW}sudo dnf install gcc${NC}  (Fedora/RHEL)"
        echo ""
    fi
    
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Please install the required dependencies and rerun this script.${NC}"
    exit 1
fi

# All checks passed, enable strict error handling
set -e

echo ""

# Build the project
echo -e "${BLUE}[3/6] Building cmd-sandbox (release mode)...${NC}"
cargo build --release -p cmd-sandbox
echo -e "${GREEN}✓ cmd-sandbox built successfully${NC}"

echo ""

echo -e "${BLUE}[4/6] Building cmd-sandbox-tests (release mode)...${NC}"
cargo build --release -p cmd-sandbox-tests
echo -e "${GREEN}✓ cmd-sandbox-tests built successfully${NC}"

echo ""

# Build test helpers if gcc is available
echo -e "${BLUE}[5/6] Building test helper binaries...${NC}"
if command_exists gcc; then
    cd cmd-sandbox-tests/test_helpers
    
    if [ -f test_stack_limit.c ]; then
        gcc -o test_stack_limit test_stack_limit.c && chmod +x test_stack_limit
        echo -e "${GREEN}✓ test_stack_limit compiled${NC}"
    fi
    
    if [ -f test_kernel_access.c ]; then
        gcc -o test_kernel_access test_kernel_access.c && chmod +x test_kernel_access
        echo -e "${GREEN}✓ test_kernel_access compiled${NC}"
    fi
    
    if [ -f test_net_config.c ]; then
        gcc -o test_net_config test_net_config.c && chmod +x test_net_config
        echo -e "${GREEN}✓ test_net_config compiled${NC}"
    fi
    
    cd ../..
else
    echo -e "${YELLOW}⚠ Skipping test helpers (gcc not found)${NC}"
fi

echo ""

# Create wrapper script
echo -e "${BLUE}[6/6] Creating cmd_sandbox wrapper script...${NC}"

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

cat > "$INSTALL_DIR/cmd_sandbox" << 'WRAPPER_EOF'
#!/bin/bash
# cmd_sandbox - Wrapper for curl_sandbox-rs

# Colors for output
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to find the project directory
if [ -f "$SCRIPT_DIR/../share/cmd-sandbox/cmd-sandbox" ]; then
    # Installed via install.sh to ~/.local
    PROJECT_DIR="$SCRIPT_DIR/../share/cmd-sandbox"
elif [ -f "$SCRIPT_DIR/../../target/release/cmd-sandbox" ]; then
    # Running from project directory
    PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
    # Try to find in current directory
    if [ -f "./target/release/cmd-sandbox" ]; then
        PROJECT_DIR="$(pwd)"
    else
        echo "Error: Could not find cmd-sandbox binary"
        echo "Make sure you run this from the project directory or install properly"
        exit 1
    fi
fi

SANDBOX_BIN="$PROJECT_DIR/target/release/cmd-sandbox"
TEST_BIN="$PROJECT_DIR/target/release/cmd-sandbox-tests"

case "$1" in
    run)
        # Run the sandbox
        shift
        if [ "$EUID" -ne 0 ]; then
            echo "Note: Running sandbox requires root privileges"
            exec sudo -E RUST_LOG="${RUST_LOG:-info}" "$SANDBOX_BIN" "$@"
        else
            exec "$SANDBOX_BIN" "$@"
        fi
        ;;
    test)
        # Run tests (tests themselves don't need sudo, but sandbox must be running)
        shift
        # Check if sandbox is running
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
        exec "$TEST_BIN" "$@"
        ;;
    build)
        # Rebuild the project
        cd "$PROJECT_DIR"
        cargo build --release
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
    
    build       Rebuild the project
    
    help        Show this help message

EXAMPLES:
    # Terminal 1: Start the sandbox
    cmd_sandbox run
    
    # Terminal 2: Run tests
    cmd_sandbox test
    
    # Start with debug logging
    RUST_LOG=debug cmd_sandbox run
    
    # Rebuild
    cmd_sandbox build

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

# Copy binaries to a permanent location
SHARE_DIR="$HOME/.local/share/cmd-sandbox"
mkdir -p "$SHARE_DIR"
cp -r target "$SHARE_DIR/"
cp -r cmd-sandbox-tests "$SHARE_DIR/" 2>/dev/null || true

echo -e "${GREEN}✓ Wrapper script created at: $INSTALL_DIR/cmd_sandbox${NC}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}The 'cmd_sandbox' command is now available!${NC}"
echo ""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}⚠ $INSTALL_DIR is not in your PATH${NC}"
    echo -e "${YELLOW}  Add this line to your ~/.bashrc or ~/.zshrc:${NC}"
    echo -e "${YELLOW}  export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    echo ""
    echo -e "${YELLOW}  Then run: source ~/.bashrc (or ~/.zshrc)${NC}"
    echo ""
fi

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
echo -e "${YELLOW}Note: Sandbox and tests require root/sudo${NC}"
echo ""
