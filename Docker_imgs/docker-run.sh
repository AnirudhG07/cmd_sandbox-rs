#!/bin/bash
# Docker build and run script for cmd_sandbox-rs

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     cmd_sandbox-rs Docker Build & Run Script                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if running on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo -e "${YELLOW}Warning: This project requires Linux kernel features (BPF LSM, cgroup v2)${NC}"
    echo -e "${YELLOW}Docker Desktop on macOS/Windows may not support these features.${NC}"
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect host architecture
HOST_ARCH=$(uname -m)
echo -e "${BLUE}Detected host architecture: ${GREEN}$HOST_ARCH${NC}"
echo ""

# Parse command line arguments
COMMAND=${1:-help}
IMAGE_NAME="cmd-sandbox-rs:latest"
CONTAINER_NAME="cmd-sandbox"

case "$COMMAND" in
    build)
        echo -e "${BLUE}Building Docker image...${NC}"
        echo -e "${YELLOW}This will build for your host architecture ($HOST_ARCH)${NC}"
        echo ""
        
        docker build -f Docker_imgs/Dockerfile -t "$IMAGE_NAME" .
        
        echo ""
        echo -e "${GREEN}✓ Image built successfully${NC}"
        echo -e "${BLUE}Image: $IMAGE_NAME${NC}"
        echo -e "${BLUE}Architecture: $HOST_ARCH${NC}"
        ;;
        
    run)
        echo -e "${BLUE}Starting Docker container...${NC}"
        echo ""
        
        # Check if image exists
        if ! docker image inspect "$IMAGE_NAME" &> /dev/null; then
            echo -e "${YELLOW}Image not found. Building...${NC}"
            echo ""
            docker build -f Docker_imgs/Dockerfile -t "$IMAGE_NAME" .
        fi
        
        # Remove existing container if exists
        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
        
        echo -e "${GREEN}Starting container: $CONTAINER_NAME${NC}"
        echo ""
        echo -e "${YELLOW}Note: Container runs with --privileged for BPF/cgroup access${NC}"
        echo ""
        
        docker run -it --rm \
            --name "$CONTAINER_NAME" \
            --privileged \
            --cap-add SYS_ADMIN \
            --cap-add NET_ADMIN \
            --cap-add BPF \
            --security-opt apparmor=unconfined \
            -v /sys/kernel/security:/sys/kernel/security:ro \
            -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
            -v /lib/modules:/lib/modules:ro \
            "$IMAGE_NAME"
        ;;
        
    exec)
        echo -e "${BLUE}Opening shell in container: $CONTAINER_NAME${NC}"
        docker exec -it "$CONTAINER_NAME" /bin/bash
        ;;
        
    stop)
        echo -e "${BLUE}Stopping container...${NC}"
        docker stop "$CONTAINER_NAME"
        echo -e "${GREEN}Container stopped${NC}"
        ;;
    
    compose-up)
        echo -e "${BLUE}Starting container with docker-compose...${NC}"
        cd "$(dirname "$0")"
        docker-compose up -d
        echo ""
        echo -e "${GREEN}Container started!${NC}"
        echo ""
        echo "Access container:"
        echo -e "  ${BLUE}docker exec -it cmd-sandbox /bin/bash${NC}"
        ;;
    
    compose-down)
        echo -e "${BLUE}Stopping containers...${NC}"
        cd "$(dirname "$0")"
        docker-compose down
        echo -e "${GREEN}Containers stopped${NC}"
        ;;
        
    clean)
        echo -e "${YELLOW}Removing Docker images and containers...${NC}"
        docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
        docker rmi -f "$IMAGE_NAME" 2>/dev/null || true
        echo -e "${GREEN}Cleanup complete${NC}"
        ;;
        
    help|--help|-h)
        cat << EOF
${BLUE}cmd_sandbox-rs Docker Helper Script${NC}

${GREEN}ARCHITECTURE SUPPORT:${NC}
  This Dockerfile automatically builds for your host architecture.
  Supported: x86_64 (amd64) and ARM64 (aarch64)

${GREEN}USAGE:${NC}
    ./docker-run.sh <COMMAND>

${GREEN}COMMANDS:${NC}
    build           Build Docker image for your architecture
                    
    run             Run interactive container
                    
    exec            Open shell in running container
    
    stop            Stop the running container
    
    compose-up      Start container using docker-compose
    
    compose-down    Stop container started with docker-compose
    
    clean           Remove image and container
    
    help            Show this help message

${GREEN}EXAMPLES:${NC}
    # Build and run
    ./docker-run.sh build
    ./docker-run.sh run
    
    # Quick run (builds if needed)
    ./docker-run.sh run
    
    # Using docker-compose
    ./docker-run.sh compose-up
    docker exec -it cmd-sandbox /bin/bash
    
    # Open second terminal in same container
    ./docker-run.sh exec

${GREEN}INSIDE CONTAINER:${NC}
    # Terminal 1: Start the sandbox
    cmd_sandbox run
    
    # Terminal 2: Run tests (in another terminal)
    docker exec -it cmd-sandbox /bin/bash
    cmd_sandbox test
    
    # Or use curl/wget directly
    curl https://example.com -o /tmp/curl_downloads/test.html

${GREEN}REQUIREMENTS:${NC}
    - Docker installed
    - Linux host (for BPF LSM and cgroup v2 support)
    - Kernel 5.7+ with BPF LSM enabled

${YELLOW}NOTE:${NC}
    Container runs with --privileged for BPF and cgroup access.
    This is required for the sandbox to function properly.

EOF
        ;;
        
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo "Run './docker-run.sh help' for usage information"
        exit 1
        ;;
esac
