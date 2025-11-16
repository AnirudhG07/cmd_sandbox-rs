# Universal Dockerfile for cmd_sandbox-rs
# Works on both x86_64 and ARM64 architectures
# Ubuntu 24.04 with all dependencies

FROM ubuntu:24.04

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Set up environment variables
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.83.0

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gcc \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    git \
    nano \
    vim \
    sudo \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (stable + nightly)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal \
    --no-modify-path && \
    rustup toolchain install nightly --component rust-src && \
    cargo install bpf-linker && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Create workspace directory
WORKDIR /workspace/cmd_sandbox-rs

# Copy the entire project
COPY . .

# Build the project (release mode)
RUN cargo build --release -p cmd-sandbox && \
    cargo build --release -p cmd-sandbox-tests

# Build test helper binaries
RUN cd cmd-sandbox-tests/test_helpers && \
    gcc -o test_stack_limit test_stack_limit.c && \
    gcc -o test_kernel_access test_kernel_access.c && \
    gcc -o test_net_config test_net_config.c && \
    chmod +x test_* && \
    cd ../..

# Create the cmd_sandbox wrapper
RUN mkdir -p /usr/local/bin && \
    cp target/release/cmd-sandbox /usr/local/bin/ && \
    cp target/release/cmd-sandbox-tests /usr/local/bin/ && \
    echo '#!/bin/bash\n\
case "$1" in\n\
    run)\n\
        shift\n\
        exec /usr/local/bin/cmd-sandbox "$@"\n\
        ;;\n\
    test)\n\
        shift\n\
        if ! pgrep -f "cmd-sandbox" > /dev/null 2>&1; then\n\
            echo "Error: Sandbox is not running!"\n\
            echo "Please start the sandbox first in another terminal:"\n\
            echo "  cmd_sandbox run"\n\
            exit 1\n\
        fi\n\
        exec /usr/local/bin/cmd-sandbox-tests "$@"\n\
        ;;\n\
    *)\n\
        echo "Usage: cmd_sandbox {run|test}"\n\
        exit 1\n\
        ;;\n\
esac' > /usr/local/bin/cmd_sandbox && \
    chmod +x /usr/local/bin/cmd_sandbox

# Set up environment for interactive use
ENV RUST_LOG=info

# Detect architecture and add to welcome message
RUN ARCH=$(uname -m) && \
    echo 'alias ll="ls -lah"' >> /root/.bashrc && \
    echo 'alias sandbox="cmd_sandbox run"' >> /root/.bashrc && \
    echo 'alias test-sandbox="cmd_sandbox test"' >> /root/.bashrc && \
    echo 'echo "╔════════════════════════════════════════════════════════════════╗"' >> /root/.bashrc && \
    echo "echo \"║     cmd_sandbox-rs Docker Container ($ARCH)\"" | sed 's/$ARCH/$(uname -m)/' >> /root/.bashrc && \
    echo 'echo "╚════════════════════════════════════════════════════════════════╝"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc && \
    echo 'echo "Quick Start:"' >> /root/.bashrc && \
    echo 'echo "  cmd_sandbox run      # Start the sandbox"' >> /root/.bashrc && \
    echo 'echo "  cmd_sandbox test     # Run tests (in another terminal)"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc && \
    echo 'echo "Project location: /workspace/cmd_sandbox-rs"' >> /root/.bashrc && \
    echo 'echo "Architecture: $(uname -m)"' >> /root/.bashrc && \
    echo 'echo ""' >> /root/.bashrc

# Expose info about the container
LABEL maintainer="AnirudhG07" \
      description="cmd_sandbox-rs - curl/wget security sandbox" \
      version="1.0"

# Default command
CMD ["/bin/bash"]
