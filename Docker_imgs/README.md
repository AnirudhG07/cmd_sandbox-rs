# Docker Image for cmd_sandbox-rs

Pre-configured Docker container with all dependencies installed. Works on both x86_64 and ARM64 architectures.

##a Quick Start

### Build and Run

```bash
cd Docker_imgs

# Build the image (auto-detects your architecture)
./docker-run.sh build

# Run the container
./docker-run.sh run
```

The Docker image automatically builds for your host architecture (x86_64 or ARM64).

## What's Included

The container comes with:
- Ubuntu 24.04 base image
- Rust toolchain (stable + nightly)
- bpf-linker pre-installed
- GCC and build tools
- Pre-compiled cmd-sandbox binaries
- Pre-compiled test helper binaries
- `cmd_sandbox` wrapper command

## Usage Inside Container

Once inside the container:

```bash
# Terminal 1: Start the sandbox
cmd_sandbox run

# Terminal 2: Run tests (open another shell in same container)
# In your host terminal:
docker exec -it cmd-sandbox /bin/bash

# Then inside the new shell:
cmd_sandbox test

# Or use curl/wget directly
curl https://example.com -o /tmp/curl_downloads/test.html
```

## Files

- `Dockerfile` - Universal Dockerfile (works on x86_64 and ARM64)
- `docker-run.sh` - Helper script for building/running containers
- `.dockerignore` - Optimizes build performance

## docker-run.sh Commands

```bash
# Build the image
./docker-run.sh build        # Builds for your host architecture

# Run the container
./docker-run.sh run          # Start interactive container

# Utilities
./docker-run.sh exec         # Open shell in running container
./docker-run.sh stop         # Stop the container
./docker-run.sh clean        # Remove image and container
./docker-run.sh help         # Show help
```

## Container Configuration

The container runs with the following privileges (required for BPF and cgroups):

- `--privileged` flag enabled
- Capabilities: `SYS_ADMIN`, `NET_ADMIN`, `BPF`
- AppArmor: unconfined
- Mounts:
  - `/sys/kernel/security` (read-only)
  - `/sys/fs/cgroup` (read-write)
  - `/lib/modules` (read-only)

## Building Manually

### Auto-detects Architecture

```bash
docker build -f Docker_imgs/Dockerfile -t cmd-sandbox-rs:latest .
docker run -it --privileged --rm cmd-sandbox-rs:latest
```

The same Dockerfile works for both x86_64 and ARM64!

## Testing in Container

The container is perfect for testing the sandbox without modifying your host system:

```bash
# Start container
./docker-run.sh run

# Inside container - Terminal 1
cmd_sandbox run

# Inside container - Terminal 2 (new shell)
# On host, run:
docker exec -it cmd-sandbox /bin/bash
# Then:
cmd_sandbox test

# All tests should pass!
```

## Notes

### Linux Host Required

This container requires a **Linux host** with:
- Kernel 5.7+ with BPF LSM enabled
- cgroup v2 support
- Docker with privileged container support

Docker Desktop on **macOS/Windows will NOT work** as they don't provide kernel-level BPF LSM support.

### Cross-Architecture Building

Docker automatically builds for your host architecture. If you want to build for a different architecture, use Docker buildx:

```bash
# Set up buildx (one time)
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap

# Build for specific platform
docker buildx build --platform linux/arm64 -f Docker_imgs/Dockerfile -t cmd-sandbox-rs:arm64 .
docker buildx build --platform linux/amd64 -f Docker_imgs/Dockerfile -t cmd-sandbox-rs:x86_64 .
```

### Performance

Building the container takes time (10-20 minutes) due to:
- Rust toolchain installation
- bpf-linker compilation
- Project compilation

Once built, starting containers is instant.

### Alternative: Pre-built Binaries

If you just want to try the sandbox quickly without Docker, use the standalone installer:

```bash
curl -fsSL https://raw.githubusercontent.com/AnirudhG07/curl_sandbox-rs/main/install.sh | bash
```

This downloads pre-built binaries and installs in seconds (no Rust/Docker needed).

## Troubleshooting

### BPF LSM not enabled

If you get errors about BPF LSM inside the container:

```bash
# Check on host
cat /sys/kernel/security/lsm

# Should include "bpf"
# If not, follow instructions in main README to enable it
```

### cgroup errors

If you see cgroup-related errors:

```bash
# Check cgroup v2 on host
mount | grep cgroup2

# Ensure /sys/fs/cgroup is mounted as cgroup2
```

### Container won't start

Make sure you're running on Linux:

```bash
uname -s  # Should output "Linux"
```

## Additional Resources

- [Main Project README](../README.md)
- [Implementation Details](../IMPLEMENTATION.md)
- [Release Documentation](../RELEASE.md)
- [Docker Documentation](https://docs.docker.com/)
- [BPF LSM Documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
