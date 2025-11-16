# Command Sandbox (cmd_sandbox-rs)

A Rust implementation of Linux security sandbox for curl/wget that enforces network, memory, CPU, and filesystem policies using eBPF LSM hooks, cgroup v2 controllers, and userspace process monitoring. Basically, it prevents certain execution of curl based on certain policies as mentioned below.

We use Aya-rs which is eBPF, but in Rust, and why not use Rust because of its memory safety features and capabilities making the sandbox itself less prone to bugs, amazing coding experience and I know Rust more than C, LOL!

> [!Important]
> This project was developed and tested on Ubuntu 24.04 on both x86_64 and ARM64 architectures.

## Features of Sandbox

This project implements a multi-layer sandbox that:

- **Blocks HTTP connections**, allows only HTTPS (eBPF LSM hook)
- **Restricts file writes** to `/tmp/curl_downloads/` only (eBPF LSM hooks)
- **Blocks sensitive environment variables** (monitoring with warnings)
- **Limits memory usage** to 10MB per process (cgroup v2)
- **Limits CPU time** to 50% of one core (cgroup v2)
- **Enforces wall-clock timeout** at 10 seconds (userspace monitoring)
- **Prevents execution** of downloaded files (noexec mount + permission watcher)

All enforcement happens at the kernel level - no wrapper scripts, no LD_PRELOAD tricks.

## Requirements

> [!NOTE]
> All the dependencies will be installed for you if you use the interactive installer script.

**Operating System:**

- Linux kernel 5.7+ with BPF LSM enabled (`CONFIG_BPF_LSM=y`)
- cgroup v2 mounted (default on modern distributions)
- Check BPF LSM: `cat /proc/cmdline | grep lsm` should include "bpf"

**Development Tools:**

- Rust stable + nightly toolchains
- `bpf-linker` for eBPF compilation
- GCC (for test helper binaries)

**Runtime:**

- Root/sudo access (for BPF and cgroup operations)

## Installation

### Automatic Installation (Recommended)

You can run an interactive install script which will set you up for running the sandbox, from scratch by installing all dependencies(and asking permissions for it). Note that to enable BPF LSM, you may need to reboot as the installation script may guide you through, please do not ignore it.

```bash
git clone https://github.com/AnirudhG07/cmd_sandbox-rs.git
cd cmd_sandbox-rs
bash install.sh
```

Then add to PATH (if not already):

```bash
export PATH="$HOME/.local/bin:$PATH"  # Add to ~/.bashrc or ~/.zshrc
```

Usage:

```bash
cmd_sandbox run      # Start the sandbox (in terminal 1)
cmd_sandbox test     # Run all tests
cmd_sandbox help     # Show help
```

### Manual Build

<details>
<summary>If you prefer to build manually, check the below steps -
</summary>

```bash
# Install Rust toolchains
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker

# Clone and build
git clone https://github.com/AnirudhG07/cmd_sandbox-rs.git
cd cmd_sandbox-rs
cargo build --release

# Compile test helper binaries
cd cmd-sandbox-tests/test_helpers
gcc -o test_stack_limit test_stack_limit.c
gcc -o test_kernel_access test_kernel_access.c
gcc -o test_net_config test_net_config.c
chmod +x test_*
cd ../..
```

</details>

## Docker Container

Pre-built Docker container with all dependencies for testing without modifying your system. Works on both **x86_64** and **ARM64** architectures.

> [!Note]
> The docker instructions will be updated by the time presentation will be done, where a container will be deployed to Docker Hub for easy pull and use.
> For the submission, pls just know I will fix the Dockerfile(not yet working) and will show it, if asked.

```bash
cd Docker_imgs

# Build and run (auto-detects your architecture)
./docker-run.sh build
./docker-run.sh run

# Or use docker-compose
./docker-run.sh compose-up
docker exec -it cmd-sandbox /bin/bash
```

**Inside the container:**

- All dependencies pre-installed (Rust, bpf-linker, GCC)
- Project pre-compiled and ready to use
- Use `cmd_sandbox run` and `cmd_sandbox test`

See [Docker_imgs/README.md](Docker_imgs/README.md) for detailed instructions.

> **Note:** Docker containers require a Linux host with BPF LSM support. Docker Desktop on macOS/Windows will NOT work.

## Usage

Start the sandbox (requires root):

```bash
cmd_sandbox run
# or sudo cmd_sandbox run
```

In another terminal, use curl/wget normally:

```bash
# HTTPS works
curl https://example.com -o /tmp/curl_downloads/test.html

# HTTP blocked
curl http://example.com
# Error: Failed to connect to port 80

# File write blocked if not in `/tmp/curl_downloads`
curl https://example.com -o /tmp/slow.html
```

## Testing

**Automated test suite:**

```bash
# Terminal 1: Start sandbox
cmd_sandbox run

# Terminal 2: Run tests
cmd_sandbox test
```

Tests validate:

- Network policies (HTTPS-only, port restrictions, domain whitelisting)
- Filesystem policies (write restrictions, execution prevention)
- Memory limits (10MB max, file size limits)
- Security policies (capability blocking, environment variable filtering)

See test output for detailed results. To check the tests in detail, see [cmd-sandbox-tests](./cmd-sandbox-tests/) for test implementations.

## Implementation Details

The policies and their configurations have been set [policy_config.json](./policy_config.json) file where you can change any as you wish to. Here is the list of policies implemented:

### NET (Network Policies)

- **NET-001**: Domain Whitelist - Only allow connections to whitelisted domains (example.com, iisc.ac.in, trusted.org)
- **NET-002**: Block Non-HTTP Protocols - Prevent FTP, SFTP, Telnet connections
- **NET-005**: Block Private IP Ranges - Prevent connections to 192.168.x.x, 10.x.x.x, 172.16.x.x, 127.0.0.1
- **NET-006**: HTTPS-Only Enforcement - Block HTTP (port 80), allow only HTTPS (port 443)

### MEM (Memory & Process Policies)

- **MEM-001**: Memory Limit - Restrict process memory usage to 10MB (cgroup v2)
- **MEM-003**: Wall Clock Timeout - Kill processes running longer than 10 seconds
- **MEM-004**: CPU Throttling - Limit CPU usage to 50% of one core (cgroup v2)
- **MEM-005**: Block Executable Memory Mapping - Prevent mmap with PROT_EXEC flag
- **MEM-006**: Stack Size Limit - Restrict stack size to 8MB

### FS (Filesystem Policies)

- **FS-001**: Write Directory Restrictions - Allow writes only to `/tmp/curl_downloads/`, block all other locations
- **FS-003**: Maximum File Download Size - Limit individual file downloads to 10MB
- **FS-004**: Prevent Execution of Downloaded Files - Mount `/tmp/curl_downloads/` with noexec, strip execute permissions
- **FS-006**: Block System Directory Access - Prevent writes to `/etc/`, `/bin/`, `/sbin/`, `/usr/`

### SEC (Security Policies)

- **SEC-001**: Run as Non-Privileged User - Execute processes as `nobody` user
- **SEC-002**: Block Sensitive Environment Variables - Filter out PASSWORD, KEY, SECRET from environment
- **SEC-003**: Prevent Network Interface Configuration - Block CAP_NET_ADMIN capability
- **SEC-004**: Restrict Signal Handling - Allow only SIGTERM and SIGINT, block dangerous signals
- **SEC-005**: Block Kernel Memory/Module Access - Prevent direct kernel memory access and module loading

For detailed technical documentation on how each policy is implemented, see [IMPLEMENTATION.md](IMPLEMENTATION.md).

**Technologies used:**

- **eBPF LSM hooks** - Kernel-level syscall interception (network, filesystem, security policies)
- **cgroup v2 controllers** - Resource limits (memory, CPU)
- **Userspace process monitoring** - Wall-clock timeout enforcement via /proc scanning
- **Rust + aya-rs** - Safe systems programming with eBPF framework
- **noexec mounts** - Prevent execution of downloaded files
- **File permission watchers** - Continuous enforcement of security attributes

## Acknowledgements

This project was done under the Course [E0256 IISc Bengaluru](https://www.csa.iisc.ac.in/~vg/teaching/256/) instructed under Professor Vinod Ganapathy.
Special thanks to the TAs and the eBPF community for their support and resources.
