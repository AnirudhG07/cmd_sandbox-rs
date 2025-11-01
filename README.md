# curl_sandbox-rs

Pure eBPF-based sandbox for curl/wget with security policies enforced at the kernel level.

## Implemented Policies

### 1. Network - HTTPS Only ✅ (eBPF LSM)
- **Implementation**: LSM hook on `socket_connect`
- **Behavior**: 
  - ✅ Blocks HTTP (port 80) connections
  - ✅ Allows HTTPS (port 443) connections  
  - ✅ Allows DNS (port 53) for hostname resolution
  - ✅ Allows Unix domain sockets (local IPC)
- **Status**: ✅ Fully working

### 2. Memory - Maximum 1MB allocation 🔄 (eBPF LSM - In Progress)
- **Implementation**: LSM hook on `mmap_file` to track memory allocations
- **Approach**: 
  - Track memory usage per PID in BPF map
  - Block new allocations when limit exceeded
- **Status**: 🔄 Implemented, needs testing
- **Limitation**: Can track mmap allocations, may not catch all memory types

### 3. File System - Read-only /tmp/downloads/ ❌ (Not Reliably Enforceable)
- **Status**: ❌ Not implemented
- **Why**: Cannot reliably get full file paths in eBPF

### 4. CPU - Time limit 30 seconds 📋 (TODO)
- **Planned**: Track CPU time in BPF map, send signal when exceeded
- **Status**: 📋 Not yet implemented

## Current Status: 1.5/4 Policies Working
- ✅ Network (HTTPS-only): Fully working
- 🔄 Memory (1MB limit): Implemented, testing needed
- ❌ File System: Not feasible in pure eBPF
- 📋 CPU limit: Not yet implemented
- **Implementation**: To be implemented
- **Behavior**: Limit curl/wget memory usage to 1MB

## Design Philosophy

**Pure eBPF, No Wrappers**
- ✅ Clean kernel-level enforcement
- ✅ No wrapper binaries or scripts required
- ✅ Works with real curl/wget directly
- ✅ Separate monitoring process approach
- ❌ Cannot enforce file path restrictions (eBPF limitation)
- ❌ Cannot catch all memory allocation types

## Installation & Usage

### 1. Build everything

```bash
cargo build --release
```

This builds:
- `target/release/cmd-sandbox` - eBPF sandbox (enforces policies)

### 2. Run the eBPF sandbox

```bash
sudo -E RUST_LOG=info ./target/release/cmd-sandbox
```

Output:
```
✓ socket_connect LSM hook attached (HTTPS-only policy)
✓ mmap_file LSM hook attached (1MB memory limit policy)
Waiting for Ctrl-C...
```

### 3. Use curl/wget normally

Simply run curl or wget as usual - the sandbox monitors and enforces policies:

```bash
# HTTPS works
curl https://example.com -o /tmp/file.txt

# HTTP is blocked
curl http://example.com -o /tmp/file.txt
# Error: Couldn't connect to server

# Large downloads (>1MB) may be blocked
curl https://httpbin.org/bytes/2097152 -o /tmp/large.bin
```

## Testing

### Quick Tests

See [TESTING.md](TESTING.md) for detailed test commands.

```bash
# Run automated test suite
./test-all-policies.sh

# Or test memory limit specifically  
./test-memory-limit.sh
```

### Manual Testing

**Test HTTPS-only policy:**
```bash
# Should work
curl https://example.com -o /tmp/test.html

# Should fail
curl http://example.com -o /tmp/test.html
```

**Test memory limit:**
```bash
# Should work (small file)
curl https://httpbin.org/bytes/102400 -o /tmp/small.bin

# Should fail (large file >1MB)
curl https://httpbin.org/bytes/2097152 -o /tmp/large.bin
```

**Check logs:**
```bash
# Sandbox output shows enforcement actions
sudo dmesg | tail -30
```
# 🔒 Launching curl with resource limits:
#    - Memory limit: 1MB
#    - CPU time limit: 30 seconds
#    - Network: HTTPS only (enforced by eBPF)
```

**Option B: Without resource limits (HTTPS-only)**
```bash
# Just HTTPS enforcement
curl https://example.com -o /tmp/file.txt
```

### 4. Test the policies

```bash
# ✅ HTTPS works
./target/release/curl-launcher curl https://example.com -o /tmp/index.html

# ❌ HTTP is BLOCKED by eBPF
./target/release/curl-launcher curl http://example.com -o /tmp/index.html
# Error: Couldn't connect to server

# ❌ Exceeding memory limit is blocked
./target/release/curl-launcher curl https://large-file.example.com -o /tmp/big.iso
# Killed (if exceeds 1MB)

# ❌ Exceeding CPU time is blocked  
./target/release/curl-launcher curl https://slow-server.example.com -o /tmp/file.txt
# Killed (if exceeds 30 seconds CPU time)
```

## Testing

### Test HTTPS-only policy:

```bash
# Terminal 1: Run sandbox
sudo -E RUST_LOG=info ./target/release/cmd-sandbox

# Terminal 2: Test HTTP (should be BLOCKED)
curl http://93.184.216.34
# Error: Couldn't connect to server

# Test HTTPS (should work)
curl https://93.184.216.34 -k -o /tmp/test.html
# Success!
```

Expected sandbox output:
```
✓ socket_connect LSM hook attached (HTTPS-only policy)
Waiting for Ctrl-C...
[INFO  cmd_sandbox] curl/wget socket_connect intercepted
[WARN  cmd_sandbox] 🚫 SANDBOX BLOCKED: curl attempted HTTP connection on port 80
[INFO  cmd_sandbox] curl/wget socket_connect intercepted  
[INFO  cmd_sandbox] curl ALLOWED: HTTPS port 443
```

## Architecture

```
User runs: curl https://example.com -o /tmp/file.txt
                    ↓
         [Real curl binary]
                    ↓
         socket_connect() → [eBPF LSM Hook]
                            ✓ Port 443 allowed
                    ↓
         write() to /tmp/file.txt → Success
                    ↓
         ✓ File saved to /tmp/file.txt
```

## Project Structure

- `cmd-sandbox/`: Userspace eBPF loader (attaches LSM hooks)
- `cmd-sandbox-ebpf/`: eBPF programs (LSM socket_connect hook)
- `cmd-sandbox-common/`: Shared types between userspace and eBPF

## Requirements

- Linux kernel with BPF LSM enabled (`CONFIG_BPF_LSM=y`)
- BPF LSM in boot parameters: `lsm=...,bpf`
- Rust nightly toolchain
- bpf-linker
- curl and/or wget binaries installed

## How It Works

### HTTPS-Only Enforcement (eBPF LSM)
1. LSM hook intercepts `socket_connect()` system calls
2. Checks if process name is "curl" or "wget"
3. Reads socket address to determine port number
4. Blocks connection if port != 443 (returns -EPERM)
5. Allows HTTPS (port 443) and Unix sockets (local DNS/IPC)

### File Write Restriction (User Responsibility)
- eBPF cannot modify system call arguments (it can only observe and block)
- Therefore, automatic path redirection is impossible
- Solution: Users must use `/tmp` explicitly
- Clear error messages guide users to correct usage

## Why No Wrapper?

**eBPF Capabilities:**
- ✅ Can observe system calls
- ✅ Can block system calls (return error codes)
- ❌ **Cannot modify** system call arguments
- ❌ **Cannot redirect** file paths

**Alternatives Considered:**
1. ❌ Wrapper script/binary - adds complexity, not pure eBPF
2. ❌ LD_PRELOAD - fragile, can be bypassed
3. ✅ **User education** - simple, transparent, secure

## Benefits of Pure eBPF Approach

✅ **Simplicity**: No wrappers, no extra binaries  
✅ **Transparency**: Users know exactly what's happening  
✅ **Security**: Kernel-level enforcement, can't be bypassed  
✅ **Performance**: Zero overhead from userspace wrappers  
✅ **Maintainability**: Clean, focused codebase## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package cmd-sandbox --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/cmd-sandbox` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, cmd-sandbox is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
