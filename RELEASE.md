# Release Process for cmd_sandbox-rs

## Automated Builds via GitHub Actions

This project uses GitHub Actions to automatically build and publish release binaries for both x86_64 and ARM64 architectures.

### Triggering a Release

1. **Create and push a version tag:**
   ```bash
   git tag -a v1.0.0 -m "Release version 1.0.0"
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically:**
   - Build binaries for x86_64
   - Build binaries for ARM64 (cross-compiled)
   - Package them into `.tar.gz` files
   - Create a GitHub Release
   - Attach the binaries to the release

3. **Users can then install with:**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/AnirudhG07/curl_sandbox-rs/main/install.sh | bash
   ```

### What Gets Built

Each release includes:
- `cmd-sandbox-x86_64.tar.gz` containing:
  - `cmd-sandbox` (main binary)
  - `cmd-sandbox-tests` (test suite)
  - `test_helpers/` (pre-compiled test binaries)
  - `policy_config.json`

- `cmd-sandbox-aarch64.tar.gz` (same contents for ARM64)

### Manual Trigger

You can also manually trigger a build without creating a tag:
1. Go to Actions tab on GitHub
2. Select "Build and Release" workflow
3. Click "Run workflow"

### Build Environment

- **OS:** Ubuntu 24.04
- **Rust:** Stable toolchain + nightly (for eBPF)
- **Tools:** bpf-linker, gcc, cross-compilation tools for ARM64

### What Users Need (Pre-built Binaries)

Users downloading pre-built binaries **DO NOT** need:
- ❌ Rust toolchain
- ❌ Cargo
- ❌ bpf-linker
- ❌ GCC
- ❌ Build tools

They **ONLY** need:
- ✅ Linux kernel 5.7+ with BPF LSM enabled
- ✅ cgroup v2 mounted
- ✅ curl or wget (for downloading)
- ✅ tar (for extracting)
- ✅ Root/sudo access (to run the sandbox)

### Workflow File

See `.github/workflows/release.yml` for the complete workflow configuration.
