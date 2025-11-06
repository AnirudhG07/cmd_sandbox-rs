# Security Test Helper Programs

These C programs are used to provide **proof-of-concept** demonstrations that our LSM security policies actually work.

## Programs

### test_kernel_access.c
**Purpose**: Proves that SEC-005 blocks kernel memory access

**What it does**:
1. Renames itself to "curl" (so LSM hooks detect it)
2. Attempts to open `/proc/kcore` (requires CAP_SYS_ADMIN)
3. Attempts to open `/dev/mem` (requires CAP_SYS_ADMIN)
4. Attempts to open `/dev/kmem` (requires CAP_SYS_ADMIN)
5. Verifies all attempts are blocked with EPERM/EACCES

**Compilation**:
```bash
gcc -o test_kernel_access test_kernel_access.c
```

**Usage**:
```bash
./test_kernel_access --as-curl
```

### test_net_config.c
**Purpose**: Proves that SEC-003 blocks network configuration changes

**What it does**:
1. Renames itself to "curl" (so LSM hooks detect it)
2. Creates a socket
3. Attempts to modify interface flags with `ioctl(SIOCSIFFLAGS)` (requires CAP_NET_ADMIN)
4. Verifies the attempt is blocked with EPERM/EACCES

**Compilation**:
```bash
gcc -o test_net_config test_net_config.c
```

**Usage**:
```bash
./test_net_config --as-curl
```

## Why These Tests Matter

Normal curl doesn't attempt these operations. But for a **security project**, we need to prove that:
1. The LSM hooks are actually loaded
2. The hooks intercept the right operations
3. The hooks return -EPERM to block attacks

These test programs **simulate attacks** - a compromised or malicious "curl" trying to:
- Access kernel memory (exploit for privilege escalation)
- Modify network configuration (network-based attacks)
- Load kernel modules (rootkit installation)

Our LSM policies block these at the kernel level, even if the process is named "curl".
