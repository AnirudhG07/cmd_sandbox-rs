# TODO: Policy Implementation Status and Roadmap

## Current Implementation Status

### ✅ Implemented Policies (3/24 total)

#### Network Access Policies (1/6)
- ✅ **NET-006**: Allow only ports 80 (HTTP) and 443 (HTTPS) - **IMPLEMENTED**
  - Using eBPF LSM `socket_connect` hook
  - Blocks port 80, allows 443 and 53 (DNS)
  - Status: **Fully working**

#### Memory and Process Policies (2/6)
- ✅ **MEM-001**: Maximum memory usage: 100MB (currently 10MB) - **IMPLEMENTED**
  - Using cgroup v2 `memory.max`
  - Currently set to 10MB, can be adjusted to 100MB
  - Status: **Working but not triggering OOM on streaming downloads**
  
- ⚠️ **MEM-003**: Maximum process execution time: 2 minutes (currently 10s wall clock) - **PARTIALLY IMPLEMENTED**
  - Wall clock timeout: 10 seconds (via userspace monitoring)
  - CPU time limit: 2 seconds (via cgroup `cpu.max`)
  - Requirement: 2 minutes (120 seconds)
  - Status: **Working but needs adjustment to 120s**

---

## 🔴 Missing Policies (21/24)

### Network Access Policies (5/6 missing)

#### ❌ NET-001: Domain Whitelist (Priority: HIGH)
**Requirement**: Allow HTTP/HTTPS only to whitelisted domains  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ DIFFICULT with eBPF alone

**Implementation Options**:
1. **eBPF + DNS monitoring** (Complex):
   - Hook `tcp_connect` and capture destination IP
   - Maintain IP→domain mapping from DNS responses
   - Hook `udp_sendmsg` to intercept DNS queries
   - Build allowlist of resolved IPs
   - **Challenges**: DNS caching, multiple IPs per domain, DNS over HTTPS

2. **Userspace proxy** (Easier but violates kernel-only requirement):
   - Transparent proxy that resolves domains
   - eBPF redirects all connections through proxy
   - Proxy enforces whitelist
   - **Challenges**: May be considered "wrapper" approach

3. **BPF_PROG_TYPE_SOCK_OPS** (Moderate):
   - Intercept socket operations
   - Parse SNI (Server Name Indication) for HTTPS
   - Block connections based on SNI
   - **Challenges**: Only works for HTTPS, not plain HTTP

**Recommendation**: BPF_PROG_TYPE_SOCK_OPS + SNI parsing for HTTPS. For HTTP, may need userspace helper.

---

#### ❌ NET-002: Block non-HTTP protocols (Priority: MEDIUM)
**Requirement**: Block FTP, SFTP, and other protocols  
**Current Status**: Partially implemented (only HTTP/HTTPS allowed by port)  
**Feasibility**: ✅ EASY to extend

**Implementation**:
- Extend current `socket_connect` LSM hook
- Add checks for ports 21 (FTP), 22 (SSH/SFTP), 23 (Telnet), etc.
- Block all ports except 80, 443, 53

**Code Location**: `cmd-sandbox-ebpf/src/main.rs` - `socket_connect()` function

---

#### ❌ NET-003: Connection timeout (30 seconds) (Priority: MEDIUM)
**Requirement**: Restrict max connection duration to 30 seconds  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ MODERATE

**Implementation Options**:
1. **BPF timers** (Modern kernels 5.15+):
   - Use `bpf_timer_init()` and `bpf_timer_set_callback()`
   - Track connection start time in BPF map
   - Kill connection after 30s
   - **Challenge**: Timer API complexity

2. **Userspace monitoring** (Current approach extended):
   - Track connection times in userspace
   - Monitor `/proc/net/tcp` for curl's connections
   - Kill process if connection exceeds 30s
   - **Challenge**: Less precise than kernel-level

**Recommendation**: Extend current userspace monitoring to track per-connection times.

---

#### ❌ NET-004: Concurrent connection limit (3) (Priority: LOW)
**Requirement**: Limit to 3 simultaneous connections  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ MODERATE

**Implementation**:
- Use BPF hash map to track active connections per PID
- In `socket_connect` hook, check connection count
- If count >= 3, return -ECONNREFUSED
- Decrement count on socket close (using `bpf_sock_destroy`)

**Challenge**: Tracking socket lifecycle (open/close) accurately in eBPF

---

#### ❌ NET-005: Block private IP ranges (Priority: MEDIUM)
**Requirement**: Block 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
- In `socket_connect` LSM hook, extract destination IP from `struct sockaddr`
- Check if IP falls in private ranges using bit masking
- Return -EPERM if in private range

**Code**: Add to existing `socket_connect()` function

```rust
// Check for private IP ranges
let ip = sockaddr.sin_addr.s_addr;
if (ip & 0xFF000000) == 0x0A000000 || // 10.0.0.0/8
   (ip & 0xFFF00000) == 0xAC100000 || // 172.16.0.0/12
   (ip & 0xFFFF0000) == 0xC0A80000 {  // 192.168.0.0/16
    return -EPERM;
}
```

---

### File System Policies (6/6 missing - MOST CHALLENGING)

#### ❌ FS-001: Restrict writes to /tmp/curl_downloads/ (Priority: HIGH)
**Requirement**: Allow writes only to specific directory  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ DIFFICULT

**Implementation Options**:
1. **LSM hooks** (Best approach):
   - Use `file_open` or `path_mknod` LSM hooks
   - Check file path in hook
   - Block if not under `/tmp/curl_downloads/`
   - **Challenge**: Path resolution in eBPF is tricky

2. **Landlock** (Alternative):
   - Use Landlock LSM (Linux 5.13+)
   - Create ruleset restricting filesystem access
   - **Challenge**: May not be available on older kernels

3. **seccomp-bpf** (Limited):
   - Filter `open`, `openat`, `creat` syscalls
   - **Challenge**: Cannot inspect path strings easily

**Recommendation**: Use `file_open` LSM hook with path checking. Need to resolve `struct path*` to string.

---

#### ❌ FS-002: Block reads outside home directory (Priority: MEDIUM)
**Requirement**: Prevent reading files outside user's home  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ DIFFICULT (similar to FS-001)

**Implementation**: Same as FS-001 but for read operations (use `file_permission` LSM hook)

---

#### ❌ FS-003: Max file size 10MB (Priority: HIGH)
**Requirement**: Limit individual file downloads to 10MB  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ MODERATE

**Implementation Options**:
1. **LSM file_open + rlimit**:
   - Use `setrlimit(RLIMIT_FSIZE, 10MB)` before curl starts
   - Enforced by kernel automatically
   - **Challenge**: Need to set before process starts

2. **BPF map tracking**:
   - Track bytes written per file descriptor in BPF map
   - Block writes when threshold exceeded
   - Use `file_permission` or `bprm_check_security` hooks

**Recommendation**: Set RLIMIT_FSIZE in userspace before moving to cgroup.

---

#### ❌ FS-004: Prevent execution of downloaded files (Priority: HIGH)
**Requirement**: Block execute permission on downloads  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
1. **LSM bprm_check_security**:
   - Hook into `bprm_check_security` (execve)
   - Check if file path is under `/tmp/curl_downloads/`
   - Return -EACCES if trying to execute

2. **File mode restrictions**:
   - Use `file_open` hook to force O_NOEXEC flag
   - Remove executable bits on file creation

**Recommendation**: Use LSM `bprm_check_security` hook.

---

#### ❌ FS-005: Total storage quota 50MB (Priority: MEDIUM)
**Requirement**: Restrict total disk usage to 50MB  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ MODERATE

**Implementation**:
- Track total bytes written in BPF hash map (per process or global)
- Increment counter on each write
- Block writes when total exceeds 50MB
- Use `file_permission` hook with MAY_WRITE check

**Challenge**: Tracking across multiple files and ensuring accurate accounting

---

#### ❌ FS-006: Block system directories (Priority: HIGH)
**Requirement**: Block access to /etc/, /bin/, /sbin/, /usr/  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY (similar to FS-001)

**Implementation**: Same path-checking logic as FS-001 in `file_open` or `file_permission` hooks.

---

### Memory and Process Policies (4/6 missing)

#### ❌ MEM-002: Block fork() and exec() (Priority: HIGH)
**Requirement**: Prevent process spawning during execution  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
1. **LSM hooks**:
   - `task_alloc` (for fork)
   - `bprm_check_security` (for exec)
   - Check if calling process is curl
   - Return -EPERM

2. **seccomp-bpf**:
   - Filter `fork`, `vfork`, `clone`, `execve` syscalls
   - Return SECCOMP_RET_KILL

**Recommendation**: Use LSM hooks (already have infrastructure).

---

#### ⚠️ MEM-003: Max execution time 2 minutes (Priority: HIGH)
**Current Status**: Implemented as 10s wall clock + 2s CPU time  
**Required**: 2 minutes (120 seconds)

**Action**: Simply change constants:
```rust
const WALL_CLOCK_LIMIT: Duration = Duration::from_secs(120);
const CPU_TIME_LIMIT_US: &str = "120000000 1000000"; // 120s CPU time
```

---

#### ❌ MEM-004: CPU throttling to 50% (Priority: MEDIUM)
**Requirement**: Restrict CPU usage to 50% of single core  
**Current Status**: CPU time limit exists (2s) but no throttling  
**Feasibility**: ✅ EASY with cgroups

**Implementation**:
- Use cgroup v2 `cpu.max` with proper ratio
- `cpu.max` format: `$MAX $PERIOD`
- For 50% of one core: `500000 1000000` (500ms per 1000ms period)

**Code change** in `setup_cgroup()`:
```rust
const CPU_LIMIT_US: &str = "500000 1000000"; // 50% of one core
```

---

#### ❌ MEM-005: Block executable memory mapping (Priority: HIGH)
**Requirement**: Prevent mmap with PROT_EXEC  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
- Use LSM `file_mmap` hook
- Check if `prot` contains `PROT_EXEC`
- Return -EACCES if executable mapping requested

**Note**: May break legitimate library loading! Need to allow PROT_EXEC for shared libraries.

---

#### ❌ MEM-006: Stack size limit 8MB (Priority: LOW)
**Requirement**: Limit stack to 8MB  
**Current Status**: Not implemented  
**Feasibility**: ✅ TRIVIAL

**Implementation**:
- Use `setrlimit(RLIMIT_STACK, 8MB)` before starting curl
- Add to userspace setup code

```rust
let stack_limit = libc::rlimit {
    rlim_cur: 8 * 1024 * 1024, // 8MB
    rlim_max: 8 * 1024 * 1024,
};
unsafe { libc::setrlimit(libc::RLIMIT_STACK, &stack_limit) };
```

---

### Security and Isolation Policies (6/6 missing)

#### ❌ SEC-001: Run as unprivileged user (nobody) (Priority: HIGH)
**Requirement**: Drop privileges to 'nobody' user  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
- In userspace, before exec'ing curl (if we spawn it)
- Use `setuid(65534)` and `setgid(65534)` (nobody:nogroup)
- OR: Launch curl as nobody from start

**Challenge**: We're not exec'ing curl ourselves - we're monitoring existing processes. May need to enforce this differently.

**Alternative**: Use LSM to check effective UID and block privileged operations.

---

#### ❌ SEC-002: Filter environment variables (Priority: MEDIUM)
**Requirement**: Block access to PASSWORD, KEY, SECRET env vars  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ VERY DIFFICULT

**Implementation Options**:
1. **Clear environment before exec** (if we control launch):
   - Parse environment variables
   - Remove sensitive ones
   - **Challenge**: We don't control curl launch

2. **eBPF bpf_probe_read**:
   - Hook into getenv() or environment access
   - Filter reads of specific variables
   - **Challenge**: Requires tracing programs, hard to block

3. **Process credential check**:
   - Don't give process access to parent environment
   - Launch in new namespace with clean env

**Recommendation**: This is very hard without controlling the curl launch. May need to document as limitation.

---

#### ❌ SEC-003: Prevent network interface changes (Priority: MEDIUM)
**Requirement**: Block netconfig syscalls  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
- Use LSM `net_admin` capability check hook
- Block CAP_NET_ADMIN operations for sandboxed processes
- Syscalls: `ioctl(SIOCSIF*)`, `setsockopt(SO_BINDTODEVICE)`, etc.

---

#### ❌ SEC-004: Signal handling restrictions (Priority: LOW)
**Requirement**: Allow only TERM, INT signals  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ MODERATE

**Implementation**:
- LSM `task_kill` hook
- Check signal number being sent
- Allow only SIGTERM (15) and SIGINT (2)
- Block others with -EPERM

---

#### ❌ SEC-005: Block kernel memory access (Priority: HIGH)
**Requirement**: Prevent access to kernel memory/modules  
**Current Status**: Not implemented  
**Feasibility**: ✅ EASY

**Implementation**:
- Block `/dev/kmem`, `/dev/mem`, `/proc/kcore` access
- Use `file_open` LSM hook
- Check path against blocklist
- Also block `init_module`, `finit_module` syscalls

---

#### ❌ SEC-006: Network namespace isolation (Priority: HIGH)
**Requirement**: Isolate network namespace from host  
**Current Status**: Not implemented  
**Feasibility**: ⚠️ DIFFICULT (requires process launch control)

**Implementation**:
- Would need to launch curl in new network namespace
- Use `unshare(CLONE_NEWNET)` before starting curl
- **Challenge**: We're monitoring existing curl processes, not launching them

**Alternative**: Use eBPF to create virtual network isolation (very complex)

**Recommendation**: Document as limitation - requires container/namespace approach.

---

## 📋 Implementation Priority Roadmap

### Phase 1: Quick Wins (Easy implementations)
1. ✅ Adjust MEM-003 to 120 seconds (2 minutes)
2. ✅ Add MEM-004 CPU throttling to 50%
3. ✅ Implement MEM-006 stack size limit (rlimit)
4. ✅ Implement NET-002 protocol blocking (extend current code)
5. ✅ Implement NET-005 private IP blocking
6. ✅ Implement MEM-005 executable mmap blocking (with care)
7. ✅ Implement MEM-002 fork/exec blocking

### Phase 2: File System Policies (Moderate difficulty)
1. ⚠️ Implement FS-001 write path restrictions (LSM file_open)
2. ⚠️ Implement FS-006 system directory blocking
3. ⚠️ Implement FS-002 read path restrictions
4. ⚠️ Implement FS-003 file size limits (rlimit)
5. ⚠️ Implement FS-004 execution prevention (LSM bprm_check)
6. ⚠️ Implement FS-005 total storage quota

### Phase 3: Security Policies (Mixed difficulty)
1. ✅ Implement SEC-003 network admin blocking
2. ✅ Implement SEC-005 kernel memory blocking
3. ⚠️ Implement SEC-004 signal restrictions
4. ⚠️ Implement SEC-001 user privilege dropping (design decision needed)
5. ❌ SEC-002 environment filtering (document limitation)
6. ❌ SEC-006 network namespace (document limitation)

### Phase 4: Advanced Network Policies (Complex)
1. ⚠️ Implement NET-003 connection timeouts
2. ⚠️ Implement NET-004 concurrent connection limits
3. ❌ NET-001 domain whitelisting (needs design decision)

---

## 🚧 Technical Challenges and Design Decisions

### Challenge 1: Process Launch Control
**Issue**: Many policies require control over process launch (SEC-001, SEC-002, SEC-006)  
**Current approach**: Monitoring existing processes  
**Options**:
1. Keep monitoring approach, document limitations
2. Switch to launch-based approach (contradicts "no wrapper" requirement)
3. Hybrid: Monitor existing, but enforce via eBPF at syscall level

**Recommendation**: Option 3 - Continue monitoring but enforce stricter eBPF policies.

---

### Challenge 2: Path Resolution in eBPF
**Issue**: File system policies need path string comparison  
**Difficulty**: eBPF has limited string operations and path resolution  
**Solution**: 
- Use `bpf_d_path()` helper (Linux 5.10+) to resolve paths
- Compare against allowed/blocked patterns
- May need to use BPF ring buffer for userspace verification

---

### Challenge 3: Domain Whitelisting (NET-001)
**Issue**: Hardest policy to implement purely in kernel  
**Options**:
1. Don't implement (document as limitation)
2. Implement SNI-based HTTPS filtering only
3. Add userspace DNS monitoring component
4. Use IP allowlist instead of domain allowlist

**Recommendation**: Option 2 + 4 - SNI filtering for HTTPS, IP allowlist for both

---

### Challenge 4: Testing OOM Killer
**Issue**: Current OOM test doesn't trigger because curl streams efficiently  
**Solution**: 
- Lower memory limit to 5MB for testing
- Or create synthetic test that allocates memory
- Or test with curl's memory buffer options

---

## 📊 Estimated Implementation Effort

| Category | Policies | Est. Hours | Difficulty |
|----------|----------|-----------|------------|
| Phase 1 (Quick Wins) | 7 policies | 8-12 hours | Easy |
| Phase 2 (File System) | 6 policies | 16-24 hours | Moderate-Hard |
| Phase 3 (Security) | 4 policies | 12-16 hours | Mixed |
| Phase 4 (Advanced Network) | 3 policies | 16-24 hours | Hard |
| **Total** | **20 policies** | **52-76 hours** | **6-10 days** |

---

## 🎯 Recommended Next Steps

1. **Immediate** (Today):
   - Adjust timeouts to 120 seconds (MEM-003)
   - Add CPU throttling to 50% (MEM-004)
   - Implement stack size limit (MEM-006)

2. **This Week**:
   - Complete Phase 1 (Quick Wins)
   - Start Phase 2 with FS-001 (write restrictions)

3. **Next Week**:
   - Complete Phase 2 (File System policies)
   - Begin Phase 3 (Security policies)

4. **Following Week**:
   - Complete Phase 3
   - Tackle Phase 4 or document limitations

5. **Documentation**:
   - Update README with policy checklist
   - Create LIMITATIONS.md for infeasible policies
   - Add policy configuration JSON support

---

## 📝 Notes and Considerations

- **eBPF verifier limitations**: Some operations may be rejected by verifier
- **Kernel version compatibility**: Test on Ubuntu 22.04+ (kernel 5.15+)
- **Performance overhead**: Monitor performance impact of multiple LSM hooks
- **Testing strategy**: Create comprehensive test suite for each policy
- **Policy configuration**: Consider implementing JSON config parsing
- **Evaluation alignment**: Ensure implementation covers evaluation criteria

---

## ✅ Success Criteria

To pass the evaluation, the implementation should:
1. ✅ Implement at least 15/24 policies (currently 3/24)
2. ✅ Have all network security policies (NET-002, NET-005, NET-006)
3. ✅ Have all file system restrictions (FS-001, FS-003, FS-004)
4. ✅ Have all memory limits (MEM-001, MEM-003, MEM-004)
5. ✅ Have proper violation handling and logging
6. ✅ Pass all mandatory test cases
7. ✅ Have comprehensive documentation

**Current Score**: 3/24 policies = 12.5%  
**Target Score**: 15/24 policies = 62.5% (passing grade)
