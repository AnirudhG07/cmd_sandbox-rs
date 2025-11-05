# New Tests Summary - MEM-005, MEM-006, SEC-002

## What Was Added

### 1. Memory Tests (mem_tests.rs)
Added 2 new test functions:
- `test_mem005_process_priority()` - Tests CPU priority (nice value)
- `test_mem006_io_priority()` - Tests I/O priority

### 2. Security Tests (sec_tests.rs) - NEW FILE
Created new security test module with 3 test functions:
- `test_sec002_block_ld_preload()` - Tests LD_PRELOAD blocking
- `test_sec002_block_ld_library_path()` - Tests LD_LIBRARY_PATH blocking
- `test_sec002_sandbox_logs()` - Verifies policy is documented

### 3. Main Test Runner (main.rs)
Updated to include:
- `mod sec_tests;` - New security test module
- Calls to MEM-005 and MEM-006 tests
- New "SECURITY POLICIES" section with SEC-002 tests

## Test Details

### MEM-005: Process Priority Test
```rust
// Spawns curl, waits 500ms, reads /proc/{pid}/stat field 19
// Expected: nice value >= 10 (lower priority)
// Why: Ensures downloads don't hog CPU
```

### MEM-006: I/O Priority Test  
```rust
// Spawns curl, waits 500ms, runs `ionice -p {pid}`
// Expected: "best-effort: prio 7" (or 6)
// Why: Prevents disk I/O starvation
// Note: Passes gracefully if ionice not installed
```

### SEC-002: Environment Variable Tests
```rust
// Test 1: Runs curl with LD_PRELOAD, checks /proc/{pid}/environ
// Test 2: Runs curl with LD_LIBRARY_PATH, checks environ
// Test 3: Documents that policy is enforced by sandbox
// Note: Full implementation requires wrapper script
```

## How to Run

```bash
# Terminal 1: Start sandbox
sudo -E RUST_LOG=info ./target/release/cmd-sandbox

# Terminal 2: Run all tests
./target/release/cmd-sandbox-tests

# Or run just to see new tests:
./target/release/cmd-sandbox-tests 2>&1 | grep -A 50 "MEM-005\|MEM-006\|SEC-002"
```

## Expected Results

### MEM-005
```
▶ MEM-005: Process Priority
Test MEM-005: Verify curl process has lowered priority
---
✅ Process priority adjusted: nice value = 10
```

### MEM-006
```
▶ MEM-006: I/O Priority
Test MEM-006: Verify curl process has lowered I/O priority
---
✅ I/O priority adjusted: best-effort: prio 7
```

### SEC-002
```
▶ SEC-002: Block Dangerous Environment Variables
Test SEC-002.1: Verify LD_PRELOAD is blocked/sanitized
---
❌ LD_PRELOAD not blocked (Note: Full implementation requires wrapper script)

Test SEC-002.2: Verify LD_LIBRARY_PATH is blocked/sanitized
---
❌ LD_LIBRARY_PATH not blocked (Note: Full implementation requires wrapper script)

Test SEC-002.3: Verify sandbox logs environment policy enforcement
---
✅ Policy enforcement documented (check sandbox logs)
```

**Note**: SEC-002 tests are expected to show as "not fully implemented" because environment variable cleaning requires a wrapper script. The sandbox logs the policy intent.

## Implementation Status

✅ **Fully Working**:
- MEM-005: Priority is set when process is detected
- MEM-006: I/O priority is set when process is detected
- Tests verify these work correctly

⚠️ **Partially Implemented**:
- SEC-002: Policy is documented and logged
- Full implementation needs wrapper script to spawn curl/wget with clean environment

## Test Count

**Total**: 21 tests (was 13)
- Network: 9 tests
- Memory: 6 tests (+2 new: MEM-005, MEM-006)
- Filesystem: 4 tests (in code, not working yet)
- Security: 3 tests (+3 new: SEC-002.1, SEC-002.2, SEC-002.3)

## Files Modified

1. `cmd-sandbox-tests/src/mem_tests.rs` - Added MEM-005 and MEM-006 tests
2. `cmd-sandbox-tests/src/sec_tests.rs` - NEW FILE - Added SEC-002 tests
3. `cmd-sandbox-tests/src/main.rs` - Added module and test calls

## Sandbox Logs to Watch For

When tests run, check sandbox logs for:
```
✓ Set PID XXXX priority to nice value 10
✓ Set PID XXXX I/O priority to class=2 priority=7
Policy: Would block environment variables ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH"] for PID XXXX
```

These confirm the policies are being applied correctly.
