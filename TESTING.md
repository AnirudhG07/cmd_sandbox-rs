# Testing Guide for curl_sandbox-rs

## Quick Start

### 1. Start the sandbox
```bash
sudo -E RUST_LOG=info ./target/release/cmd-sandbox
```

### 2. Run automated tests
```bash
./test-sandbox.sh
```

The test script will show full output for each test so you can manually verify the results.

## What Gets Tested

### ✅ Policy 1: HTTPS-Only (eBPF LSM)
- HTTPS (port 443): Should work
- HTTP (port 80): Should be blocked

### ✅ Policy 2: Memory Limit (cgroup v2)
- Small downloads: Should work
- Large downloads: Should be OOM-killed
- Checks: `/sys/fs/cgroup/curl_sandbox/memory.events`

### ✅ Policy 3: CPU Limit (cgroup v2)
- Quick operations: Should work
- Long operations: Would be throttled/killed after 30s CPU time
- Note: Hard to test with curl (I/O-bound, not CPU-bound)

### ❌ Policy 4: File Path Restrictions
- NOT IMPLEMENTED (not feasible with eBPF/cgroup)

## Manual Testing

### Test HTTPS-only:
```bash
# Should work
curl https://example.com -o /tmp/test.html

# Should fail
curl http://neverssl.com -o /tmp/test.html
```

### Test memory limit:
```bash
# Check current limit
cat /sys/fs/cgroup/curl_sandbox/memory.max

# Download large file (will be OOM-killed)
timeout 10 curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/large.bin

# Check OOM events
cat /sys/fs/cgroup/curl_sandbox/memory.events | grep oom
```

### Test CPU limit:
```bash
# Check current limit
cat /sys/fs/cgroup/curl_sandbox/cpu.max

# CPU limit is hard to test with curl (I/O-bound)
# Would need CPU-intensive operation like compression
```

### Adjust limits:
```bash
# Change memory limit
echo "10M" | sudo tee /sys/fs/cgroup/curl_sandbox/memory.max

# Change CPU limit (30 seconds per 1 second period)
echo "30000000 1000000" | sudo tee /sys/fs/cgroup/curl_sandbox/cpu.max
```

## Expected Output

### Successful HTTPS:
```
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   513  100   513    0     0    333      0  0:00:01  0:00:01 --:--:--   333
```

### Blocked HTTP:
```
curl: (7) Failed to connect to neverssl.com port 80 after 125 ms: Couldn't connect to server
```

### OOM Kill:
```
zsh: killed     curl https://...
```

Check with:
```bash
cat /sys/fs/cgroup/curl_sandbox/memory.events
# Look for: oom X (where X > 0)
```

## Monitoring

### Watch sandbox logs:
```bash
# In the terminal running cmd-sandbox
# You'll see messages like:
# ✓ Moved curl 12345 to limited cgroup (1MB memory, 30s CPU)
# 🚫 SANDBOX BLOCKED: curl attempted connection on port 80
```

### Check cgroup membership:
```bash
# While curl is running (in another terminal):
ps aux | grep curl
cat /sys/fs/cgroup/curl_sandbox/cgroup.procs
```

### Check resource usage:
```bash
cat /sys/fs/cgroup/curl_sandbox/memory.current
cat /sys/fs/cgroup/curl_sandbox/memory.peak
cat /sys/fs/cgroup/curl_sandbox/memory.events
cat /sys/fs/cgroup/curl_sandbox/cpu.stat
```

## Troubleshooting

### Sandbox not working:
1. Check if running: `pgrep -f cmd-sandbox`
2. Check if cgroup exists: `ls /sys/fs/cgroup/curl_sandbox`
3. Restart sandbox: Ctrl+C and re-run

### Curl works when it shouldn't:
1. Check if curl is in cgroup: `cat /proc/$(pgrep curl)/cgroup`
2. Check sandbox logs for "Moved curl" messages
3. Verify limits: `cat /sys/fs/cgroup/curl_sandbox/*.max`

### All curls get killed:
1. Memory limit too strict: Increase with `echo "10M" | sudo tee /sys/fs/cgroup/curl_sandbox/memory.max`
2. Check OOM count: `cat /sys/fs/cgroup/curl_sandbox/memory.events`

## Notes

- The sandbox polls `/proc` every 100ms to detect new curl/wget processes
- Processes are moved to the cgroup automatically
- Kernel enforces limits (not eBPF) - very reliable
- HTTP blocking happens at connection time (eBPF LSM)
- Memory/CPU limits happen after process starts (cgroup)

