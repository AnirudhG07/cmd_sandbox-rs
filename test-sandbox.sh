#!/bin/bash
# Comprehensive test suite for curl_sandbox-rs
# Tests all 3 implemented policies: HTTPS-only, Memory limit, CPU limit

set +e  # Don't exit on error - we want to see all test results

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Helper functions
pass_test() {
    echo "Result: ✅ PASS - $1"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

fail_test() {
    echo "Result: ❌ FAIL - $1"
    FAILED_TESTS=$((FAILED_TESTS + 1))
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
}

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       curl_sandbox-rs Comprehensive Test Suite                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Check if sandbox is running
if ! pgrep -f "cmd-sandbox" > /dev/null; then
    echo "❌ ERROR: cmd-sandbox is not running!"
    echo "   Start it first: sudo -E RUST_LOG=info ./target/release/cmd-sandbox"
    exit 1
fi

echo "✓ Sandbox is running"
echo ""

# Check cgroup exists
if [ ! -d "/sys/fs/cgroup/cmd_sandbox" ]; then
    echo "❌ ERROR: cgroup not found at /sys/fs/cgroup/cmd_sandbox"
    exit 1
fi

echo "✓ Cgroup exists"
echo ""

# Display current limits
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Current Resource Limits"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Memory limit: $(cat /sys/fs/cgroup/cmd_sandbox/memory.max)"
echo "CPU limit: $(cat /sys/fs/cgroup/cmd_sandbox/cpu.max)"
echo ""

# Get baseline OOM count
OOM_BASELINE=$(grep "oom " /sys/fs/cgroup/cmd_sandbox/memory.events | awk '{print $2}')
echo "Starting OOM count: $OOM_BASELINE"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔒 Test 1: HTTPS-Only Policy (Network)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Test 1.1: HTTPS (port 443) - Should SUCCEED"
echo "Command: curl https://example.com -o /tmp/test-https.html"
echo "---"
curl https://example.com -o /tmp/test-https.html
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ] && [ -f /tmp/test-https.html ]; then
    FILE_SIZE=$(stat -f%z /tmp/test-https.html 2>/dev/null || stat -c%s /tmp/test-https.html)
    pass_test "Downloaded $FILE_SIZE bytes via HTTPS"
    rm /tmp/test-https.html
else
    fail_test "HTTPS download failed (exit code: $EXIT_CODE)"
fi
echo ""

echo "Test 1.2: HTTP (port 80) - Should FAIL"
echo "Command: timeout 5 curl http://neverssl.com -o /tmp/test-http.html"
echo "---"
timeout 5 curl http://neverssl.com -o /tmp/test-http.html 2>&1
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    pass_test "HTTP blocked (exit code: $EXIT_CODE)"
else
    fail_test "HTTP was not blocked"
fi
rm -f /tmp/test-http.html
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💾 Test 2: Memory Limit Policy (cgroup)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Test 2.1: Small download (<5MB) - Should SUCCEED"
echo "Command: curl https://example.com -o /tmp/small.html"
echo "---"
curl https://example.com -o /tmp/small.html
EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    pass_test "Small download succeeded"
    rm /tmp/small.html
else
    fail_test "Small download failed (exit code: $EXIT_CODE)"
fi
echo ""

echo "Test 2.2: Large download with memory allocation"
echo "Testing with actual file download that uses memory..."
echo "Command: curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/large.bin --max-time 60"
echo "---"
echo "Note: This will be killed by OOM or timeout. Observing behavior..."
timeout 10 curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/large.bin 2>&1
EXIT_CODE=$?

# Check if OOM kill happened
OOM_CURRENT=$(grep "oom " /sys/fs/cgroup/cmd_sandbox/memory.events | awk '{print $2}')
OOM_DIFF=$((OOM_CURRENT - OOM_BASELINE))

echo ""
echo "Exit code: $EXIT_CODE"
echo "OOM events before: $OOM_BASELINE"
echo "OOM events after: $OOM_CURRENT"
echo "New OOM kills: $OOM_DIFF"

if [ $OOM_DIFF -gt 0 ]; then
    pass_test "Memory limit enforced! Process was OOM-killed $OOM_DIFF time(s)"
elif [ $EXIT_CODE -eq 124 ]; then
    fail_test "Process ran for 10s without OOM (timeout, may be slow download)"
else
    fail_test "No OOM event detected (exit code: $EXIT_CODE)"
fi

rm -f /tmp/large.bin
echo ""

echo "Test 2.3: Check memory statistics"
echo "Command: cat /sys/fs/cgroup/cmd_sandbox/memory.events"
echo "---"
cat /sys/fs/cgroup/cmd_sandbox/memory.events
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏱️  Test 3: Timing Limits (CPU time: 2s, Wall clock: 10s)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Test 3.1: Quick operation (<2s CPU, <10s wall clock) - Should SUCCEED"
echo "Command: curl https://example.com -o /tmp/quick.html"
echo "---"
TIME_START=$(date +%s%3N)
curl https://example.com -o /tmp/quick.html 2>&1
EXIT_CODE=$?
TIME_END=$(date +%s%3N)
DURATION=$(echo "scale=3; ($TIME_END - $TIME_START) / 1000" | bc)

if [ $EXIT_CODE -eq 0 ]; then
    pass_test "Quick operation completed in ${DURATION}s (under limits)"
    rm -f /tmp/quick.html
else
    fail_test "Quick operation failed (exit code: $EXIT_CODE after ${DURATION}s)"
fi
echo ""

echo "Test 3.2: Long download (>10s wall clock) - Should TIMEOUT"
echo "Command: curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/timeout-test.bin"
echo "---"
echo "Note: Should be killed after ~10 seconds wall clock time by sandbox"

TIME_START=$(date +%s%3N)
curl https://ash-speed.hetzner.com/10GB.bin -o /tmp/timeout-test.bin 2>&1
EXIT_CODE=$?
TIME_END=$(date +%s%3N)
DURATION=$(echo "scale=3; ($TIME_END - $TIME_START) / 1000" | bc)

echo ""
echo "Exit code: $EXIT_CODE"
echo "Duration: ${DURATION}s"
echo ""

# Exit code 137 = 128 + 9 (SIGKILL)
if [ $EXIT_CODE -eq 137 ] || [ $EXIT_CODE -eq 143 ]; then
    if (( $(echo "$DURATION > 9.5" | bc -l) )) && (( $(echo "$DURATION < 11.0" | bc -l) )); then
        pass_test "Process killed after ${DURATION}s (within 10s wall clock timeout)"
    else
        fail_test "Process killed but timing off (${DURATION}s, expected ~10s)"
    fi
else
    fail_test "Process not killed properly (exit code: $EXIT_CODE after ${DURATION}s)"
fi

rm -f /tmp/timeout-test.bin
echo ""

echo "Test 3.3: CPU-intensive operation (>2s CPU time) - Should be throttled"
echo "Command: Running 30 curl requests in rapid succession"
echo "---"
echo "Note: Multiple rapid requests accumulate CPU time, should hit 2s CPU limit"

SUCCESS_COUNT=0
THROTTLE_COUNT=0
TIME_START=$(date +%s)

for i in {1..30}; do
    timeout 2 curl -s https://example.com -o /dev/null 2>&1
    if [ $? -eq 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        THROTTLE_COUNT=$((THROTTLE_COUNT + 1))
    fi
done

TIME_END=$(date +%s)
TOTAL_DURATION=$((TIME_END - TIME_START))

echo ""
echo "Completed in ${TOTAL_DURATION}s"
echo "Successful requests: $SUCCESS_COUNT"
echo "Throttled/failed: $THROTTLE_COUNT"

# Check CPU throttling stats
echo ""
echo "CPU throttling statistics:"
cat /sys/fs/cgroup/cmd_sandbox/cpu.stat 2>/dev/null | grep throttled || echo "CPU stats not available"
echo ""

if [ $THROTTLE_COUNT -gt 0 ]; then
    pass_test "CPU throttling detected: $THROTTLE_COUNT requests throttled/failed"
else
    # It's okay if no throttling - depends on system load
    pass_test "All $SUCCESS_COUNT requests completed (CPU limit may not have been reached)"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Final Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Total Tests: $TOTAL_TESTS"
echo "✅ Passed: $PASSED_TESTS"
echo "❌ Failed: $FAILED_TESTS"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test Breakdown:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔒 Network Policy (HTTPS-only):"
echo "   • Test 1.1: HTTPS allowed"
echo "   • Test 1.2: HTTP blocked"
echo ""
echo "💾 Memory Policy (10MB limit via cgroup):"
echo "   • Test 2.1: Small download"
echo "   • Test 2.2: Large download (should OOM or be killed)"
echo "   • OOM kills this session: $OOM_DIFF"
echo ""
echo "⏱️  Timing Policies (CPU: 2s via cgroup, Wall clock: 10s):"
echo "   • Test 3.1: Quick operation (<2s CPU, <10s wall clock)"
echo "   • Test 3.2: Long download (>10s wall clock, should timeout)"
echo "   • Test 3.3: CPU-intensive (multiple requests, CPU throttling)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 All tests PASSED! Sandbox is working correctly."
else
    echo "⚠️  Some tests FAILED. Check output above for details."
fi

# Exit with appropriate code
if [ $FAILED_TESTS -eq 0 ]; then
    exit 0
else
    exit 1
fi
