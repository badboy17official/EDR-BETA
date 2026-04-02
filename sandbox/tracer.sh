#!/bin/bash
# tracer.sh - Runs inside the Docker sandbox to monitor malware execution

TARGET_BIN=$1
TIMEOUT_SEC=${2:-30} # Default 30s timeout
OUTPUT_DIR="/sandbox_out"
STRACE_LOG="${OUTPUT_DIR}/strace.log"
PCAP_LOG="${OUTPUT_DIR}/traffic.pcap"

# Ensure the executable has run permissions
chmod +x "$TARGET_BIN"

# Start background network capture if we have CAP_NET_RAW / CAP_NET_ADMIN
# Since we might run in a restricted netns, this might fail, so we || true it.
tcpdump -i any -w "$PCAP_LOG" -U > /dev/null 2>&1 &
TCPDUMP_PID=$!

# Run the binary under strace, follow forks (-f), include timestamps (-ttt)
# and decode common syscall arguments (-e trace=all initially, but we can filter later in the parser)
timeout "$TIMEOUT_SEC" strace -f -ttt -o "$STRACE_LOG" -e trace=file,process,network,desc,ipc "$TARGET_BIN" > "${OUTPUT_DIR}/stdout.log" 2> "${OUTPUT_DIR}/stderr.log"

EXIT_CODE=$?

# Kill network capture
kill $TCPDUMP_PID > /dev/null 2>&1 || true

# Save the exit code
echo "$EXIT_CODE" > "${OUTPUT_DIR}/exit_code.txt"

# Provide permissions so the host can read the output easily
chmod 777 -R "$OUTPUT_DIR"
