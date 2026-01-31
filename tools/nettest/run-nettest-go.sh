#!/bin/bash
set -e

CONTAINER=${1:-tetragon1}
TCP_PORT=${2:-9999}
UDP_PORT=${3:-9998}
PACKET_COUNT=${4:-3}
NETTEST_BIN=${5:-/tetragon/nettest}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Building nettest binary ==="
GOOS=linux GOARCH=arm64 go build -o "$SCRIPT_DIR/../../nettest" "$SCRIPT_DIR"
if [ ! -f "$SCRIPT_DIR/../../nettest" ]; then
    echo "=== Failed to build nettest binary ==="
    exit 1
fi

echo "=== Network test in container: $CONTAINER (using Go nettest) ==="

# tail -f -n 0 synthetic-events.jsonl tetragon.log &
# TAIL_PID=$!

# TCP test
echo "[TCP] Starting server on port $TCP_PORT..."
docker exec -d "$CONTAINER" "$NETTEST_BIN" -server -proto tcp -addr "0.0.0.0:$TCP_PORT"
sleep 0.2

echo "[TCP] Sending $PACKET_COUNT packets..."
docker exec "$CONTAINER" "$NETTEST_BIN" -proto tcp -addr "127.0.0.1:$TCP_PORT" -count "$PACKET_COUNT" -delay 100ms
sleep 0.1

echo "[TCP] Stopping server..."
docker exec "$CONTAINER" pkill -f "$NETTEST_BIN -server -proto tcp" 2>/dev/null || true
sleep 0.2

# UDP test
echo "[UDP] Starting server on port $UDP_PORT..."
docker exec -d "$CONTAINER" "$NETTEST_BIN" -server -proto udp -addr "0.0.0.0:$UDP_PORT"
sleep 0.2

echo "[UDP] Sending $PACKET_COUNT packets..."
docker exec "$CONTAINER" "$NETTEST_BIN" -proto udp -addr "127.0.0.1:$UDP_PORT" -count "$PACKET_COUNT" -delay 100ms
sleep 0.1

echo "[UDP] Stopping server..."
docker exec "$CONTAINER" pkill -f "$NETTEST_BIN -server -proto udp" 2>/dev/null || true

# sleep 0.3
# kill $TAIL_PID 2>/dev/null || true

echo "=== Done ==="
