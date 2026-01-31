#!/bin/bash
set -e

CONTAINER=${1:-tetragon1}
TCP_PORT=${2:-9999}
UDP_PORT=${3:-9998}
PACKET_COUNT=${4:-3}

echo "=== Network test in container: $CONTAINER ==="

tail -f -n 0 synthetic-events.jsonl tetragon.log &
TAIL_PID=$!

# TCP test
echo "[TCP] Starting server on port $TCP_PORT..."
docker exec -d "$CONTAINER" sh -c "nc -l -p $TCP_PORT > /dev/null 2>&1 &"
sleep 0.2

echo "[TCP] Sending $PACKET_COUNT packets..."
for i in $(seq 1 "$PACKET_COUNT"); do
    docker exec "$CONTAINER" sh -c "echo 'tcp-packet-$i' | nc -w 1 127.0.0.1 $TCP_PORT" 2>/dev/null || true
    sleep 0.1
done

echo "[TCP] Stopping server..."
docker exec "$CONTAINER" sh -c "pkill -f 'nc -l -p $TCP_PORT'" 2>/dev/null || true
sleep 0.2

# UDP test
echo "[UDP] Starting server on port $UDP_PORT..."
docker exec -d "$CONTAINER" sh -c "nc -l -u -p $UDP_PORT > /dev/null 2>&1 &"
sleep 0.2

echo "[UDP] Sending $PACKET_COUNT packets..."
for i in $(seq 1 "$PACKET_COUNT"); do
    docker exec "$CONTAINER" sh -c "echo 'udp-packet-$i' | nc -u -w 1 127.0.0.1 $UDP_PORT" 2>/dev/null || true
    sleep 0.1
done

echo "[UDP] Stopping server..."
docker exec "$CONTAINER" sh -c "pkill -f 'nc -l -u -p $UDP_PORT'" 2>/dev/null || true

sleep 0.3
kill $TAIL_PID 2>/dev/null || true

echo "=== Done ==="
