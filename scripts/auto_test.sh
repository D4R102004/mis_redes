#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="docker-compose.bridge.yml"

echo "Building Docker images..."
docker compose -f "$COMPOSE_FILE" build

echo "Bringing up containers..."
sudo docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting 3s for containers to start..."
sleep 3

echo "Starting receiver in nodeA (detached)..."
docker exec -d linkchat_node_a sh -c "python3 -u -m linkchat.receiver eth0 > /tmp/rcv.log 2>&1"

echo "Waiting 1s for receiver to initialize..."
sleep 1

echo "Reading MAC address of nodeA interface..."
MAC_A=$(docker exec linkchat_node_a cat /sys/class/net/eth0/address)
echo "MAC of nodeA: $MAC_A"

echo "Sending test message from nodeB to nodeA..."
docker exec linkchat_node_b sh -c "python3 -u -m linkchat.sender eth0 \"$MAC_A\" \"Mensaje de prueba desde nodeB coca\" > /tmp/snd.log 2>&1 || echo SEND_FAILED > /tmp/snd.log"

echo "Waiting 2s for delivery..."
sleep 2

echo "Receiver output (last 100 lines):"
docker exec linkchat_node_a sh -c "tail -n 100 /tmp/rcv.log || true"

echo "Sender log (nodeB):"
docker exec linkchat_node_b sh -c "cat /tmp/snd.log || true"

echo "Tearing down containers..."
sudo docker compose -f "$COMPOSE_FILE" down

echo "Done."
