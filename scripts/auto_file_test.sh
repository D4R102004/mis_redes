#!/bin/sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILE="docker-compose.bridge.yml"

echo "Building images..."
docker compose -f "$COMPOSE_FILE" build

echo "Bringing up containers..."
sudo docker compose -f "$COMPOSE_FILE" up -d

sleep 2

echo "Creating test file and copying to nodeB..."
echo "Prueba de archivo desde nodeB" > /tmp/testfile_for_transfer.txt
docker cp /tmp/testfile_for_transfer.txt linkchat_node_b:/tmp/testfile_for_transfer.txt

echo "Start receiver in nodeA (background)..."
docker exec -d linkchat_node_a sh -c "python3 -u -m linkchat.receiver eth0 > /tmp/rcv_file.log 2>&1"
sleep 1

MAC_A=$(docker exec linkchat_node_a cat /sys/class/net/eth0/address)
echo "nodeA MAC: $MAC_A"

echo "Trigger send-file from nodeB..."
docker exec linkchat_node_b sh -c "python3 -u -m linkchat.cli <<'CLI'
iface
0
send-file $MAC_A /tmp/testfile_for_transfer.txt
exit
CLI"

sleep 2

echo "Receiver log:" 
docker exec linkchat_node_a sh -c "tail -n 200 /tmp/rcv_file.log || true"

echo "Received file content (on nodeA):"
docker exec linkchat_node_a sh -c "cat /tmp/received_testfile_for_transfer.txt || echo 'No file found'"

echo "Tearing down..."
sudo docker compose -f "$COMPOSE_FILE" down

echo "Done."
