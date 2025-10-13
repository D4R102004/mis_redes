#!/bin/sh
# Simple entrypoint for Link-Chat container.
# Usage:
#  - to run CLI: ./docker-entrypoint.sh cli
#  - to run receiver blocking: ./docker-entrypoint.sh receiver <iface>
#  - to run sender one-shot: ./docker-entrypoint.sh send <iface> <dst_mac> <message>

set -e

cmd="$1"
shift || true

cd /app

case "$cmd" in
  cli)
    python3 -u linkchat/cli.py
    ;;
  receiver)
    iface="$1"
    python3 -u linkchat/receiver.py "$iface"
    ;;
  send)
    iface="$1"
    dst="$2"
    msg="$3"
    python3 -u linkchat/sender.py "$iface" "$dst" "$msg"
    ;;
  *)
    # If unknown command was provided, assume the user wants to run it directly
    # (this allows compose to use `command: ["sleep","infinity"]`).
    if [ -n "$cmd" ]; then
      exec "$cmd" "$@"
    else
      echo "Usage: $0 {cli|receiver|send} ..."
      exit 2
    fi
    ;;
esac
