Link-Chat link-layer helpers
=============================

This small package contains initial building blocks for the Link-Chat project (proyecto de redes).

Files:
- `frame.py` - Frame class with helpers to serialize/parse Ethernet-like frames.
- `sender.py` - Helpers to send frames (requires Linux + root; AF_PACKET sockets).
- `receiver.py` - Helpers to receive frames and parse them into `Frame` instances.

Quick usage (Linux, run as root):

1) Run receiver on interface `eth0`:

    python3 linkchat/receiver.py eth0

2) Send a simple text message (from another machine on the same LAN):

    python3 linkchat/sender.py eth0 aa:bb:cc:dd:ee:ff "hola desde enlace"

Notes and next steps
- The current code assumes raw link-layer access (no IP). Use with caution and as root.
- Next steps: implement framing for message types (control vs data), chunking for large files, discovery (broadcast), and a small console CLI that manages peers.
