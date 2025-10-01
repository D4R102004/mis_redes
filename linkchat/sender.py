import socket
import sys
from .frame import Frame, mac_str_to_bytes


def send_frame(frame_bytes, interface="eth0"):
    """Send raw frame bytes on the given interface.

    Note: requires root privileges and Linux AF_PACKET support.
    """
    if sys.platform != 'linux':
        raise RuntimeError("Raw AF_PACKET sockets are only supported on Linux")

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        s.bind((interface, 0))
        s.send(frame_bytes)
    finally:
        s.close()


def send_text(dst_mac, src_mac, ethertype, text, interface="eth0"):
    """Convenience helper: build a Frame from text and send it."""
    if isinstance(text, str):
        payload = text.encode('utf-8')
    else:
        payload = bytes(text)

    f = Frame(dst_mac, src_mac, ethertype, payload)
    send_frame(f.to_bytes(), interface=interface)


if __name__ == '__main__':
    # Simple CLI: send message to dst_mac
    if len(sys.argv) < 4:
        print("Usage: python sender.py <interface> <dst_mac> <message>")
        sys.exit(1)
    interface = sys.argv[1]
    dst = sys.argv[2]
    msg = sys.argv[3]
    # Use a placeholder source MAC; users should replace with their interface's MAC
    src = '11:22:33:44:55:66'
    ETH_CHAT = 0x88b5
    send_text(dst, src, ETH_CHAT, msg, interface=interface)
