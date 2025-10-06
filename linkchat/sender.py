import socket
import sys
import fcntl
import struct
from .frame import Frame, mac_str_to_bytes, mac_bytes_to_str
import os
import hashlib
import random

# File transfer message types
MSG_FILE_START = 1
MSG_FILE_CHUNK = 2
MSG_FILE_END = 3

CHUNK_SIZE = 1000
ETH_CHAT = 0x88b5


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

    # If src_mac is None, try to detect from interface
    if src_mac is None:
        try:
            src_mac = get_iface_mac(interface)
        except Exception:
            # fallback to zero MAC
            src_mac = '00:00:00:00:00:00'

    f = Frame(dst_mac, src_mac, ethertype, payload)
    try:
        send_frame(f.to_bytes(), interface=interface)
        print(f"Sent LinkChat message to {dst_mac} via {interface}")
    except Exception as e:
        print("Send failed:", e, file=sys.stderr)
        raise


def send_file(dst_mac, src_mac, filepath, interface="eth0"):
    """Send a file in simple chunks over Link-Chat.

    Protocol (payload layout):
      - FILE_START: type(1)=1 | filename_len(1) | filename | filesize(8)
      - FILE_CHUNK: type(1)=2 | seq(4) | data...
      - FILE_END:   type(1)=3 | seq(4)
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # compute SHA256 and a transfer id
    name_bytes = filename.encode('utf-8')
    if len(name_bytes) > 255:
        raise ValueError('filename too long')

    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as _fh:
        for chunk in iter(lambda: _fh.read(8192), b''):
            sha256.update(chunk)
    digest = sha256.digest()  # 32 bytes

    transfer_id = random.getrandbits(32) & 0xFFFFFFFF

    # start payload layout:
    # type(1)=1 | transfer_id(4) | filename_len(1) | filename | filesize(8) | sha256(32)
    start_payload = (bytes([MSG_FILE_START]) + struct.pack('!I', transfer_id) + bytes([len(name_bytes)])
                     + name_bytes + struct.pack('!Q', filesize) + digest)
    fstart = Frame(dst_mac, src_mac or get_iface_mac(interface), ETH_CHAT, start_payload)
    send_frame(fstart.to_bytes(), interface=interface)
    print(f"Sent FILE_START for {filename} ({filesize} bytes) transfer_id={transfer_id:08x}")

    # send chunks
    seq = 0
    with open(filepath, 'rb') as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            seq += 1
            # chunk payload: type(1)=2 | transfer_id(4) | seq(4) | data...
            payload = bytes([MSG_FILE_CHUNK]) + struct.pack('!I', transfer_id) + struct.pack('!I', seq) + chunk
            fchunk = Frame(dst_mac, src_mac or get_iface_mac(interface), ETH_CHAT, payload)
            send_frame(fchunk.to_bytes(), interface=interface)
    # send FILE_END
    # end payload: type(1)=3 | transfer_id(4) | seq(4)
    end_payload = bytes([MSG_FILE_END]) + struct.pack('!I', transfer_id) + struct.pack('!I', seq)
    fend = Frame(dst_mac, src_mac or get_iface_mac(interface), ETH_CHAT, end_payload)
    send_frame(fend.to_bytes(), interface=interface)
    print(f"Sent FILE_END (seq={seq}) transfer_id={transfer_id:08x}")


def get_iface_mac(ifname):
    """Return MAC string for interface (Linux ioctl SIOCGIFHWADDR)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname.encode('utf-8')[:15]))
        mac = info[18:24]
        return mac_bytes_to_str(mac)
    finally:
        s.close()


if __name__ == '__main__':
    # Simple CLI: send message to dst_mac
    if len(sys.argv) < 4:
        print("Usage: python sender.py <interface> <dst_mac> <message>")
        sys.exit(1)
    interface = sys.argv[1]
    dst = sys.argv[2]
    msg = sys.argv[3]
    # Let send_text detect source MAC automatically
    ETH_CHAT = 0x88b5
    send_text(dst, None, ETH_CHAT, msg, interface=interface)
