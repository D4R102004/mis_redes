# sender.py (modificado para ACKs / sliding window / retransmit)
import socket
import sys
import fcntl
import struct
from .frame import Frame, mac_str_to_bytes, mac_bytes_to_str
import os
import hashlib
import random
import threading
import time
import math

# File transfer message types
MSG_FILE_START = 1
MSG_FILE_CHUNK = 2
MSG_FILE_END = 3
MSG_FILE_ACK = 4

# Tunables
CHUNK_SIZE = 1400           # bytes per chunk (safe under typical MTU)
ETH_CHAT = 0x88b5
WINDOW_SIZE = 64            # sliding window size (chunks in-flight)
ACK_TIMEOUT = 2.0           # seconds to wait for ACK before retransmit
MAX_RETRIES = 8

# Global state for active transfers: transfer_id -> state dict
SEND_STATE = {}
# Track ack-listener threads per interface
_ACK_LISTENERS = {}
_ACK_LISTENERS_LOCK = threading.Lock()


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


def _start_ack_listener(interface):
    """Start a background thread that listens for ACK frames on interface."""
    with _ACK_LISTENERS_LOCK:
        if interface in _ACK_LISTENERS:
            return
        t = threading.Thread(target=_ack_listener, args=(interface,), daemon=True)
        _ACK_LISTENERS[interface] = t
        t.start()


def _ack_listener(interface):
    """Background loop: listen for LinkChat frames and mark ACKs."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        s.bind((interface, 0))
    except Exception as e:
        print("ACK listener bind failed:", e, file=sys.stderr)
        return
    while True:
        try:
            raw, addr = s.recvfrom(65535)
        except Exception:
            break
        try:
            f = Frame.from_bytes(raw)
        except Exception:
            continue
        try:
            if f.ethertype_int() != ETH_CHAT:
                continue
        except Exception:
            continue
        payload = f.payload
        if not payload:
            continue
        if payload[0] != MSG_FILE_ACK:
            continue
        # ACK layout: type(1)=4 | transfer_id(4) | seq(4)
        if len(payload) < 1 + 4 + 4:
            continue
        transfer_id = struct.unpack('!I', payload[1:5])[0]
        seq = struct.unpack('!I', payload[5:9])[0]
        state = SEND_STATE.get(transfer_id)
        if not state:
            continue
        with state['lock']:
            if seq in state['unacked']:
                # remove from unacked and mark acked
                del state['unacked'][seq]
                state['acked'].add(seq)
                # notify sender loop
                state['cond'].notify_all()


def get_iface_mac(ifname):
    """Return MAC string for interface (Linux ioctl SIOCGIFHWADDR)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname.encode('utf-8')[:15]))
        mac = info[18:24]
        return mac_bytes_to_str(mac)
    finally:
        s.close()


def send_file(dst_mac, src_mac, filepath, interface="eth0"):
    """Send a file reliably using ACKs + sliding window.

    Note: requires root because it uses raw AF_PACKET send and listens for ACKs.
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
    total_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
    if total_chunks == 0:
        total_chunks = 1

    # Prepare source MAC once
    if src_mac is None:
        src_mac = get_iface_mac(interface)

    # Prepare transfer state
    state = {
        'transfer_id': transfer_id,
        'filename': filename,
        'filesize': filesize,
        'total_chunks': total_chunks,
        'acked': set(),
        'unacked': {},   # seq -> {'time': t, 'attempts': n}
        'next_seq': 1,
        'lock': threading.Lock(),
        'cond': threading.Condition(),  # will set lock below
    }
    # tie condition to the same lock
    state['cond'] = threading.Condition(state['lock'])
    SEND_STATE[transfer_id] = state

    # ensure ack-listener running
    _start_ack_listener(interface)

    # Send FILE_START
    start_payload = (bytes([MSG_FILE_START]) + struct.pack('!I', transfer_id) +
                     bytes([len(name_bytes)]) + name_bytes + struct.pack('!Q', filesize) + digest)
    fstart = Frame(dst_mac, src_mac, ETH_CHAT, start_payload)
    send_frame(fstart.to_bytes(), interface=interface)
    print(f"Sent FILE_START for {filename} ({filesize} bytes) transfer_id={transfer_id:08x}")

    # open file for random access
    fh = open(filepath, 'rb')

    def _send_chunk(seq):
        """Read chunk seq and send it."""
        offset = (seq - 1) * CHUNK_SIZE
        fh.seek(offset)
        data = fh.read(CHUNK_SIZE)
        payload = bytes([MSG_FILE_CHUNK]) + struct.pack('!I', transfer_id) + struct.pack('!I', seq) + data
        fchunk = Frame(dst_mac, src_mac, ETH_CHAT, payload)
        send_frame(fchunk.to_bytes(), interface=interface)

    try:
        # Main loop: send chunks with sliding window, retransmit on timeout
        with state['lock']:
            while True:
                # 1) feed window
                while state['next_seq'] <= total_chunks and len(state['unacked']) < WINDOW_SIZE:
                    seq = state['next_seq']
                    _send_chunk(seq)
                    state['unacked'][seq] = {'time': time.time(), 'attempts': 1}
                    state['next_seq'] += 1

                # 2) exit condition: all sent and all acked
                if state['next_seq'] > total_chunks and not state['unacked']:
                    break

                # 3) wait a bit for ACKs or timeout to trigger retransmit
                state['cond'].wait(timeout=0.5)

                # 4) check for timed-out unacked seqs
                now = time.time()
                for seq, info in list(state['unacked'].items()):
                    if now - info['time'] > ACK_TIMEOUT:
                        if info['attempts'] >= MAX_RETRIES:
                            raise RuntimeError(f"Chunk {seq} failed after {MAX_RETRIES} retries")
                        # retransmit
                        try:
                            _send_chunk(seq)
                        except Exception as e:
                            print("Retransmit failed to send chunk", seq, e)
                        state['unacked'][seq]['time'] = now
                        state['unacked'][seq]['attempts'] += 1

        # all chunks acked -> send FILE_END
        end_payload = bytes([MSG_FILE_END]) + struct.pack('!I', transfer_id) + struct.pack('!I', total_chunks)
        fend = Frame(dst_mac, src_mac, ETH_CHAT, end_payload)
        send_frame(fend.to_bytes(), interface=interface)
        print(f"Sent FILE_END (seq={total_chunks}) transfer_id={transfer_id:08x}")
    finally:
        fh.close()
        # cleanup state
        try:
            del SEND_STATE[transfer_id]
        except Exception:
            pass


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
