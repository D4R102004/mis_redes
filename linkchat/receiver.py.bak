# receiver.py (modificado para random-access writes y enviar ACKs)
import socket
import sys
import struct
import os
import hashlib
import fcntl
from .frame import Frame
import threading

# receive state for file transfers: key=(src_mac, transfer_id) -> {fileobj, last_seq, filesize, outpath, filename, expected_hash, received_seqs}
RECV_STATE = {}

# directory to store received files
RECEIVE_DIR = '/tmp/linkchat_received'
os.makedirs(RECEIVE_DIR, exist_ok=True)

# protocol constants
MSG_FILE_START = 1
MSG_FILE_CHUNK = 2
MSG_FILE_END = 3
MSG_FILE_ACK = 4

CHUNK_SIZE = 1400
ETH_CHAT = 0x88b5

# receiver interface (set by receive_frames)
RECEIVER_INTERFACE = None


def get_iface_mac(ifname):
    """Return MAC string for interface (Linux ioctl SIOCGIFHWADDR)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname.encode('utf-8')[:15]))
        mac = info[18:24]
        # format
        return ":".join(f"{b:02x}" for b in mac)
    finally:
        s.close()


def send_frame(frame_bytes, interface="eth0"):
    """Send raw frame bytes on the given interface (used for ACKs)."""
    if sys.platform != 'linux':
        raise RuntimeError("Raw AF_PACKET sockets are only supported on Linux")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        s.bind((interface, 0))
        s.send(frame_bytes)
    finally:
        s.close()


def receive_frames(interface="eth0", handler=None):
    """Listen for raw link-layer frames on interface and call handler(frame, addr).

    handler is a callable that receives a Frame instance and the raw addr.
    """
    global RECEIVER_INTERFACE
    if sys.platform != 'linux':
        raise RuntimeError("Raw AF_PACKET sockets are only supported on Linux")

    RECEIVER_INTERFACE = interface

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    try:
        s.bind((interface, 0))
        while True:
            raw_data, addr = s.recvfrom(65535)
            try:
                f = Frame.from_bytes(raw_data)
            except Exception:
                # Cannot parse — print raw and continue
                if handler:
                    handler(None, raw_data, addr)
                else:
                    print("Raw frame (unparsed):", raw_data)
                continue

            if handler:
                handler(f, raw_data, addr)
            else:
                print("Frame recibido:", f)
    finally:
        s.close()


def print_handler(frame, raw, addr):
    if frame is None:
        print("Could not parse frame; raw len=", len(raw))
        return
    # Only show Link-Chat frames (our ethertype 0x88b5)
    try:
        eth = frame.ethertype_int()
    except Exception:
        print(frame)
        return

    LINKCHAT_ETHERTYPE = ETH_CHAT
    if eth != LINKCHAT_ETHERTYPE:
        # ignore other traffic by default
        return
    # If it's our Link-Chat frame, inspect payload to see if it's text or file protocol
    payload = frame.payload
    if not payload:
        return

    msg_type = payload[0]
    # File transfer protocol
    if msg_type == MSG_FILE_START:  # FILE_START
        # new payload: type(1)=1 | transfer_id(4) | filename_len(1) | filename | filesize(8) | sha256(32)
        min_len = 1 + 4 + 1 + 8 + 32
        if len(payload) < min_len:
            print('Malformed FILE_START')
            return
        transfer_id = struct.unpack('!I', payload[1:5])[0]
        name_len = payload[5]
        name = payload[6:6+name_len].decode('utf-8')
        filesize = struct.unpack('!Q', payload[6+name_len:6+name_len+8])[0]
        expected_hash = payload[6+name_len+8:6+name_len+8+32]
        # initialize reassembly state in global dict keyed by src_mac + transfer_id
        key = (frame.src_mac_str(), transfer_id)
        # create unique temp filename
        safe_name = name.replace('/', '_')
        tmpname = f".receiving.{transfer_id:08x}.{safe_name}"
        outpath = os.path.join(RECEIVE_DIR, tmpname)
        # create file of correct size and open in r+b for random-access writes
        try:
            fh = open(outpath, 'wb')
            fh.truncate(filesize)
            fh.close()
            fh = open(outpath, 'r+b')
        except Exception as e:
            print('Cannot open file for writing:', e)
            return
        RECV_STATE[key] = {
            'fileobj': fh,
            'last_seq': 0,
            'filesize': filesize,
            'outpath': outpath,
            'filename': name,
            'expected_hash': expected_hash,
            'received_seqs': set()
        }
        print(f"Receiving file start from {frame.src_mac_str()}: {name} ({filesize} bytes) transfer_id={transfer_id:08x} -> {outpath}")
        return

    if msg_type == MSG_FILE_CHUNK:  # FILE_CHUNK
        # payload: type(1)=2 | transfer_id(4) | seq(4) | data...
        if len(payload) < 1 + 4 + 4:
            print('Malformed FILE_CHUNK')
            return
        transfer_id = struct.unpack('!I', payload[1:5])[0]
        seq = struct.unpack('!I', payload[5:9])[0]
        data = payload[9:]
        src = frame.src_mac_str()
        key = (src, transfer_id)
        state = RECV_STATE.get(key)
        if state is None:
            print('Received FILE_CHUNK but no FILE_START seen for transfer', transfer_id)
            return
        try:
            # random-access write at (seq-1)*CHUNK_SIZE
            offset = (seq - 1) * CHUNK_SIZE
            fh = state['fileobj']
            fh.seek(offset)
            fh.write(data)
            fh.flush()
            state['last_seq'] = max(state.get('last_seq', 0), seq)
            state['received_seqs'].add(seq)
        except Exception as e:
            print('Error writing chunk:', e)
            return

        # send ACK for this seq back to sender
        try:
            iface = RECEIVER_INTERFACE or 'eth0'
            try:
                local_mac = get_iface_mac(iface)
            except Exception:
                local_mac = '00:00:00:00:00:00'
            ack_payload = bytes([MSG_FILE_ACK]) + struct.pack('!I', transfer_id) + struct.pack('!I', seq)
            ack_frame = Frame(frame.src_mac, local_mac, ETH_CHAT, ack_payload)
            send_frame(ack_frame.to_bytes(), interface=iface)
        except Exception as e:
            print("Failed to send ACK:", e)
        return

    if msg_type == MSG_FILE_END:  # FILE_END
        # payload: type(1)=3 | transfer_id(4) | seq(4)
        if len(payload) < 1 + 4 + 4:
            print('Malformed FILE_END')
            return
        transfer_id = struct.unpack('!I', payload[1:5])[0]
        last_seq = struct.unpack('!I', payload[5:9])[0]
        src = frame.src_mac_str()
        key = (src, transfer_id)
        if key not in RECV_STATE:
            print('Received FILE_END but no FILE_START seen for transfer', transfer_id)
            return
        state = RECV_STATE.pop(key)
        # finalize file
        fh = state.get('fileobj')
        outpath = state.get('outpath')
        filename = state.get('filename')
        expected_hash = state.get('expected_hash')
        try:
            fh.close()
            # compute sha256
            h = hashlib.sha256()
            with open(outpath, 'rb') as rf:
                for chunk in iter(lambda: rf.read(8192), b''):
                    h.update(chunk)
            got = h.digest()
            if expected_hash == got:
                final_path = os.path.join(RECEIVE_DIR, filename)
                # if final_path exists, append transfer id to avoid overwrite
                if os.path.exists(final_path):
                    final_path = os.path.join(RECEIVE_DIR, f"{transfer_id:08x}.{filename}")
                try:
                    os.rename(outpath, final_path)
                except Exception:
                    final_path = outpath
                print(f"Received file {filename} from {src} -> saved to {final_path} ({state.get('last_seq',0)} chunks) sha256 ok")
            else:
                failed_path = os.path.join(RECEIVE_DIR, f"failed.{transfer_id:08x}.{filename}")
                try:
                    os.rename(outpath, failed_path)
                except Exception:
                    failed_path = outpath
                print(f"Received file {filename} from {src} -> sha256 MISMATCH, saved as {failed_path}")
        except Exception as e:
            print('Error finalizing received file:', e)
        return

    # Otherwise treat as text message
    try:
        text = payload.decode('utf-8')
        print(f"LinkChat message from {frame.src_mac_str()} -> {frame.dst_mac_str()}: {text}")
    except Exception:
        print(f"LinkChat frame from {frame.src_mac_str()} -> {frame.dst_mac_str()}, payload bytes:", payload)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python receiver.py <interface>")
        sys.exit(1)
    iface = sys.argv[1]
    receive_frames(interface=iface, handler=print_handler)
