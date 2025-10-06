import socket
import sys
import struct
from .frame import Frame

# receive state for file transfers: key=(src_mac, filename) -> {fileobj, last_seq, filesize, outpath}
RECV_STATE = {}


def receive_frames(interface="eth0", handler=None):
    """Listen for raw link-layer frames on interface and call handler(frame, addr).

    handler is a callable that receives a Frame instance and the raw addr.
    """
    if sys.platform != 'linux':
        raise RuntimeError("Raw AF_PACKET sockets are only supported on Linux")

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

    LINKCHAT_ETHERTYPE = 0x88b5
    if eth != LINKCHAT_ETHERTYPE:
        # ignore other traffic by default
        return
    # If it's our Link-Chat frame, inspect payload to see if it's text or file protocol
    payload = frame.payload
    if not payload:
        return

    msg_type = payload[0]
    # File transfer protocol
    if msg_type == 1:  # FILE_START
        # payload: type(1)=1 | filename_len(1) | filename | filesize(8)
        if len(payload) < 1 + 1 + 8:
            print('Malformed FILE_START')
            return
        name_len = payload[1]
        name = payload[2:2+name_len].decode('utf-8')
        filesize = struct.unpack('!Q', payload[2+name_len:2+name_len+8])[0]
        # initialize reassembly state in global dict keyed by src_mac + filename
        key = (frame.src_mac_str(), name)
        outpath = '/tmp/receiving_' + name
        # open a file for streaming write
        try:
            fh = open(outpath, 'wb')
        except Exception as e:
            print('Cannot open file for writing:', e)
            return
        RECV_STATE[key] = {'fileobj': fh, 'last_seq': 0, 'filesize': filesize, 'outpath': outpath}
        print(f"Receiving file start from {frame.src_mac_str()}: {name} ({filesize} bytes) -> {outpath}")
        return
    if msg_type == 2:  # FILE_CHUNK
        # payload: type(1)=2 | seq(4) | data...
        if len(payload) < 5:
            print('Malformed FILE_CHUNK')
            return
        seq = struct.unpack('!I', payload[1:5])[0]
        data = payload[5:]
        # find state for this src (if multiple files, use latest filename in state)
        src = frame.src_mac_str()
        # find matching keys
        matches = [k for k in RECV_STATE.keys() if k[0] == src]
        if not matches:
            print('Received FILE_CHUNK but no FILE_START seen')
            return
        key = matches[0]
        state = RECV_STATE.get(key)
        if state is None:
            print('No state for incoming chunk')
            return
        try:
            # write chunk directly (we assume container/local delivery in-order for this simple impl)
            state['fileobj'].write(data)
            state['last_seq'] = seq
        except Exception as e:
            print('Error writing chunk:', e)
        return
    if msg_type == 3:  # FILE_END
        # payload: type(1)=3 | seq(4)
        if len(payload) < 5:
            print('Malformed FILE_END')
            return
        last_seq = struct.unpack('!I', payload[1:5])[0]
        src = frame.src_mac_str()
        matches = [k for k in RECV_STATE.keys() if k[0] == src]
        if not matches:
            print('Received FILE_END but no FILE_START seen')
            return
        key = matches[0]
        state = RECV_STATE.pop(key)
        # finalize file
        fh = state.get('fileobj')
        outpath = state.get('outpath')
        filename = key[1]
        try:
            fh.close()
            final_path = '/tmp/received_' + filename
            # move temp file to final path
            try:
                import os
                os.rename(outpath, final_path)
            except Exception:
                final_path = outpath
            print(f"Received file {filename} from {src} -> saved to {final_path} ({state.get('last_seq',0)} chunks)")
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
