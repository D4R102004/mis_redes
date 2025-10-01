import socket
import sys
from .frame import Frame


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
    print(frame)
    try:
        # attempt to decode payload as utf-8 text for easy debugging
        text = frame.payload.decode('utf-8')
        print("payload(text):", text)
    except Exception:
        print("payload(bytes):", frame.payload)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python receiver.py <interface>")
        sys.exit(1)
    iface = sys.argv[1]
    receive_frames(interface=iface, handler=print_handler)
