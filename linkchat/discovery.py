# linkchat/discovery.py
import socket
import json
import struct
import fcntl
from .frame import Frame
from .sender import send_text  # use sender's helper to send frames

ETH_DISCOVERY = 0x88b6  # custom ethertype for discovery frames

MSG_DISCOVER = "DISCOVER"
MSG_HELLO = "HELLO"


class PeerTable:
    """Keeps track of peers recently discovered."""
    def __init__(self):
        self.peers = {}  # mac -> (name, last_seen)

    def update(self, mac, name):
        import time
        self.peers[mac] = (name, time.time())

    def get_active(self, timeout=60):
        """Return peers seen within timeout seconds."""
        import time
        now = time.time()
        return {mac: (n, t) for mac, (n, t) in self.peers.items() if now - t < timeout}


peer_table = PeerTable()


def _get_iface_mac(ifname):
    """Return MAC string for interface (Linux ioctl SIOCGIFHWADDR)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname.encode('utf-8')[:15]))
        mac = info[18:24]
        return ":".join(f"{b:02x}" for b in mac)
    finally:
        s.close()


def send_discover_broadcast(iface):
    """Send a DISCOVER to broadcast on iface. Whoever is listening should reply with HELLO to sender."""
    local_mac = _get_iface_mac(iface)
    hostname = socket.gethostname()
    payload = json.dumps({"type": MSG_DISCOVER, "name": hostname})
    # broadcast
    try:
        send_text("ff:ff:ff:ff:ff:ff", local_mac, ETH_DISCOVERY, payload, interface=iface)
        print(f"[DISCOVERY] Sent DISCOVER from {local_mac} ({hostname}) on {iface}")
    except Exception as e:
        print("[DISCOVERY] Failed to send DISCOVER:", e)


def handle_discovery_frame(frame, iface):
    """Handle an incoming discovery frame. `frame` is Frame instance, iface is local interface name."""
    # payload is bytes; attempt to decode as UTF-8 JSON
    try:
        payload = frame.payload.decode('utf-8', errors='ignore')
        data = json.loads(payload)
    except Exception:
        # not JSON or decode error: ignore
        return

    typ = data.get("type")
    src_mac = frame.src_mac_str().lower()

    # get our local MAC on that iface to avoid replying to / recording ourselves
    try:
        local_mac = _get_iface_mac(iface).lower()
    except Exception:
        local_mac = None

    # don't process frames that allegedly come from ourselves
    if local_mac and src_mac == local_mac:
        return

    if typ == MSG_DISCOVER:
        # someone asked "who's there?" — reply with HELLO unicast
        myname = socket.gethostname()
        reply = json.dumps({"type": MSG_HELLO, "name": myname})
        try:
            # send_text(dst_mac, src_mac, ethertype, text, interface)
            local_mac_send = _get_iface_mac(iface)
            send_text(src_mac, local_mac_send, ETH_DISCOVERY, reply, interface=iface)
            print(f"[DISCOVERY] Replied HELLO to {src_mac} (requester: {data.get('name')})")
        except Exception as e:
            print("[DISCOVERY] Failed to reply HELLO:", e)
        return

    if typ == MSG_HELLO:
        # record peer
        peer_name = data.get("name", "?")
        # ensure we don't record ourselves
        if local_mac and src_mac == local_mac:
            return
        peer_table.update(src_mac, peer_name)
        print(f"[DISCOVERY] HELLO from {src_mac} -> {peer_name}")
        return


    if typ == MSG_HELLO:
        # record peer
        peer_name = data.get("name", "?")
        peer_table.update(src_mac, peer_name)
        print(f"[DISCOVERY] HELLO from {src_mac} -> {peer_name}")
        return

    # unknown discovery type: ignore
