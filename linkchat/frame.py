import struct


def mac_str_to_bytes(mac_str):
    """Convert MAC string 'aa:bb:cc:dd:ee:ff' to 6-byte representation."""
    if isinstance(mac_str, bytes):
        if len(mac_str) == 6:
            return mac_str
        raise ValueError("MAC bytes must be length 6")
    parts = mac_str.split(":")
    if len(parts) != 6:
        raise ValueError("MAC string must have 6 octets separated by ':'")
    return bytes(int(p, 16) for p in parts)


def mac_bytes_to_str(mac_bytes):
    """Convert 6-byte MAC to human-readable string."""
    if not isinstance(mac_bytes, (bytes, bytearray)) or len(mac_bytes) != 6:
        raise ValueError("MAC bytes must be a 6-byte sequence")
    return ":".join(f"{b:02x}" for b in mac_bytes)


class Frame:
    """Ethernet-like frame for Link-Chat.

    Frame format (bytes):
      dst_mac (6) | src_mac (6) | ethertype (2) | payload (variable)
    """

    def __init__(self, dst_mac, src_mac, ethertype, payload):
        # accept MAC as strings or bytes
        if isinstance(dst_mac, str):
            self.dst_mac = mac_str_to_bytes(dst_mac)
        else:
            self.dst_mac = bytes(dst_mac)

        if isinstance(src_mac, str):
            self.src_mac = mac_str_to_bytes(src_mac)
        else:
            self.src_mac = bytes(src_mac)

        # ethertype can be int or 2-byte sequence
        if isinstance(ethertype, int):
            self.ethertype = struct.pack('!H', ethertype)
        else:
            self.ethertype = bytes(ethertype)

        self.payload = bytes(payload)

    def to_bytes(self):
        return self.dst_mac + self.src_mac + self.ethertype + self.payload

    @staticmethod
    def from_bytes(data):
        """Parse raw bytes into a Frame instance."""
        if len(data) < 14:
            raise ValueError("Frame too short")
        dst = data[0:6]
        src = data[6:12]
        eth = data[12:14]
        payload = data[14:]
        # ethertype as int
        eth_int = struct.unpack('!H', eth)[0]
        return Frame(dst, src, eth_int, payload)

    def dst_mac_str(self):
        return mac_bytes_to_str(self.dst_mac)

    def src_mac_str(self):
        return mac_bytes_to_str(self.src_mac)

    def ethertype_int(self):
        return struct.unpack('!H', self.ethertype)[0]

    def __repr__(self):
        return f"Frame(dst={self.dst_mac_str()}, src={self.src_mac_str()}, eth=0x{self.ethertype_int():04x}, payload_len={len(self.payload)})"
