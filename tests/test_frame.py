import unittest
from linkchat.frame import Frame


class TestFrame(unittest.TestCase):
    def test_frame_roundtrip(self):
        dst = 'aa:bb:cc:dd:ee:ff'
        src = '11:22:33:44:55:66'
        ethertype = 0x88b5
        payload = b'hello world'

        f = Frame(dst, src, ethertype, payload)
        b = f.to_bytes()
        parsed = Frame.from_bytes(b)

        self.assertEqual(parsed.dst_mac_str(), dst)
        self.assertEqual(parsed.src_mac_str(), src)
        self.assertEqual(parsed.ethertype_int(), ethertype)
        self.assertEqual(parsed.payload, payload)


if __name__ == '__main__':
    unittest.main()
