import unittest
from model import PacketCapture


class PacketCaptureTest(unittest.TestCase):
    def setUp(self):
        self.packet_capture = PacketCapture()

    def test_get_protocol_name(self):
        self.assertEqual(self.packet_capture.get_protocol_name(1), "ICMP")
        self.assertEqual(self.packet_capture.get_protocol_name(6), "TCP")
        self.assertEqual(self.packet_capture.get_protocol_name(17), "UDP")
        self.assertEqual(self.packet_capture.get_protocol_name(123), "Unknown")

    def test_start_and_stop(self):
        self.packet_capture.start()
        self.assertEqual(self.packet_capture._stop_flag, False)
        self.packet_capture.stop()
        self.assertEqual(self.packet_capture._stop_flag, True)

if __name__ == '__main__':
    unittest.main()