import unittest
from PyQt5.QtWidgets import QApplication, QLineEdit
from unittest.mock import Mock
from view import Wireshark
from model import PacketCapture
import sys


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
    
    def test_get_protocol_name_invalid(self):
        self.assertEqual(self.packet_capture.get_protocol_name(9999), "Unknown")

class WiresharkTest(unittest.TestCase):
    def setUp(self):
        self.app = QApplication(sys.argv)
        self.wireshark = Wireshark()

    def tearDown(self):
        self.wireshark.packet_list = []
        self.wireshark.packet_dict = {}

    def test_packetHandler(self):
        packet = ['Time', 'Source', 'Destination', 'Protocol']
        self.wireshark.packetHandler(packet)
        self.assertEqual(self.wireshark.packet_list, [packet])

    def test_filterPacket(self):
        self.wireshark.packet_dict = {'PROTOCOL': [['Time', 'src:port', 'dst:port', 'PROTOCOL']]}
        self.wireshark.lineEdit = Mock(spec=QLineEdit)  # Create a mock sQLineEdit
        self.wireshark.lineEdit.text.return_value = 'protocol PROTOCOL'
        self.wireshark.filterPacket()

        # Check if the textEdit contains the expected text
        self.assertIn("['Time', 'src:port', 'dst:port', 'PROTOCOL']", self.wireshark.textEdit.toPlainText())

if __name__ == '__main__':
    unittest.main()