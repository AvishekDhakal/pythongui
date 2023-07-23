from model import PacketCapture
from PyQt5.QtCore import pyqtSlot, QObject, pyqtSignal, QThread
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP


class PacketEmitter(QObject):
    packet_emitted = pyqtSignal(list)

    def __init__(self, capture_instance):
        super().__init__()
        self.capture_instance = capture_instance
        self.capture_instance.packet_emitted.connect(self.emit_packet)

    def emit_packet(self, packet):
        self.packet_emitted.emit(packet)


class CaptureThread(QThread):
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.capture_instance = PacketCapture()  # Make this an instance variable

    def run(self):
        packet_emitter = PacketEmitter(self.capture_instance)
        packet_emitter.packet_emitted.connect(self.packet_emitted.emit)
        print("I am threading")
        # self.capture_instance.packet_capture()  # Use the instance variable here
        self.capture_instance.start() # Use the instance variable here

    def stop(self):
        self.capture_instance.stop()  # Now this should work

