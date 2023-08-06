from model import PacketCapture
from PyQt5.QtCore import QObject, pyqtSignal, QThread
from scapy.all import *



# The PacketEmitter class is a QObject that emits packets.
class PacketEmitter(QObject):
    packet_emitted = pyqtSignal(list)

    def __init__(self, capture_instance):
        """
        The function initializes an instance of a class with a capture instance and connects a signal to
        emit packets.
        
        :param capture_instance: The `capture_instance` parameter is an instance of a class that has a
        `packet_emitted` signal. This signal is emitted whenever a packet is emitted by the capture
        instance
        """
        super().__init__()
        self.capture_instance = capture_instance
        self.capture_instance.packet_emitted.connect(self.emit_packet)

    def emit_packet(self, packet):
        """
        The function emits a signal with a packet as the argument.
        
        :param packet: The "packet" parameter is an object that represents a packet of data. It could be
        any type of data that needs to be transmitted or processed
        """
        self.packet_emitted.emit(packet)


# The CaptureThread class is a subclass of QThread that is used for capturing data.
class CaptureThread(QThread):
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        """
        The function initializes an instance of the PacketCapture class.
        """
        super().__init__()
        self.capture_instance = PacketCapture()  # Make this an instance variable

    def run(self):
        """
        The function runs a packet emitter in a separate thread and connects its emitted packets to
        another signal.
        """
        packet_emitter = PacketEmitter(self.capture_instance)
        packet_emitter.packet_emitted.connect(self.packet_emitted.emit)
        print("I am threading")
        # self.capture_instance.packet_capture()  # Use the instance variable here
        self.capture_instance.start()  # Use the instance variable here

    def stop(self):
        """
        The function "stop" stops the capture instance.
        """
        self.capture_instance.stop()  # Now this should work
