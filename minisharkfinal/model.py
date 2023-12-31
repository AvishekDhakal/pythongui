
from scapy.all import *
from scapy.all import *
from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP
import datetime


class PacketCapture(QObject):
    # defining a custom signal. the signal indicates it will emit a string value when emmited.
    packet_emitted = pyqtSignal(list)

    def __init__(self):
        """
        The function initializes an object with a stop flag and an empty list for captured packets.
        """
        super().__init__()
        self._stop_flag = False
        self.captured_packets = []
# so whenever a packet is captured using packet_capture method the packet_print method is called and it will emit all the packet using packet_emmited.emit function called there.

    def get_protocol_name(self, protocol):
        """
        The function `get_protocol_name` returns the name of a protocol based on its protocol number.
        
        :param protocol: The `protocol` parameter is an integer representing the protocol number
        :return: the name of the protocol based on the protocol number provided. If the protocol number
        is found in the protocol_map dictionary, the corresponding protocol name is returned. If the
        protocol number is not found in the dictionary, the function returns "Unknown".
        """
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
            # Add more protocol numbers and their names if needed
        }
        return protocol_map.get(protocol, "Unknown")

    def packet_printing(self, captured_packet):
        """
        The `packet_printing` function takes a captured packet as input and extracts relevant
        information such as source IP, destination IP, protocol, and transport layer information, and
        emits this information as a signal.

        :param captured_packet: The `captured_packet` parameter is a packet object that represents a
        captured network packet. It can contain various layers of information such as IP, TCP, UDP, or
        ARP
        """
        current_time = datetime.datetime.now().time()
        now = current_time.strftime("%H:%M:%S")
        packet_info = []
        # self.captured_packets.append(captured_packet)
        self.captured_packets.append(captured_packet)
        # print(f"Stored packet {len(self.captured_packets)}")

        if captured_packet.haslayer(IP):
            dst_ip = captured_packet[IP].dst
            src_ip = captured_packet[IP].src
            protocol = captured_packet[IP].proto
            protocol_name = self.get_protocol_name(protocol)

            if TCP in captured_packet:

                transport_layers = captured_packet[TCP].sport
                transport_layerd = captured_packet[TCP].dport
                tsrc_ip = captured_packet[IP].src + ":" + str(transport_layers)
                tdst_ip = captured_packet[IP].dst + ":" + str(transport_layerd)
                packet_info.extend([now, tsrc_ip, tdst_ip, protocol_name])
                # packet_info.extend([now,src_ip,dst_ip,protocol_name])

            elif UDP in captured_packet:

                transport_layers = captured_packet[UDP].sport
                transport_layerd = captured_packet[UDP].dport
                usrc_ip = captured_packet[IP].src + ":" + str(transport_layers)
                udst_ip = captured_packet[IP].dst + ":" + str(transport_layerd)
                packet_info.extend([now, usrc_ip, udst_ip, protocol_name])
                # packet_info.extend([now,src_ip,dst_ip,protocol_name])
                packet_info.extend([now, src_ip, dst_ip, protocol_name])

            else:
                packet_info.extend([now, src_ip, dst_ip, protocol_name])

            self.packet_emitted.emit(packet_info)

        elif captured_packet.haslayer(ARP):
            src_ip = captured_packet[ARP].psrc
            dst_ip = captured_packet[ARP].pdst
            protocol_name = "ARP"
            packet_info.extend([now, src_ip, dst_ip, protocol_name])

            self.packet_emitted.emit(packet_info)
            # pass

        # print(summary)

    def should_stop(self, _):
        """
        The function returns the value of the `_stop_flag` attribute.
        
        :param _: The underscore (_) is a convention in Python to indicate that the parameter is not
        used in the function. It is often used when a parameter is required by the function signature
        but is not actually used within the function body. In this case, the parameter is named "_" to
        indicate that it is not used and
        :return: The method is returning the value of the `_stop_flag` attribute.
        """
        return self._stop_flag

    def stop(self):
        """
        The function sets a flag to indicate that a process should stop.
        """
        self._stop_flag = True

    # def packet_capture(self):
    #     # print("i am started")
    #     sniff(count=0, prn=self.packet_printing)
        # sniff(count=0, prn=self.packet_printing, stop_filter=self.should_stop)
    def start(self):
        """
        The start function sets the stop flag to False and then calls the packet_capture function.
        """
        self._stop_flag = False
        self.packet_capture()

    def packet_capture(self):
        """
        The function `packet_capture` captures network packets and prints them using the
        `packet_printing` function until the `should_stop` condition is met.
        """
        sniff(count=0, prn=self.packet_printing, stop_filter=self.should_stop)
