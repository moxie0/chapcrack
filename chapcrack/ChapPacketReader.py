__author__  = "Moxie Marlinspike"
__license__ = "GPLv3"

import socket
import dpkt
from chapcrack.ChapPacket import ChapPacket

class ChapPacketReader:

    def __init__(self, capture):
        self.capture = capture
        self.reader  = dpkt.pcap.Reader(capture)

    def __iter__(self):
        for timestamp, data in self.reader:
            packet = self._parseChapPacket(data)

            if packet:
                yield packet

    def _parseChapPacket(self, data):
        eth_packet = dpkt.ethernet.Ethernet(data)

        if isinstance(eth_packet.data, dpkt.ip.IP):
            ip_packet = eth_packet.data

            if ip_packet.get_proto(ip_packet.p) == dpkt.gre.GRE:
                gre_packet = ip_packet.data

                if hasattr(gre_packet, 'data') and isinstance(gre_packet.data, dpkt.ppp.PPP):
                    ppp_packet = gre_packet.data

                    if ppp_packet.p == 49699:
                        return ChapPacket(ppp_packet.data,
                            socket.inet_ntoa(ip_packet.src),
                            socket.inet_ntoa(ip_packet.dst))


