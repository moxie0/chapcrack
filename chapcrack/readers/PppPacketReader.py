"""
Given a packet capture, this class will iterate over the PPP packets
that we care about within that capture.  These include CHAP, CCP, and
MPPE packets.
"""

import socket
import dpkt

from chapcrack.packets.CcpPacket import CcpPacket
from chapcrack.packets.ChapPacket import ChapPacket
from chapcrack.packets.MppePacket import MppePacket
from chapcrack.readers.PacketReader import PacketReader

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class PppPacketReader(PacketReader):

    def __init__(self, capture):
        PacketReader.__init__(self, capture)

    def _parseForTargetPacket(self, data):
        eth_packet = dpkt.ethernet.Ethernet(data)

        if isinstance(eth_packet.data, dpkt.ip.IP):
            ip_packet = eth_packet.data

            if ip_packet.get_proto(ip_packet.p) == dpkt.gre.GRE:
                gre_packet = ip_packet.data

                if hasattr(gre_packet, 'data') and isinstance(gre_packet.data, dpkt.ppp.PPP):
                    ppp_packet = gre_packet.data

                    if ppp_packet.p == 255:
                        ppp_packet.unpack(ppp_packet.pack()[2:])

                    if ppp_packet.p == 49699:
                        return ChapPacket(ppp_packet.data,
                                          socket.inet_ntoa(ip_packet.src),
                                          socket.inet_ntoa(ip_packet.dst))

                    if ppp_packet.p == 253:
                        return MppePacket(eth_packet)

                    if ppp_packet.p == 33021:
                        return CcpPacket(ppp_packet.data,
                                         socket.inet_ntoa(ip_packet.src),
                                         socket.inet_ntoa(ip_packet.dst))

        return None