"""
A class to encapsulate and parse a 'Microsoft Point-To-Point Encryption' packet.
"""

import socket

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class MppePacket:

    def __init__(self, eth_packet):
        self.eth_packet = eth_packet
        self.ppp_data   = eth_packet.data.data.data.data

    def getSourceAddress(self):
        return socket.inet_ntoa(self.eth_packet.data.src)

    def getDestinationAddress(self):
        return socket.inet_ntoa(self.eth_packet.data.dst)

    def isFlushed(self):
        header = self.ppp_data[0]
        return ord(header) & 0x80 != 0

    def isEncrypted(self):
        header = self.ppp_data[0]
        return ord(header) & 0x10 != 0

    def getCounter(self):
        highBits = ord(self.ppp_data[0]) & 0x0F
        lowBits  = ord(self.ppp_data[1]) & 0xFF

        return highBits << 7 | lowBits

    def getData(self):
        return self.ppp_data[2:]

    def getEthernetFrame(self):
        return self.eth_packet
