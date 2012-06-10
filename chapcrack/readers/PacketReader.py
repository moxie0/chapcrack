"""
Base packet reader implementation.  Will iterate over packets
specified by a subclass.
"""

import dpkt

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class PacketReader:

    def __init__(self, capture):
        self.capture = capture
        self.reader  = dpkt.pcap.Reader(capture)

    def __iter__(self):
        for timestamp, data in self.reader:
            packet = self._parseForTargetPacket(data)

            if packet:
                yield packet

    def _parseForTargetPacket(self, data):
        assert False
