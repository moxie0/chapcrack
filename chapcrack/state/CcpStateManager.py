"""
Manages the current state of a CCP handshake.
"""

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class CcpStateManager:

    def __init__(self, clientAddress, serverAddress):
        self.handshake     = {}
        self.clientAddress = clientAddress
        self.serverAddress = serverAddress

    def addCcpPacket(self, packet):
        if packet.isConfigurationRequest() and packet.getSourceAddress() == self.clientAddress:
            self.handshake['request'] = packet

        if packet.isConfigurationAck() and packet.getSourceAddress == self.serverAddress:
            self.handshake['ack'] = packet

    def isComplete(self):
        return len(self.handshake) == 2

    def isStateless(self):
        return self.handshake['request'].isStateless()

    def is128bit(self):
        return self.handshake['request'].is128bit()
