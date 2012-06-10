"""
Keeps track of a PPP connection's state.

Manages the CCP, CHAP, and MPPE states for a given PPP connection.
"""

from chapcrack.packets.CcpPacket import CcpPacket
from chapcrack.packets.ChapPacket import ChapPacket
from chapcrack.packets.MppePacket import MppePacket
from chapcrack.state.CcpStateManager import CcpStateManager
from chapcrack.state.ChapStateManager import ChapStateManager
from chapcrack.state.MppeStateManager import MppeStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class PppStateManager:

    def __init__(self, nthash):
        self.servers = {}
        self.nthash  = nthash

    def addPacket(self, packet):
        if isinstance(packet, ChapPacket):
            self.addChapPacket(packet)
        elif isinstance(packet, CcpPacket):
            self.addCcpPacket(packet)
        elif isinstance(packet, MppePacket):
            return self.addMppePacket(packet)

    def addMppePacket(self, packet):
        sourceAddress      = packet.getSourceAddress()
        destinationAddress = packet.getDestinationAddress()

        if self._isCcpComplete(sourceAddress, destinationAddress):
            self._initializeMppeStateManagerIfNecessary(sourceAddress, destinationAddress)
            return self.servers[destinationAddress][sourceAddress]['mppe'].addMppePacket(packet)

        if self._isCcpComplete(destinationAddress, sourceAddress):
            self._initializeMppeStateManagerIfNecessary(destinationAddress, sourceAddress)
            return self.servers[sourceAddress][destinationAddress]['mppe'].addMppePacket(packet)

    def addCcpPacket(self, packet):
        sourceAddress      = packet.getSourceAddress()
        destinationAddress = packet.getDestinationAddress()

        if self._isChapComplete(sourceAddress, destinationAddress, self.nthash):
            self._initializeCcpStateManagerIfNecessary(sourceAddress, destinationAddress)
            self.servers[destinationAddress][sourceAddress]['ccp'].addCcpPacket(packet)

        elif self._isChapComplete(destinationAddress, sourceAddress, self.nthash):
            self._initializeCcpStateManagerIfNecessary(destinationAddress, sourceAddress)
            self.servers[sourceAddress][destinationAddress]['ccp'].addCcpPacket(packet)

    def addChapPacket(self, packet):
        serverAddress = packet.getServerAddress()
        clientAddress = packet.getClientAddress()

        self._initializeChapStateManagerIfNecessary(clientAddress, serverAddress)
        self.servers[serverAddress][clientAddress]['chap'].addHandshakePacket(packet)

    def _initializeChapStateManagerIfNecessary(self, clientAddress, serverAddress):
        if serverAddress not in self.servers:
            self.servers[serverAddress] = {}

        if clientAddress not in self.servers[serverAddress]:
            self.servers[serverAddress][clientAddress] = {'chap' : ChapStateManager()}

    def _initializeCcpStateManagerIfNecessary(self, clientAddress, serverAddress):
        if 'ccp' not in self.servers[serverAddress][clientAddress]:
            self.servers[serverAddress][clientAddress]['ccp'] = CcpStateManager(clientAddress, serverAddress)

    def _initializeMppeStateManagerIfNecessary(self, clientAddress, serverAddress):
        if 'mppe' not in self.servers[serverAddress][clientAddress]:
            response = self.servers[serverAddress][clientAddress]['chap'].getNtResponse()
            self.servers[serverAddress][clientAddress]['mppe'] = MppeStateManager(clientAddress, serverAddress,
                                                                                  self.nthash, response)

    def _isChapComplete(self, clientAddress, serverAddress, nthash):
        return serverAddress in self.servers and \
               clientAddress in self.servers[serverAddress] and \
               self.servers[serverAddress][clientAddress]['chap'].isComplete() and \
               self.servers[serverAddress][clientAddress]['chap'].isForHash(nthash)

    def _isCcpComplete(self, clientAddress, serverAddress):
        return serverAddress in self.servers and \
               clientAddress in self.servers[serverAddress] and \
               'ccp' in self.servers[serverAddress][clientAddress] and \
               self.servers[serverAddress][clientAddress]['ccp'].isComplete and \
               self.servers[serverAddress][clientAddress]['ccp'].isStateless() and \
               self.servers[serverAddress][clientAddress]['ccp'].is128bit()
