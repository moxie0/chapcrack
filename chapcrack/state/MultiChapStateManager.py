"""
Layer of indirection to keep track of multiple ongoing MS-CHAPv2 handshake states.
"""

from chapcrack.state.ChapStateManager import ChapStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class MultiChapStateManager:

    def __init__(self):
        self.servers = {}

    def addHandshakePacket(self, packet):
        serverAddress = packet.getServerAddress()
        clientAddress = packet.getClientAddress()

        if serverAddress not in self.servers:
            self.servers[serverAddress] = {}

        if clientAddress not in self.servers[serverAddress]:
            self.servers[serverAddress][clientAddress] = ChapStateManager()

        self.servers[serverAddress][clientAddress].addHandshakePacket(packet)

    def getCompletedHandshakes(self):
        results = {}

        for server in self.servers:
            for client in self.servers[server]:

                if self.servers[server][client].isComplete():
                    results[server] = {client : self.servers[server][client]}

        return results
