__author__  = "Moxie Marlinspike"
__license__ = "GPLv3"

class HandshakeStateManager:

    def __init__(self):
        self.servers = {}

    def addHandshakePacket(self, packet):
        serverAddress = packet.getServerAddress()
        clientAddress = packet.getClientAddress()

        if packet.isChallenge() and self._isEligibleForNewHandshake(serverAddress, clientAddress):
            self._createNewHandshake(serverAddress, clientAddress)
            self.servers[serverAddress][clientAddress]['challenge'] = packet
        elif not packet.isChallenge() and self._isEligibleForHandshakePacket(serverAddress, clientAddress):
            if packet.isResponse():
                self.servers[serverAddress][clientAddress]['response'] = packet
            elif packet.isSuccess():
                self.servers[serverAddress][clientAddress]['success'] = packet

    def getCompletedHandshakes(self):
        results = {}

        for server in self.servers:
            for client in self.servers[server]:
                if len(self.servers[server][client]) == 3:
                    results[server] = self.servers[server]

        return results

    def _isEligibleForHandshakePacket(self, serverAddress, clientAddress):
        return serverAddress in self.servers and\
               clientAddress in self.servers[serverAddress] and\
               len(self.servers[serverAddress][clientAddress]) < 3

    def _isEligibleForNewHandshake(self, serverAddress, clientAddress):
        return serverAddress not in self.servers or\
               clientAddress not in self.servers[serverAddress] or\
               len(self.servers[serverAddress][clientAddress]) < 3

    def _createNewHandshake(self, serverAddress, clientAddress):
        if serverAddress not in self.servers:
            self.servers[serverAddress] = {}

        self.servers[serverAddress][clientAddress] = {}
