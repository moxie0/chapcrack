"""
A class to encapsulate and parse an MS-CHAPv2 Packet.
"""

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class ChapPacket:

    def __init__(self, data, src, dst):
        self.data = data
        self.src  = src
        self.dst  = dst

    def getServerAddress(self):
        if self.isChallenge():
            return self.src
        elif self.isResponse():
            return self.dst
        elif self.isSuccess():
            return self.src

    def getClientAddress(self):
        if self.isChallenge():
            return self.dst
        elif self.isResponse():
            return self.src
        elif self.isSuccess():
            return self.dst

    def getIdentifier(self):
        return ord(self.data[1])

    def isChallenge(self):
        return ord(self.data[0]) == 1

    def isResponse(self):
        return ord(self.data[0]) == 2

    def isSuccess(self):
        return ord(self.data[0]) == 3

    def getName(self):
        payload         = self._getPayload()
        challengeLength = ord(payload[0])

        return payload[1+challengeLength:]

    def getChallenge(self):
        payload         = self._getPayload()
        challengeLength = ord(payload[0])

        return payload[1:challengeLength+1]

    def getPeerChallenge(self):
        payload = self._getPayload()
        return payload[1:17]

    def getNtResponse(self):
        payload = self._getPayload()
        return payload[25:49]

    def _getPayload(self):
        return self.data[4:self._getPayloadLength()]

    def _getPayloadLength(self):
        high = ord(self.data[2])
        low  = ord(self.data[3])

        return (high << 8) | low
