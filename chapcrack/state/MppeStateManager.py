"""
Manages the current state of an MPPE stream.
"""

from dpkt.ip import IP
from passlib.utils.md4 import md4
from M2Crypto.RC4 import RC4
import copy
import hashlib
import binascii

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class MppeStateManager:

    MAGIC_ONE   = binascii.unhexlify("5468697320697320746865204d505045204d6173746572204b6579")
    MAGIC_TWO   = binascii.unhexlify("4f6e2074686520636c69656e7420736964652c20746869732069732074686520"
                                     "73656e64206b65793b206f6e207468652073657276657220736964652c206974"
                                     "206973207468652072656365697665206b65792e")
    MAGIC_THREE = binascii.unhexlify("4f6e2074686520636c69656e7420736964652c20746869732069732074686520"
                                     "72656365697665206b65793b206f6e207468652073657276657220736964652c"
                                     "206974206973207468652073656e64206b65792e")

    SHS_PAD1    = binascii.unhexlify("00000000000000000000000000000000000000000000000000000000000000000000000000000000")
    SHS_PAD2    = binascii.unhexlify("f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2")

    def __init__(self, clientAddress, serverAddress, nthash, response):
        self.clientAddress   = clientAddress
        self.serverAddress   = serverAddress
        self.masterKey       = self._getMasterKey(self._getPasswordHashHash(nthash), response)

        self.clientMasterKey = self._getAsymmetricMasterKey(self.masterKey, self.MAGIC_TWO)
        self.serverMasterKey = self._getAsymmetricMasterKey(self.masterKey, self.MAGIC_THREE)

        self.clientSessionKey = self._getNextKeyFromSha(self.clientMasterKey, self.clientMasterKey)
        self.serverSessionKey = self._getNextKeyFromSha(self.serverMasterKey, self.serverMasterKey)

        self.clientSessionCounter = -1
        self.serverSessionCounter = -1

    def addMppePacket(self, packet):
        stateGetter, stateSetter = (None, None)

        if packet.getSourceAddress() == self.clientAddress:
            stateGetter, stateSetter = (self._getClientState, self._setClientState)
        elif packet.getSourceAddress() == self.serverAddress:
            stateGetter, stateSetter = (self._getServerState, self._setServerState)
        else:
            return None

        masterKey, sessionKey, counter = stateGetter()

        if counter == packet.getCounter():
            return self._decryptPacket(packet, sessionKey)
        elif self._isIncrementedCounter(counter, packet.getCounter()):
            sessionKey = self._getIncrementedSessionKey(masterKey, sessionKey,
                                                        counter, packet.getCounter())
            stateSetter(sessionKey, packet.getCounter())
            return self._decryptPacket(packet, sessionKey)
        else:
            print "Old packet: %s" % packet.getCounter()
            return None

    def _decryptPacket(self, packet, sessionKey):
        cipher    = RC4(key=sessionKey)
        plaintext = cipher.update(packet.getData())

        if ord(plaintext[0]) == 0x00 and ord(plaintext[1]) == 0x21:
            ethPacket = packet.getEthernetFrame()
            ethPacket = copy.deepcopy(ethPacket)
            ipPacket  = IP()
            ipPacket.unpack(plaintext[2:])

            ethPacket.data = ipPacket

            return ethPacket

        return None

    def _getIncrementedSessionKey(self, masterKey, sessionKey, sessionCounter, packetCounter):
        difference = 0

        if packetCounter > sessionCounter:
            difference = packetCounter - sessionCounter
        else:
            difference  = 4095 - sessionCounter
            difference += packetCounter

        for i in range(0, difference):
            sessionKey = self._getNextKey(masterKey, sessionKey)

        return sessionKey

    def _isIncrementedCounter(self, stateCounter, packetCounter):
        if packetCounter > stateCounter and (packetCounter - stateCounter) < 2000:
            return True

        if packetCounter < stateCounter and packetCounter < 250 and stateCounter > 3844:
            return True

        return False

    def _getClientState(self):
        return self.clientMasterKey, self.clientSessionKey, self.clientSessionCounter

    def _getServerState(self):
        return self.serverMasterKey, self.serverSessionKey, self.serverSessionCounter

    def _setClientState(self, sessionKey, counter):
        self.clientSessionKey     = sessionKey
        self.clientSessionCounter = counter

    def _setServerState(self, sessionKey, counter):
        self.serverSessionKey     = sessionKey
        self.serverSessionCounter = counter

    def _getPasswordHashHash(self, nthash):
        digest = md4()
        digest.update(nthash)
        return digest.digest()

    def _getMasterKey(self, passwordHashHash, response):
        digest = hashlib.sha1()
        digest.update(passwordHashHash)
        digest.update(response)
        digest.update(self.MAGIC_ONE)
        return digest.digest()[0:16]

    def _getAsymmetricMasterKey(self, masterKey, magic):
        digest = hashlib.sha1()
        digest.update(masterKey)
        digest.update(self.SHS_PAD1)
        digest.update(magic)
        digest.update(self.SHS_PAD2)
        return digest.digest()[:16]

    def _getNextKeyFromSha(self, masterKey, lastSessionKey):
        digest = hashlib.sha1()
        digest.update(masterKey)
        digest.update(self.SHS_PAD1)
        digest.update(lastSessionKey)
        digest.update(self.SHS_PAD2)
        return digest.digest()[:16]

    def _getNextKey(self, masterKey, lastSessionKey):
        nextSessionKey = self._getNextKeyFromSha(masterKey, lastSessionKey)
        cipher = RC4(key=nextSessionKey)
        return cipher.update(nextSessionKey)