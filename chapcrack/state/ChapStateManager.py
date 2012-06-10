"""
Manages the current state of a MS-CHAPv2 handshake.
"""

import hashlib
from passlib.utils import des

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class ChapStateManager:

    def __init__(self):
        self.handshake = {}

    def addHandshakePacket(self, packet):
        if packet.isChallenge():
            self.handshake = {'challenge': packet}
        elif not packet.isChallenge():
            if packet.isResponse():
                self.handshake['response'] = packet
            elif packet.isSuccess():
                self.handshake['success'] = packet

    def isComplete(self):
        return len(self.handshake) == 3

    def isForHash(self, nthash):
        plaintext  = self.getPlaintext()
        c1, c2, c3 = self.getCiphertext()
        k1, k2, k3 = self._getKeysFromHash(nthash)

        return des.des_encrypt_block(k1, plaintext) == c1 and \
               des.des_encrypt_block(k2, plaintext) == c2 and \
               des.des_encrypt_block(k3, plaintext) == c3


    def getHandshake(self):
        return self.handshake

    def getNtResponse(self):
        assert self.isComplete()
        return self.handshake['response'].getNtResponse()

    def getUserName(self):
        assert self.isComplete()
        return self.handshake['response'].getName()

    def getCiphertext(self):
        ntResponse = self.getNtResponse()
        return ntResponse[0:8], ntResponse[8:16], ntResponse[16:24]

    def getPlaintext(self):
        authenticatorChallenge = self.handshake['challenge'].getChallenge()
        peerChallenge          = self.handshake['response'].getPeerChallenge()
        username               = self.handshake['response'].getName()

        sha = hashlib.sha1()
        sha.update(peerChallenge)
        sha.update(authenticatorChallenge)
        sha.update(username)
        return sha.digest()[0:8]

    def getAuthenticatorChallenge(self):
        return self.handshake['challenge'].getChallenge()

    def _getKeysFromHash(self, nthash):
        k1 = nthash[0:7]
        k1 = des.expand_des_key(k1)

        k2 = nthash[7:14]
        k2 = des.expand_des_key(k2)

        k3  = nthash[14:16]
        k3 += (chr(0x00) * 5)
        k3  = des.expand_des_key(k3)

        return k1, k2, k3
