__author__  = "Moxie Marlinspike"
__license__ = "GPLv3"

import hashlib

class ProtocolLogic:

    @staticmethod
    def getUserName(handshake):
        return handshake['response'].getName()

    @staticmethod
    def getCiphertext(handshake):
        ntResponse = handshake['response'].getNtResponse()

        return ntResponse[0:8], ntResponse[8:16], ntResponse[16:24]

    @staticmethod
    def getPlaintext(handshake):
        authenticatorChallenge = handshake['challenge'].getChallenge()
        peerChallenge          = handshake['response'].getPeerChallenge()
        username               = handshake['response'].getName()

        sha = hashlib.sha1()
        sha.update(peerChallenge)
        sha.update(authenticatorChallenge)
        sha.update(username)
        return sha.digest()[0:8]