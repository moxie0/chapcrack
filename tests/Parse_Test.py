from chapcrack.readers import ChapPacketReader
from chapcrack.state import ProtocolLogic
from chapcrack.state.MultiChapStateManager import MultiChapStateManager

__author__  = "Moxie Marlinspike"
__license__ = "GPLv3"

from passlib.hash import nthash
from passlib.utils import des
import unittest
import binascii
from chapcrack.state.ChapStateManager import ChapStateManager
from chapcrack.readers.ChapPacketReader import ChapPacketReader

class ParseTest(unittest.TestCase):

    def test_des(self):
        result = des.des_encrypt_block('12345678', 'ABCDEFGH')
        assert binascii.hexlify(result) == "96de603eaed6256f"

    def test_parsing(self):
        capture    = open("tests/pptp.cap")
        reader     = ChapPacketReader(capture)
        handshakes = MultiChapStateManager()

        for packet in reader:
            handshakes.addHandshakePacket(packet)

        complete = handshakes.getCompletedHandshakes()

        assert len(complete) == 1

        for server in complete:
            for client in complete[server]:
                c1, c2, c3 = complete[server][client].getCiphertext()
                plaintext  = complete[server][client].getPlaintext()
                username   = complete[server][client].getUserName()

                assert username == "moxie"

                hash = nthash.raw_nthash('bPCFyF2uL1p5Lg5yrKmqmY')

                print "NT Hash: %s" % binascii.hexlify(hash)

                key1 = hash[0:7]
                key1 = des.expand_des_key(key1)

                result = des.des_encrypt_block(key1, plaintext)

                print "DES Encryption: %s" % binascii.hexlify(result)
                print "C1: %s" % binascii.hexlify(c1)

                assert result == c1



