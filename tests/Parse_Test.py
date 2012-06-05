__author__  = "Moxie Marlinspike"
__license__ = "GPLv3"

from passlib.hash import nthash
from passlib.utils import des
import unittest
import binascii
from chapcrack.ChapPacketReader import ChapPacketReader
from chapcrack.HandshakeStateManager import HandshakeStateManager
from chapcrack.ProtocolLogic import ProtocolLogic
from tests.md4 import MD4

class ParseTest(unittest.TestCase):

    def test_des(self):
        result = des.des_encrypt_block('12345678', 'ABCDEFGH')
        assert binascii.hexlify(result) == "96de603eaed6256f"

    def test_md4(self):
        digest = MD4()
        digest.update("abcdefghijklmnopqrstuvwxyz")
        result = digest.digest()

        assert binascii.hexlify(result) == "d79e1c308aa5bbcdeea8ed63df412da9"

    def test_parsing(self):
        capture    = open("tests/pptp.cap")
        reader     = ChapPacketReader(capture)
        handshakes = HandshakeStateManager()

        for packet in reader:
            handshakes.addHandshakePacket(packet)

        complete = handshakes.getCompletedHandshakes()

        assert len(complete) == 1

        for server in complete:
            for client in complete[server]:
                c1, c2, c3 = ProtocolLogic.getCiphertext(complete[server][client])
                plaintext  = ProtocolLogic.getPlaintext(complete[server][client])
                username   = ProtocolLogic.getUserName(complete[server][client])

                assert username == "scott"

#                result = nthash.raw_nthash('purple')

                digest = MD4()
                digest.update("purple")
                result = digest.digest()

                key1 = result[0:7]
                key1 = des.expand_des_key(key1)

                result = des.des_encrypt_block(key1, plaintext)

                assert result == c1



