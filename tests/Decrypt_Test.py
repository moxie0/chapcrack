from passlib.hash import nthash
import unittest
import binascii
from M2Crypto.RC4 import RC4
from chapcrack.state.MppeStateManager import MppeStateManager

class DecryptTest(unittest.TestCase):

    def test_derivation(self):
        hash     = nthash.raw_nthash("clientPass")
        response = binascii.unhexlify("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")

        state    = MppeStateManager("", "", hash, response)

        assert state.masterKey == binascii.unhexlify("FDECE3717A8C838CB388E527AE3CDD31")

        assert state.serverMasterKey == binascii.unhexlify("8B7CDC149B993A1BA118CB153F56DCCB")

        assert state.serverSessionKey == binascii.unhexlify("405CB2247A7956E6E211007AE27B22D4")

        cipher = RC4(key=state.serverSessionKey)
        assert cipher.update("test message") == binascii.unhexlify("81848317DF68846272FB5ABE")

        cipher = RC4(key=state.serverSessionKey)
        assert cipher.update(binascii.unhexlify("81848317DF68846272FB5ABE")) == "test message"