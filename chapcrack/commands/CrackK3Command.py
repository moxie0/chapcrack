"""
A command-line interface to cracking K3.
"""
import binascii
import sys
from chapcrack.commands.Command import Command
from chapcrack.crypto.K3Cracker import K3Cracker

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class CrackK3Command(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "pc", "")

    def printHelp(self):
        print(
            """Brute forces the third ciphertext/plaintext pair in a handshake.

              crack_k3

            Arguments:
              -p <plaintext>  : The handshake challenge plaintext
              -c <ciphertext> : The handshake c3 ciphertext
            """)

    def execute(self):
        ciphertext = binascii.unhexlify(self._getCiphertext())
        plaintext  = binascii.unhexlify(self._getPlaintext())

        sys.stdout.write("Cracking K3...")
        result     = K3Cracker().crack(plaintext, ciphertext, True)

        assert(result is not None)

        print ""
        print "Found K3: %s" % binascii.hexlify(result)

    def _getPlaintext(self):
        plaintext = self._getOptionValue("-p")

        if not plaintext:
            self.printError("No plaintext specified (-p)")

        if not len(plaintext) == 16:
            self.printError("Plaintext expected to be 8 hex-encoded bytes.")

        return plaintext

    def _getCiphertext(self):
        ciphertext = self._getOptionValue("-c")

        if not ciphertext:
            self.printError("No ciphertext specified (-c)")

        if not len(ciphertext) == 16:
            self.printError("Ciphertext expected to be 8 hex-encoded bytes.")

        return ciphertext

