"""
The decrypt command. Accepts an input file, output file, and NT hash.

Parses a PPTP capture, searchers for CHAPv2 handshakes which the
supplied NT hash can decrypt, and writes the decrypted PPTP traffic
to the specified output file.
"""

import binascii
import sys
from dpkt import pcap

from chapcrack.commands.Command import Command
from chapcrack.readers.PppPacketReader import PppPacketReader
from chapcrack.state.PppStateManager import PppStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class DecryptCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "ion", "")
        self.inputFile  = self._getInputFile()
        self.outputFile = self._getOutputFile()
        self.nthash     = self._getNtHash()
        self.nthash     = binascii.unhexlify(self.nthash)

    def execute(self):
        capture = open(self.inputFile)
        output  = open(self.outputFile, "w")
        reader  = PppPacketReader(capture)
        writer  = pcap.Writer(output)
        state   = PppStateManager(self.nthash)
        count   = 0

        for packet in reader:
            decryptedPacket = state.addPacket(packet)

            if decryptedPacket:
                writer.writepkt(decryptedPacket)
                count += 1

        print "Wrote %d packets." % count

    def _getNtHash(self):
        nthash = self._getOptionValue("-n")

        if not nthash:
            self.printError("No NT hash specified (-n)")

        return nthash

    def _getOutputFile(self):
        output = self._getOptionValue("-o")

        if not output:
            self.printError("No output path specified (-o)")

        return output

    def printHelp(self, message=None):
        if message:
            print "Error: %s\n\n" % message

        print(
            """Decrypts a PPTP capture with a cracked NT hash.

            decrypt

            Arguments:
              -i <input>     : The capture file
              -o <output>    : The output file to write the decrypted capture to.
              -n <hash>      : The base16-encoded cracked NT hash.
            """)

        sys.exit(-1)