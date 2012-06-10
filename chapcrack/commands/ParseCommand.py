"""
The parse command.  Accepts a pcap file containing a PPTP capture.

Parses a packet capture for CHAPv2 handshakes, and prints details
of the handshake necessary for cracking.  These include the client
and server IP addresses, the username, and the plaintext/ciphertext
pairs.
"""

from chapcrack.commands.Command import Command
from chapcrack.readers.ChapPacketReader import ChapPacketReader
from chapcrack.state.MultiChapStateManager import MultiChapStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class ParseCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "i", "")

    def printHelp(self):
        print(
            """Parses a PPTP capture and prints the ciphertext/plaintext pairs for decrypting.

              parse

            Arguments:
              -i <input> : The capture file
            """)

    def execute(self):
        inputFile  = self._getInputFile()
        handshakes = MultiChapStateManager()
        capture    = open(inputFile)
        reader     = ChapPacketReader(capture)

        for packet in reader:
            handshakes.addHandshakePacket(packet)

        complete = handshakes.getCompletedHandshakes()

        for server in complete:
            for client in complete[server]:
                print "Got completed handshake [%s --> %s]" % (client, server)

                c1, c2, c3 = complete[server][client].getCiphertext()
                plaintext  = complete[server][client].getPlaintext()
                username   = complete[server][client].getUserName()

                print "      User = %s" % username
                print "        C1 = %s" % c1.encode("hex")
                print "        C2 = %s" % c2.encode("hex")
                print "        C3 = %s" % c3.encode("hex")
                print "         P = %s" % plaintext.encode("hex")

