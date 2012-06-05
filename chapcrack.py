#!/usr/bin/env python

import sys
from chapcrack.ChapPacketReader import ChapPacketReader
from chapcrack.HandshakeStateManager import HandshakeStateManager
from chapcrack.ProtocolLogic import ProtocolLogic

def printUsage():
    print "chapcrack.py <pcap>"
    sys.exit(0)

def main(argv):
    if len(argv) < 1:
        printUsage()

    handshakes = HandshakeStateManager()
    capture    = open(argv[0])
    reader     = ChapPacketReader(capture)

    for packet in reader:
        handshakes.addHandshakePacket(packet)

    complete = handshakes.getCompletedHandshakes()

    for server in complete:
        for client in complete[server]:
            print "Got completed handshake [%s --> %s]" % (server, client)

            c1, c2, c3 = ProtocolLogic.getCiphertext(complete[server][client])
            plaintext  = ProtocolLogic.getPlaintext(complete[server][client])
            username   = ProtocolLogic.getUserName(complete[server][client])

            print "  User = %s" % username
            print "  C1   = %s" % c1.encode("hex")
            print "  C2   = %s" % c2.encode("hex")
            print "  C3   = %s" % c3.encode("hex")
            print "  P    = %s" % plaintext.encode("hex")

if __name__ == '__main__':
    main(sys.argv[1:])
