#!/usr/bin/env python

"""A tool for parsing and decrypting PPTP packet captures."""

import sys
from chapcrack.commands.CrackK3Command import CrackK3Command
from chapcrack.commands.DecryptCommand import DecryptCommand
from chapcrack.commands.HelpCommand import HelpCommand
from chapcrack.commands.ParseCommand import ParseCommand
from chapcrack.commands.RadiusCommand import RadiusCommand

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

def main(argv):
    if len(argv) < 1:
        HelpCommand.printGeneralUsage("Missing command")

    if argv[0] == 'parse':
        ParseCommand(argv[1:]).execute()
    elif argv[0] == 'decrypt':
        DecryptCommand(argv[1:]).execute()
    elif argv[0] == 'help':
        HelpCommand(argv[1:]).execute()
    elif argv[0] == 'crack_k3':
        CrackK3Command(argv[1:]).execute()
    elif argv[0] == 'radius':
        RadiusCommand(argv[1:]).execute()
    else:
        HelpCommand.printGeneralUsage("Unknown command: %s" % argv[0])

if __name__ == '__main__':
    main(sys.argv[1:])
