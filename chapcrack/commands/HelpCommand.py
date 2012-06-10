"""
The help command.  Describes details of chapcrack subcommands.
"""

import sys

from chapcrack.commands.DecryptCommand import DecryptCommand
from chapcrack.commands.ParseCommand import ParseCommand

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class HelpCommand:

    COMMANDS = {'parse' : ParseCommand, 'decrypt' : DecryptCommand }

    def __init__(self, argv):
        self.argv = argv

    def execute(self):
        if self.argv[0] in HelpCommand.COMMANDS:
            HelpCommand.COMMANDS[self.argv[0]].printHelp()
        else:
            self.printGeneralUsage("Unknown command: %s" % self.argv[0])

    def printHelp(self):
        print(
            """Provides help for individual commands.

            help <command>
            """)

    @staticmethod
    def printGeneralUsage(message):
        if message:
            print ("Error: %s\n" % message)

        sys.stdout.write(
            """chapcrack.py

    Commands (use "chapcrack.py help <command>" to see more):
      parse    -i <capture>
      decrypt  -i <capture> -o <decrypted_capture> -n <nthash>
      help     <command>
            """)

        sys.exit(-1)
