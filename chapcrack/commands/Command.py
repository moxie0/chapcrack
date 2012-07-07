"""Base class for commands.  Handles parsing supplied arguments."""

import getopt
import sys

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class Command:

    def __init__(self, argv, options, flags, allowArgRemainder=False):
        try:
            self.flags                     = flags
            self.options                   = ":".join(options) + ":"
            self.values, self.argRemainder = getopt.getopt(argv, self.options + self.flags)

            if not allowArgRemainder and self.argRemainder:
                self.printError("Too many arguments: %s" % self.argRemainder)
        except getopt.GetoptError as e:
            self.printError(e)

    def _getOptionValue(self, flag):
        for option, value in self.values:
            if option == flag:
                return value

        return None

    def _containsOption(self, flag):
        for option, value in self.values:
            if option == flag:
                return True

    def _getInputFile(self):
        inputFile = self._getOptionValue("-i")

        if not inputFile:
            self.printError("Missing input file (-i)")

        return inputFile

    def printError(self, error):
        sys.stderr.write("ERROR: %s\n" % error)
        sys.exit(-1)
