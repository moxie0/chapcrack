"""
The radius command.  Accepts "challange" and "response" parameters.

Accepts "challenge" and "response" parameters as output by freeradius-wpe
and turns them into the components necessary for submitting to CloudCracker.
"""
import binascii

from chapcrack.commands.Command import Command
from chapcrack.commands.ParseCommand import ParseCommand

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

class RadiusCommand(ParseCommand):

    def __init__(self, argv):
        Command.__init__(self, argv, "CR", "")

    def execute(self):
        plaintext = self._getChallenge()
        response  = self._getResponse()

        c1, c2, c3 = response[0:8], response[8:16], response[16:24]
        k3         = self._getK3(plaintext, c3)

        self._printParameters(None, plaintext, c1, c2, c3, k3)

    def _getChallenge(self):
        challenge = self._getOptionValue("-C")

        if not challenge:
            self.printError("Missing challenge (-C)")

        challenge = binascii.unhexlify(challenge.replace(":", ""))

        if len(challenge) != 8:
            self.printError("Invalid challenge length %d" % len(challenge))

        return challenge

    def _getResponse(self):
        response = self._getOptionValue("-R")

        if not response:
            self.printError("Missing response (-R)")

        response = binascii.unhexlify(response.replace(":", ""))

        if len(response) != 24:
            self.printError("Invalid response length %d" % len(response))

        return response

    @staticmethod
    def printHelp():
        print(
            """Generates a CloudCracker token from the output of a FreeRadius interception.

              radius

              Arguments:
                -C <challenge> : The challenge in hexadecimal format.
                -R <response>  : The response in hexadecimal format.
            """)
