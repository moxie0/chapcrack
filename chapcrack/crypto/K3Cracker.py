"""
A little utility class to crack 'K3', which is the third DES key
derived from the NTLM hash of the user's passphrase.  There are
only two bytes of key material left at this point, so CHAPv2 just
pads the other five with 0x00.

This class uses the python 'multiprocessing' module to iterate
over the 2^16 possibilities and return K3.
"""
from multiprocessing import Pool
import functools
from passlib.utils import des
import sys

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

def checkKey(plaintext, ciphertext, b1, b2):
    keyCandidateBytes = chr(b1) + chr(b2) + (chr(0x00) * 5)
    keyCandidate      = des.expand_des_key(keyCandidateBytes)
    result            = des.des_encrypt_block(keyCandidate, plaintext)

    if result == ciphertext:
        return keyCandidateBytes

class K3Cracker:

    def crack(self, plaintext, ciphertext, markTime=False):
        pool = Pool()

        for b1 in range(0, 256):
            if markTime and b1 % 20 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()

            partial = functools.partial(checkKey, plaintext, ciphertext, b1)
            results = pool.map(partial, range(0, 256))

            for result in results:
                if result is not None:
                    return result
