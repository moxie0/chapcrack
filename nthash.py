#!/usr/bin/env python

"""Generates an NT hash from a supplied argument."""

import binascii
import sys

from passlib.hash import nthash

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

print "Hashing: %s" % sys.argv[1]
hash = nthash.raw_nthash(sys.argv[1])
print binascii.hexlify(hash)