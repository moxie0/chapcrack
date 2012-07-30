#!/usr/bin/env python

from distutils.core import setup
import os
import shutil
import re

__author__    = "Moxie Marlinspike"
__license__   = "GPLv3"
__copyright__ = "Copyright 2012, Moxie Marlinspike"

def parseVersion():
    versionLine       = open("chapcrack/_version.py", "rt").read()
    versionExpression = r"^__version__ = ['\"]([^'\"]*)['\"]"
    match             = re.search(versionExpression, versionLine, re.M)

    if match:
        return match.group(1)
    else:
        raise RuntimeError("Unable to find version string in chapcrack/_version.py")

shutil.copyfile("chapcrack.py", "chapcrack/chapcrack")

REQUIRES = ['dpkt', 'passlib']

setup  (name             = 'chapcrack',
        version          = parseVersion(),
        description      = 'Parses pcaps and extracts ciphertext/plaintext pairs from CHAP handshakes.',
        author           = 'Moxie Marlinspike',
        author_email     = 'moxie@thoughtcrime.org',
        license          = 'GPLv3',
        packages         = ["chapcrack", "chapcrack.commands", "chapcrack.crypto", "chapcrack.packets",
                            "chapcrack.readers", "chapcrack.state"],
        package_dir      = {'chapcrack' : 'chapcrack/'},
        scripts          = ['chapcrack/chapcrack'],
        install_requires = REQUIRES,
)

print "Cleaning up..."
if os.path.exists("build/"):
    shutil.rmtree("build/")

try:
    os.remove("chapcrack/chapcrack")
except:
    pass
