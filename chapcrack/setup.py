#!/usr/bin/env python

__author__ = "Moxie Marlinspike"
__license__ = "GPLv3"

from distutils.core import setup
import os
import shutil

shutil.copyfile("chapcrack.py", "chapcrack/chapcrack")

REQUIRES = ['dpkt', 'passlib']

setup  (name             = 'chapcrack',
        version          = '0.1',
        description      = 'Parses pcaps and extracts ciphertext/plaintext pairs from CHAP handshakes.',
        author           = 'Moxie Marlinspike',
        author_email     = 'moxie@thoughtcrime.org',
        license          = 'GPLv3',
        packages         = ["chapcrack"],
        package_dir      = {'chapcrack' : 'chapcrack/'},
        scripts          = ['chapcrack/chapcrack'],
        install_requires = REQUIRES,
        data_files       = [('share/chapcrack', ['README', 'INSTALL', 'COPYING'])]
)

print "Cleaning up..."
if os.path.exists("build/"):
    shutil.rmtree("build/")

try:
    os.remove("chapcrack/chapcrack")
except:
    pass
