chapcrack
=================

A tool for parsing and decrypting MS-CHAPv2 network handshakes.

1) Obtain a packet capture with an MS-CHAPv2 network handshake in it (PPTP VPN or WPA2 Enterprise handshake, for instance).

2) Use chapcrack to parse relevant credentials from the handshake (chapcrack parse -i path/to/capture.cap).

3) Submit the CloudCracker token to www.cloudcracker.com

4) Get your results, and decrypt the packet capture (chapcrack decrypt -i path/to/capture.cap -o output.cap -n <results>)

Bug tracker
-----------

Have a bug? Please create an issue here on GitHub!

https://github.com/moxie0/chapcrack/issues

Copyright
---------

Copyright 2012 Moxie Marlinspike

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
