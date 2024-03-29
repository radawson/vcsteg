vcsteg3 -- VeraCrypt real steganography tool
version 3.2 (2021-09-20)
by Vladimir Ivanov <vladimirivanov815@gmail.com>
Richard Dawson <dawsora@gmail.com>
and Martin J. Fiedler <martin.fiedler@gmx.net>

This software is published under the terms of KeyJ's Research License,
version 0.2. Usage of this software is subject to the following conditions:
0. There's no warranty whatsoever. The author(s) of this software can not
   be held liable for any damages that occur when using this software.
1. This software may be used freely for both non-commercial and commercial
   purposes.
2. This software may be redistributed freely as long as no fees are charged
   for the distribution and this license information is included.
3. This software may be modified freely except for this license information,
   which must not be changed in any way.
4. If anything other than configuration, indentation or comments have been
   altered in the code, the original author(s) must receive a copy of the
   modified code.

Version history
===============
3.2 (Richard Dawson)
- change argument interpreter to argparse
- code refactor

3.1 (Richard Dawson)
- bugfixes

3.0 (Martin Fiedler)
- port to Python3

2.0 (Vladimir Ivanov, speed optimizations by Martin Fiedler)
- now supports files over 4 GiB
- erases duplicate encoder signature
- auto-renames VeraCrypt container
- supports 3gp videos
- function allowing post-embed password change

1.0 (Martin Fiedler)
- initial release