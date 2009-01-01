#!/bin/sh
rm -f config/config.guess config/config.sub config/ltmain.sh 2>/dev/null
rm -f aclocal.m4 2>/dev/null
aclocal  -I libopts/m4/
# aclocal doesn't pick up libopts.m4 so we do it manually
#cat libopts/m4/libopts.m4 libopts/m4/liboptschk.m4  >> aclocal.m4
libtoolize || glibtoolize
autoheader
automake
autoconf

