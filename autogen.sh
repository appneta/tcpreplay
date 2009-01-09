#!/bin/sh
rm -f config/config.guess config/config.sub config/ltmain.sh 2>/dev/null
rm -f aclocal.m4 2>/dev/null
aclocal  -I libopts/m4/
if test -x "`which libtoolize`" ; then
    libtoolize --copy
else
    # Necessary under OS X
    glibtoolize --copy
fi
autoheader
automake --add-missing --copy
autoconf

