#!/bin/sh

rm -f aclocal.m4 2>/dev/null
aclocal 
# aclocal doesn't pick up libopts.m4 so we do it manually
cat config/libopts.m4 >> aclocal.m4
automake && autoconf
