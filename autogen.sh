#!/bin/sh

aclocal 
# aclocal doesn't pick up libopts.m4 so we do it manually
cat config/libopts.m4 >> aclocal.m4
automake && autoconf
