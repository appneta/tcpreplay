#!/bin/bash -x
aclocal
autoheader
autoconf
automake --add-missing
./configure
