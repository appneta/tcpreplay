###################################################################
#  $Id$
#
#  Copyright (c) 2009 Aaron Turner, <aturner at synfin dot net>
#  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# * Neither the name of the Aaron Turner nor the names of its
#   contributors may be used to endorse or promote products derived
#   from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
###################################################################
# - Find libdnet
# Find the libdnet includes and library
# http://libdnet.sourceforge.net/
#
# The environment variable DNETDIR allows to specify where to find 
# libdnet in non standard location.
#  
#  DNET_CFLAGS - where to find dnet.h, etc.
#  DNET_LIBS   - List of libraries when using libdnet.
#  HAVE_LIBDNET       - True if libdnet found.
#  LIBDNET_VERSION   - version of libdnet

SET(founddnet false)
FOREACH(testdir $ENV{DNETDIR} /usr/local /opt/local /usr) 
    EXECUTE_PROCESS(COMMAND ${testdir}/bin/dnet-config --cflags
        RESULT_VARIABLE exit_code
        OUTPUT_VARIABLE DNET_CFLAGS
    )
    IF(exit_code EQUAL 0)
        SET(founddnet ${testdir})
    ENDIF(exit_code EQUAL 0)
ENDFOREACH(testdir)

IF(founddnet)
    EXECUTE_PROCESS(COMMAND ${founddnet}/bin/dnet-config --cflags
        OUTPUT_VARIABLE cflags
    )
    EXECUTE_PROCESS(COMMAND ${founddnet}/bin/dnet-config --libs
        OUTPUT_VARIABLE libs
    )
    EXECUTE_PROCESS(COMMAND ${founddnet}/bin/dnet-config --version
        OUTPUT_VARIABLE version
    )
    
    # remove new line from --version
    STRING(REGEX REPLACE "\n" "" newversion ${version})
    SET(LIBDNET_VERSION ${newversion})
    
    STRING(REGEX REPLACE "\n" "" newlibs ${libs})
    SET(DNET_LIBS ${newlibs})
    
    STRING(REGEX REPLACE "\n" "" newcflags ${cflags})
    SET(DNET_CFLAGS ${newcflags})
    
    SET(HAVE_LIBDNET 1)
    MESSAGE(STATUS "Using libdnet from ${founddnet}")
ELSE(founddnet)
    MESSAGE(STATUS "Unable to locate libdnet (missing dnet-config)")
ENDIF(founddnet)
