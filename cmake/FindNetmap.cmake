###################################################################
#  $Id:$
#
#  Copyright (c) 2013 AppNeta Inc - Fred Klassen, <fklassen at appneta dot com>
#  Copyright (c) 2013 Aaron Turner, <aturner at synfin dot net>
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
# - Find netmap
# Find the netmap includes
#
# For more information on netmap visit http://info.iet.unipi.it/~luigi/netmap/
#
# The environment variable NETMAP_DIR allows to specify where to find 
# libevent in non standard location.
#
#  NETMAP_INCLUDE_DIRS - where to find netmap.h, etc.
#  HAVE_NETMAP     - True if netmap found.
 
SET(foundnetmap false)
FOREACH(testdir /usr/src/netmap /usr/src/netmap-release ${NETMAP_DIR} $ENV{NETMAP_DIR})
    IF(EXISTS ${testdir}/sys/net/netmap.h)
        SET(foundnetmap ${testdir})
    ENDIF()
ENDFOREACH()

IF(foundnetmap)
    SET(NETMAP_INCLUDE_DIRS ${foundnetmap})
    SET(HAVE_NETMAP YES)
    MESSAGE(STATUS "Using netmap from ${foundnetmap}")
ELSE()
    MESSAGE(STATUS "Unable to locate netmap")
    SET(HAVE_NETMAP NO)
ENDIF()

MARK_AS_ADVANCED(
  NETMAP_INCLUDE_DIRS
)
