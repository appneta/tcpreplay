###################################################################
#  $Id:$
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
# - Find libevent
# Find the libevent includes and library
# http://libdnet.sourceforge.net/
#
# The environment variable LIBEVENT_DIR allows to specify where to find 
# libevent in non standard location.
#
#  EVENT_INCLUDE_DIRS - where to find event.h, etc.
#  EVENT_LIBRARIES   - List of libraries when using libevent.
#  HAVE_LIBEVENT     - True if libevent found.


IF(EXISTS ${LIBEVENT_DIR})
    FIND_PATH(EVENT_INCLUDE_DIR 
        NAMES
        event.h
        PATHS ${LIBEVENT_DIR}/include
        NO_DEFAULT_PATH
    )

    FIND_LIBRARY(EVENT_LIBRARY
        NAMES 
        event
        PATHS ${LIBEVENT_DIR}/lib
        NO_DEFAULT_PATH
    )

ELSE(EXISTS ${LIBEVENT_DIR})
    FIND_PATH(EVENT_INCLUDE_DIR 
        NAMES
        event.h
    )

    FIND_LIBRARY(EVENT_LIBRARY
        NAMES 
        event
    )
ENDIF(EXISTS ${LIBEVENT_DIR})

SET(EVENT_INCLUDE_DIRS ${EVENT_INCLUDE_DIR})
SET(EVENT_LIBRARIES ${EVENT_LIBRARY})


IF(EVENT_INCLUDE_DIRS)
  MESSAGE(STATUS "libevent include dirs set to ${EVENT_INCLUDE_DIRS}")
ELSE(EVENT_INCLUDE_DIRS)
  MESSAGE(FATAL "libevent include dirs cannot be found")
ENDIF(EVENT_INCLUDE_DIRS)

IF(EVENT_LIBRARIES)
  MESSAGE(STATUS "libevent library set to ${EVENT_LIBRARIES}")
ELSE(EVENT_LIBRARIES)
  MESSAGE(FATAL "libevent library cannot be found")
ENDIF(EVENT_LIBRARIES)



# Functions
SET(CMAKE_REQUIRED_INCLUDES ${EVENT_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_LIBRARIES ${EVENT_LIBRARIES})
CHECK_INCLUDE_FILE("event.h" EVENT_INCLUDE_FILE)
CHECK_FUNCTION_EXISTS("event_get_version" HAVE_EVENT_GET_VERSION)
CHECK_FUNCTION_EXISTS("event_init" HAVE_EVENT_INIT)
CHECK_FUNCTION_EXISTS("event_add" HAVE_EVENT_ADD)
CHECK_FUNCTION_EXISTS("event_set" HAVE_EVENT_SET)
CHECK_FUNCTION_EXISTS("event_dispatch" HAVE_EVENT_DISPATCH)

CHECK_C_SOURCE_COMPILES("
#include <stdlib.h>
#include <stdio.h>
#include <event.h>

void
callback(int fd, short event, void *args)
{
    int i;
    i = 1;
}

int
main(int argc, char *argv[])
{
    struct event ev;
    int fd;
    short event;

    evtimer_set(&ev, &callback, NULL);
    evtimer_add(&ev, NULL);
    evtimer_del(&ev);
    return 0;
}

"
HAVE_EVENT_EVTIMER)

CHECK_C_SOURCE_COMPILES("
#include <stdlib.h>
#include <stdio.h>
#include <event.h>

void
callback(int fd, short event, void *args)
{
    int i;
    i = 1;
}

int
main(int argc, char *argv[])
{
    struct event ev;
    int fd;
    short event;

    timeout_set(&ev, &callback, NULL);
    timeout_add(&ev, NULL);
    timeout_del(&ev);
    return 0;
}

"
HAVE_EVENT_TIMEOUT)

SET(HAVE_LIBEVENT NO)
IF(EVENT_INCLUDE_DIRS AND EVENT_LIBRARY)
    SET(HAVE_LIBEVENT YES)
ENDIF(EVENT_INCLUDE_DIRS AND EVENT_LIBRARY)


MARK_AS_ADVANCED(
  EVENT_LIBRARY
  EVENT_INCLUDE_DIRS
)
