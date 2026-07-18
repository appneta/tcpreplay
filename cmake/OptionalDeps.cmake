# OptionalDeps.cmake — netmap, libdnet (fragroute), libpcapnav and tcpdump
# discovery, mirroring configure.ac (issue #688).

include(CheckCSourceCompiles)
include(CheckSymbolExists)

# ---------------------------------------------------------------------------
# netmap (--with-netmap=DIR → WITH_NETMAP)
# ---------------------------------------------------------------------------
set(HAVE_NETMAP "")
set(NETMAP_INCLUDE_DIR "")
if(CMAKE_CROSSCOMPILING)
    set(_netmap_dirs ${WITH_NETMAP})
else()
    set(_netmap_dirs ${WITH_NETMAP} /opt/netmap /usr/src/netmap-release /usr/src/netmap
        /usr/local/src/netmap-release /usr/local/src/netmap /usr/include /usr/local/include)
endif()

foreach(_dir ${_netmap_dirs})
    if(EXISTS ${_dir}/sys/net/netmap.h)
        set(NETMAP_INCLUDE_DIR ${_dir}/sys)
        set(NETMAP_USER_INC ${_dir}/sys/net/netmap_user.h)
        set(HAVE_NETMAP 1)
        break()
    elseif(EXISTS ${_dir}/net/netmap.h)
        set(NETMAP_INCLUDE_DIR ${_dir})
        set(NETMAP_USER_INC ${_dir}/net/netmap_user.h)
        set(HAVE_NETMAP 1)
        break()
    endif()
endforeach()

if(HAVE_NETMAP)
    message(STATUS "Found netmap headers in ${NETMAP_INCLUDE_DIR}")
    # Deliberately NOT passing a bare -DND — see the NETMAP_CFLAGS comment in
    # configure.ac (#1015). NETMAP_WITH_LIBS + include dir are applied only to
    # the targets that need them, never to the global flags used by these
    # detection tests (avoids shadowing system net/bpf.h — see configure.ac).
    set(CMAKE_REQUIRED_FLAGS "-DNETMAP_WITH_LIBS")
    set(CMAKE_REQUIRED_INCLUDES ${NETMAP_INCLUDE_DIR})

    check_c_source_compiles("
#include <stdio.h>
#include \"${NETMAP_USER_INC}\"
int main(void) { (void)nm_open; return 0; }" HAVE_NETMAP_NM_OPEN)
    if(HAVE_NETMAP_NM_OPEN)
        set(HAVE_NETMAP_NM_OPEN 1)
    endif()

    check_c_source_compiles("
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/netmap.h>
int main(void) {
#ifdef NR_REG_MASK
    return 0;
#else
#error NR_REG_MASK not found
#endif
}" HAVE_NETMAP_NR_REG)
    if(HAVE_NETMAP_NR_REG)
        set(HAVE_NETMAP_NR_REG 1)
    endif()

    check_c_source_compiles("
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/netmap.h>
int main(void) { struct nmreq nmr; nmr.nr_flags = 0; return (int)nmr.nr_flags; }" HAVE_NETMAP_NR_FLAGS)
    if(HAVE_NETMAP_NR_FLAGS)
        set(HAVE_NETMAP_NR_FLAGS 1)
    endif()

    check_c_source_compiles("
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/netmap.h>
int main(void) { struct netmap_ring r; r.head = r.tail = 0; return (int)r.head; }" HAVE_NETMAP_RING_HEAD_TAIL)
    if(HAVE_NETMAP_RING_HEAD_TAIL)
        set(HAVE_NETMAP_RING_HEAD_TAIL 1)
    endif()

    set(CMAKE_REQUIRED_FLAGS)
    set(CMAKE_REQUIRED_INCLUDES)
endif()

# ---------------------------------------------------------------------------
# libdnet (fragroute) — skipped under Cygwin, like configure.ac
# ---------------------------------------------------------------------------
set(HAVE_LIBDNET "")
set(LIBDNET_VERSION_STR "")
set(DNET_CFLAGS "")
set(DNET_LIBRARIES "")
if(NOT HAVE_CYGWIN AND NOT WITH_LIBDNET STREQUAL "no")
    # Debian/Ubuntu name it libdumbnet (dumbnet-config); everyone else dnet-config
    set(_dnet_prefixes ${WITH_LIBDNET} /usr/local /opt/local /usr)
    if(CMAKE_OSX_SYSROOT)
        list(APPEND _dnet_prefixes ${CMAKE_OSX_SYSROOT}/usr)
    endif()
    foreach(_cfg dumbnet-config dnet-config)
        foreach(_prefix ${_dnet_prefixes})
            if(EXISTS ${_prefix}/bin/${_cfg})
                execute_process(COMMAND ${_prefix}/bin/${_cfg} --cflags
                                OUTPUT_VARIABLE DNET_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
                execute_process(COMMAND ${_prefix}/bin/${_cfg} --libs
                                OUTPUT_VARIABLE DNET_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
                execute_process(COMMAND ${_prefix}/bin/${_cfg} --version
                                OUTPUT_VARIABLE LIBDNET_VERSION_STR OUTPUT_STRIP_TRAILING_WHITESPACE)
                if(_cfg STREQUAL "dumbnet-config")
                    set(LIBDNET_VERSION_STR "${LIBDNET_VERSION_STR} (libdumbnet)")
                endif()
                set(HAVE_LIBDNET 1)
                break()
            endif()
        endforeach()
        if(HAVE_LIBDNET)
            break()
        endif()
    endforeach()

    if(HAVE_LIBDNET)
        message(STATUS "Found libdnet: ${LIBDNET_VERSION_STR}")
        separate_arguments(DNET_CFLAGS)
        separate_arguments(DNET_LIBRARIES)
        # Debian uses dumbnet.h instead of dnet.h
        set(CMAKE_REQUIRED_FLAGS "${DNET_CFLAGS}")
        check_include_file(dumbnet.h HAVE_DUMBNET_H)
        check_include_file(dnet.h HAVE_DNET_H)
        set(CMAKE_REQUIRED_FLAGS)
        if(HAVE_DUMBNET_H)
            set(HAVE_DUMBNET_H 1)
        endif()
        if(HAVE_DNET_H)
            set(HAVE_DNET_H 1)
        endif()
    else()
        message(STATUS "libdnet not found, disabling fragroute feature")
    endif()
endif()
set(ENABLE_FRAGROUTE ${HAVE_LIBDNET})

# ---------------------------------------------------------------------------
# libpcapnav (pcapnav-config)
# ---------------------------------------------------------------------------
set(HAVE_PCAPNAV "")
set(LNAV_CFLAGS "")
set(LNAV_LIBRARIES "")
set(PCAPNAV_VERSION "")
if(WITH_PCAPNAV_CONFIG)
    set(PCAPNAV_CONFIG_EXECUTABLE ${WITH_PCAPNAV_CONFIG})
else()
    find_program(PCAPNAV_CONFIG_EXECUTABLE pcapnav-config)
endif()
if(PCAPNAV_CONFIG_EXECUTABLE AND EXISTS ${PCAPNAV_CONFIG_EXECUTABLE})
    execute_process(COMMAND ${PCAPNAV_CONFIG_EXECUTABLE} --libs
                    OUTPUT_VARIABLE LNAV_LIBRARIES OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${PCAPNAV_CONFIG_EXECUTABLE} --cflags
                    OUTPUT_VARIABLE LNAV_CFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${PCAPNAV_CONFIG_EXECUTABLE} --version
                    OUTPUT_VARIABLE PCAPNAV_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    separate_arguments(LNAV_LIBRARIES)
    separate_arguments(LNAV_CFLAGS)
    if(PCAPNAV_VERSION VERSION_GREATER_EQUAL 0.4)
        set(HAVE_PCAPNAV 1)
        message(STATUS "Found libpcapnav ${PCAPNAV_VERSION}")
    else()
        message(WARNING "Libpcapnav versions < 0.4 are not supported. Disabling offset jump feature.")
        set(LNAV_CFLAGS "")
        set(LNAV_LIBRARIES "")
    endif()
endif()

# ---------------------------------------------------------------------------
# tcpdump binary (--with-tcpdump → WITH_TCPDUMP)
# ---------------------------------------------------------------------------
set(HAVE_TCPDUMP "")
if(WITH_TCPDUMP)
    set(TCPDUMP_PATH ${WITH_TCPDUMP})
else()
    find_program(TCPDUMP_PATH tcpdump PATHS /usr/sbin /sbin /usr/local/sbin)
endif()
if(TCPDUMP_PATH AND EXISTS ${TCPDUMP_PATH})
    set(HAVE_TCPDUMP 1)
    message(STATUS "Using tcpdump in ${TCPDUMP_PATH}")
else()
    message(WARNING "Unable to find tcpdump.  Please specify -DWITH_TCPDUMP.  Disabling --verbose")
    set(TCPDUMP_PATH "")
endif()

# ENABLE_VERBOSE requires both tcpdump and pcap_dump_fopen()
set(ENABLE_VERBOSE "")
if(HAVE_TCPDUMP AND HAVE_PCAP_DUMP_FOPEN)
    set(ENABLE_VERBOSE 1)
endif()
