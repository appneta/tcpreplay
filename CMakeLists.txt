# CMake build for the Tcpreplay Suite (issue #688).
#
# This mirrors the autotools build (configure.ac + Makefile.am) — autogen.sh /
# configure remain the canonical build for release; CMake support primarily
# targets IDE workflows (VS Code, CLion) and faster developer iteration.
#
#   cmake -B build [options]
#   cmake --build build
#
# Option mapping from ./configure (see ./configure --help):
#   --enable-debug            -DENABLE_DEBUG=ON
#   --enable-extra-debug      -DENABLE_EXTRA_DEBUG=ON
#   --enable-asan             -DENABLE_ASAN=ON
#   --enable-tsan             -DENABLE_TSAN=ON
#   --enable-dmalloc          -DENABLE_DMALLOC=ON
#   --enable-efence           -DENABLE_EFENCE=ON
#   --enable-gprof            -DENABLE_GPROF=ON
#   --enable-pedantic         -DENABLE_PEDANTIC=ON
#   --enable-pcapconfig       -DENABLE_PCAPCONFIG=ON
#   --disable-64bits          -DENABLE_64BITS=OFF
#   --disable-tuntap          -DENABLE_TUNTAP=OFF
#   --enable-static-link      -DENABLE_STATIC_LINK=ON
#   --enable-test-hexdump     -DENABLE_TEST_HEXDUMP=ON
#   --enable-timestamp-trace  -DENABLE_TIMESTAMP_TRACE=ON
#   --enable-force-*          -DFORCE_INJECT_<BPF|PF|LIBDNET|LIBXDP|LIBURING|PCAP_INJECT|PCAP_SENDPACKET>=ON
#   --with-libpcap=DIR        -DWITH_LIBPCAP=DIR
#   --with-netmap=DIR         -DWITH_NETMAP=DIR
#   --with-pfring-lib=LIB     -DWITH_PFRING_LIB=LIB
#   --with-libdnet=DIR        -DWITH_LIBDNET=DIR
#   --with-tcpdump=FILE       -DWITH_TCPDUMP=FILE
#   --with-pcapnav-config=F   -DWITH_PCAPNAV_CONFIG=F
#   --with-testnic=NIC        -DWITH_TESTNIC=NIC
#   --with-testnic2=NIC       -DWITH_TESTNIC2=NIC
#   --with-macos-sdk=VER      use -DCMAKE_OSX_SYSROOT=<sdk path> (CMake native)

cmake_minimum_required(VERSION 3.16)

# Single source of truth for the version: the AC_INIT line in configure.ac
file(STRINGS configure.ac _ac_init_line REGEX "^AC_INIT\\(\\[tcpreplay\\]")
string(REGEX MATCH "\\[([0-9]+\\.[0-9]+\\.[0-9]+)(_[A-Za-z0-9]+)?\\]" _ ac_ver "${_ac_init_line}")
string(REGEX REPLACE "^AC_INIT\\(\\[tcpreplay\\],\\[([^]]+)\\].*$" "\\1" TCPREPLAY_VERSION "${_ac_init_line}")
string(REGEX REPLACE "^([0-9]+\\.[0-9]+\\.[0-9]+).*$" "\\1" TCPREPLAY_BASE_VERSION "${TCPREPLAY_VERSION}")

project(tcpreplay VERSION ${TCPREPLAY_BASE_VERSION} LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

include(CheckCCompilerFlag)
include(CheckTypeSize)

# ---------------------------------------------------------------------------
# Options (mirroring configure.ac)
# ---------------------------------------------------------------------------
option(ENABLE_DEBUG "Enable debugging code and support for the -d option" OFF)
option(ENABLE_EXTRA_DEBUG "Enable additional debugging code (may affect performance)" OFF)
option(ENABLE_TIMESTAMP_TRACE "Enable dumping of trace timestamps at the end of a test" OFF)
option(ENABLE_ASAN "Enable Address Sanitizer support" OFF)
option(ENABLE_TSAN "Enable Thread Sanitizer support" OFF)
option(ENABLE_DMALLOC "Enable linking to dmalloc for better memory debugging" OFF)
option(ENABLE_PEDANTIC "Enable gcc's -pedantic option" OFF)
option(ENABLE_EFENCE "Enable Electric Fence memory debugger" OFF)
option(ENABLE_GPROF "Enable GNU Profiler" OFF)
option(ENABLE_PCAPCONFIG "Enable automatic libpcap config via pcap-config" OFF)
option(ENABLE_64BITS "Use 64bit packet counters" ON)
option(ENABLE_TUNTAP "Enable tuntap support" ON)
option(ENABLE_STATIC_LINK "Use static libraries ( .a or .A.tbd )" OFF)
option(ENABLE_TEST_HEXDUMP "Enable hexdump pcap on test failure" OFF)
option(FORCE_INJECT_BPF "Force using BPF for sending packets" OFF)
option(FORCE_INJECT_PF "Force using Linux's PF_PACKET for sending packets" OFF)
option(FORCE_INJECT_LIBDNET "Force using libdnet for sending packets" OFF)
option(FORCE_INJECT_LIBXDP "Force using libxdp for sending packets" OFF)
option(FORCE_INJECT_LIBURING "Force using io_uring for sending packets" OFF)
option(FORCE_INJECT_PCAP_INJECT "Force using libpcap's pcap_inject()" OFF)
option(FORCE_INJECT_PCAP_SENDPACKET "Force using libpcap's pcap_sendpacket()" OFF)

set(WITH_LIBPCAP "" CACHE PATH "Use libpcap in DIR")
set(WITH_NETMAP "" CACHE PATH "Use netmap in DIR")
set(WITH_PFRING_LIB "" CACHE FILEPATH "Use a specific PF_RING static library")
set(WITH_LIBDNET "" CACHE PATH "Use libdnet in DIR")
set(WITH_TCPDUMP "" CACHE FILEPATH "Path to tcpdump binary")
set(WITH_PCAPNAV_CONFIG "" CACHE FILEPATH "Use given pcapnav-config")
set(WITH_TESTNIC "" CACHE STRING "Network card to use for testing")
set(WITH_TESTNIC2 "" CACHE STRING "Optional 2nd network card to use for testing")

if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive")
endif()

# ---------------------------------------------------------------------------
# Global compile setup
# ---------------------------------------------------------------------------
# required by C23 standard (configure.ac adds -D_DEFAULT_SOURCE)
add_compile_definitions(_DEFAULT_SOURCE)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_definitions("_U_=__attribute__((unused))")
else()
    add_compile_definitions("_U_=")
endif()

macro(tcpr_add_flag_if_supported flag var)
    string(REGEX REPLACE "[^A-Za-z0-9]" "_" _flagvar "HAVE_FLAG${flag}")
    check_c_compiler_flag(${flag} ${_flagvar})
    if(${_flagvar})
        set(${var} ${flag})
        add_compile_options(${flag})
    else()
        set(${var} "")
    endif()
endmacro()

tcpr_add_flag_if_supported(-Wextra WEXTRA)
tcpr_add_flag_if_supported(-Wno-variadic-macros WNO_VARIADIC_MACROS)
tcpr_add_flag_if_supported(-Wfatal-errors WFATAL_ERRORS)
tcpr_add_flag_if_supported(-Wno-format-contains-nul WNO_FORMAT_CONTAINS_NUL)
if(APPLE)
    # OS X SDKs throw lots of unnecessary macro warnings
    tcpr_add_flag_if_supported(-Wno-macro-redefined WNO_MACRO_REDEFINED)
    tcpr_add_flag_if_supported(-Wno-format WNO_FORMAT)
endif()

if(ENABLE_DEBUG)
    set(DEBUG 1)
    add_compile_options(-g -O0 -Wall)
endif()
if(ENABLE_EXTRA_DEBUG)
    set(EXTRA_DEBUG 1)
endif()
if(ENABLE_TIMESTAMP_TRACE)
    set(TIMESTAMP_TRACE 1)
endif()
if(ENABLE_PEDANTIC)
    add_compile_options(-pedantic)
endif()
if(ENABLE_EFENCE)
    set(EFENCE 1)
    add_link_options(-lefence)
endif()
if(ENABLE_GPROF)
    set(GPROF 1)
    if(ENABLE_DEBUG)
        add_compile_options(-pg)
        add_link_options(-pg)
    else()
        add_compile_options(-ggdb -pg -fprofile-arcs)
        add_link_options(-pg -fprofile-arcs)
    endif()
endif()
if(ENABLE_ASAN)
    set(HAVE_LIBASAN 1)
    add_compile_options(-O1 -g -fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()
if(ENABLE_TSAN)
    add_compile_options(-O1 -g -fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

set(DMALLOC_LIB "")
if(ENABLE_DMALLOC)
    set(ENABLE_DMALLOC 1)
    set(DMALLOC_FUNC_CHECK 1)
    set(WITH_DMALLOC 1)
    include_directories(/opt/local/include)
    set(DMALLOC_LIB /opt/local/lib/libdmalloc.a)
endif()

if(ENABLE_64BITS)
    set(ENABLE_64BITS 1)
    message(STATUS "Using u_int64_t for packet counters")
else()
    set(ENABLE_64BITS "")
    message(STATUS "Using u_int32_t for packet counters")
endif()

if(ENABLE_STATIC_LINK)
    set(ENABLE_STATIC_LINK 1)
    set(ENABLE_DYNAMIC_LINK "")
else()
    set(ENABLE_STATIC_LINK "")
    set(ENABLE_DYNAMIC_LINK 1)
endif()

foreach(_force FORCE_INJECT_BPF FORCE_INJECT_PF FORCE_INJECT_LIBDNET FORCE_INJECT_LIBXDP
        FORCE_INJECT_LIBURING FORCE_INJECT_PCAP_INJECT FORCE_INJECT_PCAP_SENDPACKET)
    if(${_force})
        set(${_force} 1)
    else()
        set(${_force} "")
    endif()
endforeach()

# ---------------------------------------------------------------------------
# autogen (AutoOpts) — required to generate *_opts.c when building from git
# ---------------------------------------------------------------------------
find_program(AUTOGEN_EXECUTABLE autogen)
set(AUTOGEN_VERSION "unknown")
if(AUTOGEN_EXECUTABLE)
    execute_process(COMMAND ${AUTOGEN_EXECUTABLE} -v
                    OUTPUT_VARIABLE _autogen_v OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.?[0-9]*" AUTOGEN_VERSION "${_autogen_v}")
    if(AUTOGEN_VERSION VERSION_LESS 5.18.4)
        message(FATAL_ERROR "autogen ${AUTOGEN_VERSION} is too old. Upgrade to 5.18.4 or higher")
    endif()
    message(STATUS "Found autogen ${AUTOGEN_VERSION}")
elseif(NOT EXISTS ${CMAKE_SOURCE_DIR}/src/tcpreplay_opts.c)
    message(FATAL_ERROR "Please install GNU autogen if you are building from GitHub. "
            "To avoid this message download source from https://github.com/appneta/tcpreplay/releases/latest")
endif()

# ---------------------------------------------------------------------------
# Feature detection
# ---------------------------------------------------------------------------
include(ConfigureChecks)
include(FindPCAP)

# largefile support (AC_SYS_LARGEFILE)
check_type_size(off_t SIZEOF_OFF_T)
if(SIZEOF_OFF_T AND SIZEOF_OFF_T LESS 8)
    set(_FILE_OFFSET_BITS 64)
    set(_LARGEFILE_SOURCE 1)
endif()

# PF_RING static library (--with-pfring-lib)
set(HAVE_PF_RING_PCAP "")
set(PF_RING_FOUND FALSE)
if(WITH_PFRING_LIB)
    if(NOT EXISTS ${WITH_PFRING_LIB})
        message(FATAL_ERROR "Unable to find PF_RING library ${WITH_PFRING_LIB}")
    endif()
    check_library_exists(numa numa_available "" HAVE_LIBNUMA)
    check_library_exists(pthread pthread_create "" HAVE_LIBPTHREAD)
    if(NOT HAVE_LIBNUMA)
        message(FATAL_ERROR "PF_RING requires libnuma and/or libnuma-dev")
    endif()
    if(NOT HAVE_LIBPTHREAD)
        message(FATAL_ERROR "PF_RING requires libpthread")
    endif()
    list(APPEND PCAP_LIBRARIES ${WITH_PFRING_LIB} numa pthread rt)
    set(PF_RING_FOUND TRUE)
    set(HAVE_PF_RING_PCAP 1)
endif()

# Extra libs newer libpcap may need when not using pcap-config
if(NOT PCAP_VIA_PCAPCONFIG)
    check_library_exists(nl nl_cache_alloc "" HAVE_LIBNL)
    if(HAVE_LIBNL)
        list(APPEND PCAP_LIBRARIES nl)
    endif()
    check_library_exists(nl-genl-3 genl_connect "" HAVE_LIBNL_GENL_3)
    if(HAVE_LIBNL_GENL_3)
        list(APPEND PCAP_LIBRARIES nl-genl-3)
    endif()
    check_library_exists(nl-3 nl_cache_alloc "" HAVE_LIBNL_3)
    if(HAVE_LIBNL_3)
        list(APPEND PCAP_LIBRARIES nl-3)
    endif()
    check_library_exists(dbus-1 dbus_malloc "" HAVE_LIBDBUS_1)
    if(HAVE_LIBDBUS_1)
        list(APPEND PCAP_LIBRARIES dbus-1)
    endif()
endif()

include(PcapChecks)
include(OptionalDeps)

if(HAVE_LIBBPF)
    list(APPEND TCPR_SYSTEM_LIBS bpf)
endif()
if(HAVE_LIBXDP)
    list(APPEND TCPR_SYSTEM_LIBS xdp)
endif()
if(HAVE_LIBURING)
    list(APPEND TCPR_SYSTEM_LIBS uring)
endif()

# Make sure we have a valid packet injection mechanism
if(NOT HAVE_BPF AND NOT HAVE_PCAP_INJECT AND NOT HAVE_PCAP_SENDPACKET
   AND NOT HAVE_LIBDNET AND NOT HAVE_PF_PACKET)
    message(FATAL_ERROR "Unable to find a supported method to send packets. "
            "Please upgrade your libpcap or enable libdnet")
endif()

# tcpbridge requires pcap_sendpacket() (and pcap_setnonblock() on BPF systems)
set(ENABLE_TCPBRIDGE "")
if(HAVE_PCAP_SENDPACKET)
    if(NOT HAVE_BPF OR HAVE_PCAP_SETNONBLOCK)
        set(ENABLE_TCPBRIDGE 1)
        message(STATUS "Building tcpbridge")
    else()
        message(WARNING "Unable to build tcpbridge.  Try installing latest libpcap!")
    endif()
endif()

# tcpliveplay requires linux
set(ENABLE_TCPLIVEPLAY "")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(ENABLE_TCPLIVEPLAY 1)
    message(STATUS "Building tcpliveplay")
else()
    message(STATUS "Unable to build tcpliveplay.  This tool is only enabled on linux environments.")
endif()

# OS X bug: pcap_findalldevs() can make the wifi NIC disassociate on old libpcap
set(ENABLE_PCAP_FINDALLDEVS 1)
if(APPLE AND NOT LIBPCAP_VERSION_096)
    set(ENABLE_PCAP_FINDALLDEVS "")
endif()

# ---------------------------------------------------------------------------
# Test NIC selection (--with-testnic/--with-testnic2)
# ---------------------------------------------------------------------------
if(WITH_TESTNIC)
    set(nic1 ${WITH_TESTNIC})
    set(nic2 ${WITH_TESTNIC})
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(nic1 eth0)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(nic1 en0)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        set(nic1 hme0)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        set(nic1 xl0)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(nic1 em0)
    else()
        set(nic1 %0)
    endif()
    set(nic2 ${nic1})
endif()
if(WITH_TESTNIC2)
    set(nic2 ${WITH_TESTNIC2})
endif()
message(STATUS "Using ${nic1} for 1st test network interface card")
message(STATUS "Using ${nic2} for 2nd test network interface card")

# ---------------------------------------------------------------------------
# config.h / defines.h / test config generation
# ---------------------------------------------------------------------------
set(PACKAGE "\"tcpreplay\"")
set(PACKAGE_NAME "\"tcpreplay\"")
set(PACKAGE_TARNAME "\"tcpreplay\"")
set(PACKAGE_VERSION "\"${TCPREPLAY_VERSION}\"")
set(PACKAGE_STRING "\"tcpreplay ${TCPREPLAY_VERSION}\"")
set(PACKAGE_BUGREPORT "\"https://github.com/appneta/tcpreplay/issues\"")
set(PACKAGE_URL "\"http://tcpreplay.sourceforge.net/\"")
set(VERSION "\"${TCPREPLAY_VERSION}\"")
if(TCPDUMP_PATH)
    set(TCPDUMP_BINARY "\"${TCPDUMP_PATH}\"")
endif()
if(LIBDNET_VERSION_STR)
    set(LIBDNET_VERSION "\"${LIBDNET_VERSION_STR}\"")
else()
    set(LIBDNET_VERSION "\"\"")
endif()
if(PCAPNAV_VERSION)
    set(PCAPNAV_VERSION "\"${PCAPNAV_VERSION}\"")
endif()

configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.cmake
               ${CMAKE_BINARY_DIR}/src/config.h @ONLY)

# defines.h — reuses the same template as autotools (src/defines.h.in)
set(LPCAPINC ${PCAP_INCLUDE_FILE})
if(NOT INCLUDE_PCAP_BPF_HEADER)
    # dead-guarded include in defines.h.in; keep the substitution valid
    set(INCLUDE_PCAP_BPF_HEADER pcap-bpf.h)
else()
    set(INCLUDE_PCAP_BPF_HEADER ${PCAP_BPF_H_FILE})
endif()
configure_file(${CMAKE_SOURCE_DIR}/src/defines.h.in
               ${CMAKE_BINARY_DIR}/src/defines.h @ONLY)

# test/config — so `cd test && sudo make test` fixtures can also be used
set(srcdir ${CMAKE_SOURCE_DIR}/test)
configure_file(${CMAKE_SOURCE_DIR}/test/config.in
               ${CMAKE_BINARY_DIR}/test/config @ONLY)

add_compile_definitions(HAVE_CONFIG_H)

# Common include order: generated headers first, then the source tree
set(TCPR_GENERATED_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/src ${CMAKE_BINARY_DIR})
set(TCPR_SOURCE_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR})
set(LIBOPTS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/libopts)

add_subdirectory(lib)
add_subdirectory(libopts)
add_subdirectory(src)

# ---------------------------------------------------------------------------
# Configuration summary (mirrors the configure.ac results banner)
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "##########################################################################")
message(STATUS "             TCPREPLAY Suite Configuration Results (${TCPREPLAY_VERSION})")
message(STATUS "##########################################################################")
message(STATUS "libpcap:                    ${PCAP_INCLUDE_FILE} (${LIBPCAP_VERSION})")
message(STATUS "PF_RING libpcap:            ${PF_RING_FOUND} ${WITH_PFRING_LIB}")
message(STATUS "libdnet:                    ${HAVE_LIBDNET} ${LIBDNET_VERSION_STR}")
message(STATUS "autogen:                    ${AUTOGEN_EXECUTABLE} (${AUTOGEN_VERSION})")
message(STATUS "64bit counter support:      ${ENABLE_64BITS}")
message(STATUS "tcpdump binary path:        ${TCPDUMP_PATH}")
message(STATUS "fragroute support:          ${ENABLE_FRAGROUTE}")
message(STATUS "tcpbridge support:          ${ENABLE_TCPBRIDGE}")
message(STATUS "tcpliveplay support:        ${ENABLE_TCPLIVEPLAY}")
message(STATUS "")
message(STATUS "Supported Packet Injection Methods (*):")
message(STATUS "Linux TX_RING:              ${HAVE_TX_RING}")
message(STATUS "Linux PF_PACKET:            ${HAVE_PF_PACKET}")
message(STATUS "BSD BPF:                    ${HAVE_BPF}")
message(STATUS "libdnet:                    ${HAVE_LIBDNET}")
message(STATUS "pcap_inject:                ${HAVE_PCAP_INJECT}")
message(STATUS "pcap_sendpacket:            ${HAVE_PCAP_SENDPACKET} **")
message(STATUS "pcap_netmap:                ${HAVE_LIBPCAP_NETMAP}")
message(STATUS "Linux/BSD netmap:           ${HAVE_NETMAP} ${NETMAP_INCLUDE_DIR}")
message(STATUS "Tuntap device support:      ${HAVE_TUNTAP}")
message(STATUS "LIBXDP for AF_XDP socket:   ${HAVE_LIBXDP}")
message(STATUS "liburing for io_uring:      ${HAVE_LIBURING}")
message(STATUS "")
message(STATUS "* In order of preference; see options in CMakeLists.txt to override")
message(STATUS "** Required for tcpbridge")
message(STATUS "")
