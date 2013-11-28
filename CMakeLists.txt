cmake_minimum_required(VERSION 2.6) 
project(TCPREPLAY) 

include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckCCompilerFlag)
include(CheckSymbolExists)
include(CheckTypeSize)
include(FindCygwin)
include(FindGit)
include(CheckCSourceRuns)
include(CMakeFindFrameworks)

# Where to find local cmake scripts
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake-modules")


#packaging
set(CPACK_PACKAGE_NAME tcpreplay)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Pcap editing and replay tools for Unix & Windows")
set(CPACK_PACKAGE_VENDOR "tcpreplay")
# set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
# set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/docs/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "4")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0alpha1")
set(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
set(VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES
    /CMakeFiles/
    /.svn/
    /docs/web/
    /.deps/
    CMakeCache.txt
    cmake_install.cmake
    .gdb_history
    .*.a$
    .*.o$
    .*~$
    .tmproj
    Makefile
    doxygen.cfg$
    /src/tcpreplay$
    /src/tcpreplay-edit$
    /src/tcprewrite$
    /src/tcpprep$
    /src/tcpbridge$
    /test/Standard.cmake$
    .*tar.gz$
    /_CPack_Packages/
    CPackSourceConfig.cmake$
    CPackConfig.cmake$
)
include(CPack)

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr/local")
set(CPACK_GENERATOR "TGZ")
set(CPACK_SOURCE_GENERATOR "TGZ")


find_program(ECHO echo)
find_program(DIFF diff)
find_program(TCPDUMP_BINARY tcpdump)
find_program(CTAGS ctags)
find_program(ETAGS etags)
find_program(GROFF groff)

set(USE_AUTOOPTS YES)
if(WIN32 AND NOT CYGWIN)
    set(USE_AUTOOPTS NO)
    message(STATUS "Disabling GNU AutoOpts on Win32 platform")
endif(WIN32 AND NOT CYGWIN)

option(ENABLE_DEBUG "Enable debug support" NO)
option(FORCE_INJECT_PF "Force using Linux's PF_PACKET API to send frames" NO)
option(FORCE_INJECT_BPF "Force using *BSD's BPF API to send frames" NO)
option(FORCE_INJECT_LIBDNET "Force using libdnet to send frames" NO)
option(FORCE_INJECT_PCAP_INJECT "Force using libpcap pcap_inject() to send frames" NO)
option(FORCE_INJECT_PCAP_SENDPACKET "Force using winpcap/libpcap's pcap_sendpacket() to send frames" NO)
option(FORCE_INJECT_NETMAP "Force using netmap to send frames" NO)
option(USE_AUTOOPTS "Compile with GNU AutoOpts support (enables CLI tools)" ${USE_AUTOOPTS})
option(ENABLE_64BITS "Enable 64bit packet counters" YES)
option(BUILD_64BIT_BINARY "Build a 64bit binary")
option(BUILD_QT_GUI "Build QT4 GUI version of tcpreplay tools" NO)
mark_as_advanced(FORCE_INJECT_PF FORCE_INJECT_BPF FORCE_INJECT_LIBDNET FORCE_INJECT_NETMAP
    FORCE_INJECT_PCAP_INJECT FORCE_INJECT_PCAP_SENDPACKET AUTOCONF AUTOGEN AUTOMAKE
    CMAKE_BUILD_TYPE ECHO MAKE TCPDUMP_BINARY ENABLE_64BITS
    USE_AUTOOPTS LIBPCAP_DIR LIBDNET_DIR)

if(ENABLE_DEBUG)
    set(__GGDB -g)
    CHECK_C_COMPILER_FLAG(-ggdb GCC_GDB)
    if(GCC_GDB)
        set(__GGDB -ggdb)
    endif(GCC_GDB)
    add_definitions("-DDEBUG ${__GGDB}")
endif(ENABLE_DEBUG)

add_definitions(-D_GNU_SOURCE)
add_definitions(-D__USE_BSD)

set(ENABLE_VERBOSE "")
if(EXISTS ${TCPDUMP_BINARY})
    if(NOT WIN32)
        message(STATUS "Enabling tcpreplay verbose mode using ${TCPDUMP_BINARY}")
        set(ENABLE_VERBOSE 1)
    endif(NOT WIN32)
endif(EXISTS ${TCPDUMP_BINARY})

# Required to help decide how to divide 64 bit integers
check_type_size(long LONG_SIZE BUILTIN_TYPES_ONLY)


# Most of the stuff below is stolen from Wireshark which released this under GPLv2 & BSD
set(gcc_extras "")
check_c_compiler_flag(-std=gnu99 GCC_GNU99)
if(GCC_GNU99)
    set(gcc_extras -std=gnu99)
else(GCC_GNU99)
    check_c_compiler_flag(-std=c99 GCC_C99)
    if(GCC_C99)
        set(gcc_extras -std=c99)
    endif(GCC_C99)
endif(GCC_GNU99)

check_c_compiler_flag(-Wextra GCC_EXTRA)
if(GCC_EXTRA)
    set(gcc_extras ${gcc_extras} -Wextra)
else(GCC_EXTRA)
    check_c_compiler_flag(-W GCC_EXTRA_OLD)
    if(GCC_EXTRA_OLD)
        set(gcc_extras ${gcc_extras} -W)
    endif(GCC_EXTRA_OLD)
endif(GCC_EXTRA)

check_c_compiler_flag(-Wfatal-errors GCC_FATAL_ERRORS)
if(GCC_FATAL_ERRORS)
    set(gcc_extras ${gcc_extras} -Wfatal-errors)
endif(GCC_FATAL_ERRORS)

check_c_compiler_flag(-Wno-variadic-macros GCC_NO_VARIADIC_MACROS)
if(GCC_NO_VARIADIC_MACROS)
    set(gcc_extras ${gcc_extras} -Wno-variadic-macros)
endif(GCC_NO_VARIADIC_MACROS)

if(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(
    -DHAVE_CONFIG_H
    \"-D_U_=__attribute__\(\(unused\)\)\"
    -Wall -Wpointer-arith -std=gnu99 ${gcc_extras}
  )
else(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(-DHAVE_CONFIG_H -D_U_=)
endif(CMAKE_COMPILER_IS_GNUCC)

# Build for x64?.
if(BUILD_64BIT_BINARY)
check_c_compiler_flag(-m64 SUPPORTS_64BIT_FLAG)
if(SUPPORTS_64BIT_FLAG)
    # Actually make sure the code runs!
    set(CMAKE_REQUIRED_FLAGS_SAVE ${CMAKE_REQUIRED_FLAGS})
    set(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS} -m64)
    check_c_source_runs("
#include <stdlib.h>
int
main(int argc, char *argv[])
{
    printf(\"Hello world!\\\\n\");
    return 0;
}
"
        CAN_EXECUTE_M64_FLAG_CODE)

    set(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS_SAVE})

    if(CAN_EXECUTE_M64_FLAG_CODE EQUAL 1)
        message(STATUS "Building 64bit binaries via CFLAGS=-m64")
        set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -m64)
        set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -m64)
        set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -m64)
        set(CMAKE_MODULE_LINKER_FLAGS ${CMAKE_MODULE_LINKER_FLAGS} -m64)
        set(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} -m64)
    endif(CAN_EXECUTE_M64_FLAG_CODE EQUAL 1)
endif(SUPPORTS_64BIT_FLAG)
endif(BUILD_64BIT_BINARY)

# Big or little endian ?
if(WIN32)
    # Windows is always little endian
    set(WORDS_BIGENDIAN FALSE)
else(WIN32)
    include(TestBigEndian)
    test_big_endian(WORDS_BIGENDIAN)
endif(WIN32)

include(FindPCAP)
set(ENABLE_TCPBRIDGE NO)
if(NOT HAVE_PCAP_SENDPACKET)
    message(STATUS "libpcap does not have pcap_sendpacket(): skipping tcpbridge")
else(NOT HAVE_PCAP_SENDPACKET)
    message(STATUS "We will build tcpbridge")
    set(ENABLE_TCPBRIDGE YES)
endif(NOT HAVE_PCAP_SENDPACKET)

include(FindEvent)

include(FindDNET)
set(ENABLE_FRAGROUTE NO)
if(HAVE_LIBDNET)
    set(ENABLE_FRAGROUTE YES)
    set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} ${DNET_CFLAGS})
    set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} ${DNET_CFLAGS})
endif(HAVE_LIBDNET)
include(CheckBPF)
include(CheckPFPacket)
include(CheckTxRing)
include(FindNetmap)

if(NOT HAVE_LIBPCAP AND NOT HAVE_BPF AND NOT HAVE_LIBDNET AND NOT HAVE_PF_PACKET AND NOT HAVE_NETMAP)
    message(FATAL_ERROR "You must have libpcap, libdnet, /dev/bpf PF_PACKET socket or netmap support")
endif(NOT HAVE_LIBPCAP AND NOT HAVE_BPF AND NOT HAVE_LIBDNET AND NOT HAVE_PF_PACKET AND NOT HAVE_NETMAP)

#check system for includes
check_include_file("arpa/inet.h"         HAVE_ARPA_INET_H)
check_include_file("arpa/nameser.h"      HAVE_ARPA_NAMESER_H)
check_include_file("bool.h"              HAVE_BOOL_H)
check_include_file("direct.h"            HAVE_DIRECT_H)
check_include_file("dirent.h"            HAVE_DIRENT_H)
check_include_file("dlfcn.h"             HAVE_DLFCN_H)
check_include_file("fcntl.h"             HAVE_FCNTL_H)
check_include_file("getopt.h"            NEED_GETOPT_H)
check_include_file("g_ascii_strtoull.h"  NEED_G_ASCII_STRTOULL_H)
check_include_file("inet/aton.h"         NEED_INET_ATON_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("lauxlib.h"           HAVE_LAUXLIB_H)
check_include_file("memory.h"            HAVE_MEMORY_H)
check_include_file("netinet/in.h"        HAVE_NETINET_IN_H)
check_include_file("netdb.h"             HAVE_NETDB_H)
check_include_file("portaudio.h"         HAVE_PORTAUDIO_H)
check_include_file("poll.h"              HAVE_POLL_H)
check_include_file("signal.h"            HAVE_SIGNAL_H)
check_include_file("stdarg.h"            HAVE_STDARG_H)
check_include_file("stdbool.h"           HAVE_STDBOOL_H)
check_include_file("stddef.h"            HAVE_STDDEF_H)
check_include_file("stdint.h"            HAVE_STDINT_H)
check_include_file("stdlib.h"            HAVE_STDLIB_H)
check_include_file("strerror.h"          NEED_STRERROR_H)
check_include_file("strings.h"           HAVE_STRINGS_H)
check_include_file("string.h"            HAVE_STRING_H)
check_include_file("sys/ioctl.h"         HAVE_SYS_IOCTL_H)
check_include_file("sys/param.h"         HAVE_SYS_PARAM_H)
check_include_file("sys/socket.h"        HAVE_SYS_SOCKET_H)
check_include_file("sys/sockio.h"        HAVE_SYS_SOCKIO_H)
check_include_file("sys/stat.h"          HAVE_SYS_STAT_H)
check_include_file("sys/time.h"          HAVE_SYS_TIME_H)
check_include_file("sys/types.h"         HAVE_SYS_TYPES_H)
check_include_file("sys/utsname.h"       HAVE_SYS_UTSNAME_H)
check_include_file("sys/wait.h"          HAVE_SYS_WAIT_H)
check_include_file("unistd.h"            HAVE_UNISTD_H)
check_include_file("inttypes.h"          HAVE_INTTYPES_H)
check_include_file("time.h"              HAVE_TIME_H)
check_include_file("netinet/in_systm.h"  HAVE_NETINET_IN_SYSTM_H)

# look for types
check_type_size(uint8_t UINT8_T)
check_type_size(uint16_t UINT16_T)
check_type_size(uint32_t UINT32_T)
check_type_size(uint64_t UINT64_T)

# Functions
check_function_exists("chown"            HAVE_CHOWN)
check_function_exists("gethostbyname2"   HAVE_GETHOSTBYNAME2)
check_function_exists("getprotobynumber" HAVE_GETPROTOBYNUMBER)
check_function_exists("inet_ntop"        HAVE_INET_NTOP)
check_function_exists("inet_aton"        HAVE_INET_ATON)
check_function_exists("inet_pton"        HAVE_INET_PTON)
check_function_exists("inet_addr"        HAVE_INET_ADDR)
check_function_exists("issetugid"        HAVE_ISSETUGID) 
check_function_exists("mmap"             HAVE_MMAP)
check_function_exists("mprotect"         HAVE_MPROTECT)
check_function_exists("sysconf"          HAVE_SYSCONF)
check_function_exists("poll"             HAVE_POLL)
check_function_exists("strlcat"          HAVE_STRLCAT)
check_function_exists("strlcpy"          HAVE_SYSTEM_STRLCPY)

if(NOT HAVE_SYSTEM_STRLCPY)
    add_subdirectory(lib)
    include_directories(${CMAKE_SOURCE_DIR}/lib)
endif(NOT HAVE_SYSTEM_STRLCPY)

# is system strictly aligned?
include(CheckStrictAlign)

#64 Bit format
include(Check64BitFormat)

check_64bit_format(ll FORMAT_64BIT)
check_64bit_format(L FORMAT_64BIT)
check_64bit_format(q FORMAT_64BIT)
check_64bit_format(I64 FORMAT_64BIT)

if(NOT FORMAT_64BIT)
    message(FATAL " 64 bit format missing")
endif(NOT FORMAT_64BIT)

set(PRIX64 "${FORMAT_64BIT}X")
set(PRIx64 "${FORMAT_64BIT}x")
set(PRId64 "${FORMAT_64BIT}d")
set(PRIo64 "${FORMAT_64BIT}o")
set(PRIu64 "${FORMAT_64BIT}u")

# OS X has absolute time
#CMAKE_FIND_FRAMEWORKS(Carbon)
#CMAKE_FIND_FRAMEWORKS(CoreServices)
#if(CoreServices_FRAMEWORKS AND Carbon_FRAMEWORKS)
#    set(HAVE_ABSOLUTE_TIME 1)
#    message(STATUS "Enabling OS X's absolute_time()")
#endif(CoreServices_FRAMEWORKS AND Carbon_FRAMEWORKS)

include(FindDoxygen)
include(FindUnixCommands)


include(CheckAutogen)
if(USE_AUTOOPTS)
    message(STATUS "Configuring libopts tearoff...")
    include(CheckLibopts)
    CHECK_LIBOPTS_TEAROFF(${CMAKE_SOURCE_DIR}/libopts 5.9.7)
else(USE_AUTOOPTS)
    message(STATUS "Skipping libopts tearoff")
endif(USE_AUTOOPTS)

configure_file(src/config.h.cmake src/config.h @ONLY)
configure_file(src/defines.h.in src/defines.h @ONLY)
configure_file(doxygen.cfg.in doxygen.cfg @ONLY)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/src/tcpedit)
include_directories(${PCAP_INCLUDE_DIRS})
include_directories(${NETMAP_INCLUDE_DIRS}/sys)

# Recurse into the subdirectories. This does not actually 
# cause another cmake executable to run. The same process will walk through 
# the project's entire directory structure 
add_subdirectory(src)
add_subdirectory(docs)
add_subdirectory(test)

configure_file(${CMAKE_SOURCE_DIR}/cmake/BuildDistTgz.cmake.in ${CMAKE_BINARY_DIR}/cmake/BuildDistTgz.cmake)
add_custom_target(dist-gzip
   COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/cmake/BuildDistTgz.cmake
)

# Create ctags for vim, etc
add_custom_target(ctags
    COMMAND ${CTAGS} -R src lib libopts
)

# Create etags for emacs
add_custom_target(etags
    COMMAND ${ETAGS} -R src lib libopts
)

if(USE_AUTOOPTS)
    add_custom_target(clean_autogen
        COMMAND cmake -P ${CMAKE_SOURCE_DIR}/cmake/CleanAutogen.cmake
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        DEPENDS cmake/CleanAutogen.cmake
        VERBATIM)
endif(USE_AUTOOPTS)

# make doxygen
include("${CMAKE_MODULE_PATH}/TargetDoc.cmake" OPTIONAL)

# Clean up to be yes/no not 1/0
if(HAVE_PCAP_INJECT)
   set(HAVE_PCAP_INJECT YES)
else(HAVE_PCAP_INJECT)
   set(HAVE_PCAP_INJECT NO)
endif(HAVE_PCAP_INJECT)

if(HAVE_PCAP_SENDPACKET)
   set(HAVE_PCAP_SENDPACKET YES)
else(HAVE_PCAP_SENDPACKET)
   set(HAVE_PCAP_SENDPACKET NO)
endif(HAVE_PCAP_SENDPACKET)

if(HAVE_BPF)
    set(HAVE_BPF YES)
else(HAVE_BPF)
    set(HAVE_BPF NO)
endif(HAVE_BPF)

if(ENABLE_64BITS)
    set(ENABLE_64BITS YES)
else(ENABLE_64BITS)
    set(ENABLE_64BITS NO)
endif(ENABLE_64BITS)

string(COMPARE EQUAL AUTOGEN_VERSION LIBOPTS_VERSION AUTOGEN_VER_MATCH)
if(AUTOGEN_VER_MATCH)
    set(AUTOGEN_VER_MATCH "matches libopts tearoff")
else(AUTOGEN_VER_MATCH)
    set(AUTOGEN_VER_MATCH "warning! libopts tearoff is version ${LIBOPTS_VERSION}")
endif(AUTOGEN_VER_MATCH)

message(STATUS
"
##########################################################################
             TCPREPLAY Suite Configuration Results ${VERSION} ${REPO_VERSION}
##########################################################################
install location:           ${CPACK_PACKAGE_INSTALL_DIRECTORY}
libpcap:                    ${HAVE_LIBPCAP} ${PCAP_LIBRARIES}
libdnet:                    ${HAVE_LIBDNET} ${DNET_LIBS} (${LIBDNET_VERSION})
libevent:                   ${HAVE_LIBEVENT} ${EVENT_LIBRARIES}
autogen:                    ${AUTOGEN} (${AUTOGEN_VERSION}) ${AUTOGEN_VER_MATCH}
64bit counter support:      ${ENABLE_64BITS}
tcpdump binary path:        ${TCPDUMP_BINARY}
fragroute support:          ${ENABLE_FRAGROUTE}
tcpbridge support:          ${ENABLE_TCPBRIDGE}

Supported Packet Injection Methods (*):
Linux netmap:               ${HAVE_NETMAP} ${NETMAP_INCLUDE_DIRS}
Linux TX_RING:              ${HAVE_TX_RING}
Linux PF_PACKET:            ${HAVE_PF_PACKET}
BSD BPF:                    ${HAVE_BPF}
libdnet:                    ${HAVE_LIBDNET}
pcap_inject:                ${HAVE_PCAP_INJECT}
pcap_sendpacket:            ${HAVE_PCAP_SENDPACKET} **

* In order of preference; see configure --help to override
** Required for tcpbridge"
)

