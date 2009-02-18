CMAKE_MINIMUM_REQUIRED(VERSION 2.6) 
PROJECT (TCPREPLAY) 

INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFile)
INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckTypeSize)
INCLUDE(FindCygwin)
INCLUDE(FindSubversion)

#packaging
SET(CPACK_PACKAGE_NAME tcpreplay)
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Pcap editing and replay tools for Unix & Windows")
SET(CPACK_PACKAGE_VENDOR "tcpreplay")
# SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
# SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/docs/LICENSE")
SET(CPACK_PACKAGE_VERSION_MAJOR "4")
SET(CPACK_PACKAGE_VERSION_MINOR "0")
SET(CPACK_PACKAGE_VERSION_PATCH "0alpha")
SET(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
SET(VERSION ${CPACK_PACKAGE_VERSION})
SET(CPACK_CMAKE_GENERATOR "Unix Makefiles")
SET(CPACK_GENERATOR "TGZ")
SET(CPACK_SOURCE_GENERATOR "TGZ")
INCLUDE(Cpack)


SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "/usr/local")
SET(CPACK_GENERATOR "TGZ")
SET(CPACK_SOURCE_GENERATOR "TGZ")

CHECK_FUNCTION_EXISTS(strlcpy SYSTEM_STRLCPY)
IF(NOT SYSTEM_STRLCPY)
    ADD_SUBDIRECTORY(lib)
    INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib)
ENDIF(NOT SYSTEM_STRLCPY)


FIND_PROGRAM(ECHO echo)
FIND_PROGRAM(SVNVERSION svnversion)
FIND_PROGRAM(MAKE make)
FIND_PROGRAM(AUTOGEN autogen)
FIND_PROGRAM(TCPDUMP_BINARY tcpdump)
FIND_PROGRAM(AUTOMAKE automake)
FIND_PROGRAM(AUTOCONF autoconf)

# Where to find local cmake scripts
SET(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

SET(USE_AUTOOPTS ON)
# IF(WIN32 AND NOT CYGWIN)
#     SET(USE_AUTOOPTS OFF)
#     message(STATUS "Disabling autoopts on Win32 platform")
# ENDIF(WIN32 AND NOT CYGWIN)

OPTION(ENABLE_DEBUG "Enable debug support" OFF)
OPTION(FORCE_INJECT_PF "Force using Linux's PF_PACKET API to send frames" OFF)
OPTION(FORCE_INJECT_BPF "Force using *BSD's BPF API to send frames" OFF)
OPTION(FORCE_INJECT_LIBDNET "Force using libdnet to send frames" OFF)
OPTION(FORCE_INJECT_PCAP_INJECT "Force using libpcap pcap_inject() to send frames" OFF)
OPTION(FORCE_INJECT_PCAP_SENDPACKET "Force using winpcap/libpcap's pcap_sendpacket() to send frames" OFF)
OPTION(USE_AUTOOPTS "Compile with GNU AutoOpts support (enables CLI tools)" ${USE_AUTOOPTS})
OPTION(ENABLE_64BITS "Enable 64bit packet counters" ON)
OPTION(TCPDUMP_BINARY "Set the path to tcpdump binary" "/usr/sbin/tcpdump")

MARK_AS_ADVANCED(FORCE_INJECT_PF FORCE_INJECT_BPF FORCE_INJECT_LIBDNET 
    FORCE_INJECT_PCAP_INJECT FORCE_INJECT_PCAP_SENDPACKET AUTOCONF AUTOGEN AUTOMAKE
    CMAKE_BUILD_TYPE ECHO SVNVERSION MAKE TCPDUMP_BINARY ENABLE_64BITS
    USE_AUTOOPTS)

IF(ENABLE_DEBUG)
    ADD_DEFINITIONS("-DDEBUG -ggdb")
ENDIF(ENABLE_DEBUG)

SET(ENABLE_VERBOSE "")
IF(EXISTS ${TCPDUMP_BINARY})
    IF(NOT WIN32)
        message(STATUS "Enabling tcpreplay verbose mode using ${TCPDUMP_BINARY}")
        SET(ENABLE_VERBOSE 1)
    ENDIF(NOT WIN32)
ENDIF(EXISTS ${TCPDUMP_BINARY})




# Most of the stuff below is stolen from Wireshark which released this under GPLv2 & BSD
SET(gcc_extras -std=gnu99)
CHECK_C_COMPILER_FLAG(-Wextra GCC_EXTRA)
IF(GCC_EXTRA)
    SET(gcc_extras ${gcc_extras} -Wextra)
ELSE(GCC_EXTRA)
    CHECK_C_COMPILER_FLAG(-W GCC_EXTRA_OLD)
    IF(GCC_EXTRA_OLD)
        SET(gcc_extras ${gcc_extras} -W)
    ENDIF(GCC_EXTRA_OLD)
ENDIF(GCC_EXTRA)

CHECK_C_COMPILER_FLAG(-Wfatal-errors GCC_FATAL_ERRORS)
IF(GCC_FATAL_ERRORS)
    SET(gcc_extras ${gcc_extras} -Wfatal-errors)
ENDIF(GCC_FATAL_ERRORS)

CHECK_C_COMPILER_FLAG(-Wno-variadic-macros GCC_NO_VARIADIC_MACROS)
IF(GCC_NO_VARIADIC_MACROS)
    SET(gcc_extras ${gcc_extras} -Wno-variadic-macros)
ENDIF(GCC_NO_VARIADIC_MACROS)

IF(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(
    -DHAVE_CONFIG_H
    \"-D_U_=__attribute__\(\(unused\)\)\"
    -Wall -Wpointer-arith -std=gnu99 ${gcc_extras}
  )
ELSE(CMAKE_COMPILER_IS_GNUCC)
  add_definitions(-DHAVE_CONFIG_H -D_U_=\"\")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

# Build for x64?
CHECK_C_COMPILER_FLAG(-m64 SUPPORTS_64BIT_FLAG)
IF(SUPPORTS_64BIT_FLAG)
    # Actually make sure the code runs!
    SET(CMAKE_REQUIRED_FLAGS_SAVE ${CMAKE_REQUIRED_FLAGS})
    SET(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS} -m64)
    CHECK_C_SOURCE_RUNS("
#include <stdlib.h>
int
main(int argc, char *argv[])
{
    printf(\"Hello world!\\\\n\");
    return 0;
}
"
        CAN_EXECUTE_M64_FLAG_CODE)

    SET(CMAKE_REQUIRED_FLAGS ${CMAKE_REQUIRED_FLAGS_SAVE})
        
    IF(CAN_EXECUTE_M64_FLAG_CODE EQUAL 1)
        message(STATUS "Building 64bit binaries via CFLAGS=-m64")
        SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -m64)
        SET(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} -m64)
        SET(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} -m64)
        SET(CMAKE_MODULE_LINKER_FLAGS ${CMAKE_MODULE_LINKER_FLAGS} -m64)
        SET(CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} -m64)
    ENDIF(CAN_EXECUTE_M64_FLAG_CODE EQUAL 1)
ENDIF(SUPPORTS_64BIT_FLAG)

# check for big endian
#Big or little endian ?
INCLUDE(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

INCLUDE(FindPCAP)
IF(NOT HAVE_PCAP_SENDPACKET)
    MESSAGE(STATUS "libpcap does not have pcap_sendpacket(): skipping tcpbridge")
ENDIF(NOT HAVE_PCAP_SENDPACKET)

INCLUDE(FindDNET)
SET(ENABLE_FRAGROUTE 0)
IF(HAVE_LIBDNET)
    SET(ENABLE_FRAGROUTE 1)
ENDIF(HAVE_LIBDNET)
INCLUDE(CheckBPF)
INCLUDE(CheckPFPacket)

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

# look for types
CHECK_TYPE_SIZE(uint8_t UINT8_T)
CHECK_TYPE_SIZE(uint16_t UINT16_T)
CHECK_TYPE_SIZE(uint32_t UINT32_T)
CHECK_TYPE_SIZE(uint64_t UINT64_T)

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

# is system strictly aligned?
INCLUDE(CheckStrictAlign)

#64 Bit format
INCLUDE(Check64BitFormat)

check_64bit_format(ll FORMAT_64BIT)
check_64bit_format(L FORMAT_64BIT)
check_64bit_format(q FORMAT_64BIT)
check_64bit_format(I64 FORMAT_64BIT)

IF(NOT FORMAT_64BIT)
    MESSAGE(FATAL " 64 bit format missing")
ENDIF(NOT FORMAT_64BIT)

SET(PRIX64 "${FORMAT_64BIT}X")
SET(PRIx64 "${FORMAT_64BIT}x")
SET(PRId64 "${FORMAT_64BIT}d")
SET(PRIo64 "${FORMAT_64BIT}o")
SET(PRIu64 "${FORMAT_64BIT}u")

# OS X has absolute time
IF(APPLE)
    SET(HAVE_ABSOLUTE_TIME 1)
ENDIF(APPLE)

INCLUDE(FindDoxygen)
INCLUDE(FindUnixCommands)


IF(USE_AUTOOPTS)
    message(STATUS "Configuring libopts tearoff...")
    INCLUDE(CheckLibopts)
    CHECK_LIBOPTS_TEAROFF(${CMAKE_SOURCE_DIR}/libopts 5.9.7)
ELSE(USE_AUTOOPTS)
    message(STATUS "Skipping libopts tearoff")
ENDIF(USE_AUTOOPTS)

CONFIGURE_FILE(src/config.h.cmake src/config.h @ONLY)
CONFIGURE_FILE(src/defines.h.in src/defines.h @ONLY)
CONFIGURE_FILE(doxygen.cfg.in doxygen.cfg @ONLY)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIRS})

IF(Subversion_FOUND)
    Subversion_WC_INFO(${CMAKE_SOURCE_DIR} SVN_INFO)
    IF(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
        # Targets to build src/common/svn_version.c
        ADD_CUSTOM_TARGET(version ALL
            COMMAND rm -f ${CMAKE_SOURCE_DIR}/src/common/svn_version.c
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/common
            DEPENDS ${CMAKE_SOURCE_DIR}/src/common/svn_version.c
        )
        ADD_DEPENDENCIES(version svn_version)
    ENDIF(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
ENDIF(Subversion_FOUND)

# Recurse into the subdirectories. This does not actually 
# cause another cmake executable to run. The same process will walk through 
# the project's entire directory structure. 
ADD_SUBDIRECTORY(src)
# ADD_SUBDIRECTORY (docs)
# ADD_SUBDIRECTORY (test)
