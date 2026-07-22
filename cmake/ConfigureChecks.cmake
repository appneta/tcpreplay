# ConfigureChecks.cmake — mirrors the header/function/type/library detection in
# configure.ac (and libopts/m4/libopts.m4) for the CMake build (issue #688).
# Results populate the variables consumed by cmake/config.h.cmake.

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckTypeSize)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(TestBigEndian)

# ---------------------------------------------------------------------------
# Headers (AC_CHECK_HEADERS in configure.ac + libopts.m4)
# ---------------------------------------------------------------------------
macro(tcpr_check_header header var)
    check_include_file(${header} ${var})
    if(${var})
        set(${var} 1)
    endif()
endmacro()

tcpr_check_header(fcntl.h HAVE_FCNTL_H)
tcpr_check_header(stddef.h HAVE_STDDEF_H)
tcpr_check_header(sys/socket.h HAVE_SYS_SOCKET_H)
tcpr_check_header(arpa/inet.h HAVE_ARPA_INET_H)
tcpr_check_header(sys/time.h HAVE_SYS_TIME_H)
tcpr_check_header(signal.h HAVE_SIGNAL_H)
tcpr_check_header(string.h HAVE_STRING_H)
tcpr_check_header(strings.h HAVE_STRINGS_H)
tcpr_check_header(sys/types.h HAVE_SYS_TYPES_H)
tcpr_check_header(stdint.h HAVE_STDINT_H)
tcpr_check_header(sys/select.h HAVE_SYS_SELECT_H)
tcpr_check_header(netinet/in.h HAVE_NETINET_IN_H)
tcpr_check_header(netinet/in_systm.h HAVE_NETINET_IN_SYSTM_H)
tcpr_check_header(poll.h HAVE_POLL_H)
tcpr_check_header(sys/poll.h HAVE_SYS_POLL_H)
tcpr_check_header(unistd.h HAVE_UNISTD_H)
tcpr_check_header(sys/param.h HAVE_SYS_PARAM_H)
tcpr_check_header(inttypes.h HAVE_INTTYPES_H)
tcpr_check_header(libintl.h HAVE_LIBINTL_H)
tcpr_check_header(sys/file.h HAVE_SYS_FILE_H)
tcpr_check_header(sys/ioctl.h HAVE_SYS_IOCTL_H)
tcpr_check_header(sys/systeminfo.h HAVE_SYS_SYSTEMINFO_H)
tcpr_check_header(sys/io.h HAVE_SYS_IO_H)
tcpr_check_header(architecture/i386/pio.h HAVE_ARCHITECTURE_I386_PIO_H)
tcpr_check_header(sched.h HAVE_SCHED_H)
tcpr_check_header(fts.h HAVE_FTS_H)
tcpr_check_header(stdbool.h HAVE_STDBOOL_H)
tcpr_check_header(stdlib.h HAVE_STDLIB_H)
tcpr_check_header(stdio.h HAVE_STDIO_H)
tcpr_check_header(memory.h HAVE_MEMORY_H)
tcpr_check_header(errno.h HAVE_ERRNO_H)
tcpr_check_header(dirent.h HAVE_DIRENT_H)
tcpr_check_header(dlfcn.h HAVE_DLFCN_H)
tcpr_check_header(limits.h HAVE_LIMITS_H)
tcpr_check_header(sys/limits.h HAVE_SYS_LIMITS_H)
tcpr_check_header(values.h HAVE_VALUES_H)
tcpr_check_header(stdarg.h HAVE_STDARG_H)
tcpr_check_header(varargs.h HAVE_VARARGS_H)
tcpr_check_header(runetype.h HAVE_RUNETYPE_H)
tcpr_check_header(wchar.h HAVE_WCHAR_H)
tcpr_check_header(setjmp.h HAVE_SETJMP_H)
tcpr_check_header(sys/mman.h HAVE_SYS_MMAN_H)
tcpr_check_header(sys/stat.h HAVE_SYS_STAT_H)
tcpr_check_header(sys/wait.h HAVE_SYS_WAIT_H)
tcpr_check_header(sys/un.h HAVE_SYS_UN_H)
tcpr_check_header(sys/procset.h HAVE_SYS_PROCSET_H)
tcpr_check_header(sys/stropts.h HAVE_SYS_STROPTS_H)
tcpr_check_header(sysexits.h HAVE_SYSEXITS_H)
tcpr_check_header(utime.h HAVE_UTIME_H)
tcpr_check_header(libgen.h HAVE_LIBGEN_H)
tcpr_check_header(bpf/libbpf.h HAVE_BPF_LIBBPF_H)
tcpr_check_header(bpf/bpf.h HAVE_BPF_BPF_H)
tcpr_check_header(xdp/libxdp.h HAVE_XDP_LIBXDP_H)
tcpr_check_header(net/bpf.h HAVE_NET_BPF_H)

# OpenBSD needs sys/param.h et al. as prerequisites (configure.ac line ~365)
check_c_source_compiles("
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
int main(void) { return 0; }" HAVE_SYS_SYSCTL_H)
check_c_source_compiles("
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
int main(void) { return 0; }" HAVE_NET_ROUTE_H)

if(HAVE_NET_BPF_H)
    set(HAVE_BPF 1)
endif()

set(STDC_HEADERS 1)

# ---------------------------------------------------------------------------
# Types (AC_TYPE_*/AC_CHECK_TYPE)
# ---------------------------------------------------------------------------
set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h)
check_type_size(u_char U_CHAR)
check_type_size(u_short U_SHORT)
check_type_size(u_int U_INT)
check_type_size(u_int8_t U_INT8_T)
check_type_size(u_int16_t U_INT16_T)
check_type_size(u_int32_t U_INT32_T)
check_type_size(u_int64_t U_INT64_T)
set(CMAKE_EXTRA_INCLUDE_FILES)

# AC_CHECK_TYPE(foo, replacement): define replacement when the type is missing
if(NOT HAVE_U_CHAR)
    set(u_char uint8_t)
endif()
if(NOT HAVE_U_SHORT)
    set(u_short uint16_t)
endif()
if(NOT HAVE_U_INT)
    set(u_int uint32_t)
endif()
if(NOT HAVE_U_INT8_T)
    set(u_int8_t uint8_t)
endif()
if(NOT HAVE_U_INT16_T)
    set(u_int16_t uint16_t)
endif()
if(NOT HAVE_U_INT32_T)
    set(u_int32_t uint32_t)
endif()
if(NOT HAVE_U_INT64_T)
    set(u_int64_t uint64_t)
endif()

check_type_size("char *" SIZEOF_CHAR_P)
check_type_size(int SIZEOF_INT)
check_type_size(long SIZEOF_LONG)
check_type_size(short SIZEOF_SHORT)
check_type_size(pid_t PID_T)
if(HAVE_PID_T)
    set(HAVE_PID_T 1)
endif()
check_type_size(size_t SIZE_T)
if(HAVE_SIZE_T)
    set(HAVE_SIZE_T 1)
endif()
check_type_size(ssize_t SSIZE_T)
if(NOT HAVE_SSIZE_T)
    set(ssize_t int)
endif()
check_type_size(intptr_t INTPTR_T)
if(HAVE_INTPTR_T)
    set(HAVE_INTPTR_T 1)
endif()
check_type_size(uintptr_t UINTPTR_T)
if(HAVE_UINTPTR_T)
    set(HAVE_UINTPTR_T 1)
endif()
check_type_size(ptrdiff_t PTRDIFF_T)
if(HAVE_PTRDIFF_T)
    set(HAVE_PTRDIFF_T 1)
endif()
set(CMAKE_EXTRA_INCLUDE_FILES wchar.h)
check_type_size(wchar_t WCHAR_T)
if(HAVE_WCHAR_T)
    set(HAVE_WCHAR_T 1)
endif()
check_type_size(wint_t WINT_T)
if(HAVE_WINT_T)
    set(HAVE_WINT_T 1)
endif()
set(CMAKE_EXTRA_INCLUDE_FILES)
check_type_size(int8_t INT8_T)
set(HAVE_INT8_T ${HAVE_INT8_T})
check_type_size(int16_t INT16_T)
check_type_size(int32_t INT32_T)
check_type_size(int64_t INT64_T)
check_type_size(uint8_t UINT8_T)
check_type_size(uint16_t UINT16_T)
check_type_size(uint32_t UINT32_T)
check_type_size(uint64_t UINT64_T)
check_type_size(_Bool _BOOL)
if(HAVE__BOOL)
    set(HAVE__BOOL 1)
endif()

check_c_source_compiles("
#include <sys/time.h>
int main(void) { struct timeval tv; tv.tv_sec = 0; return (int)tv.tv_sec; }
" HAVE_STRUCT_TIMEVAL_TV_SEC)

# ---------------------------------------------------------------------------
# Endianness
# ---------------------------------------------------------------------------
test_big_endian(WORDS_BIGENDIAN_RESULT)
if(WORDS_BIGENDIAN_RESULT)
    set(WORDS_BIGENDIAN 1)
endif()

# ---------------------------------------------------------------------------
# Support libraries (AC_CHECK_LIB socket/nsl/rt/resolv/bsd/network)
# ---------------------------------------------------------------------------
set(TCPR_SYSTEM_LIBS "")
check_library_exists(socket socket "" HAVE_LIBSOCKET)
if(HAVE_LIBSOCKET)
    list(APPEND TCPR_SYSTEM_LIBS socket)
endif()
check_library_exists(nsl gethostbyname "" HAVE_LIBNSL)
if(HAVE_LIBNSL)
    list(APPEND TCPR_SYSTEM_LIBS nsl)
endif()
check_library_exists(rt nanosleep "" HAVE_LIBRT)
if(HAVE_LIBRT)
    list(APPEND TCPR_SYSTEM_LIBS rt)
endif()
check_library_exists(resolv resolv "" HAVE_LIBRESOLV)
if(HAVE_LIBRESOLV)
    list(APPEND TCPR_SYSTEM_LIBS resolv)
endif()

# ---------------------------------------------------------------------------
# Functions (AC_CHECK_FUNCS + libopts.m4)
# ---------------------------------------------------------------------------
macro(tcpr_check_function func var)
    check_function_exists(${func} ${var})
    if(${var})
        set(${var} 1)
    endif()
endmacro()

tcpr_check_function(alarm HAVE_ALARM)
tcpr_check_function(atexit HAVE_ATEXIT)
tcpr_check_function(bzero HAVE_BZERO)
tcpr_check_function(dup2 HAVE_DUP2)
tcpr_check_function(gethostbyname HAVE_GETHOSTBYNAME)
tcpr_check_function(getpagesize HAVE_GETPAGESIZE)
tcpr_check_function(gettimeofday HAVE_GETTIMEOFDAY)
tcpr_check_function(ctime HAVE_CTIME)
tcpr_check_function(inet_ntoa HAVE_INET_NTOA)
tcpr_check_function(memmove HAVE_MEMMOVE)
tcpr_check_function(memset HAVE_MEMSET)
tcpr_check_function(munmap HAVE_MUNMAP)
tcpr_check_function(mmap HAVE_MMAP)
tcpr_check_function(pow HAVE_POW)
tcpr_check_function(putenv HAVE_PUTENV)
tcpr_check_function(realpath HAVE_REALPATH)
tcpr_check_function(regcomp HAVE_REGCOMP)
tcpr_check_function(strdup HAVE_STRDUP)
tcpr_check_function(select HAVE_SELECT)
tcpr_check_function(socket HAVE_SOCKET)
tcpr_check_function(strcasecmp HAVE_STRCASECMP)
tcpr_check_function(strchr HAVE_STRCHR)
tcpr_check_function(strcspn HAVE_STRCSPN)
tcpr_check_function(strerror HAVE_STRERROR)
tcpr_check_function(strtol HAVE_STRTOL)
tcpr_check_function(strncpy HAVE_STRNCPY)
tcpr_check_function(strtoull HAVE_STRTOULL)
tcpr_check_function(poll HAVE_POLL)
tcpr_check_function(ntohll HAVE_NTOHLL)
tcpr_check_function(snprintf HAVE_SNPRINTF)
tcpr_check_function(vsnprintf HAVE_VSNPRINTF)
tcpr_check_function(strsignal HAVE_STRSIGNAL)
tcpr_check_function(strpbrk HAVE_STRPBRK)
tcpr_check_function(strrchr HAVE_STRRCHR)
tcpr_check_function(strspn HAVE_STRSPN)
tcpr_check_function(strstr HAVE_STRSTR)
tcpr_check_function(strtoul HAVE_STRTOUL)
tcpr_check_function(ioperm HAVE_IOPERM)
tcpr_check_function(vprintf HAVE_VPRINTF)
tcpr_check_function(strftime HAVE_STRFTIME)
tcpr_check_function(canonicalize_file_name HAVE_CANONICALIZE_FILE_NAME)
tcpr_check_function(pathfind HAVE_PATHFIND)
tcpr_check_function(fseeko HAVE_FSEEKO)
tcpr_check_function(chmod HAVE_CHMOD)
tcpr_check_function(fchmod HAVE_FCHMOD)
tcpr_check_function(fstat HAVE_FSTAT)
tcpr_check_function(fork HAVE_FORK)
tcpr_check_function(vfork HAVE_VFORK)
if(HAVE_FORK)
    set(HAVE_WORKING_FORK 1)
endif()
if(HAVE_VFORK)
    set(HAVE_WORKING_VFORK 1)
else()
    set(vfork fork)
endif()
set(LSTAT_FOLLOWS_SLASHED_SYMLINK 1)

# strlcpy: some BSDs (and macOS) have it in libc
tcpr_check_function(strlcpy HAVE_STRLCPY)

# inet_aton/inet_pton/inet_ntop/inet_addr — on Haiku these live in libnetwork
tcpr_check_function(inet_aton HAVE_INET_ATON)
tcpr_check_function(inet_pton HAVE_INET_PTON)
tcpr_check_function(inet_ntop HAVE_INET_NTOP)
tcpr_check_function(inet_addr HAVE_INET_ADDR)
if(NOT HAVE_INET_ATON OR NOT HAVE_INET_PTON OR NOT HAVE_INET_NTOP)
    check_library_exists(network inet_aton "" HAVE_LIBNETWORK)
    if(HAVE_LIBNETWORK)
        set(HAVE_INET_ATON 1)
        set(HAVE_INET_PTON 1)
        set(HAVE_INET_NTOP 1)
        list(APPEND TCPR_SYSTEM_LIBS network)
    endif()
endif()
if(NOT HAVE_INET_NTOP AND NOT HAVE_INET_PTON)
    message(FATAL_ERROR "We need either inet_ntop or inet_pton")
endif()
if(NOT HAVE_INET_ADDR)
    message(FATAL_ERROR "We need inet_addr.  See bug 26")
endif()

# Haiku: fts_*() lives in libbsd
check_function_exists(fts_read HAVE_FTS_READ)
if(NOT HAVE_FTS_READ)
    check_library_exists(bsd fts_read "" HAVE_LIBBSD)
    if(HAVE_LIBBSD)
        list(APPEND TCPR_SYSTEM_LIBS bsd)
    endif()
endif()

# ---------------------------------------------------------------------------
# libopts tearoff support defines (libopts/m4/libopts.m4)
# ---------------------------------------------------------------------------
foreach(shell /bin/sh /bin/bash /bin/dash /usr/xpg4/bin/sh)
    if(EXISTS ${shell})
        set(POSIX_SHELL "\"${shell}\"")
        break()
    endif()
endforeach()
if(NOT POSIX_SHELL)
    set(POSIX_SHELL "\"/bin/sh\"")
endif()

if(HAVE_REGCOMP)
    set(REGEX_HEADER "<regex.h>")
    set(WITH_LIBREGEX 1)
endif()

if(EXISTS /dev/zero)
    set(HAVE_DEV_ZERO 1)
endif()

set(FOPEN_BINARY_FLAG "\"\"")
set(FOPEN_TEXT_FLAG "\"\"")

# ---------------------------------------------------------------------------
# Strict byte alignment (FORCE_ALIGN) — mirrors the unaligned access test
# ---------------------------------------------------------------------------
if(APPLE)
    set(UNALIGNED_FAIL FALSE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(alpha|arm|aarch64|hp|mips|sparc|ia64)")
    set(UNALIGNED_FAIL TRUE)
elseif(CMAKE_CROSSCOMPILING)
    set(UNALIGNED_FAIL TRUE)
else()
    check_c_source_runs("
unsigned char a[5] = { 1, 2, 3, 4, 5 };
int main(void) {
    unsigned int i = *(unsigned int *)&a[1];
    return (i == 0) ? 1 : 0;
}" UNALIGNED_OK)
    if(UNALIGNED_OK)
        set(UNALIGNED_FAIL FALSE)
    else()
        set(UNALIGNED_FAIL TRUE)
    endif()
endif()
if(UNALIGNED_FAIL)
    set(FORCE_ALIGN 1)
endif()

# ---------------------------------------------------------------------------
# Injection method probes: PF_PACKET, TX_RING, AF_XDP (compile tests)
# ---------------------------------------------------------------------------
check_c_source_compiles("
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
int main(void) {
    int pf_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return pf_socket < 0;
}" HAVE_PF_PACKET)

# <netpacket/packet.h> and <linux/if_packet.h> cannot be included together
# before C23 - both define struct sockaddr_ll/packet_mreq, and the
# __UAPI_DEF_* de-duplication guards don't apply pre-C23 - so this probe
# used to fail to even compile (never defining HAVE_TX_RING) under
# -std=gnu11/-std=gnu17, exactly the collision src/common/txring.h had
# (#1043/#1044). <netpacket/packet.h> supplies nothing this probe uses.
check_c_source_compiles("
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
int main(void) { int test = TP_STATUS_WRONG_FORMAT; return test; }
" HAVE_TX_RING)

# PF_INET/SOCK_RAW raw IP socket support (#465): unlike PF_PACKET, packets
# sent this way go through the normal Linux IP stack (routing,
# netfilter/iptables) rather than straight onto the wire. SO_BINDTODEVICE
# is Linux-specific, so this probe effectively gates the feature to Linux.
check_c_source_compiles("
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
int main(void) {
    int raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    struct ifreq ifr;
    return setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
}" HAVE_SOCK_RAW)

check_library_exists(bpf bpf_object__open_file "" HAVE_LIBBPF_LIB)
check_library_exists(xdp xsk_umem__delete "" HAVE_LIBXDP_LIB)
if(HAVE_LIBXDP_LIB)
    # check_c_source_compiles() links a full test executable despite its
    # name, so xsk_socket__create() below needs -lxdp on the link line via
    # CMAKE_REQUIRED_LIBRARIES, or the check fails with "undefined
    # reference" even though the header and call are both fine - it was
    # never being set here, so this check always failed even with libxdp
    # genuinely installed (matches the pattern already used correctly for
    # liburing just below).
    set(CMAKE_REQUIRED_LIBRARIES xdp)
    check_c_source_compiles("
#include <stdlib.h>
#include <xdp/xsk.h>
#include <sys/socket.h>
int main(void) {
    struct xsk_socket *xsk = NULL;
    struct xsk_ring_cons *rxr = NULL;
    struct xsk_ring_prod *txr = NULL;
    xsk_socket__create(&xsk, \"lo\", 0, NULL, rxr, txr, NULL);
    return socket(AF_XDP, SOCK_RAW, 0) < 0;
}" HAVE_LIBXDP_COMPILES)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif()
if(HAVE_LIBXDP_COMPILES AND HAVE_LIBXDP_LIB)
    set(HAVE_LIBXDP 1)
endif()
if(HAVE_LIBBPF_LIB AND HAVE_BPF_LIBBPF_H)
    set(HAVE_LIBBPF 1)
endif()

check_library_exists(uring io_uring_queue_init "" HAVE_LIBURING_LIB)
if(HAVE_LIBURING_LIB)
    set(CMAKE_REQUIRED_LIBRARIES uring)
    check_c_source_compiles("
#include <liburing.h>
#include <sys/socket.h>
int main(void) {
    struct io_uring ring;
    io_uring_queue_init(64, &ring, 0);
    io_uring_queue_exit(&ring);
    return 0;
}" HAVE_LIBURING_COMPILES)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif()
if(HAVE_LIBURING_COMPILES AND HAVE_LIBURING_LIB)
    set(HAVE_LIBURING 1)
endif()

# ---------------------------------------------------------------------------
# tuntap support
# ---------------------------------------------------------------------------
if(ENABLE_TUNTAP)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        check_include_file(linux/if_tun.h HAVE_TUNTAP_HEADER)
    else()
        check_include_file(net/if_tun.h HAVE_TUNTAP_HEADER)
    endif()
    if(HAVE_TUNTAP_HEADER)
        set(HAVE_TUNTAP 1)
    endif()
endif()

# ---------------------------------------------------------------------------
# OS identification (mirrors the case $host blocks)
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(HAVE_LINUX 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(HAVE_DARWIN 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
    set(HAVE_SOLARIS 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    set(HAVE_OPENBSD 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    set(HAVE_FREEBSD 1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "CYGWIN")
    set(HAVE_CYGWIN 1)
    set(HAVE_WIN32 1)
endif()
