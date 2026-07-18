# PcapChecks.cmake — libpcap capability probes from configure.ac (issue #688).
# Requires FindPCAP.cmake to have run (PCAP_INCLUDE_DIR / PCAP_LIBRARIES).

include(CheckCSourceCompiles)

set(CMAKE_REQUIRED_INCLUDES ${PCAP_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARIES} ${TCPR_SYSTEM_LIBS})

# Note: winpcap declares functions in headers that aren't in the library, so
# these must LINK, not just compile (see the comment in configure.ac).
macro(pcap_link_check var code)
    check_c_source_compiles("
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
int main(void) { ${code} ; return 0; }" ${var})
    if(${var})
        set(${var} 1)
    endif()
endmacro()

pcap_link_check(HAVE_PCAP_SETNONBLOCK
    "pcap_t *p = NULL; char *errbuf = NULL; pcap_setnonblock(p, 1, errbuf)")
pcap_link_check(HAVE_DLT_VAL_TO_DESC
    "if (strcmp(pcap_datalink_val_to_description(1), \\\"Ethernet (10Mb)\\\") == 0) exit(0)")
pcap_link_check(HAVE_PCAP_GET_SELECTABLE_FD
    "pcap_t *p = NULL; int f = pcap_get_selectable_fd(p); (void)f")
pcap_link_check(HAVE_PCAP_DUMP_FOPEN
    "pcap_dumper_t *dump; pcap_t *pcap = NULL; FILE *foo = NULL; dump = pcap_dump_fopen(pcap, foo); (void)dump")
pcap_link_check(HAVE_PCAP_INJECT
    "pcap_t *pcap = NULL; char *buf = NULL; pcap_inject(pcap, (void *)buf, 0)")
pcap_link_check(HAVE_PCAP_SENDPACKET
    "pcap_t *pcap = NULL; u_char *buf = NULL; pcap_sendpacket(pcap, buf, 0)")
pcap_link_check(HAVE_PCAP_BREAKLOOP
    "pcap_t *pcap = NULL; pcap_breakloop(pcap)")
pcap_link_check(HAVE_PCAP_SNAPSHOT
    "pcap_t *p = NULL; int len = pcap_snapshot(p); (void)len")
pcap_link_check(HAVE_PCAP_OPEN_OFFLINE_WITH_TSTAMP_PRECISION
    "pcap_t *pcap; char ebuf[PCAP_ERRBUF_SIZE];
     pcap = pcap_open_offline_with_tstamp_precision(\\\"fake.pcap\\\", PCAP_TSTAMP_PRECISION_NANO, &ebuf[0]); (void)pcap")

check_c_source_compiles("
#include <stdio.h>
#include <pcap.h>
extern char pcap_version[];
int main(void) { printf(\"%s\", pcap_version); return 0; }" HAVE_PCAP_VERSION)
if(HAVE_PCAP_VERSION)
    set(HAVE_PCAP_VERSION 1)
endif()

# Basic sanity: can we link pcap_close at all?
check_c_source_compiles("
#include <pcap.h>
int main(void) { pcap_close((pcap_t *)0); return 0; }" PCAP_LINKS)
if(NOT PCAP_LINKS)
    message(FATAL_ERROR "Unable to link libpcap (${PCAP_LIBRARIES})")
endif()

if(HAVE_PCAP_OPEN_OFFLINE_WITH_TSTAMP_PRECISION)
    set(PCAP_TSTAMP_US_TO_NS_MULTIPLIER 1)
    set(PCAP_TSTAMP_US_TO_US_DIVISOR 1000)
else()
    set(PCAP_TSTAMP_US_TO_NS_MULTIPLIER 1000)
    set(PCAP_TSTAMP_US_TO_US_DIVISOR 1)
endif()

# DLT availability in this libpcap
pcap_link_check(HAVE_DLT_LINUX_SLL "int foo = DLT_LINUX_SLL; (void)foo")
pcap_link_check(HAVE_DLT_LINUX_SLL2 "int foo = DLT_LINUX_SLL2; (void)foo")
pcap_link_check(HAVE_DLT_C_HDLC "int foo = DLT_C_HDLC; (void)foo")

# libpcap bpf header usable?
if(PCAP_BPF_H_FILE)
    check_c_source_compiles("
#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include \"${PCAP_BPF_H_FILE}\"
int main(void) { int foo = BPF_MAJOR_VERSION; return foo; }" PCAP_BPF_HEADER_USABLE)
    if(PCAP_BPF_HEADER_USABLE)
        set(INCLUDE_PCAP_BPF_HEADER 1)
    endif()
endif()

# libpcap runtime version (only when not cross compiling)
set(LIBPCAP_VERSION "unknown")
set(LIBPCAP_VERSION_096 FALSE)
if(NOT CMAKE_CROSSCOMPILING)
    file(WRITE ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/pcap_version_test.c "
#include <stdio.h>
#include <pcap.h>
int main(void) { printf(\"%s\\n\", pcap_lib_version()); return 0; }
")
    try_run(_pcap_run _pcap_compile ${CMAKE_BINARY_DIR}
            ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/pcap_version_test.c
            CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${PCAP_INCLUDE_DIR}"
            LINK_LIBRARIES ${PCAP_LIBRARIES} ${TCPR_SYSTEM_LIBS}
            RUN_OUTPUT_VARIABLE _pcap_version_out)
    if(_pcap_compile AND _pcap_run EQUAL 0)
        string(REGEX MATCH "[0-9]+\\.[0-9]+(\\.[0-9]+)?" LIBPCAP_VERSION "${_pcap_version_out}")
        if(LIBPCAP_VERSION)
            if(LIBPCAP_VERSION VERSION_LESS 0.7.2)
                message(FATAL_ERROR "Libpcap versions < 0.7.2 are not supported. Your version is ${LIBPCAP_VERSION}")
            endif()
            if(LIBPCAP_VERSION VERSION_GREATER_EQUAL 0.9.6)
                set(LIBPCAP_VERSION_096 TRUE)
            endif()
        endif()
    endif()
endif()
message(STATUS "libpcap version: ${LIBPCAP_VERSION}")

set(CMAKE_REQUIRED_INCLUDES)
set(CMAKE_REQUIRED_LIBRARIES)
