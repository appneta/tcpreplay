#cmakedefine ENABLE_VERBOSE 1
#cmakedefine USE_AUTOOPTS 1

/* use 64bit packet counters */
#cmakedefine ENABLE_64BITS 1

/* system/arch tests */
#cmakedefine FORCE_ALIGN 1
#cmakedefine WORDS_BIGENDIAN 1

#cmakedefine HAVE_BPF 1
#cmakedefine HAVE_PF_PACKET 1
#cmakedefine HAVE_LIBDNET 1
#cmakedefine HAVE_NETMAP 1

/* checks by FindPCAP */
#cmakedefine HAVE_PCAP_INJECT 1
#cmakedefine HAVE_PCAP_SENDPACKET 1
#cmakedefine HAVE_PCAP_BREAKLOOP 1
#cmakedefine HAVE_PCAP_DATALINK_NAME_TO_VAL 1
#cmakedefine HAVE_PCAP_DATALINK_VAL_TO_NAME 1
#cmakedefine HAVE_PCAP_DATALINK_VAL_TO_DESC 1
#cmakedefine HAVE_PCAP_FINDALLDEVS 1
#cmakedefine HAVE_PCAP_FREECODE 1
#cmakedefine HAVE_PCAP_GET_SELECTABLE_FD 1
#cmakedefine HAVE_PCAP_LIB_VERSION 1
#cmakedefine HAVE_PCAP_LIST_DATALINKS 1
#cmakedefine HAVE_PCAP_OPEN_DEAD 1
#cmakedefine HAVE_PCAP_SET_DATALINK 1
#cmakedefine HAVE_PCAP_DUMP_FOPEN 1
#cmakedefine HAVE_PCAP_SNAPSHOT 1
#cmakedefine HAVE_PCAP_SETDIRECTION 1

/* Linux TX_RING support */
#cmakedefine HAVE_TX_RING 1

/* set to true to override the default */
#cmakedefine FORCE_INJECT_BPF 1
#cmakedefine FORCE_INJECT_PF 1
#cmakedefine FORCE_INJECT_LIBDNET 1
#cmakedefine FORCE_INJECT_PCAP_INJECT 1
#cmakedefine FORCE_INJECT_PCAP_SENDPACKET 1

/* FindDNET */
#cmakedefine HAVE_LIBDNET 1
#cmakedefine HAVE_DNET_H 1
#cmakedefine HAVE_DUMBNET_H 1

/* Does your OS have strlcpy() ? */
#cmakedefine HAVE_SYSTEM_STRLCPY 1

#cmakedefine TCPREPLAY_EDIT 1
#cmakedefine LIBDNET_VERSION "@LIBDNET_VERSION@"
#cmakedefine ENABLE_FRAGROUTE 1
#cmakedefine VERSION "@VERSION@"
#cmakedefine TCPDUMP_BINARY "@TCPDUMP_BINARY@"

#cmakedefine UINT8_T
#cmakedefine UINT16_T
#cmakedefine UINT32_T
#cmakedefine UINT64_T

#cmakedefine HAVE_BOOL_H 1
#cmakedefine HAVE_STDBOOL_H 1
#cmakedefine HAVE_ARPA_INET_H 1
#cmakedefine HAVE_ARPA_NAMESER_H 1
#cmakedefine HAVE_DIRECT_H 1
#cmakedefine HAVE_DIRENT_H 1
#cmakedefine HAVE_DLFCN_H 1
#cmakedefine HAVE_FCNTL_H 1
#cmakedefine NEED_GETOPT_H 1
#cmakedefine NEED_G_ASCII_STRTOULL_H 1
#cmakedefine NEED_INET_ATON_H 1
#cmakedefine HAVE_INTTYPES_H 1
#cmakedefine HAVE_LAUXLIB_H 1
#cmakedefine HAVE_MEMORY_H 1
#cmakedefine HAVE_NETINET_IN_H 1
#cmakedefine HAVE_NETDB_H 1
#cmakedefine HAVE_PORTAUDIO_H 1
#cmakedefine HAVE_POLL_H 1
#cmakedefine HAVE_SIGNAL_H 1
#cmakedefine HAVE_STDARG_H 1
#cmakedefine HAVE_STDDEF_H 1
#cmakedefine HAVE_STDINT_H 1
#cmakedefine HAVE_STDLIB_H 1
#cmakedefine NEED_STRERROR_H 1
#cmakedefine HAVE_STRINGS_H 1
#cmakedefine HAVE_STRING_H 1
#cmakedefine HAVE_SYS_IOCTL_H 1
#cmakedefine HAVE_SYS_PARAM_H 1
#cmakedefine HAVE_SYS_SOCKET_H 1
#cmakedefine HAVE_SYS_SOCKIO_H 1
#cmakedefine HAVE_SYS_STAT_H 1
#cmakedefine HAVE_SYS_TIME_H 1
#cmakedefine HAVE_SYS_TYPES_H 1
#cmakedefine HAVE_SYS_UTSNAME_H 1
#cmakedefine HAVE_SYS_WAIT_H 1
#cmakedefine HAVE_UNISTD_H 1
#cmakedefine HAVE_TIME_H 1
#cmakedefine HAVE_NETINET_IN_SYSTM_H 1

#cmakedefine HAVE_CHOWN 1
#cmakedefine HAVE_GETHOSTBYNAME2 1
#cmakedefine HAVE_GETPROTOBYNUMBER 1
#cmakedefine HAVE_INET_NTOP_PROTO 1
#cmakedefine HAVE_ISSETUGID 1
#cmakedefine HAVE_MMAP 1
#cmakedefine HAVE_MPROTECT 1
#cmakedefine HAVE_SYSCONF 1
#cmakedefine HAVE_ABSOLUTE_TIME 1

#cmakedefine HAVE_INET_NTOP 1
#cmakedefine HAVE_INET_NTOA 1
#cmakedefine HAVE_INET_PTON 1
#cmakedefine HAVE_INET_ADDR 1

@LONG_SIZE_CODE@                                                          
#define BITS_PER_LONG LONG_SIZE * 8

