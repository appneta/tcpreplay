/* config.h.cmake — generated from src/config.h.in for the CMake build (issue #688) */

/* Define if building universal (internal helper macro) */
#cmakedefine AC_APPLE_UNIVERSAL_BUILD @AC_APPLE_UNIVERSAL_BUILD@

/* What version of autogen is installed on this system */
#cmakedefine AUTOGEN_VERSION @AUTOGEN_VERSION@

/* Enable debugging code and support for the -d option */
#cmakedefine DEBUG @DEBUG@

/* Enable dmalloc function arg checking */
#cmakedefine DMALLOC_FUNC_CHECK @DMALLOC_FUNC_CHECK@

/* Enable Electric Fence memory debugger */
#cmakedefine EFENCE @EFENCE@

/* Use 64bit packet counters */
#cmakedefine ENABLE_64BITS @ENABLE_64BITS@

/* Enable dmalloc */
#cmakedefine ENABLE_DMALLOC @ENABLE_DMALLOC@

/* Use shared libraries ( .so .dylib or .tbd ) */
#cmakedefine ENABLE_DYNAMIC_LINK @ENABLE_DYNAMIC_LINK@

/* Enable fragroute module */
#cmakedefine ENABLE_FRAGROUTE @ENABLE_FRAGROUTE@

/* nls support in libopts */
#cmakedefine ENABLE_NLS @ENABLE_NLS@

/* Enable use of pcap_findalldevs() */
#cmakedefine ENABLE_PCAP_FINDALLDEVS @ENABLE_PCAP_FINDALLDEVS@

/* Use static libraries ( .a or .A.tbd ) */
#cmakedefine ENABLE_STATIC_LINK @ENABLE_STATIC_LINK@

/* Compile tcpbridge */
#cmakedefine ENABLE_TCPBRIDGE @ENABLE_TCPBRIDGE@

/* Compile tcpliveplay */
#cmakedefine ENABLE_TCPLIVEPLAY @ENABLE_TCPLIVEPLAY@

/* Do we have tcpdump and pcap_dump_fopen()? */
#cmakedefine ENABLE_VERBOSE @ENABLE_VERBOSE@

/* Enable additional debugging code (may affect performance) */
#cmakedefine EXTRA_DEBUG @EXTRA_DEBUG@

/* fopen(3) accepts a 'b' in the mode flag */
#cmakedefine FOPEN_BINARY_FLAG @FOPEN_BINARY_FLAG@

/* fopen(3) accepts a 't' in the mode flag */
#cmakedefine FOPEN_TEXT_FLAG @FOPEN_TEXT_FLAG@

/* Are we strictly aligned? */
#cmakedefine FORCE_ALIGN @FORCE_ALIGN@

/* Force using BPF for sending packet */
#cmakedefine FORCE_INJECT_BPF @FORCE_INJECT_BPF@

/* Force using libdnet for sending packets */
#cmakedefine FORCE_INJECT_LIBDNET @FORCE_INJECT_LIBDNET@

/* Force using libxdp for sending packets */
#cmakedefine FORCE_INJECT_LIBXDP @FORCE_INJECT_LIBXDP@

/* Force using io_uring for sending packets */
#cmakedefine FORCE_INJECT_LIBURING @FORCE_INJECT_LIBURING@

/* Force using libpcap's pcap_inject() for sending packets */
#cmakedefine FORCE_INJECT_PCAP_INJECT @FORCE_INJECT_PCAP_INJECT@

/* Force using libpcap's pcap_sendpacket() for sending packets */
#cmakedefine FORCE_INJECT_PCAP_SENDPACKET @FORCE_INJECT_PCAP_SENDPACKET@

/* Force using Linux's PF_PACKET for sending packets */
#cmakedefine FORCE_INJECT_PF @FORCE_INJECT_PF@

/* Enable GNU Profiler */
#cmakedefine GPROF @GPROF@

/* Define to 1 if you have the 'alarm' function. */
#cmakedefine HAVE_ALARM @HAVE_ALARM@

/* Define to 1 if you have the <architecture/i386/pio.h> header file. */
#cmakedefine HAVE_ARCHITECTURE_I386_PIO_H @HAVE_ARCHITECTURE_I386_PIO_H@

/* Define to 1 if you have the <arpa/inet.h> header file. */
#cmakedefine HAVE_ARPA_INET_H @HAVE_ARPA_INET_H@

/* Define to 1 if you have the 'atexit' function. */
#cmakedefine HAVE_ATEXIT @HAVE_ATEXIT@

/* Do we have BPF device support? */
#cmakedefine HAVE_BPF @HAVE_BPF@

/* Define to 1 if you have the <bpf/bpf.h> header file. */
#cmakedefine HAVE_BPF_BPF_H @HAVE_BPF_BPF_H@

/* Define to 1 if you have the <bpf/libbpf.h> header file. */
#cmakedefine HAVE_BPF_LIBBPF_H @HAVE_BPF_LIBBPF_H@

/* Define to 1 if you have the 'bzero' function. */
#cmakedefine HAVE_BZERO @HAVE_BZERO@

/* Define to 1 if you have the 'canonicalize_file_name' function. */
#cmakedefine HAVE_CANONICALIZE_FILE_NAME @HAVE_CANONICALIZE_FILE_NAME@

/* Define to 1 if you have the 'chmod' function. */
#cmakedefine HAVE_CHMOD @HAVE_CHMOD@

/* Define to 1 if you have the 'ctime' function. */
#cmakedefine HAVE_CTIME @HAVE_CTIME@

/* Building Cygwin */
#cmakedefine HAVE_CYGWIN @HAVE_CYGWIN@

/* Building Apple/Darwin */
#cmakedefine HAVE_DARWIN @HAVE_DARWIN@

/* Define this if /dev/zero is readable device */
#cmakedefine HAVE_DEV_ZERO @HAVE_DEV_ZERO@

/* Define to 1 if you have the <dirent.h> header file, and it defines 'DIR'.
   */
#cmakedefine HAVE_DIRENT_H @HAVE_DIRENT_H@

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine HAVE_DLFCN_H @HAVE_DLFCN_H@

/* Does pcap.h include a header with DLT_C_HDLC? */
#cmakedefine HAVE_DLT_C_HDLC @HAVE_DLT_C_HDLC@

/* Does pcap.h include a header with DLT_LINUX_SLL? */
#cmakedefine HAVE_DLT_LINUX_SLL @HAVE_DLT_LINUX_SLL@

/* Does pcap.h include a header with DLT_LINUX_SLL2? */
#cmakedefine HAVE_DLT_LINUX_SLL2 @HAVE_DLT_LINUX_SLL2@

/* Does libpcap have pcap_datalink_val_to_description? */
#cmakedefine HAVE_DLT_VAL_TO_DESC @HAVE_DLT_VAL_TO_DESC@

/* Define to 1 if you have the <dnet.h> header file. */
#cmakedefine HAVE_DNET_H @HAVE_DNET_H@

/* Define to 1 if you don't have 'vprintf' but do have '_doprnt.' */
#cmakedefine HAVE_DOPRNT @HAVE_DOPRNT@

/* Define to 1 if you have the <dumbnet.h> header file. */
#cmakedefine HAVE_DUMBNET_H @HAVE_DUMBNET_H@

/* Define to 1 if you have the 'dup2' function. */
#cmakedefine HAVE_DUP2 @HAVE_DUP2@

/* Define to 1 if you have the <errno.h> header file. */
#cmakedefine HAVE_ERRNO_H @HAVE_ERRNO_H@

/* Define to 1 if you have the 'fchmod' function. */
#cmakedefine HAVE_FCHMOD @HAVE_FCHMOD@

/* Define to 1 if you have the <fcntl.h> header file. */
#cmakedefine HAVE_FCNTL_H @HAVE_FCNTL_H@

/* Define to 1 if you have the 'fork' function. */
#cmakedefine HAVE_FORK @HAVE_FORK@

/* Building Free BSD */
#cmakedefine HAVE_FREEBSD @HAVE_FREEBSD@

/* Define to 1 if fseeko (and ftello) are declared in stdio.h. */
#cmakedefine HAVE_FSEEKO @HAVE_FSEEKO@

/* Define to 1 if you have the 'fstat' function. */
#cmakedefine HAVE_FSTAT @HAVE_FSTAT@

/* Define to 1 if you have the <fts.h> header file. */
#cmakedefine HAVE_FTS_H @HAVE_FTS_H@

/* Define to 1 if you have the 'gethostbyname' function. */
#cmakedefine HAVE_GETHOSTBYNAME @HAVE_GETHOSTBYNAME@

/* Define to 1 if you have the 'getpagesize' function. */
#cmakedefine HAVE_GETPAGESIZE @HAVE_GETPAGESIZE@

/* Define to 1 if you have the 'gettimeofday' function. */
#cmakedefine HAVE_GETTIMEOFDAY @HAVE_GETTIMEOFDAY@

/* Do we have inet_addr? */
#cmakedefine HAVE_INET_ADDR @HAVE_INET_ADDR@

/* Do we have inet_aton? */
#cmakedefine HAVE_INET_ATON @HAVE_INET_ATON@

/* Define to 1 if you have the 'inet_ntoa' function. */
#cmakedefine HAVE_INET_NTOA @HAVE_INET_NTOA@

/* Do we have inet_ntop? */
#cmakedefine HAVE_INET_NTOP @HAVE_INET_NTOP@

/* Do we have inet_pton? */
#cmakedefine HAVE_INET_PTON @HAVE_INET_PTON@

/* Define to 1 if the system has the type 'int16_t'. */
#cmakedefine HAVE_INT16_T @HAVE_INT16_T@

/* Define to 1 if the system has the type 'int32_t'. */
#cmakedefine HAVE_INT32_T @HAVE_INT32_T@

/* Define to 1 if the system has the type 'int8_t'. */
#cmakedefine HAVE_INT8_T @HAVE_INT8_T@

/* Define to 1 if the system has the type 'intptr_t'. */
#cmakedefine HAVE_INTPTR_T @HAVE_INTPTR_T@

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine HAVE_INTTYPES_H @HAVE_INTTYPES_H@

/* Define to 1 if you have the 'ioperm' function. */
#cmakedefine HAVE_IOPERM @HAVE_IOPERM@

/* Define to 1 if you have the 'asan' library (-lasan). */
#cmakedefine HAVE_LIBASAN @HAVE_LIBASAN@

/* Define to 1 if you have the 'bpf' library (-lbpf). */
#cmakedefine HAVE_LIBBPF @HAVE_LIBBPF@

/* Define to 1 if you have the 'bsd' library (-lbsd). */
#cmakedefine HAVE_LIBBSD @HAVE_LIBBSD@

/* Do we have libdnet? */
#cmakedefine HAVE_LIBDNET @HAVE_LIBDNET@

/* Define to 1 if you have the 'gen' library (-lgen). */
#cmakedefine HAVE_LIBGEN @HAVE_LIBGEN@

/* Define to 1 if you have the <libgen.h> header file. */
#cmakedefine HAVE_LIBGEN_H @HAVE_LIBGEN_H@

/* Define to 1 if you have the 'intl' library (-lintl). */
#cmakedefine HAVE_LIBINTL @HAVE_LIBINTL@

/* Define to 1 if you have the <libintl.h> header file. */
#cmakedefine HAVE_LIBINTL_H @HAVE_LIBINTL_H@

/* Define to 1 if you have the 'nsl' library (-lnsl). */
#cmakedefine HAVE_LIBNSL @HAVE_LIBNSL@

/* Does this version of libpcap support netmap? */
#cmakedefine HAVE_LIBPCAP_NETMAP @HAVE_LIBPCAP_NETMAP@

/* Define to 1 if you have the 'resolv' library (-lresolv). */
#cmakedefine HAVE_LIBRESOLV @HAVE_LIBRESOLV@

/* Define to 1 if you have the 'rt' library (-lrt). */
#cmakedefine HAVE_LIBRT @HAVE_LIBRT@

/* Define to 1 if you have the 'socket' library (-lsocket). */
#cmakedefine HAVE_LIBSOCKET @HAVE_LIBSOCKET@

/* Do we have LIBXDP AF_XDP socket support? */
#cmakedefine HAVE_LIBXDP @HAVE_LIBXDP@

/* Do we have Linux io_uring support via liburing? */
#cmakedefine HAVE_LIBURING @HAVE_LIBURING@

/* Define to 1 if you have the <limits.h> header file. */
#cmakedefine HAVE_LIMITS_H @HAVE_LIMITS_H@

/* Building Linux */
#cmakedefine HAVE_LINUX @HAVE_LINUX@

/* Define to 1 if you have the 'memmove' function. */
#cmakedefine HAVE_MEMMOVE @HAVE_MEMMOVE@

/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine HAVE_MEMORY_H @HAVE_MEMORY_H@

/* Define to 1 if you have the 'memset' function. */
#cmakedefine HAVE_MEMSET @HAVE_MEMSET@

/* Define to 1 if you have the 'mmap' function. */
#cmakedefine HAVE_MMAP @HAVE_MMAP@

/* Define to 1 if you have the 'munmap' function. */
#cmakedefine HAVE_MUNMAP @HAVE_MUNMAP@

/* Define to 1 if you have the <ndir.h> header file, and it defines 'DIR'. */
#cmakedefine HAVE_NDIR_H @HAVE_NDIR_H@

/* Define to 1 if you have the <netinet/in.h> header file. */
#cmakedefine HAVE_NETINET_IN_H @HAVE_NETINET_IN_H@

/* Define to 1 if you have the <netinet/in_systm.h> header file. */
#cmakedefine HAVE_NETINET_IN_SYSTM_H @HAVE_NETINET_IN_SYSTM_H@

/* Do we have netmap support? */
#cmakedefine HAVE_NETMAP @HAVE_NETMAP@

/* Does netmap have nm_open function? */
#cmakedefine HAVE_NETMAP_NM_OPEN @HAVE_NETMAP_NM_OPEN@

/* Does netmap struct nmreq have nr_flags defined? */
#cmakedefine HAVE_NETMAP_NR_FLAGS @HAVE_NETMAP_NR_FLAGS@

/* Does netmap have NR_REG_MASK defined? */
#cmakedefine HAVE_NETMAP_NR_REG @HAVE_NETMAP_NR_REG@

/* Does structure netmap_ring have head/tail defined? */
#cmakedefine HAVE_NETMAP_RING_HEAD_TAIL @HAVE_NETMAP_RING_HEAD_TAIL@

/* Define to 1 if you have the <net/bpf.h> header file. */
#cmakedefine HAVE_NET_BPF_H @HAVE_NET_BPF_H@

/* Define to 1 if you have the <net/route.h> header file. */
#cmakedefine HAVE_NET_ROUTE_H @HAVE_NET_ROUTE_H@

/* Define to 1 if you have the 'ntohll' function. */
#cmakedefine HAVE_NTOHLL @HAVE_NTOHLL@

/* Building Open BSD */
#cmakedefine HAVE_OPENBSD @HAVE_OPENBSD@

/* Define this if pathfind(3) works */
#cmakedefine HAVE_PATHFIND @HAVE_PATHFIND@

/* Do we have libpcapnav? */
#cmakedefine HAVE_PCAPNAV @HAVE_PCAPNAV@

/* Does libpcap have pcap_breakloop? */
#cmakedefine HAVE_PCAP_BREAKLOOP @HAVE_PCAP_BREAKLOOP@

/* Does libpcap have pcap_dump_fopen? */
#cmakedefine HAVE_PCAP_DUMP_FOPEN @HAVE_PCAP_DUMP_FOPEN@

/* Does libpcap have pcap_get_selectable_fd? */
#cmakedefine HAVE_PCAP_GET_SELECTABLE_FD @HAVE_PCAP_GET_SELECTABLE_FD@

/* Does libpcap have pcap_inject? */
#cmakedefine HAVE_PCAP_INJECT @HAVE_PCAP_INJECT@

/* Does libpcap have pcap_open_offline_with_tstamp_precision? */
#cmakedefine HAVE_PCAP_OPEN_OFFLINE_WITH_TSTAMP_PRECISION @HAVE_PCAP_OPEN_OFFLINE_WITH_TSTAMP_PRECISION@

/* Does libpcap have pcap_sendpacket? */
#cmakedefine HAVE_PCAP_SENDPACKET @HAVE_PCAP_SENDPACKET@

/* Does libpcap have pcap_setnonblock? */
#cmakedefine HAVE_PCAP_SETNONBLOCK @HAVE_PCAP_SETNONBLOCK@

/* Does libpcap have pcap_snapshot? */
#cmakedefine HAVE_PCAP_SNAPSHOT @HAVE_PCAP_SNAPSHOT@

/* Does libpcap have pcap_version[] */
#cmakedefine HAVE_PCAP_VERSION @HAVE_PCAP_VERSION@

/* Do we have Linux PF_PACKET socket support? */
#cmakedefine HAVE_PF_PACKET @HAVE_PF_PACKET@

/* ${with_pfring_lib} numa pthread rt */
#cmakedefine HAVE_PF_RING_PCAP @HAVE_PF_RING_PCAP@

/* Define to 1 if the system has the type 'pid_t'. */
#cmakedefine HAVE_PID_T @HAVE_PID_T@

/* Define to 1 if you have the 'poll' function. */
#cmakedefine HAVE_POLL @HAVE_POLL@

/* Define to 1 if you have the <poll.h> header file. */
#cmakedefine HAVE_POLL_H @HAVE_POLL_H@

/* Define to 1 if you have the 'pow' function. */
#cmakedefine HAVE_POW @HAVE_POW@

/* Define to 1 if the system has the type 'ptrdiff_t'. */
#cmakedefine HAVE_PTRDIFF_T @HAVE_PTRDIFF_T@

/* Define to 1 if you have the 'putenv' function. */
#cmakedefine HAVE_PUTENV @HAVE_PUTENV@

/* Define this if we have a functional realpath(3C) */
#cmakedefine HAVE_REALPATH @HAVE_REALPATH@

/* Define to 1 if you have the 'regcomp' function. */
#cmakedefine HAVE_REGCOMP @HAVE_REGCOMP@

/* Define to 1 if you have the <runetype.h> header file. */
#cmakedefine HAVE_RUNETYPE_H @HAVE_RUNETYPE_H@

/* Define to 1 if you have the <sched.h> header file. */
#cmakedefine HAVE_SCHED_H @HAVE_SCHED_H@

/* Define to 1 if you have the 'select' function. */
#cmakedefine HAVE_SELECT @HAVE_SELECT@

/* Define to 1 if you have the <setjmp.h> header file. */
#cmakedefine HAVE_SETJMP_H @HAVE_SETJMP_H@

/* Define to 1 if you have the <signal.h> header file. */
#cmakedefine HAVE_SIGNAL_H @HAVE_SIGNAL_H@

/* Define to 1 if the system has the type 'size_t'. */
#cmakedefine HAVE_SIZE_T @HAVE_SIZE_T@

/* Define to 1 if you have the 'snprintf' function. */
#cmakedefine HAVE_SNPRINTF @HAVE_SNPRINTF@

/* Do we have PF_INET SOCK_RAW raw IP socket support? */
#cmakedefine HAVE_SOCK_RAW @HAVE_SOCK_RAW@

/* Define to 1 if you have the 'socket' function. */
#cmakedefine HAVE_SOCKET @HAVE_SOCKET@

/* Building Solaris */
#cmakedefine HAVE_SOLARIS @HAVE_SOLARIS@

/* Define to 1 if you have the <stdarg.h> header file. */
#cmakedefine HAVE_STDARG_H @HAVE_STDARG_H@

/* Define to 1 if you have the <stdbool.h> header file. */
#cmakedefine HAVE_STDBOOL_H @HAVE_STDBOOL_H@

/* Define to 1 if you have the <stddef.h> header file. */
#cmakedefine HAVE_STDDEF_H @HAVE_STDDEF_H@

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine HAVE_STDINT_H @HAVE_STDINT_H@

/* Define to 1 if you have the <stdio.h> header file. */
#cmakedefine HAVE_STDIO_H @HAVE_STDIO_H@

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine HAVE_STDLIB_H @HAVE_STDLIB_H@

/* Define to 1 if you have the 'strcasecmp' function. */
#cmakedefine HAVE_STRCASECMP @HAVE_STRCASECMP@

/* Define to 1 if you have the 'strchr' function. */
#cmakedefine HAVE_STRCHR @HAVE_STRCHR@

/* Define to 1 if you have the 'strcspn' function. */
#cmakedefine HAVE_STRCSPN @HAVE_STRCSPN@

/* Define to 1 if you have the 'strdup' function. */
#cmakedefine HAVE_STRDUP @HAVE_STRDUP@

/* Define to 1 if you have the 'strerror' function. */
#cmakedefine HAVE_STRERROR @HAVE_STRERROR@

/* Define this if strftime() works */
#cmakedefine HAVE_STRFTIME @HAVE_STRFTIME@

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine HAVE_STRINGS_H @HAVE_STRINGS_H@

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine HAVE_STRING_H @HAVE_STRING_H@

/* Define to 1 if you have the 'strlcpy' function. */
#cmakedefine HAVE_STRLCPY @HAVE_STRLCPY@

/* Define to 1 if you have the 'strncpy' function. */
#cmakedefine HAVE_STRNCPY @HAVE_STRNCPY@

/* Define to 1 if you have the 'strpbrk' function. */
#cmakedefine HAVE_STRPBRK @HAVE_STRPBRK@

/* Define to 1 if you have the 'strrchr' function. */
#cmakedefine HAVE_STRRCHR @HAVE_STRRCHR@

/* Define to 1 if you have the 'strsignal' function. */
#cmakedefine HAVE_STRSIGNAL @HAVE_STRSIGNAL@

/* Define to 1 if you have the 'strspn' function. */
#cmakedefine HAVE_STRSPN @HAVE_STRSPN@

/* Define to 1 if you have the 'strstr' function. */
#cmakedefine HAVE_STRSTR @HAVE_STRSTR@

/* Define to 1 if you have the 'strtol' function. */
#cmakedefine HAVE_STRTOL @HAVE_STRTOL@

/* Define to 1 if you have the 'strtoul' function. */
#cmakedefine HAVE_STRTOUL @HAVE_STRTOUL@

/* Define to 1 if you have the 'strtoull' function. */
#cmakedefine HAVE_STRTOULL @HAVE_STRTOULL@

/* Define to 1 if 'tv_sec' is a member of 'struct timeval'. */
#cmakedefine HAVE_STRUCT_TIMEVAL_TV_SEC @HAVE_STRUCT_TIMEVAL_TV_SEC@

/* Building SunOS */
#cmakedefine HAVE_SUNOS @HAVE_SUNOS@

/* Define to 1 if you have the <sysexits.h> header file. */
#cmakedefine HAVE_SYSEXITS_H @HAVE_SYSEXITS_H@

/* Define to 1 if you have the <sys/dir.h> header file, and it defines 'DIR'.
   */
#cmakedefine HAVE_SYS_DIR_H @HAVE_SYS_DIR_H@

/* Define to 1 if you have the <sys/file.h> header file. */
#cmakedefine HAVE_SYS_FILE_H @HAVE_SYS_FILE_H@

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#cmakedefine HAVE_SYS_IOCTL_H @HAVE_SYS_IOCTL_H@

/* Define to 1 if you have the <sys/io.h> header file. */
#cmakedefine HAVE_SYS_IO_H @HAVE_SYS_IO_H@

/* Define to 1 if you have the <sys/limits.h> header file. */
#cmakedefine HAVE_SYS_LIMITS_H @HAVE_SYS_LIMITS_H@

/* Define to 1 if you have the <sys/mman.h> header file. */
#cmakedefine HAVE_SYS_MMAN_H @HAVE_SYS_MMAN_H@

/* Define to 1 if you have the <sys/ndir.h> header file, and it defines 'DIR'.
   */
#cmakedefine HAVE_SYS_NDIR_H @HAVE_SYS_NDIR_H@

/* Define to 1 if you have the <sys/param.h> header file. */
#cmakedefine HAVE_SYS_PARAM_H @HAVE_SYS_PARAM_H@

/* Define to 1 if you have the <sys/poll.h> header file. */
#cmakedefine HAVE_SYS_POLL_H @HAVE_SYS_POLL_H@

/* Define to 1 if you have the <sys/procset.h> header file. */
#cmakedefine HAVE_SYS_PROCSET_H @HAVE_SYS_PROCSET_H@

/* Define to 1 if you have the <sys/select.h> header file. */
#cmakedefine HAVE_SYS_SELECT_H @HAVE_SYS_SELECT_H@

/* Define to 1 if you have the <sys/socket.h> header file. */
#cmakedefine HAVE_SYS_SOCKET_H @HAVE_SYS_SOCKET_H@

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine HAVE_SYS_STAT_H @HAVE_SYS_STAT_H@

/* Define to 1 if you have the <sys/stropts.h> header file. */
#cmakedefine HAVE_SYS_STROPTS_H @HAVE_SYS_STROPTS_H@

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#cmakedefine HAVE_SYS_SYSCTL_H @HAVE_SYS_SYSCTL_H@

/* Define to 1 if you have the <sys/systeminfo.h> header file. */
#cmakedefine HAVE_SYS_SYSTEMINFO_H @HAVE_SYS_SYSTEMINFO_H@

/* Define to 1 if you have the <sys/time.h> header file. */
#cmakedefine HAVE_SYS_TIME_H @HAVE_SYS_TIME_H@

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine HAVE_SYS_TYPES_H @HAVE_SYS_TYPES_H@

/* Define to 1 if you have the <sys/un.h> header file. */
#cmakedefine HAVE_SYS_UN_H @HAVE_SYS_UN_H@

/* Define to 1 if you have the <sys/wait.h> header file. */
#cmakedefine HAVE_SYS_WAIT_H @HAVE_SYS_WAIT_H@

/* Do we have tcpdump? */
#cmakedefine HAVE_TCPDUMP @HAVE_TCPDUMP@

/* Do we have TUNTAP device support? */
#cmakedefine HAVE_TUNTAP @HAVE_TUNTAP@

/* Do we have Linux TX_RING socket support? */
#cmakedefine HAVE_TX_RING @HAVE_TX_RING@

/* Define to 1 if the system has the type 'uint16_t'. */
#cmakedefine HAVE_UINT16_T @HAVE_UINT16_T@

/* Define to 1 if the system has the type 'uint32_t'. */
#cmakedefine HAVE_UINT32_T @HAVE_UINT32_T@

/* Define to 1 if the system has the type 'uint8_t'. */
#cmakedefine HAVE_UINT8_T @HAVE_UINT8_T@

/* Define to 1 if the system has the type 'uintptr_t'. */
#cmakedefine HAVE_UINTPTR_T @HAVE_UINTPTR_T@

/* Define to 1 if the system has the type 'uint_t'. */
#cmakedefine HAVE_UINT_T @HAVE_UINT_T@

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine HAVE_UNISTD_H @HAVE_UNISTD_H@

/* Define to 1 if you have the <utime.h> header file. */
#cmakedefine HAVE_UTIME_H @HAVE_UTIME_H@

/* Define to 1 if you have the <values.h> header file. */
#cmakedefine HAVE_VALUES_H @HAVE_VALUES_H@

/* Define to 1 if you have the <varargs.h> header file. */
#cmakedefine HAVE_VARARGS_H @HAVE_VARARGS_H@

/* Define to 1 if you have the 'vfork' function. */
#cmakedefine HAVE_VFORK @HAVE_VFORK@

/* Define to 1 if you have the <vfork.h> header file. */
#cmakedefine HAVE_VFORK_H @HAVE_VFORK_H@

/* Define to 1 if you have the 'vprintf' function. */
#cmakedefine HAVE_VPRINTF @HAVE_VPRINTF@

/* Define to 1 if you have the 'vsnprintf' function. */
#cmakedefine HAVE_VSNPRINTF @HAVE_VSNPRINTF@

/* Define to 1 if you have the <wchar.h> header file. */
#cmakedefine HAVE_WCHAR_H @HAVE_WCHAR_H@

/* Define to 1 if the system has the type 'wchar_t'. */
#cmakedefine HAVE_WCHAR_T @HAVE_WCHAR_T@

/* Windows/Cygwin */
#cmakedefine HAVE_WIN32 @HAVE_WIN32@

/* Do we have WinPcap? */
#cmakedefine HAVE_WINPCAP @HAVE_WINPCAP@

/* Define to 1 if the system has the type 'wint_t'. */
#cmakedefine HAVE_WINT_T @HAVE_WINT_T@

/* Define to 1 if 'fork' works. */
#cmakedefine HAVE_WORKING_FORK @HAVE_WORKING_FORK@

/* Define to 1 if 'vfork' works. */
#cmakedefine HAVE_WORKING_VFORK @HAVE_WORKING_VFORK@

/* Define to 1 if you have the <xdp/libxdp.h> header file. */
#cmakedefine HAVE_XDP_LIBXDP_H @HAVE_XDP_LIBXDP_H@

/* Define to 1 if the system has the type '_Bool'. */
#cmakedefine HAVE__BOOL @HAVE__BOOL@

/* What is the path (if any) to the libpcap bpf header file? */
#cmakedefine INCLUDE_PCAP_BPF_HEADER @INCLUDE_PCAP_BPF_HEADER@

/* Version of libdnet */
#cmakedefine LIBDNET_VERSION @LIBDNET_VERSION@

/* Define to 1 if 'lstat' dereferences a symlink specified with a trailing
   slash. */
#cmakedefine LSTAT_FOLLOWS_SLASHED_SYMLINK @LSTAT_FOLLOWS_SLASHED_SYMLINK@

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#cmakedefine LT_OBJDIR @LT_OBJDIR@

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in <mkdev.h>.
   */
#cmakedefine MAJOR_IN_MKDEV @MAJOR_IN_MKDEV@

/* Define to 1 if 'major', 'minor', and 'makedev' are declared in
   <sysmacros.h>. */
#cmakedefine MAJOR_IN_SYSMACROS @MAJOR_IN_SYSMACROS@

/* Define this if optional arguments are disallowed */
#cmakedefine NO_OPTIONAL_OPT_ARGS @NO_OPTIONAL_OPT_ARGS@

/* Name of package */
#cmakedefine PACKAGE @PACKAGE@

/* Define to the address where bug reports for this package should be sent. */
#cmakedefine PACKAGE_BUGREPORT @PACKAGE_BUGREPORT@

/* Define to the full name of this package. */
#cmakedefine PACKAGE_NAME @PACKAGE_NAME@

/* Define to the full name and version of this package. */
#cmakedefine PACKAGE_STRING @PACKAGE_STRING@

/* Define to the one symbol short name of this package. */
#cmakedefine PACKAGE_TARNAME @PACKAGE_TARNAME@

/* Define to the home page for this package. */
#cmakedefine PACKAGE_URL @PACKAGE_URL@

/* Define to the version of this package. */
#cmakedefine PACKAGE_VERSION @PACKAGE_VERSION@

/* libpcapnav's version? */
#cmakedefine PCAPNAV_VERSION @PCAPNAV_VERSION@

/* Multiplier for conversion from PCAP usec to nsec */
#cmakedefine PCAP_TSTAMP_US_TO_NS_MULTIPLIER @PCAP_TSTAMP_US_TO_NS_MULTIPLIER@

/* Divisor for conversion from PCAP usec to usec */
#cmakedefine PCAP_TSTAMP_US_TO_US_DIVISOR @PCAP_TSTAMP_US_TO_US_DIVISOR@

/* define to a working POSIX compliant shell */
#cmakedefine POSIX_SHELL @POSIX_SHELL@

/* name of regex header file */
#cmakedefine REGEX_HEADER @REGEX_HEADER@

/* The size of 'char *', as computed by sizeof. */
#cmakedefine SIZEOF_CHAR_P @SIZEOF_CHAR_P@

/* The size of 'int', as computed by sizeof. */
#cmakedefine SIZEOF_INT @SIZEOF_INT@

/* The size of 'long', as computed by sizeof. */
#cmakedefine SIZEOF_LONG @SIZEOF_LONG@

/* The size of 'short', as computed by sizeof. */
#cmakedefine SIZEOF_SHORT @SIZEOF_SHORT@

/* Define to 1 if all of the C89 standard headers exist (not just the ones
   required in a freestanding environment). This macro is provided for
   backward compatibility; new code need not use it. */
#cmakedefine STDC_HEADERS @STDC_HEADERS@

/* The tcpdump binary initially used */
#cmakedefine TCPDUMP_BINARY @TCPDUMP_BINARY@

/* Enable dumping of trace timestamps at the end of a test */
#cmakedefine TIMESTAMP_TRACE @TIMESTAMP_TRACE@

/* Version number of package */
#cmakedefine VERSION @VERSION@

/* Define if using the dmalloc debugging malloc package */
#cmakedefine WITH_DMALLOC @WITH_DMALLOC@

/* Define this if a working libregex can be found */
#cmakedefine WITH_LIBREGEX @WITH_LIBREGEX@

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#cmakedefine WORDS_BIGENDIAN @WORDS_BIGENDIAN@

/* Number of bits in a file offset, on hosts where this is settable. */
#cmakedefine _FILE_OFFSET_BITS @_FILE_OFFSET_BITS@

/* Define to 1 if necessary to make fseeko visible. */
#cmakedefine _LARGEFILE_SOURCE @_LARGEFILE_SOURCE@

/* Define to 1 on platforms where this makes off_t a 64-bit type. */
#cmakedefine _LARGE_FILES @_LARGE_FILES@

/* Number of bits in time_t, on hosts where this is settable. */
#cmakedefine _TIME_BITS @_TIME_BITS@

/* Define for Solaris 2.5.1 so the uint32_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
#cmakedefine _UINT32_T @_UINT32_T@

/* Define for Solaris 2.5.1 so the uint64_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
#cmakedefine _UINT64_T @_UINT64_T@

/* Define for Solaris 2.5.1 so the uint8_t typedef from <sys/synch.h>,
   <pthread.h>, or <semaphore.h> is not used. If the typedef were allowed, the
   #define below would cause a syntax error. */
#cmakedefine _UINT8_T @_UINT8_T@

/* Define to 1 on platforms where this makes time_t a 64-bit type. */
#cmakedefine __MINGW_USE_VC2005_COMPAT @__MINGW_USE_VC2005_COMPAT@

/* Define to empty if 'const' does not conform to ANSI C. */
#cmakedefine const @const@

/* Define to '__inline__' or '__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#cmakedefine inline @inline@
#endif

/* Define to the type of a signed integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine int16_t @int16_t@

/* Define to the type of a signed integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine int32_t @int32_t@

/* Define to the type of a signed integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine int64_t @int64_t@

/* Define to the type of a signed integer type of width exactly 8 bits if such
   a type exists and the standard includes do not define it. */
#cmakedefine int8_t @int8_t@

/* Define to 'long int' if <sys/types.h> does not define. */
#cmakedefine off_t @off_t@

/* Define as a signed integer type capable of holding a process identifier. */
#cmakedefine pid_t @pid_t@

/* Define as 'unsigned int' if <stddef.h> doesn't define. */
#cmakedefine size_t @size_t@

/* Define as 'int' if <sys/types.h> doesn't define. */
#cmakedefine ssize_t @ssize_t@

/* Define to 'uint8_t' if <sys/types.h> does not define. */
#cmakedefine u_char @u_char@

/* Define to 'uint32_t' if <sys/types.h> does not define. */
#cmakedefine u_int @u_int@

/* Define to 'uint16_t' if <sys/types.h> does not define. */
#cmakedefine u_int16_t @u_int16_t@

/* Define to 'uint32_t' if <sys/types.h> does not define. */
#cmakedefine u_int32_t @u_int32_t@

/* Define to 'uint64_t' if <sys/types.h> does not define. */
#cmakedefine u_int64_t @u_int64_t@

/* Define to 'uint8_t' if <sys/types.h> does not define. */
#cmakedefine u_int8_t @u_int8_t@

/* Define to 'uint16_t' if <sys/types.h> does not define. */
#cmakedefine u_short @u_short@

/* Define to the type of an unsigned integer type of width exactly 16 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine uint16_t @uint16_t@

/* Define to the type of an unsigned integer type of width exactly 32 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine uint32_t @uint32_t@

/* Define to the type of an unsigned integer type of width exactly 64 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine uint64_t @uint64_t@

/* Define to the type of an unsigned integer type of width exactly 8 bits if
   such a type exists and the standard includes do not define it. */
#cmakedefine uint8_t @uint8_t@

/* Define as 'fork' if 'vfork' does not work. */
#cmakedefine vfork @vfork@
