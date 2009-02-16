# All the tests necessary for libopts go here.  Note that this is not for
# checking if libopts/AutoGen/AutoOpts is installed on your system, but 
# rather for doing a compatibility check for your libopts tearoff

# You may need to set these

########################################################
# You probably don't want to change anything below here!
########################################################

# Takes the path to the tearoff directory & the version of autogen
MACRO(CHECK_LIBOPTS_TEAROFF LIBOPTS_TEAROFF_PATH __AUTOGEN_VERSION)
    CONFIGURE_FILE(${LIBOPTS_TEAROFF_PATH}/config.h.cmake ${LIBOPTS_TEAROFF_PATH}/config.h @ONLY)
    SET(AUTOGEN_VERSION ${__AUTOGEN_VERSION})
    
    INCLUDE(CheckFunctionExists)
    INCLUDE(CheckIncludeFile)
    INCLUDE(CheckSymbolExists)
    INCLUDE(CheckTypeSize)

    # Check for header files!
    check_include_file("dirent.h"       HAVE_DIRENT_H)
    check_include_file("dlfcn.h"        HAVE_DLFCN_H)
    check_include_file("errno.h"        HAVE_ERRNO_H)
    check_include_file("fcntl.h"        HAVE_FCNTL_H)
    check_include_file("inttypes.h"     HAVE_INTTYPES_H)
    check_include_file("libgen.h"       HAVE_LIBGEN_H)
    check_include_file("limits.h"       HAVE_LIMITS_H)
    check_include_file("memory.h"       HAVE_MEMORY_H)
    check_include_file("ndir.h"         HAVE_NDIR_H)
    check_include_file("netinet/in.h"   HAVE_NETINET_IN_H)
    check_include_file("runetype.h"     HAVE_RUNETYPE_H)
    check_include_file("setjmp.h"       HAVE_SETJMP_H)
    check_include_file("stdarg.h"       HAVE_STDARG_H)
    check_include_file("stdint.h"       HAVE_STDINT_H)
    check_include_file("stdlib.h"       HAVE_STDLIB_H)
    check_include_file("strings.h"      HAVE_STRINGS_H)
    check_include_file("string.h"       HAVE_STRING_H)
    check_include_file("sysexits.h"     HAVE_SYSEXITS_H)
    check_include_file("sys/dir.h"      HAVE_SYS_DIR_H)
    check_include_file("sys/limits.h"   HAVE_SYS_LIMITS_H)
    check_include_file("sys/mman.h"     HAVE_SYS_MMAN_H)
    check_include_file("sys/ndir.h"     HAVE_SYS_NDIR_H)
    check_include_file("sys/param.h"    HAVE_SYS_PARAM_H)
    check_include_file("sys/poll.h"     HAVE_SYS_POLL_H)
    check_include_file("sys/procset.h"  HAVE_SYS_PROCSET_H)
    check_include_file("sys/select.h"   HAVE_SYS_SELECT_H)
    check_include_file("sys/socket.h"   HAVE_SYS_SOCKET_H)
    check_include_file("sys/stat.h"     HAVE_SYS_STAT_H)
    check_include_file("sys/stropts.h"  HAVE_SYS_STROPTS_H)
    check_include_file("sys/time.h"     HAVE_SYS_TIME_H)
    check_include_file("sys/types.h"    HAVE_SYS_TYPES_H)
    check_include_file("sys/un.h"       HAVE_SYS_UN_H)
    check_include_file("sys/wait.h"     HAVE_SYS_WAIT_H)
    check_include_file("unistd.h"       HAVE_UNISTD_H)
    check_include_file("utime.h"        HAVE_UTIME_H)
    check_include_file("values.h"       HAVE_VALUES_H)
    check_include_file("varargs.h"      HAVE_VARARGS_H)
    check_include_file("wchar.h"        HAVE_WCHAR_H)
    
    # Check for various types
    check_type_size("char *"            SIZEOF_CHARP)
    check_type_size("int"               SIZEOF_INT)
    check_type_size("uint"              HAVE_UINT_T)
    check_type_size("long"              SIZEOF_LONG)
    check_type_size("short"             SIZEOF_SHORT)
    check_type_size("int16_t"           HAVE_INT16_T)
    check_type_size("int32_t"           HAVE_INT32_T)
    check_type_size("int8_t"            HAVE_INT8_T)
    check_type_size("uint16_t"          HAVE_UINT16_T)
    check_type_size("uint32_t"          HAVE_UINT32_T)
    check_type_size("uint8_t"           HAVE_UINT8_T)
    check_type_size("intptr_t"          HAVE_INTPTR_T)
    check_type_size("uintptr_t"         HAVE_UINTPTR_T)
    check_type_size("pid_t"             HAVE_PID_T)
    check_type_size("size_t"            HAVE_SIZE_T)
    check_type_size("wchar_t"           HAVE_WCHAR_T)
    check_type_size("wint_t"            HAVE_WINT_T)
    
    check_function_exists(vprintf       HAVE_VPRINTF)
    
ENDMACRO(CHECK_LIBOPTS)
