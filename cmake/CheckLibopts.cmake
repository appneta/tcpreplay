# All the tests necessary for libopts go here.  Note that this is not for
# checking if libopts/AutoGen/AutoOpts is installed on your system, but 
# rather for doing a compatibility check for your libopts tearoff

########################################################
# You probably don't want to change anything below here!
########################################################

# Takes the path to the tearoff directory & the version of autogen
MACRO(CHECK_LIBOPTS_TEAROFF LIBOPTS_TEAROFF_PATH __AUTOGEN_VERSION)
    SET(AUTOGEN_VERSION ${__AUTOGEN_VERSION})
    
    INCLUDE(CheckFunctionExists)
    INCLUDE(CheckIncludeFile)
    INCLUDE(CheckSymbolExists)
    INCLUDE(CheckTypeSize)
    INCLUDE(CheckCSourceRuns)

    # Check for /dev/zero
    SET(HAVE_DEV_ZERO 0)
    IF(EXISTS /dev/zero)
        SET(HAVE_DEV_ZERO 1)
    ENDIF(EXISTS /dev/zero)
    
    # Check for header files!
    check_include_file("dirent.h"       HAVE_DIRENT_H)
    check_include_file("dlfcn.h"        HAVE_DLFCN_H)
    check_include_file("errno.h"        HAVE_ERRNO_H)
    check_include_file("fcntl.h"        HAVE_FCNTL_H)
    check_include_file("float.h"        HAVE_FLOAT_H)
    check_include_file("inttypes.h"     HAVE_INTTYPES_H)
    check_include_file("libgen.h"       HAVE_LIBGEN_H)
    check_include_file("limits.h"       HAVE_LIMITS_H)
    check_include_file("memory.h"       HAVE_MEMORY_H)
    check_include_file("ndir.h"         HAVE_NDIR_H)
    check_include_file("netinet/in.h"   HAVE_NETINET_IN_H)
    check_include_file("runetype.h"     HAVE_RUNETYPE_H)
    check_include_file("setjmp.h"       HAVE_SETJMP_H)
    check_include_file("stdarg.h"       HAVE_STDARG_H)
    check_include_file("stddef.h"       HAVE_STDDEF_H)
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
    
    # Not quite as good as the real autoconf AC_HEADER_STDC test, but prolly good enough
    IF(HAVE_STDLIB_H AND HAVE_STDARG_H AND HAVE_STRING_H AND HAVE_FLOAT_H)
        check_function_exists(free          HAVE_FREE)
        check_function_exists(memchr        HAVE_MEMCHR)
        IF(HAVE_FREE AND HAVE_MEMCHR)
            SET(STDC_HEADERS 1)
        ENDIF(HAVE_FREE AND HAVE_MEMCHR)
    ENDIF(HAVE_STDLIB_H AND HAVE_STDARG_H AND HAVE_STRING_H AND HAVE_FLOAT_H)

    # Check for various types
    check_type_size("char *"            SIZEOF_CHARP)
    check_type_size("int"               SIZEOF_INT)
    check_type_size("uint_t"            HAVE_UINT_T)
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

    # OSX doesn't define wint_t in one of the standard include headers
    IF(NOT HAVE_WINT_T AND HAVE_WCHAR_H)
        check_c_source_compiles("
#include <wchar.h>
static void testcb(wint_t w) { }
int main() {
  wint_t w = 0;
  testcb(w);
  return 0;
}
"
           HAVE_WINT_T)
    ENDIF(NOT HAVE_WINT_T AND HAVE_WCHAR_H)

    check_function_exists(strftime      HAVE_STRFTIME)
    check_function_exists(canonicalize_file_name HAVE_CANONICALIZE_FILE_NAME)
    check_function_exists(mmap          HAVE_MMAP)
    check_function_exists(realpath      HAVE_REALPATH)
    check_function_exists(snprintf      HAVE_SNPRINTF)
    check_function_exists(strchr        HAVE_STRCHR)
    check_function_exists(strdup        HAVE_STRDUP)
    check_function_exists(strrchr       HAVE_STRRCHR)
    check_function_exists(strsignal     HAVE_STRSIGNAL)
    check_function_exists(vprintf       HAVE_VPRINTF)
    
    # only check for _doprnt if vfprintf doesn't exist
    IF(NOT HAVE_VPRINTF)
        check_function_exists(_doprnt   HAVE_DOPRNT)
    ENDIF(NOT HAVE_VPRINTF)

    # Check for fopen 'b' mode flag, set to "b" if available
    SET(FOPEN_BINARY_FLAG "")
    check_c_source_runs("
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    FILE *fd;
    
    if ((fd = fopen(\"foo\", \"w+b\")) < 0)
        return 1;
    else
        fclose(fd);
    return 0;
}
"
    FOPEN_BINARY_FLAG_RESULT)

    IF(FOPEN_BINARY_FLAG_RESULT EQUAL 1)
        message(STATUS "fopen supports the \"b\" flag")
        SET(FOPEN_BINARY_FLAG "\"b\"")
    ELSE(FOPEN_BINARY_FLAG_RESULT EQUAL 1)
        message(STATUS "fopen does not support the \"b\"")
    ENDIF(FOPEN_BINARY_FLAG_RESULT EQUAL 1)
    
    # Check for fopen 't' mode flag, set to "t" if available
    SET(FOPEN_TEXT_FLAG "")
    check_c_source_runs("
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
    FILE *fd;
    
    if ((fd = fopen(\"foo\", \"w+t\")) < 0)
        return 1;
    else
        fclose(fd);
    return 0;
}
"
    FOPEN_TEXT_FLAG_RESULT)

    IF(FOPEN_TEXT_FLAG_RESULT EQUAL 1)
        message(STATUS "fopen supports the \"t\" flag")
        SET(FOPEN_TEXT_FLAG "\"t\"")
    ELSE(FOPEN_TEXT_FLAG_RESULT EQUAL 1)
        message(STATUS "fopen does not support the \"t\" flag")
    ENDIF(FOPEN_TEXT_FLAG_RESULT EQUAL 1)

    ADD_SUBDIRECTORY(${LIBOPTS_TEAROFF_PATH})    
ENDMACRO(CHECK_LIBOPTS_TEAROFF)
