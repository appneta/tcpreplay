# Generates git_version.c (mirrors src/common/Makefile.am's git_version.c rule).
# Invoked at build time:
#   cmake -DOUTPUT=<path> -DSOURCE_DIR=<repo root> -P GitVersion.cmake

execute_process(
    COMMAND git describe --always
    WORKING_DIRECTORY "${SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_DESCRIBE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE GIT_RESULT)

if(NOT GIT_RESULT EQUAL 0 OR GIT_DESCRIBE STREQUAL "")
    set(GIT_DESCRIBE "unknown")
endif()

set(CONTENT "const char GIT_Version[] = \"git:${GIT_DESCRIBE}\";
const char *git_version(void) {
    return GIT_Version;
}
")

# Only rewrite when changed so we don't trigger needless rebuilds
if(EXISTS "${OUTPUT}")
    file(READ "${OUTPUT}" OLD_CONTENT)
else()
    set(OLD_CONTENT "")
endif()

if(NOT OLD_CONTENT STREQUAL CONTENT)
    file(WRITE "${OUTPUT}" "${CONTENT}")
endif()
