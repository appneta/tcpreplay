# lib/CMakeLists.txt — vendored strlcpy/strlcat, only when libc lacks them
# (mirrors lib/Makefile.am's SYSTEM_STRLCPY conditional).

if(NOT HAVE_STRLCPY)
    add_library(strl STATIC strlcat.c strlcpy.c)
    target_include_directories(strl PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS})
endif()
