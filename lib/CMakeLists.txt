# lib/CMakeLists.txt — vendored strlcpy/strlcat, only when libc lacks them
# (mirrors lib/Makefile.am's SYSTEM_STRLCPY conditional).

if(NOT HAVE_STRLCPY)
    # object library so the installable libtcpreplay archive can fold these
    # objects in (#133); the 'strl' static wrapper keeps consumers unchanged
    add_library(strl_obj OBJECT strlcat.c strlcpy.c)
    target_include_directories(strl_obj PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS})
    add_library(strl STATIC $<TARGET_OBJECTS:strl_obj>)
endif()
