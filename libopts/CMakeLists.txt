# libopts/CMakeLists.txt — the AutoOpts "tearoff" library.
# libopts.c #includes every other translation unit, so this is a single-TU build
# (same as libopts/Makefile.am's libopts_la_SOURCES = libopts.c).

add_library(opts STATIC libopts.c)
target_include_directories(opts PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/autoopts)
target_include_directories(opts PRIVATE ${TCPR_GENERATED_INCLUDE_DIRS})
# The tearoff triggers plenty of warnings on modern compilers; it is vendored
# code we don't maintain, so keep the build output focused on our own sources.
target_compile_options(opts PRIVATE -w)
