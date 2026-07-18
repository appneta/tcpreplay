# src/CMakeLists.txt — the six binaries (mirrors src/Makefile.am).

# netmap flags are applied here, after configure-time detection has finished,
# for the same reason configure.ac defers NETMAP_CFLAGS until just before
# AC_OUTPUT (a netmap checkout shadows system headers like net/bpf.h).
if(HAVE_NETMAP)
    add_compile_definitions(NETMAP_WITH_LIBS)
    include_directories(${NETMAP_INCLUDE_DIR})
endif()

add_subdirectory(common)
add_subdirectory(tcpedit)
if(ENABLE_FRAGROUTE)
    add_subdirectory(fragroute)
endif()

# ---------------------------------------------------------------------------
# AutoOpts code generation (*_opts.def → *_opts.c/h)
# ---------------------------------------------------------------------------
# Search path matches src/Makefile.am's `opts_list = -L tcpedit`.
set(TCPR_AUTOGEN_OPTS_DIR ${CMAKE_CURRENT_BINARY_DIR})

# tcpr_autogen_opts(<base> <def-file> [FLAGS ...] [DEPENDS ...])
# Defines <base>_SOURCE pointing at the generated (or pre-generated) .c file.
#
# A pre-generated ${base}.h in the source directory always shadows the
# build-dir copy: the C sources include it with #include "..." and the
# quote-include search looks in the including file's own directory first.
# So when source-dir copies exist (release tarballs) they are used wholesale
# and must be up to date vs their .def inputs - generating a second copy in
# the build dir would mix a fresh .c with a shadowing stale .h and fail with
# 'INDEX_OPT_* undeclared' errors (#1020).
function(tcpr_autogen_opts base def)
    cmake_parse_arguments(ARG "" "" "FLAGS;DEPENDS" ${ARGN})
    set(_insrc_c ${CMAKE_CURRENT_SOURCE_DIR}/${base}.c)
    set(_insrc_h ${CMAKE_CURRENT_SOURCE_DIR}/${base}.h)
    if(EXISTS ${_insrc_c} OR EXISTS ${_insrc_h})
        set(_stale "")
        foreach(_f ${_insrc_c} ${_insrc_h})
            if(NOT EXISTS ${_f})
                set(_stale ${_f})
            else()
                foreach(_dep ${def} ${ARG_DEPENDS})
                    if(${_dep} IS_NEWER_THAN ${_f})
                        set(_stale ${_f})
                    endif()
                endforeach()
            endif()
        endforeach()
        if(_stale)
            message(FATAL_ERROR
                "Stale pre-generated AutoOpts file in the source tree: ${_stale} is missing or "
                "older than ${def}. Source-dir copies shadow the build-dir copies for "
                "quote-includes and would break the build with 'INDEX_OPT_* undeclared' errors "
                "(see issue #1020). Remove them and re-run cmake:\n"
                "  rm -f ${_insrc_c} ${_insrc_h}\n"
                "In a git checkout, 'git clean -fx src' removes all leftover generated files.")
        endif()
        # up-to-date pre-generated copies (e.g. a release tarball) - use them as-is
        set(${base}_SOURCE ${_insrc_c} PARENT_SCOPE)
    elseif(AUTOGEN_EXECUTABLE)
        add_custom_command(
            OUTPUT ${TCPR_AUTOGEN_OPTS_DIR}/${base}.c ${TCPR_AUTOGEN_OPTS_DIR}/${base}.h
            COMMAND ${AUTOGEN_EXECUTABLE}
                    -L ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit
                    ${ARG_FLAGS}
                    -b ${base}
                    ${def}
            DEPENDS ${def} ${ARG_DEPENDS}
            WORKING_DIRECTORY ${TCPR_AUTOGEN_OPTS_DIR}
            COMMENT "Generating ${base}.c with autogen")
        set(${base}_SOURCE ${TCPR_AUTOGEN_OPTS_DIR}/${base}.c PARENT_SCOPE)
    else()
        message(FATAL_ERROR
            "No pre-generated ${base}.c and GNU autogen is not installed. "
            "Install autogen if you are building from a git checkout.")
    endif()
endfunction()

set(NETMAP_AUTOGEN_FLAGS "")
if(HAVE_NETMAP)
    set(NETMAP_AUTOGEN_FLAGS -DHAVE_NETMAP)
endif()

set(TCPEDIT_OPTS_DEF ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit/tcpedit_opts.def)

tcpr_autogen_opts(tcpreplay_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def
    FLAGS ${NETMAP_AUTOGEN_FLAGS})
tcpr_autogen_opts(tcpreplay_edit_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def
    FLAGS ${NETMAP_AUTOGEN_FLAGS} -DTCPREPLAY_EDIT)
tcpr_autogen_opts(tcprewrite_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcprewrite_opts.def
    DEPENDS ${TCPEDIT_OPTS_DEF})
tcpr_autogen_opts(tcpprep_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpprep_opts.def)
tcpr_autogen_opts(tcpbridge_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpbridge_opts.def
    DEPENDS ${TCPEDIT_OPTS_DEF})
tcpr_autogen_opts(tcpliveplay_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpliveplay_opts.def)
tcpr_autogen_opts(tcpcapinfo_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpcapinfo_opts.def)

# ---------------------------------------------------------------------------
# Shared link interface
# ---------------------------------------------------------------------------
set(TCPR_COMMON_LIBS common opts ${PCAP_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
set(TCPR_OSX_FRAMEWORKS "")
if(APPLE)
    set(TCPR_OSX_FRAMEWORKS "-framework CoreServices" "-framework Carbon")
endif()

macro(tcpr_binary_common target)
    target_include_directories(${target} PRIVATE
        ${TCPR_AUTOGEN_OPTS_DIR}
        ${TCPR_GENERATED_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${TCPR_SOURCE_INCLUDE_DIRS}
        ${PCAP_INCLUDE_DIR})
    if(LNAV_CFLAGS)
        target_compile_options(${target} PRIVATE ${LNAV_CFLAGS})
    endif()
    if(DNET_CFLAGS)
        target_compile_options(${target} PRIVATE ${DNET_CFLAGS})
    endif()
endmacro()

# ---------------------------------------------------------------------------
# tcpreplay
# ---------------------------------------------------------------------------
set(TCPREPLAY_CORE_SOURCES send_packets.c signal_handler.c tcpreplay.c tcpreplay_api.c sleep.c replay.c)

add_executable(tcpreplay_bin ${tcpreplay_opts_SOURCE} ${TCPREPLAY_CORE_SOURCES})
set_target_properties(tcpreplay_bin PROPERTIES OUTPUT_NAME tcpreplay)
target_compile_definitions(tcpreplay_bin PRIVATE TCPREPLAY)
tcpr_binary_common(tcpreplay_bin)
target_link_libraries(tcpreplay_bin PRIVATE ${TCPR_COMMON_LIBS} ${DNET_LIBRARIES} ${TCPR_OSX_FRAMEWORKS})

# ---------------------------------------------------------------------------
# tcpreplay-edit
# ---------------------------------------------------------------------------
add_executable(tcpreplay_edit ${tcpreplay_edit_opts_SOURCE} ${TCPREPLAY_CORE_SOURCES})
set_target_properties(tcpreplay_edit PROPERTIES OUTPUT_NAME tcpreplay-edit)
target_compile_definitions(tcpreplay_edit PRIVATE TCPREPLAY TCPREPLAY_EDIT HAVE_CACHEFILE_SUPPORT)
tcpr_binary_common(tcpreplay_edit)
target_include_directories(tcpreplay_edit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit)
target_link_libraries(tcpreplay_edit PRIVATE tcpedit ${TCPR_COMMON_LIBS} ${DNET_LIBRARIES} ${TCPR_OSX_FRAMEWORKS})

# ---------------------------------------------------------------------------
# tcprewrite
# ---------------------------------------------------------------------------
add_executable(tcprewrite ${tcprewrite_opts_SOURCE} tcprewrite.c)
target_compile_definitions(tcprewrite PRIVATE TCPREWRITE HAVE_CACHEFILE_SUPPORT)
tcpr_binary_common(tcprewrite)
target_include_directories(tcprewrite PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit)
target_link_libraries(tcprewrite PRIVATE tcpedit ${TCPR_COMMON_LIBS} ${DMALLOC_LIB})
if(ENABLE_FRAGROUTE)
    target_link_libraries(tcprewrite PRIVATE fragroute ${DNET_LIBRARIES})
endif()

# ---------------------------------------------------------------------------
# tcpprep
# ---------------------------------------------------------------------------
add_executable(tcpprep ${tcpprep_opts_SOURCE} tcpprep.c tree.c tcpprep_api.c)
target_compile_definitions(tcpprep PRIVATE TCPPREP)
tcpr_binary_common(tcpprep)
target_link_libraries(tcpprep PRIVATE ${TCPR_COMMON_LIBS} ${DMALLOC_LIB})

# ---------------------------------------------------------------------------
# tcpcapinfo
# ---------------------------------------------------------------------------
add_executable(tcpcapinfo ${tcpcapinfo_opts_SOURCE} tcpcapinfo.c)
target_compile_definitions(tcpcapinfo PRIVATE TCPCAPINFO)
tcpr_binary_common(tcpcapinfo)
target_link_libraries(tcpcapinfo PRIVATE ${TCPR_COMMON_LIBS} ${DMALLOC_LIB})

set(TCPR_INSTALL_TARGETS tcpreplay_bin tcpreplay_edit tcprewrite tcpprep tcpcapinfo)

# ---------------------------------------------------------------------------
# tcpbridge (conditional)
# ---------------------------------------------------------------------------
if(ENABLE_TCPBRIDGE)
    add_executable(tcpbridge ${tcpbridge_opts_SOURCE} tcpbridge.c bridge.c)
    target_compile_definitions(tcpbridge PRIVATE TCPBRIDGE)
    tcpr_binary_common(tcpbridge)
    target_include_directories(tcpbridge PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit)
    target_link_libraries(tcpbridge PRIVATE tcpedit ${TCPR_COMMON_LIBS} ${DNET_LIBRARIES}
                          ${DMALLOC_LIB} ${TCPR_OSX_FRAMEWORKS})
    list(APPEND TCPR_INSTALL_TARGETS tcpbridge)
endif()

# ---------------------------------------------------------------------------
# tcpliveplay (linux only)
# ---------------------------------------------------------------------------
if(ENABLE_TCPLIVEPLAY)
    add_executable(tcpliveplay ${tcpliveplay_opts_SOURCE} tcpliveplay.c)
    target_compile_definitions(tcpliveplay PRIVATE TCPREPLAY TCPLIVEPLAY)
    tcpr_binary_common(tcpliveplay)
    target_link_libraries(tcpliveplay PRIVATE ${TCPR_COMMON_LIBS} ${DNET_LIBRARIES})
    list(APPEND TCPR_INSTALL_TARGETS tcpliveplay)
endif()

install(TARGETS ${TCPR_INSTALL_TARGETS} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

# ---------------------------------------------------------------------------
# man pages (optional target, requires autogen; mirrors the manpages target)
# ---------------------------------------------------------------------------
if(AUTOGEN_EXECUTABLE)
    set(_manpages "")
    foreach(_man tcpprep tcprewrite tcpreplay tcpbridge tcpliveplay tcpcapinfo)
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_man}.1
            COMMAND ${AUTOGEN_EXECUTABLE} -T agman-cmd.tpl
                    -L ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_man}_opts.def
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_man}_opts.def
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating ${_man}.1")
        list(APPEND _manpages ${CMAKE_CURRENT_BINARY_DIR}/${_man}.1)
    endforeach()
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/tcpreplay-edit.1
        COMMAND ${AUTOGEN_EXECUTABLE} -T agman-cmd.tpl
                -L ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit
                -DTCPREPLAY_EDIT -DTCPREPLAY_EDIT_MAN
                -b tcpreplay-edit
                ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating tcpreplay-edit.1")
    list(APPEND _manpages ${CMAKE_CURRENT_BINARY_DIR}/tcpreplay-edit.1)
    add_custom_target(manpages DEPENDS ${_manpages})
endif()
