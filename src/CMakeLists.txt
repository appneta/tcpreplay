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
# AutoOpts code generation (*_opts.def → *_opts.c/h, *.adoc man-page source)
# ---------------------------------------------------------------------------
# Unlike src/tcpedit/tcpedit_stub.h, none of these generated files are
# committed to git (see .gitignore) - they're ordinary build products,
# matching this project's original convention (nothing generated was ever
# committed; a release tarball ships the already-built output via 'make
# dist'). scripts/autoopts (python3) replaces GNU autogen for these targets
# - see scripts/autoopts/README.md - so python3 (and asciidoctor, for the
# man pages) is needed for any build from a git checkout, exactly like
# autogen used to be, except neither tool is EOL. Regeneration happens here
# at configure time, in the source tree, so the build graph never runs it
# (and cannot race on its outputs). autogen remains required only for
# src/tcpedit/tcpedit_stub.h (further down in this file), a distinct
# AutoOpts template mode not yet ported to scripts/autoopts - that one file
# stays committed since autogen genuinely is EOL.
set(TCPR_AUTOGEN_OPTS_DIR ${CMAKE_CURRENT_BINARY_DIR})
set(AUTOOPTS_DIR ${CMAKE_SOURCE_DIR}/scripts/autoopts)

# tcpr_autogen_opts(<base> <def-file> [MANBASE name] [DEFINES sym] [DEPENDS ...])
# Defines <base>_SOURCE pointing at the (re)generated .c file in the source
# tree.  MANBASE (the man page/adoc basename, e.g. "tcpreplay-edit" for base
# "tcpreplay_edit_opts") defaults to <base> with any trailing "_opts"
# stripped.
function(tcpr_autogen_opts base def)
    cmake_parse_arguments(ARG "" "MANBASE;DEFINES" "DEPENDS" ${ARGN})
    if(ARG_MANBASE)
        set(_manbase ${ARG_MANBASE})
    else()
        string(REGEX REPLACE "_opts$" "" _manbase ${base})
    endif()
    set(_out_c ${CMAKE_CURRENT_SOURCE_DIR}/${base}.c)
    set(_out_h ${CMAKE_CURRENT_SOURCE_DIR}/${base}.h)
    set(_out_adoc ${CMAKE_CURRENT_SOURCE_DIR}/${_manbase}.adoc)
    # strictly-newer comparison (like make): IS_NEWER_THAN treats equal
    # timestamps as newer, which a fresh git checkout produces for every file
    set(_stale FALSE)
    foreach(_f ${_out_c} ${_out_h} ${_out_adoc})
        if(NOT EXISTS ${_f})
            set(_stale TRUE)
        else()
            file(TIMESTAMP ${_f} _f_ts "%s" UTC)
            foreach(_dep ${def} ${ARG_DEPENDS})
                file(TIMESTAMP ${_dep} _dep_ts "%s" UTC)
                if(_dep_ts GREATER _f_ts)
                    set(_stale TRUE)
                endif()
            endforeach()
        endif()
    endforeach()
    if(_stale)
        if(PYTHON3_EXECUTABLE)
            message(STATUS "Regenerating ${base}.c/h and ${_manbase}.adoc with python3")
            execute_process(
                COMMAND ${PYTHON3_EXECUTABLE} ${AUTOOPTS_DIR}/emit_h.py ${base} ${def} "${ARG_DEFINES}"
                OUTPUT_FILE ${_out_h}
                RESULT_VARIABLE _rc)
            if(NOT _rc EQUAL 0)
                message(FATAL_ERROR "emit_h.py failed regenerating ${base}.h from ${def}")
            endif()
            execute_process(
                COMMAND ${PYTHON3_EXECUTABLE} ${AUTOOPTS_DIR}/emit_c.py ${base} ${def} "${ARG_DEFINES}"
                OUTPUT_FILE ${_out_c}
                RESULT_VARIABLE _rc)
            if(NOT _rc EQUAL 0)
                message(FATAL_ERROR "emit_c.py failed regenerating ${base}.c from ${def}")
            endif()
            execute_process(
                COMMAND ${PYTHON3_EXECUTABLE} ${AUTOOPTS_DIR}/emit_adoc.py ${_manbase} ${def} "${ARG_DEFINES}"
                OUTPUT_FILE ${_out_adoc}
                RESULT_VARIABLE _rc)
            if(NOT _rc EQUAL 0)
                message(FATAL_ERROR "emit_adoc.py failed regenerating ${_manbase}.adoc from ${def}")
            endif()
        else()
            message(FATAL_ERROR
                "${base}.c/h or ${_manbase}.adoc is missing or older than ${def}, and python3 is "
                "not installed. Install python3 to regenerate them, or if the .def content is "
                "unchanged refresh the timestamps:\n  touch src/*_opts.c src/*_opts.h src/*.adoc")
        endif()
    endif()
    set(${base}_SOURCE ${_out_c} PARENT_SCOPE)
endfunction()

set(TCPEDIT_OPTS_DEF ${CMAKE_CURRENT_SOURCE_DIR}/tcpedit/tcpedit_opts.def)

tcpr_autogen_opts(tcpreplay_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def)
tcpr_autogen_opts(tcpreplay_edit_opts ${CMAKE_CURRENT_SOURCE_DIR}/tcpreplay_opts.def
    MANBASE tcpreplay-edit DEFINES TCPREPLAY_EDIT)
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
# libtcpreplay - installable static library exposing tcpreplay_api.h (#133)
# (mirrors the lib_LIBRARIES/tcpreplayinclude_HEADERS rules in Makefile.am)
# ---------------------------------------------------------------------------
add_library(tcpreplay_static STATIC
    ${tcpreplay_opts_SOURCE}
    send_packets.c signal_handler.c tcpreplay_api.c sleep.c replay.c
    libtcpreplay_globals.c
    $<TARGET_OBJECTS:common_obj>
    $<TARGET_OBJECTS:opts_obj>)
if(NOT HAVE_STRLCPY)
    target_sources(tcpreplay_static PRIVATE $<TARGET_OBJECTS:strl_obj>)
endif()
set_target_properties(tcpreplay_static PROPERTIES OUTPUT_NAME tcpreplay)
target_compile_definitions(tcpreplay_static PRIVATE TCPREPLAY)
tcpr_binary_common(tcpreplay_static)
target_include_directories(tcpreplay_static PRIVATE
    ${CMAKE_SOURCE_DIR}/libopts ${CMAKE_SOURCE_DIR}/libopts/autoopts)
if(HAVE_NETMAP)
    # tcpreplay_api.h (via common/sendpacket.h) conditionally includes
    # net/netmap.h, so any consumer compiling against the installed headers
    # needs these too - PUBLIC exports them as usage requirements. The plain
    # include_directories()/add_compile_definitions() above only cover
    # targets under this directory (src/ and its subdirectories); they don't
    # reach sibling directories like examples/, added separately from the
    # top-level CMakeLists.txt.
    target_include_directories(tcpreplay_static PUBLIC ${NETMAP_INCLUDE_DIR})
    target_compile_definitions(tcpreplay_static PUBLIC NETMAP_WITH_LIBS)
endif()

install(TARGETS tcpreplay_static ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
install(FILES tcpreplay_api.h tcpreplay.h tcpr.h common.h
        ${CMAKE_BINARY_DIR}/src/defines.h ${CMAKE_BINARY_DIR}/src/config.h
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/tcpreplay)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/common/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/include/tcpreplay/common
        FILES_MATCHING PATTERN "*.h")

# libtcpreplay.pc: reuse the autotools template; the tearoff is always folded
# into the archive in CMake builds so no -lopts is needed
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${exec_prefix}/lib")
set(includedir "\${prefix}/include")
set(VERSION ${PROJECT_VERSION})
# entries may be bare library names or ready-made -l/-L/absolute-path flags
function(tcpr_pc_libs out)
    set(_flags "")
    foreach(_l ${ARGN})
        if(_l MATCHES "^-" OR _l MATCHES "^/")
            list(APPEND _flags "${_l}")
        else()
            list(APPEND _flags "-l${_l}")
        endif()
    endforeach()
    string(REPLACE ";" " " _s "${_flags}")
    set(${out} "${_s}" PARENT_SCOPE)
endfunction()
tcpr_pc_libs(LPCAPLIB ${PCAP_LIBRARIES})
tcpr_pc_libs(LDNETLIB ${DNET_LIBRARIES})
tcpr_pc_libs(LIBS ${TCPR_SYSTEM_LIBS})
set(LIBTCPREPLAY_PCLIBS "")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libtcpreplay.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/libtcpreplay.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libtcpreplay.pc
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/pkgconfig)

# ---------------------------------------------------------------------------
# man pages (optional target, requires asciidoctor; mirrors the autotools
# manpages target).  Renders from the .adoc source in the source tree (kept
# current by tcpr_autogen_opts() above) into the build tree, so a plain
# `cmake --build` never needs asciidoctor - only `--target manpages` does.
# ---------------------------------------------------------------------------
if(ASCIIDOCTOR_EXECUTABLE)
    set(_manpages "")
    foreach(_man tcpprep tcprewrite tcpreplay tcpbridge tcpliveplay tcpcapinfo tcpreplay-edit)
        add_custom_command(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_man}.1
            COMMAND ${ASCIIDOCTOR_EXECUTABLE} -b manpage
                    -o ${CMAKE_CURRENT_BINARY_DIR}/${_man}.1
                    ${CMAKE_CURRENT_SOURCE_DIR}/${_man}.adoc
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_man}.adoc
            COMMENT "Generating ${_man}.1")
        list(APPEND _manpages ${CMAKE_CURRENT_BINARY_DIR}/${_man}.1)
    endforeach()
    add_custom_target(manpages DEPENDS ${_manpages})
endif()
