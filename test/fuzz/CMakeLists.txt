# test/fuzz/CMakeLists.txt - corpus replay, registered with CTest.
#
# Mirrors the default half of test/fuzz/Makefile.am: the targets are built with
# the standalone driver so the checked-in corpus runs as a regression test with
# no fuzzing toolchain present. Actual fuzzing is autotools + clang via
# --enable-fuzzer (see README.md); CMake is not wired for libFuzzer because
# OSS-Fuzz drives that build itself.

set(TCPR_FUZZ_TARGETS fuzz_services fuzz_pcap fuzz_tcpedit)
if(ENABLE_FRAGROUTE)
    list(APPEND TCPR_FUZZ_TARGETS fuzz_fragroute)
endif()

foreach(_t ${TCPR_FUZZ_TARGETS})
    # fuzz_globals.c: globals libcommon.a references but does not define
    if(_t STREQUAL fuzz_tcpedit)
        # The DLT plugins reference the tcpedit_tcpedit_optDesc_p descriptor
        # defined by the generated tcprewrite_opts.c, so compile it into the
        # target like tcprewrite itself does.
        add_executable(${_t} ${_t}.c fuzz_globals.c ${tcprewrite_opts_SOURCE})
    else()
        add_executable(${_t} ${_t}.c fuzz_globals.c)
    endif()
    target_compile_definitions(${_t} PRIVATE FUZZ_STANDALONE)
    target_include_directories(${_t} PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR})
    if(_t STREQUAL fuzz_tcpedit)
        # tcpedit.h/portmap.h live in src/tcpedit; the generated
        # tcprewrite_opts.h is already reachable through src/.
        target_include_directories(${_t} PRIVATE
            ${CMAKE_SOURCE_DIR}/src/tcpedit)
    endif()
    # fragroute first: it calls into common and libdnet, and a static archive
    # only resolves backwards
    if(ENABLE_FRAGROUTE)
        target_link_libraries(${_t} PRIVATE fragroute)
    endif()
    if(_t STREQUAL fuzz_tcpedit)
        target_link_libraries(${_t} PRIVATE tcpedit opts)
    endif()
    target_link_libraries(${_t} PRIVATE common
        ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
endforeach()

add_test(NAME fuzz_corpus
         COMMAND ${CMAKE_COMMAND} -E env srcdir=${CMAKE_CURRENT_SOURCE_DIR}
                 ${CMAKE_CURRENT_SOURCE_DIR}/run-corpus.sh
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
