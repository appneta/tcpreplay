# test/fuzz/CMakeLists.txt - corpus replay, registered with CTest.
#
# Mirrors the default half of test/fuzz/Makefile.am: the targets are built with
# the standalone driver so the checked-in corpus runs as a regression test with
# no fuzzing toolchain present. Actual fuzzing is autotools + clang via
# --enable-fuzzer (see README.md); CMake is not wired for libFuzzer because
# OSS-Fuzz drives that build itself.

set(TCPR_FUZZ_TARGETS fuzz_services fuzz_pcap)
if(ENABLE_FRAGROUTE)
    list(APPEND TCPR_FUZZ_TARGETS fuzz_fragroute)
endif()

foreach(_t ${TCPR_FUZZ_TARGETS})
    # fuzz_globals.c: globals libcommon.a references but does not define
    add_executable(${_t} ${_t}.c fuzz_globals.c)
    target_compile_definitions(${_t} PRIVATE FUZZ_STANDALONE)
    target_include_directories(${_t} PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR})
    if(DNET_CFLAGS)
        target_compile_options(${_t} PRIVATE ${DNET_CFLAGS})
    endif()
    # fragroute first: it calls into common and libdnet, and a static archive
    # only resolves backwards
    if(ENABLE_FRAGROUTE)
        target_link_libraries(${_t} PRIVATE fragroute)
    endif()
    target_link_libraries(${_t} PRIVATE common
        ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
endforeach()

add_test(NAME fuzz_corpus
         COMMAND ${CMAKE_COMMAND} -E env srcdir=${CMAKE_CURRENT_SOURCE_DIR}
                 ${CMAKE_CURRENT_SOURCE_DIR}/run-corpus.sh
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
