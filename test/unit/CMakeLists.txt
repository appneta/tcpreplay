# test/unit/CMakeLists.txt - unit tests, registered with CTest.
#
# Mirrors test/unit/Makefile.am.  Run with `ctest --test-dir build`, or
# `cmake --build build --target test`.  The tests report TAP-shaped output and
# use automake's standard exit codes, which CTest reads directly: 0 pass,
# 1 fail, 77 skip (declared via SKIP_RETURN_CODE below).

set(TCPR_UNIT_TESTS test_txring test_get_ipv6)

foreach(_test ${TCPR_UNIT_TESTS})
    # unit_globals.c: globals libcommon.a references but does not define
    add_executable(${_test} ${_test}.c unit_globals.c)
    target_include_directories(${_test} PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR})
    if(DNET_CFLAGS)
        target_compile_options(${_test} PRIVATE ${DNET_CFLAGS})
    endif()
    target_link_libraries(${_test} PRIVATE common
        ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
    add_test(NAME ${_test} COMMAND ${_test})
    # automake's standard "this test does not apply here" code
    set_tests_properties(${_test} PROPERTIES SKIP_RETURN_CODE 77)
endforeach()

# test_fragroute links libfragroute, so it only exists where libdnet does
if(ENABLE_FRAGROUTE)
    add_executable(test_fragroute test_fragroute.c unit_globals.c)
    target_include_directories(test_fragroute PRIVATE
        ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR})
    if(DNET_CFLAGS)
        target_compile_options(test_fragroute PRIVATE ${DNET_CFLAGS})
    endif()
    # fragroute before common: it calls into common, static archives resolve backwards
    target_link_libraries(test_fragroute PRIVATE fragroute common
        ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
    add_test(NAME test_fragroute COMMAND test_fragroute)
    set_tests_properties(test_fragroute PROPERTIES SKIP_RETURN_CODE 77)
endif()
