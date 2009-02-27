find_program(SVNVERSION svnversion)
set(WC_REVISION unknown)
if(EXISTS ${CMAKE_SOURCE_DIR}/.svn)
    if(SVNVERSION)
        execute_process(COMMAND ${SVNVERSION} -n .
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE WC_REVISION)
    else(SVNVERSION)
        message(STATUS "Missing SVNVERSION! ${SVNVERSION}")
    endif(SVNVERSION)
else(EXISTS ${CMAKE_SOURCE_DIR}/.svn)
    set(WC_REVISION exported)
endif(EXISTS ${CMAKE_SOURCE_DIR}/.svn)

configure_file(${CMAKE_SOURCE_DIR}/svn_version.tmpl ${CMAKE_BINARY_DIR}/svn_version.c @ONLY)
