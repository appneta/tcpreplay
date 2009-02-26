# Check to see if we build with tcpdump/verbose support
set(tcpdump_src)
if(TCPDUMP_BINARY)
    if(WIN32)
        message(STATUS "Unable to build verbose support under Win32")    
    else(WIN32)
        set(tcpdump_src tcpdump.c)
    endif(WIN32)
else(TCPDUMP_BINARY)
    message(STATUS "Unable to build verbose support without tcpdump")
endif(TCPDUMP_BINARY)


add_library(common STATIC abort.c cache.c cidr.c dlt_names.c err.c fakepcap.c 
	fakepcapnav.c fakepoll.c get.c interface.c list.c mac.c rdtsc.c
	sendpacket.c services.c timer.c utils.c xX.c ${tcpdump_src} svn_version.c)

if(Subversion_FOUND)
    Subversion_WC_INFO(${CMAKE_SOURCE_DIR} SVN_INFO)
    if(NOT SVN_INFO_WC_REVISION STREQUAL "exported")

        # Targets to build src/common/svn_version.c
        add_custom_target(svn_version_c
            DEPENDS svn_version.c)

        add_custom_command(OUTPUT svn_version.c
            COMMAND cmake -P GenerateVersion.cmake
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/common
            DEPENDS ${CMAKE_SOURCE_DIR}/src/common/GenerateVersion.cmake ${CMAKE_SOURCE_DIR}/src/common/svn_version.tmpl
            VERBATIM)
    endif(NOT SVN_INFO_WC_REVISION STREQUAL "exported")

    add_custom_target(version)
    add_custom_command(TARGET version
        COMMAND cmake -P DeleteVersion.cmake)
    add_dependencies(version svn_version_c)
endif(Subversion_FOUND)


# 
# if(NOT EXISTS svn_version.c)
# execute_process(COMMAND ${CMAKE_C_COMPILER} -E -DWC_REVISION=\"${WC_REVISION}\" -
#     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/common
#     INPUT_FILE svn_version.tmpl
#     OUTPUT_FILE svn_version.c
# )
# endif(NOT EXISTS svn_version.c)
