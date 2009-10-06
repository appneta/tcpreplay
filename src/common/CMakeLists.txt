INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src)

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


add_library(common STATIC cache.c cidr.c dlt_names.c err.c fakepcap.c
    fakepcapnav.c fakepoll.c get.c interface.c list.c mac.c rdtsc.c
    sendpacket.c services.c timer.c utils.c xX.c ${tcpdump_src} svn_version.c)

add_custom_target(version)

if(Subversion_FOUND AND EXISTS ${CMAKE_SOURCE_DIR}/.svn)
    Subversion_WC_INFO(${CMAKE_SOURCE_DIR} SVN_INFO)
    if(NOT SVN_INFO_WC_REVISION STREQUAL "exported")

        add_custom_command(OUTPUT svn_version.c
            COMMAND cmake -P GenerateVersion.cmake
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/common
            DEPENDS ${CMAKE_SOURCE_DIR}/src/common/GenerateVersion.cmake ${CMAKE_SOURCE_DIR}/src/common/svn_version.tmpl
            VERBATIM)

        # Targets to build src/common/svn_version.c
        add_custom_target(svn_version_c
            DEPENDS svn_version.c)

        set_source_files_properties(svn_version.c
            PROPERTIES GENERATED true)

    endif(NOT SVN_INFO_WC_REVISION STREQUAL "exported")


    add_custom_target(delete_version)
    add_custom_command(TARGET delete_version
        COMMAND cmake -P DeleteVersion.cmake)

    add_dependencies(version delete_version svn_version_c)
else(Subversion_FOUND AND EXISTS ${CMAKE_SOURCE_DIR}/.svn)
    if(NOT EXISTS ${CMAKE_SOURCE_DIR}/src/common/svn_version.c)
        message(FATAL_ERROR "Unable to build svn_version.c: not in svn repository!")
    endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/src/common/svn_version.c)
endif(Subversion_FOUND AND EXISTS ${CMAKE_SOURCE_DIR}/.svn)
