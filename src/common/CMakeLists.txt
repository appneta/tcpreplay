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
    sendpacket.c services.c timer.c utils.c xX.c ${tcpdump_src} git_version.c)

add_custom_target(version)

if(EXISTS ${CMAKE_SOURCE_DIR}/.git)
    include(GetGitRevisionDescription)
    get_git_head_revision(GIT_REFSPEC GIT_SHA1)

    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/git_version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/git_version.c" @ONLY)

    set_source_files_properties(git_version.c
        PROPERTIES GENERATED true)

    add_custom_target(delete_version)
    add_custom_command(TARGET delete_version
        COMMAND cmake -P DeleteVersion.cmake)

    # dependancy order is BACKWARDS!
    add_dependencies(version git_version_c delete_version)

else(EXISTS ${CMAKE_SOURCE_DIR}/.git)
    if(NOT EXISTS ${CMAKE_SOURCE_DIR}/src/common/git_version.c)
        message(FATAL_ERROR "Unable to build git_version.c: not in git repository!")
    endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/src/common/git_version.c)
endif(EXISTS ${CMAKE_SOURCE_DIR}/.git)
