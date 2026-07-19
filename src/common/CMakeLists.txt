# src/common/CMakeLists.txt — libcommon (mirrors src/common/Makefile.am).

# git_version.c (build-time generated, same content as the Makefile.am rule)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/git_version.c
    COMMAND ${CMAKE_COMMAND}
            -DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/git_version.c
            -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
            -P ${CMAKE_SOURCE_DIR}/cmake/GitVersion.cmake
    DEPENDS ${CMAKE_SOURCE_DIR}/cmake/GitVersion.cmake
    COMMENT "Generating git_version.c")

set(COMMON_SOURCES
    cidr.c err.c list.c cache.c services.c get.c
    fakepcap.c fakepcapnav.c fakepoll.c xX.c utils.c
    timer.c ${CMAKE_CURRENT_BINARY_DIR}/git_version.c sendpacket.c
    dlt_names.c mac.c interface.c
    flows.c txring.c)

if(ENABLE_VERBOSE)
    list(APPEND COMMON_SOURCES tcpdump.c)
endif()

if(HAVE_NETMAP)
    list(APPEND COMMON_SOURCES netmap.c)
endif()

# object library so the installable libtcpreplay archive can fold these
# objects in (#133); the 'common' static wrapper keeps every existing
# consumer unchanged
add_library(common_obj OBJECT ${COMMON_SOURCES})
target_include_directories(common_obj PRIVATE
    ${TCPR_GENERATED_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${TCPR_SOURCE_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIR})
if(LNAV_CFLAGS)
    target_compile_options(common_obj PRIVATE ${LNAV_CFLAGS})
endif()
if(DNET_CFLAGS)
    target_compile_options(common_obj PRIVATE ${DNET_CFLAGS})
endif()

add_library(common STATIC $<TARGET_OBJECTS:common_obj>)
target_include_directories(common PUBLIC
    ${TCPR_GENERATED_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${TCPR_SOURCE_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIR})
if(NOT HAVE_STRLCPY)
    target_link_libraries(common PUBLIC strl)
endif()
