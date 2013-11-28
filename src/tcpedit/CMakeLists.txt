# don't clean tcpedit_stub.h
set_property(DIRECTORY PROPERTY CLEAN_NO_CUSTOM true)

INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/libopts)
INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit/plugins)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIRS})
INCLUDE_DIRECTORIES($NETMAP_INCLUDE_DIRS})

# grab all the plugin .c files
file(GLOB_RECURSE tcpedit_srcs plugins/*.c)

file(GLOB_RECURSE tcpedit_headers plugins/*.h)
set(tcpedit_headers ${tcpedit_headers} checksum.h dlt.h edit_packet.h
    plugins.h plugins_api.h plugins_types.h portmap.h tcpedit.h tcpedit_api.h
    tcpedit_types.h)

# add the tcpedit base files
set(tcpedit_srcs ${tcpedit_srcs} tcpedit.c dlt.c edit_packet.c checksum.c
    portmap.c tcpedit_api.c)

if(USE_AUTOOPTS)
    set(tcpedit_srcs ${tcpedit_srcs} parse_args.c tcpedit_stub.h)
    set(tcpedit_headers ${tcpedit_headers} parse_args.h)

    add_custom_command(OUTPUT tcpedit_stub.h
        COMMAND ${AUTOGEN} ${CMAKE_SOURCE_DIR}/src/tcpedit/tcpedit_stub.def
        DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpedit/tcpedit_stub.def)

    set_source_files_properties(tcpedit_stub.h
        PROPERTIES GENERATED true)

    set_source_files_properties(tcpedit.o
        PROPERTIES OBJECT_DEPENDS tcpedit_stub.h)

endif(USE_AUTOOPTS)

add_library(tcpedit STATIC ${tcpedit_srcs})
add_dependencies(tcpedit ${tcpedit_headers})
