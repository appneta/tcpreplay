INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/libopts)
INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit/plugins)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIRS})

# grab all the plugin .c files
file(GLOB_RECURSE tcpedit_srcs ${CMAKE_SOURCE_DIR}/src/tcpedit/plugins *.c)

# add the tcpedit base files
SET(tcpedit_srcs ${tcpedit_srcs} tcpedit.c dlt.c edit_packet.c checksum.c
    portmap.c tcpedit_api.c)

IF(USE_AUTOOPTS)
    SET(tcpedit_srcs ${tcpedit_srcs} parse_args.c tcpedit_stub.h)

    ADD_CUSTOM_COMMAND(OUTPUT tcpedit_stub.h
        COMMAND ${AUTOGEN} ${CMAKE_SOURCE_DIR}/src/tcpedit/tcpedit_stub.def
        DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpedit/tcpedit_stub.def)

    SET_SOURCE_FILES_PROPERTIES(tcpedit_stub.h
        PROPERTIES HEADER_FILE_ONLY true
        GENERATED true)

    SET_SOURCE_FILES_PROPERTIES(tcpedit.o
        PROPERTIES OBJECT_DEPENDS tcpedit_stub.h)

ENDIF(USE_AUTOOPTS)

ADD_LIBRARY(tcpedit STATIC ${tcpedit_srcs})
