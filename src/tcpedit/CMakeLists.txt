INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/tcpedit/plugins)
INCLUDE_DIRECTORIES(${PCAP_INCLUDE_DIRS})



SET(tcpedit_srcs
    tcpedit.c dlt.c edit_packet.c checksum.c portmap.c
    tcpedit_api.c 
    plugins/dlt_plugins.c plugins/dlt_utils.c plugins/ethernet.c
    plugins/dlt_en10mb/en10mb.c  plugins/dlt_en10mb/en10mb_api.c
    plugins/dlt_user/user.c  plugins/dlt_user/user_api.c
    plugins/dlt_hdlc/hdlc.c  plugins/dlt_hdlc/hdlc_api.c
    plugins/dlt_ieee80211/ieee80211.c plugins/dlt_ieee80211/ieee80211_hdr.c 
    plugins/dlt_linuxsll/linuxsll.c 
    plugins/dlt_loop/loop.c 
    plugins/dlt_null/null.c
    plugins/dlt_radiotap/radiotap.c 
    plugins/dlt_raw/raw.c)

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
