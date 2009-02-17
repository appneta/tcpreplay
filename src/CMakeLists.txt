ADD_SUBDIRECTORY(common)
IF(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
    ADD_SUBDIRECTORY(fragroute)
ENDIF(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
ADD_SUBDIRECTORY(tcpedit)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src)

SET(baselibs "common")
IF(NOT HAVE_SYSTEM_STRLCPY)
    SET(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/lib/libstrl.a)
ENDIF(NOT HAVE_SYSTEM_STRLCPY)

SET(tcprewrite_srcs tcprewrite.c)
SET(tcpreplay_srcs tcpreplay.c send_packets.c signal_handler.c sleep.c)
SET(tcpreplay_edit_srcs tcpreplay.c send_packets.c signal_handler.c sleep.c)
SET(tcpprep_srcs tcpprep.c tree.c)
SET(tcpbridge_srcs tcpbridge.c bridge.c)

# VC++ needs the .h files listed as sources so they show up
IF(WIN32)
    SET(tcprewrite_srcs ${tcprewrite_srcs} tcprewrite.h)
    SET(tcpreplay_srcs ${tcpreplay_srcs} tcpreplay.h send_packets.h 
        signal_handler.h sleep.h)
    SET(tcpreplay_edit_srcs ${tcpreplay_srcs} tcpreplay.h send_packets.h 
        signal_handler.h sleep.h)
    SET(tcpprep_srcs ${tcpprep_srcs} tcpprep.h tree.h)
    SET(tcpbridge_srcs ${tcpbridge_srcs} tcpbridge.h bridge.h)
ENDIF(WIN32)

SET(autoopts_libs "")
# Do we link to libopts and compile in AutoOpts support?
IF(USE_AUTOOPTS)
    IF(WIN32)
        MESSAGE(FATAL " AutoOpts doesn't support the Win32 environment")
    ENDIF(WIN32)

    INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/libopts)

    ADD_CUSTOM_COMMAND(OUTPUT tcprewrite_opts.c tcprewrite_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcprewrite_opts.def
        DEPENDS tcprewrite_opts.def
    )

    ADD_CUSTOM_COMMAND(OUTPUT tcpreplay_opts.c tcpreplay_opts.h tcpreplay_edit_opts.c tcpreplay_edit_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpreplay_opts.def
        COMMAND ${AUTOGEN} -L tcpedit -DTCPREPLAY_EDIT -b tcpreplay_edit_opts tcpreplay_opts.def
        DEPENDS tcpreplay_opts.def
    )
    
    ADD_CUSTOM_COMMAND(OUTPUT tcpprep_opts.c tcpprep_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpprep_opts.def
        DEPENDS tcpprep_opts.def
    )

    ADD_CUSTOM_COMMAND(OUTPUT tcpbridge_opts.c tcpbridge_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpbridge_opts.def
        DEPENDS tcpbridge_opts.def
    )

    SET(tcpreplay_edit_srcs ${tcpreplay_edit_srcs} tcpreplay_edit_opts.c)
    SET(tcpreplay_srcs ${tcpreplay_srcs} tcpreplay_opts.c)
    SET(tcprewrite_srcs ${tcprewrite_srcs} tcprewrite_opts.c)
    SET(tcpprep_srcs ${tcpprep_srcs} tcpprep_opts.c)
    SET(tcpbridge_srcs ${tcpbridge_srcs} tcpbridge_opts.c)
    
    SET(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/libopts/libopts.a)
ENDIF(USE_AUTOOPTS)


SET(tcpreplay_edit_libs tcpedit ${baselibs})
SET(tcpreplay_libs ${baselibs})
SET(tcprewrite_libs tcpedit ${baselibs})
SET(tcpprep_libs ${baselibs})
SET(tcpbridge_libs tcpedit ${baselibs})


# Do we include fragroute support?
IF(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
    SET(tcprewrite_libs ${tcprewrite_libs} fragroute)
    SET(tcpbridge_libs ${tcpbridge_libs} fragroute)

    SET(tcpreplay_edit_libs ${tcpreplay_edit_libs} fragroute)

    SET_TARGET_PROPERTIES(fragroute
        PROPERTIES COMPILE_FLAGS ${DNET_CFLAGS})    
ENDIF(ENABLE_FRAGROUTE AND HAVE_LIBDNET)

# Always need libpcap or winpcap
IF(WIN32)
    SET(tcprewrite_libs ${tcprewrite_libs} winpcap)
    SET(tcpreplay_libs ${tcpreplay_libs} winpcap)
    SET(tcpreplay_edit_libs ${tcpreplay_edit_libs} winpcap)
    SET(tcpbridge_libs ${tcpbridge_libs} winpcap)
    SET(tcpprep_libs ${tcpprep_libs} winpcap)
ELSE(WIN32)
    SET(tcprewrite_libs ${tcprewrite_libs} pcap)
    SET(tcpreplay_libs ${tcpreplay_libs} pcap)
    SET(tcpreplay_edit_libs ${tcpreplay_edit_libs} pcap)
    SET(tcpbridge_libs ${tcpbridge_libs} pcap)
    SET(tcpprep_libs ${tcpprep_libs} pcap)
ENDIF(WIN32)

# Build our CLI binaries
IF(USE_AUTOOPTS)
    ADD_EXECUTABLE(tcprewrite ${tcprewrite_srcs})
    TARGET_LINK_LIBRARIES(tcprewrite ${tcprewrite_libs})

    # Necessary since tcpedit's features change for tcprewrite vs. tcpbridge
    SET_TARGET_PROPERTIES(tcprewrite
        PROPERTIES COMPILE_FLAGS "-DTCPREWRITE -DHAVE_CACHEFILE_SUPPORT")

    ADD_EXECUTABLE(tcpreplay ${tcpreplay_srcs})
    TARGET_LINK_LIBRARIES(tcpreplay ${tcpreplay_libs})

    SET_TARGET_PROPERTIES(tcpreplay
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY -DHAVE_CACHEFILE_SUPPORT")

    ADD_EXECUTABLE(tcpreplay-edit ${tcpreplay_edit_srcs})
    TARGET_LINK_LIBRARIES(tcpreplay-edit ${tcpreplay_edit_libs})

    SET_TARGET_PROPERTIES(tcpreplay-edit
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY_EDIT -DHAVE_CACHEFILE_SUPPORT")

    IF(HAVE_LIBDNET)
        SET_TARGET_PROPERTIES(tcprewrite tcpreplay tcpreplay-edit
            PROPERTIES LINK_FLAGS ${DNET_LIBS})    
    ENDIF(HAVE_LIBDNET)

    ADD_EXECUTABLE(tcpprep ${tcpprep_srcs})
    TARGET_LINK_LIBRARIES(tcpprep ${tcpprep_libs})

    # Only build tcpbridge if we have pcap_sendpacket()
    IF(HAVE_PCAP_SENDPACKET)
        ADD_EXECUTABLE(tcpbridge ${tcpbridge_srcs})
        TARGET_LINK_LIBRARIES(tcpbridge ${tcpbridge_libs})

        SET_TARGET_PROPERTIES(tcpbridge
            PROPERTIES COMPILE_FLAGS -DTCPBRIDGE)

        SET_TARGET_PROPERTIES(tcpbridge
            PROPERTIES LINK_FLAGS ${DNET_LIBS})    

    ENDIF(HAVE_PCAP_SENDPACKET)
ENDIF(USE_AUTOOPTS)

