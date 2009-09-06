add_subdirectory(common)
if(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
    add_subdirectory(fragroute)
endif(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
add_subdirectory(tcpedit)

include_directories(${CMAKE_SOURCE_DIR}/src)

# External libraries to link to which we can't use TARGET_LINK_LIBRARIES() for
set(link_flags)
set(abstime_libs "-framework Carbon -framework CoreServices")
if(HAVE_LIBDNET)
    set(link_flags "${DNET_LIBS} ${abstime_libs}")
else(HAVE_LIBDNET)
    set(link_flags ${abstime_libs})
endif(HAVE_LIBDNET)

set(baselibs "common")
if(NOT SYSTEM_STRLCPY)
    set(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/lib/libstrl.a)
endif(NOT SYSTEM_STRLCPY)

set(tcprewrite_srcs tcprewrite.c)
set(tcpreplay_srcs tcpreplay.c tcpreplay_api.c send_packets.c signal_handler.c sleep.c)
set(tcpreplay_edit_srcs tcpreplay.c tcpreplay_api.c send_packets.c signal_handler.c sleep.c)
set(tcpprep_srcs tcpprep.c tree.c tcpprep_api.c)
set(tcpbridge_srcs tcpbridge.c bridge.c)

# VC++ needs the .h files listed as sources so they show up
if(WIN32)
    set(tcprewrite_srcs ${tcprewrite_srcs} tcprewrite.h)
    set(tcpreplay_srcs ${tcpreplay_srcs} tcpreplay.h tcpreplay_api.h send_packets.h 
        signal_handler.h sleep.h)
    set(tcpreplay_edit_srcs ${tcpreplay_srcs} tcpreplay.h tcpreplay_api.h send_packets.h 
        signal_handler.h sleep.h)
    set(tcpprep_srcs ${tcpprep_srcs} tcpprep.h tree.h)
    set(tcpbridge_srcs ${tcpbridge_srcs} tcpbridge.h bridge.h)
endif(WIN32)

set(autoopts_libs)
# Do we link to libopts and compile in AutoOpts support?
if(USE_AUTOOPTS)
    if(WIN32)
        message(FATAL "AutoOpts doesn't support the Win32 environment")
    endif(WIN32)

    include_directories(${CMAKE_SOURCE_DIR}/libopts)

    add_custom_command(OUTPUT tcprewrite_opts.c tcprewrite_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcprewrite_opts.def
        DEPENDS tcprewrite_opts.def
    )

    add_custom_command(OUTPUT tcpreplay_opts.c tcpreplay_opts.h tcpreplay_edit_opts.c tcpreplay_edit_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpreplay_opts.def
        COMMAND ${AUTOGEN} -L tcpedit -DTCPREPLAY_EDIT -b tcpreplay_edit_opts tcpreplay_opts.def
        DEPENDS tcpreplay_opts.def
    )

    add_custom_command(OUTPUT tcpprep_opts.c tcpprep_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpprep_opts.def
        DEPENDS tcpprep_opts.def
    )

    add_custom_command(OUTPUT tcpbridge_opts.c tcpbridge_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpbridge_opts.def
        DEPENDS tcpbridge_opts.def
    )

    set(tcpreplay_edit_srcs ${tcpreplay_edit_srcs} tcpreplay_edit_opts.c)
    set(tcpreplay_srcs ${tcpreplay_srcs} tcpreplay_opts.c)
    set(tcprewrite_srcs ${tcprewrite_srcs} tcprewrite_opts.c)
    set(tcpprep_srcs ${tcpprep_srcs} tcpprep_opts.c)
    set(tcpbridge_srcs ${tcpbridge_srcs} tcpbridge_opts.c)

    set(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/libopts/libopts.a)
endif(USE_AUTOOPTS)


set(tcpreplay_edit_libs tcpedit ${baselibs})
set(tcpreplay_libs ${baselibs})
set(tcprewrite_libs tcpedit ${baselibs})
set(tcpprep_libs ${baselibs})
set(tcpbridge_libs tcpedit ${baselibs})


# Do we include fragroute support?
if(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
    set(tcprewrite_libs ${tcprewrite_libs} fragroute)
    set(tcpbridge_libs ${tcpbridge_libs} fragroute)

    set(tcpreplay_edit_libs ${tcpreplay_edit_libs} fragroute)

    set_target_properties(fragroute
        PROPERTIES COMPILE_FLAGS ${DNET_CFLAGS})
endif(ENABLE_FRAGROUTE AND HAVE_LIBDNET)

# Always need libpcap or winpcap
if(WIN32)
    set(tcprewrite_libs ${tcprewrite_libs} winpcap)
    set(tcpreplay_libs ${tcpreplay_libs} winpcap)
    set(tcpreplay_edit_libs ${tcpreplay_edit_libs} winpcap)
    set(tcpbridge_libs ${tcpbridge_libs} winpcap)
    set(tcpprep_libs ${tcpprep_libs} winpcap)
else(WIN32)
    set(tcprewrite_libs ${tcprewrite_libs} pcap)
    set(tcpreplay_libs ${tcpreplay_libs} pcap)
    set(tcpreplay_edit_libs ${tcpreplay_edit_libs} pcap)
    set(tcpbridge_libs ${tcpbridge_libs} pcap)
    set(tcpprep_libs ${tcpprep_libs} pcap)
endif(WIN32)

# Build our CLI binaries
if(USE_AUTOOPTS)
    add_executable(tcprewrite ${tcprewrite_srcs})
    target_link_libraries(tcprewrite ${tcprewrite_libs})

    # Necessary since tcpedit's features change for tcprewrite vs. tcpbridge
    set_target_properties(tcprewrite
        PROPERTIES COMPILE_FLAGS "-DTCPREWRITE -DHAVE_CACHEFILE_SUPPORT")

    add_executable(tcpreplay ${tcpreplay_srcs})
    target_link_libraries(tcpreplay ${tcpreplay_libs})

    set_target_properties(tcpreplay
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY -DHAVE_CACHEFILE_SUPPORT ${abstime_flags}")

    add_executable(tcpreplay-edit ${tcpreplay_edit_srcs})
    TARGET_LINK_LIBRARIES(tcpreplay-edit ${tcpreplay_edit_libs})

    SET_TARGET_PROPERTIES(tcpreplay-edit
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY_EDIT -DHAVE_CACHEFILE_SUPPORT ${abstime_flags}")

    SET_TARGET_PROPERTIES(tcprewrite tcpreplay tcpreplay-edit
        PROPERTIES LINK_FLAGS ${link_flags})

    ADD_EXECUTABLE(tcpprep ${tcpprep_srcs})
    TARGET_LINK_LIBRARIES(tcpprep ${tcpprep_libs})

    # Only build tcpbridge if we have pcap_sendpacket()
    IF(HAVE_PCAP_SENDPACKET)
        ADD_EXECUTABLE(tcpbridge ${tcpbridge_srcs})
        TARGET_LINK_LIBRARIES(tcpbridge ${tcpbridge_libs})

        SET_TARGET_PROPERTIES(tcpbridge
            PROPERTIES COMPILE_FLAGS -DTCPBRIDGE ${abstime_flags})

        SET_TARGET_PROPERTIES(tcpbridge
            PROPERTIES LINK_FLAGS ${link_flags})

    ENDIF(HAVE_PCAP_SENDPACKET)
ENDIF(USE_AUTOOPTS)

set(autogen_opts -T agman1.tpl -L tcpedit)

ADD_CUSTOM_COMMAND(OUTPUT tcpreplay.1
    COMMAND ${AUTOGEN} ${autogen_opts} -b tcpreplay tcpreplay_opts.def
    DEPENDS tcpreplay_opts.def)
ADD_CUSTOM_COMMAND(OUTPUT tcpreplay-edit.1
    COMMAND ${AUTOGEN} ${autogen_opts} -DTCPREPLAY_EDIT -b tcpreplay-edit tcpreplay_opts.def
    DEPENDS tcpreplay_opts.def)
ADD_CUSTOM_COMMAND(OUTPUT tcpprep.1
    COMMAND ${AUTOGEN} ${autogen_opts} -b tcpprep tcpprep_opts.def
    DEPENDS tcpprep_opts.def)
ADD_CUSTOM_COMMAND(OUTPUT tcprewrite.1
    COMMAND ${AUTOGEN} ${autogen_opts} -b tcprewrite tcprewrite_opts.def
    DEPENDS tcprewrite_opts.def)
ADD_CUSTOM_COMMAND(OUTPUT tcpbridge.1
    COMMAND ${AUTOGEN} ${autogen_opts} -b tcpbridge tcpbridge_opts.def
    DEPENDS tcpbridge_opts.def)

ADD_CUSTOM_TARGET(man_pages
    DEPENDS tcpreplay.1 tcpreplay-edit.1 tcpprep.1 tcprewrite.1 tcpbridge.1)
