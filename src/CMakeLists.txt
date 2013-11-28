add_subdirectory(common)
add_subdirectory(tcpedit)
add_subdirectory(gui)

if(ENABLE_FRAGROUTE AND HAVE_LIBDNET)
    add_subdirectory(fragroute)
endif(ENABLE_FRAGROUTE AND HAVE_LIBDNET)

# don't clean *_opts.[ch]
set_property(DIRECTORY PROPERTY CLEAN_NO_CUSTOM true)

include_directories(${CMAKE_SOURCE_DIR}/src)

# External libraries to link to which we can't use TARGET_LINK_LIBRARIES() for
set(link_flags)

if(APPLE)
    set(abstime_libs "-framework Carbon -framework CoreServices")
endif(APPLE)

if(HAVE_LIBDNET)
    set(link_flags "${DNET_LIBS} ${abstime_libs}")
else(HAVE_LIBDNET)
    set(link_flags ${abstime_libs})
endif(HAVE_LIBDNET)

set(baselibs "common")
if(NOT HAVE_SYSTEM_STRLCPY)
    set(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/lib/libstrl.a)
endif(NOT HAVE_SYSTEM_STRLCPY)

set(tcpcapinfo_srcs tcpcapinfo.c tcpcapinfo_opts.c)
set(tcprewrite_srcs tcprewrite.c)
set(tcpreplay_srcs tcpreplay.c tcpreplay_api.c send_packets.c signal_handler.c sleep.c replay.c)
set(tcpreplay_edit_srcs tcpreplay.c tcpreplay_api.c send_packets.c signal_handler.c sleep.c replay.c)
set(tcpprep_srcs tcpprep.c tree.c tcpprep_api.c)
set(tcpbridge_srcs tcpbridge.c bridge.c)
set(libtcpreplay_srcs tcpreplay_api.c send_packets.c signal_handler.c sleep.c replay.c)
set(libtcpprep_srcs tree.c tcpprep_api.c)

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

    if(HAVE_NETMAP)
        add_custom_command(OUTPUT tcpreplay_opts.c tcpreplay_opts.h tcpreplay_edit_opts.c tcpreplay_edit_opts.h
        	COMMAND ${AUTOGEN} -DHAVE_NETMAP tcpreplay_opts.def
            COMMAND ${AUTOGEN} -L tcpedit -DTCPREPLAY_EDIT -DHAVE_NETMAP -b tcpreplay_edit_opts tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def
        )
    else(HAVE_NETMAP)
        add_custom_command(OUTPUT tcpreplay_opts.c tcpreplay_opts.h tcpreplay_edit_opts.c tcpreplay_edit_opts.h
        	COMMAND ${AUTOGEN} tcpreplay_opts.def
            COMMAND ${AUTOGEN} -L tcpedit -DTCPREPLAY_EDIT -b tcpreplay_edit_opts tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def
        )
    endif(HAVE_NETMAP)

    add_custom_command(OUTPUT tcpprep_opts.c tcpprep_opts.h
        COMMAND ${AUTOGEN} tcpprep_opts.def
        DEPENDS tcpprep_opts.def
    )

    add_custom_command(OUTPUT tcpbridge_opts.c tcpbridge_opts.h
        COMMAND ${AUTOGEN} -L tcpedit tcpbridge_opts.def
        DEPENDS tcpbridge_opts.def
    )

    add_custom_command(OUTPUT tcpcapinfo_opts.c tcpcapinfo_opts.h
        COMMAND ${AUTOGEN} tcpcapinfo_opts.def
        DEPENDS tcpcapinfo_opts.def
    )

    set(tcpreplay_edit_srcs ${tcpreplay_edit_srcs} tcpreplay_edit_opts.c)
    set(tcpreplay_srcs ${tcpreplay_srcs} tcpreplay_opts.c)
    set(tcprewrite_srcs ${tcprewrite_srcs} tcprewrite_opts.c)
    set(tcpprep_srcs ${tcpprep_srcs} tcpprep_opts.c)
    set(tcpbridge_srcs ${tcpbridge_srcs} tcpbridge_opts.c)
    set(libtcpreplay_srcs ${libtcpreplay_srcs} tcpreplay_opts.c)
    set(libtcpprep_srcs ${libtcpprep_srcs} tcpprep_opts.c)

    set(baselibs ${baselibs} ${CMAKE_SOURCE_DIR}/libopts/libopts.a)
endif(USE_AUTOOPTS)


set(tcpreplay_edit_libs tcpedit ${baselibs})
set(tcpreplay_libs ${baselibs})
set(tcprewrite_libs tcpedit ${baselibs})
set(tcpprep_libs ${baselibs})
set(tcpbridge_libs tcpedit ${baselibs})
set(tcpcapinfo_libs ${baselibs})


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
    target_link_libraries(tcpreplay-edit ${tcpreplay_edit_libs})

    set_target_properties(tcpreplay-edit
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY_EDIT -DHAVE_CACHEFILE_SUPPORT ${abstime_flags}")

    add_executable(tcpcapinfo ${tcpcapinfo_srcs})
    target_link_libraries(tcpcapinfo ${tcpcapinfo_libs})

    if (link_flags)
        set_target_properties(tcprewrite tcpreplay tcpreplay-edit tcpcapinfo
            PROPERTIES LINK_FLAGS ${link_flags})
    endif(link_flags)

    add_executable(tcpprep ${tcpprep_srcs})
    target_link_libraries(tcpprep ${tcpprep_libs})

    # Only build tcpbridge if we have pcap_sendpacket()
    if(HAVE_PCAP_SENDPACKET)
        add_executable(tcpbridge ${tcpbridge_srcs})
        target_link_libraries(tcpbridge ${tcpbridge_libs})

        if(link_flags)
            set_target_properties(tcpbridge
                PROPERTIES COMPILE_FLAGS -DTCPBRIDGE ${abstime_flags}
                LINK_FLAGS ${link_flags})
        endif(link_flags)
    endif(HAVE_PCAP_SENDPACKET)


    file(GLOB autogen_headers *_opts.h)
    set_source_files_properties(${autogen_headers}
        PROPERTIES GENERATED true)

    # Generate man pages
    set(autogen_opts -T agman1.tpl -L tcpedit)

    if(HAVE_NETMAP)
        add_custom_command(OUTPUT tcpreplay.1
            COMMAND ${AUTOGEN} ${autogen_opts} -DTCPREPLAY -DHAVE_NETMAP -b tcpreplay tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def)
        add_custom_command(OUTPUT tcpreplay-edit.1
            COMMAND ${AUTOGEN} ${autogen_opts} -DTCPREPLAY_EDIT -DHAVE_NETMAP -b tcpreplay-edit tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def)
    else(HAVE_NETMAP)
        add_custom_command(OUTPUT tcpreplay.1
            COMMAND ${AUTOGEN} ${autogen_opts} -DTCPREPLAY -b tcpreplay tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def)
        add_custom_command(OUTPUT tcpreplay-edit.1
            COMMAND ${AUTOGEN} ${autogen_opts} -DTCPREPLAY_EDIT -b tcpreplay-edit tcpreplay_opts.def
            DEPENDS tcpreplay_opts.def)
    endif(HAVE_NETMAP)
    add_custom_command(OUTPUT tcpprep.1
        COMMAND ${AUTOGEN} ${autogen_opts} -b tcpprep tcpprep_opts.def
        DEPENDS tcpprep_opts.def)
    add_custom_command(OUTPUT tcprewrite.1
        COMMAND ${AUTOGEN} ${autogen_opts} -b tcprewrite tcprewrite_opts.def
        DEPENDS tcprewrite_opts.def)
    add_custom_command(OUTPUT tcpcapinfo.1
        COMMAND ${AUTOGEN} ${autogen_opts} -b tcpcapinfo tcpcapinfo_opts.def
        DEPENDS tcprewrite_opts.def)

    # Build/install tcpbridge & man page
    if(HAVE_PCAP_SENDPACKET)
        add_custom_command(OUTPUT tcpbridge.1
            COMMAND ${AUTOGEN} ${autogen_opts} -b tcpbridge tcpbridge_opts.def
            DEPENDS tcpbridge_opts.def)

        install(TARGETS tcpbridge RUNTIME
            DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

        add_custom_target(man_pages ALL
            DEPENDS tcpreplay.1 tcpreplay-edit.1 tcpprep.1 tcprewrite.1 tcpbridge.1 tcpcapinfo.1)

        install(FILES tcpbridge.1
            DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)

    else(HAVE_PCAP_SENDPACKET)
        add_custom_target(man_pages ALL
            DEPENDS tcpreplay.1 tcpreplay-edit.1 tcpprep.1 tcprewrite.1 tcpcapinfo.1)

    endif(HAVE_PCAP_SENDPACKET)

    install(FILES tcpreplay.1 tcpreplay-edit.1 tcprewrite.1 tcpprep.1 tcpcapinfo.1
        DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)

    install(TARGETS tcpreplay tcpreplay-edit tcprewrite tcpprep tcpcapinfo 
        RUNTIME
        DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

endif(USE_AUTOOPTS)


# disable this for now.
if(false)
    # build the libraries
    add_library(replay STATIC ${libtcpreplay_srcs})
    set_target_properties(replay
        PROPERTIES COMPILE_FLAGS "-DTCPREPLAY -DHAVE_CACHEFILE_SUPPORT ${abstime_flags}")

    add_library(prep STATIC ${libtcpprep_srcs})
endif(false)

