# src/fragroute/CMakeLists.txt — libfragroute (mirrors src/fragroute/Makefile.am).
# Only built when libdnet is available (ENABLE_FRAGROUTE).

add_library(fragroute STATIC
    fragroute.c bget.c mod.c pkt.c argv.c
    randutil.c mod_delay.c mod_drop.c mod_dup.c
    mod_echo.c mod_ip_chaff.c mod_ip_frag.c mod_ip_opt.c
    mod_ip_ttl.c mod_ip_tos.c mod_order.c mod_print.c
    mod_tcp_chaff.c mod_tcp_opt.c mod_tcp_seg.c
    iputil.c mod_ip6_opt.c mod_ip6_qos.c)

target_include_directories(fragroute PRIVATE
    ${TCPR_GENERATED_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${TCPR_SOURCE_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIR})
if(DNET_CFLAGS)
    target_compile_options(fragroute PRIVATE ${DNET_CFLAGS})
endif()
