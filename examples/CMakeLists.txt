# examples/CMakeLists.txt — libtcpreplay usage examples (#133); built always,
# never installed (mirrors examples/Makefile.am's noinst_PROGRAMS).

add_executable(replay_stats replay_stats.c)
target_link_libraries(replay_stats PRIVATE tcpreplay_static
    ${PCAP_LIBRARIES} ${DNET_LIBRARIES} ${TCPR_SYSTEM_LIBS} ${LNAV_LIBRARIES})
target_include_directories(replay_stats PRIVATE
    ${TCPR_GENERATED_INCLUDE_DIRS} ${TCPR_SOURCE_INCLUDE_DIRS})
