set(TCPPREP ${CMAKE_SOURCE_DIR}/src/tcpprep)
set(TCPREWRITE ${CMAKE_SOURCE_DIR}/src/tcprewrite)
set(TCPREPLAY ${CMAKE_SOURCE_DIR}/src/tcpreplay)
set(DEBUG_FLAG "")
if(ENABLE_DEBUG)
    set(DEBUG_FLAG -d 5)
endif(ENABLE_DEBUG)    

if(NOT NIC1)
    if(LINUX)
        SET(NIC1 eth0)
    elseif(APPLE)
        SET(NIC1 en0)
    elseif(SOLARIS)
        SET(NIC1 hme0)
    elseif(WIN32)
        set(NIC1 %0)
    elseif(OPENBSD)
        set(NIC1 xl0)
    endif(LINUX)
endif(NOT NIC1)

if(NOT NIC2)
    set(NIC2 ${NIC1})
endif(NOT NIC2)

set(TEST_VER "")
if(WORDS_BIGENDIAN)
    set(endian Big-endian)
else(WORDS_BIGENDIAN)
    set(endian Little-endian)
    set(TEST_VER 2)
endif(WORDS_BIGENDIAN)

# tcpprep tests
set(tcpprep_tests auto_bridge auto_router auto_client auto_first auto_server
        cidr cidr_reverse comment mac mac_reverse port prep_config
        regex regex_reverse)

# tcprewrite tests
set(tcprewrite_tests rewrite_1ttl rewrite_2ttl rewrite_3ttl rewrite_config rewrite_dlthdlc
    rewrite_dltuser rewrite_efcs rewrite_endpoint rewrite_layer2 rewrite_mac
    rewrite_pad rewrite_pnat rewrite_portmap rewrite_seed rewrite_skip
    rewrite_tos rewrite_trunc rewrite_vlandel rewrite_mtutrunc)

#########################################################
# TARGET: standard
#########################################################
add_custom_target(standard)

configure_file(${CMAKE_SOURCE_DIR}/test/Standard.cmake.in ${CMAKE_SOURCE_DIR}/test/Standard.cmake @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/test/RunUnitTest.cmake.in ${CMAKE_SOURCE_DIR}/test/RunUnitTest.cmake @ONLY)
configure_file(${CMAKE_SOURCE_DIR}/test/config.in ${CMAKE_SOURCE_DIR}/test/config @ONLY)
add_custom_command(TARGET standard
    COMMAND cmake -P Standard.cmake
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test
    DEPENDS Standard.cmake
    VERBATIM)



#########################################################
# TARGET: test
#########################################################
if(BUILD_TESTING)

endif(BUILD_TESTING)
