# Check to see if we build with tcpdump/verbose support
SET(tcpdump_src "")
IF(TCPDUMP_BINARY)
    IF(WIN32)
        MESSAGE(STATUS "Unable to build verbose support under Win32")    
    ELSE(WIN32)
        SET(tcpdump_src tcpdump.c)
    ENDIF(WIN32)
ELSE(TCPDUMP_BINARY)
    MESSAGE(STATUS "Unable to build verbose support without tcpdump")
ENDIF(TCPDUMP_BINARY)


ADD_LIBRARY(common STATIC abort.c cache.c cidr.c dlt_names.c err.c fakepcap.c 
	fakepcapnav.c fakepoll.c get.c interface.c list.c mac.c rdtsc.c
	sendpacket.c services.c timer.c utils.c xX.c ${tcpdump_src} svn_version.c)

# Only rebuild svn_version.c if we're inside the svn working dir
IF(Subversion_FOUND)
    IF(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
        ADD_CUSTOM_TARGET(prepare_svn_version
            rm -f svn_version.c)  # first delete the old source file

        ADD_CUSTOM_TARGET(svn_version
            DEPENDS svn_version.c)

        IF(SVNVERSION)
            EXECUTE_PROCESS(COMMAND ${SVNVERSION} -n .
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                OUTPUT_VARIABLE SVNVERSION_REVISION)
                
            SET_TARGET_PROPERTIES(common
                PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"${SVNVERSION_REVISION}\\\")

        ELSE(SVNVERSION)
            # Using SVN_INFO_WC_REVISION isn't accurate, so don't even try
            SET_TARGET_PROPERTIES(common
                PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"unknown\\\")
        ENDIF(SVNVERSION)
        

        ADD_CUSTOM_COMMAND(OUTPUT svn_version.c
            COMMAND rm -f svn_version.c
            COMMAND ${ECHO} const char SVN_Version[] = WC_Revision\;   > svn_version.c 
        	COMMAND ${ECHO} const char *svn_version\(void\) {           >> svn_version.c
        	COMMAND ${ECHO} 	return SVN_Version\;		            >> svn_version.c
        	COMMAND ${ECHO} } 			      				            >> svn_version.c
        	VERBATIM)
    
    ENDIF(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
ENDIF(Subversion_FOUND)