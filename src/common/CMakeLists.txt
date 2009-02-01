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
IF(INSIDE_SVN_WORKING_DIRECTORY)
    ADD_CUSTOM_TARGET(prepare_svn_version
        rm -f svn_version.c)  # first delete the old source file

    ADD_CUSTOM_TARGET(svn_version
        DEPENDS svn_version.c)

    ADD_CUSTOM_COMMAND(OUTPUT svn_version.c
        COMMAND rm -f svn_version.c
        COMMAND ${ECHO} -n const char SVN_Version[] = \"     > svn_version.c 
    	COMMAND ${SVNVERSION} -n ${CMAKE_SOURCE_DIR}        >> svn_version.c
    	COMMAND ${ECHO} \"\;  								>> svn_version.c
    	COMMAND ${ECHO} const char *svn_version\(void\) {   >> svn_version.c
    	COMMAND ${ECHO} 	return SVN_Version\;		    >> svn_version.c
    	COMMAND ${ECHO} } 			      				    >> svn_version.c
    	VERBATIM)
    
ENDIF(INSIDE_SVN_WORKING_DIRECTORY)
