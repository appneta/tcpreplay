# Check to see if we build with tcpdump/verbose support
set(tcpdump_src)
if(TCPDUMP_BINARY)
    if(WIN32)
        message(STATUS "Unable to build verbose support under Win32")    
    else(WIN32)
        set(tcpdump_src tcpdump.c)
    endif(WIN32)
else(TCPDUMP_BINARY)
    message(STATUS "Unable to build verbose support without tcpdump")
endif(TCPDUMP_BINARY)


add_library(common STATIC abort.c cache.c cidr.c dlt_names.c err.c fakepcap.c 
	fakepcapnav.c fakepoll.c get.c interface.c list.c mac.c rdtsc.c
	sendpacket.c services.c timer.c utils.c xX.c ${tcpdump_src} svn_version.c)

# Only rebuild svn_version.c if we're inside the svn working dir
if(EXISTS .svn)
    if(Subversion_FOUND)
        if(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
            add_custom_target(prepare_svn_version
                rm -f svn_version.c)  # first delete the old source file

            add_custom_target(svn_version
                DEPENDS svn_version.c)

            if(SVNVERSION)
                execute_process(COMMAND ${SVNVERSION} -n .
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
                    OUTPUT_VARIABLE SVNVERSION_REVISION)
                
                set_target_properties(common
                    PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"${SVNVERSION_REVISION}\\\")

            else(SVNVERSION)
                # Using SVN_INFO_WC_REVISION isn't accurate, so don't even try
                set_target_properties(common
                    PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"unknown\\\")
            endif(SVNVERSION)
            
        ENDIF(NOT SVN_INFO_WC_REVISION STREQUAL "exported")
    else(Subversion_FOUND)
        set_target_properties(common
            PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"unknown\\\")        
    endif(Subversion_FOUND)
else(EXISTS .svn)
    set_target_properties(common
        PROPERTIES COMPILE_FLAGS -DWC_Revision=\\\"unknown\\\")
endif(EXISTS .svn)    
    
add_custom_command(OUTPUT svn_version.c
    COMMAND rm -f svn_version.c
    COMMAND ${ECHO} const char SVN_Version[] = WC_Revision\;   > svn_version.c 
	COMMAND ${ECHO} const char *svn_version\(void\) {           >> svn_version.c
	COMMAND ${ECHO} 	return SVN_Version\;		            >> svn_version.c
	COMMAND ${ECHO} } 			      				            >> svn_version.c
	VERBATIM)
