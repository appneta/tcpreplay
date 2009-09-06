add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/web/tcpreplay.html
    COMMAND ${GROFF} -Thtml -mman ${CMAKE_SOURCE_DIR}/src/tcpreplay.1 >tcpreplay.html
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web
    DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpreplay.1
)
add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/web/tcpreplay-edit.html
    COMMAND ${GROFF} -Thtml -mman ${CMAKE_SOURCE_DIR}/src/tcpreplay-edit.1 >tcpreplay-edit.html
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web
    DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpreplay-edit.1
)
add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/web/tcpprep.html
    COMMAND ${GROFF} -Thtml -mman ${CMAKE_SOURCE_DIR}/src/tcpprep.1 >tcpprep.html
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web
    DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpprep.1
)
add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/web/tcprewrite.html
    COMMAND ${GROFF} -Thtml -mman ${CMAKE_SOURCE_DIR}/src/tcprewrite.1 >tcprewrite.html
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web
    DEPENDS ${CMAKE_SOURCE_DIR}/src/tcprewrite.1
)
add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/docs/web/tcpbridge.html
    COMMAND ${GROFF} -Thtml -mman ${CMAKE_SOURCE_DIR}/src/tcpbridge.1 >tcpbridge.html
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web
    DEPENDS ${CMAKE_SOURCE_DIR}/src/tcpbridge.1
)

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/docs/web)
    file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/docs/web)
endif(NOT EXISTS ${CMAKE_SOURCE_DIR}/docs/web)

set(__webpages
    ${CMAKE_SOURCE_DIR}/docs/web/tcpreplay.html
    ${CMAKE_SOURCE_DIR}/docs/web/tcpreplay-edit.html
    ${CMAKE_SOURCE_DIR}/docs/web/tcprewrite.html
    ${CMAKE_SOURCE_DIR}/docs/web/tcpprep.html)
if(ENABLE_TCPBRIDGE)
    set(__webpages ${__webpages} ${CMAKE_SOURCE_DIR}/docs/web/tcpbridge.html)
endif(ENABLE_TCPBRIDGE)

add_custom_target(webpages DEPENDS ${__webpages})

add_custom_target(postweb
    COMMAND rsync -qe ssh --exclude '.svn/' --exclude '/**/.svn' --exclude '/**~' --exclude '*~' -avz web/ aturner@malbec.synfin.net:/var/vhosts/tcpreplay
    COMMAND scp CHANGELOG TODO aturner@malbec.synfin.net:/var/vhosts/tcpreplay/
    COMMENT Copying documentation to /var/vhosts/tcpreplay...
    DEPENDS ${__webpages})
