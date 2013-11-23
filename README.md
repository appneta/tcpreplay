# Tcpreplay

The new home for Tcpreplay is on Github!

Looking for the stable 3.4 branch?  Go here: https://github.com/synfinatic/tcpreplay/tree/3.4

## Install

### Simple directions for Unix users:

    cmake -G "Unix Makefiles" 
    make 
    sudo make install

### More details

As of Tcpreplay 4.0, the build system has moved from GNU Autoconf to CMake.
While Autoconf may be the closest thing to an "industry standard", it's 
also unfortunately very difficult for developers to use and does not allow for 
building native Windows applications.

The 'cmake' application replaces the old './configure' command.  In most 
cases you can just run 'cmake' without any arguments and it will detect 
your system and generate the appropriate Makefiles.

If you want more control over the configuration process you can run 
'cmake -i' (prompts for configuration options) or 'ccmake' (a curses UI 
configurator).

For more information about CMake, visit: http://www.cmake.org

## Build netmap feature

This feature will detect netmap capable network drivers on Linux and BSD 
systems. If detected, the network driver is bypassed for the execution 
duration of tcpreplay and tcpreplay-edit, and network buffers will be 
written to directly. This will allow you to achieve full line rates on 
commodity network adapters, similar torates achieved by commercial network 
test hardware.

Note that bypassing the network driver will disrupt other applications connected
through the test interface. Don't test on the same interface you ssh'ed into.

Download latest and install netmap from http://info.iet.unipi.it/~luigi/netmap/
If you extracted netmap into /usr/src/ you can build normally. Otherwise you 
will have to specify the netmap source directory, for example:

NETMAP_DIR=/home/fklassen/git/netmap/ cmake -G "Unix Makefiles"
make
sudo make install

### Simple directions for everyone else:

Sorry you're out of luck for using 4.0. 

Right now, Tcpreplay 4.0-Alpha only supports Unix based systems like Linux and
OS X.  I hope to add support for Windows as well, but I haven't gotten there yet.
If you're a Windows developer and are interested in helping port Tcpreplay to
Windows, please contact me!

Windows users or anyone having problems with CMake can use the 3.4.x release 
available in the 3.4 branch.

## Support

If you have a question or think you are experiancing a bug, it is important
that you provide enough information for us to help you.  Failure to provide
enough information will likely cause your email to be ignored or get an
annoyed reply from the author.

If your problem has to do with COMPILING tcpreplay:
- Version of tcpreplay you are trying to compile
- Platform (Red Hat Linux 9 on x86, Solaris 7 on SPARC, OS X on PPC, etc)
- cmake options
- Contents of CMakeCache.txt
- Output from 'make'
- Any additional information you think that would be useful.

If your problem has to do with RUNNING tcpreplay or one of the sub-tools:
- Version information (output of -V)
- Command line used (options and arguments)
- Platform (Red Hat Linux 9 on Intel, Solaris 7 on SPARC, etc)
- Make & model of the network card(s) and driver(s) version
- Error message (if available) and/or description of problem
- If possible, attach the pcap file used (compressed with bzip2 or gzip
    preferred)
- The core dump or backtrace if available
- Detailed description of your problem or what you are trying to accomplish

Note: The author of tcpreplay primarily uses OS X; hence, if you're reporting
an issue on another platform, it is important that you give very detailed
information as I may not be able to reproduce your issue.

You are also strongly encouraged to read the extensive documentation (man
pages, FAQ, documents in /docs and email list archives) BEFORE posting to the
tcpreplay-users email list:

http://lists.sourceforge.net/lists/listinfo/tcpreplay-users

Lastly, please don't email the author directly with your questions.  Doing so
prevents others from potentially helping you and your question/answer from
showing up in the list archives.

## License

Tcpreplay 4.0 is GPLv3 and includes software developed by the University of
California, Berkeley, Lawrence Berkeley Laboratory and its contributors.
