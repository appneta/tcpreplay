This document attempts to explain how to get tcpreplay compiled and running
under Windows.  Please note that this document is a work in progress and
Windows support in general considered BETA right now.


Background:

Tcpreplay is not a native Win32 application right now.  Hence it requires
the Cygwin. (http://www.cygwin.com).  Cygwin creates a Linux-like on your 
Windows system which allows Linux/UNIX programs to run after a recompile.

Tcpreplay supports numerous API's for sending packets depending on the 
operating system.  Under Windows, the only supported method of sending
packets is with WinPcap 4.0.  (http://www.winpcap.org)  Please be sure to
install both the WinPcap driver AND the developer pack.

Right now, I've only done testing under Windows XP.  My guess is that 2000
and 2003 should have no problems.  Since WinPcap and Cygwin are EOL'ing 
support for Win98/ME, I doubt that they'll ever be supported.  Not sure
the story on Vista, but I assume WinPcap & Cygwin will support them sooner
or later if not already.  Would love to hear if anyone has any luck one
way or another.

What you will need:

- Cygwin environment
- GNU build chain tools (Autoconf, Automake, Autoheader)
- GNU Autogen
- GCC compiler and system header files
- WinPcap 4.0 DLL
- WinPcap 4.0 Developer Pack (headers, etc)

Directions:
- Install all the requirements

- Enter into the Cygwin environment by clicking on the Cygwin icon

- Checkout the latest tcpreplay source code from the trunk branch:
	svn co https://www.synfin.net/svn/tcpreplay/trunk tcpreplay

- Run the autogen.sh bootstrapper:
	cd tcpreplay
	./autogen.sh

- Configure tcpreplay:
	./configure --with-libpcap=<path to winpcap> --enable-debug
	
	Note: The winpcap developer pack needs to be accessible from the Cygwin 
	environment.  On my system, it's called /WpdPack, but due to how cygwin
	works, I have to use all lowercase: --with-libpcap=/wpdpack

- Build tcpreplay:	
	make
	
- Test:
	make test
	
	Note: currently, the tcprewrite tests are broken due to how the test
	harness is configured.  Hence, errors should be expected.
	
- Install:
	make install
	
- Try it out!