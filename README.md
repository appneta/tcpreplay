Tcpreplay
=========
[![Build Status](https://travis-ci.org/appneta/tcpreplay.svg?branch=master)](https://travis-ci.org/appneta/tcpreplay)
[![Test Status](https://github.com/appneta/tcpreplay/actions/workflows/github-actions-ci.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/github-actions-ci.yml)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/12017/badge.svg)](https://scan.coverity.com/projects/12017)
[![Website](https://img.shields.io/website-up-down-green-red/http/shields.io.svg)](http://tcpreplay.appneta.com)
[![CodeQL](https://github.com/appneta/tcpreplay/actions/workflows/codeql.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/codeql.yml)
[![cpp-linter](https://github.com/appneta/tcpreplay/actions/workflows/c-linter.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/c-linter.yml)

Tcpreplay is a suite of [GPLv3] licensed utilities for UNIX (and Win32 under
[Cygwin]) operating systems for editing and replaying network traffic which
was previously captured by tools like [tcpdump] and [Wireshark]. 
It allows you to classify traffic as client or server, rewrite Layer 2, 3 and 4 
packets and finally replay the traffic back onto the network and through other
devices such as switches, routers, firewalls, NIDS and IPS's. Tcpreplay supports
both single and dual NIC modes for testing both sniffing and in-line devices.

Tcpreplay is used by numerous firewall, IDS, IPS, NetFlow and other networking
vendors, enterprises, universities, labs and open source projects. If your
organization uses Tcpreplay, please let us know who you are and what you use
it for so that I can continue to add features which are useful.

Tcpreplay is designed to work with network hardware and normally does not
penetrate deeper than Layer 2. Yazan Siam with sponsorship from [Cisco] developed
*tcpliveplay* to replay TCP pcap files directly to servers. Use this utility
if you want to test the entire network stack and into the application.

As of version 4.0, Tcpreplay has been enhanced to address the complexities of
testing and tuning [IP Flow][flow]/[NetFlow] hardware. Enhancements include:

* Support for [netmap] modified network drivers for 10GigE wire-speed performance
* Increased accuracy for playback speed
* Increased accuracy of results reporting
* Flow statistics including Flows Per Second (fps)
* Flow analysis for analysis and fine tuning of flow expiry timeouts
* Hundreds of thousands of flows per second (dependent flow sizes in pcap file) 

Version 4.0 is the first version delivered by Fred Klassen and sponsored by 
[AppNeta]. Many thanks to the author of Tcpreplay, Aaron Turner who has supplied
the world with a a solid and full-featured test product thus far. The new author
strives to take Tcprelay performance to levels normally only seen in commercial
network test equipment.

Downloads
=========
* [![Releases](https://img.shields.io/github/downloads/appneta/tcpreplay/total.svg)](https://github.com/appneta/tcpreplay/releases) [GitHub](https://github.com/appneta/tcpreplay/releases)
* [![SourceForge](https://img.shields.io/sourceforge/dt/tcpreplay.svg)](https://sourceforge.net/projects/tcpreplay) [SourceForge](https://sourceforge.net/projects/tcpreplay) 

Products
========
[![Releases](https://img.shields.io/github/release/appneta/tcpreplay.svg)](https://github.com/appneta/tcpreplay/releases)

The Tcpreplay suite includes the following tools:

Network playback products:
--------------------------
* **tcpreplay** - replays pcap files at arbitrary speeds onto the network with an
option to replay with random IP addresses
* **tcpreplay-edit** - replays pcap files at arbitrary speeds onto the network with
numerous options to modify packets packets on the fly
* **tcpliveplay** - replays TCP network traffic stored in a pcap file on live
networks in a manner that a remote server will respond to

Pcap file editors and utilities:
--------------------------------
* **tcpprep** - multi-pass pcap file pre-processor which determines packets as
client or server and splits them into creates output files for use by tcpreplay and tcprewrite
* **tcprewrite** - pcap file editor which rewrites TCP/IP and Layer 2 packet headers
* **tcpbridge** - bridge two network segments with the power of tcprewrite
* **tcpcapinfo** - raw pcap file decoder and debugger

Install package
===============
Please visit our [downloads](http://tcpreplay.appneta.com/wiki/installation.html#downloads)
page on our [wiki](http://tcpreplay.appneta.com) 
for detailed download and installation instructions.


Simple directions for Unix users:
---------------------------------
If you're building from a release tarball, `configure` is already generated:
```
./configure 
make
sudo make install
```

If you're building from a git checkout, `configure` doesn't exist yet - generate it
first with `autogen.sh` (requires `autoconf`, `automake` and `libtool`; despite the
similar name this script has nothing to do with GNU AutoGen, see the CMake section
below):
```
./autogen.sh
./configure
make
sudo make install
```

Building with CMake
-------------------
As of version 4.6, the suite can also be built with [CMake](https://cmake.org) (3.16+).
**CMake is the recommended and primary way to compile Tcpreplay** — the
autotools build (`./configure` / automake) is still provided and used for
release tarballs, but it will be retired in a future release, so new
scripts and packaging should use CMake. Building from a git checkout no
longer requires `autogen` (GNU AutoGen, which is EOL) for the generated CLI
option parsers and man-page source: `scripts/autoopts` (a small in-tree
Python replacement) and `asciidoctor` produce them from the `.def` files at
build time instead, so you need those two tools installed to build from git
(neither is EOL, unlike autogen). GNU autogen itself is only still needed
for one internal header (`src/tcpedit/tcpedit_stub.h`); see
`scripts/autoopts/README.md`. Release tarballs (`make dist`) ship the
already-generated files, so building from a tarball needs none of these
three tools.

```
cmake -B build
cmake --build build
sudo cmake --install build
```

Every `./configure` flag has a CMake equivalent (see the table at the top of
`CMakeLists.txt`). Examples:

```
# debug build with support for the -d option
cmake -B build -DENABLE_DEBUG=ON

# AddressSanitizer or ThreadSanitizer build
cmake -B build -DENABLE_ASAN=ON
cmake -B build -DENABLE_TSAN=ON

# netmap support from an out-of-tree netmap checkout
cmake -B build -DWITH_NETMAP=/home/fklassen/git/netmap

# custom libpcap install
cmake -B build -DWITH_LIBPCAP=/usr/local/opt/libpcap

# static libraries, custom tcpdump path
cmake -B build -DENABLE_STATIC_LINK=ON -DWITH_TCPDUMP=/usr/sbin/tcpdump

# force a specific packet injection method
cmake -B build -DFORCE_INJECT_PCAP_SENDPACKET=ON

# several configurations side by side
cmake -B build-debug -DENABLE_DEBUG=ON
cmake -B build-release
```

Handy targets: `cmake --build build --target manpages` renders the man pages
with asciidoctor — a plain `cmake --build build` never needs asciidoctor,
only that explicit target does. VS Code users with the CMake Tools extension
can simply open the repository folder and select a configure preset when
prompted.

Build netmap feature
--------------------
This feature will detect [netmap](http://info.iet.unipi.it/~luigi/netmap/)
capable network drivers on Linux and BSD 
systems. If detected, the network driver is bypassed for the execution 
duration of tcpreplay and tcpreplay-edit, and network buffers will be 
written to directly. This will allow you to achieve full line rates on 
commodity network adapters, similar to rates achieved by commercial network 
traffic generators.

**Note** that bypassing the network driver will disrupt other applications connected
through the test interface. Don't test on the same interface you ssh'ed into.

Download latest and install netmap from <http://info.iet.unipi.it/~luigi/netmap/>
If you extracted netmap into **/usr/src/** or **/usr/local/src** you can build normally. Otherwise you 
will have to specify the netmap source directory, for example:
```
cmake -B build -DWITH_NETMAP=/home/fklassen/git/netmap
cmake --build build
sudo cmake --install build
```

You can also find netmap source [here](http://code.google.com/p/netmap/).

Build AF_XDP feature
--------------------
This feature will detect [AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)
capable network drivers on Linux systems that have `libxdp-dev` and
`libbpf-dev` installed. If detected, the `--xdp` option becomes available to
tcpreplay and tcpreplay-edit. When selected, the network stack is bypassed
and packets are sent directly to an eBPF enabled driver. This will allow you
to achieve full line rates on commodity network adapters, similar to rates
achieved by commercial network traffic generators. For example:

```
sudo apt-get install libxdp-dev libbpf-dev
cmake -B build
cmake --build build
sudo cmake --install build
sudo tcpreplay -i eth0 --xdp test.pcap
```

Build io_uring feature
----------------------
This feature is detected on Linux systems that have `liburing-dev` installed
and a kernel with [io_uring](https://man7.org/linux/man-pages/man7/io_uring.7.html)
support. If detected, the `--io-uring` option becomes available to tcpreplay
and tcpreplay-edit. Packets are still sent through a PF_PACKET raw socket,
but sends are submitted asynchronously through an io_uring submission queue,
which reduces per-packet syscall overhead and lets the kernel process
transmissions while tcpreplay prepares the next packet. For example:

```
sudo apt-get install liburing-dev
cmake -B build
cmake --build build
sudo cmake --install build
sudo tcpreplay -i eth0 --io-uring test.pcap
```

Replaying onto raw IP (L3) interfaces
-------------------------------------
On Linux, tcpreplay can replay directly onto layer-3-only interfaces such as
WireGuard and tun devices — no build option or command line flag needed. Any
layer 2 header in the input file (Ethernet including VLAN tags, Linux SLL,
loopback, ...) is stripped automatically and packets are sent as bare
IPv4/IPv6 with the correct protocol, which drivers like WireGuard require:

```
sudo tcpreplay -i wg0 test.pcap
```

Note that non-IP packets (e.g. ARP) cannot be sent on these interfaces and
are reported as failed, and that `--io-uring` is not supported on them.

libtcpreplay C library
----------------------
Since version 4.6 the suite installs **libtcpreplay**, a static library
exposing the same replay engine the `tcpreplay` binary uses via
`tcpreplay_api.h`. Applications can replay pcap files and read live
statistics programmatically instead of forking the binary and scraping its
output:

```
cc myapp.c $(pkg-config --cflags --libs --static libtcpreplay) -o myapp
```

Headers install under `include/tcpreplay/` and both the autotools and CMake
builds install the library and its `libtcpreplay.pc`. See the
[examples](examples/) directory for a complete program.

Detailed installation instructions are available in the INSTALL document in the tar ball.

Install Tcpreplay from source code
------------------------
Download the [tar ball](https://github.com/appneta/tcpreplay/tarball/master) or 
[zip](https://github.com/appneta/tcpreplay/zipball/master) file. Optionally clone the git
repository:

```
git clone git@github.com:appneta/tcpreplay.git
```

Support
=======
If you have a question or think you are experiencing a bug, submit them 
[here](https://github.com/appneta/tcpreplay/issues). It is important
that you provide enough information for us to help you.

If your problem has to do with COMPILING tcpreplay:
* Version of tcpreplay you are trying to compile
* Platform (Red Hat Linux 9 on x86, Solaris 7 on SPARC, OS X on PPC, etc)
* Contents of config.status
* Output from **configure** and **make**
* Any additional information you think that would be useful.

If your problem has to do with RUNNING tcpreplay or one of the sub-tools:
* Version information (output of -V)
* Command line used (options and arguments)
* Platform (Red Hat Linux 9 on Intel, Solaris 7 on SPARC, etc)
* Make & model of the network card(s) and driver(s) version
* Error message (if available) and/or description of problem
* If possible, attach the pcap file used (compressed with bzip2 or gzip preferred)
* The core dump or backtrace if available
* Detailed description of your problem or what you are trying to accomplish

Note: The author of tcpreplay primarily uses OS X and Linux; hence, if you're reporting
an issue on another platform, it is important that you give very detailed
information as I may not be able to reproduce your issue.

You are also strongly encouraged to read the extensive documentation (man
pages, FAQ, documents in /docs and email list archives) BEFORE posting to the
tcpreplay-users email list:

http://lists.sourceforge.net/lists/listinfo/tcpreplay-users

If you have a bug to report you can submit it here:

https://github.com/appneta/tcpreplay/issues

If you want to help with development, visit our developers wiki:

https://github.com/appneta/tcpreplay/wiki

Lastly, please don't email the authors directly with your questions.  Doing so
prevents others from potentially helping you and your question/answer from
showing up in the list archives.

License
=======
Tcpreplay 3.5 is GPLv3 and includes software developed by the University of
California, Berkeley, Lawrence Berkeley Laboratory and its contributors.

Authors and Contributors
========================
Tcpreplay is authored by Aaron Turner. In 2013 Fred Klassen, Founder and VP Network Technology,
[AppNeta](http://appneta.com) added performance features and enhancements,
and ultimately took over the maintenance of Tcpreplay.

The source code repository has moved to GitHub. You can get a working copy of the repository 
by installing [git] and executing:

```
git clone https://github.com/appneta/tcpreplay.git
```

How To Contribute
=================
It's easy. Basically you...

* [Set up git][git]
* [Fork]
* Edit (we create a branch per issue)
* [Send a PR][pr]

<br />

Details:
--------
You will find that you will not be able to contribute to the Tcpreplay project directly if you
use clone the appneta/tcpreplay repo. If you believe that you may someday contribute to the
repository, GitHub provides an innovative approach. Forking the @appneta/tcpreplay repository
allows you to work on your own copy of the repository and submit code changes without first
asking permission from the authors. Forking is also considered to be a compliment so fork away:
   
* if you haven't already done so, get yourself a free [GitHub](https://github.com) ID and visit @appneta/tcpreplay
* click the **Fork** button to get your own private copy of the repository
* on your build system clone your private repository:

```
git clone git@github.com:<your ID>/tcpreplay.git
```

* we like to keep the **master** branch available for projection ready code so we recommend that you make a 
branch for each feature or bug fix
* when you are happy with your work, push it to your GitHub repository
* on your GitHub repository select your new branch and submit a **Pull Request** to **master**
* optionally monitor the status of your submission [here](https://github.com/appneta/tcpreplay/network)

We will review and possibly discuss the changes with you through GitHub services. 
If we accept the submission, it will instantly be applied to the production **master** branch.

Additional Information
======================
Please visit our [wiki](http://tcpreplay.appneta.com).

or visit our [developers wiki](https://github.com/appneta/tcpreplay/wiki)

[GPLv3]:    http://www.gnu.org/licenses/gpl-3.0.html
[netmap]:   http://info.iet.unipi.it/~luigi/netmap/
[flow]:     http://en.wikipedia.org/wiki/Traffic_flow_%28computer_networking%29
[NetFlow]:  http://www.cisco.com/go/netflow
[Cygwin]:   http://www.cygwin.com/
[Wireshark]: https://www.wireshark.org
[tcpdump]:  http://www.tcpdump.org
[Cisco]:    http://www.cisco.com
[AppNeta]:  http://www.appneta.com
[git]:      https://help.github.com/articles/set-up-git
[Fork]:     https://help.github.com/articles/fork-a-repo
[pr]:       https://help.github.com/articles/using-pull-requests
