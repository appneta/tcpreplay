Tcpreplay
=========
[![Test Status](https://github.com/appneta/tcpreplay/actions/workflows/github-actions-ci.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/github-actions-ci.yml)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/12017/badge.svg)](https://scan.coverity.com/projects/12017)
[![CodeQL](https://github.com/appneta/tcpreplay/actions/workflows/codeql.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/codeql.yml)
[![cpp-linter](https://github.com/appneta/tcpreplay/actions/workflows/c-linter.yml/badge.svg)](https://github.com/appneta/tcpreplay/actions/workflows/c-linter.yml)
[![Website](https://img.shields.io/website-up-down-green-red/https/tcpreplay.appneta.com.svg)](http://tcpreplay.appneta.com)
[![Release](https://img.shields.io/github/release/appneta/tcpreplay.svg)](https://github.com/appneta/tcpreplay/releases)

Tcpreplay is a suite of [GPLv3] licensed utilities for UNIX (and Windows under
[Cygwin]) for editing and replaying network traffic previously captured by
tools like [tcpdump] and [Wireshark]. It classifies traffic as client or
server, rewrites Layer 2/3/4 headers, and replays it back onto the network
through switches, routers, firewalls, NIDS and IPS's — at anywhere from a
trickle up to full wire rate. Tcpreplay supports both single and dual NIC
modes, for testing both sniffing and in-line devices.

Tcpreplay is used by numerous firewall, IDS, IPS, NetFlow and other
networking vendors, enterprises, universities, labs and open source
projects. If your organization uses Tcpreplay, please let us know who you
are and what you use it for, so we can keep prioritizing the features that
matter.

Since 4.0, Tcpreplay also specifically targets [IP Flow][flow]/[NetFlow]
appliance testing: accurate high-rate playback timing and results reporting,
Flows Per Second (fps) statistics, and flow-expiry analysis for tuning a
flow product's timeout settings — up to hundreds of thousands of flows/sec,
depending on the flow sizes in the pcap file.

- [The suite](#the-suite)
- [What's new in 4.6](#whats-new-in-46)
- [Installing a release](#installing-a-release)
- [Building from source](#building-from-source)
  - [Autotools](#autotools)
  - [CMake](#cmake-recommended)
  - [Performance: netmap, AF\_XDP, io\_uring](#performance-netmap-af_xdp-io_uring)
  - [Replaying onto raw IP (L3) interfaces](#replaying-onto-raw-ip-l3-interfaces)
  - [libtcpreplay C library](#libtcpreplay-c-library)
  - [Running the test suite](#running-the-test-suite)
- [Getting help](#getting-help)
- [Contributing](#contributing)
- [License](#license)
- [Authors](#authors)

The Suite
=========
Network playback:
--------------------------
* **tcpreplay** / **tcpreplay-edit** — replay pcap files at arbitrary speeds
  onto the network, optionally editing packets on the fly (`tcpreplay-edit`)
  or randomizing IP addresses (`tcpreplay`)
* **tcpliveplay** — replay a captured TCP session on a live network in a
  manner that a remote server will actually respond to (contributed by Yazan
  Siam, sponsored by [Cisco], for testing the full network stack up into the
  application — plain `tcpreplay` normally stays at Layer 2)

Pcap file editors and utilities:
--------------------------------
* **tcpprep** — multi-pass pcap pre-processor that classifies packets as
  client or server and writes a cache file consumed by tcpreplay/tcprewrite
* **tcprewrite** — rewrites TCP/IP and Layer 2 packet headers in a pcap file
* **tcpbridge** — bridge two network segments using tcprewrite's rewriting logic
* **tcpcapinfo** — raw pcap file decoder and debugger

What's New in 4.6
==================
* [CMake](#cmake-recommended) is now the primary, recommended build system
  (autotools is still used for release tarballs)
* [io_uring](#performance-netmap-af_xdp-io_uring) and
  [AF_XDP](#performance-netmap-af_xdp-io_uring) fast-path packet injection,
  alongside the existing netmap support — both need less setup than netmap
  and no patched drivers
* [libtcpreplay](#libtcpreplay-c-library), a static C library for embedding
  the replay engine directly in your own program
* Automatic support for [replaying onto raw IP (L3) interfaces](#replaying-onto-raw-ip-l3-interfaces)
  like WireGuard and tun devices

See the [CHANGELOG](docs/CHANGELOG) for the full release history.

Installing a Release
=====================
[![GitHub downloads](https://img.shields.io/github/downloads/appneta/tcpreplay/total.svg)](https://github.com/appneta/tcpreplay/releases)
[![SourceForge downloads](https://img.shields.io/sourceforge/dt/tcpreplay.svg)](https://sourceforge.net/projects/tcpreplay)

Download the latest [release tarball](https://github.com/appneta/tcpreplay/releases/latest)
(also mirrored on [SourceForge](https://sourceforge.net/projects/tcpreplay)),
then:
```
tar xf tcpreplay-*.tar.xz && cd tcpreplay-*
./configure && make && sudo make install
```
A release tarball ships pre-generated CLI parsers and man pages, so this
needs nothing beyond a C compiler and libpcap — see
[Building from source](#building-from-source) below only if you're working
from a git checkout, or want CMake, netmap, AF_XDP or io_uring support.

More detailed platform-specific instructions are in the `INSTALL` file
included in the tarball (same content as [`docs/INSTALL`](docs/INSTALL) here).

Building From Source
=====================
Building from a git checkout requires `python3` and `asciidoctor` (either
build system) to generate the CLI option parsers and man pages from the
`*_opts.def` files — this replaced GNU AutoGen for that purpose in 4.6
(AutoGen is EOL; these aren't). AutoGen itself is only still needed for one
internal header (`src/tcpedit/tcpedit_stub.h`) — see
[`scripts/autoopts/README.md`](scripts/autoopts/README.md). None of this is
needed when building a release tarball, which ships these already generated.

Autotools
---------
```
./autogen.sh   # only needed once, from a git checkout
./configure
make
sudo make install
```

CMake (recommended)
--------------------
As of 4.6, the suite can also be built with [CMake](https://cmake.org)
(3.16+) — **the recommended and primary way to compile Tcpreplay**.
Autotools is still provided and used for release tarballs, but will
eventually be retired, so new scripts/packaging should target CMake.

```
cmake -B build
cmake --build build
sudo cmake --install build
```

Every `./configure` flag has a CMake equivalent — see the table at the top
of [`CMakeLists.txt`](CMakeLists.txt). A few examples:

```
# debug build with support for the -d option
cmake -B build -DENABLE_DEBUG=ON

# AddressSanitizer or ThreadSanitizer build
cmake -B build -DENABLE_ASAN=ON
cmake -B build -DENABLE_TSAN=ON

# custom libpcap install, static linking, custom tcpdump path
cmake -B build -DWITH_LIBPCAP=/usr/local/opt/libpcap \
               -DENABLE_STATIC_LINK=ON -DWITH_TCPDUMP=/usr/sbin/tcpdump

# force a specific packet injection method
cmake -B build -DFORCE_INJECT_PCAP_SENDPACKET=ON

# several configurations side by side
cmake -B build-debug -DENABLE_DEBUG=ON
cmake -B build-release
```

`cmake --build build --target manpages` regenerates the man pages
(python3 + asciidoctor); a plain `cmake --build build` never touches them.
VS Code users with the CMake Tools extension can just open the repository
folder and pick a configure preset when prompted.

Performance: netmap, AF_XDP, io_uring
--------------------------------------
If the default socket path isn't fast enough, Tcpreplay has three
lower-overhead ways to push packets straight to the NIC. Try them roughly in
this order — io_uring needs the least setup, netmap the most:

<details>
<summary><b>io_uring</b> (Linux, needs <code>liburing-dev</code> — no patched driver required)</summary>

Detected on Linux systems with `liburing-dev` installed and a kernel with
[io_uring](https://man7.org/linux/man-pages/man7/io_uring.7.html) support.
Packets still go out through a regular PF_PACKET raw socket, but sends are
submitted asynchronously through an io_uring queue, cutting per-packet
syscall overhead.

```
sudo apt-get install liburing-dev
cmake -B build && cmake --build build && sudo cmake --install build
sudo tcpreplay -i eth0 --io-uring test.pcap
```
</details>

<details>
<summary><b>AF_XDP</b> (Linux, needs <code>libxdp-dev</code>/<code>libbpf-dev</code> + an eBPF-capable driver)</summary>

Detected on Linux systems with `libxdp-dev` and `libbpf-dev` installed. When
selected (`--xdp`), the kernel network stack is bypassed and packets are
sent directly through an eBPF-enabled driver — full line rate on commodity
adapters, comparable to commercial traffic generators, without patching the
driver.

```
sudo apt-get install libxdp-dev libbpf-dev
cmake -B build && cmake --build build && sudo cmake --install build
sudo tcpreplay -i eth0 --xdp test.pcap
```
</details>

<details>
<summary><b>netmap</b> (Linux/BSD, needs netmap-patched network drivers — most invasive, highest ceiling)</summary>

[netmap] bypasses the network driver for the duration of the replay and
writes directly to the NIC's TX buffers. This is the most invasive of the
three options — the network stack goes dark on that interface while it's
active, so **don't test on the interface you SSH'ed in on** — but has the
highest throughput ceiling on supported hardware.

Download and install netmap from the [project page][netmap]. If you
extracted it into `/usr/src` or `/usr/local/src` it'll be picked up
automatically; otherwise point the build at it:

```
cmake -B build -DWITH_NETMAP=/home/fklassen/git/netmap
cmake --build build
sudo cmake --install build
```
</details>

Replaying onto raw IP (L3) interfaces
--------------------------------------
On Linux, tcpreplay can replay directly onto layer-3-only interfaces such as
WireGuard and tun devices — no build option or command line flag needed. Any
layer 2 header in the input file (Ethernet including VLAN tags, Linux SLL,
loopback, ...) is stripped automatically and packets are sent as bare
IPv4/IPv6 with the correct protocol, which drivers like WireGuard require:

```
sudo tcpreplay -i wg0 test.pcap
```

Note that non-IP packets (e.g. ARP) can't be sent on these interfaces and
are reported as failed, and that `--io-uring` isn't supported on them.

libtcpreplay C library
-----------------------
Since 4.6 the suite installs **libtcpreplay**, a static library exposing the
same replay engine the `tcpreplay` binary uses via `tcpreplay_api.h`.
Applications can replay pcap files and read live statistics
programmatically, instead of forking the binary and scraping its output:

```
cc myapp.c $(pkg-config --cflags --libs --static libtcpreplay) -o myapp
```

Headers install under `include/tcpreplay/`; both build systems install the
library and its `libtcpreplay.pc`. See [`examples/`](examples/) for a
complete program.

Running the test suite
------------------------
```
cd test
sudo make test
```
Requires root (raw sockets/packet injection) and sends live traffic on the
configured test NICs — don't run it against an interface you're connected
through. `make test` is autotools-only; see [`docs/INSTALL`](docs/INSTALL)
for configuring test NICs with `--with-testnic`/`--with-testnic2`.

Getting Help
============
Think you've found a bug, or have a question? Search
[existing issues](https://github.com/appneta/tcpreplay/issues) first, then
[open a new one](https://github.com/appneta/tcpreplay/issues/new) if it's not
already covered. Please include:

* The Tcpreplay version (`-V`/`--version`) and platform
* If it's a build problem: the output of `configure`/`cmake` and `make`
* If it's a runtime problem: the exact command line, and a description (or
  attached pcap) of what you were trying to do
* Anything else that seems relevant — the more detail, the faster we can help

Found a security vulnerability specifically? Please follow
[`docs/SECURITY.md`](docs/SECURITY.md) instead of filing a public issue.

You're also encouraged to read the man pages, [FAQ](http://tcpreplay.appneta.com/wiki/faq.html)
and [`docs/`](docs/) before posting to the tcpreplay-users
[mailing list](https://lists.sourceforge.net/lists/listinfo/tcpreplay-users) —
and please don't email the maintainers directly, so others can benefit from
(and help answer) your question too.

Contributing
============
1. [Fork] the repository and [set up git][git] if you haven't already
2. Create a branch for your feature or bug fix
3. Make your change — see [`docs/HACKING`](docs/HACKING) for coding
   standards and what contributing your code implies license-wise
4. Push to your fork and [send a pull request][pr] against `master`

We'll review and discuss it with you on GitHub; once accepted, it's applied
directly to `master`. See also the
[developer wiki](https://github.com/appneta/tcpreplay/wiki) for
architecture-level guides (DLT plugin development, embedding libtcpedit,
...).

License
=======
Tcpreplay is licensed under [GPLv3], and includes software developed by the
University of California, Berkeley, Lawrence Berkeley Laboratory and its
contributors. See [`docs/LICENSE`](docs/LICENSE) for the full text.

Authors
=======
Tcpreplay was created by Aaron Turner. Fred Klassen ([AppNeta by Broadcom][AppNeta])
took over maintenance in 2013, starting with the 4.0 release, adding the
performance and flow-testing features described above.

[GPLv3]:    http://www.gnu.org/licenses/gpl-3.0.html
[netmap]:   https://github.com/luigirizzo/netmap
[flow]:     https://en.wikipedia.org/wiki/Traffic_flow_(computer_networking)
[NetFlow]:  http://www.cisco.com/go/netflow
[Cygwin]:   http://www.cygwin.com/
[Wireshark]: https://www.wireshark.org
[tcpdump]:  http://www.tcpdump.org
[Cisco]:    http://www.cisco.com
[AppNeta]:  http://www.appneta.com
[git]:      https://help.github.com/articles/set-up-git
[Fork]:     https://help.github.com/articles/fork-a-repo
[pr]:       https://help.github.com/articles/using-pull-requests
