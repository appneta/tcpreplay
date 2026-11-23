---
title: Installation
description: Build Tcpreplay from source with CMake or autotools, or install from a package manager.
---

# Installation

Tcpreplay is portable C. It builds on Linux, macOS/Darwin, the BSDs, Solaris,
Haiku and Cygwin. You need a C compiler and **libpcap**; everything else is
optional.

## Requirements

| | Required | Purpose |
| --- | --- | --- |
| C toolchain | ✅ | Compiler + linker (`gcc`/`clang`). |
| **libpcap** (`libpcap-dev`) | ✅ | Reading and writing pcap files; default packet injection. |
| CMake ≥ 3.16 **or** autotools | ✅ | One of the two build systems. |
| Python 3 | git builds | Regenerates the CLI parsers from a source checkout. |
| asciidoctor | git builds | Renders the man pages from a source checkout. |
| libdnet (`libdumbnet-dev`) | optional | Enables the `fragroute` traffic-mangling modules. |
| liburing | optional | `--io-uring` fast injection path (Linux). |
| libxdp / libbpf | optional | `--xdp` (AF_XDP) fast injection path (Linux). |
| netmap headers | optional | `--netmap` fast injection path. |

!!! info "Release tarball vs git checkout"
    A **release tarball** (`tcpreplay-*.tar.xz`) ships the generated CLI parsers
    and pre-rendered man pages, so it builds with just a C toolchain and
    libpcap — no Python 3 or asciidoctor needed. A **git checkout** regenerates
    those at build time, so it additionally needs Python 3 and asciidoctor.

## Install the dependencies

=== "Debian / Ubuntu"

    ```console
    $ sudo apt install build-essential cmake libpcap-dev
    # optional extras:
    $ sudo apt install libdumbnet-dev liburing-dev libxdp-dev
    # only needed to build from a git checkout:
    $ sudo apt install python3 asciidoctor
    ```

=== "Fedora / RHEL"

    ```console
    $ sudo dnf install gcc make cmake libpcap-devel
    # optional extras:
    $ sudo dnf install libnet-devel liburing-devel libxdp-devel
    # only needed to build from a git checkout:
    $ sudo dnf install python3 rubygem-asciidoctor
    ```

=== "macOS (Homebrew)"

    ```console
    $ brew install cmake libpcap
    # only needed to build from a git checkout:
    $ brew install python3 asciidoctor
    ```

## Build with CMake (recommended)

CMake is the primary, recommended build system since 4.6. From a source tree:

```console
$ cmake -B build            # configure into ./build
$ cmake --build build       # compile
$ sudo cmake --install build
```

Prefer a preset? The repo ships `CMakePresets.json`:

```console
$ cmake --preset debug      # or: asan, tsan
$ cmake --build build
```

Every `configure` feature has a CMake option — for example:

```console
$ cmake -B build -DENABLE_DEBUG=ON -DWITH_NETMAP=/path/to/netmap
```

The mapping from `--enable-*`/`--with-*` flags to `-D…` options is documented in
the header comment of the top-level `CMakeLists.txt`.

!!! note "`make test` needs autotools"
    The test suite is currently autotools-only. If you want to run
    `sudo make test`, configure with autotools as shown below. CMake is
    otherwise the recommended path for building the tools.

## Build with autotools

The classic flow, and the one required for the test suite:

```console
$ ./autogen.sh          # git checkout only: regenerate configure, Makefiles
$ ./configure
$ make
$ sudo make install
```

Useful `./configure` flags:

| Flag | Effect |
| --- | --- |
| `--enable-debug` | Runtime debug output (`-v` / `dbg()` messages). |
| `--enable-asan` / `--enable-tsan` | AddressSanitizer / ThreadSanitizer builds. |
| `--with-netmap=DIR` | Build netmap support against an out-of-tree netmap checkout. |
| `--enable-static-link` / `--enable-dynamic-link` | Force static or dynamic linking. |
| `--with-testnic=NIC` | NIC used by the live-traffic test suite. |

## From a package manager

Many distributions package Tcpreplay. These are often a release or two behind;
build from source if you need the newest features or a security fix.

=== "Debian / Ubuntu"

    ```console
    $ sudo apt install tcpreplay
    ```

=== "Fedora"

    ```console
    $ sudo dnf install tcpreplay
    ```

=== "macOS (Homebrew)"

    ```console
    $ brew install tcpreplay
    ```

## Verify the install

```console
$ tcpreplay --version
tcpreplay version: 4.6.4 ...
```

You're ready for the [Quickstart](quickstart.md).

## Verifying a release download

Official release tarballs are published on the
[GitHub releases page](https://github.com/appneta/tcpreplay/releases/latest)
with a detached PGP signature (`.asc`) alongside each archive:

```console
$ gpg --verify tcpreplay-4.6.4.tar.xz.asc tcpreplay-4.6.4.tar.xz
```

A *Good signature* from the Tcpreplay release key confirms the archive is
authentic and unmodified.
