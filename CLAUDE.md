# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Tcpreplay is a GPLv3 C suite for editing and replaying network traffic previously captured by tools
like tcpdump/Wireshark. It builds several binaries from a shared codebase:

- **tcpreplay** / **tcpreplay-edit** - replay pcap files onto the network at arbitrary speeds
- **tcpprep** - pre-processes a pcap into a cache file, classifying packets as client/server
- **tcprewrite** - rewrites L2/L3/L4 headers in a pcap (front-end to libtcpedit)
- **tcpbridge** - bridges two network segments using tcprewrite logic
- **tcpliveplay** - replays captured TCP sessions against a live server (full stack, not just L2)
- **tcpcapinfo** - raw pcap decoder/debugger

This is old, portable, autotools-based C (targets Linux, macOS/Darwin, *BSD, Solaris, Haiku, Cygwin),
performance-sensitive (line-rate packet generation), and used as a network test tool by security/network
vendors, so correctness of packet parsing and header rewriting matters more than idiomatic modern C.

## Build

Standard autotools flow:

```
./autogen.sh          # regenerates aclocal.m4, configure, Makefile.in via libtool/autoconf/automake
./configure
make
sudo make install
```

Out-of-tree build (used by CI):

```
mkdir build && cd build
../autogen.sh
../configure --disable-local-libopts --enable-debug --enable-test-hexdump
make
```

Useful `./configure` flags when working on specific areas:
- `--enable-debug` - runtime debug output (`-v`/`dbg()` messages)
- `--enable-asan` / `--enable-tsan` - AddressSanitizer / ThreadSanitizer builds
- `--with-netmap=DIR` - build netmap support against an out-of-tree netmap checkout
- `--enable-static-link` / `--enable-dynamic-link`
- `--with-testnic=NIC` / `--with-testnic2=NIC2` - NICs used by the live-traffic test suite (defaults are
  OS-specific, e.g. `eth0` on Linux, `en0` on macOS — see `configure.ac`)
- `--enable-test-hexdump` - hexdump the pcap on test failure

Requires `libpcap` (and `autogen`/AutoOpts to regenerate `*_opts.def` derived files). On Debian/Ubuntu:
`apt install autogen libpcap-dev automake autoconf libtool`.

## Tests

```
cd test
sudo make test          # regenerates fixtures then runs the tcpprep/tcpreplay/tcprewrite comparisons
```

Notes:
- Tests must be run as root (raw sockets / packet injection) and will send live traffic on the
  configured NICs (`nic1`/`nic2` from `./configure --with-testnic`) — don't run this against an
  interface you're connected through (e.g. an SSH session).
- The `test/` directory doesn't have per-test runner scripts; instead `test/Makefile.am` defines one
  make target per case (e.g. `rewrite_portmap`, `auto_router`, `replay_basic`), each of which invokes a
  built binary directly (`$(TCPPREP)`, `$(TCPREWRITE)`, `$(TCPREPLAY)`, ...) against `test/test.pcap`.
  `tcprewrite`/`tcpprep` targets diff the output against a checked-in golden file of the matching name
  (`test.rewrite_portmap`, `test.auto_router`, ...); `tcpreplay` targets (which put live packets on the
  wire) mostly just check the exit status. To run a single case: `cd test && make rewrite_portmap`
  (see `test/Makefile.am` for the full list of target names, grouped under the `tcpprep`, `tcprewrite`,
  and `tcpreplay` umbrella targets).
- On failure, `test/test.log` has the diff output (`cat test/test.log`).
- CI (`.github/workflows/github-actions-ci.yml`) builds out-of-tree, runs `make dist`/`make dist-xz`,
  then `sudo make test`.

## Linting / formatting

- `.clang-format` (based on LLVM style, 4-space indent, 120 col) — format C changes with `clang-format`
  before committing.
- `.clang-tidy` defines the enabled checks; CI runs `cpp-linter` on changed lines only.
- CodeQL runs on push/PR to `master`.

## Architecture

### Directory layout
- `src/` - the six `main()` entry points (`tcpreplay.c`, `tcprewrite.c`, `tcpprep.c`, `tcpbridge.c`,
  `tcpliveplay.c`, `tcpcapinfo.c`) plus shared engine code: `send_packets.c` (core TX loop/timing),
  `replay.c`, `bridge.c`, `sleep.c` (interpacket timing), `signal_handler.c`, `tree.c` (the client/server
  IP tree tcpprep builds and tcpreplay/tcprewrite consume via cache files).
- `src/common/` - shared support used by every binary: `sendpacket.c` (packet-injection abstraction, see
  below), `cache.c` (reads/writes tcpprep cache files), `cidr.c`, `mac.c`, `flows.c` (flow tracking/FPS
  stats), `netmap.c`, `txring.c`, `interface.c`, `services.c`, `err.c` (warnx/dbg/errx), `utils.c`
  (safe_malloc/safe_strdup/safe_realloc).
- `src/tcpedit/` - **libtcpedit**, the packet-rewriting engine shared by `tcprewrite`, `tcpbridge`, and
  `tcpreplay-edit`. Public API in `tcpedit.h`/`tcpedit_api.h`/`tcpedit_types.h`. Anything that rewrites
  packet headers belongs here, not in `tcprewrite.c` directly, since `tcpbridge` depends on the same logic.
- `src/tcpedit/plugins/` - DLT (link-layer type) plugins (`dlt_en10mb`, `dlt_ieee80211`, `dlt_raw`,
  `dlt_linuxsll`, `dlt_hdlc`, `dlt_loop`, `dlt_null`, `dlt_pppserial`, `dlt_radiotap`, `dlt_jnpr_ether`,
  `dlt_user`, ...) — each implements the same interface (see `dlt_plugins.c`/`dlt_opts.def`) to translate
  a given link layer to/from Ethernet-equivalent processing. `dlt_template`/`dlt_template.sh` scaffold a
  new plugin. Adding a new DLT means adding a plugin here, not branching in generic code.
- `src/fragroute/` - vendored/adapted fragroute packet-mangling modules (delay, drop, dup, IP/TCP option
  and fragmentation mangling, chaff, reordering) used for traffic-shaping tests.
- `lib/` - small vendored utility code (`strlcpy`/`strlcat`, `queue.h`, `sll.h`, `tree.h`).
- `libopts/` - GNU AutoOpts "tearoff" used to generate CLI parsing.
- `test/` - fixtures and autotools test targets (see Tests section).
- `docs/` - `HACKING` (contribution/coding-standard doc), `CHANGELOG`, `INSTALL`, `SECURITY.md`, plus a
  `Makefile.am` that renders the already-built man pages (generated into `src/` from the `*_opts.def`
  files, see below) to HTML for the website.

### CLI option definitions (`*_opts.def`)
Each binary's command-line options are declared declaratively in an AutoOpts `.def` file
(`src/tcpreplay_opts.def`, `src/tcpprep_opts.def`, `src/tcprewrite_opts.def`,
`src/tcpedit/tcpedit_opts.def`, etc.), not hand-written `getopt` code. `autogen` (AutoGen, from the
same project as AutoOpts) turns these into generated `*_opts.c`/`.h` and man pages at build time (see
the `.def` dependency rules in `src/Makefile.am`). When adding/changing a CLI flag, edit the relevant
`.def` file rather than the generated `_opts.c`. `tcprewrite`/`tcpbridge` include both their own opts
file and `tcpedit/tcpedit_opts.def` since they expose libtcpedit's rewrite options directly.

### Packet injection abstraction (`sendpacket_type_t`)
`src/common/sendpacket.c`/`sendpacket.h` abstract over the many OS-specific ways to inject packets:
libpcap, BPF, `PF_PACKET`, TX_RING, netmap, XDP/AF_XDP, libdnet, libnet, tuntap, and `KHIAL`
(https://github.com/boundary/khial) pseudo-nic virtual interfaces used for direction-controlled test
setups. Send-path code should go through this abstraction rather than calling a specific backend's API
directly, so all binaries keep working across platforms/build configs.

### tcpprep -> cache file -> tcpreplay/tcprewrite pipeline
`tcpprep` reads a pcap once, classifies each packet as client-to-server or server-to-client (`tree.c`
builds the IP/MAC classification tree), and writes a compact per-packet cache file. `tcpreplay` and
`tcprewrite` consume that cache file (`src/common/cache.c`) rather than reclassifying, so the two stages
should stay format-compatible.

## Coding standards (from `docs/HACKING`)
1. Indent 4 spaces, not tabs.
2. Opening brace for control blocks (`if`, `while`, ...) on the same line; opening brace for functions on
   the next line. (`.clang-format` encodes this: `BreakBeforeBraces: Custom` with `AfterFunction: true`.)
3. Use `warnx`/`dbg`/`errx` from `src/common/err.h` for error/debug output, not raw `printf`/`fprintf`.
4. Use `safe_strdup`/`safe_malloc`/`safe_realloc` from `src/common/utils.h` instead of the raw libc calls.
5. Use the `strl*` functions in `lib/strlcat.c`/`lib/strlcpy.c` instead of `strcat`/`strcpy`.
6. Packet-rewriting logic belongs in `src/tcpedit/`, since `tcprewrite` and `tcpbridge` both depend on it
   — don't duplicate rewrite logic in `tcprewrite.c` itself.

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
| ------ | ---------- |
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.

### Setup (one-time, per machine)

The MCP server registration (`.mcp.json`, `.claude/settings.json`) is **not** checked into git —
`code-review-graph install` writes machine-specific absolute paths (your pipx venv location, your
local repo path) into those files, so a committed copy would be broken on every other machine.
`.claude/skills/` *is* checked in — it's portable, so re-running `install` should regenerate it
identically.

```
pipx install code-review-graph
code-review-graph install --platform claude-code --repo .
code-review-graph build --repo .   # first-time graph population; `update` after that is incremental
```
