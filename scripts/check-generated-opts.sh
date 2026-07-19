#!/bin/sh
# Verify the committed AutoOpts output is current (#895).
#
# Copies src/ to a scratch directory, regenerates every *_opts.c/h, man page
# and tcpedit_stub.h there with GNU autogen, and diffs the results against
# the committed copies.  CI runs this so the committed files can never drift
# from their .def sources.  The working tree is never modified.
#
# Man pages embed the generation date in their .TH line, which is expected
# to differ - it is normalized away before diffing.
#
# This is also the phase 2 oracle harness for #895: a replacement generator
# must produce output that passes this same comparison.

set -e

if ! command -v autogen >/dev/null 2>&1; then
    echo "SKIP: GNU autogen not installed" >&2
    exit 77
fi

top_srcdir=$(cd "$(dirname "$0")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cp -r "$top_srcdir/src" "$tmpdir/src"

# regenerate everything in the scratch copy, exactly as the Makefile rules do
(
    cd "$tmpdir/src"
    for tool in tcpprep tcprewrite tcpbridge tcpliveplay tcpcapinfo tcpreplay; do
        autogen -L tcpedit ${tool}_opts.def
        autogen -T agman-cmd.tpl -L tcpedit ${tool}_opts.def
    done
    autogen -L tcpedit -DTCPREPLAY_EDIT -b tcpreplay_edit_opts tcpreplay_opts.def
    autogen -T agman-cmd.tpl -L tcpedit -DTCPREPLAY_EDIT -DTCPREPLAY_EDIT_MAN tcpreplay_opts.def
    cd tcpedit
    autogen tcpedit_stub.def
)

fail=0
for f in \
    tcpprep_opts.c tcpprep_opts.h tcpprep.1 \
    tcprewrite_opts.c tcprewrite_opts.h tcprewrite.1 \
    tcpbridge_opts.c tcpbridge_opts.h tcpbridge.1 \
    tcpliveplay_opts.c tcpliveplay_opts.h tcpliveplay.1 \
    tcpcapinfo_opts.c tcpcapinfo_opts.h tcpcapinfo.1 \
    tcpreplay_opts.c tcpreplay_opts.h tcpreplay.1 \
    tcpreplay_edit_opts.c tcpreplay_edit_opts.h tcpreplay-edit.1 \
    tcpedit/tcpedit_stub.h; do
    case "$f" in
    *.1)
        a="$tmpdir/norm_a"; b="$tmpdir/norm_b"
        sed 's/^\.TH .*//' "$tmpdir/src/$f" > "$a"
        sed 's/^\.TH .*//' "$top_srcdir/src/$f" > "$b"
        cmp -s "$a" "$b" || { echo "DRIFT: src/$f"; fail=1; }
        ;;
    *)
        cmp -s "$tmpdir/src/$f" "$top_srcdir/src/$f" || { echo "DRIFT: src/$f"; fail=1; }
        ;;
    esac
done

if [ "$fail" -ne 0 ]; then
    echo "Committed AutoOpts output differs from what the .def files generate." >&2
    echo "Regenerate with 'make autoopts' in src/ (requires GNU autogen) and commit." >&2
    exit 1
fi
echo "OK: committed AutoOpts output matches the .def sources"
