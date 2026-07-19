#!/bin/sh
# Verify the committed autogen-sourced output is current (#895).
#
# As of #895 phase 2, GNU autogen only produces src/tcpedit/tcpedit_stub.h;
# every *_opts.c/h and man page (*.adoc/*.1) is produced by scripts/autoopts
# (python3/asciidoctor) instead - see scripts/autoopts/check_emitters.py
# (byte-identical *_opts.c/h oracle) and scripts/autoopts/check_adoc.py
# (content-validated man pages).
#
# This script copies src/tcpedit/ to a scratch directory, regenerates
# tcpedit_stub.h there with GNU autogen, and diffs the result against the
# committed copy, so it can never drift from its .def sources.  The working
# tree is never modified.

set -e

if ! command -v autogen >/dev/null 2>&1; then
    echo "SKIP: GNU autogen not installed" >&2
    exit 77
fi

top_srcdir=$(cd "$(dirname "$0")/.." && pwd)
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

cp -r "$top_srcdir/src" "$tmpdir/src"

(
    cd "$tmpdir/src/tcpedit"
    autogen tcpedit_stub.def
)

if cmp -s "$tmpdir/src/tcpedit/tcpedit_stub.h" "$top_srcdir/src/tcpedit/tcpedit_stub.h"; then
    echo "OK: committed tcpedit_stub.h matches its .def sources"
else
    echo "DRIFT: src/tcpedit/tcpedit_stub.h" >&2
    echo "Regenerate: (cd src/tcpedit && autogen tcpedit_stub.def) and commit." >&2
    exit 1
fi
