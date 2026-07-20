#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Smoke-test emit_h/emit_c for all seven tool configs (#895).

*_opts.c/h are not committed to git (see .gitignore) - they're ordinary
build products, regenerated from the .def by scripts/autoopts, so there's
no committed golden file to byte-diff against any more. Byte-identical
equivalence with real GNU autogen's output was verified once, during
phase 2 development (see scripts/autoopts/README.md); that migration
proof doesn't need re-running on every CI invocation, since neither
emitter has any autogen dependency to drift against.

This instead confirms each emitter still runs to completion and produces
output with the shape a *_opts.c/h file must have, for every config
(including the -DTCPREPLAY_EDIT variant) - catching crashes or obviously
malformed output from a .def/emitter change. Run from the top of the tree;
exits non-zero on any failure.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from emit_h import emit_h  # noqa: E402
from emit_c import emit as emit_c  # noqa: E402

CASES = [
    ("tcpcapinfo_opts", "src/tcpcapinfo_opts.def", []),
    ("tcpliveplay_opts", "src/tcpliveplay_opts.def", []),
    ("tcpprep_opts", "src/tcpprep_opts.def", []),
    ("tcprewrite_opts", "src/tcprewrite_opts.def", []),
    ("tcpbridge_opts", "src/tcpbridge_opts.def", []),
    ("tcpreplay_opts", "src/tcpreplay_opts.def", []),
    ("tcpreplay_edit_opts", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"]),
]

# minimal shape checks per extension - not exhaustive, just enough to catch
# an emitter crashing partway through or returning obviously wrong content
SHAPE_MARKERS = {
    ".h": ("#define OPTION_CT", "INDEX_OPT_"),
    ".c": ("tOptDesc", "tOptions"),
}


def main():
    failed = False
    for base, def_path, defines in CASES:
        for ext, emit in ((".h", emit_h), (".c", emit_c)):
            try:
                generated = emit(def_path, base, defines, ["src", "src/tcpedit"])
            except Exception as e:  # noqa: BLE001
                failed = True
                print(f"FAIL {base}{ext}: emitter raised {e!r}")
                continue
            missing = [m for m in SHAPE_MARKERS[ext] if m not in generated]
            if not generated.strip() or missing:
                failed = True
                print(f"FAIL {base}{ext}: missing expected content {missing}")
            else:
                print(f"OK   {base}{ext}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
