#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Byte-compare emitter output against the committed autogen output (#895).

Extends validate_ir.py's structural checks to full file equivalence for the
emitters implemented so far (currently *_opts.h).  Run from the top of the
tree; exits non-zero on any difference.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from emit_h import emit_h  # noqa: E402

CASES = [
    ("tcpcapinfo_opts", "src/tcpcapinfo_opts.def", []),
    ("tcpliveplay_opts", "src/tcpliveplay_opts.def", []),
    ("tcpprep_opts", "src/tcpprep_opts.def", []),
    ("tcprewrite_opts", "src/tcprewrite_opts.def", []),
    ("tcpbridge_opts", "src/tcpbridge_opts.def", []),
    ("tcpreplay_opts", "src/tcpreplay_opts.def", []),
    ("tcpreplay_edit_opts", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"]),
]


def main():
    failed = False
    for base, def_path, defines in CASES:
        generated = emit_h(def_path, base, defines, ["src", "src/tcpedit"])
        committed = Path(f"src/{base}.h").read_text()
        if generated == committed:
            print(f"OK   {base}.h")
        else:
            failed = True
            print(f"FAIL {base}.h differs from emitter output")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
