#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Regenerate the AutoOpts option parsers without GNU autogen (#895).

Writes every src/*_opts.c and src/*_opts.h from the .def sources - the
same files GNU autogen produces, byte for byte (proven by
check_emitters.py against the committed autogen output).

    python3 scripts/autoopts/generate.py           # write the files
    python3 scripts/autoopts/generate.py --check   # verify only, write nothing

Man pages (src/*.1) are NOT produced by this tool yet; they still require
GNU autogen.  See README.md in this directory.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from emit_adoc import emit as emit_adoc  # noqa: E402
from emit_c import emit as emit_c  # noqa: E402
from emit_h import emit_h  # noqa: E402

# (basename, def file, -D defines) - mirrors the rules in src/Makefile.am
# and src/CMakeLists.txt
CASES = [
    ("tcpcapinfo_opts", "src/tcpcapinfo_opts.def", []),
    ("tcpliveplay_opts", "src/tcpliveplay_opts.def", []),
    ("tcpprep_opts", "src/tcpprep_opts.def", []),
    ("tcprewrite_opts", "src/tcprewrite_opts.def", []),
    ("tcpbridge_opts", "src/tcpbridge_opts.def", []),
    ("tcpreplay_opts", "src/tcpreplay_opts.def", []),
    ("tcpreplay_edit_opts", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"]),
]

SEARCH = ["src", "src/tcpedit"]


# man pages use the tool's plain name (no "_opts" suffix), and the
# -edit variant is spelled with a hyphen, not an underscore
MAN_BASE = {
    "tcpcapinfo_opts": "tcpcapinfo",
    "tcpliveplay_opts": "tcpliveplay",
    "tcpprep_opts": "tcpprep",
    "tcprewrite_opts": "tcprewrite",
    "tcpbridge_opts": "tcpbridge",
    "tcpreplay_opts": "tcpreplay",
    "tcpreplay_edit_opts": "tcpreplay-edit",
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="compare against the files on disk instead of writing")
    ap.add_argument("--no-adoc", action="store_true",
                    help="skip src/*.adoc (man-page source); only write *_opts.c/h")
    ap.add_argument("--top", default=".", help="top of the source tree")
    args = ap.parse_args(argv)

    top = Path(args.top).resolve()
    rc = 0
    for base, def_rel, defines in CASES:
        def_path = top / def_rel
        search = [str(top / s) for s in SEARCH]
        targets = [(".h", emit_h), (".c", emit_c)]
        if not args.no_adoc:
            man_base = MAN_BASE[base]
            targets.append((None, lambda *a, _b=man_base, **kw: emit_adoc(*a, **kw)))
        for ext, emit in targets:
            text = emit(str(def_path), base, defines, search)
            out_name = f"{MAN_BASE[base]}.adoc" if ext is None else f"{base}{ext}"
            out = top / "src" / out_name
            if args.check:
                current = out.read_text() if out.exists() else None
                if current == text:
                    print(f"OK      {out.relative_to(top)}")
                else:
                    print(f"DIFFERS {out.relative_to(top)}")
                    rc = 1
            elif out.exists() and out.read_text() == text:
                print(f"current {out.relative_to(top)}")
            else:
                out.write_text(text)
                print(f"wrote   {out.relative_to(top)}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
