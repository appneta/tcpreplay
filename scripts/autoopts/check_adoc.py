#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
# GPLv3 - part of the Tcpreplay Suite.
"""Content-validate the AsciiDoc man-page emitter (#895 phase 2, stage 4).

Unlike check_emitters.py (byte-identical against the autogen oracle), the
.adoc output has no oracle to compare against (see emit_adoc.py's module
docstring), so this instead checks properties that must always hold:

  - every real (non-documentation) option in the .def appears in the
    rendered page
  - asciidoctor renders the .adoc to roff without error (when installed)
  - groff parses the roff with zero warnings (when installed)

Exits non-zero, and prints which check failed, on any violation.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file  # noqa: E402
from emit_adoc import emit as emit_adoc  # noqa: E402

CASES = [
    ("tcpcapinfo", "src/tcpcapinfo_opts.def", []),
    ("tcpliveplay", "src/tcpliveplay_opts.def", []),
    ("tcpprep", "src/tcpprep_opts.def", []),
    ("tcprewrite", "src/tcprewrite_opts.def", []),
    ("tcpbridge", "src/tcpbridge_opts.def", []),
    ("tcpreplay", "src/tcpreplay_opts.def", []),
    ("tcpreplay-edit", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"]),
]

SEARCH = ["src", "src/tcpedit"]


def option_names(def_path, defines):
    ir = parse_def_file(def_path, defines=defines, search=SEARCH)
    return [
        dict(fl["attributes"])["name"]
        for fl in ir["flags"]
        if "documentation" not in dict(fl["attributes"])
    ]


def main():
    asciidoctor = shutil.which("asciidoctor")
    groff = shutil.which("groff")
    failed = False

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for base, def_path, defines in CASES:
            adoc = emit_adoc(def_path, base, defines, SEARCH)
            names = option_names(def_path, defines)
            missing = [n for n in names if f"--{n}" not in adoc]
            if missing:
                failed = True
                print(f"FAIL {base}: missing options in .adoc: {missing}")
                continue

            if not asciidoctor:
                print(f"OK   {base} (content check only; asciidoctor not installed)")
                continue

            adoc_path = tmp / f"{base}.adoc"
            man_path = tmp / f"{base}.1"
            adoc_path.write_text(adoc)
            r = subprocess.run(
                [asciidoctor, "-b", "manpage", "-o", str(man_path), str(adoc_path)],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                failed = True
                print(f"FAIL {base}: asciidoctor error:\n{r.stderr}")
                continue

            if groff:
                r = subprocess.run(
                    [groff, "-Tutf8", "-man", "-ww", str(man_path)],
                    capture_output=True, text=True,
                )
                if r.stderr.strip():
                    failed = True
                    print(f"FAIL {base}: groff warnings:\n{r.stderr}")
                    continue

            print(f"OK   {base}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
