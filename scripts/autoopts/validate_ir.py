#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Validate defparser's IR against the committed autogen output (#895).

For every tool (including the -DTCPREPLAY_EDIT variant) this parses the
.def sources and cross-checks against the committed *_opts.h headers:

  - option names and their order must match the INDEX_OPT_* enum, with
    AutoOpts 'documentation' pseudo-flags occupying an index slot but
    emitting no constant (the reason tcprewrite's enum starts at 1)
  - OPTION_CT must equal doc entries + real flags + the automatic
    help/more-help (+ save-opts/load-opts unless disabled) options

Run from the top of the tree.  This is the first stage of the phase 2
oracle: emitters extend the comparison to full byte-identical output via
scripts/check-generated-opts.sh.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file  # noqa: E402

CASES = [
    ("tcpcapinfo", "src/tcpcapinfo_opts.def", [], "src/tcpcapinfo_opts.h"),
    ("tcpliveplay", "src/tcpliveplay_opts.def", [], "src/tcpliveplay_opts.h"),
    ("tcpprep", "src/tcpprep_opts.def", [], "src/tcpprep_opts.h"),
    ("tcprewrite", "src/tcprewrite_opts.def", [], "src/tcprewrite_opts.h"),
    ("tcpbridge", "src/tcpbridge_opts.def", [], "src/tcpbridge_opts.h"),
    ("tcpreplay", "src/tcpreplay_opts.def", [], "src/tcpreplay_opts.h"),
    ("tcpreplay-edit", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"], "src/tcpreplay_edit_opts.h"),
]

AUTO_OPTS = ("HELP", "MORE_HELP", "SAVE_OPTS", "LOAD_OPTS")


def validate(name, def_path, defines, header_path):
    ir = parse_def_file(def_path, defines=defines, search=["src", "src/tcpedit"])
    header = Path(header_path).read_text()

    doc_ct = 0
    real = []
    for fl in ir["flags"]:
        attrs = dict(fl["attributes"])
        if "documentation" in attrs:
            doc_ct += 1
        else:
            real.append(attrs["name"].upper().replace("-", "_"))

    enum = re.findall(r"INDEX_OPT_([A-Z0-9_]+)\s*=\s*(\d+)", header)
    committed = [n for n, _ in enum if n not in AUTO_OPTS]
    auto_ct = sum(1 for n, _ in enum if n in AUTO_OPTS)
    first_idx = int(enum[0][1]) if enum else 0

    errors = []
    if real != committed:
        for i, (p, c) in enumerate(zip(real, committed)):
            if p != c:
                errors.append(f"name/order divergence at {i}: parsed={p} committed={c}")
                break
        if len(real) != len(committed):
            errors.append(f"count: parsed {len(real)} vs committed {len(committed)}")
    if first_idx != doc_ct:
        errors.append(f"first enum index {first_idx} != documentation entries {doc_ct}")

    opt_ct = int(re.search(r"#define OPTION_CT\s+(\d+)", header).group(1))
    expect_ct = doc_ct + len(real) + auto_ct
    if opt_ct != expect_ct:
        errors.append(f"OPTION_CT {opt_ct} != computed {expect_ct}")

    return errors


def main():
    failed = False
    for case in CASES:
        errors = validate(*case)
        if errors:
            failed = True
            for e in errors:
                print(f"FAIL {case[0]}: {e}")
        else:
            print(f"OK   {case[0]}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
