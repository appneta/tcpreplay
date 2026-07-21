#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
# GPLv3 - part of the Tcpreplay Suite.
"""Cross-check defparser's IR against emit_h's own output (#895).

*_opts.c/h are not committed to git (see .gitignore) - they're ordinary
build products, regenerated from the .def by scripts/autoopts, so there's
no committed golden file to validate against.  Instead this independently
re-derives, from the parsed IR, the same facts emit_h.py's Model class
computes from its own (separate) reading of the IR, and checks they agree:

  - option names and their order must match the INDEX_OPT_* enum emit_h
    produces, with AutoOpts 'documentation' pseudo-flags occupying an
    index slot but emitting no constant (the reason tcprewrite's enum
    starts at 1)
  - OPTION_CT must equal doc entries + real flags + the automatic
    help/more-help (+ save-opts/load-opts unless disabled) options

This catches divergence between defparser.py's parsing and emit_h.py's
interpretation of it. Byte-identical-to-real-autogen equivalence was
verified once, during phase 2 development, and remains documented in
scripts/autoopts/README.md; it's not re-checked on every run since there's
no committed oracle to diff against any more (see check_emitters.py).

Run from the top of the tree.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file  # noqa: E402
from emit_h import emit_h  # noqa: E402

CASES = [
    ("tcpcapinfo", "src/tcpcapinfo_opts.def", [], "tcpcapinfo_opts"),
    ("tcpliveplay", "src/tcpliveplay_opts.def", [], "tcpliveplay_opts"),
    ("tcpprep", "src/tcpprep_opts.def", [], "tcpprep_opts"),
    ("tcprewrite", "src/tcprewrite_opts.def", [], "tcprewrite_opts"),
    ("tcpbridge", "src/tcpbridge_opts.def", [], "tcpbridge_opts"),
    ("tcpreplay", "src/tcpreplay_opts.def", [], "tcpreplay_opts"),
    ("tcpreplay-edit", "src/tcpreplay_opts.def", ["TCPREPLAY_EDIT"], "tcpreplay_edit_opts"),
]

AUTO_OPTS = ("HELP", "MORE_HELP", "SAVE_OPTS", "LOAD_OPTS")


def validate(name, def_path, defines, base):
    ir = parse_def_file(def_path, defines=defines, search=["src", "src/tcpedit"])
    header = emit_h(def_path, base, defines, ["src", "src/tcpedit"])

    doc_ct = 0
    real = []
    for fl in ir["flags"]:
        attrs = dict(fl["attributes"])
        if "documentation" in attrs:
            doc_ct += 1
        else:
            real.append(attrs["name"].upper().replace("-", "_"))

    enum = re.findall(r"INDEX_OPT_([A-Z0-9_]+)\s*=\s*(\d+)", header)
    emitted = [n for n, _ in enum if n not in AUTO_OPTS]
    auto_ct = sum(1 for n, _ in enum if n in AUTO_OPTS)
    first_idx = int(enum[0][1]) if enum else 0

    errors = []
    if real != emitted:
        for i, (p, c) in enumerate(zip(real, emitted)):
            if p != c:
                errors.append(f"name/order divergence at {i}: parsed={p} emitted={c}")
                break
        if len(real) != len(emitted):
            errors.append(f"count: parsed {len(real)} vs emitted {len(emitted)}")
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
