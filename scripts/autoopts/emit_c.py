#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Emit AutoOpts-compatible *_opts.c from the defparser IR (#895 phase 2).

Output must be byte-identical to what GNU autogen 5.18.16 produced from the
same .def (the committed files are the oracle).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file, text_of  # noqa: E402
from emit_h import Model, LICENSES  # noqa: E402

WRAP = 75


import re as _re


def texi(text):
    """The texinfo-ish conversions autogen applies to pooled texts."""
    text = _re.sub(r"@file\{([^}]*)\}", r"'\1'", text)
    text = _re.sub(r"@var\{([^}]*)\}", r"'\1'", text)
    # an @item line becomes a wider paragraph break
    text = _re.sub(r"^@item\n", "\n\n", text, flags=_re.M)
    return text


def reflow(text, width=WRAP):
    """autogen's paragraph re-wrap: greedy fill to `width` columns,
    preserving intra-paragraph spacing runs (sentence double-spaces).
    Paragraphs (blank-line separated) keep a blank line between them.
    """
    parts = _re.split(r"(\n{2,})", text)
    out = []
    seps = []
    paras = []
    for i, seg in enumerate(parts):
        if i % 2 == 0:
            paras.append(seg)
        else:
            seps.append(seg)
    for p in paras:
        # whitespace runs collapse on refill; a word that ends a sentence
        # is followed by two spaces (classic fill behavior)
        words = [(w, 2 if w.endswith((".", "!", "?")) else 1) for w in p.split()]
        if not words:
            continue
        lines = []
        cur, cur_sp = words[0]
        for w, sp in words[1:]:
            if len(cur) + cur_sp + len(w) <= width:
                cur += " " * cur_sp + w
                cur_sp = sp
            else:
                lines.append(cur)
                cur = w
                cur_sp = sp
        lines.append(cur)
        out.append("\n".join(lines) + "\n")
    result = ""
    si = 0
    first = True
    for i, seg in enumerate(parts):
        if i % 2 == 0:
            if seg.split():
                if not first:
                    result += sep_pending
                result += out[si]
                si += 1
                first = False
        else:
            sep_pending = seg[1:]  # paragraph text already ends with \n
    return result


def c_escape(s):
    return (
        s.replace("\\", "\\\\").replace('"', '\\"').replace("\t", "\\t").replace("\n", "\\n")
    )


class StringPool:
    """The <prog>_opt_strs table: segments at computed byte offsets."""

    def __init__(self, prog):
        self.prog = prog
        self.segments = []  # (offset, text)
        self.size = 0
        self._dedup = {}

    def add(self, text):
        if text in self._dedup:
            return self._dedup[text]
        off = self.size
        self.segments.append((off, text))
        self.size += len(text) + 1  # NUL terminator
        self._dedup[text] = off
        return off

    def render(self):
        lines = [f"static char const {self.prog}_opt_strs[{self.size}] ="]
        for si, (off, text) in enumerate(self.segments):
            last_seg = si == len(self.segments) - 1
            # split the segment into chunks: one source line per chunk,
            # with any run of following newlines (paragraph breaks) glued on
            parts = text.split("\n")
            if parts and parts[-1] == "":
                parts.pop()
            chunks = []
            i2 = 0
            trailing_nl = text.endswith("\n")
            while i2 < len(parts):
                part = parts[i2]
                nls = 1
                j2 = i2 + 1
                while j2 < len(parts) and parts[j2] == "":
                    nls += 1
                    j2 += 1
                if i2 == len(parts) - 1 and not trailing_nl:
                    nls = 0
                chunks.append(c_escape(part) + "\\n" * nls)
                i2 = j2
            if not chunks:
                chunks = [""]
            for ci, chunk in enumerate(chunks):
                first = ci == 0
                last_chunk = ci == len(chunks) - 1
                nul = "" if (last_seg and last_chunk) else ("\\0" if last_chunk else "")
                prefix = f"/* {off:5d} */ " if first else " " * 12
                terminator = ";" if (last_seg and last_chunk) else ""
                lines.append(f'{prefix}"{chunk}{nul}"{terminator}')
        return "\n".join(lines)


class _IdxNames(dict):
    def __missing__(self, key):
        return key.upper().replace("-", "_")


class CModel(Model):
    """Extends the header model with .c specific derivations."""

    def __init__(self, ir, base):
        super().__init__(ir, base)
        self.raw_attrs = [(n, v) for n, v in ir["attributes"]]
        # combined def-order list of doc and real flags with running index
        self.all_flags = []
        di, ri = 0, 0
        combined = []
        for fl in ir["flags"]:
            keys = {k.replace("_", "-") for k, _ in fl["attributes"]}
            combined.append("doc" if "documentation" in keys else "real")
        idx = 0
        d_iter = iter(self.doc_flags)
        r_iter = iter(self.flags)
        for kind in combined:
            fa = next(d_iter) if kind == "doc" else next(r_iter)
            fa["_kind"] = kind
            fa["_index"] = idx
            idx += 1
            self.all_flags.append(fa)
        self.package = self.attrs.get("package", "")
        self.title = self.attrs.get("prog-title", "")
        self.argument = self.attrs.get("argument")
        self.eaddr = dict(self.attrs["copyright"]).get("eaddr")
        cp = dict(self.attrs["copyright"])
        self.cp_date = cp["date"]
        self.cp_owner = cp["owner"]
        self.cp_type = str(cp.get("type", "gpl")).strip('"')


BSD_SHORT = """\
Copyright (C) {date} {owner}, all rights reserved.
This is free software. It is licensed for use, modification and
redistribution under the terms of the
Modified (3 clause) Berkeley Software Distribution License
<http://www.xfree86.org/3.3.6/COPYRIGHT2.html>
"""

BSD_LONG = (
    "Redistribution and use in source and binary forms, with or without "
    "modification, are permitted provided that the following conditions "
    "are met: 1.  Redistributions of source code must retain the above "
    "copyright notice, this list of conditions and the following "
    "disclaimer.  2.  Redistributions in binary form must reproduce the "
    "above copyright notice, this list of conditions and the following "
    "disclaimer in the documentation and/or other materials provided "
    "with the distribution.  3.  Neither the name {owner}'' nor the name "
    "of any other contributor may be used to endorse or promote products "
    "derived from this software without specific prior written "
    "permission.\n\n"
    "{prog} IS PROVIDED BY {owner} AS IS'' AND ANY EXPRESS OR IMPLIED "
    "WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES "
    "OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE "
    "DISCLAIMED.  IN NO EVENT SHALL {owner} OR ANY OTHER CONTRIBUTORS BE "
    "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR "
    "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT "
    "OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR "
    "BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF "
    "LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT "
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE "
    "USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH "
    "DAMAGE.\n"
)

GPL_SHORT = """\
Copyright (C) {date} {owner}, all rights reserved.
This is free software. It is licensed for use, modification and
redistribution under the terms of the GNU General Public License,
version 3 or later <http://gnu.org/licenses/gpl.html>
"""

GPL_LONG = """\
{prog} is free software: you can redistribute it and/or modify it under the \
terms of the GNU General Public License as published by the Free Software \
Foundation, either version 3 of the License, or (at your option) any later \
version.

{prog} is distributed in the hope that it will be useful, but WITHOUT ANY \
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS \
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more \
details.

You should have received a copy of the GNU General Public License along \
with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


def build_pool(m):
    """Assemble the string pool; returns (pool, refs dict)."""
    pool = StringPool(m.prog)
    refs = {}
    if m.cp_type == "bsd":
        short = BSD_SHORT
        long_ = reflow(BSD_LONG.format(prog=m.prog, owner=m.cp_owner))
    else:
        short = GPL_SHORT
        long_ = reflow(GPL_LONG.format(prog=m.prog))
    refs["zCopyright"] = pool.add(
        f"{m.prog} ({m.package})\n" + short.format(date=m.cp_date, owner=m.cp_owner)
    )
    refs["zLicenseDescrip"] = pool.add(long_)
    for fa in m.all_flags:
        if fa["_kind"] == "doc":
            fa["_desc_text"] = texi(text_of(fa.get("descrip", ""))) or ":"
            fa["_desc_off"] = pool.add(fa["_desc_text"])
            continue
        n = m.cname(fa)
        desc = texi(text_of(fa.get("descrip", "")))
        desc = reflow(desc, 72).rstrip("\n")
        fa["_desc_text"] = desc
        fa["_desc_off"] = pool.add(desc)
        fa["_NAME_off"] = pool.add(n)
        fa["_name_off"] = pool.add(fa["name"].replace("_", "-"))
        if "arg-default" in fa and fa.get("arg-type") != "number":
            fa["_dft_off"] = pool.add(text_of(fa["arg-default"]))
    refs["help_desc"] = pool.add("display extended usage information and exit")
    refs["help_name"] = pool.add("help")
    refs["morehelp_desc"] = pool.add("extended usage information passed thru pager")
    refs["morehelp_name"] = pool.add("more-help")
    if m.save_opts:
        refs["save_desc"] = pool.add("save the option state to a config file")
        refs["save_name"] = pool.add("save-opts")
    if m.load_opts:
        refs["load_desc"] = pool.add("load options from a config file")
        refs["load_NAME"] = pool.add("LOAD_OPTS")
        refs["no_load_name"] = pool.add("no-load-opts")
        refs["load_pfx"] = pool.add("no")
    refs["zPROGNAME"] = pool.add(m.prog.upper().replace("-", "_"))
    base_usage = (
        f"{m.prog} ({m.package}) - {m.title}\n"
        f"Usage:  %s [ -<flag> [<val>] | --<name>[{{=| }}<val>] ]..."
    )
    if m.argument and 57 + 1 + len(m.argument) > 79:
        refs["zUsageTitle"] = pool.add(base_usage + f" \\\n\t\t{m.argument}\n")
    elif m.argument:
        refs["zUsageTitle"] = pool.add(base_usage + f" {m.argument}\n")
    else:
        refs["zUsageTitle"] = pool.add(base_usage + "\n")
    m.homercs = []
    if "homerc" in m.attrs and m.load_opts:
        # homerc may repeat; collect in def order from the raw attribute list
        for n2, v2 in m.raw_attrs:
            if n2.replace("_", "-") == "homerc":
                m.homercs.append(text_of(v2))
        for hr in m.homercs:
            refs.setdefault("homerc_offs", []).append(pool.add(hr))
        rcfile = text_of(m.attrs.get("rcfile", "." + m.prog + "rc"))
        refs["zRcName"] = pool.add(rcfile)
    if m.eaddr:
        refs["zBugsAddr"] = pool.add(m.eaddr)
    if text_of(m.attrs.get("explain", "")).strip():
        refs["zExplain"] = pool.add(reflow(texi(text_of(m.attrs["explain"]))))
    if text_of(m.attrs.get("detail", "")).strip():
        refs["zDetail"] = pool.add(reflow(texi(text_of(m.attrs["detail"]))))
    return pool, refs


def flag_bits(fa):
    bits = ["OPTST_DISABLED"]
    if "stack-arg" in fa:
        bits.append("OPTST_STACKED")
    if "must-set" in fa:
        bits.append("OPTST_MUST_SET")
    if "immediate" in fa:
        bits.append("OPTST_IMM")
    at = fa.get("arg-type")
    if at == "number":
        bits.append("OPTST_SET_ARGTYPE(OPARG_TYPE_NUMERIC)")
    elif at == "string":
        bits.append("OPTST_SET_ARGTYPE(OPARG_TYPE_STRING)")
    return bits


def flags_define_lines(name, bits):
    """FLAGS define wrapped greedily at 78 columns, autogen style."""
    first = f"#define {name}_FLAGS     ({bits[0]}"
    lines = []
    cur = first
    for b in bits[1:]:
        add = f" | {b}"
        if len(cur) + len(add) > 75:
            lines.append(cur + " \\")
            cur = f"        | {b}"
        else:
            cur += add
    lines.append(cur + ")")
    return lines


def emit(def_path, base, defines=(), search=()):
    ir = parse_def_file(def_path, defines=defines, search=search)
    m = CModel(ir, base)
    m.attrs["_deffile"] = Path(def_path).name
    pool, refs = build_pool(m)
    P = m.prog
    up = P.upper().replace("-", "_")
    strs = f"{P}_opt_strs"
    out = []
    a = out.append

    # ---- header comment (same as .h, s/header/source/) -------------------
    lic = LICENSES[m.cp_type]
    a("/*   -*- buffer-read-only: t -*- vi: set ro:")
    a(" *")
    a(f" *  DO NOT EDIT THIS FILE   ({base}.c)")
    a(" *")
    a(" *  It has been AutoGen-ed")
    a(f" *  From the definitions    {m.attrs['_deffile']}")
    a(" *  and the template file   options")
    a(" *")
    a(" * Generated from AutoOpts 42:1:17 templates.")
    a(" *")
    a(" *  AutoOpts is a copyrighted work.  This source file is not encumbered")
    a(" *  by AutoOpts licensing, but is provided under the licensing terms chosen")
    a(f" *  by the {P} author or copyright holder.  AutoOpts is")
    a(" *  licensed under the terms of the LGPL.  The redistributable library")
    a(" *  (``libopts'') is licensed under the terms of either the LGPL or, at the")
    a(" *  users discretion, the BSD license.  See the AutoOpts and/or libopts sources")
    a(" *  for details.")
    a(" *")
    a(f" * The {P} program is copyrighted and licensed")
    a(" * under the following terms:")
    a(" *")
    a(lic.format(date=m.cp_date, owner=m.cp_owner, prog=P))
    a(" */")
    a("")
    a("#ifndef __doxygen__")
    a("#define OPTION_CODE_COMPILE 1")
    a(f'#include "{base}.h"')
    a("#include <sys/types.h>")
    a("#include <sys/stat.h>")
    a("")
    a("#include <errno.h>")
    a("#include <fcntl.h>")
    a("#include <limits.h>")
    a("#include <stdio.h>")
    a("#include <stdlib.h>")
    a("#include <string.h>")
    a("#include <unistd.h>")
    a("")
    a("#ifdef  __cplusplus")
    a('extern "C" {')
    a("#endif")
    a("extern FILE * option_usage_fp;")
    a(f"#define zCopyright      ({strs}+{refs['zCopyright']})")
    a(f"#define zLicenseDescrip ({strs}+{refs['zLicenseDescrip']})")
    a("")
    if "include" in m.attrs:
        a("/*")
        a(" *  global included definitions")
        a(" */")
        out.extend(text_of(m.attrs["include"]).split("\n"))
    a("")
    a("#ifndef NULL")
    a("#  define NULL 0")
    a("#endif")
    a("")
    a("/**")
    a(f" *  static const strings for {P} options")
    a(" */")
    a(pool.render())
    a("")

    # ---- per-option describe blocks --------------------------------------
    for fa in m.all_flags:
        n = m.cname(fa)
        if fa["_kind"] == "doc":
            a("/**")
            a(f" *  {fa['name']} option description:")
            a(" */")
            a(f"/** {fa['name']} option separation text */")
            a(f"#define {n}_DESC      ({strs}+{fa['_desc_off']})")
            a(f"#define {n}_FLAGS     (OPTST_DOCUMENT | OPTST_NO_INIT)")
            a("")
            continue
        guard = fa.get("ifdef")
        has_lists = "flags-must" in fa or "flags-cant" in fa
        a("/**")
        if has_lists:
            a(f" *  {fa['name']} option description with")
            a(' *  "Must also have options" and "Incompatible options":')
        else:
            a(f" *  {fa['name']} option description:")
        a(" */")
        if guard:
            a(f"#ifdef {guard}")
        a(f"/** Descriptive text for the {fa['name']} option */")
        a(f"#define {n}_DESC      ({strs}+{fa['_desc_off']})")
        a(f"/** Upper-cased name for the {fa['name']} option */")
        a(f"#define {n}_NAME      ({strs}+{fa['_NAME_off']})")
        a(f"/** Name string for the {fa['name']} option */")
        a(f"#define {n}_name      ({strs}+{fa['_name_off']})")
        if "arg-default" in fa:
            a(f"/** The compiled in default value for the {fa['name']} option argument */")
            if "_dft_off" in fa:
                a(f"#define {n}_DFT_ARG   ({strs}+{fa['_dft_off']})")
            else:
                a(f"#define {n}_DFT_ARG   ((char const*){text_of(fa['arg-default'])})")
        camel = "_".join(w[0].upper() + w[1:] for w in fa["name"].replace("_", "-").split("-"))
        # autogen uppercases the referenced name without checking that the
        # option exists in this tool (such blocks are always #ifdef-guarded)
        idx_of = _IdxNames()
        if "flags-must" in fa:
            a(f"/** Other options that are required by the {fa['name']} option */")
            a(f"static int const a{camel}MustList[] = {{")
            names = fa["flags-must"]
            rows = [f"    INDEX_OPT_{idx_of[x]}," for x in names[:-1]]
            rows.append(f"    INDEX_OPT_{idx_of[names[-1]]}, NO_EQUIVALENT }};")
            out.extend(rows)
        if "flags-cant" in fa:
            a(f"/** Other options that appear in conjunction with the {fa['name']} option */")
            a(f"static int const a{camel}CantList[] = {{")
            names = fa["flags-cant"]
            rows = [f"    INDEX_OPT_{idx_of[x]}," for x in names[:-1]]
            rows.append(f"    INDEX_OPT_{idx_of[names[-1]]}, NO_EQUIVALENT }};")
            out.extend(rows)
        a(f"/** Compiled in flag settings for the {fa['name']} option */")
        out.extend(flags_define_lines(n, flag_bits(fa)))
        a("")
        if guard:
            a(f"#else   /* disable {fa['name']} */")
            a(f"#define {n}_FLAGS     (OPTST_OMITTED | OPTST_NO_INIT)")
            if "arg-default" in fa:
                a(f"#define {n}_DFT_ARG   NULL")
            if "flags-must" in fa:
                a(f"#define a{camel}MustList   NULL")
            if "flags-cant" in fa:
                a(f"#define a{camel}CantList   NULL")
            a(f"#define {n}_NAME      NULL")
            a(f"#define {n}_DESC      NULL")
            a(f"#define {n}_name      NULL")
            a(f"#endif  /* {guard} */")
            a("")

    # ---- help/more-help block --------------------------------------------
    a("/*")
    a(" *  Help/More_Help option descriptions:")
    a(" */")
    a(f"#define HELP_DESC       ({strs}+{refs['help_desc']})")
    a(f"#define HELP_name       ({strs}+{refs['help_name']})")
    a("#ifdef HAVE_WORKING_FORK")
    a(f"#define MORE_HELP_DESC  ({strs}+{refs['morehelp_desc']})")
    a(f"#define MORE_HELP_name  ({strs}+{refs['morehelp_name']})")
    a("#define MORE_HELP_FLAGS (OPTST_IMM | OPTST_NO_INIT)")
    a("#else")
    a("#define MORE_HELP_DESC  HELP_DESC")
    a("#define MORE_HELP_name  HELP_name")
    a("#define MORE_HELP_FLAGS (OPTST_OMITTED | OPTST_NO_INIT)")
    a("#endif")
    if m.save_opts:
        a(f"#define SAVE_OPTS_DESC  ({strs}+{refs['save_desc']})")
        a(f"#define SAVE_OPTS_name  ({strs}+{refs['save_name']})")
    if m.load_opts:
        a(f"#define LOAD_OPTS_DESC     ({strs}+{refs['load_desc']})")
        a(f"#define LOAD_OPTS_NAME     ({strs}+{refs['load_NAME']})")
        a(f"#define NO_LOAD_OPTS_name  ({strs}+{refs['no_load_name']})")
        a(f"#define LOAD_OPTS_pfx      ({strs}+{refs['load_pfx']})")
        a("#define LOAD_OPTS_name     (NO_LOAD_OPTS_name + 3)")

    # ---- callback declarations -------------------------------------------
    a("/**")
    a(" *  Declare option callback procedures")
    a(" */")
    range_procs = []
    code_procs = []
    for fa in m.flags:
        cap = "_".join(w[0].upper() + w[1:] for w in fa["name"].split("-"))
        if "arg-range" in fa:
            range_procs.append((fa, f"doOpt{cap}"))
        elif "flag-code" in fa:
            code_procs.append((fa, f"doOpt{cap}"))
    static_list = sorted([p2 for fa2, p2 in code_procs if not fa2.get("ifdef")]
                         + [p2 for fa2, p2 in range_procs if not fa2.get("ifdef")]
                         + ["doUsageOpt"])
    guarded = []
    for fa2 in m.flags:
        cap2 = "_".join(w[0].upper() + w[1:] for w in fa2["name"].replace("_", "-").split("-"))
        if ("arg-range" in fa2 or "flag-code" in fa2) and fa2.get("ifdef"):
            guarded.append((fa2, f"doOpt{cap2}"))
    for fa, proc in guarded:
        guard = fa.get("ifdef")
        if not guard:
            continue
        a(f"#ifdef {guard}")
        a(f"  static tOptProc {proc};")
        a(f"#else /* not {guard} */")
        a(f"# define {proc} NULL")
        a(f"#endif /* def/not {guard} */")
    a("extern tOptProc")
    a("    optionBooleanVal,   optionNestedVal,    optionNumericVal,")
    a("    optionPagedUsage,   optionPrintVersion, optionResetOpt,")
    a("    optionStackArg,     optionTimeDate,     optionTimeVal,")
    a("    optionUnstackArg,   optionVendorOption;")
    a("static tOptProc")
    if len(static_list) <= 3:
        a("    " + ", ".join(static_list) + ";")
    else:
        cellw = max(len(x) for x in static_list) + 2
        per_row = max(1, (76 - 4 + 0) // cellw)
        per_row = min(per_row, 3)
        rows = []
        for i in range(0, len(static_list), per_row):
            chunk = static_list[i:i + per_row]
            cells = []
            for j, name2 in enumerate(chunk):
                sep = ";" if (i + j == len(static_list) - 1) else ","
                cell = name2 + sep
                if j < len(chunk) - 1:
                    cell = cell.ljust(cellw)
                cells.append(cell)
            rows.append("    " + "".join(cells))
        out.extend(rows)
    a("")

    # ---- descriptor table -------------------------------------------------
    a("/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */")
    a("/**")
    a(f" *  Define the {P} Option Descriptions.")
    a(" * This is an array of OPTION_CT entries, one for each")
    a(f" * option that the {P} program responds to.")
    a(" */")
    a("static tOptDesc optDesc[OPTION_CT] = {")
    entries = []
    for fa in m.all_flags:
        n = m.cname(fa)
        idx = fa["_index"]
        if fa["_kind"] == "doc":
            entries.append("\n".join([
                f"  {{  /* entry idx, value */ {idx}, 0,",
                f"     /* equiv idx, value */ {idx}, 0,",
                "     /* equivalenced to  */ NO_EQUIVALENT,",
                "     /* min, max, act ct */ 0, 0, 0,",
                f"     /* opt state flags  */ {n}_FLAGS, 0,",
                "     /* last opt argumnt */ { NULL },",
                "     /* arg list/cookie  */ NULL,",
                "     /* must/cannot opts */ NULL, NULL,",
                "     /* option proc      */ NULL,",
                f"     /* desc, NAME, name */ {n}_DESC, NULL, NULL,",
                "     /* disablement strs */ NULL, NULL }",
            ]))
            continue
        proc = "NULL"
        cap = "_".join(w[0].upper() + w[1:] for w in fa["name"].split("-"))
        if "arg-range" in fa or "flag-code" in fa:
            proc = f"doOpt{cap}"
        elif "stack-arg" in fa:
            proc = "optionStackArg"
        elif fa.get("arg-type") == "number":
            proc = "optionNumericVal"
        maxc = fa.get("max", "1")
        dft = f"{n}_DFT_ARG" if "arg-default" in fa else "NULL"
        argcmt = "" if "arg-default" in fa else f" /* --{fa['name']} */"
        camel = "_".join(w[0].upper() + w[1:] for w in fa["name"].replace("_", "-").split("-"))
        must = f"a{camel}MustList" if "flags-must" in fa else "NULL"
        cant = f"a{camel}CantList" if "flags-cant" in fa else "NULL"
        if fa.get("_equiv_target"):
            equiv = "NO_EQUIVALENT, 0"
            equiv_to = "NO_EQUIVALENT"
        elif "equivalence" in fa:
            equiv = "NOLIMIT, NOLIMIT"
            tgt = fa["equivalence"].upper().replace("-", "_")
            equiv_to = f"INDEX_OPT_{tgt}"
        else:
            equiv = f"{idx}, VALUE_OPT_{n}"
            equiv_to = "NO_EQUIVALENT"
        minc = "1" if "must-set" in fa else "0"
        e = [
            f"  {{  /* entry idx, value */ {idx}, VALUE_OPT_{n},",
            f"     /* equiv idx, value */ {equiv},",
            f"     /* equivalenced to  */ {equiv_to},",
            f"     /* min, max, act ct */ {minc}, {maxc}, 0,",
            f"     /* opt state flags  */ {n}_FLAGS, 0,",
            f"     /* last opt argumnt */ {{ {dft} }},{'' if dft != 'NULL' else argcmt}",
            "     /* arg list/cookie  */ NULL,",
            f"     /* must/cannot opts */ {must}, {cant},",
            f"     /* option proc      */ {proc},",
            f"     /* desc, NAME, name */ {n}_DESC, {n}_NAME, {n}_name,",
            "     /* disablement strs */ NULL, NULL }",
        ]
        entries.append("\n".join(e))
    entries.append("\n".join([
        "  {  /* entry idx, value */ INDEX_OPT_HELP, VALUE_OPT_HELP,",
        "     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_HELP,",
        "     /* equivalenced to  */ NO_EQUIVALENT,",
        "     /* min, max, act ct */ 0, 1, 0,",
        "     /* opt state flags  */ OPTST_IMM | OPTST_NO_INIT, AOUSE_HELP,",
        "     /* last opt argumnt */ { NULL },",
        "     /* arg list/cookie  */ NULL,",
        "     /* must/cannot opts */ NULL, NULL,",
        "     /* option proc      */ doUsageOpt,",
        "     /* desc, NAME, name */ HELP_DESC, NULL, HELP_name,",
        "     /* disablement strs */ NULL, NULL }",
    ]))
    entries.append("\n".join([
        "  {  /* entry idx, value */ INDEX_OPT_MORE_HELP, VALUE_OPT_MORE_HELP,",
        "     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_MORE_HELP,",
        "     /* equivalenced to  */ NO_EQUIVALENT,",
        "     /* min, max, act ct */ 0, 1, 0,",
        "     /* opt state flags  */ MORE_HELP_FLAGS, AOUSE_MORE_HELP,",
        "     /* last opt argumnt */ { NULL },",
        "     /* arg list/cookie  */ NULL,",
        "     /* must/cannot opts */ NULL,  NULL,",
        "     /* option proc      */ optionPagedUsage,",
        "     /* desc, NAME, name */ MORE_HELP_DESC, NULL, MORE_HELP_name,",
        "     /* disablement strs */ NULL, NULL }",
    ]))
    if m.save_opts:
        entries.append("\n".join([
            "  {  /* entry idx, value */ INDEX_OPT_SAVE_OPTS, VALUE_OPT_SAVE_OPTS,",
            "     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_SAVE_OPTS,",
            "     /* equivalenced to  */ NO_EQUIVALENT,",
            "     /* min, max, act ct */ 0, 1, 0,",
            "     /* opt state flags  */ OPTST_SET_ARGTYPE(OPARG_TYPE_STRING)",
            "                       | OPTST_ARG_OPTIONAL | OPTST_NO_INIT, AOUSE_SAVE_OPTS,",
            "     /* last opt argumnt */ { NULL },",
            "     /* arg list/cookie  */ NULL,",
            "     /* must/cannot opts */ NULL,  NULL,",
            "     /* option proc      */ NULL,",
            "     /* desc, NAME, name */ SAVE_OPTS_DESC, NULL, SAVE_OPTS_name,",
            "     /* disablement strs */ NULL, NULL }",
        ]))
    if m.load_opts:
        entries.append("\n".join([
            "  {  /* entry idx, value */ INDEX_OPT_LOAD_OPTS, VALUE_OPT_LOAD_OPTS,",
            "     /* equiv idx value  */ NO_EQUIVALENT, VALUE_OPT_LOAD_OPTS,",
            "     /* equivalenced to  */ NO_EQUIVALENT,",
            "     /* min, max, act ct */ 0, NOLIMIT, 0,",
            "     /* opt state flags  */ OPTST_SET_ARGTYPE(OPARG_TYPE_STRING)",
            "\t\t\t  | OPTST_DISABLE_IMM, AOUSE_LOAD_OPTS,",
            "     /* last opt argumnt */ { NULL },",
            "     /* arg list/cookie  */ NULL,",
            "     /* must/cannot opts */ NULL, NULL,",
            "     /* option proc      */ optionLoadOpt,",
            "     /* desc, NAME, name */ LOAD_OPTS_DESC, LOAD_OPTS_NAME, LOAD_OPTS_name,",
            "     /* disablement strs */ NO_LOAD_OPTS_name, LOAD_OPTS_pfx }",
        ]))
    a(",\n\n".join(entries))
    a("};")
    _ptr = False
    for fa in m.all_flags:
        if fa["_kind"] == "doc" and "lib-name" in fa:
            a("")
            a(f"tOptDesc * const {fa['lib-name']}_{fa['name']}_optDesc_p = "
              f"optDesc + {fa['_index']};")
            _ptr = True
    a("")
    if not _ptr:
        a("")

    # ---- program references ------------------------------------------------
    a("/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */")
    a(f"/** Reference to the upper cased version of {P}. */")
    a(f"#define zPROGNAME       ({strs}+{refs['zPROGNAME']})")
    a(f"/** Reference to the title line for {P} usage. */")
    a(f"#define zUsageTitle     ({strs}+{refs['zUsageTitle']})")
    if m.homercs:
        a(f"/** {P} configuration file name. */")
        a(f"#define zRcName         ({strs}+{refs['zRcName']})")
        a(f"/** Directories to search for {P} config files. */")
        a(f"static char const * const apzHomeList[{len(m.homercs) + 1}] = {{")
        for off in refs["homerc_offs"]:
            a(f"    {strs}+{off},")
        a("    NULL };")
    else:
        a(f"/** There is no {P} configuration file. */")
        a("#define zRcName         NULL")
        a(f"/** There are no directories to search for {P} config files. */")
        a("#define apzHomeList     NULL")
    a(f"/** The {P} program bug email address. */")
    if m.eaddr:
        a(f"#define zBugsAddr       ({strs}+{refs['zBugsAddr']})")
    else:
        a("#define zBugsAddr       (NULL)")
    a(f"/** Clarification/explanation of what {P} does. */")
    if "zExplain" in refs:
        a(f"#define zExplain        ({strs}+{refs['zExplain']})")
    else:
        a("#define zExplain        (NULL)")
    a(f"/** Extra detail explaining what {P} does. */")
    if "zDetail" in refs:
        a(f"#define zDetail         ({strs}+{refs['zDetail']})")
    else:
        a("#define zDetail         (NULL)")
    a(f"/** The full version string for {P}. */")
    a("#define zFullVersion    (NULL)")
    a("/* extracted from optcode.tlib near line 342 */")
    a("")
    a("#if defined(ENABLE_NLS)")
    a("# define OPTPROC_BASE OPTPROC_TRANSLATE")
    a("  static tOptionXlateProc translate_option_strings;")
    a("#else")
    a("# define OPTPROC_BASE OPTPROC_NONE")
    a("# define translate_option_strings NULL")
    a("#endif /* ENABLE_NLS */")
    a("")
    a(f"#define {P}_full_usage (NULL)")
    a(f"#define {P}_short_usage (NULL)")
    a("")
    a("#endif /* not defined __doxygen__ */")
    a("")
    a("/*")
    a(" *  Create the static procedure(s) declared above.")
    a(" */")
    a("/**")
    a(" * The callout function that invokes the optionUsage function.")
    a(" *")
    a(" * @param[in] opts the AutoOpts option description structure")
    a(' * @param[in] od   the descriptor for the "help" (usage) option.')
    a(" * @noreturn")
    a(" */")
    a("static void")
    a("doUsageOpt(tOptions * opts, tOptDesc * od)")
    a("{")
    a("    int ex_code;")
    a(f"    ex_code = {up}_EXIT_SUCCESS;")
    a(f"    optionUsage(&{m.progvar}, ex_code);")
    a("    /* NOTREACHED */")
    a(f"    exit({up}_EXIT_FAILURE);")
    a("    (void)opts;")
    a("    (void)od;")
    a("}")

    # ---- generated option procs, in flag order ------------------------
    procs = []
    for fa in m.flags:
        n0 = fa["name"]
        cap = n0[0].upper() + n0[1:].replace("-", "_")
        cap = "_".join(w[0].upper() + w[1:] for w in n0.split("-"))
        if "arg-range" in fa:
            procs.append((fa, f"doOpt{cap}", "range"))
        elif "flag-code" in fa:
            procs.append((fa, f"doOpt{cap}", "code"))
    for fa, proc, kind in procs:
        n = fa["name"]
        guard = fa.get("ifdef")
        a("")
        a("/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */")
        a("/**")
        gsfx = f", when {guard} is #define-d" if guard else ""
        a(f" * Code to handle the {n} option{gsfx}.")
        doc = text_of(fa.get("doc", ""))
        if doc.endswith("\n"):
            doc = doc[:-1]
        for dl in doc.split("\n"):
            a(f" * {dl.rstrip()}" if dl.strip() else " *")
        a(f" * @param[in] pOptions the {P} options data structure")
        a(" * @param[in,out] pOptDesc the option descriptor for this option.")
        a(" */")
        if kind == "range":
            ranges = [text_of(fa["arg-range"])]
            if guard:
                a(f"#ifdef {guard}")
            a("static void")
            a(f"{proc}(tOptions* pOptions, tOptDesc* pOptDesc)")
            a("{")
            a("    static struct {long rmin, rmax;} const rng[%d] = {" % len(ranges))
            rrows = []
            for r in ranges:
                lo, hi = r.split("->")
                lo = lo.strip() or "LONG_MIN"
                hi = hi.strip() or "LONG_MAX"
                rrows.append(f"        {{ {lo}, {hi} }}")
            a(",\n".join(rrows) + " };")
            a("    int  ix;")
            a("")
            a("    if (pOptions <= OPTPROC_EMIT_LIMIT)")
            a("        goto emit_ranges;")
            a("    optionNumericVal(pOptions, pOptDesc);")
            a("")
            a(f"    for (ix = 0; ix < {len(ranges)}; ix++) {{")
            a("        if (pOptDesc->optArg.argInt < rng[ix].rmin)")
            a("            continue;  /* ranges need not be ordered. */")
            a("        if (pOptDesc->optArg.argInt == rng[ix].rmin)")
            a("            return;")
            a("        if (rng[ix].rmax == LONG_MIN)")
            a("            continue;")
            a("        if (pOptDesc->optArg.argInt <= rng[ix].rmax)")
            a("            return;")
            a("    }")
            a("")
            a("    option_usage_fp = stderr;")
            a("")
            a(" emit_ranges:")
            a(f"optionShowRange(pOptions, pOptDesc, VOIDP(rng), {len(ranges)});")
            a("}")
            if guard:
                a(f"#endif /* defined {guard} */")
        else:
            code = fa["flag-code"]
            if guard:
                a(f"#ifdef {guard}")
            a("static void")
            a(f"{proc}(tOptions* pOptions, tOptDesc* pOptDesc)")
            a("{")
            a("    /*")
            a("     * Be sure the flag-code[0] handles special values for the options pointer")
            a("     * viz. (poptions <= OPTPROC_EMIT_LIMIT) *and also* the special flag bit")
            a("     * ((poptdesc->fOptState & OPTST_RESET) != 0) telling the option to")
            a("     * reset its state.")
            a("     */")
            a(f"    /* extracted from {code['file']}, line {code['line']} */")
            body = text_of(code)
            if body.endswith("\n"):
                body = body[:-1]
            a(body)
            a("    (void)pOptDesc;")
            a("    (void)pOptions;")
            a("}")
            if guard:
                a(f"#endif /* defined {guard} */")
    a("/* extracted from optmain.tlib near line 1250 */")
    a("")
    a("/**")
    a(f" * The directory containing the data associated with {P}.")
    a(" */")
    a("#ifndef  PKGDATADIR")
    a('# define PKGDATADIR ""')
    a("#endif")
    a("")
    a("/**")
    a(f" * Information about the person or institution that packaged {P}")
    a(" * for the current distribution.")
    a(" */")
    a("#ifndef  WITH_PACKAGER")
    a(f"# define {P}_packager_info NULL")
    a("#else")
    a(f"/** Packager information for {P}. */")
    a(f"static char const {P}_packager_info[] =")
    a('    "Packaged by " WITH_PACKAGER')
    a("")
    a("# ifdef WITH_PACKAGER_VERSION")
    a('        " ("WITH_PACKAGER_VERSION")"')
    a("# endif")
    a("")
    a("# ifdef WITH_PACKAGER_BUG_REPORTS")
    a(f'    "\\nReport {P} bugs to " WITH_PACKAGER_BUG_REPORTS')
    a("# endif")
    a('    "\\n";')
    a("#endif")
    a("#ifndef __doxygen__")
    a("")
    a("#endif /* __doxygen__ */")
    a("/**")
    a(f" * The option definitions for {P}.  The one structure that")
    a(" * binds them all.")
    a(" */")
    a(f"tOptions {m.progvar} = {{")
    a("    OPTIONS_STRUCT_VERSION,")
    a("    0, NULL,                    /* original argc + argv    */")
    a("    ( OPTPROC_BASE")
    a("    + OPTPROC_ERRSTOP")
    a("    + OPTPROC_SHORTOPT")
    a("    + OPTPROC_LONGOPT")
    a("    + OPTPROC_NO_REQ_OPT")
    if m.argument:
        a("    + OPTPROC_ARGS_REQ")
    else:
        a("    + OPTPROC_NO_ARGS")
    a("    + OPTPROC_GNUUSAGE ),")
    a("    0, NULL,                    /* current option index, current option */")
    a("    NULL,         NULL,         zPROGNAME,")
    a("    zRcName,      zCopyright,   zLicenseDescrip,")
    a("    zFullVersion, apzHomeList,  zUsageTitle,")
    a("    zExplain,     zDetail,      optDesc,")
    a("    zBugsAddr,                  /* address to send bugs to */")
    a("    NULL, NULL,                 /* extensions/saved state  */")
    a("    optionUsage, /* usage procedure */")
    a("    translate_option_strings,   /* translation procedure */")
    a("    /*")
    a("     *  Indexes to special options")
    a("     */")
    a("    { INDEX_OPT_MORE_HELP, /* more-help option index */")
    if m.save_opts:
        a("      INDEX_OPT_SAVE_OPTS, /* save option index */")
    else:
        a("      NO_EQUIVALENT, /* save option index */")
    a("      NO_EQUIVALENT, /* '-#' option index */")
    dflt = next((f2["_index"] for f2 in m.all_flags if "default" in f2), None)
    a(f"      {dflt if dflt is not None else 'NO_EQUIVALENT'} /* index of default opt */")
    a("    },")
    a(f"    {m.option_ct} /* full option count */, {len(m.all_flags)} /* user option count */,")
    a(f"    {P}_full_usage, {P}_short_usage,")
    a("    NULL, NULL,")
    a(f"    PKGDATADIR, {P}_packager_info")
    a("};")
    a("")
    a(nls_section(m, pool, refs))
    return "\n".join(out) + "\n"


def paragraph_chunks(text):
    """Reproduce libopts' optionPrintParagraphs() chunking exactly.

    Ported from libopts/usage.c (the function autogen's mk-gettextable
    delegates to): texts under 256 bytes emit as one puts(); longer ones
    are split at paragraph boundaries, but only once at least 40 bytes
    have accumulated and only while 256+ bytes remain.
    """
    n = len(text)
    if n < 256:
        return [text]

    def at(i):
        return text[i] if i < n else "\0"

    chunks = []
    buf = 0
    length = n
    while True:
        if length < 256:
            chunks.append(text[buf:])
            return chunks
        scan = buf
        while True:  # try_longer
            idx = text.find("\n", scan)
            if idx < 0:
                chunks.append(text[buf:])
                return chunks
            scan = idx
            if (scan - buf) < 40:
                scan += 1
                continue
            scan += 1
            ch = at(scan)
            if (not ch.isspace()) or ch == "\t":
                continue  # continuation line
            if ch == "\n":
                scan += 1
                while at(scan) == "\n":
                    scan += 1
                break
            # whitespace: up to 7 leading spaces still starts a paragraph
            p2 = scan
            sp_ct = 0
            restart = False
            while at(p2) == " ":
                sp_ct += 1
                if sp_ct >= 8:
                    scan = p2
                    restart = True
                    break
                p2 += 1
            if restart:
                continue
            break
        chunks.append(text[buf:scan])
        length -= scan - buf
        if length <= 0:
            return chunks
        buf = scan


def xgettext_string(text):
    """Render a puts(_( ... )) literal: one chunk per source line with any
    run of following newlines glued on, joined by backslash continuations."""
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    trailing_nl = text.endswith("\n")
    chunks = []
    i = 0
    while i < len(parts):
        part = parts[i]
        nls = 1
        j = i + 1
        while j < len(parts) and parts[j] == "":
            nls += 1
            j += 1
        if i == len(parts) - 1 and not trailing_nl:
            nls = 0
        chunks.append(c_escape(part) + "\\n" * nls)
        i = j
    return "\\\n".join(chunks)


def nls_section(m, pool, refs):
    P = m.prog
    up = P.upper().replace("-", "_")
    strs = f"{P}_opt_strs"
    o = []
    a = o.append
    a("#if ENABLE_NLS")
    a("/**")
    a(" * This code is designed to translate translatable option text for the")
    a(f" * {P} program.  These translations happen upon entry")
    a(" * to optionProcess().")
    a(" */")
    a("#include <stdio.h>")
    a("#include <stdlib.h>")
    a("#include <string.h>")
    a("#include <unistd.h>")
    a("#ifdef HAVE_DCGETTEXT")
    a("# include <gettext.h>")
    a("#endif")
    a("#include <autoopts/usage-txt.h>")
    a("")
    a("static char * AO_gettext(char const * pz);")
    a("static void   coerce_it(void ** s);")
    a("")
    a("/**")
    a(" * AutoGen specific wrapper function for gettext.  It relies on the macro _()")
    a(" * to convert from English to the target language, then strdup-duplicates the")
    a(' * result string.  It tries the "libopts" domain first, then whatever has been')
    a(" * set via the \\a textdomain(3) call.")
    a(" *")
    a(" * @param[in] pz the input text used as a lookup key.")
    a(" * @returns the translated text (if there is one),")
    a(" *   or the original text (if not).")
    a(" */")
    a("static char *")
    a("AO_gettext(char const * pz)")
    a("{")
    a("    char * res;")
    a("    if (pz == NULL)")
    a("        return NULL;")
    a("#ifdef HAVE_DCGETTEXT")
    a("    /*")
    a("     * While processing the option_xlateable_txt data, try to use the")
    a('     * "libopts" domain.  Once we switch to the option descriptor data,')
    a("     * do *not* use that domain.")
    a("     */")
    a("    if (option_xlateable_txt.field_ct != 0) {")
    a('        res = dgettext("libopts", pz);')
    a("        if (res == pz)")
    a("            res = (char *)VOIDP(_(pz));")
    a("    } else")
    a("        res = (char *)VOIDP(_(pz));")
    a("#else")
    a("    res = (char *)VOIDP(_(pz));")
    a("#endif")
    a("    if (res == pz)")
    a("        return res;")
    a("    res = strdup(res);")
    a("    if (res == NULL) {")
    a('        fputs(_("No memory for duping translated strings\\n"), stderr);')
    a(f"        exit({up}_EXIT_FAILURE);")
    a("    }")
    a("    return res;")
    a("}")
    a("")
    a("/**")
    a(' * All the pointers we use are marked "* const", but they are stored in')
    a(" * writable memory.  Coerce the mutability and set the pointer.")
    a(" */")
    a("static void coerce_it(void ** s) { *s = AO_gettext(*s);")
    a("}")
    a("")
    a("/**")
    a(f" * Translate all the translatable strings in the {m.progvar}")
    a(" * structure defined above.  This is done only once.")
    a(" */")
    a("static void")
    a("translate_option_strings(void)")
    a("{")
    a(f"    tOptions * const opts = &{m.progvar};")
    a("")
    a("    /*")
    a("     *  Guard against re-translation.  It won't work.  The strings will have")
    a("     *  been changed by the first pass through this code.  One shot only.")
    a("     */")
    a("    if (option_xlateable_txt.field_ct != 0) {")
    a("        /*")
    a("         *  Do the translations.  The first pointer follows the field count")
    a("         *  field.  The field count field is the size of a pointer.")
    a("         */")
    a("        char ** ppz = (char**)VOIDP(&(option_xlateable_txt));")
    a("        int     ix  = option_xlateable_txt.field_ct;")
    a("")
    a("        do {")
    a("            ppz++; /* skip over field_ct */")
    a("            *ppz = AO_gettext(*ppz);")
    a("        } while (--ix > 0);")
    a('        /* prevent re-translation and disable "libopts" domain lookup */')
    a("        option_xlateable_txt.field_ct = 0;")
    a("")
    a("        coerce_it(VOIDP(&(opts->pzCopyright)));")
    a("        coerce_it(VOIDP(&(opts->pzCopyNotice)));")
    a("        coerce_it(VOIDP(&(opts->pzFullVersion)));")
    a("        coerce_it(VOIDP(&(opts->pzUsageTitle)));")
    a("        coerce_it(VOIDP(&(opts->pzExplain)));")
    a("        coerce_it(VOIDP(&(opts->pzDetail)));")
    a("        {")
    a("            tOptDesc * od = opts->pOptDesc;")
    a("            for (ix = opts->optCt; ix > 0; ix--, od++)")
    a("                coerce_it(VOIDP(&(od->pzText)));")
    a("        }")
    a("    }")
    a("}")
    a("#endif /* ENABLE_NLS */")
    a("")
    a("#ifdef DO_NOT_COMPILE_THIS_CODE_IT_IS_FOR_GETTEXT")
    a("/** I18N function strictly for xgettext.  Do not compile. */")
    a("static void bogus_function(void) {")
    a("  /* TRANSLATORS:")
    a("")
    a("     The following dummy function was crated solely so that xgettext can")
    a("     extract the correct strings.  These strings are actually referenced")
    a(f"     by a field name in the {m.progvar} structure noted in the")
    a(f"     comments below.  The literal text is defined in {strs}.")
    a("")
    a("     NOTE: the strings below are segmented with respect to the source string")
    a(f"     {strs}.  The strings above are handed off for translation")
    a("     at run time a paragraph at a time.  Consequently, they are presented here")
    a("     for translation a paragraph at a time.")
    a("")
    a("     ALSO: often the description for an option will reference another option")
    a("     by name.  These are set off with apostrophe quotes (I hope).  Do not")
    a("     translate option names.")
    a("   */")
    seg = dict(pool.segments)

    def seg_text(off):
        return seg[off]

    a(f"  /* referenced via {m.progvar}.pzCopyright */")
    for para in paragraph_chunks(seg_text(refs["zCopyright"])):
        a(f'  puts(_("{xgettext_string(para)}"));')
    a("")
    a(f"  /* referenced via {m.progvar}.pzCopyNotice */")
    for para in paragraph_chunks(seg_text(refs["zLicenseDescrip"])):
        a(f'  puts(_("{xgettext_string(para)}"));')
    a("")
    for fa in m.all_flags:
        a(f"  /* referenced via {m.progvar}.pOptDesc->pzText */")
        for para in paragraph_chunks(fa["_desc_text"]):
            a(f'  puts(_("{xgettext_string(para)}"));')
        a("")
    a(f"  /* referenced via {m.progvar}.pOptDesc->pzText */")
    a('  puts(_("display extended usage information and exit"));')
    a("")
    a(f"  /* referenced via {m.progvar}.pOptDesc->pzText */")
    a('  puts(_("extended usage information passed thru pager"));')
    a("")
    if m.save_opts:
        a(f"  /* referenced via {m.progvar}.pOptDesc->pzText */")
        a('  puts(_("save the option state to a config file"));')
        a("")
    if m.load_opts:
        a(f"  /* referenced via {m.progvar}.pOptDesc->pzText */")
        a('  puts(_("load options from a config file"));')
        a("")
    a(f"  /* referenced via {m.progvar}.pzUsageTitle */")
    for para in paragraph_chunks(seg_text(refs["zUsageTitle"])):
        a(f'  puts(_("{xgettext_string(para)}"));')
    a("")
    if "zExplain" in refs:
        a(f"  /* referenced via {m.progvar}.pzExplain */")
        for para in paragraph_chunks(seg_text(refs["zExplain"])):
            a(f'  puts(_("{xgettext_string(para)}"));')
        a("")
    if "zDetail" in refs:
        a(f"  /* referenced via {m.progvar}.pzDetail */")
        for para in paragraph_chunks(seg_text(refs["zDetail"])):
            a(f'  puts(_("{xgettext_string(para)}"));')
        a("")
    a(f"  /* referenced via {m.progvar}.pzFullUsage */")
    a('  puts(_("<<<NOT-FOUND>>>"));')
    a("")
    a(f"  /* referenced via {m.progvar}.pzShortUsage */")
    a('  puts(_("<<<NOT-FOUND>>>"));')
    a(LIBOPTS_CATALOG)
    a("}")
    a("#endif /* uncompilable code */")
    a("#ifdef  __cplusplus")
    a("}")
    a("#endif")
    a(f"/* {m.base}.c ends here */")
    return "\n".join(o)


LIBOPTS_CATALOG = r'''  /* LIBOPTS-MESSAGES: */
#line 67 "../autoopts.c"
  puts(_("allocation of %d bytes failed\n"));
#line 89 "../autoopts.c"
  puts(_("allocation of %d bytes failed\n"));
#line 48 "../init.c"
  puts(_("AutoOpts function called without option descriptor\n"));
#line 81 "../init.c"
  puts(_("\tThis exceeds the compiled library version:  "));
#line 79 "../init.c"
  puts(_("Automated Options Processing Error!\n"
       "\t%s called AutoOpts function with structure version %d:%d:%d.\n"));
#line 78 "../autoopts.c"
  puts(_("realloc of %d bytes at 0x%p failed\n"));
#line 83 "../init.c"
  puts(_("\tThis is less than the minimum library version:  "));
#line 121 "../version.c"
  puts(_("Automated Options version %s\n"
       "\tCopyright (C) 1999-2017 by Bruce Korb - all rights reserved\n"));
#line 49 "../makeshell.c"
  puts(_("(AutoOpts bug):  %s.\n"));
#line 90 "../reset.c"
  puts(_("optionResetOpt() called, but reset-option not configured"));
#line 241 "../usage.c"
  puts(_("could not locate the 'help' option"));
#line 330 "../autoopts.c"
  puts(_("optionProcess() was called with invalid data"));
#line 697 "../usage.c"
  puts(_("invalid argument type specified"));
#line 568 "../find.c"
  puts(_("defaulted to option with optional arg"));
#line 76 "../alias.c"
  puts(_("aliasing option is out of range."));
#line 210 "../enum.c"
  puts(_("%s error:  the keyword '%s' is ambiguous for %s\n"));
#line 78 "../find.c"
  puts(_("  The following options match:\n"));
#line 263 "../find.c"
  puts(_("%s: ambiguous option name: %s (matches %d options)\n"));
#line 161 "../check.c"
  puts(_("%s: Command line arguments required\n"));
#line 43 "../alias.c"
  puts(_("%d %s%s options allowed\n"));
#line 56 "../makeshell.c"
  puts(_("%s error %d (%s) calling %s for '%s'\n"));
#line 268 "../makeshell.c"
  puts(_("interprocess pipe"));
#line 171 "../version.c"
  puts(_("error: version option argument '%c' invalid.  Use:\n"
       "\t'v' - version only\n"
       "\t'c' - version and copyright\n"
       "\t'n' - version and full copyright notice\n"));
#line 58 "../check.c"
  puts(_("%s error:  the '%s' and '%s' options conflict\n"));
#line 187 "../find.c"
  puts(_("%s: The '%s' option has been disabled."));
#line 400 "../find.c"
  puts(_("%s: The '%s' option has been disabled."));
#line 38 "../alias.c"
  puts(_("-equivalence"));
#line 439 "../find.c"
  puts(_("%s: illegal option -- %c\n"));
#line 110 "../reset.c"
  puts(_("%s: illegal option -- %c\n"));
#line 241 "../find.c"
  puts(_("%s: illegal option -- %s\n"));
#line 740 "../find.c"
  puts(_("%s: illegal option -- %s\n"));
#line 118 "../reset.c"
  puts(_("%s: illegal option -- %s\n"));
#line 305 "../find.c"
  puts(_("%s: unknown vendor extension option -- %s\n"));
#line 135 "../enum.c"
  puts(_("  or an integer from %d through %d\n"));
#line 145 "../enum.c"
  puts(_("  or an integer from %d through %d\n"));
#line 696 "../usage.c"
  puts(_("%s error:  invalid option descriptor for %s\n"));
#line 1030 "../usage.c"
  puts(_("%s error:  invalid option descriptor for %s\n"));
#line 355 "../find.c"
  puts(_("%s: invalid option name: %s\n"));
#line 497 "../find.c"
  puts(_("%s: The '%s' option requires an argument.\n"));
#line 150 "../autoopts.c"
  puts(_("(AutoOpts bug):  Equivalenced option '%s' was equivalenced to both\n"
       "\t'%s' and '%s'."));
#line 94 "../check.c"
  puts(_("%s error:  The %s option is required\n"));
#line 602 "../find.c"
  puts(_("%s: The '%s' option cannot have an argument.\n"));
#line 151 "../check.c"
  puts(_("%s: Command line arguments are not allowed.\n"));
#line 568 "../save.c"
  puts(_("error %d (%s) creating %s\n"));
#line 210 "../enum.c"
  puts(_("%s error:  '%s' does not match any %s keywords.\n"));
#line 93 "../reset.c"
  puts(_("%s error: The '%s' option requires an argument.\n"));
#line 122 "../save.c"
  puts(_("error %d (%s) stat-ing %s\n"));
#line 175 "../save.c"
  puts(_("error %d (%s) stat-ing %s\n"));
#line 143 "../restore.c"
  puts(_("%s error: no saved option state\n"));
#line 225 "../autoopts.c"
  puts(_("'%s' is not a command line option.\n"));
#line 113 "../time.c"
  puts(_("%s error:  '%s' is not a recognizable date/time.\n"));
#line 50 "../time.c"
  puts(_("%s error:  '%s' is not a recognizable time duration.\n"));
#line 92 "../check.c"
  puts(_("%s error:  The %s option must appear %d times.\n"));
#line 165 "../numeric.c"
  puts(_("%s error:  '%s' is not a recognizable number.\n"));
#line 176 "../enum.c"
  puts(_("%s error:  %s exceeds %s keyword count\n"));
#line 279 "../usage.c"
  puts(_("Try '%s %s' for more information.\n"));
#line 45 "../alias.c"
  puts(_("one %s%s option allowed\n"));
#line 170 "../makeshell.c"
  puts(_("standard output"));
#line 905 "../makeshell.c"
  puts(_("standard output"));
#line 223 "../usage.c"
  puts(_("standard output"));
#line 364 "../usage.c"
  puts(_("standard output"));
#line 574 "../usage.c"
  puts(_("standard output"));
#line 178 "../version.c"
  puts(_("standard output"));
#line 223 "../usage.c"
  puts(_("standard error"));
#line 364 "../usage.c"
  puts(_("standard error"));
#line 574 "../usage.c"
  puts(_("standard error"));
#line 178 "../version.c"
  puts(_("standard error"));
#line 170 "../makeshell.c"
  puts(_("write"));
#line 905 "../makeshell.c"
  puts(_("write"));
#line 222 "../usage.c"
  puts(_("write"));
#line 363 "../usage.c"
  puts(_("write"));
#line 573 "../usage.c"
  puts(_("write"));
#line 177 "../version.c"
  puts(_("write"));
#line 60 "../numeric.c"
  puts(_("%s error:  %s option value %ld is out of range.\n"));
#line 44 "../check.c"
  puts(_("%s error:  %s option requires the %s option\n"));
#line 121 "../save.c"
  puts(_("%s warning:  cannot save options - %s not regular file\n"));
#line 174 "../save.c"
  puts(_("%s warning:  cannot save options - %s not regular file\n"));
#line 193 "../save.c"
  puts(_("%s warning:  cannot save options - %s not regular file\n"));
#line 567 "../save.c"
  puts(_("%s warning:  cannot save options - %s not regular file\n"));
  /* END-LIBOPTS-MESSAGES */

  /* USAGE-TEXT: */
#line 822 "../usage.c"
  puts(_("\t\t\t\t- an alternate for '%s'\n"));
#line 1097 "../usage.c"
  puts(_("Version, usage and configuration options:"));
#line 873 "../usage.c"
  puts(_("\t\t\t\t- default option for unnamed options\n"));
#line 786 "../usage.c"
  puts(_("\t\t\t\t- disabled as '--%s'\n"));
#line 1066 "../usage.c"
  puts(_(" --- %-14s %s\n"));
#line 1064 "../usage.c"
  puts(_("This option has been disabled"));
#line 813 "../usage.c"
  puts(_("\t\t\t\t- enabled by default\n"));
#line 40 "../alias.c"
  puts(_("%s error:  only "));
#line 1143 "../usage.c"
  puts(_(" - examining environment variables named %s_*\n"));
#line 168 "../file.c"
  puts(_("\t\t\t\t- file must not pre-exist\n"));
#line 172 "../file.c"
  puts(_("\t\t\t\t- file must pre-exist\n"));
#line 329 "../usage.c"
  puts(_("Options are specified by doubled hyphens and their name or by a single\n"
       "hyphen and the flag character.\n"));
#line 882 "../makeshell.c"
  puts(_("\n"
       "= = = = = = = =\n\n"
       "This incarnation of genshell will produce\n"
       "a shell script to parse the options for %s:\n\n"));
#line 142 "../enum.c"
  puts(_("  or an integer mask with any of the lower %d bits set\n"));
#line 846 "../usage.c"
  puts(_("\t\t\t\t- is a set membership option\n"));
#line 867 "../usage.c"
  puts(_("\t\t\t\t- must appear between %d and %d times\n"));
#line 331 "../usage.c"
  puts(_("Options are specified by single or double hyphens and their name.\n"));
#line 853 "../usage.c"
  puts(_("\t\t\t\t- may appear multiple times\n"));
#line 840 "../usage.c"
  puts(_("\t\t\t\t- may not be preset\n"));
#line 1258 "../usage.c"
  puts(_("   Arg Option-Name    Description\n"));
#line 1194 "../usage.c"
  puts(_("  Flg Arg Option-Name    Description\n"));
#line 1252 "../usage.c"
  puts(_("  Flg Arg Option-Name    Description\n"));
#line 1253 "../usage.c"
  puts(_(" %3s %s"));
#line 1259 "../usage.c"
  puts(_(" %3s %s"));
#line 336 "../usage.c"
  puts(_("The '-#<number>' option may omit the hash char\n"));
#line 332 "../usage.c"
  puts(_("All arguments are named options.\n"));
#line 920 "../usage.c"
  puts(_(" - reading file %s"));
#line 358 "../usage.c"
  puts(_("\n"
       "Please send bug reports to:  <%s>\n"));
#line 100 "../version.c"
  puts(_("\n"
       "Please send bug reports to:  <%s>\n"));
#line 129 "../version.c"
  puts(_("\n"
       "Please send bug reports to:  <%s>\n"));
#line 852 "../usage.c"
  puts(_("\t\t\t\t- may NOT appear - preset only\n"));
#line 893 "../usage.c"
  puts(_("\n"
       "The following option preset mechanisms are supported:\n"));
#line 1141 "../usage.c"
  puts(_("\n"
       "The following option preset mechanisms are supported:\n"));
#line 631 "../usage.c"
  puts(_("prohibits these options:\n"));
#line 626 "../usage.c"
  puts(_("prohibits the option '%s'\n"));
#line 81 "../numeric.c"
  puts(_("%s%ld to %ld"));
#line 79 "../numeric.c"
  puts(_("%sgreater than or equal to %ld"));
#line 75 "../numeric.c"
  puts(_("%s%ld exactly"));
#line 68 "../numeric.c"
  puts(_("%sit must lie in one of the ranges:\n"));
#line 68 "../numeric.c"
  puts(_("%sit must be in the range:\n"));
#line 88 "../numeric.c"
  puts(_(", or\n"));
#line 66 "../numeric.c"
  puts(_("%sis scalable with a suffix: k/K/m/M/g/G/t/T\n"));
#line 77 "../numeric.c"
  puts(_("%sless than or equal to %ld"));
#line 339 "../usage.c"
  puts(_("Operands and options may be intermixed.  They will be reordered.\n"));
#line 601 "../usage.c"
  puts(_("requires the option '%s'\n"));
#line 604 "../usage.c"
  puts(_("requires these options:\n"));
#line 1270 "../usage.c"
  puts(_("   Arg Option-Name   Req?  Description\n"));
#line 1264 "../usage.c"
  puts(_("  Flg Arg Option-Name   Req?  Description\n"));
#line 143 "../enum.c"
  puts(_("or you may use a numeric representation.  Preceding these with a '!'\n"
       "will clear the bits, specifying 'none' will clear all bits, and 'all'\n"
       "will set them all.  Multiple entries may be passed as an option\n"
       "argument list.\n"));
#line 859 "../usage.c"
  puts(_("\t\t\t\t- may appear up to %d times\n"));
#line 52 "../enum.c"
  puts(_("The valid \"%s\" option keywords are:\n"));
#line 1101 "../usage.c"
  puts(_("The next option supports vendor supported extra options:"));
#line 722 "../usage.c"
  puts(_("These additional options are:"));
  /* END-USAGE-TEXT */'''


if __name__ == "__main__":
    base = sys.argv[1]
    def_path = sys.argv[2]
    defines = sys.argv[3].split(",") if len(sys.argv) > 3 and sys.argv[3] else []
    sys.stdout.write(emit(def_path, base, defines, ["src", "src/tcpedit"]))
