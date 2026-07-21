#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay.dev at gmail dot com> - AppNeta by Broadcom
# GPLv3 - part of the Tcpreplay Suite.
"""Emit AutoOpts-compatible *_opts.h from the defparser IR (#895 phase 2).

Output must be byte-identical to what GNU autogen 5.18.16 produced from the
same .def (the committed files are the oracle).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file  # noqa: E402

GPL_BLURB = """\
 *  Copyright (C) {date} {owner}, all rights reserved.
 *  This is free software. It is licensed for use, modification and
 *  redistribution under the terms of the GNU General Public License,
 *  version 3 or later <http://gnu.org/licenses/gpl.html>
 *
 *  {prog} is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  {prog} is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program.  If not, see <http://www.gnu.org/licenses/>."""

BSD_BLURB = """\
 *  Copyright (C) {date} {owner}, all rights reserved.
 *  This is free software. It is licensed for use, modification and
 *  redistribution under the terms of the
 *  Modified (3 clause) Berkeley Software Distribution License
 *  <http://www.xfree86.org/3.3.6/COPYRIGHT2.html>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name ``{owner}'' nor the name of any other
 *     contributor may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  {prog} IS PROVIDED BY {owner} ``AS IS'' AND ANY EXPRESS
 *  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL {owner} OR ANY OTHER CONTRIBUTORS
 *  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""

LICENSES = {"gpl": GPL_BLURB, "bsd": BSD_BLURB}


class Model:
    """Everything the emitters need, derived from the IR."""

    def __init__(self, ir, base):
        self.base = base                      # e.g. tcpcapinfo_opts
        self.attrs = {}
        for n, v in ir["attributes"]:
            self.attrs.setdefault(n.replace("_", "-"), v)
        self.prog = self.attrs["prog-name"]
        self.progvar = self.prog.replace("-", "_") + "Options"
        self.guard = "AUTOOPTS_" + base.upper() + "_H_GUARD"
        self.load_opts = "no-load-opts" not in self.attrs
        self.save_opts = "no-save-opts" not in self.attrs

        self.doc_flags = []
        self.flags = []
        REPEATABLE = {"flags-must", "flags-cant"}
        for fl in ir["flags"]:
            fa = {}
            order = []
            for n, v in fl["attributes"]:
                n = n.replace("_", "-")
                if n in REPEATABLE:
                    fa.setdefault(n, []).append(v)
                else:
                    fa.setdefault(n, v)
                order.append(n)
            fa["_order"] = order
            if "documentation" in fa:
                self.doc_flags.append(fa)
            else:
                self.flags.append(fa)

        # hex values for long-only options, assigned in flag order; the
        # automatic save-opts/load-opts options draw from the same counter
        counter = 0x1001
        for fa in self.flags:
            if "value" in fa:
                fa["_value"] = "'%s'" % fa["value"]
            else:
                fa["_value"] = "0x%04X" % counter
                counter += 1
        self.save_value = self.load_value = None
        if self.save_opts:
            self.save_value = "0x%04X" % counter
            counter += 1
        if self.load_opts:
            self.load_value = "0x%04X" % counter
            counter += 1

        # enum entries: doc flags consume leading indexes silently
        self.enum = []
        idx = len(self.doc_flags)
        for fa in self.flags:
            fa["_index"] = idx
            self.enum.append((self.cname(fa), idx))
            idx += 1
        for auto in self.auto_opts():
            self.enum.append((auto, idx))
            idx += 1
        self.option_ct = idx

        names = [dict(fl["attributes"])["name"] for fl in ir["flags"]]
        self.example = names[0].upper().replace("-", "_") if names else "OPTION"

        # equivalence targets get WHICH_ macros
        targets = {fa.get("equivalence") for fa in self.flags if "equivalence" in fa}
        for fa in self.flags:
            fa["_equiv_target"] = fa["name"] in targets

    @staticmethod
    def cname(fa):
        return fa["name"].upper().replace("-", "_")

    def auto_opts(self):
        auto = ["HELP", "MORE_HELP"]
        if self.save_opts:
            auto.append("SAVE_OPTS")
        if self.load_opts:
            auto.append("LOAD_OPTS")
        return auto


def emit_header_comment(m, out):
    lic = LICENSES[str(m.attrs["copyright"] and dict(m.attrs["copyright"]).get("type", "gpl")).strip('"')]
    cp = dict(m.attrs["copyright"])
    out.append("/*   -*- buffer-read-only: t -*- vi: set ro:")
    out.append(" *")
    out.append(f" *  DO NOT EDIT THIS FILE   ({m.base}.h)")
    out.append(" *")
    out.append(" *  It has been AutoGen-ed")
    out.append(f" *  From the definitions    {m.attrs['_deffile']}")
    out.append(" *  and the template file   options")
    out.append(" *")
    out.append(" * Generated from AutoOpts 42:1:17 templates.")
    out.append(" *")
    out.append(" *  AutoOpts is a copyrighted work.  This header file is not encumbered")
    out.append(" *  by AutoOpts licensing, but is provided under the licensing terms chosen")
    out.append(f" *  by the {m.prog} author or copyright holder.  AutoOpts is")
    out.append(" *  licensed under the terms of the LGPL.  The redistributable library")
    out.append(" *  (``libopts'') is licensed under the terms of either the LGPL or, at the")
    out.append(" *  users discretion, the BSD license.  See the AutoOpts and/or libopts sources")
    out.append(" *  for details.")
    out.append(" *")
    out.append(f" * The {m.prog} program is copyrighted and licensed")
    out.append(" * under the following terms:")
    out.append(" *")
    out.append(lic.format(date=cp["date"], owner=cp["owner"], prog=m.prog))
    out.append(" */")


def emit_prologue(m, out):
    out.append("/**")
    out.append(" *  This file contains the programmatic interface to the Automated")
    out.append(f" *  Options generated for the {m.prog} program.")
    out.append(" *  These macros are documented in the AutoGen info file in the")
    out.append(' *  "AutoOpts" chapter.  Please refer to that doc for usage help.')
    out.append(" */")
    out.append(f"#ifndef {m.guard}")
    out.append(f"#define {m.guard} 1")
    out.append(f'#include "{m.attrs["config-header"]}"')
    out.append("#include <autoopts/options.h>")
    out.append("#include <stdarg.h>")
    out.append("#include <stdnoreturn.h>")
    out.append("")
    out.append("/**")
    out.append(" *  Ensure that the library used for compiling this generated header is at")
    out.append(" *  least as new as the version current when the header template was released")
    out.append(" *  (not counting patch version increments).  Also ensure that the oldest")
    out.append(" *  tolerable version is at least as old as what was current when the header")
    out.append(" *  template was released.")
    out.append(" */")
    out.append("#define AO_TEMPLATE_VERSION 172033")
    out.append("#if (AO_TEMPLATE_VERSION < OPTIONS_MINIMUM_VERSION) \\")
    out.append(" || (AO_TEMPLATE_VERSION > OPTIONS_STRUCT_VERSION)")
    out.append("# error option template version mismatches autoopts/options.h header")
    out.append("  Choke Me.")
    out.append("#endif")
    out.append("")
    out.append("#if GCC_VERSION > 40400")
    out.append("#define NOT_REACHED __builtin_unreachable();")
    out.append("#else")
    out.append("#define NOT_REACHED")
    out.append("#endif")
    out.append("")


def emit_enum(m, out):
    out.append("/**")
    out.append(f" *  Enumeration of each option type for {m.prog}")
    out.append(" */")
    out.append("typedef enum {")
    width = max(max(len("INDEX_OPT_" + n) for n, _ in m.enum) + 1, 21)
    rows = []
    for n, idx in m.enum:
        rows.append(f"    {('INDEX_OPT_' + n).ljust(width)} = {idx:2d}")
    out.append(",\n".join(rows))
    out.append("} teOptIndex;")
    out.append(f"/** count of all options for {m.prog} */")
    out.append(f"#define OPTION_CT    {m.option_ct}")
    out.append("")


def emit_interface(m, out):
    out.append("""/**
 *  Interface defines for all options.  Replace "n" with the UPPER_CASED
 *  option name (as in the teOptIndex enumeration above).
 *  e.g. HAVE_OPT({example})
 */""".format(example=m.example))
    out.append(f"#define         DESC(n) ({m.progvar}.pOptDesc[INDEX_OPT_## n])")
    out.append("""/** 'true' if an option has been specified in any way */
#define     HAVE_OPT(n) (! UNUSED_OPT(& DESC(n)))
/** The string argument to an option. The argument type must be \\"string\\". */
#define      OPT_ARG(n) (DESC(n).optArg.argString)
/** Mask the option state revealing how an option was specified.
 *  It will be one and only one of \\a OPTST_SET, \\a OPTST_PRESET,
 * \\a OPTST_DEFINED, \\a OPTST_RESET or zero.
 */
#define    STATE_OPT(n) (DESC(n).fOptState & OPTST_SET_MASK)
/** Count of option's occurrances *on the command line*. */
#define    COUNT_OPT(n) (DESC(n).optOccCt)
/** mask of \\a OPTST_SET and \\a OPTST_DEFINED. */
#define    ISSEL_OPT(n) (SELECTED_OPT(&DESC(n)))
/** 'true' if \\a HAVE_OPT would yield 'false'. */
#define ISUNUSED_OPT(n) (UNUSED_OPT(& DESC(n)))
/** 'true' if OPTST_DISABLED bit not set. */
#define  ENABLED_OPT(n) (! DISABLED_OPT(& DESC(n)))
/** number of stacked option arguments.
 *  Valid only for stacked option arguments. */
#define  STACKCT_OPT(n) (((tArgList*)(DESC(n).optCookie))->useCt)
/** stacked argument vector.
 *  Valid only for stacked option arguments. */
#define STACKLST_OPT(n) (((tArgList*)(DESC(n).optCookie))->apzArgs)
/** Reset an option. */
#define    CLEAR_OPT(n) STMTS( \\
                DESC(n).fOptState &= OPTST_PERSISTENT_MASK;   \\
                if ((DESC(n).fOptState & OPTST_INITENABLED) == 0) \\
                    DESC(n).fOptState |= OPTST_DISABLED; \\
                DESC(n).optCookie = NULL )""")
    out.append("/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */")


def emit_exit_codes(m, out):
    up = m.prog.upper().replace("-", "_")
    codes = [("SUCCESS", 0), ("FAILURE", 1), ("USAGE_ERROR", 64)]
    if m.load_opts:
        codes.append(("NO_CONFIG_INPUT", 66))
    codes.append(("LIBOPTS_FAILURE", 70))
    out.append("/**")
    out.append(f" *  Enumeration of {m.prog} exit codes")
    out.append(" */")
    out.append("typedef enum {")
    width = max(len(f"{up}_EXIT_{n}") for n, _ in codes)
    rows = [f"    {(f'{up}_EXIT_{n}').ljust(width)} = {v}" for n, v in codes]
    out.append(",\n".join(rows))
    out.append(f"}}   {m.prog.replace('-', '_')}_exit_code_t;")


def emit_option_defines(m, out):
    out.append("/**")
    out.append(" *  Interface defines for specific options.")
    out.append(" * @{")
    out.append(" */")

    for fa in m.flags:
        n = m.cname(fa)
        guard = fa.get("ifdef")
        out.append(f"#define {('VALUE_OPT_' + n).ljust(24)} {fa['_value']}")
        body = []
        if fa.get("arg-type") == "number":
            body.append(f"#define {('OPT_VALUE_' + n).ljust(24)} (DESC({n}).optArg.argInt)")
        if "settable" in fa and "arg-type" in fa:
            body.append(f"#define SET_OPT_{n}(a)   STMTS( \\")
            body.append(f"        DESC({n}).optActualIndex = {fa['_index']}; \\")
            body.append(f"        DESC({n}).optActualValue = VALUE_OPT_{n}; \\")
            body.append(f"        DESC({n}).fOptState &= OPTST_PERSISTENT_MASK; \\")
            body.append(f"        DESC({n}).fOptState |= OPTST_SET; \\")
            body.append(f"        DESC({n}).optArg.argString = (a); \\")
            body.append(f"        (*(DESC({n}).pOptProc))(&{m.progvar}, \\")
            body.append(f"                {m.progvar}.pOptDesc + {fa['_index']}); )")
        elif "settable" in fa:
            body.append(f"#define SET_OPT_{n}   STMTS( \\")
            body.append(f"        DESC({n}).optActualIndex = {fa['_index']}; \\")
            body.append(f"        DESC({n}).optActualValue = VALUE_OPT_{n}; \\")
            body.append(f"        DESC({n}).fOptState &= OPTST_PERSISTENT_MASK; \\")
            body.append(f"        DESC({n}).fOptState |= OPTST_SET )")
        if body and guard:
            out.append(f"#ifdef {guard}")
            out.extend(body)
            out.append(f"#endif /* {guard} */")
        elif body:
            out.append("")
            out.extend(body)
        if fa["_equiv_target"]:
            out.append("")
            out.append(f"/** Define the option value {fa['name']} is equivalenced to */")
            out.append(f"#define {('WHICH_OPT_' + n).ljust(24)} (DESC({n}).optActualValue)")
            out.append(f"/** Define the index of the option {fa['name']} is equivalenced to */")
            out.append(f"#define {('WHICH_IDX_' + n).ljust(24)} (DESC({n}).optActualIndex)")
    out.append("/** option flag (value) for help-value option */")
    out.append(f"#define VALUE_OPT_HELP          '{m.attrs.get('help-value', '?')}'")
    out.append("/** option flag (value) for more-help-value option */")
    out.append("#define VALUE_OPT_MORE_HELP     '!'")
    if m.save_opts:
        out.append("/** option flag (value) for save-opts-value option */")
        out.append(f"#define VALUE_OPT_SAVE_OPTS     {m.save_value}")
    if m.load_opts:
        out.append("/** option flag (value) for load-opts-value option */")
        out.append(f"#define VALUE_OPT_LOAD_OPTS     {m.load_value}")
    if m.save_opts:
        out.append("#define SET_OPT_SAVE_OPTS(a)   STMTS( \\")
        out.append("        DESC(SAVE_OPTS).fOptState &= OPTST_PERSISTENT_MASK; \\")
        out.append("        DESC(SAVE_OPTS).fOptState |= OPTST_SET; \\")
        out.append("        DESC(SAVE_OPTS).optArg.argString = (char const*)(a))")


def emit_tail(m, out):
    out.append("/*")
    out.append(" *  Interface defines not associated with particular options")
    out.append(" */")
    out.append(f"#define ERRSKIP_OPTERR  STMTS({m.progvar}.fOptSet &= ~OPTPROC_ERRSTOP)")
    out.append(f"#define ERRSTOP_OPTERR  STMTS({m.progvar}.fOptSet |= OPTPROC_ERRSTOP)")
    out.append("#define RESTART_OPT(n)  STMTS( \\")
    out.append(f"                {m.progvar}.curOptIdx = (n); \\")
    out.append(f"                {m.progvar}.pzCurOpt  = NULL )")
    out.append("#define START_OPT       RESTART_OPT(1)")
    out.append(f"#define USAGE(c)        (*{m.progvar}.pUsageProc)(&{m.progvar}, c)")
    out.append("")
    out.append("#ifdef  __cplusplus")
    out.append('extern "C" {')
    out.append("#endif")
    out.append("")
    out.append("")
    out.append("/* * * * * *")
    out.append(" *")
    out.append(f" *  Declare the {m.prog} option descriptor.")
    out.append(" */")
    out.append(f"extern tOptions {m.progvar};")
    out.append("")
    out.append("#if defined(ENABLE_NLS)")
    out.append("# ifndef _")
    out.append("#   include <stdio.h>")
    out.append("#   ifndef HAVE_GETTEXT")
    out.append("      extern char * gettext(char const *);")
    out.append("#   else")
    out.append("#     include <libintl.h>")
    out.append("#   endif")
    out.append("")
    out.append("# ifndef ATTRIBUTE_FORMAT_ARG")
    out.append("#   define ATTRIBUTE_FORMAT_ARG(_a)")
    out.append("# endif")
    out.append("")
    out.append("static inline char* aoGetsText(char const* pz) ATTRIBUTE_FORMAT_ARG(1);")
    out.append("static inline char* aoGetsText(char const* pz) {")
    out.append("    if (pz == NULL) return NULL;")
    out.append("    return (char*)gettext(pz);")
    out.append("}")
    out.append("#   define _(s)  aoGetsText(s)")
    out.append("# endif /* _() */")
    out.append("")
    out.append(f"# define OPT_NO_XLAT_CFG_NAMES  STMTS({m.progvar}.fOptSet |= \\")
    out.append("                                    OPTPROC_NXLAT_OPT_CFG;)")
    out.append(f"# define OPT_NO_XLAT_OPT_NAMES  STMTS({m.progvar}.fOptSet |= \\")
    out.append("                                    OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG;)")
    out.append("")
    out.append(f"# define OPT_XLAT_CFG_NAMES     STMTS({m.progvar}.fOptSet &= \\")
    out.append("                                  ~(OPTPROC_NXLAT_OPT|OPTPROC_NXLAT_OPT_CFG);)")
    out.append(f"# define OPT_XLAT_OPT_NAMES     STMTS({m.progvar}.fOptSet &= \\")
    out.append("                                  ~OPTPROC_NXLAT_OPT;)")
    out.append("")
    out.append("#else   /* ENABLE_NLS */")
    out.append("# define OPT_NO_XLAT_CFG_NAMES")
    out.append("# define OPT_NO_XLAT_OPT_NAMES")
    out.append("")
    out.append("# define OPT_XLAT_CFG_NAMES")
    out.append("# define OPT_XLAT_OPT_NAMES")
    out.append("")
    out.append("# ifndef _")
    out.append("#   define _(_s)  _s")
    out.append("# endif")
    out.append("#endif  /* ENABLE_NLS */")
    out.append("")
    out.append("")
    out.append("#ifdef  __cplusplus")
    out.append("}")
    out.append("#endif")
    out.append(f"#endif /* {m.guard} */")
    out.append("")
    out.append(f"/* {m.base}.h ends here */")


def emit_h(def_path, base, defines=(), search=()):
    ir = parse_def_file(def_path, defines=defines, search=search)
    m = Model(ir, base)
    m.attrs["_deffile"] = Path(def_path).name
    out = []
    emit_header_comment(m, out)
    emit_prologue(m, out)
    emit_enum(m, out)
    emit_interface(m, out)
    emit_exit_codes(m, out)
    emit_option_defines(m, out)
    emit_tail(m, out)
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    base = sys.argv[1]
    def_path = sys.argv[2]
    defines = sys.argv[3].split(",") if len(sys.argv) > 3 and sys.argv[3] else []
    sys.stdout.write(emit_h(def_path, base, defines, ["src", "src/tcpedit"]))
