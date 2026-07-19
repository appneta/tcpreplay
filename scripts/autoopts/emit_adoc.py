#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""Emit AsciiDoc man-page source from the defparser IR (#895 phase 2, stage 4).

GNU autogen's man-page pipeline (cmd-doc.tlib -> mdoc -> mdoc2man, ~1900
lines of Scheme and Perl we do not vendor) has no in-tree source of truth
to port the way emit_c.py ported optionPrintParagraphs() from libopts. So
this emitter is NOT byte-for-byte oracle-verified like emit_h.py/emit_c.py
- instead it renders directly from the same .def content (descrip/doc/
explain/detail) that already drives --help and the option tables, so the
man pages, --help output and this emitter can never disagree, and there
is no hand-duplicated prose to fall out of sync (the mistake in the
reverted PR #991, which hand-wrote separate .adoc files).

Output is AsciiDoc; render to roff with:
    asciidoctor -b manpage -o out.1 in.adoc
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from defparser import parse_def_file, text_of  # noqa: E402
from emit_h import Model  # noqa: E402

# ---------------------------------------------------------------------------
# texinfo -> AsciiDoc text conversion
# ---------------------------------------------------------------------------

_INLINE_RE = re.compile(r"@(file|var)\{([^}]*)\}|@(samp|code)\{([^}]*)\}")


def _inline(text):
    """Convert inline texinfo markup to AsciiDoc emphasis/monospace."""

    def sub(m):
        if m.group(1):
            return f"_{m.group(2)}_"
        return f"`{m.group(4)}`"

    text = _INLINE_RE.sub(sub, text)
    # escape stray AsciiDoc-significant characters that appear in option
    # syntax text (e.g. bare '*' would start emphasis)
    return text


_ITEM_BLOCK_RE = re.compile(
    r"@(table|enumerate)(?: @\w+)?\n(.*?)\n@end \1\n?", re.S
)
_ITEM_SPLIT_RE = re.compile(r"^@item[ \t]*(.*)$", re.M)
_EXAMPLE_RE = re.compile(r"@example\n(.*?)\n@end example\n?", re.S)


def _render_literal(text):
    lines = text.rstrip("\n").split("\n")
    return "....\n" + "\n".join(lines) + "\n...."


_INDENT_RUN_RE = re.compile(
    r"(?<=\S\n)((?:[ \t]{3,}\S.*\n?){2,})(?=[ \t]*\S|\Z)"
)


def _isolate_indent_runs(text):
    """Give a mid-paragraph run of 2+ indented lines (a literal block with
    no blank-line separation from the prose introducing it, e.g. "valid
    arguments:\n    [ -x ]\n    [ -y ]") its own paragraph, so the normal
    literal-block detection (which requires a paragraph to already start
    indented) can find it."""
    return _INDENT_RUN_RE.sub(lambda m: "\n" + m.group(1).rstrip("\n") + "\n\n", text)


def _convert_body(text):
    """Convert a chunk of prose (an item body, or a paragraph) to AsciiDoc:
    protect @example blocks from whitespace collapse, collapse line-wrapped
    prose to single lines, apply inline markup, and strip texinfo's
    "- " item-body marker (a bare hyphen prefix is a formatting convention
    in these .def files, not meaningful content or an AsciiDoc bullet)."""
    text = text.strip("\n")
    text = re.sub(r"^-\s+", "", text)  # texinfo item-body marker
    text = _isolate_indent_runs(text)
    placeholders = []

    def stash(m):
        placeholders.append(_render_literal(m.group(1)))
        return f"\x00LITERAL{len(placeholders) - 1}\x00"

    text = _EXAMPLE_RE.sub(stash, text)
    paras = [p for p in text.split("\n\n") if p.strip()]
    conv = []
    for p in paras:
        if re.match(r"^[ \t]{2,}\S", p) and "\n" in p and "\x00LITERAL" not in p:
            conv.append(_render_literal(p))
            continue
        p = re.sub(r"[ \t]*\n[ \t]*", " ", p).strip()
        p = _inline(p)
        for i, block in enumerate(placeholders):
            p = p.replace(f"\x00LITERAL{i}\x00", "\n+\n" + block + "\n+\n")
        conv.append(p)
    # '+' continuation joins multi-paragraph list-item bodies correctly both
    # at the top level and inside a nested (open-block) description list;
    # plain blank lines only work for the former
    return "\n+\n".join(conv)


def _render_items(body):
    """Render the item list found inside an @table/@enumerate block."""
    pieces = _ITEM_SPLIT_RE.split(body)
    # pieces[0] is any text before the first @item (normally empty/blank)
    entries = []
    it = iter(pieces[1:])
    for label, item_body in zip(it, it):
        label = label.strip()
        item_body = item_body.strip("\n")
        if label.startswith("@var{"):
            m = re.match(r"@var\{([^}]*)\}\s*(.*)", label, re.S)
            if m:
                label = m.group(1)
        elif not label:
            # bare "@item" on its own line, with the label on the line that
            # follows (typically "@var{X}", occasionally plain text)
            body_lines = item_body.split("\n", 1)
            first = body_lines[0].strip()
            m = re.match(r"^@var\{([^}]*)\}$", first)
            if m:
                label = m.group(1)
                item_body = body_lines[1] if len(body_lines) > 1 else ""
            elif first:
                label = first
                item_body = body_lines[1] if len(body_lines) > 1 else ""
        entries.append(f"*{_inline(label)}*:::\n{_convert_body(item_body)}")
    return "\n".join(entries)


def texi_to_adoc(text, nested=False):
    """Convert a full .def doc/detail/explain text block to AsciiDoc.

    Paragraphs separate on blank lines.  @table/@enumerate blocks become
    AsciiDoc description lists; when such a block is embedded inside
    another list item (an option's description), it must be wrapped in
    AsciiDoc's list-continuation ('+' then an open block) to nest
    correctly - the `nested` flag controls that wrapping.
    """
    if not text.strip():
        return ""

    out_parts = []
    pos = 0
    for m in _ITEM_BLOCK_RE.finditer(text):
        before = text[pos:m.start()].strip("\n")
        if before.strip():
            out_parts.append(("para", before))
        out_parts.append(("list", _render_items(m.group(2))))
        pos = m.end()
    tail = text[pos:].strip("\n")
    if tail.strip():
        out_parts.append(("para", tail))

    rendered = []
    for kind, content in out_parts:
        if kind == "list":
            if nested:
                rendered.append("+\n--\n" + content + "\n--")
            else:
                rendered.append(content)
        else:
            rendered.append(_convert_body(content))
    return "\n\n".join(r for r in rendered if r.strip())


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class AdocModel(Model):
    def __init__(self, ir, base):
        super().__init__(ir, base)
        self.package = self.attrs.get("package", "")
        self.title = self.attrs.get("prog-title", "")
        self.argument = self.attrs.get("argument")
        cp = dict(self.attrs["copyright"])
        self.cp_date = cp["date"]
        self.cp_owner = cp["owner"]
        self.cp_type = str(cp.get("type", "gpl")).strip('"')
        self.eaddr = cp.get("eaddr")
        self.author_text = text_of(cp.get("author", ""))
        self.homercs = []
        if "homerc" in self.attrs and self.load_opts:
            for n2, v2 in ir["attributes"]:
                if n2.replace("_", "-") == "homerc":
                    self.homercs.append(text_of(v2))


def flag_syntax(fa):
    """'-x, --name' / '--name' style flag name list for an OPTIONS entry."""
    parts = []
    if "value" in fa:
        parts.append(f"*-{fa['value']}*")
    long_ = f"*--{fa['name']}*"
    parts.append(long_)
    head = ", ".join(parts)
    if fa.get("arg-type") == "number":
        head += "=_number_"
    elif fa.get("arg-type") == "string":
        head += "=_string_"
    return head


def option_body(fa):
    """The description body text for one OPTIONS entry."""
    bits = []
    desc = text_of(fa.get("descrip", "")).strip()
    if desc and not desc.endswith("."):
        desc += "."
    if desc:
        bits.append(_inline(desc))

    maxc = fa.get("max", "1")
    if maxc not in ("1",):
        bits.append(f"May appear up to {maxc} times." if maxc != "NOLIMIT" else "May appear an unlimited number of times.")
    if "must-set" in fa:
        bits.append("This option is required.")

    if "arg-range" in fa:
        lo, hi = text_of(fa["arg-range"]).split("->")
        lo, hi = lo.strip() or "any", hi.strip() or "any"
        bits.append(f"Range: {lo} to {hi}.")
    if "arg-default" in fa:
        dft = text_of(fa["arg-default"])
        if dft not in ("", None):
            bits.append(f"Default: `{dft}`.")

    if "flags-must" in fa:
        req = ", ".join(f"*--{x}*" for x in fa["flags-must"])
        bits.append(f"Requires: {req}.")
    if "flags-cant" in fa:
        cant = ", ".join(f"*--{x}*" for x in fa["flags-cant"])
        bits.append(f"Cannot be combined with: {cant}.")

    head = " ".join(bits)
    doc = texi_to_adoc(text_of(fa.get("doc", "")), nested=True)
    if doc:
        return head + "\n+\n" + doc if head else doc
    return head


def emit_synopsis(m):
    parts = [f"*{m.prog}*"]
    parts.append("[_OPTION_]...")
    if m.argument:
        arg = text_of(m.argument) if not isinstance(m.argument, str) else m.argument
        parts.append(_inline(arg))
    return " ".join(parts)


def emit_options_section(m):
    lines = []
    for fa in m.flags:
        lines.append(flag_syntax(fa) + "::")
        # AsciiDoc description-list bodies must start at column 0: leading
        # whitespace on a paragraph triggers literal-block interpretation
        lines.append(option_body(fa))
        lines.append("")
    # standard help/more-help entries (version is always user-authored in
    # these .def files and already covered by the loop above)
    help_flag = m.attrs.get("help-value", "h")
    lines.append(f"*-{help_flag}*, *--help*::")
    lines.append("Display usage information and exit.")
    lines.append("")
    lines.append("*--more-help*::")
    lines.append("Pass the extended usage information through a pager.")
    if m.save_opts:
        lines.append("")
        lines.append("*--save-opts*[=_string_]::")
        lines.append("Save the current option state to a config file.")
    if m.load_opts:
        lines.append("")
        lines.append("*--load-opts*=_string_, *--no-load-opts*::")
        lines.append("Load options from a config file; *--no-load-opts* disables this.")
    return "\n".join(lines)


def emit_exit_status(m):
    up = m.prog.upper().replace("-", "_")
    lines = ["One of the following exit values will be returned:", ""]
    lines.append("*0* (EXIT_SUCCESS)::")
    lines.append("  Successful program execution.")
    lines.append("")
    lines.append("*1* (EXIT_FAILURE)::")
    lines.append("  The operation failed or the command syntax was not valid.")
    if m.load_opts:
        lines.append("")
        lines.append("*66* (EX_NOINPUT)::")
        lines.append("  A specified configuration file could not be loaded.")
    lines.append("")
    lines.append("*70* (EX_SOFTWARE)::")
    lines.append("  libopts had an internal operational error. Please report it to "
                 "autogen-users@lists.sourceforge.net. Thank you.")
    return "\n".join(lines)


def emit_authors(m):
    lines = []
    if m.author_text.strip():
        for para in [p for p in m.author_text.split("\n\n") if p.strip()]:
            lines.append(re.sub(r"[ \t]*\n[ \t]*", " ", para.strip()))
            lines.append("")
    else:
        lines.append(f"Copyright {m.cp_date} {m.cp_owner}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def emit_copyright(m):
    if m.cp_type == "bsd":
        return ("This program is released under the Modified (3 clause) Berkeley "
                "Software Distribution License.")
    return (f"Copyright (C) {m.cp_date} {m.cp_owner}, all rights reserved.\n"
            "This program is released under the terms of the GNU General Public "
            "License, version 3 or later.")


def emit(def_path, base, defines=(), search=()):
    ir = parse_def_file(def_path, defines=defines, search=search)
    m = AdocModel(ir, base)
    out = []
    a = out.append

    a(f"= {m.prog}(1)")
    a(":doctype: manpage")
    a(":manmanual: Tcpreplay Suite")
    a(":mansource: Tcpreplay Suite")
    a(":man-linkstyle: pass:[blue R < >]")
    a("")
    a("== NAME")
    a("")
    a(f"{m.prog} - {_inline(m.title)}")
    a("")
    a("== SYNOPSIS")
    a("")
    a(emit_synopsis(m))
    a("")
    a("== DESCRIPTION")
    a("")
    explain = texi_to_adoc(text_of(m.attrs.get("explain", "")))
    detail = texi_to_adoc(text_of(m.attrs.get("detail", "")))
    for block in (explain, detail):
        if block:
            a(block)
            a("")
    a("== OPTIONS")
    a("")
    a(emit_options_section(m))
    a("")
    if m.load_opts:
        a("== OPTION PRESETS")
        a("")
        a("Any option that is not marked as _not presettable_ may be preset "
          "by loading values from configuration (\"RC\" or \".INI\") file(s).")
        if m.homercs:
            a(f"The homerc file is _{m.homercs[0]}_, unless that is a directory; "
              f"in that case _.{m.prog}rc_ is searched for within it.")
        a("")
        a("== FILES")
        a("")
        a("See *OPTION PRESETS* for configuration files.")
        a("")
    a("== EXIT STATUS")
    a("")
    a(emit_exit_status(m))
    a("")
    a("== AUTHORS")
    a("")
    a(emit_authors(m))
    a("== COPYRIGHT")
    a("")
    a(emit_copyright(m))
    a("")
    a("== BUGS")
    a("")
    if m.eaddr:
        a(f"Please send bug reports to: {m.eaddr}")
    else:
        a("Please send bug reports through the project's issue tracker.")
    a("")
    a("== NOTES")
    a("")
    a(f"This manual page was generated from the {m.prog} option definitions.")
    a("")
    return "\n".join(out)


if __name__ == "__main__":
    base = sys.argv[1]
    def_path = sys.argv[2]
    defines = sys.argv[3].split(",") if len(sys.argv) > 3 and sys.argv[3] else []
    sys.stdout.write(emit(def_path, base, defines, ["src", "src/tcpedit"]))
