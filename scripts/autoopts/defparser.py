#!/usr/bin/env python3
# Copyright (c) 2013-2026 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
# GPLv3 - part of the Tcpreplay Suite.
"""AutoGen .def parser for the Tcpreplay Suite (#895, phase 2).

GNU autogen is EOL.  Phase 1 committed autogen's generated output; this
package is the replacement generator, starting with a parser that turns the
existing AutoOpts .def files into a plain JSON-serializable intermediate
representation (IR).  Emitters that turn the IR back into the exact
libopts-compatible *_opts.c/h tables and man pages hang off this; their
output must pass scripts/check-generated-opts.sh's byte comparison against
autogen while autogen still exists as the oracle.

Supported syntax (the subset the tcpreplay defs use):
  - `autogen definitions options;` prologue
  - `name = value;` where value is a quoted string (C escapes, adjacent
    string concatenation across lines), a bare word (e.g. `gpl`), or a
    number
  - here-documents: `name = <<- MARKER ... MARKER;` (<<- allows the
    terminator to be indented; bodies are taken verbatim)
  - value-less attributes: `long-opts;`, `immediate;`
  - repeatable blocks: `flag = { ... };`, `copyright = { ... };`
  - C comments (/* */ and //) on structural lines; heredoc bodies are
    protected and taken verbatim
  - preprocessor lines honoring -D defines: #ifdef/#ifndef/#else/#endif
    and `#include <file>` resolved against the def's directory plus -L
    search paths (heredoc bodies keep their own preprocessor lines - they
    belong to the embedded C code)

The IR preserves entry order (option index order matters) and records each
flag's attributes verbatim, with heredoc text unmodified - reflowing to
autogen's usage/man width is the emitters' job, not the parser's.
"""

import json
import re
import sys
from pathlib import Path

__all__ = ["parse_def_file", "text_of", "ParseError"]


def text_of(value):
    """Return the text of an attribute value (heredocs carry metadata)."""
    if isinstance(value, dict) and value.get("__heredoc__"):
        return value["text"]
    return value

_HEREDOC_START_RE = re.compile(
    r"^(\s*[A-Za-z_][A-Za-z0-9_-]*\s*=\s*)<<(-?)\s*([A-Za-z_][A-Za-z0-9_]*)\s*$"
)


class ParseError(Exception):
    pass


class _Preprocessor:
    """Produces structural lines with heredoc bodies swapped for sentinels.

    Heredoc state is tracked here so that #-directives, #include and
    comment stripping never touch embedded C code.
    """

    def __init__(self, defines, search):
        self.defines = set(defines)
        self.search = [Path(p) for p in search]
        self.lines = []          # structural lines (heredocs -> sentinels)
        self.heredocs = {}       # sentinel id -> body text
        self._counter = 0

    def _resolve(self, name, relative_to):
        for c in [relative_to / name] + [d / name for d in self.search]:
            if c.is_file():
                return c
        raise ParseError(f"#include {name}: not found")

    def load(self, path):
        path = Path(path)
        stack = []
        raw_lines = path.read_text().splitlines()
        i = 0
        while i < len(raw_lines):
            raw = raw_lines[i]
            m = _HEREDOC_START_RE.match(raw)
            if m and all(stack):
                prefix, dash, marker = m.groups()
                body = []
                i += 1
                body_start = i + 1  # 1-based line of the first body line
                while i < len(raw_lines):
                    line = raw_lines[i]
                    stripped = line.strip() if dash else line
                    if stripped in (marker + ";", marker):
                        break
                    body.append(line)
                    i += 1
                else:
                    raise ParseError(f"{path}: unterminated heredoc {marker}")
                self._counter += 1
                key = f"@HEREDOC{self._counter}@"
                self.heredocs[key] = {
                    "__heredoc__": True,
                    "text": "\n".join(body) + ("\n" if body else ""),
                    "file": path.name,
                    "line": body_start,
                }
                self.lines.append(f"{prefix}{key};")
                i += 1
                continue

            stripped = raw.strip()
            if stripped.startswith("#"):
                directive = stripped[1:].strip()
                if directive.startswith("ifdef"):
                    stack.append(directive.split()[1] in self.defines)
                elif directive.startswith("ifndef"):
                    stack.append(directive.split()[1] not in self.defines)
                elif directive.startswith("else"):
                    stack[-1] = not stack[-1]
                elif directive.startswith("endif"):
                    stack.pop()
                elif directive.startswith("include"):
                    if all(stack):
                        name = directive.split(None, 1)[1].strip().strip('"<>')
                        self.load(self._resolve(name, path.parent))
                else:
                    raise ParseError(f"{path}:{i + 1}: unknown directive {stripped!r}")
                i += 1
                continue

            if all(stack):
                self.lines.append(raw)
            i += 1
        if stack:
            raise ParseError(f"{path}: unterminated #ifdef")


def _strip_comments(text):
    """Remove /* */ and // comments, respecting double-quoted strings."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("/*", i):
            j = text.index("*/", i + 2)
            out.append("\n" * text.count("\n", i, j + 2))
            i = j + 2
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


_STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _c_unescape(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _parse_value(text, lines, idx, heredocs):
    """Parse the value after '=', returning (value, next_line_idx)."""
    buf = text.strip()
    i = idx
    while ";" not in buf:
        i += 1
        if i >= len(lines):
            raise ParseError(f"missing ';' after value: {buf[:40]!r}")
        buf += "\n" + lines[i]
    buf = buf[: buf.rindex(";")].strip()
    if buf in heredocs:
        return heredocs[buf], i + 1
    strs = _STR_RE.findall(buf)
    if strs:
        return "".join(_c_unescape(s) for s in strs), i + 1
    return buf, i + 1


def _parse_entries(lines, idx, heredocs, end_at_brace):
    entries = []
    i = idx
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            i += 1
            continue
        if end_at_brace and line.startswith("}"):
            return entries, i + 1
        if line.startswith("autogen "):  # 'autogen definitions options;'
            i += 1
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*(=?)\s*(.*)$", line)
        if not m:
            raise ParseError(f"unparseable line: {line!r}")
        name, eq, rest = m.groups()
        if not eq:
            if rest not in ("", ";"):
                raise ParseError(f"unparseable line: {line!r}")
            entries.append((name, True))
            i += 1
        elif rest.lstrip().startswith("{"):
            sub, i = _parse_entries(lines, i + 1, heredocs, end_at_brace=True)
            entries.append((name, sub))
        else:
            value, i = _parse_value(rest, lines, i, heredocs)
            entries.append((name, value))
    if end_at_brace:
        raise ParseError("unterminated block")
    return entries, i


def parse_def_file(path, defines=(), search=()):
    """Parse an AutoOpts .def file into an IR dict."""
    pp = _Preprocessor(defines, search)
    pp.load(path)
    lines = _strip_comments("\n".join(pp.lines)).splitlines()
    entries, _ = _parse_entries(lines, 0, pp.heredocs, end_at_brace=False)

    ir = {"attributes": [], "flags": []}
    for name, value in entries:
        if name == "flag":
            ir["flags"].append({"attributes": [[n, v] for n, v in value]})
        elif isinstance(value, list):
            ir["attributes"].append([name, [[n, v] for n, v in value]])
        else:
            ir["attributes"].append([name, value])
    return ir


def main(argv):
    if len(argv) < 2:
        print("usage: defparser.py [-D SYM]... [-L DIR]... <file.def>", file=sys.stderr)
        return 64
    defines, search, files = [], [], []
    i = 1
    while i < len(argv):
        if argv[i] == "-D":
            defines.append(argv[i + 1]); i += 2
        elif argv[i].startswith("-D"):
            defines.append(argv[i][2:]); i += 1
        elif argv[i] == "-L":
            search.append(argv[i + 1]); i += 2
        elif argv[i].startswith("-L"):
            search.append(argv[i][2:]); i += 1
        else:
            files.append(argv[i]); i += 1
    for f in files:
        json.dump(parse_def_file(f, defines, search), sys.stdout, indent=2)
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
