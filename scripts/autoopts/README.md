# autoopts generator (#895 phase 2)

Replacement for EOL GNU autogen: emit the libopts-compatible `*_opts.c/h`
tables and man pages directly from the `.def` files. The vendored libopts
runtime is untouched — this replaces only the generator.

## Status

- [x] Stage 1 — `defparser.py`: .def → JSON IR (heredocs, -D conditionals,
      -L includes, adjacent strings, blocks). `validate_ir.py` proves option
      names/order/counts match the committed autogen output for all seven
      tool configurations, including the `documentation` pseudo-flag
      subtlety (occupies an enum index, emits no constant — tcprewrite's
      enum starts at 1).
- [x] Stage 2 — `emit_h.py`: *_opts.h emitter. Byte-identical to the
      committed autogen output for all seven configurations
      (`check_emitters.py` proves it). Layout rules discovered: enum name
      field is `max(maxname+1, 21)` wide; the per-option value column is a
      fixed `%-24s ` (long names overflow with one space); unguarded
      OPT_VALUE defines get a preceding blank line, ifdef-guarded ones do
      not; save/load-opts draw from the same 0x1001+ hex counter as
      long-only options; settable+arg options emit the extended
      `SET_OPT_NAME(a)` proc-invoking form; the HAVE_OPT example in the
      interface comment uses the first flag including documentation
      pseudo-flags; `EXIT_NO_CONFIG_INPUT=66` appears iff load-opts is
      enabled.
- [x] Stage 3 — `emit_c.py`: *_opts.c emitter. Byte-identical for all
      seven configurations. The decisive move was porting libopts'
      **`optionPrintParagraphs()`** (libopts/usage.c) verbatim rather than
      guessing at the xgettext paragraph grouping — autogen's
      `mk-gettextable` delegates straight to it, and we vendor the same
      libopts, so the algorithm is authoritative and frozen. Other rules:
      string pool is deduplicated with cumulative byte offsets; text
      refills at 75 cols (descrips at 72) with whitespace collapse and
      two spaces after sentence-ending words; texinfo `@file{}`/`@var{}`
      become `'x'` and `@item` becomes a wider paragraph break;
      `documentation` pseudo-flags emit an OPTST_DOCUMENT descriptor plus
      a `lib-name`-prefixed `optDesc_p` pointer and count toward the *user*
      option count; `flags-must`/`flags-cant` names are uppercased blindly
      (dangling refs like tcpbridge's `cachefile` are legal because those
      blocks are `#ifdef`-guarded); an option carrying a bare `default`
      attribute becomes the default-opt index.
- [x] Stage 4a — `generate.py`: driver that regenerates all 14 parser
      files without autogen. Verified end-to-end: with autogen removed
      from the system, deleting every `src/*_opts.c/h` and regenerating
      reproduces them byte-identically (`git diff` empty), the tree
      builds, `sudo make test` passes in full, and both regressions that
      sank #991 work — `--load-opts` (the `prep_config` test case) and
      `--more-help`.
- [x] Stage 4b — `emit_adoc.py`: AsciiDoc man-page source emitter, +
      `check_adoc.py` gate. Not byte-oracle-verified (no in-tree source
      of truth for autogen's ~1900-line Scheme+Perl mdoc pipeline, see
      rationale in the emitter's module docstring) - instead it renders
      straight from the same `.def` content (`descrip`/`doc`/`explain`/
      `detail`) that already drives `--help` and the option tables, so
      the docs, `--help` and the .adoc source can never disagree, and
      there is nothing hand-duplicated to fall out of sync (the mistake
      in the reverted #991, which hand-wrote separate `.adoc` files).
      `check_adoc.py` verifies every real option from the `.def` appears
      in the rendered page, and (when installed) that `asciidoctor`
      renders it and `groff -man -ww` parses the result with zero
      warnings. All seven configurations pass. A hand-eyeballed diff
      against the old autogen-rendered pages for tcpcapinfo confirms
      full content parity with cleaner formatting (subsections instead
      of run-on `.NOP` paragraphs).
      Texinfo constructs handled: `@file`/`@var` -> _italic_,
      `@samp`/`@code` -> `` `mono` ``, `@table`/`@enumerate` + `@item`
      (both the "@item LABEL" and bare-"@item"-then-"@var{X}"-on-the-
      next-line forms) -> nested AsciiDoc description lists (with the
      texinfo "- " item-body marker convention stripped, not rendered
      as a bullet), `@example` and mid-paragraph indented-line runs ->
      literal blocks, all correctly nested inside an option's own list
      entry via AsciiDoc's `+`/open-block continuation syntax.
      Known limitation: `man-doc` content (SIGNALS/custom
      BUGS/SEE ALSO prose in tcpreplay, tcpbridge, tcpliveplay,
      tcprewrite, tcpprep) is not rendered - matching current behavior,
      since it turns out the existing `agman-cmd.tpl` pipeline does not
      emit it into the committed man pages either (verified: none of
      that text appears in the committed `.1` files). Worth revisiting
      as a separate enhancement if that content should actually be
      surfaced.

## Running the gates## Running the gates

## Running the gates

    python3 scripts/autoopts/validate_ir.py      # structural
    python3 scripts/autoopts/check_emitters.py   # byte-identical .h/.c
    python3 scripts/autoopts/check_adoc.py        # content + asciidoctor/groff validity
    ./scripts/check-generated-opts.sh            # committed vs autogen

## Method: oracle-driven equivalence

autogen 5.18.16 still works today. Every emitter must produce output
byte-identical to the committed (autogen-generated) files —
`../check-generated-opts.sh` is the comparison harness (man `.TH` dates
normalized). Iterate diff-by-diff per tool, smallest first
(tcpcapinfo → tcpliveplay → tcpprep → tcpreplay → tcprewrite → tcpbridge
→ tcpreplay-edit). Do not switch the build until all seven pass.

## Emitter notes (learned from the committed output)

- **Headers** are a fixed skeleton with computed spans: filenames,
  prog-name casings, guard names, the INDEX enum (names padded to the
  longest entry, `= %2d`, doc entries skipped but consuming indexes),
  OPTION_CT, per-option VALUE_OPT_/OPT_VALUE_ defines with `ifdef` guards
  from the def, exit-code enum, NLS block. License blurbs are AutoOpts'
  canned texts parameterized by copyright type/owner/date/prog — at least
  `gpl` (most tools) and `mbsd` (tcpliveplay) are needed; copy them
  verbatim from the committed headers into a table.
- **.c files**: single string pool `<prog>_opt_strs[N]` with `/* off */`
  byte-offset comments — offsets are simple cumulative byte counts
  (NUL-terminated entries). Text from descrip/explain/detail is
  **reflowed** (~76 cols) — replicate autogen's paragraph wrap exactly
  (compare against committed strings). Then per-option `#define`
  name/desc blocks, `tOptDesc` array (flag masks derived from def
  attributes: immediate, max, arg-type, must/cant-sets, enabled state),
  callback functions (flag-code passthrough verbatim, doOptDbug-style
  range checkers generated), usage/version strings, translation
  (`AO_...`) block, `tOptions` struct.
- **Generation flags per tool** are encoded in CASES inside
  `validate_ir.py` and in `../check-generated-opts.sh`.
- The `-DTCPREPLAY_EDIT` variant emits `#ifdef`-guarded sections in the
  output where the def guards flags with `ifdef`/`omitted-usage` — grep
  the committed tcpreplay_edit_opts.c for `#ifdef` to see the pattern.

## Ground rules

- Python 3 stdlib only (this must not add build dependencies).
- Never modify the vendored `libopts/` runtime.
- Keep `validate_ir.py` passing at every commit; add per-stage
  equivalence checks to CI as each emitter lands.
