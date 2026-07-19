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
- [ ] **Stage 4b — man pages: OPEN DESIGN QUESTION, see below.**
- [ ] Stage 5 — switch the build rules to `generate.py` and drop autogen
      from the documented toolchain, keeping `check-generated-opts.sh` as
      the regression gate while any autogen install still exists.

## Man pages: why they are not done yet

The parser emitters had an authoritative source to port from — autogen's
`mk-gettextable` delegates to `optionPrintParagraphs()`, which lives in
the libopts **we vendor**, so the algorithm is in-tree and frozen.

Man pages have no such anchor. autogen builds them with
`cmd-doc.tlib` (1172 lines of Scheme) emitting mdoc, then pipes that
through `mdoc2man` + `Mdoc.pm` (761 lines of Perl). None of it is
vendored here. Reproducing byte-identical roff means either porting
~1900 lines of external code, or inferring the rules from the seven
current outputs — which would be verified only against today's inputs
and could silently diverge on a future `.def` edit.

The texinfo surface actually used is small (`@var`, `@item`, `@end`,
`@samp`, `@file`, `@code`, `@table`), so direct roff emission is
feasible — it is a question of whether the cost is worth it, given:

  * Debian's requirement (#895) was **already met in phase 1**: autogen
    is not needed to *build*.
  * Man pages are prose. A rendering difference is cosmetic and
    reviewable, unlike the compiled option tables.

Options, cheapest first:

  1. **Leave as is.** Committed man pages stay; regenerating them after
     a `.def` doc change needs autogen. Everything else is autogen-free.
  2. **Direct roff emitter** (~500-800 lines) aiming for byte-identical
     output, gated by `check-generated-opts.sh`. Rules inferred from the
     current seven pages.
  3. **Switch the man source format** (e.g. asciidoctor, as the rejected
     #991 proposed) — clean long term, but adds a build dependency and
     rewrites all seven pages, so the diff is large and reviewable only
     by reading.

## Running the gates

## Running the gates

    python3 scripts/autoopts/validate_ir.py      # structural
    python3 scripts/autoopts/check_emitters.py   # byte-identical .h/.c
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
