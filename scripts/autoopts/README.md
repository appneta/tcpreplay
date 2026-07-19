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
- [ ] Stage 3 — `emit_c.py`: *_opts.c emitter (the long pole).
- [ ] Stage 4 — `emit_man.py`: man page emitter; then switch the build
      rules and retire autogen.

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
