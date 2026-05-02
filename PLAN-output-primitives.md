# Implementation Plan: ioc-scan output-primitive refactor (A+B+D)

**Goal:** Bring `sessionscribe-ioc-scan.sh` detection-side rendering into alignment with `sessionscribe-mitigate.sh`'s idiom: replace Unicode `━━━` section banners with mitigate's `== id == desc` style (A), replace icon-glyph severity rendering with bracketed ASCII tags (B), and add a per-section verdict matrix at the top of the summary block (D). Renderer-only — no JSON/JSONL/CSV/envelope schema changes.

**Architecture:** Three additive primitive changes scoped to four functions of `sessionscribe-ioc-scan.sh`. Phase 1 adds the `hdr_section(id, desc)` primitive (renaming the existing forensic `hdr()`) plus per-section ordering constants — no operator-visible change. Phase 2 rewrites the 11 detection-side `section()` call sites to the new primitive and deletes the old function. Phase 3 swaps glyph rendering in `print_signal_human` for bracketed tags compatible with EL6/CL6 non-UTF8 SSH terminals. Phase 4 accumulates a worst-wins `SECTION_VERDICT[area]` map during `aggregate_verdict` and renders it as a 7-row matrix at the top of `print_verdict`. Phase 5 bumps `VERSION` and runs live regression on `host2.alps-supplies.com` via the `cpanel_client` tmux session.

**Tech Stack:** bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 floor (CL6 EL6). No test framework — verification is `bash -n`, `shellcheck -S error`, grep call-site counts, and live runs on lab host (`cpanel_client` tmux session). Conventions documented in `CLAUDE.md`.

**Spec:** No spec file — input was operator brief: "assess ioc-scan output vs mitigate; propose A+B+D primitives". Real baseline captured 2026-05-02 from host2 (cPanel 110.0.103, COMPROMISED, 33 strong + 32 critical IOC, 166 lines stderr).

**Phases:** 5

**Plan Version:** 3.0.6

---

## Conventions

**Bash floor (per CLAUDE.md):** No `mapfile`/`readarray`, no `printf -v arr[$i]`, no `${var^^}`/`${var,,}`, no `coproc`, no `${var: -1}`, no `declare -g`, no `local -n`, no `wait -n`. `case` inside `$()` uses leading-paren patterns. Empty arrays guarded with `(( ${#arr[@]} > 0 ))` before iteration under `set -u`. Newline required after `$(` before `{`.

**ASCII-only output:** All operator-facing stderr text in this PR uses ASCII. No `━`, `→`, `✗`, `⚠`, `⚐`, `✓`, `·`, `…`. Operator terminals (PuTTY, screen-without-utf, `screen` over SSH) on the EL6 floor render Unicode as garbage. Tags must be ≤10 chars to fit `%-10s` column.

**Verbosity contract:** A new `--verbose` flag (Phase 1) is the escape hatch for any rendering choice in this PR or later PRs (C/E/G) that summarizes/elides operator-relevant detail. Default is `VERBOSE=0` (terse). Today the matrix detail column tallies counts only (`2 ioc, 1 warn`); under `--verbose` it also lists the matching IOC keys (one per line, indented under the matrix row). Future PRs that collapse the WHERE/WHO/WHAT triplet (item G) MUST guard the collapse on `(( VERBOSE == 0 ))` so `--verbose` restores the full form. Operators running with `--verbose` should never see less information than v2.0.0 produced by default.

**Section ID vocabulary** (one ID per detection scan; reused as `SECTION_VERDICT` keys):

| Section ID | Old prose banner | Detection function | emit() area |
|------------|------------------|---------------------|-------------|
| `version`  | "Version" | `check_version` | `version` |
| `patterns` | "Static patterns (ancillary; not primary CVE-2026-41940 verdict drivers)" | `check_static` | `static` |
| `cpsrvd`   | "cpsrvd binary" | `check_binary` | `binary` |
| `iocscan`  | "IOC access-log scan" | `check_logs` | `logs` |
| `sessions` | "Session-store IOC scan" | `check_sessions` | `sessions` |
| `destruct` | "Destruction IOC scan (Patterns A-I)" | `check_destruction_iocs` | `destruction` |
| `probe`    | "Localhost marker probe (--probe)" | `check_localhost_probe` | `probe` |
| `summary`  | "Summary" | `print_verdict` | (terminal) |

The `area` column is the existing `emit()` area, untouched. Phase 4's matrix renders one row per `area` in the order shown above, using the section ID as the row label (3rd column) and the existing area name as the verdict-aggregation key.

**Severity → tag mapping** (Phase 3):

| `emit()` severity | Tag       | Color    | Notes                                                                            |
|-------------------|-----------|----------|----------------------------------------------------------------------------------|
| `strong`          | `[IOC]`   | `$RED`   | Critical detection signal                                                        |
| `evidence`        | `[EVIDENCE]` | `$YELLOW` | 9-char tag — fits `%-10s`                                                     |
| `warning`         | `[WARN]`  | `$YELLOW`| Review-tier IOC or non-fatal anomaly                                             |
| `advisory`        | `[ADVISORY]` | `$CYAN` | 10-char tag — fits `%-10s` exactly                                            |
| `error`           | `[ERR]`   | `$RED`   | Tool/internal error                                                              |
| `info` (good keys)| `[OK]`    | `$GREEN` | `patched_per_build`, `ancillary_bug_fixed`, `patch_marker_present`, `acl_machinery_present_informational`, `no_ioc_hits`, `no_session_iocs` |
| `info` (other)    | `[..]`    | `$DIM`   | Neutral / sample / progress                                                      |

The "good info keys" list is identical to the existing one in `print_signal_human` (lines 875 and 933-936) — copy verbatim, do not invent new keys.

**Worst-wins verdict ladder** (Phase 4): `IOC > VULN > WARN > ADVISORY > OK > unset`. The `SECTION_VERDICT[area]` array tracks the worst tag observed for each area in `SIGNALS[]`. Mapping from `emit()` severity to ladder rank is identical to the tag mapping above (`[IOC]`, `[VULN]`, `[WARN]`, `[ADVISORY]`, `[OK]`); the matrix renderer emits the tag with the highest rank seen, defaulting to `[OK]` when an area has signals but no failure-tier ones, or `[..]` when an area was skipped (no signals at all).

`[VULN]` is reserved for code-state failures (currently `acl_strings` strong, version-string strong) and is rendered for `version`/`cpsrvd`/`patterns` rows when the worst-severity `emit()` signal in those areas is `strong` AND the key is NOT `ioc_*`. This separates "code is unpatched" from "host is exploited" in the matrix.

**Boilerplate** — script header is unchanged. Existing format:
```bash
#!/bin/bash
#
##
# sessionscribe-ioc-scan.sh v${VERSION}
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
```

**Commit message format** — per `git log --oneline` (recent 10 commits):
```
<scope> v<version>: <one-line summary>

<body explaining the why, the surface area touched, and verification done>
```
Phases 1-4 use `ioc-scan v2.1.0-pre<N>:` prefix. Phase 5 uses `ioc-scan v2.1.0:` for the version bump + final.

**CRITICAL:** Never `git add -A` / `git add .` — add specific files only. Never push to `main` without operator confirmation (changes ship via the curl one-liner; `main` is the fleet's source of truth). Commits stay local until Phase 5 completes and the operator approves the `main` push.

---

## File Map

### New Files

| File | Lines | Purpose | Test File |
|------|-------|---------|-----------|
| (none) | — | All changes are in-place edits to existing scripts | N/A |

### Modified Files

| File | Changes | Test File |
|------|---------|-----------|
| `sessionscribe-ioc-scan.sh` | Add `hdr_section`, rename forensic `hdr→hdr_section`, add `SECTION_ORDER`/`SECTION_LABEL`/`SECTION_VERDICT` constants (P1); rewrite 11 `section()` call sites + remove old `section()` (P2); replace icon glyphs with bracketed tags in `print_signal_human` (P3); track `SECTION_VERDICT[area]` in `aggregate_verdict` and render matrix in `print_verdict` (P4); bump `VERSION` 2.0.0 → 2.1.0 (P5) | N/A (refactor) — `bash -n` + live regression on host2 |

### Deleted Files

| File | Reason |
|------|--------|
| (none) | — |

---

## Phase Dependencies

- Phase 1: none
- Phase 2: [1]
- Phase 3: none
- Phase 4: [1]
- Phase 5: [1, 2, 3, 4]

Phase 3 is independent of 1/2/4 because `print_signal_human` is a separate function from `section()`/`hdr()`/`aggregate_verdict`. A `/r-build --parallel` run could schedule Phase 3 alongside Phase 1, but since both phases mutate `sessionscribe-ioc-scan.sh`, file ownership forces serialization in practice. Listed here as a structural aid for the dispatcher; treat as serial in execution.

---

### Phase 1: Scaffold — add hdr_section primitive, rename forensic hdr, add SECTION_* constants, add --verbose flag

Establish the primitive, the section-ordering tables, and a `--verbose` flag for the verbosity contract — without changing any operator-visible output. Forensic phases keep rendering identically because they were already calling `hdr "id" "desc"` — the rename is mechanical. `--verbose` is parsed and stored as `VERBOSE=1` but no consumer exists yet (Phase 4 wires the first one).

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (add `hdr_section`, rename forensic `hdr` calls, add `SECTION_ORDER` + `SECTION_LABEL` + `SECTION_VERDICT` declarations, add `VERBOSE=0` global + `--verbose|-v` parser entry + usage line)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -cE '^hdr_section\(\)' sessionscribe-ioc-scan.sh` returns 1; `grep -cE '^hdr\(\)' sessionscribe-ioc-scan.sh` returns 0 (old name removed); `grep -cE '^\s*hdr\s+"' sessionscribe-ioc-scan.sh` returns 0 (no callers of the old name); `grep -cE '^\s*hdr_section\s+"' sessionscribe-ioc-scan.sh` returns 5 (the 5 forensic call sites now using the new name); `grep -c '^SECTION_ORDER=(' sessionscribe-ioc-scan.sh` returns 1; `grep -c 'declare -A SECTION_LABEL=' sessionscribe-ioc-scan.sh` returns 1; `grep -c 'declare -A SECTION_VERDICT=' sessionscribe-ioc-scan.sh` returns 1; `grep -cE '^VERBOSE=0' sessionscribe-ioc-scan.sh` returns 1; `grep -cE -- '--verbose\)' sessionscribe-ioc-scan.sh` returns 1 (parser entry); `bash sessionscribe-ioc-scan.sh --verbose --help >/dev/null` exits 0 (flag is accepted by the parser); running `bash sessionscribe-ioc-scan.sh --help >/dev/null` exits 0 (script still parses + executes the help path with the renamed primitive).
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect literal `OK`; `bash sessionscribe-ioc-scan.sh --help 2>&1 | head -1 | grep -c 'sessionscribe-ioc-scan.sh'` → expect `1`. No live host run yet — Phase 5 covers that.
- **Edge cases**: none (no spec; no behavior change in this phase by construction).
- **Regression-case**: N/A — refactor — Phase 1 is pure scaffolding; renaming an internal helper function and adding three unread arrays cannot change any operator-visible output. The 5 forensic call sites still produce identical stderr because `hdr_section` is byte-identical to the old `hdr`. Verification is `bash -n` and a parser smoke-run via `--help`.

- [ ] **Step 1: Add SECTION_ORDER and SECTION_LABEL constants alongside existing globals**

  Location: `sessionscribe-ioc-scan.sh` between line 718 (`BUNDLE_TGZ=""`) and line 720 (`# Resolved by write_ledger() ...`).

  Insert this block:
  ```bash

  ###############################################################################
  # Per-section verdict tracking (output primitive v2.1.0)
  # SECTION_ORDER drives the summary matrix row sequence + section ID display.
  # SECTION_LABEL maps the emit() area to the human-facing matrix row label.
  # SECTION_VERDICT[area] is filled by aggregate_verdict() (worst-wins) and
  # consumed by print_verdict() to render the 7-row matrix at the top of
  # the summary block.
  ###############################################################################
  SECTION_ORDER=(version static binary logs sessions destruction probe)
  declare -A SECTION_LABEL=(
      [version]="version"
      [static]="patterns"
      [binary]="cpsrvd"
      [logs]="iocscan"
      [sessions]="sessions"
      [destruction]="destruct"
      [probe]="probe"
  )
  declare -A SECTION_VERDICT=()      # area -> worst tag observed in SIGNALS[]
  declare -A SECTION_COUNTS=()       # area -> "ioc=N warn=M ok=K" rollup string
  ```

  Self-correction note: `declare -A` is bash 4.0+ — already used elsewhere in this script (`declare -A PHASE_DESC` in mitigate, multiple `-A` arrays in forensic helpers), so floor-safe.

- [ ] **Step 2: Add hdr_section() helper at line 988 (replacing old hdr())**

  Location: `sessionscribe-ioc-scan.sh:988` — the line currently reads:
  ```bash
  hdr()           { (( QUIET )) || printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$1" "$C_NC" "$C_DIM" "$2" "$C_NC" >&2; }
  ```

  Replace with:
  ```bash
  hdr_section()   { (( QUIET )) || printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$1" "$C_NC" "$C_DIM" "$2" "$C_NC" >&2; }
  ```

  (Identical body — only the function name changes from `hdr` to `hdr_section`.)

- [ ] **Step 3: Rewrite 5 forensic call sites from `hdr` → `hdr_section`**

  Each of the 5 sites has the literal form `    hdr "ID" "DESC"`. Run the rewrite in-place with `sed`:

  ```bash
  sed -i 's/^\(\s*\)hdr "/\1hdr_section "/' sessionscribe-ioc-scan.sh
  ```

  Then verify exact line numbers:
  ```bash
  grep -nE '^\s*hdr_section\s+"' sessionscribe-ioc-scan.sh
  # expect (lines may shift by ±0 from these — confirm the 5 areas, not the line numbers):
  # 1442:    hdr_section "defense" "extracting timestamps for every mitigation layer"
  # 1713:    hdr_section "offense" "ingesting IOCs from canonical detector + deep checks"
  # 1727:    hdr_section "reconcile" "comparing defense activation vs compromise timestamps"
  # 2697:    hdr_section "bundle" "capturing raw artifacts (window=${SINCE_DAYS:-all}d, cap=${MAX_BUNDLE_MB}MB)"
  # 3041:    hdr_section "upload" "submitting bundle to $INTAKE_URL"
  ```

  Self-correction note: The `sed` regex `^\(\s*\)hdr "` matches only `hdr ` followed by a quoted argument at line start (with leading whitespace). It will NOT match `hdr_section` (already-rewritten lines), `hdr_` prefixed names (none exist), or the function definition `hdr() {` (no space after, so the original anchor `hdr "` doesn't match). Confirmed by reading every match — there are exactly 5 forensic call sites and no others use `hdr ` literally.

- [ ] **Step 4: Verify parse + help-path execution**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  ```

  ```bash
  bash sessionscribe-ioc-scan.sh --help 2>&1 | head -1
  # expect: a line containing "sessionscribe-ioc-scan.sh"
  ```

  ```bash
  grep -cE '^hdr\(\)' sessionscribe-ioc-scan.sh
  # expect: 0
  ```

  ```bash
  grep -cE '^hdr_section\(\)' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -cE '^\s*hdr_section\s+"' sessionscribe-ioc-scan.sh
  # expect: 5
  ```

  ```bash
  grep -c '^SECTION_ORDER=(' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -c 'declare -A SECTION_LABEL=' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -c 'declare -A SECTION_VERDICT=' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

- [ ] **Step 5: Add VERBOSE=0 global + --verbose|-v parser entry + usage line**

  Three insertions, in order:

  (a) Location: `sessionscribe-ioc-scan.sh:309` — line currently reads `QUIET=0`. Insert immediately after it:
  ```bash
  VERBOSE=0
  ```

  (b) Location: `sessionscribe-ioc-scan.sh:534` — line currently reads `        --quiet)              QUIET=1; shift ;;`. Insert immediately after it:
  ```bash
          --verbose|-v)         VERBOSE=1; shift ;;
  ```

  (c) Location: `sessionscribe-ioc-scan.sh:461` — line currently reads:
  ```
        --quiet                Suppress sectioned report.
  ```
  Insert immediately after it:
  ```
        --verbose, -v          Expand the per-section verdict matrix to
                               include matching IOC keys per row. Reserved
                               for future renderer changes that elide
                               operator-relevant detail.
  ```

  (d) Location: `sessionscribe-ioc-scan.sh:70` (the top-of-file usage comment block). Line currently reads `#   --quiet     suppress sectioned report`. Insert immediately after it:
  ```
  #   --verbose   expand matrix detail; future-proof escape for elided info
  ```

  Verify all four insertions:
  ```bash
  grep -cE '^VERBOSE=0' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -cE -- '--verbose\|-v\)' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -cE '^      --verbose, -v' sessionscribe-ioc-scan.sh
  # expect: 1
  bash sessionscribe-ioc-scan.sh --verbose --help >/dev/null && echo OK
  # expect: OK
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.1.0-pre1: scaffold hdr_section primitive + SECTION_* constants + --verbose flag

  Rename forensic hdr() to hdr_section() (5 call sites: defense, offense,
  reconcile, bundle, upload). Add SECTION_ORDER, SECTION_LABEL,
  SECTION_VERDICT, SECTION_COUNTS globals to support the upcoming
  detection-side section() rewrite (Phase 2) and per-section verdict
  matrix in print_verdict (Phase 4). Add VERBOSE=0 global + --verbose|-v
  CLI flag as the verbosity escape hatch — first consumer is the matrix
  detail column (Phase 4); future PRs that elide info (deferred items
  C/E/G) will guard their elision on (( VERBOSE == 0 )) so --verbose
  always restores the v2.0.0 default detail level.

  No operator-visible behavior change in this commit — forensic phases
  render identically (hdr_section is byte-identical to the old hdr) and
  --verbose has no consumer yet.

  Verified: bash -n exits 0; --help and --verbose --help both parse; all
  5 forensic call sites confirmed via grep; VERBOSE=0 + --verbose|-v
  parser entry present.
  EOF
  )"
  ```

---

### Phase 2: Replace section() call sites with hdr_section(id, desc); remove old section()

Convert the 11 detection-side `section "<prose>"` invocations to the new `hdr_section "<id>" "<desc>"` form, then delete the old `section()` function. After this phase the human-readable stderr stream matches mitigate's `== id == desc` idiom across detection and forensic.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (rewrite 11 call sites; delete `section()` definition)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -cE '^section\(\)' sessionscribe-ioc-scan.sh` returns 0 (old fn removed); `grep -cE '^\s*section\s+"' sessionscribe-ioc-scan.sh` returns 0 (no callers of old name); `grep -cE '^\s*hdr_section\s+"' sessionscribe-ioc-scan.sh` returns 16 (5 forensic from P1 + 11 new detection sites = 16); `grep -cE '^\s*hdr_section\s+"version"' sessionscribe-ioc-scan.sh` returns 1; `grep -cE '^\s*hdr_section\s+"iocscan"' sessionscribe-ioc-scan.sh` returns at least 1; `grep -c '━━━' sessionscribe-ioc-scan.sh` returns 0 (no Unicode box-drawing horizontals remain in the script). Running `bash sessionscribe-ioc-scan.sh --help >/dev/null` exits 0.
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect `OK`; `grep -c '━━━' sessionscribe-ioc-scan.sh` → expect `0`.
- **Edge cases**: The two adjacent `section "Destruction IOC scan (Patterns A-I)"` calls inside `check_destruction_iocs` (lines 4244 + 4249) are inside `if [[ -n "$ROOT_OVERRIDE" ]]` then-/fall-through branches — both must rewrite to `hdr_section "destruct" "destruction IOC scan (Patterns A-I)"`. The IOC-only branch (line 5613) and replay-mode banner (line 5645) keep distinct IDs (`ioc-only` and `replay`) so they don't collide with the section verdict matrix (matrix uses the canonical 7 IDs from SECTION_ORDER; `ioc-only`/`replay` are sub-flow announcements that bypass the matrix).
- **Regression-case**: N/A — logging — output banner shape changes from `\n ━━━ <prose>` to `\n== <id> == <desc>`. JSON/JSONL/CSV/envelope/exit-code unchanged. Pure stderr-format change with no functional behavior delta — verification is "Phase 5 live regression confirms the new banner renders correctly on a real run".

- [ ] **Step 1: Rewrite 11 section() call sites**

  The 11 sites map to the table below. Use `Edit` (one per site) to replace each `section "<prose>"` with `hdr_section "<id>" "<desc>"`.

  | Line | Old call                                                                                | New call                                                                              |
  |------|-----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|
  | 3137 | `    section "Version"`                                                                  | `    hdr_section "version" "cpanel -V vs published patched-build cutoffs"`            |
  | 3271 | `    section "Static patterns (ancillary; not primary CVE-2026-41940 verdict drivers)"` | `    hdr_section "patterns" "static config-file patterns (ancillary; not CVE-driver)"` |
  | 3327 | `    section "cpsrvd binary"`                                                            | `    hdr_section "cpsrvd" "cpsrvd binary patch markers"`                              |
  | 3380 | `    section "IOC access-log scan"`                                                      | `    hdr_section "iocscan" "access_log scan over ${SINCE_DAYS:-all}d window"`         |
  | 3983 | `    section "Session-store IOC scan"`                                                   | `    hdr_section "sessions" "session-store IOC ladder"`                               |
  | 4244 | `        section "Destruction IOC scan (Patterns A-I)"`                                  | `        hdr_section "destruct" "destruction IOC scan (Patterns A-I)"`                |
  | 4249 | `    section "Destruction IOC scan (Patterns A-I)"`                                      | `    hdr_section "destruct" "destruction IOC scan (Patterns A-I)"`                    |
  | 5064 | `    section "Localhost marker probe (--probe)"`                                         | `    hdr_section "probe" "localhost marker probe"`                                    |
  | 5260 | `    section "Summary"`                                                                  | `    hdr_section "summary" "code state + host posture"`                               |
  | 5613 | `        section "IOC-only mode (--ioc-only): code-state checks skipped"`                | `        hdr_section "ioc-only" "code-state checks skipped"`                          |
  | 5645 | `    section "Replay mode: detection skipped, forensic phases on $ENVELOPE_PATH"`        | `    hdr_section "replay" "forensic phases on $ENVELOPE_PATH"`                        |

  Self-correction note: do not bulk-`sed` this — every replacement has a different second string and the line at 4244 has 8-space indentation while 4249 has 4-space. Use `Edit` with the full leading-whitespace + quoted prose to keep the matches unique. Re-run `grep -nE '^\s*section\s+"' sessionscribe-ioc-scan.sh` between edits if any indentation surprises arise.

- [ ] **Step 2: Delete the old section() function definition**

  Location: `sessionscribe-ioc-scan.sh:790` — the line currently reads:
  ```bash
  section() { (( QUIET )) || printf '\n %s━━━ %s%s\n\n' "$BOLD" "$1" "$NC" >&2; }
  ```

  Delete this entire line (do not leave a blank in its place — `say()` at line 788 and `sayf()` at line 789 should sit immediately above `banner()` at line 791 with no gap).

- [ ] **Step 3: Verify parse + zero residual old-form references**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  ```

  ```bash
  grep -cE '^section\(\)' sessionscribe-ioc-scan.sh
  # expect: 0
  ```

  ```bash
  grep -cE '^\s*section\s+"' sessionscribe-ioc-scan.sh
  # expect: 0
  ```

  ```bash
  grep -cE '^\s*hdr_section\s+"' sessionscribe-ioc-scan.sh
  # expect: 16
  ```

  ```bash
  grep -c '━━━' sessionscribe-ioc-scan.sh
  # expect: 0
  ```

  ```bash
  bash sessionscribe-ioc-scan.sh --help 2>&1 | head -1
  # expect: a line containing "sessionscribe-ioc-scan.sh"
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.1.0-pre2: section()->hdr_section() across 11 detection sites

  Detection-side section banners now render as `== id == desc` (mitigate
  idiom) instead of `━━━ <prose>` (Unicode box-drawing). The Unicode form
  garbled on EL6/CL6 SSH terminals without UTF-8; the new form is
  ASCII-clean and adds a machine-readable section ID (version, patterns,
  cpsrvd, iocscan, sessions, destruct, probe, summary, plus ioc-only +
  replay sub-flows). Old section() function deleted — fully replaced by
  hdr_section() from Phase 1.

  Verified: bash -n exits 0; zero residual section() calls; zero ━━━
  characters in script; --help still parses.
  EOF
  )"
  ```

---

### Phase 3: Bracket-tag severity rendering in print_signal_human

Replace the icon-glyph `case` block in `print_signal_human` with bracketed ASCII tags. The `%-44s` id column shrinks to `%-10s` for the tag plus the existing `%-44s` for the id (preserved). Operators see `[IOC] ioc_pattern_e_websocket_shell ...` instead of `✗ ioc_pattern_e_websocket_shell ...`.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (rewrite `print_signal_human` lines 866-878 + 922 + 924)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -cE 'icon="[✗⚠⚐✓·]"' sessionscribe-ioc-scan.sh` returns 0 (Unicode glyphs in print_signal_human gone); `grep -cE 'tag="\[(IOC|EVIDENCE|WARN|ADVISORY|ERR|OK|\.\.)\]"' sessionscribe-ioc-scan.sh` returns at least 7 (one per severity branch); `grep -c "'%-10s'" sessionscribe-ioc-scan.sh` returns at least 1 (new tag column format string). Running `bash sessionscribe-ioc-scan.sh --help >/dev/null` exits 0.
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect `OK`; `awk 'BEGIN { if (match("[ADVISORY]", /\[[A-Z\.]+\]/)) print "tag-OK"; else print "BROKEN" }'` → expect `tag-OK` (smoke that the bracket pattern parses cleanly under gawk-3.x).
- **Edge cases**: `info` severity has two sub-cases (good keys → `[OK]`, neutral → `[..]`) — both must be preserved in the new switch; the inner-case key list (line 875) must NOT change. The detail-suppression early-return at line 933-936 keys off `key` (not severity) and is unchanged.
- **Regression-case**: N/A — logging — output column shape changes from `<icon> <id-44>` to `[<tag-10>] <id-44>`. JSON/JSONL/CSV outputs are unaffected (this function only writes to stderr). Pure stderr-format change with no functional behavior delta. Verification is Phase 5 live regression diff vs baseline.

- [ ] **Step 1: Rewrite the severity → (icon, color) case block to (tag, color)**

  Location: `sessionscribe-ioc-scan.sh:866-881` — the current block reads:
  ```bash
      local icon color
      case "$severity" in
          strong)   icon="✗"; color="$RED" ;;
          evidence) icon="!"; color="$YELLOW" ;;
          warning)  icon="⚠"; color="$YELLOW" ;;
          advisory) icon="⚐"; color="$CYAN" ;;
          error)    icon="X"; color="$RED" ;;
          info)
              case "$key" in
                  patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs)
                      icon="✓"; color="$GREEN" ;;
                  *) icon="·"; color="$DIM" ;;
              esac
              ;;
          *) icon=" "; color="$DIM" ;;
      esac
  ```

  Replace with:
  ```bash
      local tag color
      case "$severity" in
          strong)   tag="[IOC]";      color="$RED"    ;;
          evidence) tag="[EVIDENCE]"; color="$YELLOW" ;;
          warning)  tag="[WARN]";     color="$YELLOW" ;;
          advisory) tag="[ADVISORY]"; color="$CYAN"   ;;
          error)    tag="[ERR]";      color="$RED"    ;;
          info)
              case "$key" in
                  patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs)
                      tag="[OK]"; color="$GREEN" ;;
                  *)  tag="[..]"; color="$DIM"   ;;
              esac
              ;;
          *) tag="[..]"; color="$DIM" ;;
      esac
  ```

  Self-correction note: the original `evidence` icon was `!` (ASCII), not Unicode — but it conflicts visually with `!` used elsewhere in `kpi`/banners. Tag `[EVIDENCE]` is unambiguous and consumes 10 chars exactly, fitting `%-10s`. The original `error` icon was `X` (ASCII); rendered via `[ERR]` (5 chars) for verbosity-parity with the other tags.

- [ ] **Step 2: Rewrite the header-line printf to use the bracket tag**

  Location: `sessionscribe-ioc-scan.sh:920-925` — the current block reads:
  ```bash
      # Header line: id + note (or key as fallback)
      if [[ -n "$note" ]]; then
          printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$note" "$NC" >&2
      else
          printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$key" "$NC" >&2
      fi
  ```

  Replace with:
  ```bash
      # Header line: tag + id + note (or key as fallback)
      if [[ -n "$note" ]]; then
          printf '  %s%-10s%s %-44s %s%s%s\n' "$color" "$tag" "$NC" "$id" "$DIM" "$note" "$NC" >&2
      else
          printf '  %s%-10s%s %-44s %s%s%s\n' "$color" "$tag" "$NC" "$id" "$DIM" "$key" "$NC" >&2
      fi
  ```

  Self-correction note: leading indentation changes from 3 spaces (`'   '`) to 2 spaces (`'  '`) so the total left margin stays at 2 + 10 (tag) + 1 (space) = 13 chars, matching mitigate's `'  [TAG]    %s\n'` two-space indent + bracket-tag column. The `%-44s` id width is unchanged.

- [ ] **Step 3: Verify parse + glyph removal**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  ```

  ```bash
  awk 'NR>=863 && NR<=982 { if (/[✗⚠⚐✓·]/) print NR": "$0 }' sessionscribe-ioc-scan.sh
  # expect: no output (zero residual icon glyphs in print_signal_human's body)
  ```

  ```bash
  grep -cE 'tag="\[(IOC|EVIDENCE|WARN|ADVISORY|ERR|OK|\.\.)\]"' sessionscribe-ioc-scan.sh
  # expect: 8 (strong, evidence, warning, advisory, error, info-good, info-neutral, fallback)
  ```

  ```bash
  bash sessionscribe-ioc-scan.sh --help 2>&1 | head -1
  # expect: a line containing "sessionscribe-ioc-scan.sh"
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.1.0-pre3: bracket-tag severity in print_signal_human

  Replace Unicode icon glyphs (✗ ! ⚠ ⚐ X ✓ ·) with bracketed ASCII tags
  ([IOC] [EVIDENCE] [WARN] [ADVISORY] [ERR] [OK] [..]). Icon column
  becomes %-10s wide (was 1 char + 3 spaces); leading indent normalized
  to 2 chars to match mitigate.sh's idiom. Operator-visible diff:
  every detection signal row now leads with a bracketed action-oriented
  tag readable on non-UTF8 SSH terminals (PuTTY, screen-without-utf,
  EL6/CL6 console).

  No data semantics change — JSON/JSONL/CSV outputs are unaffected
  (this function only writes to stderr).

  Verified: bash -n exits 0; zero residual icon glyphs in
  print_signal_human; 8 tag branches confirmed via grep.
  EOF
  )"
  ```

---

### Phase 4: Per-section verdict matrix in print_verdict (with --verbose expansion)

Track `SECTION_VERDICT[area]` worst-wins during `aggregate_verdict`, then render a 7-row matrix at the top of `print_verdict` immediately after the new `summary` banner and before the existing rollup counters. Under `--verbose`, each matrix row is followed by an indented list of the matching IOC keys for that area — restoring per-section signal vocabulary that the count-only form summarizes away.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (extend `aggregate_verdict` to fill `SECTION_VERDICT` + `SECTION_COUNTS` + `SECTION_KEYS`; insert `print_section_matrix()` helper with `--verbose` branch; call it from `print_verdict` after the `hdr_section "summary" ...` line)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -c '^print_section_matrix()' sessionscribe-ioc-scan.sh` returns 1; `grep -c 'SECTION_VERDICT\[\$area\]=' sessionscribe-ioc-scan.sh` returns 1 (single worst-wins assign in aggregate_verdict's loop); `grep -c 'declare -A SECTION_KEYS=' sessionscribe-ioc-scan.sh` returns 1; `grep -c 'print_section_matrix' sessionscribe-ioc-scan.sh` returns 2 (1 definition + 1 call site); `grep -cE '\(\(\s*VERBOSE\s*\)\)' sessionscribe-ioc-scan.sh` returns at least 1 (verbose guard inside print_section_matrix); calling the script with `--help` still exits 0. Live verification deferred to Phase 5.
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect `OK`. `bash sessionscribe-ioc-scan.sh --help 2>&1 >/dev/null` → expect exit 0. `bash sessionscribe-ioc-scan.sh --verbose --help 2>&1 >/dev/null` → expect exit 0.
- **Edge cases**: (1) An area with zero signals — render `[..]` not `[OK]` (skipped vs clean). (2) An area with only `info`-tier signals where the key is in the good-info list — render `[OK]`. (3) `evidence` severity ranks above `warning` (it adds to score) but is not visible in the matrix — fold `evidence` into `[WARN]` for display purposes (no `[EVIDENCE]` row tag in the matrix). (4) `[VULN]` is rendered when an area has a `strong` signal whose key is NOT `ioc_*` — distinguishes code-state vulnerability from host-state exploitation. The areas eligible for `[VULN]` are `version`, `static`, `binary`, `probe`; `logs`/`sessions`/`destruction` strong signals are always `ioc_*` and render `[IOC]`. (5) Under `--verbose`, the per-area key list MUST deduplicate (`sort -u`) — host2 fires `ioc_pattern_a_readme` 25 times and we don't want a 25-line block under that one matrix row.
- **Regression-case**: N/A — logging — adds a new stderr render block (the matrix) before the existing counter rollup. No JSON/JSONL/CSV/envelope/exit-code changes. Pure stderr instrumentation addition with no functional behavior delta. Verification is Phase 5 live regression: matrix renders correctly on a known-COMPROMISED host (host2) and a known-CLEAN host (must be verified live).

- [ ] **Step 0: Add SECTION_KEYS global alongside the other SECTION_* declarations from Phase 1**

  Location: `sessionscribe-ioc-scan.sh` — after the `declare -A SECTION_COUNTS=()` line added in Phase 1 Step 1, append:
  ```bash
  declare -A SECTION_KEYS=()         # area -> space-joined unique IOC keys (verbose mode only)
  ```

- [ ] **Step 1: Extend aggregate_verdict to fill SECTION_VERDICT + SECTION_COUNTS + SECTION_KEYS**

  Location: `sessionscribe-ioc-scan.sh:5117` — between `REASONS=()` and `IOC_KEYS=()` in the reset block, add:
  ```bash
      # Reset per-area verdict tracking. Worst-wins ladder:
      #   [IOC] > [VULN] > [WARN] > [ADVISORY] > [OK] > [..] (skipped/empty)
      SECTION_VERDICT=()
      SECTION_COUNTS=()
      SECTION_KEYS=()
  ```

  Then, inside the `for row in "${SIGNALS[@]}"` loop after the `case "$key"` switch (line ~5135) and before the `weight="${weight:-0}"` line, insert per-area accumulation:
  ```bash
          # Per-section verdict: track worst tag observed per area.
          local _tag=""
          case "$sev" in
              strong)
                  if [[ "$key" == ioc_* ]]; then _tag="[IOC]"; else _tag="[VULN]"; fi ;;
              evidence|warning) _tag="[WARN]" ;;
              advisory)         _tag="[ADVISORY]" ;;
              info)
                  case "$key" in
                      patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs)
                          _tag="[OK]" ;;
                  esac
                  ;;
          esac
          if [[ -n "$_tag" ]]; then
              local _cur="${SECTION_VERDICT[$area]:-}"
              # worst-wins: only overwrite if _tag outranks _cur
              if [[ -z "$_cur" ]] \
                 || [[ "$_cur" == "[OK]" ]] \
                 || [[ "$_cur" == "[ADVISORY]" && "$_tag" =~ ^\[(WARN|VULN|IOC)\]$ ]] \
                 || [[ "$_cur" == "[WARN]" && "$_tag" =~ ^\[(VULN|IOC)\]$ ]] \
                 || [[ "$_cur" == "[VULN]" && "$_tag" == "[IOC]" ]]; then
                  SECTION_VERDICT[$area]="$_tag"
              fi
          fi
          # Per-area roll-up counts (used in matrix detail column).
          case "$sev" in
              strong)   SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} ioc" ;;
              warning|evidence) SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} warn" ;;
              advisory) SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} advisory" ;;
              info)
                  case "$key" in
                      patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs)
                          SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} ok" ;;
                  esac
                  ;;
          esac
          # Per-area unique key list (used by --verbose matrix expansion).
          # Append to a space-joined string; print_section_matrix dedupes via sort -u.
          if [[ "$sev" == "strong" || "$sev" == "warning" || "$sev" == "evidence" || "$sev" == "advisory" ]]; then
              SECTION_KEYS[$area]="${SECTION_KEYS[$area]:-} $key"
          fi
  ```

  Self-correction note: bash 4.1 `=~` uses libc POSIX ERE, which supports `(WARN|VULN|IOC)` alternation and `\[`/`\]` literals — confirmed safe per CLAUDE.md ("Bash regex (`=~`) vs awk regex" section). `local _tag=""` inside the loop is intentional: `local` is function-scoped (not loop-scoped) in bash, so the declaration is idempotent after the first iteration; the explicit `=""` re-initializes the tag on every pass so a high-tier tag from a prior SIGNALS row cannot bleed into a row whose severity has no tag mapping. The accumulated worst-wins state lives in `SECTION_VERDICT[$area]`, which IS function-external (declared as a top-level `declare -A`) and survives the loop.

- [ ] **Step 2: Add print_section_matrix() helper above print_verdict()**

  Location: `sessionscribe-ioc-scan.sh:5258` — immediately above the `print_verdict() {` line, insert:
  ```bash
  # Per-section verdict matrix - mitigate-style 7-row table rendered at the
  # top of print_verdict. Reads SECTION_VERDICT[] + SECTION_COUNTS[] populated
  # by aggregate_verdict(). Each row: <tag> <section_label> <count_summary>.
  # Areas with no signals render as [..] / "skipped".
  print_section_matrix() {
      (( QUIET )) && return
      local area label tag counts color
      local n_ioc n_warn n_adv n_ok detail
      for area in "${SECTION_ORDER[@]}"; do
          label="${SECTION_LABEL[$area]:-$area}"
          tag="${SECTION_VERDICT[$area]:-[..]}"
          counts="${SECTION_COUNTS[$area]:-}"
          # Tally by tag class.
          n_ioc=0; n_warn=0; n_adv=0; n_ok=0
          for tok in $counts; do
              case "$tok" in
                  ioc)      ((n_ioc++)) ;;
                  warn)     ((n_warn++)) ;;
                  advisory) ((n_adv++)) ;;
                  ok)       ((n_ok++)) ;;
              esac
          done
          # Build a compact detail string. Empty area -> "skipped".
          if [[ -z "$counts" ]]; then
              detail="skipped"
          else
              detail=""
              (( n_ioc  > 0 )) && detail+="${detail:+, }${n_ioc} ioc"
              (( n_warn > 0 )) && detail+="${detail:+, }${n_warn} warn"
              (( n_adv  > 0 )) && detail+="${detail:+, }${n_adv} advisory"
              (( n_ok   > 0 )) && detail+="${detail:+, }${n_ok} ok"
          fi
          # Color matches the tag.
          color="$DIM"
          case "$tag" in
              "[IOC]"|"[VULN]"|"[ERR]") color="$RED"    ;;
              "[WARN]")                  color="$YELLOW" ;;
              "[ADVISORY]")              color="$CYAN"   ;;
              "[OK]")                    color="$GREEN"  ;;
              "[..]")                    color="$DIM"    ;;
          esac
          printf '  %s%-10s%s %-10s %s%s%s\n' \
              "$color" "$tag" "$NC" "$label" "$DIM" "$detail" "$NC" >&2
          # --verbose: list unique IOC keys for this area, indented under the row.
          # Restores per-section signal vocabulary that the count-only form summarizes.
          if (( VERBOSE )) && [[ -n "${SECTION_KEYS[$area]:-}" ]]; then
              local k
              for k in $(printf '%s\n' ${SECTION_KEYS[$area]} | sort -u); do
                  printf '             %s%s%s\n' "$DIM" "$k" "$NC" >&2
              done
          fi
      done
      printf '\n' >&2
  }
  ```

  Self-correction note: the inner `for tok in $counts` relies on word-splitting; intentional (counts is a space-joined string). Under `set -u` an empty `$counts` is harmless because the for-loop simply iterates zero times. The leading `local tok` is omitted because bash 4.1 hoists loop variable `tok` to function scope — declaring it explicitly via `local` would shadow correctly but is redundant. (Confirm by grep: existing function bodies in this script use the same pattern; e.g., `for entry in "${ADVISORIES[@]:-}"` at line 5414 has no `local entry` either.)

  Correction-on-correction: Actually `local entry` IS declared at line 5413 (`local entry adv_id adv_key adv_note`) for `write_csv`. To match the project convention, declare `local tok` inside `print_section_matrix`. Updated block:
  ```bash
          local tok
          for tok in $counts; do
  ```

- [ ] **Step 3: Insert print_section_matrix call into print_verdict**

  Location: `sessionscribe-ioc-scan.sh:5260` — the line currently reads (after Phase 2 rewrite):
  ```bash
      hdr_section "summary" "code state + host posture"
  ```

  Immediately after this line, before line 5261 (`sayf '   strong-vuln signals : ...'`), insert:
  ```bash
      sayf '  host: %s   os: %s   cpanel: %s\n\n' \
          "$HOSTNAME_FQDN" "${OS_PRETTY:-unknown}" "${CPANEL_NORM:-unknown}"
      print_section_matrix
  ```

  Self-correction note: `OS_PRETTY` and `CPANEL_NORM` may be unset in snapshot/replay mode — the `${VAR:-unknown}` default protects under `set -u`. `HOSTNAME_FQDN` is set early (banner line ~791 reads it directly) so no fallback needed. The blank line in the format string visually separates the host context from the matrix.

- [ ] **Step 4: Verify parse + helper presence**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  ```

  ```bash
  grep -c '^print_section_matrix()' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -c '    print_section_matrix$' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -cE 'SECTION_VERDICT\[\$?area\]=' sessionscribe-ioc-scan.sh
  # expect: 1  (single worst-wins assign inside aggregate_verdict's SIGNALS[] loop;
  # this line fires once per matching iteration but appears once in source)
  ```

  ```bash
  bash sessionscribe-ioc-scan.sh --help 2>&1 >/dev/null && echo OK
  # expect: OK
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.1.0-pre4: per-section verdict matrix in print_verdict (+ --verbose expansion)

  Track SECTION_VERDICT[area] worst-wins over SIGNALS[] in
  aggregate_verdict, then render a 7-row matrix at the top of
  print_verdict (immediately after the `summary` banner, before the
  existing rollup counters). Each row: <tag> <section_label>
  <count_summary>. Areas with zero signals render as [..]/"skipped";
  good-info-only areas render as [OK]; mixed areas render the worst tag
  observed.

  Under --verbose, each matrix row is followed by the deduplicated list
  of IOC keys for that area, indented one level. This is the first
  consumer of the --verbose flag added in Phase 1 and establishes the
  pattern for future PRs that elide info: the elided form is the
  default; --verbose restores the v2.0.0 detail level.

  Operator-visible win: full host posture readable in 7 lines at the top
  of summary instead of scrolling to find which sections were hot.
  Matches mitigate.sh's print_summary_text idiom (sessionscribe-mitigate.sh
  lines 1748-1768).

  Verified: bash -n exits 0; print_section_matrix defined + called once;
  --help and --verbose --help both parse. Live verification deferred to
  Phase 5.
  EOF
  )"
  ```

---

### Phase 5: Version bump + live regression on host2

Bump `VERSION` from 2.0.0 to 2.1.0 and run a live regression on the cpanel_client tmux session (host2.alps-supplies.com — known-COMPROMISED, baseline 166 lines, 33 strong + 32 critical IOC). Confirm: (1) banner renders ASCII-clean, (2) all 7 sections show the new `== id == desc` form, (3) every signal row leads with a bracketed tag, (4) summary opens with the 7-row matrix and the existing rollup + verdict still render correctly below it, (5) no Unicode characters appear in stderr, (6) JSON envelope at `/var/cpanel/sessionscribe-ioc/<run_id>.json` is byte-comparable in schema (tool_version is the only difference).

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (bump `VERSION="2.0.0"` → `VERSION="2.1.0"` at line 106)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -c '^VERSION="2.1.0"' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^VERSION="2.0.0"' sessionscribe-ioc-scan.sh` returns 0; live run on host2 (no `--probe` flag) produces stderr output where: (a) `grep -c '^== ' /tmp/ioc.stderr.new` returns 7 (6 detection sections that fired — version, patterns, cpsrvd, iocscan, sessions, destruct — plus 1 summary banner; the `probe` section is gated on `(( PROBE ))` and does not emit a banner without `--probe`), (b) `grep -cE '\[(IOC|VULN|WARN|ADVISORY|OK|\.\.)\]' /tmp/ioc.stderr.new` returns at least 30 (matrix rows + signal rows), (c) `grep -c '━━━' /tmp/ioc.stderr.new` returns 0, (d) `grep -cE '[✗⚠⚐✓·]' /tmp/ioc.stderr.new` returns 0, (e) the section verdict matrix block (between `== summary ==` and the first `strong-vuln signals` line) contains 7 lines matching the pattern `^\s*\[[A-Z\.]+\]\s+\S+` (the matrix renders ALL 7 areas including `probe` as `[..] skipped` because `SECTION_ORDER` drives the matrix unconditionally), (f) the existing exit code remains `4` (COMPROMISED).
- **Test**: Live regression against host2 via `tmux send-keys -t cpanel_client`. Concrete probes (run AFTER deploying the script to /tmp/ioc-scan.sh on host2):
  1. `bash /tmp/ioc-scan.sh --since 14 2>/tmp/ioc.stderr.new; echo EXIT=$?` → expect `EXIT=4` (matches baseline).
  2. `wc -l /tmp/ioc.stderr.new` → expect a line count noticeably less than the 166-line baseline (target ≤120; goal ≤95). The line count is informational, not a Rule 9 assertion — the operator confirms the output is readable, not a numeric target.
  3. `grep -c '━━━' /tmp/ioc.stderr.new && grep -cE '[✗⚠⚐✓·]' /tmp/ioc.stderr.new` → expect both to be `0`.
  4. `diff <(jq -S 'del(.tool_version,.ts,.run_id)' /var/cpanel/sessionscribe-ioc/<old_run_id>.json) <(jq -S 'del(.tool_version,.ts,.run_id)' /var/cpanel/sessionscribe-ioc/<new_run_id>.json)` → expect EMPTY output (envelope schema unchanged across version bump; `tool_version`, `ts`, `run_id` legitimately differ and are stripped before comparison).
- **Edge cases**: (1) A CLEAN host should render the matrix with mostly `[OK]` and `[..]` tags, no `[IOC]`/`[VULN]` — find a CLEAN host in the lab (cpanel_client2 / cp1 / cp2 / cp3 may serve) and run there as a secondary regression; if no clean host is reachable, document the gap in the commit message and accept it as a known-incomplete verification. (2) A `--ioc-only` run skips the version/static/binary checks — the matrix should still render those rows as `[..] / skipped`. (3) A `--replay` run reads SIGNALS from envelope, not live; matrix must still render correctly.
- **Regression-case**: N/A — logging — final integration phase bumps `VERSION` and runs live regression. The cumulative change across phases 1-5 is stderr renderer-only; JSON/JSONL/CSV/envelope schema and exit-code semantics are unchanged across the v2.0.0→v2.1.0 bump (Phase 5 Step 5 explicitly diffs the envelope to confirm). Pure stderr-format change with no functional behavior delta. The live regression on host2 is the verification: COMPROMISED-tier host with rich IOC mix exercises every matrix tag class (`[IOC]`, `[VULN]`, `[ADVISORY]`, `[OK]`, `[..]`).

- [ ] **Step 1: Bump VERSION constant**

  Location: `sessionscribe-ioc-scan.sh:106` — the line currently reads:
  ```bash
  VERSION="2.0.0"
  ```

  Replace with:
  ```bash
  VERSION="2.1.0"
  ```

- [ ] **Step 2: Local parse + lint gate**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  ```

  ```bash
  shellcheck -S error sessionscribe-ioc-scan.sh
  # expect: zero output (no error-level findings)
  ```

  ```bash
  grep -c '^VERSION="2.1.0"' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

  ```bash
  grep -c '^VERSION="2.0.0"' sessionscribe-ioc-scan.sh
  # expect: 0
  ```

- [ ] **Step 3: Deploy to host2 via tmux + base64 chunks**

  Per `reference_lab_hosts.md` push pattern. Run from `/home/cpanel_ic5790/repo-sessionscribe/`:
  ```bash
  base64 -w 0 sessionscribe-ioc-scan.sh > /tmp/ioc-scan.b64
  rm -f /tmp/ioc-scan.x-*
  split -b 1500 /tmp/ioc-scan.b64 /tmp/ioc-scan.x-
  tmux send-keys -t cpanel_client 'rm -f /tmp/ioc-scan.b64 /tmp/ioc-scan.sh' Enter
  sleep 1
  for f in /tmp/ioc-scan.x-*; do
    c=$(cat "$f")
    tmux send-keys -t cpanel_client "printf '%s' '$c' >> /tmp/ioc-scan.b64" Enter
    sleep 0.12
  done
  tmux send-keys -t cpanel_client 'base64 -d /tmp/ioc-scan.b64 > /tmp/ioc-scan.sh && chmod +x /tmp/ioc-scan.sh && bash -n /tmp/ioc-scan.sh && echo PARSE_OK' Enter
  sleep 3
  tmux capture-pane -t cpanel_client -p -S -10 | grep -E '^(PARSE_OK|.*error|.*line [0-9]+:)'
  # expect: PARSE_OK
  ```

- [ ] **Step 4: Run live regression on host2 — default mode**

  ```bash
  tmux send-keys -t cpanel_client 'bash /tmp/ioc-scan.sh --since 14 2>/tmp/ioc.stderr.new >/tmp/ioc.stdout.new; echo === EXIT=$? === LINES=$(wc -l < /tmp/ioc.stderr.new)' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -S -10 | grep -E '^=== EXIT='
  # expect: a line of the form `=== EXIT=4 === LINES=<N>` where N is the new line count
  ```

  Then probe the output shape:
  ```bash
  tmux send-keys -t cpanel_client 'echo === SECTIONS === && grep -c "^== " /tmp/ioc.stderr.new; echo === TAGS === && grep -cE "\[(IOC|VULN|WARN|ADVISORY|OK|\.\.)\]" /tmp/ioc.stderr.new; echo === UNICODE === && grep -c "━━━" /tmp/ioc.stderr.new; grep -cE "[✗⚠⚐✓·]" /tmp/ioc.stderr.new' Enter
  sleep 2
  tmux capture-pane -t cpanel_client -p -S -20 | grep -E '^=== |^[0-9]+$'
  # expect:
  #   === SECTIONS ===
  #   7                    (6 detection sections fired without --probe + summary)
  #   === TAGS ===
  #   <large number, ≥30>  (matrix rows + signal rows)
  #   === UNICODE ===
  #   0
  #   0
  ```

- [ ] **Step 4b: Run live regression on host2 — --verbose mode**

  ```bash
  tmux send-keys -t cpanel_client 'bash /tmp/ioc-scan.sh --since 14 --verbose 2>/tmp/ioc.stderr.verbose >/tmp/ioc.stdout.verbose; echo === V_EXIT=$? === V_LINES=$(wc -l < /tmp/ioc.stderr.verbose)' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -S -10 | grep -E '^=== V_EXIT='
  # expect: a line of the form `=== V_EXIT=4 === V_LINES=<N>` where N is greater than
  # the default-mode line count (verbose adds the keys-per-area block under each matrix row)
  ```

  ```bash
  tmux send-keys -t cpanel_client 'awk "/^== summary ==/,/^ Code verdict:/" /tmp/ioc.stderr.verbose | grep -cE "^             ioc_"' Enter
  sleep 2
  tmux capture-pane -t cpanel_client -p -S -10 | tail -3
  # expect: a positive integer ≥ 5 — the indented IOC-key list under at least the
  # iocscan and destruct matrix rows on host2 (Pattern A/D/E/F keys + CRLF-chain key
  # + attacker-IP key; deduplication drops the 25 readme repeats to one line)
  ```

- [ ] **Step 5: Verify envelope schema parity (only tool_version/ts/run_id differ)**

  ```bash
  tmux send-keys -t cpanel_client 'OLD=$(ls -t /var/cpanel/sessionscribe-ioc/*.json | sed -n "2p"); NEW=$(ls -t /var/cpanel/sessionscribe-ioc/*.json | head -1); echo OLD=$OLD; echo NEW=$NEW; diff <(jq -S "del(.tool_version,.ts,.run_id,.signals,.advisories)" "$OLD") <(jq -S "del(.tool_version,.ts,.run_id,.signals,.advisories)" "$NEW") | head -40' Enter
  sleep 2
  tmux capture-pane -t cpanel_client -p -S -20
  # expect: OLD=<path1>, NEW=<path2>, then either zero diff lines or only counter-value drift
  # (counters may legitimately differ between runs even on the same host).
  ```

  Self-correction note: signals[] and advisories[] arrays differ legitimately between runs even on the same host (timing, log rotation, transient state), so they're stripped before diff. The remaining envelope keys (`tool`, `code_verdict`, `host_verdict`, `score`, `summary {strong, fixed, ...}`) should be either identical or differ only in numeric counts that fluctuate run-to-run. The diff is a smoke check for added/removed top-level keys, not a strict equality.

- [ ] **Step 6: Visual-diff confirmation (manual operator step)**

  Capture the new stderr for operator review:
  ```bash
  tmux send-keys -t cpanel_client 'cat /tmp/ioc.stderr.new' Enter
  sleep 2
  tmux capture-pane -t cpanel_client -p -S -200 > /tmp/ioc-scan-new-output.txt
  ```

  Operator confirms: (a) banner is ASCII-only, (b) every section header reads `== <id> == <desc>`, (c) every signal row leads with `[TAG]`, (d) summary opens with a 7-row matrix listing version/patterns/cpsrvd/iocscan/sessions/destruct/probe in that order, (e) the existing `Code verdict:` / `Host verdict:` / `reasons:` block is unchanged below the matrix, (f) the `!! HOST SHOWS EXPLOITATION ARTIFACTS !!` callout still fires (host2 is COMPROMISED).

  If any criterion fails: revert by `git reset --hard HEAD~5` (NOT `~4` — there are 5 commits in this PR including version bump), redeploy the prior CDN version to host2, and reopen the failing phase.

- [ ] **Step 7: Commit the version bump**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.1.0: output-primitive refactor (A+B+D)

  Renderer-only refactor — no JSON/JSONL/CSV/envelope schema changes.
  Three operator-facing wins:

    A. Section banners now `== id == desc` (was Unicode `━━━ <prose>`),
       ASCII-clean on EL6/CL6 SSH terminals, machine-readable section
       IDs (version, patterns, cpsrvd, iocscan, sessions, destruct,
       probe, summary, plus ioc-only + replay sub-flows).

    B. Signal severity renders as bracketed ASCII tags ([IOC] [WARN]
       [ADVISORY] [OK] [..] [VULN] [EVIDENCE] [ERR]) instead of Unicode
       glyphs (✗ ⚠ ⚐ ✓ ·). Action-oriented vocabulary matches mitigate.sh.

    D. Summary opens with a 7-row per-section verdict matrix
       (worst-wins from SIGNALS[]) — full host posture readable in 7
       lines instead of scrolling 160. Counts: ioc/warn/advisory/ok per
       section.

  Verification: live regression on host2.alps-supplies.com (cPanel
  110.0.103, COMPROMISED, 33 strong + 32 critical IOC) — exit code 4
  preserved, output reduced from 166 to <N> lines [fill in actual N from
  Phase 5 Step 4 capture], envelope schema unchanged across bump (only
  tool_version/ts/run_id differ).

  Verbosity contract: --verbose flag (Phase 1) is the escape hatch for
  any rendering choice in this PR or future PRs (C/E/G) that elides
  operator-relevant detail. Today it expands the matrix detail column
  to list deduplicated IOC keys per area; future PRs that collapse the
  WHERE/WHO/WHAT triplet (item G) will guard the collapse on
  (( VERBOSE == 0 )) so --verbose always restores the full form.

  Deferred to v2.2.0+: IOC_KEY_LABEL operator-friendly labels (item C),
  plain-text reasons line (item E), banner mode/run_id surface (item F),
  single-line WHERE/WHO/WHAT collapse (item G).
  EOF
  )"
  ```

- [ ] **Step 8: Push to main only after operator approval**

  ```bash
  git log --oneline origin/main..HEAD
  # expect: 5 commits (pre1, pre2, pre3, pre4, v2.1.0)
  ```

  Operator confirms ALL 5 commits look correct, then:
  ```bash
  git push origin main
  ```

  After push, validate fleet pull works through the curl one-liner with cache-buster:
  ```bash
  curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --help | head -1
  # expect: a line containing "sessionscribe-ioc-scan.sh v2.1.0"
  ```

  CDN republish is a separate operator action via `/root/bin/sync_local-remote` per `reference_cdn_deploy.md` — not part of this plan.

---
