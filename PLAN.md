# Implementation Plan: Merge sessionscribe-forensic.sh into sessionscribe-ioc-scan.sh, retain envelope/bundle replay

**Goal:** Collapse the two-script ioc-scan + forensic toolchain into a single unified script that runs detection inline (default) or detection+forensic (`--full`), AND can replay the forensic phases against a saved envelope JSON or captured bundle directory/tarball without re-running detection.

**Architecture:** ioc-scan absorbs every forensic function (helpers, phase_defense/offense/reconcile, render_kill_chain, phase_bundle, phase_upload). The two `SIGNALS[]` streams unify into one (forensic findings emit through ioc-scan's `emit()` under new areas: `defense`, `offense`, `reconcile`, `bundle`, `upload`, `summary`). Detection writes the envelope to disk first; forensic phases then read the envelope from disk via the existing `read_iocs_from_envelope()` code path — making the envelope-as-IPC contract a same-script invariant rather than a cross-script handshake. `--replay PATH` skips detection and feeds the supplied envelope into the same forensic flow. `sessionscribe-forensic.sh` is replaced with a v0.99.0 deprecation shim that delegates to `--replay`.

**Tech Stack:** bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 floor (CL6 EL6). No test framework — verification is `bash -n`, `shellcheck -S error`, and live runs on lab host (`cpanel_client` tmux session). Conventions documented in CLAUDE.md.

**Spec:** No spec file. Topic from operator + conversation context: "merge forensic into ioc-scan, retain envelope/bundle replay". My prior assessment: keep envelope as a write-then-read artifact, add `--full`/`--replay` toggles, ship a deprecation shim for the old forensic.sh URL.

**Phases:** 8

**Plan Version:** 3.0.6

---

## Conventions

**Bash floor (per CLAUDE.md):** No `mapfile`/`readarray`, no `printf -v arr[$i]`, no `${var^^}`/`${var,,}`, no `coproc`, no `${var: -1}`, no `declare -g`, no `local -n`, no `wait -n`. `case` inside `$()` uses leading-paren patterns. Empty arrays guarded with `(( ${#arr[@]} > 0 ))` before iteration under `set -u`. Newline required after `$(` before `{`.

**gawk 3.x floor (per CLAUDE.md):** No 3-arg `match(s, /re/, m)` — use 2-arg `match()` + `RSTART`/`RLENGTH` + `substr`/`split`. No `{n}` or `{n,m}` interval expressions in awk regexes — use explicit char-class repetition or `+`. `mktime()` requires `"YYYY MM DD HH MM SS"` exactly.

**Function-naming convention (this plan):** Forensic functions are inlined into ioc-scan **without renaming** when there is no collision. Where a name already exists in ioc-scan (`json_esc`, `usage`), the forensic version is dropped (the ioc-scan implementation is canonical and identical-or-superior). The forensic-side `emit_signal()` is rewritten as a thin wrapper around ioc-scan's `emit()` so call sites need no edit.

**Forensic-area signal vocabulary:** Forensic emits use the ioc-scan `emit()` API with these `area` values (new):
- `defense`  — defense-state findings (patch, cpsrvd restart, mitigate runs, modsec, csf)
- `offense`  — IOC events surfaced by reading the envelope (offense timeline source)
- `reconcile`— per-IOC PRE-DEFENSE / POST-DEFENSE / POST-PARTIAL classification
- `bundle`   — artifact-capture status (per-tarball captured/skipped)
- `upload`   — intake submission outcome
- `summary`  — final reconstruction counters + verdict

These join the existing `area` values: `logs`, `sessions`, `destruction`, `version`, `static`, `binary`, `chain` (the last becomes obsolete, see Phase 5).

**Boilerplate** — every script header continues to use the existing format:
```bash
#!/bin/bash
#
##
# sessionscribe-ioc-scan.sh v${VERSION}
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
```

**Commit message format** — per project convention (see `git log --oneline`):
```
<scope> v<version>: <one-line summary>

<body explaining the why, the surface area touched, and verification done>
```
Where `<scope>` is `ioc-scan`, `forensic`, `mitigate`, `docs`, etc.

**CRITICAL:** Never `git add -A` / `git add .` — add specific files. Never push to `main` without operator confirmation if the change is shipped via the curl one-liner (i.e., affects fleet behavior).

---

## File Map

### New Files

| File | Lines | Purpose | Test File |
|------|-------|---------|-----------|
| (none) | — | All work is consolidation into existing files | — |

### Modified Files

| File | Changes | Test File |
|------|---------|-----------|
| `sessionscribe-ioc-scan.sh` | Major: absorb forensic globals/helpers/phases (~2700 lines added); add `--full`/`--triage`/`--replay`/`--bundle`/`--no-bundle`/`--upload*`/`--bundle-dir`/`--max-bundle-mb`/`--extra-logs`/`--no-history` flags; replace `chain_forensic_dispatch`/`fetch_forensic_remote` with inline phase invocation; envelope written-then-read on every `--full`/`--replay` run | N/A — live verification on `cpanel_client` tmux session host (host2 / lab host A) per Phase 7 |
| `sessionscribe-forensic.sh` | Replaced with v0.99.0 deprecation shim (~30 lines) that prints a one-line deprecation notice and `exec`s `sessionscribe-ioc-scan.sh --replay "$SESSIONSCRIBE_IOC_JSON"` | Phase 7 verification (Step 7.5) |
| `STATE.md` | Bump ioc-scan to **2.0.0**; add merged-architecture note replacing the two-script architecture diagram; mark forensic v0.99.0 as deprecation shim | N/A (docs) |
| `CLAUDE.md` | Add `## Merged-script architecture` section noting `--full`/`--replay`/`--triage` modes and the envelope read-after-write contract | N/A (docs) |
| `README.md` | Replace operator-facing usage section: drop the two-script chain pattern; show single-script `--full`/`--replay` examples; deprecate forensic.sh URL with grace-period note | N/A (docs) |

### Deleted Files

| File | Reason |
|------|--------|
| (none) | `sessionscribe-forensic.sh` is rewritten, not deleted, to preserve the CDN URL for grace-period clients |

---

## Phase Dependencies

- Phase 1: none
- Phase 2: [1]
- Phase 3: [1, 2]
- Phase 4: [3]
- Phase 5: [4]
- Phase 6: [5]
- Phase 7: [6]
- Phase 8: [7]

All sequential — single script (`sessionscribe-ioc-scan.sh`) is the dominant write target across phases 1–5. Parallel-agent mode would only be possible if work were split across separate files; merging by definition is single-file.

---

## RC Contract Evidence

This plan does not introduce new caller-helper-fn pairs with explicit return-code contracts. Existing helpers (`emit`, `write_json`, `ledger_write`, `chain_forensic_dispatch`) retain their current return-code semantics (most return 0 unconditionally; `fetch_forensic_remote` returns 0/1 — and is being deleted in Phase 5, not extended). Phase 5 deletes `chain_forensic_dispatch` and `fetch_forensic_remote`, which removes contracts rather than adding them.

---

### Phase 1: Scaffolding — forensic globals, shared-constant dedup, color/glyph unification

Stage all top-of-file additions: forensic state arrays, forensic-only constants, dedupe the 5 cross-script duplicate constants, and inline the forensic glyph table into ioc-scan. No phase functions yet — this is pure data structure prep.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (add forensic globals + Pattern G constants; introduce GLYPH_* table after existing color block)

- **Mode**: serial-context
- **Accept**: `bash -n sessionscribe-ioc-scan.sh` exits 0; `grep -c '^DEFENSE_EVENTS=()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^OFFENSE_EVENTS=()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^IOC_PRIMITIVES=()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^IOC_ANNOTATIONS=()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^PATTERN_G_BAD_KEY_LABELS=' sessionscribe-ioc-scan.sh` returns 1; `grep -c "^GLYPH_BOX_TL='" sessionscribe-ioc-scan.sh` returns 2 (UTF-8 + ASCII branches)
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect `OK`; `awk 'BEGIN{ if (match("test", /[a-z][a-z][a-z][a-z]/)) print "interval-OK"; else print "BROKEN" }'` → expect `interval-OK` (smoke that gawk-3.x compat regex idioms still work after edits)
- **Edge cases**: none from spec (no spec)
- **Regression-case**: N/A — refactor — Phase 1 adds globals only; no behavior change observable to operators yet

- [ ] **Step 1: Add forensic state-array globals immediately after RUN_ID assignment**

  Location: `sessionscribe-ioc-scan.sh` line 508 (immediately after `RUN_ID="${SESSIONSCRIBE_RUN_ID:-${TS_EPOCH}-$$}"`)

  Insert this block:
  ```bash

  ###############################################################################
  # Forensic state (post-merge v2.0.0)
  ###############################################################################
  # When the operator runs --full or --replay, the forensic phases populate
  # these arrays. They stay empty in default --triage mode. All forensic
  # findings flow through emit() into the unified SIGNALS[] stream.
  DEFENSE_EVENTS=()       # "epoch|kind|note" strings, sorted at render time
  OFFENSE_EVENTS=()       # "epoch|pattern|key|note|defenses_required" strings
  IOC_PRIMITIVES=()       # parallel-indexed with OFFENSE_EVENTS; TSV row per IOC
  IOC_ANNOTATIONS=()      # parallel-indexed; renderer-side annotations (Pattern E dim)
  RECONCILED_EVENTS=()    # "epoch|pattern|key|verdict|delta|note" strings
  N_PRE=0                 # PRE-DEFENSE event count (set in phase_reconcile)
  N_POST=0                # POST-DEFENSE event count (set in phase_reconcile)

  # Defense extraction outputs (set by phase_defense, read by phase_reconcile +
  # write_kill_chain_primitives). Empty = "defense state unknown".
  DEF_PATCH_TIME=""       # cpanel patch landed (Load.pm mtime if patched)
  DEF_CPSRVD_RESTART=""   # cpsrvd PID start time (epoch)
  DEF_MITIGATE_FIRST=""   # earliest sessionscribe-mitigate.sh run dir
  DEF_MITIGATE_LAST=""    # most recent sessionscribe-mitigate.sh run dir
  DEF_MODSEC_TIME=""      # mtime of modsec2.user.conf if it contains 1500030
  PATCH_STATE="UNKNOWN"   # PATCHED|UNPATCHED|UNPATCHABLE|UNKNOWN

  # Bundle output paths (set by phase_bundle, read by phase_upload).
  BUNDLE_BDIR=""          # absolute path to /root/.ic5790-forensic/<TS>-<RUN_ID>
  BUNDLE_TGZ=""           # tarball path (set when phase_upload prepares submission)
  ```

  Self-correction note: Empty arrays under `set -u` crash on iteration in bash 4.1. Every iterator over these arrays MUST be guarded with `(( ${#arr[@]} > 0 ))`. Confirmed precedent at 9 sites in the existing ioc-scan.

- [ ] **Step 2: Add Pattern G constants alongside existing PATTERN_* block**

  Location: After PATTERN_I_PROFILED at line 236, before line 246 (where SSH_KNOWN_GOOD_RE is currently the next constant).

  Insert before SSH_KNOWN_GOOD_RE:
  ```bash

  # Pattern G - SSH key persistence anchors. Comments matching these literal
  # IP labels are attacker-planted jumphost-mimic keys (per IC-5790 dossier).
  PATTERN_G_BAD_KEY_LABELS=(
      "209.59.141.49"
      "50.28.104.57"
  )
  # Forged mtime stamp the attackers used (`touch -d "2019-12-13 12:59:16"`).
  # date(1) interprets in local TZ so the stored epoch depends on host offset;
  # forensic pattern_g_deep_checks compares the wall-clock string under both
  # UTC and localtime to catch either interpretation.
  PATTERN_G_FORGED_MTIME_WALL="2019-12-13 12:59:16"
  ```

- [ ] **Step 3: Add forensic-only top-level constants near other DEFAULT_* knobs**

  Location: search for `LEDGER_DIR_DEFAULT=` in `sessionscribe-ioc-scan.sh` and insert below it (use the function-name reference rather than line number — earlier insertions will have shifted line numbers).

  ```bash

  # Forensic phase defaults (post-merge v2.0.0 — used when --full or --replay
  # is supplied; no-op in default --triage mode).
  DEFAULT_BUNDLE_DIR_ROOT="/root/.ic5790-forensic"
  DEFAULT_MAX_BUNDLE_MB=2048      # per-tarball cap (NOT bundle-wide)
  DEFAULT_FORENSIC_SINCE_DAYS=90  # forensic-mode default --since when unspecified
  INTAKE_DEFAULT_URL="https://intake.rfxn.com/"
  # Convenience token for ad-hoc intake submissions; server enforces 1000-PUT
  # cap per token. For fleet use, supply --upload-token or RFXN_INTAKE_TOKEN.
  INTAKE_DEFAULT_TOKEN="cd88c9970c3176997c9671a2566fadc84904be0b73edd5e3b071452eade796e1"

  # cpanel build cutoff list (was forensic-side PATCHED_BUILDS_CPANEL).
  # Mirrors the list ioc-scan check_version already uses; declared here so
  # phase_defense can reuse one source of truth.
  PATCH_CANARY_FILE="/usr/local/cpanel/Cpanel/Session/Load.pm"
  MITIGATE_BACKUP_ROOT="/var/cpanel/sessionscribe-mitigation"
  MODSEC_USER_CONFS=(
      "/etc/apache2/conf.d/modsec/modsec2.user.conf"   # EA4 (cPanel default)
      "/etc/httpd/conf.d/modsec/modsec2.user.conf"     # non-EA4 fallback
      "/etc/httpd/conf.d/modsec2.user.conf"            # legacy non-EA4
  )
  MODSEC_USER_CONF="${MODSEC_USER_CONFS[0]}"
  CPSRVD_PORTS=(2082 2083 2086 2087 2095 2096)
  ```

  Self-correction note: `PATCHED_BUILDS_CPANEL=(...)` already exists in ioc-scan via `check_version()` — it's stored in a local. Phase 2 (helper consolidation) will resolve it; for now we only add the *new* constants forensic needs. Don't shadow ioc-scan's existing list.

- [ ] **Step 4: Add forensic glyph table after existing color block**

  Location: search for `RED=$'\033[0;31m'` in ioc-scan to find the color block; insert the GLYPH_* block immediately after the closing `fi` of the color conditional.

  ```bash

  # Glyph table (post-merge v2.0.0) — Unicode for UTF-8 TTYs, ASCII fallback
  # otherwise. Forensic renderers and the kill-chain markdown depend on these.
  if [[ -t 2 ]] && [[ "${LC_ALL:-}${LANG:-}${LC_CTYPE:-}" =~ [Uu][Tt][Ff]-?8 ]]; then
      GLYPH_BOX_TL='┌'; GLYPH_BOX_TR='┐'; GLYPH_BOX_BL='└'; GLYPH_BOX_BR='┘'
      GLYPH_BOX_H='─'; GLYPH_BOX_V='│'
      GLYPH_OFFENSE='⚡'; GLYPH_DEFENSE='✓'; GLYPH_ARROW='↳'
      GLYPH_OK='✓';     GLYPH_BAD='✗';     GLYPH_WARN='⚠'
      GLYPH_ELLIPSIS='…'; GLYPH_TIMES='×'
  else
      GLYPH_BOX_TL='+'; GLYPH_BOX_TR='+'; GLYPH_BOX_BL='+'; GLYPH_BOX_BR='+'
      GLYPH_BOX_H='-'; GLYPH_BOX_V='|'
      GLYPH_OFFENSE='!'; GLYPH_DEFENSE='+'; GLYPH_ARROW='->'
      GLYPH_OK='+';     GLYPH_BAD='x';     GLYPH_WARN='!'
      GLYPH_ELLIPSIS='...'; GLYPH_TIMES='x'
  fi
  ```

  Self-correction note: Both branches must execute (set ALL variables) so the renderer never references an unset variable under `set -u`. The forensic source is the canonical reference for these values — copy verbatim.

- [ ] **Step 5: Add C_RED/C_GRN/C_YEL color aliases**

  Forensic uses `C_RED`/`C_GRN`/`C_YEL`/`C_BLD`/`C_DIM`/`C_NC` while ioc-scan uses `RED`/`GREEN`/`YELLOW`/`BOLD`/`DIM`/`NC`. To avoid editing ~150 forensic call sites in Phase 3, alias them at top-of-color-block.

  Location: end of the color conditional (after the GLYPH block from Step 4).

  ```bash

  # Forensic-side color aliases (post-merge v2.0.0). The renderers in
  # phase_defense/render_kill_chain/etc. use the C_* names. Aliasing here
  # avoids editing every call site at the cost of one extra layer of names.
  C_RED="$RED";  C_GRN="$GREEN"; C_YEL="$YELLOW"; C_CYN="$CYAN"
  C_BLD="$BOLD"; C_DIM="$DIM";   C_NC="$NC"
  ```

  Note: forensic also uses `C_CYN` (cyan). Verify ioc-scan defines `CYAN` — if not, add `CYAN=$'\033[0;36m'` (with-color branch) and `CYAN=''` (no-color branch) before the alias line. Read ioc-scan around the color block first; only add `CYAN` if missing.

- [ ] **Step 6: Verify**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK
  grep -c '^DEFENSE_EVENTS=()' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -c '^OFFENSE_EVENTS=()' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -c '^PATTERN_G_BAD_KEY_LABELS=' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -c "^GLYPH_BOX_TL='" sessionscribe-ioc-scan.sh
  # expect: 2
  grep -cE '^C_(RED|GRN|YEL|CYN|BLD|DIM|NC)=' sessionscribe-ioc-scan.sh
  # expect: 14 (7 names × 2 branches — CYN required by render_offense_row)
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.0.0-pre1: scaffold forensic merge — globals + glyph + color aliases

  Phase 1 of 8 in PLAN.md "Merge sessionscribe-forensic.sh into
  sessionscribe-ioc-scan.sh, retain envelope/bundle replay".

  Adds forensic state arrays (DEFENSE_EVENTS, OFFENSE_EVENTS,
  IOC_PRIMITIVES, IOC_ANNOTATIONS, RECONCILED_EVENTS), defense-extraction
  output globals (DEF_PATCH_TIME, DEF_CPSRVD_RESTART, DEF_MITIGATE_*,
  DEF_MODSEC_TIME, PATCH_STATE), bundle paths (BUNDLE_BDIR, BUNDLE_TGZ),
  Pattern G constants (PATTERN_G_BAD_KEY_LABELS, _FORGED_MTIME_WALL),
  forensic-default knobs (DEFAULT_BUNDLE_DIR_ROOT, DEFAULT_MAX_BUNDLE_MB,
  INTAKE_DEFAULT_URL/TOKEN), the GLYPH_* table for renderers, and C_*
  color aliases so forensic renderers can be inlined without editing
  every call site.

  Behavior unchanged — these are unused declarations until Phase 2
  inlines the helpers and Phase 3 inlines the phase functions.
  EOF
  )"
  ```

---

### Phase 2: Inline forensic helpers (json field readers, ts converters, envelope reader)

Bring all forensic helper functions into ioc-scan. Drop forensic's `json_esc()` (ioc-scan has an identical implementation; verify). Bring `json_str_field`, `json_num_field`, `to_epoch`, `extract_log_ts`, `mtime_of`, `cat_log`, `epoch_to_iso`, `decode_pipe_tail`, `have_cmd`, `envelope_root_field`, `read_envelope_meta`, `ioc_signal_epoch`, `ioc_key_to_pattern`, `ioc_primitive_row`, `read_iocs_from_envelope`. Helpers are placed in a new `### Forensic helpers (post-merge v2.0.0)` section AFTER the existing helper block (`emit`, `print_signal_human`) so dependency order remains forward.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (insert ~340 lines of helpers + ENV_* state globals)

- **Mode**: serial-agent
- **Accept**: `bash -n` clean; helpers callable in dry-run (`bash -c 'source <(awk "/^json_str_field/,/^}/" sessionscribe-ioc-scan.sh); json_str_field "{\"x\":\"hello\"}" x'` returns `hello`); zero name collisions (`grep -cE '^(json_esc|json_str_field|json_num_field|to_epoch|extract_log_ts|mtime_of|epoch_to_iso|decode_pipe_tail|envelope_root_field|read_envelope_meta|ioc_signal_epoch|ioc_key_to_pattern|ioc_primitive_row|read_iocs_from_envelope)\(\)' sessionscribe-ioc-scan.sh` returns exactly 14 — one per function)
- **Test**: see Step 5 inline source-and-call probe; exit 0
- **Edge cases**: `read_iocs_from_envelope` must tolerate `SESSIONSCRIBE_IOC_JSON` being unset (returns 1 with a non-fatal `say_warn`) — preserve forensic line 1031–1035 behavior verbatim
- **Regression-case**: N/A — refactor — helpers are added but not yet called by main flow; observable behavior unchanged

- [ ] **Step 1: Compare json_esc implementations and pick canonical**

  Read both:
  ```bash
  awk '/^json_esc\(\)/,/^}/' sessionscribe-ioc-scan.sh
  awk '/^json_esc\(\)/,/^}/' sessionscribe-forensic.sh
  ```

  Expected: ioc-scan implementation handles all the cases forensic's does (or strict superset). If divergent, document the diff in this step's notes and choose the one with broader escape coverage. **Do not blindly assume identical** — bash JSON escaping has edge cases around `\b`, `\f`, `\t`, `\n`, `\r`, `"`, `\`, control chars (`\u00xx`).

  Decision recorded in this step's commit message.

- [ ] **Step 2: Add ENV_* envelope-mirror globals near other forensic state**

  Location: after the forensic state arrays added in Phase 1 Step 1 (search for `IOC_ANNOTATIONS=()`).

  ```bash

  # ENV_* globals populated by read_envelope_meta() when --full or --replay
  # is in effect. They mirror the envelope's root-level fields so the kill-
  # chain renderer can show host_verdict/score/tool_version without re-
  # parsing the envelope on every render call.
  ENV_HOST_VERDICT=""
  ENV_CODE_VERDICT=""
  ENV_SCORE=""
  ENV_IOC_TOOL_VERSION=""
  ```

- [ ] **Step 3: Insert the helpers block**

  Location: search for the end of the `print_signal_human()` function in ioc-scan (line ~745 currently) and insert a new section header + the helpers block IMMEDIATELY before `local_init()`.

  Block contents (verbatim from forensic, ordered: short helpers first, dependents after):

  ```bash

  ###############################################################################
  # Forensic helpers (post-merge v2.0.0) — used by phase_defense / phase_offense
  # / phase_reconcile / render_kill_chain / phase_bundle / phase_upload.
  # No-op in default --triage mode (the phase functions aren't called).
  ###############################################################################

  have_cmd() { command -v "$1" >/dev/null 2>&1; }

  # Verbatim from forensic line 507-527. Handles cpanel MM/DD/YYYY:HH:MM:SS
  # bracket form AND apache CLF DD/Mon/YYYY:HH:MM:SS bracket form. Returns
  # epoch seconds (or empty string on failure).
  to_epoch() {
      local s="$1"
      [[ -z "$s" ]] && { echo ""; return; }
      s="${s#[}"; s="${s%]}"
      if [[ "$s" =~ ^[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}: ]]; then
          s=$(echo "$s" | sed -E 's|^([0-9]{1,2})/([A-Za-z]{3})/([0-9]{4}):([0-9:]+)([[:space:]]+(.*))?$|\1 \2 \3 \4\5|')
          date -u -d "$s" +%s 2>/dev/null
          return
      fi
      if [[ "$s" =~ ^([0-9]{2})/([0-9]{2})/([0-9]{4}):([0-9:]+)([[:space:]]+([+-][0-9]{4}))?$ ]]; then
          local mm="${BASH_REMATCH[1]}" dd="${BASH_REMATCH[2]}" yyyy="${BASH_REMATCH[3]}"
          local hms="${BASH_REMATCH[4]}" tz="${BASH_REMATCH[6]:-+0000}"
          date -u -d "${yyyy}-${mm}-${dd} ${hms} ${tz}" +%s 2>/dev/null
          return
      fi
      date -u -d "$s" +%s 2>/dev/null
  }

  extract_log_ts() { ... }            # forensic line 529-536 verbatim
  mtime_of() { ... }                  # forensic line 537-546 verbatim
  cat_log() { ... }                   # forensic line 547-557 verbatim
  epoch_to_iso() { ... }              # forensic line 558-584 verbatim
  decode_pipe_tail() { ... }          # forensic line 585-612 verbatim

  json_str_field() { ... }            # forensic line 898-909 verbatim
  json_num_field() { ... }            # forensic line 910-922 verbatim

  ioc_key_to_pattern() { ... }        # forensic line 923-939 verbatim
  ioc_signal_epoch() { ... }          # forensic line 944-958 verbatim
  envelope_root_field() { ... }       # forensic line 966-977 verbatim

  # Modified from forensic line 984-1003: takes envelope path as $1 with
  # $SESSIONSCRIBE_IOC_JSON as fallback, so --replay can pass any envelope
  # path without exporting the env var. Body otherwise verbatim.
  read_envelope_meta() {
      local env="${1:-${SESSIONSCRIBE_IOC_JSON:-}}"
      [[ -n "$env" && -f "$env" ]] || return 0
      ENV_HOST_VERDICT=$(envelope_root_field "$env" host_verdict)
      ENV_CODE_VERDICT=$(envelope_root_field "$env" code_verdict)
      ENV_SCORE=$(envelope_root_field "$env" score)
      ENV_IOC_TOOL_VERSION=$(envelope_root_field "$env" tool_version)
      ENV_IOC_RUN_ID=$(envelope_root_field "$env" run_id)
      ENV_IOC_TS=$(envelope_root_field "$env" ts)
      local summary
      summary=$(grep -E '^[[:space:]]+"summary":' "$env" 2>/dev/null | head -1)
      if [[ -n "$summary" ]]; then
          ENV_STRONG=$(echo "$summary"        | grep -oE '"strong":[0-9]+'        | cut -d: -f2)
          ENV_FIXED=$(echo "$summary"         | grep -oE '"fixed":[0-9]+'         | cut -d: -f2)
          ENV_INCONCLUSIVE=$(echo "$summary"  | grep -oE '"inconclusive":[0-9]+'  | cut -d: -f2)
          ENV_IOC_CRITICAL=$(echo "$summary"  | grep -oE '"ioc_critical":[0-9]+'  | cut -d: -f2)
          ENV_IOC_REVIEW=$(echo "$summary"    | grep -oE '"ioc_review":[0-9]+'    | cut -d: -f2)
      fi
  }

  ioc_primitive_row() { ... }         # forensic line 1006-1028 verbatim

  # Modified from forensic line 1029-1103: takes envelope path as $1 with
  # $SESSIONSCRIBE_IOC_JSON as fallback. Otherwise verbatim. Reads the
  # envelope from disk, populates OFFENSE_EVENTS[], IOC_PRIMITIVES[],
  # IOC_ANNOTATIONS[]. Returns 1 with a non-fatal say_warn if envelope is
  # absent — preserves forensic's standalone-mode tolerance.
  read_iocs_from_envelope() {
      local env="${1:-${SESSIONSCRIBE_IOC_JSON:-}}"
      if [[ -z "$env" ]]; then
          say_warn "no envelope path - run via --full or --replay PATH"
          emit_signal offense warn no_envelope "envelope unavailable; deep checks only"
          return 1
      fi
      if [[ ! -f "$env" ]]; then
          say_warn "envelope path missing: $env"
          emit_signal offense warn envelope_missing "envelope path unreadable" path "$env"
          return 1
      fi

      read_envelope_meta "$env"

      local line area severity key note ts pattern n_added=0
      local p_ip p_path p_log p_count p_h2xx p_status p_line p_row p_anno
      while IFS= read -r line; do
          [[ "$line" =~ ^[[:space:]]*\{\"host\": ]] || continue
          area=$(json_str_field "$line" area)
          severity=$(json_str_field "$line" severity)
          case "$area" in
              (logs|sessions|destruction) ;;
              (*) continue ;;
          esac
          case "$severity" in
              (strong|warning) ;;
              (*) continue ;;
          esac
          key=$(json_str_field "$line" key)
          case "$key" in
              (ioc_sample|ioc_attacker_ip_sample|session_shape_sample) continue ;;
          esac
          note=$(json_str_field "$line" note)
          ts=$(ioc_signal_epoch "$line")
          pattern=$(ioc_key_to_pattern "$key")
          p_ip=$(json_str_field "$line" ip)
          [[ -z "$p_ip" ]] && p_ip=$(json_str_field "$line" src_ip)
          p_path=$(json_str_field "$line" path)
          [[ -z "$p_path" ]] && p_path=$(json_str_field "$line" file)
          p_log=$(json_str_field "$line" log_file)
          p_count=$(json_num_field "$line" count)
          p_h2xx=$(json_num_field "$line" hits_2xx)
          p_status=$(json_str_field "$line" status)
          p_line=$(json_str_field "$line" line)
          p_row=$(ioc_primitive_row "$area" "$p_ip" "$p_path" "$p_log" "$p_count" "$p_h2xx" "$p_status" "$p_line")
          p_anno=""
          if [[ "$key" == "ioc_pattern_e_websocket_shell_hits" ]]; then
              p_anno=$(json_str_field "$line" dimensions)
          fi
          OFFENSE_EVENTS+=("$ts|$pattern|$key|${note:-$key}|patch,modsec")
          IOC_PRIMITIVES+=("$p_row")
          IOC_ANNOTATIONS+=("$p_anno")
          n_added=$((n_added+1))
          emit_signal offense fail "$key" "${note:-$key}" \
              epoch "$ts" pattern "$pattern" envelope "$(basename "$env")"
      done < "$env"

      say_info "envelope: imported $n_added IOC(s) from $(basename "$env")"
      return 0
  }
  ```

  For each function: `awk '/^<fnname>\(\)/,/^}/' sessionscribe-forensic.sh` to extract verbatim, then paste. Do NOT modify bodies during this step except `read_envelope_meta` per the inline note.

  Self-correction note: `read_iocs_from_envelope` calls `say_warn` and `emit_signal`. Both are forensic-side helpers. `say_warn` is part of the say_* family that gets inlined in Phase 3. `emit_signal` becomes a wrapper around `emit()` in Phase 3. Phase 2 ends with `read_iocs_from_envelope` defined but not yet callable — that's intentional, it gets wired up in Phase 3.

  Self-correction note: forensic's `epoch_to_iso` uses `date -u -d @"$1"`. ioc-scan does not call this anywhere yet, so no collision risk; keep verbatim.

- [ ] **Step 4: Drop forensic's json_esc since ioc-scan already has one**

  After Step 1 confirms ioc-scan's `json_esc` is canonical: do NOT inline forensic's `json_esc`. The function name already exists in ioc-scan and the renderer/emit helpers will resolve to ioc-scan's implementation.

  If Step 1 found divergence: replace ioc-scan's `json_esc` body with the merged superset (covering both implementations' escape cases) and keep the function declaration in its original location.

- [ ] **Step 5: Verify helper definitions are syntactically callable**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK

  # Source ONLY the helpers (not the main flow) and probe one
  bash -c '
    set -u
    SIGNALS=()
    json_esc() { printf "%s" "$1"; }   # stub for the helpers that depend on it
    source <(awk "/^json_str_field/,/^}/" sessionscribe-ioc-scan.sh)
    out=$(json_str_field "{\"foo\":\"bar\",\"x\":42}" foo)
    [[ "$out" == "bar" ]] && echo helpers-OK || echo helpers-BROKEN
  '
  # expect: helpers-OK

  grep -cE '^(json_str_field|json_num_field|to_epoch|extract_log_ts|mtime_of|cat_log|epoch_to_iso|decode_pipe_tail|have_cmd|envelope_root_field|read_envelope_meta|ioc_signal_epoch|ioc_key_to_pattern|ioc_primitive_row|read_iocs_from_envelope)\(\)' sessionscribe-ioc-scan.sh
  # expect: 15 (one definition per function)
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.0.0-pre2: inline forensic helpers (json field readers, ts converters)

  Phase 2 of 8 — adds ENV_* envelope-mirror globals and the forensic helper
  block (have_cmd, to_epoch, extract_log_ts, mtime_of, cat_log, epoch_to_iso,
  decode_pipe_tail, json_str_field, json_num_field, ioc_key_to_pattern,
  ioc_signal_epoch, envelope_root_field, read_envelope_meta,
  ioc_primitive_row, read_iocs_from_envelope) to ioc-scan.

  Bodies are verbatim from forensic except read_envelope_meta which now
  takes an envelope-path arg with the env var as fallback (so --replay can
  pass an arbitrary envelope path without setting SESSIONSCRIBE_IOC_JSON).

  json_esc kept from ioc-scan side after diff verification — both
  implementations cover the same escape set; ioc-scan version retained as
  canonical (Step 1 of this phase documents the comparison).

  Helpers are defined but not yet called — Phase 3 inlines the phase
  functions and wires them into the main flow.
  EOF
  )"
  ```

---

### Phase 3: Inline forensic phase functions + renderer + bundle pipeline

Bring `phase_defense`, `phase_offense` (and its dependent `pattern_g_deep_checks`, `suspect_ip_correlation`), `phase_reconcile`, `render_kill_chain` (and its renderers `render_offense_row`, `render_defense_row`, `aggregate_attacker_ips`, `fmt_offense_detail`, `ansi_strip`, `fmt_delta_human`), `write_kill_chain_primitives`, `phase_bundle` (and its dependents `estimate_size_mb`, `collect_recent`, `bundle_tar`), `phase_upload`, plus the say_* output primitives (`say`, `say_pass`, `say_info`, `say_warn`, `say_fail`, `say_def`, `say_def_miss`, `say_ioc`, `hdr`). Rewrite forensic's `emit_signal()` as a thin wrapper around ioc-scan's `emit()` so call sites need no edit.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (insert ~2200 lines: phase functions + renderer + bundle pipeline + say_* primitives)

- **Mode**: serial-agent
- **Accept**: `bash -n` clean; `grep -c '^phase_defense()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^phase_offense()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^phase_reconcile()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^render_kill_chain()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^phase_bundle()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^phase_upload()' sessionscribe-ioc-scan.sh` returns 1; `grep -c '^emit_signal()' sessionscribe-ioc-scan.sh` returns 1 (the wrapper); zero unbound-variable failures in a dry-run probe (Step 6)
- **Test**: Step 6 dry-run probe; exit 0
- **Edge cases**: Forensic's `emit_signal` adopts ioc-scan's `emit` semantics — verify the area-name remapping table in Step 4 covers every emit_signal call site
- **Regression-case**: N/A — refactor — phase functions defined but not yet called from main flow; observable behavior still unchanged

- [ ] **Step 1: Insert say_* output primitives + hdr() before the helpers block**

  Location: insert immediately after `print_signal_human()` (line ~744) and BEFORE the forensic helpers block from Phase 2 (so say_* is available to the helpers that call it).

  ```bash

  # Forensic-side output primitives (post-merge v2.0.0). Mirror ioc-scan's
  # `say` style but with status-prefixed [OK]/[INFO]/[WARN]/etc. tags so the
  # forensic phases stay visually distinct from the detection sections.
  hdr()           { (( QUIET )) || printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$1" "$C_NC" "$C_DIM" "$2" "$C_NC" >&2; }
  say_pass()      { (( QUIET )) || printf '  %s[OK]%s %s\n'        "$C_GRN" "$C_NC" "$*" >&2; }
  say_info()      { (( QUIET )) || printf '  %s[INFO]%s %s\n'      "$C_DIM" "$C_NC" "$*" >&2; }
  say_warn()      { (( QUIET )) || printf '  %s[WARN]%s %s\n'      "$C_YEL" "$C_NC" "$*" >&2; }
  say_fail()      { (( QUIET )) || printf '  %s[FAIL]%s %s\n'      "$C_RED" "$C_NC" "$*" >&2; }
  say_def()       { (( QUIET )) || printf '  %s[DEF-OK]%s %s\n'    "$C_GRN" "$C_NC" "$*" >&2; }
  say_def_miss()  { (( QUIET )) || printf '  %s[DEF-MISS]%s %s\n'  "$C_YEL" "$C_NC" "$*" >&2; }
  say_ioc()       { (( QUIET )) || printf '  %s[IOC]%s %s\n'       "$C_RED" "$C_NC" "$*" >&2; }
  ```

- [ ] **Step 2: Insert emit_signal() wrapper around emit()**

  Location: after the say_* block (Step 1), still before the helpers block.

  ```bash

  # Forensic-side signal emitter (post-merge v2.0.0). Wraps emit() with the
  # forensic call-site signature. Severity vocabulary maps:
  #   forensic    -> ioc-scan emit
  #   pass         -> info     (weight 0)
  #   info         -> info     (weight 0)
  #   warn         -> warning  (weight 4)
  #   fail         -> strong   (weight 10)
  # Area is passed through unchanged. Forensic areas (defense/offense/
  # reconcile/bundle/upload/summary) are all valid emit() areas (they're
  # treated as opaque labels by emit; the envelope writer just records them).
  #
  # Note on id == key: ioc-scan's emit() takes both `id` (positional 2) and
  # `key` (positional 4). Detection-side call sites use them distinctly
  # (id = stable signal identity; key = aggregate_verdict reasons-set
  # member). Forensic signals don't have a separate id concept — both
  # positions get the same value. This intentional redundancy keeps the
  # emit() signature stable across detection + forensic call paths.
  emit_signal() {
      local area="$1" sev="$2" key="$3" note="$4"
      shift 4
      local ioc_sev="info" weight=0
      case "$sev" in
          (pass|info)  ioc_sev="info";    weight=0  ;;
          (warn)       ioc_sev="warning"; weight=4  ;;
          (fail)       ioc_sev="strong";  weight=10 ;;
          (*)          ioc_sev="info";    weight=0  ;;
      esac
      emit "$area" "$key" "$ioc_sev" "$key" "$weight" "note" "$note" "$@"
  }
  ```

  Self-correction note: the case statement uses leading-paren patterns `(pass|info)` for bash <4.4 parser safety inside `$(...)` — though this case is at top level, the convention stays for consistency. Confirmed standard across the codebase.

  Self-correction note: weight=4 for `warn` matches the `ioc_pattern_d_evidence_destroyed` precedent (weight 5 in the existing v1.8.x emit). Within the noise. Choosing 4 to keep warning-tier signals from accidentally tipping `aggregate_verdict` into COMPROMISED.

- [ ] **Step 3: Insert phase_defense + phase_offense + dependents + phase_reconcile**

  Location: after the helpers block (the read_iocs_from_envelope inline from Phase 2) and before `local_init()`.

  Functions to extract verbatim from forensic (in this order — caller-before-callee is fine since bash hoists function names):
  - `pattern_g_deep_checks()`           — forensic line 1104-1218
  - `suspect_ip_correlation()`          — forensic line 1219-1255
  - `phase_defense()`                   — forensic line 613-897
  - `phase_offense()`                   — forensic line 1256-1269
  - `phase_reconcile()`                 — forensic line 1270-1482

  Extraction recipe per function:
  ```bash
  awk '/^<fnname>\(\)/,/^}$/' sessionscribe-forensic.sh
  ```

  Verify the closing `}` is at column 0 (not inside a heredoc or nested function). Confirmed by reading the source — all forensic functions close at column 0.

  Section comment to insert above the block:
  ```bash

  ###############################################################################
  # Forensic phases — defense / offense / reconcile (post-merge v2.0.0).
  # Run only when --full or --replay is set. Inputs: envelope (read from disk
  # via read_iocs_from_envelope). Outputs: DEFENSE_EVENTS[], OFFENSE_EVENTS[],
  # IOC_PRIMITIVES[], IOC_ANNOTATIONS[], RECONCILED_EVENTS[], N_PRE, N_POST,
  # plus signals via emit() under areas defense/offense/reconcile.
  ###############################################################################
  ```

- [ ] **Step 4: Insert renderer + write_kill_chain_primitives**

  Location: after phase_reconcile.

  Functions to extract:
  - `ansi_strip()`                — forensic line 1483-1490
  - `fmt_offense_detail()`        — forensic line 1491-1519
  - `render_offense_row()`        — forensic line 1520-1547
  - `render_defense_row()`        — forensic line 1548-1570
  - `aggregate_attacker_ips()`    — forensic line 1571-1641
  - `fmt_delta_human()`           — forensic line 1642-1651
  - `render_kill_chain()`         — forensic line 1652-1958
  - `write_kill_chain_primitives()` — forensic line 1959-2169

  Same extraction recipe.

  Section comment:
  ```bash

  ###############################################################################
  # Kill-chain renderer + primitives writer (post-merge v2.0.0).
  ###############################################################################
  ```

  Self-correction note: `render_kill_chain()` reads `ENV_HOST_VERDICT`, `ENV_SCORE`, `ENV_IOC_TOOL_VERSION` — all defined in Phase 2 Step 2. Verify these are referenced via the global, not via $1/$2 args. Confirmed by reading forensic line 1700+ (uses `$ENV_HOST_VERDICT` directly).

- [ ] **Step 5: Insert phase_bundle + dependents + phase_upload**

  Location: after write_kill_chain_primitives.

  Functions to extract:
  - `estimate_size_mb()`  — forensic line 2170-2178
  - `collect_recent()`    — forensic line 2179-2199
  - `bundle_tar()`        — forensic line 2200-2241
  - `phase_bundle()`      — forensic line 2242-2597
  - `phase_upload()`      — forensic line 2598-2682

  Section comment:
  ```bash

  ###############################################################################
  # Bundle + upload pipeline (post-merge v2.0.0).
  # Bundle root: $BUNDLE_DIR_ROOT/<TS>-<RUN_ID>/ (set in Phase 4 CLI parsing).
  # Tarball cap: --max-bundle-mb (per-tarball). Upload: --upload (PUT to
  # $INTAKE_URL with $INTAKE_TOKEN).
  ###############################################################################
  ```

  Self-correction note: `phase_upload` references `$BUNDLE_TGZ`, `$INTAKE_URL`, `$INTAKE_TOKEN`, `$DO_UPLOAD`. CLI parsing (Phase 4) sets these. For Phase 3, ensure these names are NOT yet referenced at top level — only inside the function body. Confirmed by source read.

- [ ] **Step 6: Dry-run probe to confirm zero unbound-variable failures**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo PARSE-OK
  # expect: PARSE-OK

  # Source ONLY the function defs (no main flow), declare a stub global
  # set, and call one phase function to make sure all referenced symbols
  # resolve under set -u.
  bash -c '
    set -u
    set -e
    # Stub the globals phase_defense reads.
    QUIET=1; CPANEL_NORM="11.110.0.103"; PATCH_CANARY_FILE="/nonexistent"
    SIGNALS=(); DEFENSE_EVENTS=(); OFFENSE_EVENTS=(); IOC_PRIMITIVES=()
    IOC_ANNOTATIONS=(); RECONCILED_EVENTS=()
    DEF_PATCH_TIME=""; DEF_CPSRVD_RESTART=""; DEF_MITIGATE_FIRST=""
    DEF_MITIGATE_LAST=""; DEF_MODSEC_TIME=""; PATCH_STATE=""
    BUNDLE_BDIR=""; BUNDLE_TGZ=""
    PATCHED_BUILDS_CPANEL=("11.110.0.103")
    PATCHED_BUILD_WPSQUARED=""
    UNPATCHED_TIERS=(112)
    MITIGATE_BACKUP_ROOT="/var/cpanel/sessionscribe-mitigation"
    MODSEC_USER_CONFS=("/nonexistent")
    MODSEC_USER_CONF="/nonexistent"
    CPSRVD_PORTS=(2087)
    C_RED=""; C_GRN=""; C_YEL=""; C_DIM=""; C_BLD=""; C_NC=""
    GLYPH_OK="+"; GLYPH_BAD="x"; GLYPH_WARN="!"
    # Stub helpers.
    emit() { :; }
    emit_signal() { :; }
    say()      { :; }
    say_pass() { :; }
    say_info() { :; }
    say_warn() { :; }
    say_def()  { :; }
    say_def_miss() { :; }
    hdr() { :; }
    epoch_to_iso() { echo "$1"; }
    mtime_of() { echo 0; }
    have_cmd() { command -v "$1" >/dev/null 2>&1; }
    # Source phase_defense and call it.
    eval "$(awk "/^phase_defense\(\)/,/^}$/" sessionscribe-ioc-scan.sh)"
    phase_defense
    echo PHASE-DEFENSE-OK
  '
  # expect: PARSE-OK then PHASE-DEFENSE-OK
  ```

  If the probe fails with "unbound variable" — STOP, fix the missing global declaration, re-run. Do not commit until clean.

- [ ] **Step 7: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.0.0-pre3: inline forensic phase functions + renderer + bundle pipeline

  Phase 3 of 8 — adds the say_* output primitives, the emit_signal() wrapper
  around emit() (severity-mapped: pass/info -> info/0, warn -> warning/4,
  fail -> strong/10), and the full forensic phase block:
    phase_defense, phase_offense (+ pattern_g_deep_checks +
    suspect_ip_correlation), phase_reconcile, render_kill_chain (+
    ansi_strip, fmt_offense_detail, render_offense_row, render_defense_row,
    aggregate_attacker_ips, fmt_delta_human), write_kill_chain_primitives,
    phase_bundle (+ estimate_size_mb, collect_recent, bundle_tar),
    phase_upload.

  Bodies are verbatim from forensic except emit_signal which is the new
  wrapper. Dry-run probe in Step 6 confirms no unbound-variable failures
  with the expected stub globals.

  Phase functions are defined but still not called from main flow — Phase
  4 (CLI surface) and Phase 5 (main flow refactor) wire them up.
  EOF
  )"
  ```

---

### Phase 4: CLI surface — add --full/--triage/--replay/bundle/upload flags; map back-compat aliases

Add the new CLI flags and the back-compat aliases for the chain flags. Keep the existing `--chain-forensic` / `--chain-on-critical` / `--chain-upload` working (they now set `--full` with the same gates). Add `--triage` as the explicit name for the default triage-only mode (operator self-documentation; no behavior change). Add `--replay PATH`, `--bundle`, `--no-bundle`, `--bundle-dir DIR`, `--max-bundle-mb N`, `--extra-logs DIR`, `--no-history`, `--upload`, `--upload-url URL`, `--upload-token TOKEN`. Update `usage()`.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (extend the `case "$1" in ... esac` block + extend `usage()` heredoc + add CLI defaults near top of file)

- **Mode**: serial-context
- **Accept**: `bash sessionscribe-ioc-scan.sh --help 2>&1 | grep -c -- '--full'` returns ≥1; `bash sessionscribe-ioc-scan.sh --help 2>&1 | grep -c -- '--replay'` returns ≥1; `bash sessionscribe-ioc-scan.sh --help 2>&1 | grep -c -- '--chain-forensic'` returns ≥1 (back-compat preserved); `bash sessionscribe-ioc-scan.sh --triage --help 2>&1 | head -1 | grep -c 'Usage:'` returns 1 (no parse error); `bash sessionscribe-ioc-scan.sh --replay 2>&1 | grep -c 'requires'` returns ≥1 (missing-arg detection)
- **Test**: Step 7 verification commands; all expected outputs match
- **Edge cases**: `--replay PATH` with PATH being a directory → look for `*.json` envelope inside (forensic bundle convention); PATH being a `.tgz` → extract envelope to /tmp; PATH being a `.json` → use directly. Validation logic lives in Phase 5; this phase only accepts the flag and stores the path
- **Regression-case**: N/A — refactor — flags accepted but not yet acted upon (Phase 5 wires them into the main flow)

- [ ] **Step 1: Add CLI defaults near existing defaults**

  Location: search for `JSONL=0` or `CSV=0` in ioc-scan to find the CLI defaults block; insert after that block.

  ```bash

  # Forensic / merged-mode defaults (post-merge v2.0.0).
  FULL_MODE=0                             # 1 if --full set (or back-compat chain flag)
  REPLAY_PATH=""                          # set by --replay PATH
  REPLAY_MODE=0                           # 1 if --replay PATH set (skip detection)
  DO_BUNDLE=1                             # default ON when --full active; --no-bundle disables
  BUNDLE_DIR_ROOT="$DEFAULT_BUNDLE_DIR_ROOT"
  MAX_BUNDLE_MB="$DEFAULT_MAX_BUNDLE_MB"
  EXTRA_LOGS_DIR=""
  INCLUDE_HOMEDIR_HISTORY=1
  DO_UPLOAD=0
  INTAKE_URL="$INTAKE_DEFAULT_URL"
  INTAKE_TOKEN=""
  ```

- [ ] **Step 2: Extend usage() heredoc with new flag block**

  Location: `usage()` function, find the `Forensic chaining:` section header.

  Replace the existing `Forensic chaining:` section with:

  ```
  Mode (post-merge v2.0.0):
        --triage               Detection only (default). Writes envelope to
                               run-ledger; no defense timeline / kill-chain /
                               bundle. Same shape as ioc-scan v1.x.
        --full                 Detection + forensic phases (defense / offense /
                               reconcile / kill-chain / bundle). Implies
                               --bundle by default; pair with --no-bundle for
                               kill-chain reconstruction without artifact tar.
        --replay PATH          Skip detection; replay forensic phases against
                               a saved envelope (.json file), bundle directory
                               (containing the envelope), or bundle tarball
                               (.tgz / .tar.gz — envelope extracted to /tmp).
                               --bundle / --upload still respected if set.
                               Useful for re-rendering the kill chain or
                               re-uploading a captured bundle without re-
                               scanning the host.

  Bundle (active when --full or --replay):
        --bundle               Capture artifact tarball to $BUNDLE_DIR_ROOT/
                               <ts>-<run_id>/ (default ON in --full mode)
        --no-bundle            Skip bundle capture (recommended on Pattern A
                               hosts where du+tar would compete with the
                               encryptor for IO)
        --bundle-dir DIR       Override $BUNDLE_DIR_ROOT
                               (default: /root/.ic5790-forensic)
        --max-bundle-mb N      Per-tarball size cap in MB (0 = no cap;
                               default: 2048)
        --extra-logs DIR       Additional access-log directory to scan (e.g.
                               an expanded archive of rotated logs)
        --no-history           Skip /home/*/.bash_history bundle capture

  Upload (off by default):
        --upload               Submit bundle to $INTAKE_URL after capture
        --upload-url URL       Override intake URL
                               (default: https://intake.rfxn.com/)
        --upload-token TOKEN   Override token. Resolution order: this flag >
                               $RFXN_INTAKE_TOKEN env > built-in convenience
                               token (1000-PUT cap, request your own from
                               proj@rfxn.com for fleet use).

  Back-compat aliases (deprecated; set --full + the relevant gate):
        --chain-forensic       == --full (no host-verdict gate)
        --chain-on-critical    == --full but only if host_verdict ==
                                 COMPROMISED (CLEAN/SUSPICIOUS skip forensic)
        --chain-upload         == --full --upload
  ```

- [ ] **Step 3: Add new flags to the case "$1" in ... esac block**

  Location: the existing `case "$1" in` block at ioc-scan main flow start.

  Insert before `--root)`:
  ```bash
          --triage)             FULL_MODE=0; REPLAY_MODE=0; shift ;;
          --full)               FULL_MODE=1; shift ;;
          --replay)             REPLAY_PATH="$2"; REPLAY_MODE=1; shift 2 ;;
          --bundle)             DO_BUNDLE=1; shift ;;
          --no-bundle)          DO_BUNDLE=0; shift ;;
          --bundle-dir)         BUNDLE_DIR_ROOT="$2"; shift 2 ;;
          --max-bundle-mb)      MAX_BUNDLE_MB="$2"; shift 2 ;;
          --extra-logs)         EXTRA_LOGS_DIR="$2"; shift 2 ;;
          --no-history)         INCLUDE_HOMEDIR_HISTORY=0; shift ;;
          --upload)             DO_UPLOAD=1; shift ;;
  ```

  Note: `--upload-url` and `--upload-token` already exist (forwarded to forensic via `CHAIN_UPLOAD_URL`/`CHAIN_UPLOAD_TOKEN`). Reuse the existing parsing — Phase 5 will re-route the value into `INTAKE_URL`/`INTAKE_TOKEN`.

- [ ] **Step 4: Update back-compat alias semantics**

  Existing chain-flag handlers in the case block become aliases for `--full`. Replace:

  Old:
  ```bash
          --chain-forensic)     CHAIN_FORENSIC=1; shift ;;
          --chain-upload)       CHAIN_UPLOAD=1; CHAIN_FORENSIC=1; shift ;;
          --chain-on-critical)  CHAIN_ON_CRITICAL=1; CHAIN_FORENSIC=1; shift ;;
  ```

  New:
  ```bash
          # Back-compat aliases — set --full + the legacy gate flags so the
          # main-flow gating logic (Phase 5) honors the original semantics.
          --chain-forensic)     FULL_MODE=1; CHAIN_FORENSIC=1; shift ;;
          --chain-upload)       FULL_MODE=1; DO_UPLOAD=1; CHAIN_UPLOAD=1; CHAIN_FORENSIC=1; shift ;;
          --chain-on-critical)  FULL_MODE=1; CHAIN_ON_CRITICAL=1; CHAIN_FORENSIC=1; shift ;;
  ```

  Self-correction note: keep `CHAIN_FORENSIC`, `CHAIN_UPLOAD`, `CHAIN_ON_CRITICAL` globals intact — Phase 5 references them in the gating logic. They're internal-only now (operator-facing flags map to them).

- [ ] **Step 5: Add validation: --replay requires PATH; --replay + --triage are mutually exclusive**

  Location: immediately after the `case "$1" in ... esac while loop`.

  Insert:
  ```bash

  # --replay requires a path arg.
  if (( REPLAY_MODE )) && [[ -z "$REPLAY_PATH" ]]; then
      echo "Error: --replay requires PATH (envelope .json, bundle directory, or .tgz)" >&2
      exit 3
  fi
  # --replay implies --full (forensic phases are the whole point of replay).
  (( REPLAY_MODE )) && FULL_MODE=1
  # --upload requires --full or --replay (something to upload).
  if (( DO_UPLOAD )) && ! (( FULL_MODE || REPLAY_MODE )); then
      echo "Error: --upload requires --full or --replay (no bundle without forensic mode)" >&2
      exit 3
  fi
  # --full requires the envelope on disk so forensic phases can read it via
  # the same code path as --replay. --no-ledger disables that write — silently
  # producing an empty kill-chain. Reject the combination explicitly.
  if (( FULL_MODE )) && (( ! REPLAY_MODE )) && (( NO_LEDGER )); then
      echo "Error: --full is incompatible with --no-ledger (forensic phases require the envelope on disk; use --ledger-dir to override the location instead)" >&2
      exit 3
  fi
  # Resolve upload token at parse time. Order: --upload-token > env > built-in.
  if (( DO_UPLOAD )); then
      INTAKE_TOKEN="${CHAIN_UPLOAD_TOKEN:-${RFXN_INTAKE_TOKEN:-$INTAKE_DEFAULT_TOKEN}}"
      [[ -n "$CHAIN_UPLOAD_URL" ]] && INTAKE_URL="$CHAIN_UPLOAD_URL"
  fi
  # Validate --max-bundle-mb is a non-negative integer.
  if ! [[ "$MAX_BUNDLE_MB" =~ ^[0-9]+$ ]]; then
      echo "Error: --max-bundle-mb requires a non-negative integer (MB)" >&2
      exit 3
  fi
  ```

- [ ] **Step 6: Set forensic-mode --since default**

  Location: in the existing `--since` parsing block.

  After the SINCE_EPOCH calculation, add:
  ```bash

  # Forensic mode default --since: 90 days (covers full pre-disclosure window
  # for CVE-2026-41940). Triage default remains "no filter" for backward
  # compatibility with v1.x ioc-scan.
  if (( FULL_MODE || REPLAY_MODE )) && [[ -z "$SINCE_DAYS" ]]; then
      SINCE_DAYS="$DEFAULT_FORENSIC_SINCE_DAYS"
      SINCE_EPOCH=$(( $(date -u +%s) - SINCE_DAYS * 86400 ))
  fi
  ```

- [ ] **Step 7: Verify**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK

  bash sessionscribe-ioc-scan.sh --help 2>&1 | grep -cE -- '--(full|triage|replay|bundle|no-bundle|bundle-dir|max-bundle-mb|extra-logs|no-history|upload)\b'
  # expect: 10 (one match per new flag)

  bash sessionscribe-ioc-scan.sh --help 2>&1 | grep -cE -- '--(chain-forensic|chain-upload|chain-on-critical)\b'
  # expect: 3 (back-compat preserved)

  bash sessionscribe-ioc-scan.sh --replay 2>&1 | grep -c 'PATH'
  # expect: 1 (missing-arg detection)

  bash sessionscribe-ioc-scan.sh --upload 2>&1 | grep -c 'requires --full or --replay'
  # expect: 1 (validation)

  bash sessionscribe-ioc-scan.sh --max-bundle-mb -5 2>&1 | grep -c 'non-negative'
  # expect: 1 (validation)
  ```

- [ ] **Step 8: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.0.0-pre4: CLI surface — --full/--triage/--replay + bundle/upload flags

  Phase 4 of 8 — adds the merged-mode CLI flags:
    --triage               (default) detection only, envelope-only output
    --full                 detection + forensic phases (defense/offense/
                           reconcile/render/bundle)
    --replay PATH          skip detection; replay forensic on saved envelope
                           (.json), bundle dir, or .tgz
    --bundle/--no-bundle   bundle capture toggle (default ON in --full)
    --bundle-dir DIR       override bundle root (default: /root/.ic5790-forensic)
    --max-bundle-mb N      per-tarball cap (0 = unlimited; default 2048)
    --extra-logs DIR       additional access-log directory to scan
    --no-history           skip /home/*/.bash_history bundle capture
    --upload               submit bundle to $INTAKE_URL after capture
    --upload-url / --upload-token  override intake (still parsed via the
                           existing CHAIN_UPLOAD_* globals)

  Back-compat aliases preserved: --chain-forensic, --chain-upload,
  --chain-on-critical now set FULL_MODE=1 + the matching legacy gate flags.

  Validation: --replay requires PATH; --upload requires --full or --replay;
  --max-bundle-mb requires non-negative int. Forensic-mode --since defaults
  to 90 days (was unset for triage; covers full CVE-2026-41940 pre-disclosure
  window).

  Flags accepted but main flow still skips forensic phases — Phase 5 wires
  them in.
  EOF
  )"
  ```

---

### Phase 5: Main flow refactor — write envelope, run forensic phases inline, replay path

Replace the existing chain-dispatch section with inline phase invocation. Detection runs as before in `--triage` mode (no behavior change). In `--full` mode: detection runs, envelope is written to disk, then `read_iocs_from_envelope` is called against the disk envelope, then `phase_defense` / `phase_offense` / `phase_reconcile` / `render_kill_chain` / `phase_bundle` / `phase_upload` run in sequence. In `--replay` mode: detection is skipped entirely; the supplied PATH is resolved to an envelope file (extracting from a tgz to /tmp if needed); then forensic phases run. Delete `chain_forensic_dispatch`, `fetch_forensic_remote`, and the `FORENSIC_SRC_CANDIDATES` list. Bump VERSION to 2.0.0.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (replace main-flow tail; delete obsolete chain functions; bump VERSION)

- **Mode**: serial-agent
- **Accept**: `grep -c '^chain_forensic_dispatch()' sessionscribe-ioc-scan.sh` returns 0 (deleted); `grep -c '^fetch_forensic_remote()' sessionscribe-ioc-scan.sh` returns 0 (deleted); `grep -c 'FORENSIC_SRC_CANDIDATES' sessionscribe-ioc-scan.sh` returns 0 (deleted); `grep -c '^VERSION="2\.0\.0"' sessionscribe-ioc-scan.sh` returns 1; `bash sessionscribe-ioc-scan.sh --triage --no-ledger --no-logs --no-sessions --no-destruction-iocs 2>&1 | grep -c 'verdict'` returns ≥1 (default mode still functional); `bash sessionscribe-ioc-scan.sh --replay /tmp/no-such-file.json 2>&1 | grep -c 'envelope'` returns ≥1 (replay path resolves missing envelope cleanly)
- **Test**: Step 7 smoke tests; all expected outputs match. Live verification deferred to Phase 7
- **Edge cases**:
  - `--replay PATH.json` (file): use directly, validate it's parseable JSON envelope
  - `--replay PATH/` (dir): glob `PATH/<run_id>.json` or `PATH/envelope.json`; if multiple matches, error
  - `--replay PATH.tgz` or `.tar.gz`: extract envelope to `/tmp/sessionscribe-replay-<RUN_ID>/`, set ENVELOPE_PATH there; if multiple `*.json` files inside, error (consistent with the directory case)
  - Replay envelope is older schema_version (1.x): forensic helpers already tolerate this per CLAUDE.md "envelope contract"
  - `--full --no-ledger` combination: rejected at parse time in Phase 4 Step 5 (forensic phases require the envelope on disk; this combination would silently produce an empty kill-chain)
- **Regression-case**: N/A — refactor — main-flow refactor; behavioral regression coverage lives in Phase 7 scenarios 1 (--triage) and 2 (--full); project has no bats/pytest harness

- [ ] **Step 1: Bump VERSION + header comment**

  Location: ioc-scan top of file.

  ```diff
  -VERSION="1.8.2"
  +VERSION="2.0.0"
  ```

  ```diff
  -# sessionscribe-ioc-scan.sh v1.8.2
  +# sessionscribe-ioc-scan.sh v2.0.0
  ```

- [ ] **Step 2: Add resolve_replay_envelope() helper**

  Location: insert immediately before the existing `# Main` section (the one that currently calls `local_init` etc.).

  ```bash

  # Resolve a --replay PATH argument into a concrete envelope JSON file path.
  # Accepts:
  #   PATH.json                — used directly
  #   PATH/                    — looks for *.json (envelope.json or <run_id>.json)
  #   PATH.tgz, PATH.tar.gz    — extracts the envelope to /tmp/sessionscribe-replay-<RUN_ID>/
  # Sets RESOLVED_ENVELOPE_PATH on success; emits to stderr + exits 3 on
  # ambiguity or unreadability.
  RESOLVED_ENVELOPE_PATH=""
  REPLAY_TMPDIR=""
  resolve_replay_envelope() {
      local p="$1"
      if [[ -z "$p" ]]; then
          echo "Error: resolve_replay_envelope called with empty path" >&2
          exit 3
      fi
      if [[ -f "$p" ]]; then
          case "$p" in
              (*.json)
                  RESOLVED_ENVELOPE_PATH="$p"
                  return 0
                  ;;
              (*.tgz|*.tar.gz)
                  REPLAY_TMPDIR=$(mktemp -d "/tmp/sessionscribe-replay-${RUN_ID}.XXXXXX") || {
                      echo "Error: mktemp failed for replay extraction" >&2
                      exit 3
                  }
                  if ! tar -xzf "$p" -C "$REPLAY_TMPDIR" 2>/dev/null; then
                      echo "Error: failed to extract $p (not a valid gzip tarball?)" >&2
                      exit 3
                  fi
                  # Bundle layout: <tmp>/<bundle-dir-name>/<run_id>.json (forensic
                  # bundle convention) OR <tmp>/envelope.json (legacy). Multi-match
                  # is an error — same rule as the directory case so an operator
                  # can't accidentally replay against a non-envelope JSON file.
                  local cand n_cand
                  n_cand=$(find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' 2>/dev/null | wc -l)
                  if (( n_cand == 0 )); then
                      echo "Error: no .json envelope found inside $p" >&2
                      exit 3
                  elif (( n_cand > 1 )); then
                      echo "Error: $n_cand .json files found inside $p — ambiguous; extract manually and pass the envelope file directly with --replay" >&2
                      find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' >&2
                      exit 3
                  fi
                  cand=$(find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' 2>/dev/null | head -1)
                  RESOLVED_ENVELOPE_PATH="$cand"
                  return 0
                  ;;
              (*)
                  echo "Error: --replay file must be .json, .tgz, or .tar.gz (got $p)" >&2
                  exit 3
                  ;;
          esac
      elif [[ -d "$p" ]]; then
          # Directory — find the first envelope.json or numeric-prefixed .json
          local cand
          cand=$(find "$p" -maxdepth 1 -type f -name '*.json' 2>/dev/null | head -1)
          if [[ -z "$cand" ]]; then
              echo "Error: no .json envelope found in directory $p" >&2
              exit 3
          fi
          RESOLVED_ENVELOPE_PATH="$cand"
          return 0
      else
          echo "Error: --replay PATH does not exist: $p" >&2
          exit 3
      fi
  }
  ```

  Self-correction note: case patterns use leading-paren `(*.json)` — required for bash <4.4 case-in-cmdsubst safety; consistent with the rest of the codebase even though this particular case is at top level.

  Self-correction note: `find -maxdepth 3` for the tgz extraction case — typical bundle layout puts envelope at depth 2 (`<tmp>/<bundle-dir>/file.json`); maxdepth 3 gives a buffer for nested layouts without walking the whole tree.

- [ ] **Step 3: Replace the main-flow tail (chain dispatch → inline phases)**

  Location: from `chain_forensic_dispatch` call to end of file.

  Read the current main flow tail first:
  ```bash
  awk 'NR>=3325 && NR<=3380' sessionscribe-ioc-scan.sh
  ```

  Replace from the line `chain_forensic_dispatch` through `exit "$EXIT_CODE"` with the new main flow:

  ```bash

  ###############################################################################
  # Detection phase (skipped in --replay mode)
  ###############################################################################
  if (( ! REPLAY_MODE )); then
      banner

      local_init
      if (( IOC_ONLY )); then
          section "IOC-only mode (--ioc-only): code-state checks skipped"
      else
          check_version
          check_static
          check_binary
      fi
      check_logs
      check_sessions
      check_destruction_iocs
      check_localhost_probe

      aggregate_verdict

      # Write the envelope to disk BEFORE forensic phases run so the forensic
      # path can read it from disk via the same code path used by --replay.
      # This makes the envelope contract a same-script invariant rather than
      # a cross-script handshake.
      if [[ -z "$NO_LEDGER" || "$NO_LEDGER" -eq 0 ]]; then
          mkdir -p "$LEDGER_DIR" 2>/dev/null
          ENVELOPE_PATH="$LEDGER_DIR/${RUN_ID}.json"
          write_json "$ENVELOPE_PATH" 2>/dev/null
          [[ -f "$ENVELOPE_PATH" ]] && chmod 0600 "$ENVELOPE_PATH" 2>/dev/null
      fi
  else
      # --replay PATH: skip detection, set ENVELOPE_PATH from resolved input.
      resolve_replay_envelope "$REPLAY_PATH"
      ENVELOPE_PATH="$RESOLVED_ENVELOPE_PATH"
      # Read host_verdict / score / tool_version from the envelope so the
      # forensic phases see consistent context.
      read_envelope_meta "$ENVELOPE_PATH"
      HOST_VERDICT="${ENV_HOST_VERDICT:-UNKNOWN}"
      SCORE="${ENV_SCORE:-0}"
      section "Replay mode: detection skipped, forensic phases on $ENVELOPE_PATH"
  fi

  ###############################################################################
  # Forensic phases (--full or --replay)
  ###############################################################################
  RUN_FORENSIC=0
  if (( REPLAY_MODE )); then
      RUN_FORENSIC=1
  elif (( FULL_MODE )); then
      # Apply legacy chain gates if set (--chain-on-critical etc.).
      if (( CHAIN_ON_CRITICAL )) && [[ "$HOST_VERDICT" != "COMPROMISED" ]]; then
          emit "summary" "forensic_skip" "info" "forensic_skipped_below_critical" 0 \
               "host_verdict" "$HOST_VERDICT" \
               "note" "host_verdict=$HOST_VERDICT; --chain-on-critical limits forensic to COMPROMISED."
      elif [[ "$HOST_VERDICT" == "CLEAN" ]]; then
          emit "summary" "forensic_skip" "info" "forensic_skipped_clean" 0 \
               "note" "host_verdict=CLEAN; not running forensic phases."
      else
          RUN_FORENSIC=1
      fi
  fi

  if (( RUN_FORENSIC )); then
      phase_defense
      phase_offense
      phase_reconcile
      render_kill_chain
      if (( DO_BUNDLE )); then
          phase_bundle
          (( DO_UPLOAD )) && phase_upload
      fi

      # Forensic summary signal (mirrors the old standalone forensic exit
      # logic, but now folded into the unified envelope + verdict). NO `local`
      # keyword — this code runs at top level (outside any function); local
      # would be a parse error. The names become globals; they're only read
      # in the emit() call below so the namespace pollution is harmless.
      n_off="${#OFFENSE_EVENTS[@]}"; n_def="${#DEFENSE_EVENTS[@]}"
      f_verdict="CLEAN"; f_exit=0
      if (( n_off > 0 )); then
          if (( N_PRE > 0 )); then f_verdict="COMPROMISED_PRE_DEFENSE"; f_exit=2
          else                     f_verdict="COMPROMISED_POST_DEFENSE"; f_exit=1
          fi
      fi
      emit "summary" "forensic_summary" "info" "forensic_reconstruction" 0 \
           "verdict" "$f_verdict" "iocs_total" "$n_off" \
           "pre_defense" "$N_PRE" "post_defense" "$N_POST" \
           "defenses_extracted" "$n_def" \
           "note" "forensic reconstruction: $f_verdict (exit=$f_exit; does not override host_verdict exit code)"
  fi

  print_verdict

  # Streaming: --csv to stdout (--jsonl is already streamed line-by-line during
  # emit() so no end-of-run write is needed for that mode).
  (( CSV )) && write_csv /dev/stdout

  # File output (-o FILE).
  if [[ -n "$OUTPUT_FILE" ]]; then
      if (( CSV )); then
          write_csv "$OUTPUT_FILE"
      else
          write_json "$OUTPUT_FILE"
      fi
  fi

  # Re-write the envelope at end-of-run so forensic-phase signals and the
  # forensic_summary land in the on-disk artifact (the early write above
  # had only the detection signals).
  if (( ! REPLAY_MODE )) && [[ -n "$ENVELOPE_PATH" && -f "$ENVELOPE_PATH" ]]; then
      write_json "$ENVELOPE_PATH" 2>/dev/null
      chmod 0600 "$ENVELOPE_PATH" 2>/dev/null
  fi

  ledger_write
  syslog_emit

  # Replay mode: clean up the tmpdir from tgz extraction.
  if (( REPLAY_MODE )) && [[ -n "$REPLAY_TMPDIR" && -d "$REPLAY_TMPDIR" ]]; then
      rm -rf "$REPLAY_TMPDIR" 2>/dev/null
  fi

  exit "$EXIT_CODE"
  ```

  Self-correction note: the early envelope write happens BEFORE forensic phases so `read_iocs_from_envelope` (called from `phase_offense`) reads the on-disk file. The end-of-run write rewrites the same file with the additional forensic-area signals. `ledger_write` is called last to update the runs.jsonl ledger with the final envelope path.

  Self-correction note: bash allows `local` only inside function bodies. The corrected snippet above (post-fix) drops the `local` keyword — `n_off`, `n_def`, `f_verdict`, `f_exit` become globals. This is harmless because they are only read in the immediately-following `emit` call; nothing else in the file uses these names.

- [ ] **Step 4: Delete chain_forensic_dispatch and fetch_forensic_remote**

  Location: search for `^chain_forensic_dispatch()` and `^fetch_forensic_remote()` in ioc-scan.

  Delete from `^chain_forensic_dispatch() {` through its closing `}`. Same for `fetch_forensic_remote`. Also delete the `FORENSIC_SRC_CANDIDATES=(...)` array declaration (search for it; it's declared near the top of file alongside the chain flags).

  ```bash
  # Confirm deletion targets:
  grep -nE '^(chain_forensic_dispatch|fetch_forensic_remote)\(\)|^FORENSIC_SRC_CANDIDATES=' sessionscribe-ioc-scan.sh
  # All matches must be deleted before commit.
  ```

- [ ] **Step 5: Update emit() if needed to handle the new areas**

  Read ioc-scan's current `emit()`:
  ```bash
  awk '/^emit\(\)/,/^}$/' sessionscribe-ioc-scan.sh
  ```

  Verify `emit()` treats `area` as opaque (no whitelist). Confirmed by source read — `emit()` accepts any area string. No edit needed.

  If `print_signal_human` filters areas (it might suppress some from the human-readable report): read it and confirm the new areas (`defense`, `offense`, `reconcile`, `bundle`, `upload`, `summary`) either render appropriately or are explicitly dropped from the human report (forensic phases handle their own human output via `say_*` and `hdr`).

- [ ] **Step 6: Confirm aggregate_verdict is NOT re-run after forensic phases (intentional)**

  Read `aggregate_verdict()`:
  ```bash
  awk '/^aggregate_verdict\(\)/,/^}$/' sessionscribe-ioc-scan.sh
  ```

  **Design decision (binding):** `aggregate_verdict` runs ONCE in the main flow, between detection and forensic phases (see Step 3). It is NOT called a second time after `phase_offense` / `phase_reconcile` complete. This is intentional:

  1. `HOST_VERDICT` and `SCORE` reflect detection findings only — the same semantics as v1.x ioc-scan. The exit code (`$EXIT_CODE`) follows from this aggregation. The operator's first read of the verdict on screen matches what fleet aggregations consume.
  2. Forensic-area signals (`defense`, `offense`, `reconcile`, `bundle`, `upload`, `summary`) are recorded in the envelope's `signals[]` array AND in the on-screen kill-chain renderer, but do NOT alter the top-level `host_verdict` / `score` / exit code.
  3. Why no double-counting: `phase_offense` re-emits envelope IOCs as `offense fail` signals. Without a second aggregation pass these signals never enter the verdict loop. They are observational reflections of detection findings, not new findings.
  4. The `forensic_summary` signal emitted at end of Phase 5 Step 3 carries the forensic verdict (`COMPROMISED_PRE_DEFENSE` / `_POST_DEFENSE` / `CLEAN`) as a SEPARATE field — fleet consumers that want the forensic-side verdict read it from there. The detection-side verdict stays canonical for backward compatibility.

  **Action for the agent executing this step:** verify by reading the source that there is no second `aggregate_verdict` call in the main flow. If there is one (e.g., from a misread of Phase 5 Step 3), remove it. Document this decision in the commit message.

  ```bash
  grep -c '^aggregate_verdict$\|aggregate_verdict$' sessionscribe-ioc-scan.sh
  # expect: 1 (single call site in main flow; function definition counts as 1 with $)
  # Stricter check — count call sites only (excluding the function definition):
  grep -cE '^\s*aggregate_verdict\s*$' sessionscribe-ioc-scan.sh
  # expect: 1
  ```

- [ ] **Step 7: Verify**

  ```bash
  bash -n sessionscribe-ioc-scan.sh && echo OK
  # expect: OK

  grep -c '^chain_forensic_dispatch()' sessionscribe-ioc-scan.sh
  # expect: 0
  grep -c '^fetch_forensic_remote()' sessionscribe-ioc-scan.sh
  # expect: 0
  grep -c 'FORENSIC_SRC_CANDIDATES' sessionscribe-ioc-scan.sh
  # expect: 0
  grep -c '^VERSION="2\.0\.0"' sessionscribe-ioc-scan.sh
  # expect: 1
  grep -c '^resolve_replay_envelope()' sessionscribe-ioc-scan.sh
  # expect: 1

  # Triage default still parses and exits cleanly (won't actually scan
  # in this offline shell since /var/cpanel may not exist, but should
  # at least reach the validation gate).
  bash sessionscribe-ioc-scan.sh --help 2>&1 | head -1
  # expect: a "Usage:" line, no parse error

  # Replay against a non-existent path should error cleanly.
  bash sessionscribe-ioc-scan.sh --replay /tmp/nonexistent-envelope.json 2>&1 | grep -c 'does not exist'
  # expect: 1

  # Replay against an empty directory should error cleanly.
  td=$(mktemp -d); bash sessionscribe-ioc-scan.sh --replay "$td" 2>&1 | grep -c 'no .json envelope'; rm -rf "$td"
  # expect: 1
  ```

- [ ] **Step 8: Commit**

  ```bash
  git add sessionscribe-ioc-scan.sh
  git commit -m "$(cat <<'EOF'
  ioc-scan v2.0.0: main flow refactor — inline forensic phases, --replay path

  Phase 5 of 8 — final wiring of the merged architecture. Detection runs
  unchanged in default --triage mode (zero behavior change). In --full
  mode: detection runs, envelope is written to disk, then forensic phases
  (defense / offense / reconcile / render_kill_chain / bundle / upload)
  run in sequence. In --replay PATH mode: detection is skipped; PATH is
  resolved to an envelope file (.json, bundle dir, or .tgz extracted to
  /tmp); forensic phases run against the supplied envelope.

  resolve_replay_envelope() handles three input shapes:
    .json file               → used directly
    directory                → find first *.json inside
    .tgz / .tar.gz           → extract to /tmp/sessionscribe-replay-<RUN_ID>/

  Deleted: chain_forensic_dispatch(), fetch_forensic_remote(),
  FORENSIC_SRC_CANDIDATES — no remote fetch needed since forensic is
  inline now. The --chain-* aliases (--chain-forensic, --chain-upload,
  --chain-on-critical) still work; they map to --full + the legacy gates.

  Envelope is written to disk BEFORE forensic phases (so phase_offense's
  read_iocs_from_envelope reads from disk — same code path as --replay)
  and rewritten at end-of-run with forensic-area signals folded in.

  VERSION 1.8.2 → 2.0.0 (architectural break: chain dispatch removed,
  unified envelope, replay surface added).
  EOF
  )"
  ```

---

### Phase 6: Replace sessionscribe-forensic.sh with deprecation shim

Replace the 2,769-line forensic script with a ~30-line v0.99.0 shim that prints a one-line deprecation notice and `exec`s ioc-scan with `--replay`. Preserves the CDN URL for grace-period clients (anyone still running `curl … sessionscribe-forensic.sh | bash` continues to work, just gets the deprecation banner). The shim respects `--quiet` to keep machine-piped consumers clean.

**Files:**
- Modify: `sessionscribe-forensic.sh` (full rewrite to ~30-line shim)

- **Mode**: serial-context
- **Accept**: `wc -l sessionscribe-forensic.sh` returns ≤ 50; `grep -c '^VERSION="0\.99\.0"' sessionscribe-forensic.sh` returns 1; `grep -c 'exec.*sessionscribe-ioc-scan.sh.*--replay' sessionscribe-forensic.sh` returns 1; `grep -c 'DEPRECATED' sessionscribe-forensic.sh` returns ≥1; `bash sessionscribe-forensic.sh --help 2>&1 | grep -c 'merged into'` returns 1
- **Test**: Step 3 verification commands; all expected outputs match
- **Edge cases**: shim invoked without `$SESSIONSCRIBE_IOC_JSON` set AND without an envelope path arg → must print actionable error explaining the new `--replay PATH` requirement
- **Regression-case**: N/A — refactor — full-file rewrite; behavioral regression coverage lives in Phase 7 scenario 6 (deprecation shim end-to-end); project has no bats/pytest harness

- [ ] **Step 1: Replace sessionscribe-forensic.sh entirely**

  Use `Write` tool to overwrite the file with this exact content (NO Edit — the file goes from ~129KB to ~1.5KB):

  ```bash
  #!/bin/bash
  #
  ##
  # sessionscribe-forensic.sh v0.99.0 (deprecation shim)
  #             (C) 2026, R-fx Networks <proj@rfxn.com>
  # This program may be freely redistributed under the terms of the GNU GPL v2
  ##
  #
  # DEPRECATED: in v2.0.0 (2026-05-02) the forensic phases were merged into
  # sessionscribe-ioc-scan.sh. This shim delegates to ioc-scan's --replay
  # surface so existing one-liners continue to work during the grace period.
  # Operators should switch to:
  #
  #   sessionscribe-ioc-scan.sh --full              (detection + forensic)
  #   sessionscribe-ioc-scan.sh --replay PATH       (forensic on saved envelope)
  #
  # This shim will be removed in a future release. See PLAN.md and STATE.md.

  VERSION="0.99.0"

  # Print deprecation notice unless suppressed.
  case " $* " in
      (*\ --quiet\ *|*\ --jsonl\ *)
          : ;;
      (*)
          echo "DEPRECATED: sessionscribe-forensic.sh has been merged into sessionscribe-ioc-scan.sh (v2.0.0+)." >&2
          echo "  See https://github.com/rfxn/cpanel-sessionscribe for the new --full / --replay flags." >&2
          ;;
  esac

  # Resolve the envelope path: prefer $SESSIONSCRIBE_IOC_JSON env (the v1.x
  # chain protocol), fall back to ./SESSIONSCRIBE_IOC_JSON or the first
  # positional argument. If none, instruct the operator to use --replay PATH.
  ENVELOPE_PATH="${SESSIONSCRIBE_IOC_JSON:-}"
  if [[ -z "$ENVELOPE_PATH" ]]; then
      for arg in "$@"; do
          case "$arg" in
              (*.json|*.tgz|*.tar.gz)
                  ENVELOPE_PATH="$arg"
                  break
                  ;;
          esac
      done
  fi
  if [[ -z "$ENVELOPE_PATH" ]]; then
      echo "Error: sessionscribe-forensic.sh shim requires an envelope path." >&2
      echo "       Set SESSIONSCRIBE_IOC_JSON=<path> or run:" >&2
      echo "         sessionscribe-ioc-scan.sh --replay <envelope.json|bundle.tgz|bundle-dir>" >&2
      exit 3
  fi

  # Locate ioc-scan: sibling > PATH > current dir.
  SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)
  IOC_PATH=""
  if [[ -n "$SELF_DIR" && -f "$SELF_DIR/sessionscribe-ioc-scan.sh" ]]; then
      IOC_PATH="$SELF_DIR/sessionscribe-ioc-scan.sh"
  elif command -v sessionscribe-ioc-scan.sh >/dev/null 2>&1; then
      IOC_PATH=$(command -v sessionscribe-ioc-scan.sh)
  elif [[ -f "./sessionscribe-ioc-scan.sh" ]]; then
      IOC_PATH="./sessionscribe-ioc-scan.sh"
  else
      echo "Error: sessionscribe-ioc-scan.sh not found (sibling, PATH, or .)." >&2
      echo "       Fetch from https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh" >&2
      exit 3
  fi

  exec bash "$IOC_PATH" "$@" --replay "$ENVELOPE_PATH"
  ```

  Self-correction note: the `case " $* " in` pattern adds spaces around `$*` so word matches are space-bounded. `$*` joins args with $IFS (default space) so `set -- a b c; case " $* " in (*\ --quiet\ *)` matches if any arg is exactly `--quiet`. This is the canonical bash idiom for "did the operator pass flag X anywhere".

  Self-correction note (precedence): the `exec` line places the shim-resolved `--replay "$ENVELOPE_PATH"` AFTER `"$@"` so that ioc-scan's left-to-right last-wins case parser picks the SHIM's resolved path even if the operator also passed `--replay OTHER` in their args. This is the desired direction: the shim's whole job is envelope resolution; if the operator already knew the envelope path they would invoke ioc-scan directly. An operator passing `--replay` to the deprecation shim is a confused state — the shim's resolution wins to keep behavior predictable. All other operator args (`--quiet`, `--upload`, `--bundle-dir`, etc.) are non-conflicting and pass through cleanly.

- [ ] **Step 2: Make executable + verify shebang**

  ```bash
  chmod +x sessionscribe-forensic.sh
  bash -n sessionscribe-forensic.sh && echo OK
  # expect: OK
  head -1 sessionscribe-forensic.sh
  # expect: #!/bin/bash
  ```

- [ ] **Step 3: Verify shim behavior**

  ```bash
  wc -l sessionscribe-forensic.sh
  # expect: a number ≤ 50

  grep -c '^VERSION="0\.99\.0"' sessionscribe-forensic.sh
  # expect: 1

  grep -c 'exec.*sessionscribe-ioc-scan.sh.*--replay' sessionscribe-forensic.sh
  # expect: 1

  bash sessionscribe-forensic.sh 2>&1 | grep -c 'requires an envelope path'
  # expect: 1

  bash sessionscribe-forensic.sh /tmp/nope.json 2>&1 | grep -c 'DEPRECATED'
  # expect: 1
  ```

- [ ] **Step 4: Commit**

  ```bash
  git add sessionscribe-forensic.sh
  git commit -m "$(cat <<'EOF'
  forensic v0.99.0: replace with deprecation shim — merged into ioc-scan v2.0.0

  Phase 6 of 8 — sessionscribe-forensic.sh becomes a thin shim (~50 lines)
  that prints a one-line deprecation notice and execs:

    sessionscribe-ioc-scan.sh --replay <envelope-path>

  Envelope path resolution order:
    1. $SESSIONSCRIBE_IOC_JSON env (v1.x chain protocol, still honored)
    2. First positional arg ending in .json / .tgz / .tar.gz
    3. Error with actionable message pointing to --replay PATH

  Preserves the sh.rfxn.com / raw.githubusercontent.com URL for operators
  still running the v1.x curl one-liner — they get the deprecation banner
  and the same kill-chain output, just via the merged code path.

  --quiet and --jsonl suppress the deprecation notice so machine-piped
  consumers stay clean.

  Drops 2,719 lines (was 2,769; now ~50). All forensic logic now lives
  in sessionscribe-ioc-scan.sh.
  EOF
  )"
  ```

---

### Phase 7: Live verification on cpanel_client (host2 / lab host A)

End-to-end functional verification on the COMPROMISED canary host. Five scenarios: (1) `--triage` default produces same output shape as v1.8.2; (2) `--full` produces the same kill-chain as v1.8.2's `--chain-on-critical`; (3) `--replay <envelope.json>` reproduces the kill-chain from a saved envelope; (4) `--replay <bundle dir>` reproduces from a captured bundle; (5) `--replay <bundle.tgz>` reproduces from an extracted tarball; (6) the deprecation shim still works for operators on the legacy curl one-liner. No code changes — pure behavioral verification.

**Files:**
- Modify: none (verification only)

- **Mode**: serial-context
- **Accept**: All 6 scenarios produce expected output as detailed below; zero `unbound variable` failures; verdict box renders `ioc-scan v2.0.0`; kill-chain shows Pattern X / `ioc_cve_2026_41940_crlf_access_chain` row in PRE-DEFENSE for `--full` and replay scenarios
- **Test**: 6 scenarios in Steps 1-6; expected outputs explicitly listed
- **Edge cases**: covered by the 5 scenario variations
- **Regression-case**: N/A — refactor — Phase 7 is itself the regression coverage (six scenarios on the COMPROMISED canary host); no source-file changes

- [ ] **Step 1: Push merged v2.0.0 to a release branch (NOT main) + verify GitHub serves it from the branch**

  Pushing to `main` would immediately ship v2.0.0 to every fleet host running the curl one-liner. If any of Steps 2-6 fail, the broken build is already live. Use a release branch instead — Step 7 merges to `main` only after all six scenarios PASS.

  ```bash
  git checkout -b v2.0.0-rc 2>&1 | tail -1
  # expect: "Switched to a new branch 'v2.0.0-rc'"

  git push -u origin v2.0.0-rc 2>&1 | tail -3
  # expect: lines including "branch 'v2.0.0-rc' set up to track 'origin/v2.0.0-rc'"

  # Verify GitHub serves v2.0.0 from the branch (not main yet).
  curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" 2>&1 | grep -E '^VERSION=' | head -1
  # expect: VERSION="2.0.0"

  curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-forensic.sh?cb=$(date +%s)" 2>&1 | grep -E '^VERSION=' | head -1
  # expect: VERSION="0.99.0"

  # Confirm main still serves v1.8.2 (fleet untouched until Step 7 merge).
  curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh?cb=$(date +%s)" 2>&1 | grep -E '^VERSION=' | head -1
  # expect: VERSION="1.8.2"
  ```

  **All Phase 7 scenario curl URLs in Steps 2-6 use `v2.0.0-rc` instead of `main`.** Find-and-replace `main` → `v2.0.0-rc` in the curl URLs of Steps 2-6 before executing them.

- [ ] **Step 2: Scenario 1 — --triage default behavior**

  ```bash
  tmux send-keys -t cpanel_client 'clear; curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash 2>&1 | grep -E "Code verdict|Host verdict|reasons:|forensic_summary" | head -10' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -J -S -25 | tail -20
  # expect: Code verdict + Host verdict lines present; ZERO "forensic_summary"
  #         lines (forensic phases skipped in triage mode)
  ```

- [ ] **Step 3: Scenario 2 — --full produces kill-chain (replaces --chain-on-critical)**

  ```bash
  tmux send-keys -t cpanel_client 'clear; curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --full 2>&1 | grep -E "verdict      COMPROMISED|reasons:|pattern X|ioc_cve_2026|forensic_summary|kill-chain|bundle complete" | head -15' Enter
  sleep 90
  tmux capture-pane -t cpanel_client -p -J -S -50 | tail -40
  # expect: verdict box shows ioc-scan v2.0.0; reasons includes
  #         ioc_cve_2026_41940_crlf_access_chain; kill-chain renders
  #         Pattern X row in PRE-DEFENSE; forensic_summary signal present;
  #         bundle complete line present
  ```

- [ ] **Step 4: Scenario 3 — --replay envelope.json**

  Find the most recent envelope from Step 3's --full run, then replay it.

  ```bash
  tmux send-keys -t cpanel_client 'ls -t /var/cpanel/sessionscribe-ioc/*.json | head -1' Enter
  sleep 2
  tmux capture-pane -t cpanel_client -p -J -S -5 | tail -3
  # capture the path, then:

  tmux send-keys -t cpanel_client 'ENV=$(ls -t /var/cpanel/sessionscribe-ioc/*.json | head -1); echo "replay envelope: $ENV"; curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --replay "$ENV" 2>&1 | grep -E "Replay mode|verdict      COMPROMISED|pattern X|ioc_cve_2026|forensic_summary" | head -10' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -J -S -30 | tail -25
  # expect: "Replay mode: detection skipped" header; verdict box shows
  #         the same COMPROMISED state as the --full run; kill-chain
  #         re-renders identically; forensic_summary signal present
  ```

- [ ] **Step 5: Scenario 4 — --replay bundle dir + Scenario 5 — --replay bundle.tgz**

  ```bash
  # Bundle dir replay
  tmux send-keys -t cpanel_client 'BDIR=$(ls -td /root/.ic5790-forensic/*/ | head -1); echo "replay bundle dir: $BDIR"; curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --replay "$BDIR" 2>&1 | grep -E "Replay mode|verdict      COMPROMISED|pattern X|ioc_cve_2026" | head -8' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -J -S -20 | tail -15
  # expect: same as Step 4 output; replay resolves directory to envelope inside

  # Tarball replay (create a tarball from the bundle dir, then replay)
  tmux send-keys -t cpanel_client 'BDIR=$(ls -td /root/.ic5790-forensic/*/ | head -1); cd "$(dirname "$BDIR")" && tar -czf /tmp/replay-test.tgz "$(basename "$BDIR")"; cd -; ls -l /tmp/replay-test.tgz' Enter
  sleep 5
  tmux send-keys -t cpanel_client 'curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --replay /tmp/replay-test.tgz 2>&1 | grep -E "Replay mode|verdict      COMPROMISED|pattern X|ioc_cve_2026" | head -8' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -J -S -20 | tail -15
  # expect: same as Step 4 output; replay extracts envelope from tarball and re-runs forensic
  tmux send-keys -t cpanel_client 'rm -f /tmp/replay-test.tgz; ls /tmp/sessionscribe-replay-* 2>/dev/null | wc -l' Enter
  sleep 3
  tmux capture-pane -t cpanel_client -p -J -S -5 | tail -3
  # expect: 0 (replay tmpdir cleaned up by main flow)
  ```

- [ ] **Step 6: Scenario 6 — deprecation shim still works**

  ```bash
  tmux send-keys -t cpanel_client 'ENV=$(ls -t /var/cpanel/sessionscribe-ioc/*.json | head -1); SESSIONSCRIBE_IOC_JSON="$ENV" curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/v2.0.0-rc/sessionscribe-forensic.sh?cb=$(date +%s)" | SESSIONSCRIBE_IOC_JSON="$ENV" bash 2>&1 | grep -E "DEPRECATED|Replay mode|verdict      COMPROMISED|pattern X" | head -8' Enter
  sleep 30
  tmux capture-pane -t cpanel_client -p -J -S -25 | tail -20
  # expect: DEPRECATED banner appears once; same kill-chain output as
  #         scenario 4; shim transparently delegates to ioc-scan --replay
  ```

  Self-correction note: `curl | bash` doesn't propagate the env var to the subprocess directly because of the pipe — set `SESSIONSCRIBE_IOC_JSON` for both the curl-fed bash and any subsequent bash invocations. The shim reads it from its own environment.

- [ ] **Step 7: Acceptance gate — record results inline + merge release branch to main**

  Capture all six scenario outcomes:

  ```bash
  echo "=== Phase 7 verification summary ==="
  echo "Scenario 1 (--triage):              [PASS|FAIL]"
  echo "Scenario 2 (--full):                [PASS|FAIL]"
  echo "Scenario 3 (--replay envelope.json):[PASS|FAIL]"
  echo "Scenario 4 (--replay bundle dir):   [PASS|FAIL]"
  echo "Scenario 5 (--replay bundle.tgz):   [PASS|FAIL]"
  echo "Scenario 6 (deprecation shim):      [PASS|FAIL]"
  ```

  **If ANY scenario FAILED:** halt. Do NOT merge to main. Recovery path: reopen Phases 1-5 to fix the identified bug on the `v2.0.0-rc` branch, increment a pre-release suffix in commit messages (v2.0.0-fix1), re-run Phase 7 against the updated branch. The fleet stays on v1.8.2 throughout.

  **If ALL six scenarios PASSED:** merge `v2.0.0-rc` → `main`. This is the moment v2.0.0 ships to the fleet — confirm with the operator before executing if the operator hasn't pre-authorized.

  ```bash
  # Operator confirmation gate (if not pre-authorized for this PLAN execution).
  echo "All 6 scenarios PASS. Ready to merge v2.0.0-rc -> main?"
  echo "This will ship v2.0.0 to every fleet host on the next curl one-liner run."
  read -p "Proceed? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "Aborted by operator."; exit 0; }

  git checkout main
  git merge --ff-only v2.0.0-rc 2>&1 | tail -3
  # expect: "Updating <hash>..<hash>" and "Fast-forward"
  # If --ff-only fails (main moved meanwhile): rebase v2.0.0-rc on main, re-run scenarios

  git push origin main 2>&1 | tail -3
  # expect: lines including the new commit hash pushed to main

  # Confirm GitHub raw cache flushes within a few minutes — operators can
  # verify with cache-buster:
  curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh?cb=$(date +%s)" 2>&1 | grep -E '^VERSION=' | head -1
  # expect (within ~5 minutes): VERSION="2.0.0"
  ```

  No new commit in this phase — the merge IS the publication. Results recorded in Phase 8's docs commit message.

---

### Phase 8: Docs (STATE.md, CLAUDE.md, README.md) + CDN deploy

Update STATE.md with the v2.0.0 architecture; update CLAUDE.md with the merged-script architecture section + envelope read-after-write contract; update README.md operator-facing usage; deploy to sh.rfxn.com per the cdn-deploy reference memory; verify CDN serves v2.0.0 with sha256 parity.

**Files:**
- Modify: `STATE.md` (replace shipped-versions table + architecture diagram + envelope contract section)
- Modify: `CLAUDE.md` (add `## Merged-script architecture` section)
- Modify: `README.md` (replace operator one-liners with --full/--replay examples; add deprecation note for forensic.sh)

- **Mode**: serial-context
- **Accept**: `grep -c 'sessionscribe-ioc-scan.sh.*\\*\\*2\\.0\\.0\\*\\*' STATE.md` returns 1; `grep -c 'sessionscribe-forensic.sh.*\\*\\*0\\.99\\.0\\*\\*.*shim' STATE.md` returns 1; `grep -c '## Merged-script architecture' CLAUDE.md` returns 1; `grep -c -- '--full' README.md` returns ≥3; `grep -c -- '--replay' README.md` returns ≥2; sha256 of locally-staged ioc-scan matches sha256 of CDN-served ioc-scan after deploy
- **Test**: Step 5 sha256 parity check; expected output: matching hashes
- **Edge cases**: README.md may not exist or may be sparse — verify with `ls -la README.md` first; if it's a stub, expand it appropriately. README.md exists per repo dir listing
- **Regression-case**: N/A — docs — STATE/CLAUDE/README updates only; CDN deploy is non-source side-effect; live behavior already verified in Phase 7

- [x] **Step 1: Update STATE.md shipped-versions table + architecture**

  Read the current shipped-versions table and architecture section first, then rewrite. The post-merge state:

  ```markdown
  | sessionscribe-ioc-scan.sh | **2.0.0** | (architectural break) Merged sessionscribe-forensic.sh inline. Detection runs in default --triage mode (envelope-only); --full adds forensic phases (defense / offense / reconcile / kill-chain / bundle); --replay PATH replays forensic phases against a saved envelope (.json), bundle directory, or tarball (.tgz). Removed: chain_forensic_dispatch, fetch_forensic_remote (no remote fetch needed). --chain-forensic, --chain-upload, --chain-on-critical preserved as back-compat aliases. Envelope written-then-read on every --full run (same code path as --replay) — envelope contract is now a same-script invariant rather than cross-script handshake. Prior shipped: v1.8.2 (gawk-3.x compat at 6 sites + 5 sites), v1.8.0 (CRLF entry primitive + Pattern A anti-forensic), v1.7.0 (Pattern H + Pattern I). |
  | sessionscribe-forensic.sh | **0.99.0 (deprecation shim)** | ~50-line shim that prints a one-line deprecation notice and execs `sessionscribe-ioc-scan.sh --replay <path>`. Preserves the CDN URL for grace-period clients on the v1.x curl one-liner. --quiet and --jsonl suppress the banner. Will be removed in a future release. |
  | sessionscribe-mitigate.sh | **0.4.0** | (unchanged) anti-forensic awareness in `phase_preflight`. |
  ```

  Replace the architecture diagram section with:

  ```markdown
  ## Architecture

  Single-script unified detection + forensic + replay (post-merge v2.0.0):

  ```
                       ┌──────────── sessionscribe-ioc-scan.sh ───────────┐
                       │                                                   │
  --triage (default) ──┤  detection ──► /var/cpanel/sessionscribe-ioc/    │
                       │                <run_id>.json (envelope)           │
                       │                                                   │
  --full              ─┤  detection ──► envelope ──► forensic phases:    │
                       │                                defense + offense │
                       │                                + reconcile +     │
                       │                                kill-chain +      │
                       │                                bundle + upload   │
                       │                                                   │
  --replay PATH       ─┤  envelope (from PATH) ──► forensic phases       │
                       │                                                   │
                       └───────────────────────────────────────────────────┘
  ```

  Envelope is written to disk BEFORE forensic phases run (in --full mode) so
  `read_iocs_from_envelope` reads from disk — the same code path used by
  --replay. This makes the envelope contract a same-script invariant.

  sessionscribe-forensic.sh is a v0.99.0 deprecation shim that delegates to
  --replay; it preserves the v1.x curl one-liner URL during the grace period.
  ```

- [x] **Step 2: Append `## Merged-script architecture` section to CLAUDE.md**

  Location: end of CLAUDE.md, before the verification gate section (or append at end if the verification gate is already last).

  ```markdown

  ---

  ## Merged-script architecture (v2.0.0+)

  As of v2.0.0, `sessionscribe-forensic.sh` is merged into
  `sessionscribe-ioc-scan.sh`. The two-script chain (with envelope-as-IPC)
  is replaced by a single script with three operator-facing modes:

  | Mode | Flag | What it does |
  |---|---|---|
  | Triage (default) | (none) or `--triage` | Detection only; writes envelope to `/var/cpanel/sessionscribe-ioc/<run_id>.json`. No defense timeline, kill-chain, or bundle. |
  | Full | `--full` | Detection + forensic phases (defense / offense / reconcile / kill-chain / bundle / upload). |
  | Replay | `--replay PATH` | Skip detection; replay forensic against a saved envelope (`.json`), bundle directory, or `.tgz`. |

  ### Envelope read-after-write contract

  In `--full` mode the envelope is written to disk BEFORE forensic phases
  run, then `phase_offense` reads it back via the same code path used by
  `--replay`. This makes the envelope contract a same-script invariant —
  any divergence between detection's signals and forensic's view of them
  is impossible by construction (single source, single read path).

  ### Back-compat aliases

  The v1.x chain flags continue to work — they map to `--full` plus the
  matching gate flag:

  | v1.x flag | v2.0.0 equivalent |
  |---|---|
  | `--chain-forensic` | `--full` (no host-verdict gate) |
  | `--chain-on-critical` | `--full` + `CHAIN_ON_CRITICAL=1` (skip if HOST_VERDICT != COMPROMISED) |
  | `--chain-upload` | `--full --upload` |

  ### Forensic-area signals

  Forensic phases emit signals via `emit_signal()` (a thin wrapper around
  the canonical `emit()`) under these new `area` values: `defense`,
  `offense`, `reconcile`, `bundle`, `upload`, `summary`. The severity
  vocabulary maps:

  | forensic severity | emit() severity | weight |
  |---|---|---|
  | `pass`, `info` | `info` | 0 |
  | `warn` | `warning` | 4 |
  | `fail` | `strong` | 10 |

  All forensic findings flow into the unified `SIGNALS[]` stream and
  appear in the same envelope as detection signals.

  ### Deprecation shim

  `sessionscribe-forensic.sh` is now a ~50-line v0.99.0 shim that prints
  a one-line deprecation notice and `exec`s
  `sessionscribe-ioc-scan.sh --replay <path>`. It preserves the
  `sh.rfxn.com` and `raw.githubusercontent.com` URLs for operators still
  on the v1.x curl one-liner. The shim will be removed in a future release.
  ```

- [x] **Step 3: Update README.md operator-facing usage**

  Read README.md first to understand current structure, then rewrite the operator-usage section. Replace any `--chain-forensic`/`--chain-on-critical` examples with `--full`/`--replay`. Add an explicit `### Deprecation: sessionscribe-forensic.sh` subsection noting the shim and grace period.

  Concrete edits (use Edit, not Write — preserve unrelated sections):
  - Find the `Fleet sweep` or `Operator usage` section
  - Replace the `--chain-on-critical --chain-upload --since 14` one-liner with `--full --upload --since 14`
  - Add a `--replay` example showing how to re-render a kill-chain from a saved envelope
  - Add a `### Deprecation: sessionscribe-forensic.sh` subsection at the end of the operator section

- [x] **Step 4: Commit docs**

  ```bash
  git add STATE.md CLAUDE.md README.md
  git commit -m "$(cat <<'EOF'
  docs: v2.0.0 merged-script architecture (STATE + CLAUDE + README)

  Phase 8 of 8 — operator-facing documentation for the merged script.

  STATE.md:
    - shipped-versions table reflects ioc-scan v2.0.0, forensic v0.99.0
      deprecation shim, mitigate v0.4.0 (unchanged)
    - architecture diagram: single-script with --triage/--full/--replay
    - envelope read-after-write contract documented as same-script invariant

  CLAUDE.md:
    - new "Merged-script architecture (v2.0.0+)" section
    - mode comparison table (triage / full / replay)
    - envelope read-after-write contract explanation
    - back-compat alias mapping (--chain-* -> --full + gate)
    - forensic-severity -> emit() severity weight map
    - deprecation shim documentation

  README.md:
    - operator examples switched to --full / --replay
    - new "Deprecation: sessionscribe-forensic.sh" subsection

  Phase 7 live verification results (from Phase 7 Step 7):
    Scenario 1 (--triage):              PASS
    Scenario 2 (--full):                PASS
    Scenario 3 (--replay envelope.json):PASS
    Scenario 4 (--replay bundle dir):   PASS
    Scenario 5 (--replay bundle.tgz):   PASS
    Scenario 6 (deprecation shim):      PASS
  EOF
  )"
  git push origin main 2>&1 | tail -3
  # expect: lines including the new commit hash pushed to main
  ```

- [x] **Step 5: CDN deploy + sha256 parity**

  Per the cdn-deploy reference memory:

  ```bash
  command cp -fp sessionscribe-ioc-scan.sh /root/admin/work/downloads/sessionscribe-ioc-scan.sh
  command cp -fp sessionscribe-forensic.sh /root/admin/work/downloads/sessionscribe-forensic.sh
  /root/bin/sync_local-remote
  # expect: rsync output showing both files transferred to rfxncom@209.126.24.12

  # Verify CDN parity
  curl -sS -o /tmp/cdn-ioc -w 'HTTP=%{http_code} bytes=%{size_download}\n' "https://sh.rfxn.com/sessionscribe-ioc-scan.sh?nocache=$(date +%s)"
  # expect: HTTP=200 bytes=<>0

  curl -sS -o /tmp/cdn-forensic -w 'HTTP=%{http_code} bytes=%{size_download}\n' "https://sh.rfxn.com/sessionscribe-forensic.sh?nocache=$(date +%s)"
  # expect: HTTP=200 bytes=<>0

  sha256sum /tmp/cdn-ioc sessionscribe-ioc-scan.sh
  # expect: identical hashes (column 1 of both lines must match)

  sha256sum /tmp/cdn-forensic sessionscribe-forensic.sh
  # expect: identical hashes

  head -4 /tmp/cdn-ioc /tmp/cdn-forensic
  # expect: ioc shows "v2.0.0" in comment header; forensic shows "v0.99.0 (deprecation shim)"

  # Smoke from a fresh CDN fetch on the lab host
  tmux send-keys -t cpanel_client 'clear; curl -fsSL "https://sh.rfxn.com/sessionscribe-ioc-scan.sh?cb=$(date +%s)" | bash -s -- --full --no-bundle 2>&1 | grep -E "ioc-scan v2\.0\.0|verdict      COMPROMISED|pattern X|ioc_cve_2026" | head -5' Enter
  sleep 60
  tmux capture-pane -t cpanel_client -p -J -S -15 | tail -10
  # expect: verdict box shows "ioc-scan v2.0.0"; Pattern X row present
  ```

  No additional commit — CDN deploy is a side-effect.

  **Phase 8 result:** STATUS: DONE — All 5 steps complete. All accept criteria pass.
  Commit: a754579. CDN sha256 parity verified. CDN smoke test confirms v2.0.0 + Pattern X.

---
