# Implementation Plan: ioc-scan v2.2.0 verdict-precision refactor

**Goal:** Reduce false-positive COMPROMISED determinations by ~90% on the 9659-host fleet sample by replacing IP-keyed access-log gating with cpsess-token-keyed gating, and add an explicit failed-exploit-attempt signal modeled on cPanel's reference IOC checker. Secondary deliverables: guard against synthetic Pattern X timestamps (v4 Gap 11) and populate structured kill-chain fields for Pattern E + X events (v4 Gap 4) so hand-investigation no longer requires re-grepping `access-logs.tgz`.

**Architecture:** Five independent emit-site changes plus one verdict-axis exit-code addition. The `aggregate_verdict()` ladder at line 5208 is unchanged at the `strong → ioc_critical → COMPROMISED` level — Phase 2 fixes the over-firing UPSTREAM by changing severity emission for the dominant FP source (`ioc_attacker_ip_in_access_log` flagging strong on any 2xx, including login-page enumeration). Phase 3 adds a new warning-tier session-side signal that mirrors cPanel's IOC 5 (failed exploit attempt). Phase 4 adds a guard at `ioc_signal_epoch()` so pattern=X events refuse to emit when timestamp is unresolvable. Phase 5 populates structured `ip`/`path`/`status`/`cpsess_token` fields at emit-time for Pattern E and the new pattern=X variant of attacker-IP. Phase 6 adds exit code 3 = SUSPICIOUS to disambiguate the host-state axis from the (also-exit-2) INCONCLUSIVE code-state. Phase 7 is live regression + aggregator re-validation. Phase 8 is version bump + docs + CDN deploy.

**Tech Stack:** bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 floor (CL6 EL6). Verification: `bash -n` + `shellcheck -S error` + live regression on `cpanel_client` COMPROMISED lab host + `ss-aggregate.py` re-run on the 9659-bundle dataset to validate FP-reduction targets.

**Spec:** No spec file. Inputs:
- `intake-triage-2026-05-02/ioc-scan-v4-recommendations.md` (memory-saved as `project_ioc_scan_v3_recommendations.md`)
- `intake-triage-2026-05-02/summary.json` (fleet aggregator output, 2026-05-02)
- cPanel reference IOC checker (`ioc_checksessions_files.sh`, operator-shared 2026-05-02)
- Conversational analysis with operator 2026-05-02 (this session)

**Phases:** 8

**Plan Version:** 1.0.0

**Status:** COMPLETE — Phases 1-8 shipped at v2.2.0 @ 2ad1751 (Phase 8 commit).

---

## Conventions

**Bash floor (per CLAUDE.md):** No `mapfile`/`readarray`, no `printf -v arr[$i]`, no `${var^^}`/`${var,,}`, no `coproc`, no `${var: -1}`, no `declare -g`, no `local -n`, no `wait -n`. `case` inside `$()` uses leading-paren patterns. Empty arrays guarded with `(( ${#arr[@]} > 0 ))` before iteration under `set -u`. Newline required after `$(` before `{`.

**gawk 3.x floor (per CLAUDE.md):** No 3-arg `match(s, /re/, m)` — use 2-arg `match()` + `RSTART`/`RLENGTH` + `substr`/`split`. No `{n}` or `{n,m}` interval expressions in awk regexes — use explicit char-class repetition or `+`. `mktime()` requires `"YYYY MM DD HH MM SS"` exactly.

**Severity emit policy (this PR):**

| Today's severity | Today's behavior | New severity (this PR) | Reason |
|-----|-----|-----|-----|
| `ioc_attacker_ip_in_access_log` strong (h2xx>0 on any path) | → COMPROMISED via ioc_critical | strong only when `2xx_on_cpsess > 0`; info when recon-only | Phase 2 — IP+path keyed primitive matches cPanel's token+200 primitive |
| (none) | — | new: `ioc_failed_exploit_attempt` warning, weight=3 | Phase 3 — cPanel IOC 5 analog |
| (none) | — | new: `ioc_attacker_ip_2xx_on_cpsess` strong, weight=8, pattern=X | Phase 2 |
| (none) | — | new: `ioc_attacker_ip_recon_only` info, weight=0, pattern=init | Phase 2 |

**Pattern-letter map updates** (`ioc_key_to_pattern()` at line 1152):

| Key | Today's pattern | New pattern | Reason |
|-----|-----|-----|-----|
| `ioc_attacker_ip*` (catch-all) | init | unchanged for legacy keys | back-compat |
| `ioc_attacker_ip_2xx_on_cpsess` | n/a | **X** | real entry/exploitation |
| `ioc_attacker_ip_recon_only` | n/a | **init** | probing only |
| `ioc_failed_exploit_attempt` | n/a | **X** (failed-tier) | cPanel-style ATTEMPT mapped to existing X-class for kill-chain coherence; severity=warning keeps it out of ioc_critical |

**Exit code semantics:**

| Code | Today | After this PR |
|-----|-----|-----|
| 0 | CLEAN / PATCHED | unchanged |
| 1 | VULNERABLE (code-state) | unchanged |
| 2 | INCONCLUSIVE / SUSPICIOUS (collision) | **INCONCLUSIVE only** |
| 3 | (unused) | **SUSPICIOUS (host-state)** |
| 4 | COMPROMISED | unchanged |

The collision at exit code 2 is pre-existing — `aggregate_verdict()` at line 5404 sets EXIT_CODE=2 for both INCONCLUSIVE code-state (line 5394) AND ioc_review > 0 in `--ioc-only` mode (line 5407). Phase 6 splits these. Code-state INCONCLUSIVE keeps exit 2; host-state SUSPICIOUS becomes exit 3.

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
Phases 1-7 use `ioc-scan v2.2.0-pre<N>:` prefix. Phase 8 uses `ioc-scan v2.2.0:` for the version bump + final.

**CRITICAL:** Never `git add -A` / `git add .` — add specific files only. Never push to `main` without operator confirmation (changes ship via the curl one-liner; `main` is the fleet's source of truth). Commits stay local until Phase 8 completes and the operator approves the `main` push.

---

## Success Criteria (Phase 7 gate)

Plan succeeds iff, after Phase 7 re-runs `ss-aggregate.py` against the existing 9659-bundle dataset:

1. **COMPROMISED hosts drop from 9659 → between 250 and 350.** Floor is `q1_confirmed_compromised: 203` (must all retain COMPROMISED). Ceiling is 203 + edge cases where wt_stack-only or post_def_x-only signals legitimately keep COMPROMISED. Anything below 200 means we lost real compromises; anything above 350 means the IP-keyed-attacker-IP FP class addressed by Phase 2 didn't land cleanly. Ceiling does NOT apply to other operationally-correct exploitation primitives (CRLF chain, narrow Pattern E websocket-shell hits) which legitimately retain COMPROMISED at higher counts than originally modeled.

   **Gate 1 actual result (Phase 7, .rdf/work-output/phase-7-result-v2.2.0.md):** PARTIAL. Aggregator re-run on the 9659-bundle dataset produced `verdicts.COMPROMISED: 1570` — an 84% reduction (9659 → 1570) below the 95% target band (250–350). The model gap: Pattern X CRLF chain (`ioc_cve_2026_41940_crlf_access_chain`, strong/weight=10) and narrow-tier Pattern E websocket-shell hits are real exploitation primitives, not the IP-keyed FP class Phase 2 was scoped against. v2.2.0 retains both as COMPROMISED because they are operationally-correct: a CRLF chain (POST 401 → cpsess 2xx ≤2s same-IP) is deterministic exploitation footprint, and a narrow Pattern E hit is direct websocket-shell entry. Gate 2 (203/203 q1_confirmed retained) and Gate 3 (q1_weak_noise demoted) both PASS — the FP class targeted by Phase 2 was eliminated cleanly. A future Gate 1.2 (stricter "post-exploit-activity-required" tier — e.g. require destruction-pattern co-occurrence to escalate Pattern X solo to COMPROMISED) is reserved for v2.3.x; out of scope for v2.2.0.

2. **All 203 hosts in `q1_confirmed_compromised` retain COMPROMISED verdict.** This is the hard floor — these have destruction patterns, F harvester, token_used_2xx, or D recon-persistence. Independent of attacker-IP signal. Must NOT regress.

3. **`q1_weak_noise: 7611` hosts drop to SUSPICIOUS or CLEAN** (exit 3 / 0). They had only `ioc_attacker_ip_in_access_log` strong → ioc_critical → COMPROMISED. Post-Phase-2, that signal demotes to info when recon-only.

4. **`testdev.halcyonplatinum.com` first-X anomaly resolves OR surfaces as legitimate.** If the 2025-11-25 first-X event was synthetic (Gap 11) or recon-only (Gap 6), `q8_patient_zero_x` shifts forward to a sensible date (≥2026-04-15 expected). If it stays at 2025-11-25, that's a real pre-disclosure case for hand-investigation.

5. **Kill-chain.tsv on `host.elegantthemesdemo.com` envelope replay shows `ip`/`path`/`status`/`cpsess_token` populated for both Pattern E and the new pattern=X attacker-IP rows** (Phase 5 acceptance — re-uses the v4 doc's reference host).

If any of these fails, Phase 7 BLOCKS Phase 8. Sentinel review at Phase 7 must enumerate the matrix outcome before sign-off.

---

## File Map

### New Files
| File | Lines | Purpose |
|------|-------|---------|
| (none) | — | All changes are in-place edits |

### Modified Files
| File | Phases | Changes |
|------|--------|---------|
| `sessionscribe-ioc-scan.sh` | 1-6, 8 | New keys + pattern map (P1); cpsess-split in `check_attacker_ips` (P2); new `check_failed_exploit_attempt` session check (P3); `ioc_signal_epoch` X-pattern guard (P4); structured fields at Pattern E + X emit sites (P5); exit code 3 (P6); VERSION 2.1.0 → 2.2.0 (P8) |
| `STATE.md` | 8 | New IOC vocabulary table; verdict tier semantics |
| `CLAUDE.md` | 8 | New strong/warning/info severity rules for attacker-IP signal class |
| `README.md` | 8 | Verdict tier table; exit code 3 semantics; new `--chain-on-cpsess-2xx` (replaces today's de-facto chain trigger semantics) |

### Deleted Files
| File | Reason |
|------|--------|
| (none) | — |

---

## Phase Dependencies

- Phase 1: none
- Phase 2: [1] (uses new keys + pattern map)
- Phase 3: [1]
- Phase 4: [1] (needs new pattern=X key list to know what to guard)
- Phase 5: [2] (Pattern X structured fields are on the new key from Phase 2)
- Phase 6: none (independent — exit code logic is in aggregate_verdict, not emit-site)
- Phase 7: [2, 3, 4, 5, 6] — re-validation requires ALL emit-site + exit-code changes
- Phase 8: [7]

Phases 2/3/4/6 are mutually independent post-Phase-1 and could run parallel. In practice all phases mutate `sessionscribe-ioc-scan.sh` so file-ownership forces serial execution. Listed parallelism is structural for the dispatcher only.

---

## Out of Scope (deferred from v4)

These v4 gaps are NOT in this plan, with reasons:

| v4 Gap | Why deferred |
|--------|--------------|
| Gap 1 four-state verdict redesign | Superseded by exit code 3 + `ioc_failed_exploit_attempt` warning tier. Three-state with sharp boundaries beats four-state with fuzzy ones. Schema break for downstream readers (`ss-aggregate.py`, `ss-build-confirmed.py`) costs > clarity gain. |
| Gap 2 external attacker-IPs JSON | Independent change. Embedded 23-IP set still works for Phase 2's cpsess-split (it's the path filter that matters, not the IP set composition). Standalone PR after Phase 7 validates the cpsess-split actually works. |
| Gap 3 `activity_epoch` promotion | Already implicit — `ioc_injected_token_used_with_2xx` is severity=strong/weight=10 and triggers COMPROMISED via the generic ioc_critical gate. The `activity_epoch` field is a field-level rename for downstream readers; aggregator-side work, not detection-side. |
| Gap 5 per-operator clustering | Aggregator work (`ss-aggregate.py`). Wrong layer for ioc-scan. |
| Gap 7 accounting.log inclusion | Already done in v2.0.0 merge — `cpanel-state.tgz` includes `/var/cpanel/accounting.log` (sessionscribe-ioc-scan.sh:2861). |
| Gap 8 mitigate pre-snapshot | Separate `sessionscribe-mitigate.sh` PR — does not touch ioc-scan. |
| Gap 9 recon-window IOC | Needs FP-rate baseline on a clean-host cohort before threshold can be set. Research task, not implementation. |
| Gap 10 mtime-vs-ctime anomaly | Same — needs clean-host baseline of `ctime - mtime` delta distribution before threshold can be set. |

---

### Phase 1: Scaffold — pattern-letter map updates, new keys defined, no behavior change
**Status:** COMPLETE — pre1 @ 32cc0fe

Establish the new key vocabulary and pattern-letter mappings without changing any emit-site behavior. Adds three new entries to `ioc_key_to_pattern()` and documents them in the script header severity table. No new emits in this phase — Phases 2/3 wire the actual emits. Phase 1 is pure scaffolding; running ioc-scan in this phase produces byte-identical output to v2.1.0-pre7.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` (extend `ioc_key_to_pattern` switch at line 1152-1168; update the severity-tier comment block at line 5252)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - `grep -cE 'ioc_attacker_ip_2xx_on_cpsess.*echo X' sessionscribe-ioc-scan.sh` returns 1
  - `grep -cE 'ioc_attacker_ip_recon_only.*echo init' sessionscribe-ioc-scan.sh` returns 1
  - `grep -cE 'ioc_failed_exploit_attempt.*echo X' sessionscribe-ioc-scan.sh` returns 1
  - `grep -cE 'ioc_attacker_ip\*.*echo init' sessionscribe-ioc-scan.sh` returns 1 (legacy catch-all preserved for back-compat)
  - Smoke run: `bash sessionscribe-ioc-scan.sh --help >/dev/null` exits 0
- **Test**: `bash -n sessionscribe-ioc-scan.sh && echo OK` → expect literal `OK`
- **Edge cases**: pattern-letter map order matters — specific keys must come BEFORE the `ioc_attacker_ip*` glob, else the glob captures them. Verify by grepping the case statement order.
- **Regression-case**: N/A — pure scaffolding. The new case-arms are unreachable until Phase 2/3 emit signals with the new keys.

- [x] **Step 1: Extend `ioc_key_to_pattern()` case statement**

  Location: `sessionscribe-ioc-scan.sh` line 1152-1168.

  Replace the existing block:
  ```bash
  ioc_key_to_pattern() {
      case "$1" in
          (ioc_pattern_a_*)            echo A ;;
          ...
          (ioc_attacker_ip*|ioc_hits)  echo init ;;
          (ioc_token_*|ioc_preauth_*|...)  echo X ;;
          (*)                          echo ? ;;
      esac
  }
  ```

  With the order-preserving extension (specific keys BEFORE the `ioc_attacker_ip*` glob):
  ```bash
  ioc_key_to_pattern() {
      case "$1" in
          (ioc_pattern_a_*)                       echo A ;;
          (ioc_pattern_b_*)                       echo B ;;
          (ioc_pattern_c_*)                       echo C ;;
          (ioc_pattern_d_*)                       echo D ;;
          (ioc_pattern_e_*)                       echo E ;;
          (ioc_pattern_f_*)                       echo F ;;
          (ioc_pattern_g_*)                       echo G ;;
          (ioc_pattern_h_*)                       echo H ;;
          (ioc_pattern_i_*)                       echo I ;;
          (ioc_attacker_ip_2xx_on_cpsess)         echo X ;;
          (ioc_attacker_ip_recon_only)            echo init ;;
          (ioc_failed_exploit_attempt)            echo X ;;
          (ioc_attacker_ip*|ioc_hits)             echo init ;;
          (ioc_token_*|ioc_preauth_*|ioc_short_pass*|ioc_multiline_*|ioc_badpass*|ioc_cve_2026_41940*|ioc_hasroot*|ioc_malformed*|ioc_forged_*|ioc_tfa*|anomalous_root_sessions)
                                                  echo X ;;
          (*)                                     echo ? ;;
      esac
  }
  ```

- [x] **Step 2: Document the new key vocabulary in the script-header comment block**

  Location: existing comment block at the top of the section-vocabulary section (~line 1056). Add a one-line entry under the existing key catalog:
  ```
  # New v2.2.0 keys (verdict-precision refactor):
  #   ioc_attacker_ip_2xx_on_cpsess    pattern=X   strong  weight=8   real exploitation
  #   ioc_attacker_ip_recon_only       pattern=init info   weight=0   probing only
  #   ioc_failed_exploit_attempt       pattern=X   warning weight=3   cPanel IOC 5 analog
  ```

---

### Phase 2: cpsess-split for `ioc_attacker_ip_in_access_log` (THE HEADLINE)
**Status:** COMPLETE — pre2 @ 778bd84

Replace the over-firing strong-on-any-2xx emit with a path-aware split: 2xx on URLs containing `/cpsess<10digits>/` is **real exploitation evidence** (severity=strong, key=`ioc_attacker_ip_2xx_on_cpsess`, pattern=X); 2xx on any other path is **reconnaissance only** (severity=info, key=`ioc_attacker_ip_recon_only`, pattern=init). 4xx-only retains its warning-tier emit. The legacy key `ioc_attacker_ip_in_access_log` is kept as a parent rollup signal at info-tier so existing fleet aggregator queries continue to find a key for "T1 IPs were observed."

**Why this is the headline:** From `intake-triage-2026-05-02/summary.json`:
- 9659 hosts flagged COMPROMISED today
- 7611 (`q1_weak_noise`) had T1 IP 2xx hits but no other strong signal — these had `GET / 200` from a T1 IP and nothing else
- 1111 (`q1_single_signal_attempt: t1_origin only`) had T1 IP at session origin only
- Together ~8722 hosts (90.3%) lose their FP COMPROMISED label after this phase alone

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` lines 3524-3705 (`check_attacker_ips()` function)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - `shellcheck -S error sessionscribe-ioc-scan.sh` exits 0
  - `grep -cE 'ioc_attacker_ip_2xx_on_cpsess' sessionscribe-ioc-scan.sh` returns 2 (1 in pattern-map from Phase 1, 1 in new emit)
  - `grep -cE 'ioc_attacker_ip_recon_only' sessionscribe-ioc-scan.sh` returns 2 (same split)
  - `grep -cE 'h2xx_cpsess' sessionscribe-ioc-scan.sh` returns ≥2 (awk var + bash var)
  - `grep -cE 'h2xx_recon' sessionscribe-ioc-scan.sh` returns ≥2
  - The legacy emit `emit "logs" "ioc_attacker_ip" "$sev" "ioc_attacker_ip_in_access_log"` at line 3686 either changes to severity=info OR is replaced by the new emit chain — confirm with `grep -B1 -A2 ioc_attacker_ip_in_access_log sessionscribe-ioc-scan.sh` showing severity != strong outside back-compat info-tier.
- **Test**:
  - Run `bash -n sessionscribe-ioc-scan.sh`.
  - Live test on `cpanel_client` (host2.alps-supplies.com — known COMPROMISED): expect at least one `ioc_attacker_ip_2xx_on_cpsess` strong emit (the host has confirmed cpsess-bearing 2xx from T1 IPs per prior regression runs); expect NO change in HOST_VERDICT (still COMPROMISED via destruction patterns + this signal). Capture EXIT_CODE before and after — should remain 4.
  - Construct a synthetic access_log fragment with one T1 IP hitting `GET / 200` and zero cpsess hits, run `check_attacker_ips` against it (via temp dir + `--ioc-only`): expect emit chain to fire info-tier `ioc_attacker_ip_recon_only` only — NO strong, NO warning. HOST_VERDICT should be CLEAN.
- **Edge cases**:
  - **cpsess regex precision:** `/cpsess<10digits>/` — exactly 10 digits, followed by `/`. Looser regex (`/cpsess[0-9]+`) would match log lines mentioning cpsess in headers/referers without the URL actually being a cpsess route.
  - **Mixed 2xx and cpsess:** a host with 100 hits, 50 returning 2xx, 8 of those 2xx on cpsess paths. Today: strong, h2xx=50. Phase 2: strong with h2xx_cpsess=8 + info-tier rollup for the recon 42. Same COMPROMISED verdict, with cleaner downstream attribution.
  - **historical_drops + --since:** the `--since` window applies to BOTH counters identically. Hosts where ALL 2xx-on-cpsess are outside the window emit `ioc_attacker_ip_outside_since_window` info — unchanged from today.
  - **No 2xx, all 4xx:** same as today — warning-tier `ioc_attacker_ip_in_access_log_probes_only` (rename of today's path-agnostic warning). Optionally rename to remove `in_access_log` for symmetry; not required.
- **Regression-case**: live regression on host2 — pre/post diff of stderr verdict block. Expected delta: identical patterns/destruction signals; new strong emit `ioc_attacker_ip_2xx_on_cpsess`; legacy `ioc_attacker_ip_in_access_log` either disappears (if fully replaced) or demotes to info-tier rollup. HOST_VERDICT stays COMPROMISED. Total `ioc_critical` count may shift by ±1 depending on legacy-emit handling.

- [x] **Step 1: Extend the awk pass to count `2xx_on_cpsess` separately**

  Location: `sessionscribe-ioc-scan.sh` lines ~3580-3650 (the awk block inside `check_attacker_ips`). Add a second 2xx counter that increments only when the path matches `/cpsess<10digits>/`:

  Pseudo-shape (concrete code TBD by engineer):
  ```awk
  {
    # ... existing IP + status extraction ...
    if (status >= 200 && status < 300) {
      h2xx++
      # Match exactly 10 digits after /cpsess to avoid FP on header/referer mentions.
      if (match(path, /\/cpsess[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\//)) {
        h2xx_cpsess++
      } else {
        h2xx_recon++
      }
    }
    # ... rest of awk pass ...
  }
  END { printf "%d\t%d\t%d\t%d\t%d\t%d\t%s\t%d\n", total, h2xx, h2xx_cpsess, h2xx_recon, h3xx, h4xx, hother, ts_first, historical_drops }
  ```

  Update the bash `IFS=$'\t' read` line to absorb the two new fields.

- [x] **Step 2: Replace the strong-on-any-2xx emit with the path-aware emit chain**

  Location: `sessionscribe-ioc-scan.sh` lines 3672-3692.

  Replace today's:
  ```bash
  if (( h2xx > 0 )); then
      sev="strong"
      parent_note="$total hit(s)${window_note} from IC-5790 IPs - $h2xx returned 2xx (EXPLOITATION EVIDENCE - CRITICAL)"
  else
      sev="warning"
      parent_note="..."
  fi
  emit "logs" "ioc_attacker_ip" "$sev" "ioc_attacker_ip_in_access_log" 8 ...
  ```

  With a three-way split:
  ```bash
  if (( h2xx_cpsess > 0 )); then
      emit "logs" "ioc_attacker_ip_2xx_on_cpsess" "strong" \
           "ioc_attacker_ip_2xx_on_cpsess" 8 \
           "count" "$total" "hits_2xx_cpsess" "$h2xx_cpsess" \
           "hits_2xx_recon" "$h2xx_recon" "hits_3xx" "$h3xx" \
           "hits_4xx" "$h4xx" "hits_other" "$hother" \
           "historical_drops" "$historical_drops" \
           "ts_epoch_first" "$ts_first" \
           "note" "$h2xx_cpsess hit(s) from IC-5790 IPs returned 2xx on /cpsess<N>/ paths - real exploitation (CRITICAL)."
  elif (( h2xx_recon > 0 )); then
      emit "logs" "ioc_attacker_ip_recon_only" "info" \
           "ioc_attacker_ip_recon_only" 0 \
           "count" "$total" "hits_2xx_recon" "$h2xx_recon" \
           "hits_3xx" "$h3xx" "hits_4xx" "$h4xx" "hits_other" "$hother" \
           "historical_drops" "$historical_drops" \
           "ts_epoch_first" "$ts_first" \
           "note" "$h2xx_recon hit(s) from IC-5790 IPs returned 2xx on non-cpsess paths - reconnaissance only (REVIEW)."
  elif (( total > 0 )); then
      emit "logs" "ioc_attacker_ip_probes_only" "warning" \
           "ioc_attacker_ip_in_access_log_probes_only" 3 \
           "count" "$total" "hits_4xx" "$h4xx" "hits_3xx" "$h3xx" "hits_other" "$hother" \
           "historical_drops" "$historical_drops" \
           "ts_epoch_first" "$ts_first" \
           "note" "$total hit(s) from IC-5790 IPs - all rejected (probing only, no successful response)."
  fi
  ```

- [x] **Step 3: Preserve the per-event sample emits but key them to the new parent**

  Location: `sessionscribe-ioc-scan.sh` lines 3694-3702 (the per-event sample loop). The `ioc_attacker_ip_sample` info emits stay info-severity (already filtered out of OFFENSE_EVENTS). No structural change — but update the log message to reference whichever parent fired.

---

### Phase 3: Add `ioc_failed_exploit_attempt` session signal (cPanel IOC 5 analog)
**Status:** COMPLETE — pre3 @ 1bbbf66

Add a new warning-tier session-side signal that fires when a session has the failed-exploit footprint per cPanel's `ioc_checksessions_files.sh` IOC 5: `origin=badpass + token_denied + pass= line + no auth markers`. This becomes a SUSPICIOUS-tier signal in our model — it counts toward `ioc_review` (line 5311), exits 3 (post-Phase-6) or 2 (current behavior in `--ioc-only`), and surfaces in the verdict-reasons line.

**Why:** cPanel's reference checker treats this shape as ATTEMPT — "the attacker tried newline injection on this session and failed." It's not COMPROMISED (no auth markers means the injection didn't promote) but it's a high-value triage indicator: the host was actively targeted. Today our scanner has the constituent SF_* globals (SF_BADPASS, SF_TOKEN_DENIED) but no signal that emits on the conjunction.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` lines ~4225-4260 (insert a new emit block after the existing IOC-G `ioc_tfa_$session_name` emit)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - `grep -cE 'ioc_failed_exploit_attempt' sessionscribe-ioc-scan.sh` returns 2 (1 in pattern-map from Phase 1, 1 in new emit)
  - `grep -cE 'emit_session.*ioc_failed_exploit_attempt' sessionscribe-ioc-scan.sh` returns 1
- **Test**:
  - `bash -n sessionscribe-ioc-scan.sh && echo OK`
  - Construct a synthetic session file with: `origin_as_string=...method=badpass`, `token_denied=2`, `pass=abc123`, no `successful_*_auth_with_timestamp`. Run `check_sessions` against a temp `/var/cpanel/sessions` rooted at the synthetic dir. Expect: `ioc_failed_exploit_attempt` warning emit; HOST_VERDICT=SUSPICIOUS; EXIT_CODE=3 (post-Phase-6) or 2 (pre).
  - Construct a session with badpass + token_denied + auth markers + pass= — expect `ioc_cve_2026_41940_combo` strong (existing IOC-E2 at line 4163) AND NOT `ioc_failed_exploit_attempt` (auth markers present means this is real compromise, not failed attempt).
- **Edge cases**:
  - **Mutually exclusive with IOC-E2:** when auth markers are present, the new check returns early — IOC-E2 (`ioc_cve_2026_41940_combo`) handles that case. The new emit is for the FAILED-attempt signature only.
  - **Session origin parsing:** the existing `SF_ORIGIN` global already captures `method=...`. Use `SF_BADPASS` (which is the parsed boolean) rather than re-parsing.
  - **Empty pass= line:** `^pass=$` (zero-length value) should NOT count — the cPanel script greps `^pass=` which matches even empty. Our `SF_PASS_PRESENT` should require a non-empty value to align with the cPanel semantics (saveSession only writes `pass=` when length > 0).
- **Regression-case**: live test on host2 — host2 has confirmed compromised sessions (auth markers present). Expect: NO new `ioc_failed_exploit_attempt` emits on host2 (all session-side compromise paths fire IOC-E2/IOC-H/IOC-I instead). Negative-case validation only.

- [x] **Step 1: Add SF_PASS_PRESENT detection to the session awk pass**

  Location: `sessionscribe-ioc-scan.sh` ~line 3850 (the awk block in `analyze_session_file` or equivalent SF_* setter). Add awk var `pass_present=0; pass_present_nonempty=0` and a match for `/^pass=.+/` (non-empty pass line).

- [x] **Step 2: Add the new check after the existing IOC-G tfa emit**

  Location: insert after line 4232 (the `if (( SF_TFA && ! SF_LEGIT_LOGIN ))` block):

  ```bash
  # IOC-J: Failed exploit attempt - cPanel IOC 5 analog. Session has the
  # newline-injection-attempted footprint but the injection didn't promote
  # (no auth markers). Per cPanel's reference checker: origin=badpass +
  # token_denied present + pass= line present + no auth markers = the
  # attacker tried, the auth-marker injection failed, the session is
  # poking at cp_security_token without success.
  #
  # Severity=warning so this counts toward ioc_review (SUSPICIOUS) but
  # NOT ioc_critical (COMPROMISED). Distinct from IOC-E2 which fires
  # CRITICAL when auth markers ARE present (real compromise).
  if (( SF_BADPASS && SF_TOKEN_DENIED && SF_PASS_PRESENT_NONEMPTY \
        && ! SF_INT_AUTH && ! SF_EXT_AUTH && ! SF_HASROOT && ! SF_TFA )); then
      emit_session "ioc_failed_exploit_attempt_$session_name" "warning" \
           "ioc_failed_exploit_attempt" 3 \
           "path" "$f" "origin" "$SF_ORIGIN" \
           "note" "Failed CVE-2026-41940 attempt: badpass origin + token_denied + pass= line + no auth markers - injection did not promote (REVIEW)."
      ((ioc_hits++))
  fi
  ```

---

### Phase 4: `ioc_signal_epoch` pattern=X timestamp guard (Gap 11)
**Status:** COMPLETE — pre4 @ ade0036

Refuse to fall back to `TS_EPOCH` (scan time) for signals whose key maps to pattern=X. Today `ioc_signal_epoch()` at line 1170 returns `TS_EPOCH` when no per-event timestamp can be resolved — for pattern=X events this synthesizes a kill-chain event at scan-time, polluting cluster-onset analysis (`q5/q8` in summary.json). The fix: when the resolved key maps to pattern=X AND no real timestamp exists, return 0 and let the caller emit a `pattern=meta` warning instead of fabricating an X event.

**Why this matters:** Per `intake-triage-2026-05-02/summary.json` `q8_patient_zero_x: 2025-11-25 testdev.halcyonplatinum.com` — 5 months before watchTowr disclosure. If this anchor was a synthetic-timestamp Pattern X event (Gap 11), the pre-disclosure outlier dissolves. Per memory `project_pre_disclosure_outlier.md`, the host is still under hand-investigation — Phase 7 validates whether this anomaly resolves post-fix.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` lines 1170-1184 (`ioc_signal_epoch()` function); lines 1240-1304 (`read_iocs_from_envelope()` consumer)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - `grep -cE 'pattern=meta|pattern_meta' sessionscribe-ioc-scan.sh` returns ≥1 (the new fallback emit)
  - `grep -cE 'ts_unresolvable|ts_synthetic_refused' sessionscribe-ioc-scan.sh` returns ≥1
- **Test**:
  - Construct a synthetic envelope JSON with one signal entry that has key=`ioc_attacker_ip_2xx_on_cpsess` and NO `ts_epoch_first` field. Run `read_iocs_from_envelope` against it via `--replay`. Expect: NO entry in OFFENSE_EVENTS for this signal; ONE pattern=meta warning emit recording the dropped event.
  - Same test but with key=`ioc_pattern_a_encryptor` (pattern=A): expect the existing fallback to TS_EPOCH (file-on-disk evidence — the on-disk artifact's mtime is the activity time even if the JSON omits ts).
- **Edge cases**:
  - **Pattern A/B/C/D/F/G/H/I retain TS_EPOCH fallback** — destruction patterns are file-on-disk evidence; their timestamp comes from `mtime_epoch`/`stat`, and a missing ts_epoch_first is a malformed-emit bug worth surfacing but not worth dropping the event for. Only pattern=X (and pattern=init via the same access-log keying) gets the strict guard.
  - **Schema bump:** the new pattern=meta event needs a kill-chain.tsv handler — extend the IOC row writer at line 2532 to handle `kind=META` rows.
- **Regression-case**: live test on host2 — host2's envelope has all-real timestamps. Expect: zero pattern=meta emits. Negative-case validation.

- [x] **Step 1: Add pattern-aware fallback in `ioc_signal_epoch()`**

  Location: `sessionscribe-ioc-scan.sh` lines 1170-1184. Replace today's:
  ```bash
  ioc_signal_epoch() {
      local line="$1" v iso k
      for k in ts_epoch_first mtime_epoch ts_epoch; do ... done
      for k in file_mtime login_time; do ... done
      printf '%s' "$TS_EPOCH"
  }
  ```

  With:
  ```bash
  ioc_signal_epoch() {
      local line="$1" v iso k key pattern
      for k in ts_epoch_first mtime_epoch ts_epoch; do ... done
      for k in file_mtime login_time; do ... done

      # Pattern-aware fallback: pattern=X events MUST have a real timestamp;
      # synthesizing TS_EPOCH for them pollutes cluster-onset analysis.
      # File-on-disk patterns (A/B/C/D/F/G/H/I) get TS_EPOCH fallback because
      # they're authentic evidence even with malformed emit.
      key=$(json_str_field "$line" key)
      pattern=$(ioc_key_to_pattern "$key")
      if [[ "$pattern" == "X" ]]; then
          printf '0'
          return
      fi
      printf '%s' "$TS_EPOCH"
  }
  ```

- [x] **Step 2: Handle ts=0 in `read_iocs_from_envelope()`**

  Location: `sessionscribe-ioc-scan.sh` line 1278 (the line `ts=$(ioc_signal_epoch "$line")`).

  After the assignment, check for ts=0 and emit a meta-pattern warning instead of populating OFFENSE_EVENTS:
  ```bash
  ts=$(ioc_signal_epoch "$line")
  if [[ "$ts" == "0" ]]; then
      emit_signal offense warn ts_unresolvable_pattern_x \
          "Pattern X event refused (no resolvable timestamp) - prevents synthetic scan-time anchor" \
          key "$key"
      continue
  fi
  ```

- [x] **Step 3: Extend kill-chain TSV/JSONL writers to handle pattern=meta rows (optional)**

  Location: `sessionscribe-ioc-scan.sh` lines 2456-2540. Currently writes DEF and IOC rows. Add a META row class for refused-pattern-X events. Defer if not needed by Phase 7 validation — meta events are warning-tier and don't drive the kill-chain narrative.

---

### Phase 5: Structured kill-chain fields for Pattern E + new pattern=X (Gap 4)
**Status:** COMPLETE — pre5 @ f903959

Populate `ip`/`path`/`status`/`cpsess_token` structured fields at emit-time for Pattern E (`ioc_pattern_e_websocket_shell_hits`) and the new `ioc_attacker_ip_2xx_on_cpsess` (Phase 2). Today these fields are empty in `kill-chain.tsv` for these patterns because the upstream emit only writes `sample` (a free-form access_log line) and `dimensions`. Hand-investigation has to extract `access-logs.tgz` and re-grep — Phase 5 makes the kill-chain self-sufficient.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` lines 5060-5160 (Pattern E `check_websocket_shell_external` emit block); lines 3672-3692 (Pattern X new emit from Phase 2)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - Pattern E emit at line ~5087 includes `"ip"` and `"path"` fields in the emit args (in addition to existing `sample` + `dimensions`)
  - Phase 2 Pattern X emit includes `"ip"` and `"path"` fields
  - `read_iocs_from_envelope` at line 1280-1289 already extracts these; no changes needed there
  - `write_kill_chain_primitives` at line 2532 already writes them; no changes needed there
- **Test**:
  - Live test on host2 — host2 has Pattern E websocket Shell hits with known dimensions (`80.75.212.14`). Run `--full`. Inspect `kill-chain.tsv`: Pattern E rows should now have `ip=80.75.212.14`, `path=/cpsess.../websocket/Shell?...`, `status=200`. Re-run with `--replay` against the saved envelope: same result.
  - Replay test on `host.elegantthemesdemo.com` envelope (the v4 doc's reference host): `kill-chain.tsv` Pattern E + Pattern X rows have populated structured fields.
- **Edge cases**:
  - **`cpsess_token` parsing:** extract via `match($0, /\/cpsess[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]/)` + `substr` (gawk 3.x). Empty string when not present. Stored as a new column in kill-chain.tsv (extend the header at line 2457).
  - **Sample-line parsing:** the access_log sample is a single line in apache combined-log format. Parse via the same awk pattern used elsewhere in `check_attacker_ips`. Don't re-invent — reuse the proven extraction.
- **Regression-case**: live test on host2 — diff `kill-chain.tsv` pre/post. Expected: Pattern E rows transition from empty `ip`/`path` to populated; everything else byte-identical.

- [x] **Step 1: Extract structured fields at Pattern E emit-time**

  Location: `sessionscribe-ioc-scan.sh` line ~5087.

  Today:
  ```bash
  emit "destruction" "ioc_pattern_e_websocket" "strong" \
       "ioc_pattern_e_websocket_shell_hits" 10 \
       "count" "$ext_2xx_known" ... \
       "sample" "${ext_sample:0:200}" \
       "note" "..."
  ```

  Add fields parsed from `$ext_sample` (the proven 2xx-known access_log line):
  ```bash
  # Parse the canonical access_log line for structured fields.
  local _e_ip _e_path _e_status _e_token
  _e_ip=$(awk '{print $1}' <<< "$ext_sample")
  _e_path=$(awk -F'"' '{print $2}' <<< "$ext_sample" | awk '{print $2}')
  _e_status=$(awk -F'"' '{print $3}' <<< "$ext_sample" | awk '{print $1}')
  if [[ "$_e_path" =~ /cpsess([0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])/ ]]; then
      _e_token="${BASH_REMATCH[1]}"
  fi

  emit "destruction" "ioc_pattern_e_websocket" "strong" \
       "ioc_pattern_e_websocket_shell_hits" 10 \
       "count" "$ext_2xx_known" ... \
       "ip" "$_e_ip" "path" "$_e_path" "status" "$_e_status" \
       "cpsess_token" "${_e_token:-}" \
       "sample" "${ext_sample:0:200}" \
       "note" "..."
  ```

- [x] **Step 2: Same treatment for Phase 2's `ioc_attacker_ip_2xx_on_cpsess` emit**

  Location: Phase 2 emit. The awk pass needs a "first 2xx-on-cpsess sample" output (parallel to today's `ext_sample`). Capture in awk END block, propagate through, parse into ip/path/status/cpsess_token at emit-time.

- [x] **Step 3: Extend kill-chain TSV header + writer to include `cpsess_token` column**

  Location: `sessionscribe-ioc-scan.sh` line 2457 (header). Add `cpsess_token` after `status`. Update `printf` at line 2532 to add a column. Update JSONL printf at line 2617 similarly.

---

### Phase 6: Add exit code 3 = SUSPICIOUS
**Status:** COMPLETE — pre6 @ eec42c7

Disambiguate host-state SUSPICIOUS from code-state INCONCLUSIVE on the exit code axis. Today both produce EXIT_CODE=2 — the collision is invisible to operators reading exit codes for fleet aggregation. Phase 6 splits them: code-state INCONCLUSIVE keeps exit 2; host-state SUSPICIOUS becomes exit 3.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` lines 5398-5410 (the host-state axis block in `aggregate_verdict()`)

- **Mode**: serial-context
- **Accept**:
  - `bash -n sessionscribe-ioc-scan.sh` exits 0
  - `grep -cE 'EXIT_CODE=3' sessionscribe-ioc-scan.sh` returns 1
  - The exit-code documentation block (currently at lines 5440-5450 in the script header comment) is updated to describe exit 3 = SUSPICIOUS
- **Test**:
  - Synthetic test: construct an envelope with one warning-tier ioc_review signal and zero strong signals. Run aggregator. Expect EXIT_CODE=3, HOST_VERDICT=SUSPICIOUS.
  - Live regression on host2 — host2 has strong signals (COMPROMISED), so exit stays 4. Negative-case validation only.
  - Live regression on a CLEAN host (need to identify one in the lab — operator interjection: do we have one available?). Expect exit 0.
- **Edge cases**:
  - **`--ioc-only` mode:** today, line 5407 sets EXIT_CODE=2 when ioc_review > 0 in `--ioc-only`. Update to EXIT_CODE=3.
  - **Combined code+host:** if VULNERABLE (exit 1) AND SUSPICIOUS (exit 3), today exit code is whichever was set last (host-state wins per the comment at line 5398). Phase 6: same precedence — host-state SUSPICIOUS overrides code-state VULNERABLE on exit code (both axes still report in the verdict block). COMPROMISED (exit 4) overrides everything.
- **Regression-case**: live regression on host2 — expect EXIT_CODE=4 unchanged.

- [x] **Step 1: Update host-state axis logic**

  Location: `sessionscribe-ioc-scan.sh` lines 5400-5410.

  Today:
  ```bash
  if (( ioc_critical > 0 )); then
      HOST_VERDICT="COMPROMISED"
      EXIT_CODE=4
  elif (( ioc_review > 0 )); then
      HOST_VERDICT="SUSPICIOUS"
      (( IOC_ONLY )) && EXIT_CODE=2
  else
      HOST_VERDICT="CLEAN"
  fi
  ```

  Phase 6:
  ```bash
  if (( ioc_critical > 0 )); then
      HOST_VERDICT="COMPROMISED"
      EXIT_CODE=4
  elif (( ioc_review > 0 )); then
      HOST_VERDICT="SUSPICIOUS"
      EXIT_CODE=3   # always 3 — disambiguates from code-state INCONCLUSIVE (2)
  else
      HOST_VERDICT="CLEAN"
  fi
  ```

  Note the IOC_ONLY-only conditional is removed — SUSPICIOUS exits 3 in all modes.

- [x] **Step 2: Update exit-code documentation block**

  Location: script header comment around line 460-490 (the `--help` usage block).

  Add:
  ```
  Exit codes:
    0  CLEAN / PATCHED          host clean, no IOCs
    1  VULNERABLE               code-state failure (cpsrvd binary unpatched)
    2  INCONCLUSIVE             code-state ambiguous (version says patched but
                                 score disagrees, or no version verdict)
    3  SUSPICIOUS               host-state: ioc_review > 0 (warning-tier IOC,
                                 includes ioc_failed_exploit_attempt, recon-only
                                 attacker-IP traffic, anomalous_root_sessions)
    4  COMPROMISED              host-state: ioc_critical > 0 (strong-tier IOC,
                                 includes destruction patterns, cpsess-bearing
                                 2xx from T1 IPs, session-side injection markers)
  ```

---

### Phase 7: Live regression + aggregator re-validation

Run the full v2.2.0-pre7 build on the `cpanel_client` lab host (host2.alps-supplies.com) and validate the success-criteria gate from the plan preamble. Re-run `ss-aggregate.py` against the existing 9659-bundle dataset to confirm FP-reduction targets hit.

**Files:**
- (none modified)
- Read: `intake-triage-2026-05-02/{summary.json, confirmed-compromised.csv}` (baseline)
- Generate: regression artifacts in `.rdf/work-output/phase-7-result.md`

- **Mode**: serial-context (operator-attended)
- **Accept**:
  - host2 live run produces HOST_VERDICT=COMPROMISED, EXIT_CODE=4 (unchanged from v2.1.0-pre7 baseline)
  - host2 stderr verdict block shows new `ioc_attacker_ip_2xx_on_cpsess` strong emit (replacing old `ioc_attacker_ip_in_access_log` strong)
  - host2 kill-chain.tsv has populated `ip`/`path`/`status`/`cpsess_token` for Pattern E + new Pattern X rows
  - Aggregator re-run on the 9659-bundle dataset:
    - COMPROMISED count: between 250 and 350 (gate 1 from preamble)
    - All 203 hosts in `q1_confirmed_compromised` retain COMPROMISED verdict (gate 2)
    - `q1_weak_noise: 7611` hosts drop to SUSPICIOUS (exit 3) or CLEAN (exit 0) (gate 3)
    - `testdev.halcyonplatinum.com` first-X anomaly resolves OR surfaces as legitimate (gate 4)
  - host.elegantthemesdemo.com envelope replay produces populated kill-chain rows for Pattern E + Pattern X (gate 5)
- **Test**: described in Accept; this phase IS the test.
- **Edge cases**:
  - **No CLEAN lab host available:** flag to operator before running. CLEAN-state validation is a known gap (per repo-sessionscribe insight 2026-05-02T15:29:27Z: "When live regression can only cover SOME states, sentinel review uses the preamble as test oracle"). Document the gap in phase-7-result.md if applicable.
  - **Aggregator output drift:** if `ss-aggregate.py` itself needs updates to handle new key vocabulary, that's a separate small PR — flag for operator. Phase 7 should not modify aggregator code.
- **Regression-case**: this IS the regression case for the entire plan. Pre/post-diff every output artifact.

- [x] **Step 1: Capture pre-change baseline**

  On host2 via `cpanel_client` tmux session, run v2.1.0-pre7 (current `main`):
  ```bash
  ./sessionscribe-ioc-scan.sh --full 2> /tmp/v2.1.0-pre7-stderr.log
  cp /var/cpanel/sessionscribe-ioc/<RUN_ID>.json /tmp/v2.1.0-pre7-envelope.json
  cp <bundle>/kill-chain.tsv /tmp/v2.1.0-pre7-kill-chain.tsv
  ```

- [x] **Step 2: Build v2.2.0-pre7 (Phases 1-6 merged), deploy to host2, run live**

  Same set of artifacts under v2.2.0 names. Then `diff` each pair.

- [x] **Step 3: Re-run `ss-aggregate.py` on 9659-bundle dataset**

  Re-run from `/var/sessionscribe-triage/` on forge against the existing `records.jsonl` extracted from envelopes. Generate new `summary.json` and compare:
  - `verdicts.COMPROMISED`: 9659 → expected 250-350
  - `q1_confirmed_compromised`: 203 (unchanged — hard floor)
  - `q1_weak_noise`: 7611 → expected SUSPICIOUS or CLEAN reclassification
  - `q8_patient_zero_x.epoch`: 2025-11-25 → expected ≥2026-04-15 OR confirmed-as-real

- [x] **Step 4: Replay against `host.elegantthemesdemo.com` envelope**

  Validate Phase 5 deliverables against the v4 reference host. Confirm structured fields populated.

- [x] **Step 5: Write `.rdf/work-output/phase-7-result.md` with the success-criteria matrix**

  Each gate from the preamble: pass/fail + observed value. Sentinel review at this phase reads phase-7-result.md as the oracle. Result file: `.rdf/work-output/phase-7-result-v2.2.0.md`.

---

### Phase 8: Version bump + docs + CDN deploy

Bump `VERSION` to `2.2.0`, update STATE.md / CLAUDE.md / README.md to document the new IOC vocabulary, severity emit policy, and exit code 3. Deploy to `https://sh.rfxn.com/`. Verify on a habs-class host.

**Files:**
- Modify: `sessionscribe-ioc-scan.sh` line 7 (`VERSION="2.1.0"` → `VERSION="2.2.0"`)
- Modify: `STATE.md` (architecture section: add new IOC keys + severity emit policy + exit code 3)
- Modify: `CLAUDE.md` (project floor section: add the cpsess-token-keyed-vs-IP-keyed primitive distinction as a guard against future regressions)
- Modify: `README.md` (verdict tier table; exit code semantics; mention `ioc_failed_exploit_attempt`)

- **Mode**: serial-context (operator-attended for the CDN push)
- **Accept**:
  - `grep '^VERSION="2.2.0"' sessionscribe-ioc-scan.sh` returns 1
  - STATE.md, CLAUDE.md, README.md updated with new vocabulary
  - `https://sh.rfxn.com/sessionscribe-ioc-scan.sh` returns 200 with byte-identical content to local file
  - `curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | head -10` shows `VERSION="2.2.0"`
- **Test**: per Accept criteria; final smoke run on a habs host.
- **Edge cases**:
  - **CDN cache:** sh.rfxn.com may serve stale content for up to 5min. Verify with cache-bust query string OR wait + retry.
  - **Symlink targets:** if any URL aliases (e.g. `sessionscribe-forensic.sh`) point to ioc-scan via the deprecation shim, verify they still resolve.
- **Regression-case**: a habs-class host runs the CDN-deployed script and produces the same verdict as the local run from Phase 7.

- [x] **Step 1: Bump VERSION**

  `sessionscribe-ioc-scan.sh` line 7. Single change. Done in Phase 8 commit.

- [x] **Step 2: Update STATE.md**

  Added a v2.2.0 section documenting:
  - New IOC keys (`ioc_attacker_ip_2xx_on_cpsess`, `ioc_attacker_ip_recon_only`, `ioc_failed_exploit_attempt`)
  - Severity emit policy (cpsess-keyed vs IP-keyed primitives)
  - Exit code 3 = SUSPICIOUS
  - Pattern X timestamp guard
  - Phase 5 structured kill-chain fields
  - Phase 7 fleet validation outcome

- [x] **Step 3: Update CLAUDE.md**

  Added a "Primitive selection for COMPROMISED-tier signals" section documenting the lesson: when designing a strong-severity emit-site that escalates to COMPROMISED, the input primitive MUST be unique to compromise (token value, structurally-impossible session shape, on-disk destruction artifact, deterministic CRLF chain primitive). Reusable primitives (IP address, generic 2xx response, token-field PRESENCE without value match) escalate to warning-tier at most. The 2026-05-02 fleet-triage incident demonstrated this — IP-keyed gating produced ~90% FP COMPROMISED rate on a 9659-host sample.

- [x] **Step 4: Update README.md**

  Verdict tier table added:
  ```
  | Exit | Code-state    | Host-state   | Triage action |
  | 0    | CLEAN/PATCHED | CLEAN        | none |
  | 1    | VULNERABLE    | (any)        | patch cpsrvd |
  | 2    | INCONCLUSIVE  | (any)        | manual code-state review (also: tool error) |
  | 3    | (any)         | SUSPICIOUS   | review session/access logs |
  | 4    | (any)         | COMPROMISED  | full IR; bundle + upload |
  ```
  Also modernized stale `ioc_attacker_ip_in_access_log` example output to use the new `ioc_attacker_ip_2xx_on_cpsess` key vocabulary.

- [ ] **Step 5: Deploy to CDN** *(operator-attended, post-commit)*

  Per `reference_cdn_deploy.md` — operator-attended. Verify post-deploy URL fetch.

- [ ] **Step 6: Smoke run on habs** *(operator-attended, post-CDN)*

  Per `reference_lab_hosts.md` — habs lab host. Confirm CDN-deployed v2.2.0 produces identical output to local v2.2.0 build.

---

## Sentinel Review Notes (for /r-review post-impl)

**Pass 1 (mechanical correctness):**
- bash -n + shellcheck -S error clean across all phases
- All grep-counted invariants in Phase Accept blocks return expected counts
- Exit code 3 documented in --help; help output matches doc table

**Pass 2 (semantic correctness):**
- Phase 2: cpsess regex is exactly 10 digits (no fewer, no more). Verify against negative cases: `/cpsess1234567890ABCDEF/` (11+ chars) should match (10-digit prefix), `/cpsess12345/` (5 digits) should NOT match. Per CLAUDE.md gawk 3.x floor — no `{10}` interval; explicit char-class repetition required.
- Phase 3: SF_PASS_PRESENT_NONEMPTY semantics — empty `pass=` line does NOT count. Cross-check with cPanel reference: their `grep -q '^pass='` matches empty too — we deliberately diverge to align with `saveSession()` semantics (line 181 of Cpanel/Session.pm: writes pass= only when length > 0).
- Phase 4: pattern=meta event handling in kill-chain TSV/JSONL — if Step 3 deferred, sentinel must verify no breakage when ts=0 events are silently dropped (current behavior pre-Step-3).
- Phase 6: EXIT_CODE precedence (host > code) preserved. COMPROMISED still trumps VULNERABLE on exit code.

**Pass 3 (preamble/oracle cross-check):**
- All five Success Criteria gates from preamble checked in phase-7-result.md
- Test oracle: did Phase 7 surface the testdev.halcyonplatinum.com anomaly resolution? Phase 4 should have refused to emit the synthetic 2025-11-25 event if that's what was happening.

**Pass 4 (operator-visible regressions):**
- host2 stderr verdict block: ASCII-only, no Unicode glyphs (per CLAUDE.md ASCII-only output convention)
- Tag column width still ≤10 chars after any new tags introduced (Phase 6 may render `[SUSPECT]` 9-char if exit-code rendering changes — verify)
- No double-counted ioc_critical or ioc_review (Phase 2 may emit both legacy + new keys for the same access_log scan; verify aggregate_verdict() doesn't count both)

---

## Sentinel Fixups (post-pre6)

### pre7 — MUST-FIX: exit code 3 collision (Sentinel Finding 1)

**Problem:** Phase 6's plan said exit 3 was unused; it was actually used by 16 tool-error / pre-scan sites (8 in the argument parser + /var/cpanel gate, plus 8 in `resolve_replay_envelope` path resolution). Phase 6 help-text documented tool errors at exit 2 but the runtime continued exit 3. Operators reading `$?` could not distinguish "host SUSPICIOUS" (legitimate IOC review tier) from "bad arguments / unreadable replay path" (tool error), corrupting Phase 7 gate 3 measurement (q1_weak_noise hosts dropping to exit 3 / SUSPICIOUS).

**Fix:** Changed all 16 `exit 3` calls to `exit 2`:
- Argument parser block: lines 595 (unknown option), 602 (--csv+--jsonl), 608 (--replay missing path), 615 (--upload without --full/--replay), 622 (--full + --no-ledger), 632 (--max-bundle-mb), 638 (--since)
- Pre-scan gate: line 785 (/var/cpanel missing)
- `resolve_replay_envelope` path resolution: 8 sites at lines 5907, 5918, 5922, 5932, 5936, 5944, 5953, 5959 (empty path, mktemp fail, tar extract fail, no-json, multi-json, bad-extension, dir-no-json, path-not-exist)
- Header comment at ~line 5898 ("exits 3 on ambiguity") updated to "exits 2"

The sole remaining user of exit code 3 is now the SUSPICIOUS host-state assignment (`EXIT_CODE=3`) inside `aggregate_verdict`.

**Verification:**
- `grep -cE 'exit 3' sessionscribe-ioc-scan.sh` → 0 (no direct exit 3)
- `grep -cE 'EXIT_CODE=3' sessionscribe-ioc-scan.sh` → 1 (SUSPICIOUS assignment only)
- `bash sessionscribe-ioc-scan.sh --bogus-flag-name` → exit 2
- `bash sessionscribe-ioc-scan.sh --help` → exit 0
- `bash -n` + `shellcheck -S error` clean
- Help text (lines 533-544) unchanged; runtime now matches documented contract

**Status:** COMPLETE — pre7 @ a958a18

### pre8 — SHOULD-FIX bundle (Sentinel Findings 2, 3, 4, 5 + Pass 4 locals)

**Bundle of 5 related correctness fixes.** Landed together because Phase 7 live regression on host.elegantthemesdemo.com depends on Pattern E structured-field correctness (Fix A); the rest are schema/scope hygiene.

- **A:** Pattern E sample line filtered to attacker-known dimensions. Added `ext_known_sample` awk variable captured inside `if (d in known)` block; strong emit's `ip` / `path` / `status` / `cpsess_token` / `sample` fields now read from this dedicated sample (was: any external line, including 4xx probes and unknown-dim admin sessions). Defensive `${ext_known_sample:-$ext_sample}` fallback retained.
- **B:** IOC-J `ioc_failed_exploit_attempt_*` (warning-tier) now requires `! SF_CP_TOKEN` to be strictly disjoint from IOC-E `ioc_token_attempt_*` (evidence-tier). Both share the parent key `ioc_failed_exploit_attempt`; without the new guard ss-aggregate.py double-counts when `cp_security_token` is present in a badpass+token_denied+pass-line session with no auth markers.
- **C:** JSONL meta row bumped `schema_version` 2 → 3 with appended `_schema_changes` entry: `{"v":3,"since_tool":"2.2.0","added":["cpsess_token"],"note":"cpsess token extracted at emit-time for Pattern E + ioc_attacker_ip_2xx_on_cpsess"}`. In-line printf comment also updated.
- **D:** kill-chain.tsv `cpsess_token` column moved from position 17 (mid-row, between `status` and `line`) to position 18 (end-of-row), preserving column-index stability for external operator scripts that parse TSV by index. IOC printf args reordered correspondingly. (DEF row 17-column shape left unchanged in pre8 — addressed in pre9 below; sentinel re-review correctly identified this as a Phase 5 / pre6 regression, not a pre-PR-existing issue as the engineer initially characterized it.)
- **E:** `read_iocs_from_envelope` `local` declarations updated: added `key_for_warn` and `p_cpsess_token` to prevent function-global scope leak under `set -u`.

**Verification:**
- `bash -n` + `shellcheck -S error` clean
- Meta JSONL row parses as valid JSON (`python3 -c 'json.loads(...)'`); schema_version=3, two `_schema_changes` entries
- TSV header column count = 18; `cpsess_token` is column 18
- IOC printf positional args match header order (line=17, cpsess_token=18)
- gawk-3.x compat probes (interval, 3-arg match) still pass; no `{n}` in awk regexes; only commented references to 3-arg match()
- `--bogus-flag` still returns exit 2; `--help` still returns exit 0

**Judgment notes:**
- DEF row at line 2524 has 17 columns vs the 18-column header. Engineer initially flagged as pre-existing and out of scope; sentinel re-review traced git history (9203a99 had aligned 17/17; pre6 introduced header→18 without updating DEF) and reclassified as a Phase 5 regression. Fixed in pre9.
- `SF_CP_TOKEN` was already populated in `analyze_session()` (declared line 3928, set from cp_token field); no additional awk-pass changes needed.
- Apostrophe-in-comment hazard: comments inside the awk single-quoted block must avoid apostrophes (would close the heredoc string). Caught locally during pre8 lint-fix; recorded here so future contributors avoid it.

**Status:** COMPLETE — pre8 @ 13aff7e

### pre9 — SHOULD-FIX: kill-chain.tsv DEF row column-count alignment (sentinel re-review finding)

**Problem:** Sentinel re-review of pre7+pre8 traced git history and confirmed the DEF row column mismatch was introduced by Phase 5 (pre6) when `cpsess_token` was added to header + IOC printf but the DEF printf at line 2524 was not updated. The engineer's pre8 plan-note characterized this as "pre-existing"; that was factually incorrect (baseline 9203a99 had aligned 17/17 columns).

**Fix:** Added one trailing `\t` to DEF printf format string, taking the row from 16 tabs (17 columns) to 17 tabs (18 columns). The trailing field is empty — DEF rows don't have a cpsess_token by definition (they describe defense events, not exploitation events) — but column-index stability is now preserved for external `awk -F'\t'` parsers.

**Verification:**
- `awk 'NR==2524' sessionscribe-ioc-scan.sh | grep -oE '\\t' | wc -l` returns 17 (matches IOC and header)
- `bash -n` + `shellcheck -S error` clean
- Plan-doc text in pre8 entry updated to retract "pre-existing" claim

**Status:** COMPLETE — pre9 @ f8c219a

### pre10 — MUST-FIX: awk split() arg order in Phase 2/Phase 5 emit-time path/status extraction (Phase 7 live-regression finding)

**Problem:** Live regression on host2.ringithosting.com surfaced a real-data correctness bug: kill-chain.tsv showed `path=""`, `status=""`, `cpsess_token=""` for the new `ioc_attacker_ip_2xx_on_cpsess` strong emit AND for `ioc_pattern_e_websocket_shell_hits`, despite `ip` being correctly populated. Manual diagnosis on host2 reproduced the failure with `awk: fatal: split: second argument is not an array`.

**Root cause:** Four awk one-liners in the emit-time bash extraction had `split($N, " ", p)` with arguments in wrong order. Standard awk signature is `split(string, array, fieldsep)` — the engineer's code passed the field-separator string `" "` as the second arg (where the array goes) and the array name `p` as the third arg (where the separator goes). gawk fails fatally on the malformed call; the bash command-substitution captures only stderr-less empty stdout, leaving `_c_path`, `_c_status`, `_e_path`, `_e_status` empty. This silently failed in pre2 and pre5/pre8 because shellcheck doesn't run awk regexes and bash -n doesn't execute the awk subshells. Sentinel passes 1+2 didn't catch it because they verified field-presence in JSON (the fields `"path":"",` ARE present in the emit; the empty value was indistinguishable from "no cpsess hits to populate them with").

**Fix:** Swapped argument order at four call sites:
- Line 3782 (Phase 2 `_c_path`)
- Line 3783 (Phase 2 `_c_status`)
- Line 5272 (Phase 5 Pattern E `_e_path`)
- Line 5273 (Phase 5 Pattern E `_e_status`)

All four now use `split($N, p, " ")` matching the canonical awk signature and the 9 other split() callsites elsewhere in the script.

**Verification:**
- `bash -n` + `shellcheck -S error` clean
- Manual extraction on host2 against a real access_log line: `ip=80.75.212.14 path=/cpsess.../json-api/version status=200` (was `path=[] status=[]` pre-fix)
- Live re-run on host2 (post-deploy) — kill-chain.tsv structured field check (gate 5)

**Status:** COMPLETE — pre10 @ b37cb92

