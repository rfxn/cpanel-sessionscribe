# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per the affected component.

## sessionscribe-ioc-scan.sh v2.7.1 — 2026-05-03

### Added
- **Pattern J — init-facility persistence detection.** New IOC class
  alongside the existing A-I dossier patterns. Two sub-detectors inside
  `check_destruction_iocs`:
  - **J1 (udev)** — walks `/etc/udev/rules.d/` and `/run/udev/rules.d/`.
    Strong tier requires the `RUN+="...sh -c '... | at now'"` shape
    (dossier-observed; the pipe-to-`at now` form is vanishingly rare in
    benign udev automation). Warning tier covers `nohup`/`setsid`/`disown`
    backgrounded shell-outs. Both gates AND with non-RPM-ownership.
  - **J2 (systemd)** — walks `/etc/systemd/system/*.service` only
    (operator-customizable tree; `/usr/lib/systemd/system/` is RPM
    territory and is intentionally skipped). Strong tier requires the
    conjunction: ExecStart inside `/usr/share/` + Description shadows a
    known systemd/cPanel service name + unit and binary not RPM-owned +
    mtime within 90 days. Otherwise warning. Allowlist for legit
    ExecStart roots includes `/usr/local/cpanel/`, `/usr/local/lsws/`,
    `/opt/`, `/var/cpanel/`, `/var/lib/dovecot/`, `/var/lib/mysql/` so
    a stock control-panel host doesn't FP.
  - Snapshot-aware: when `--root DIR` is set, walks `${DIR}/etc/...`
    and demotes severity to `info` with `degraded_confidence_snapshot=1`
    (no live rpmdb to cross-check ownership).
  - RPM ownership probe via new helper `is_rpm_owned()` and bulk-mode
    `bulk_rpm_owned_filter()` (one rpmdb open for N paths instead of N
    individual rpm calls). Falls back to `dpkg -S` on debian-ish hosts;
    if neither tool is present, severity downgrades automatically.
  - Pattern letter `J` wired into `ioc_key_to_pattern()`, `PATTERN_ORDER`,
    and `PATTERN_LABEL`. `[I]` and `[G]` labels relabeled to
    `persistence (...)` for symmetry with `[J]` and `[D]`.
- **Mitigate-quarantine secondary read** in `check_sessions`. On hosts
  where `sessionscribe-mitigate.sh` ran, forged sessions are moved out
  of `/var/cpanel/sessions/raw/` and into the quarantine tree at
  `$MITIGATE_BACKUP_ROOT/<RUN>/quarantined-sessions/raw/`. The live walk
  saw an empty raw/ on those hosts and produced `host_verdict=CLEAN` on
  demonstrably compromised systems. New `check_quarantined_sessions()`
  function walks the quarantine, reads each `<sname>.info` sidecar with
  a data-only key=value parser (no eval), and emits one synthetic
  `ioc_quarantined_session_<sname>` warning-tier signal per file with:
  `original_path`, `quarantine_run_dir`, `quarantine_ts`, original
  `mtime_epoch` (from sidecar — attacker write-time, not our cp time),
  `reasons_ioc` (the IOC pattern letters that fired the quarantine),
  `sha256`. Quarantined emits route to Pattern X via dedicated
  `(ioc_quarantined_session_*) echo X` branch in `ioc_key_to_pattern`.
  Cap of 200 sessions analyzed per scan, oldest-skip beyond. Sidecar
  fallback when missing (mitigate v0.4.x predates sidecars): use file
  mtime + `low_confidence_no_sidecar=1` flag, never crash.
- **`45.92.1.188` added to `ATTACKER_IPS`** (rev5; Pattern J operator).

### Changed
- VERSION 2.6.1 → 2.7.1 (additive features, new IOC class, schema bump).
- `_schema_changes` meta record bumped to `schema_version=4` with a v4
  entry describing the new emit fields (`pattern_j`,
  `quarantined_session_emit`, `quarantine_run_dir`, `original_path`,
  `reasons_ioc`, `low_confidence_no_sidecar`,
  `degraded_confidence_snapshot`).
- `check_destruction_iocs` snapshot-mode early-return now runs Pattern J
  (degraded confidence) before returning, instead of skipping
  destruction probes wholesale. Matches the user expectation that
  `--root` against an offline snapshot can still surface persistence.
- `check_sessions` early-return path (when `/var/cpanel/sessions` is
  missing) now runs the quarantine secondary first — previously, hosts
  without a live sessions dir reported `CLEAN` even when the quarantine
  contained evidence of past compromise.

### Notes
- Pattern J detection is RPM-ownership-anchored to bound FP rate. Hosts
  running heavy site-tooling that drops non-RPM-owned udev rules or
  systemd units may emit `warning`-tier J signals; the `strong` tier
  requires the attacker-specific shape conjunction so should be
  near-zero-FP on typical fleet hosts.
- For fleet aggregation: query `signals[].id == "ioc_pattern_j_*"` for
  J emits and `signals[].id ^= "ioc_quarantined_session_"` for the
  quarantine secondary's contribution. The kill-chain renderer slots J
  alongside G/I as co-stage persistence (post-RCE).

## sessionscribe-ioc-scan.sh v2.6.1 — 2026-05-02

### Fixed
- **`manifest.txt` and `kill-chain.jsonl` meta record now carry real values.**
  `CPANEL_NORM`, `PRIMARY_IP`, `OS_PRETTY`, `LP_UID`, and their JSON-escaped
  twins were declared empty at top-level with comments saying "set by
  banner()" — but `banner()` only printed. Result: every bundle since the
  meta record was added had empty `cpanel_version` / `primary_ip` / `os` /
  `uid`. Fleet aggregation that read those fields silently lost ~100% of
  host context. Added `collect_host_meta()` (data-only key=value parser
  for `/etc/os-release` with double- and single-quote stripping; same
  cpanel-V resolution chain as `check_version()`; `ip route get` →
  `hostname -I` for primary IP; env-var override for `LP_UID`).
- **`PATCHED_BUILDS_CPANEL` was declared empty and never populated.**
  `phase_defense`'s patched-build for-loop walked a 0-element array on
  every host, so no host could ever reach the PATCHED branch via the
  build-equality check. Now populated from `PATCHED_TIERS_KEYS` /
  `PATCHED_TIERS_VALS` at startup, producing strings of shape
  `11.<tier>.0.<build>` that match `CPANEL_NORM`.
- **`PATCHED_BUILD_WPSQUARED` was declared empty and never assigned.**
  WP Squared hosts (build 136.1.7) could never match the equality test.
  Now set to `"11.136.1.7"` per the source comment.
- **`UNPATCHED_TIERS` was a scalar string iterated as an array.**
  `for t in "${UNPATCHED_TIERS[@]}"` over `"112 114 116 120 122 128"`
  iterated ONCE with `t` set to the entire string, so `[[ "$tier" == "$t" ]]`
  never matched. Every UNPATCHABLE-tier host (112/114/116/120/122/128)
  was misclassified as UNPATCHED in `phase_defense`. Converted to an
  array; both `phase_defense` and `check_version` now use the same
  substring-match idiom against the derived `UNPATCHED_TIERS_STR`.
- **`LP_UID` env-var override was clobbered.** `LP_UID="${LP_UID:-}"`
  inside `collect_host_meta` came AFTER the top-level `LP_UID=""` had
  already wiped the inherited env. Changed top-level to
  `: "${LP_UID:=}"` so `LP_UID=nx-prod-12 ./sessionscribe-ioc-scan ...`
  at fleet dispatch survives the initialization.
- **`/etc/os-release` parser was shell-injection-vulnerable.** Original
  `eval "$(awk ... print "VAR="$2)"` interpolated raw values; a
  `PRETTY_NAME="end"; touch /tmp/x; X="rest"` would execute the `touch`.
  Trust boundary holds today (root-owned file), but a snapshot/offline
  run could consume an attacker-influenced copy. Replaced with a
  data-only `while IFS='=' read -r _k _v; do ... done` parser.
- **`check_version()` and `collect_host_meta()` regex paths diverged.**
  `check_version` was unanchored (`([0-9]{2,3})\.0...`) — input like
  `"1234.0 (build 5)"` matched the trailing `234` via leftmost-not-
  anchored bash regex. `collect_host_meta` was anchored. Both now use
  `^[[:space:]]*(...)` and the `cpanel -V` read uses the same
  `2>/dev/null | head -1 | tr -d '\r'` form so they produce identical
  output on stderr-noisy hosts.

### Removed
- Dead `to_epoch()` and `extract_log_ts()` helpers (zero callers).
- Orphan globals: `BUNDLE_TGZ`, `ENV_STRONG`, `ENV_FIXED`,
  `ENV_INCONCLUSIVE`, `ENV_IOC_CRITICAL`, `ENV_IOC_REVIEW`. The latter
  five were assigned by `read_envelope_meta`'s summary-block parser but
  never read; the parser block was deleted with them.
- `HOSTNAME_J` global — duplicated `HOSTNAME_JSON` (same json_esc'd
  hostname, different consumers). Consolidated to `HOSTNAME_JSON`.

### Changed
- VERSION 2.5.0 → 2.6.1. Skipping 2.6.0 because the same fix landed on
  the engineering branch under that label before the slop-cleanup
  cycle expanded scope; 2.6.1 is the first published release.

### Notes
- The `version_detect` signal in `signals[]` was already populated
  correctly pre-fix (it's emitted from local `tier`/`build` parsing
  inside `check_version`, independent of the broken globals). For fleet
  aggregation that needs cpanel version, query
  `signals[].id == "version_detect" → version` as the authoritative
  source. The `meta` record's `cpanel_version` field is now also
  reliable as of v2.6.1.

## sessionscribe-ioc-scan.sh v2.5.0 — 2026-05-02

### Added
- **`--chain-on-all` / `--chain-always` flag** — runs the forensic
  chain (defense + offense + reconcile + kill-chain + bundle) for
  EVERY host scanned, regardless of `host_verdict`. Overrides the
  default CLEAN-skip and overrides `--chain-on-critical`. Pair with
  `--upload` to ship every bundle to intake. Use cases:
  - Fleet baseline collection (snapshot of every host's defense + IOC
    state for trend analysis).
  - Post-incident "are we definitely clean?" verification (CLEAN
    verdict + clean kill-chain artifact = strong evidence).
  - Threat-intel data-lake construction (every scan contributes a
    bundle for cross-fleet pattern mining).
- Forensic-gate priority documented in main flow (highest first):
  `--chain-on-all` > `--chain-on-critical` > default `--full`.
  When both `--chain-on-all` and `--chain-on-critical` are set,
  `--chain-on-all` wins (operator's explicit "I want everything"
  override).
- `forensic_chain_on_all` info signal emitted when the override
  fires, so envelope consumers can attribute the bundle to an
  unconditional run vs. a verdict-gated one.
- `forensic_skipped_clean` note now hints at `--chain-on-all` as
  the explicit override path, so operators discover the flag from
  the existing skip message.

### Changed
- VERSION 2.4.1 → 2.5.0 (additive flag = minor bump).

### Notes
- `--chain-on-all` does NOT change verdict semantics — host_verdict,
  exit_code, and score are computed the same way regardless of which
  gate decides whether forensic phases run. The flag only controls
  whether the kill-chain artifact + bundle get produced.

## sessionscribe-ioc-scan.sh v2.4.1 — 2026-05-02

### Added
- **Visual kill-chain rendering for v2.4.0 advisory entries.** The
  pre-compromise gate keys (`ioc_pattern_e_websocket_shell_hits_pre_compromise`,
  `ioc_pattern_e_websocket_shell_hits_orphan`,
  `ioc_attacker_ip_2xx_on_cpsess_pre_compromise`) were filtered out of
  `read_iocs_from_envelope` in v2.4.0 (severity ∈ {strong, warning}
  filter excluded advisory), so they were invisible in the kill-chain
  timeline. v2.4.1 admits them via a narrow allow-list (specific keys,
  not blanket advisory-pass) so operators see the full forensic
  picture. They render in dedicated zones with cyan styling so they
  remain clearly distinct from the actual attack chronology.
- New verdict types in `phase_reconcile`:
  - `ADVISORY-PRE-COMPROMISE` — for `*_pre_compromise` keys (no CRLF
    anchor or event predates first CRLF chain).
  - `ADVISORY-ORPHAN` — for `*_orphan` keys (post-CRLF but >7 days
    from nearest 2xx_on_cpsess).
  Both short-circuit the standard PRE/POST defense comparison and
  do NOT increment `N_PRE` / `N_POST` (advisory rows are context, not
  attack-chain events).
- New zone IDs in `render_kill_chain`: `adv_pre` (header label
  "ADVISORY (PRE-COMPROMISE CONTEXT)") and `adv_orphan` ("ADVISORY
  (EXPLOITATION-DETACHED)"), both rendered in cyan + bold via the
  existing zone-header machinery so they appear as labeled bands in
  the timeline above/around the real attack zones.
- `render_offense_row` colors `ADVISORY-*` verdicts in cyan to match
  their zone header — visible in the timeline but visually distinct
  from the red/green/yellow attack-chain palette.
- New `counters` line breakout: `advisory=N` shows the count of
  advisory rows; the existing `iocs=N` field now shows attack-chain
  events only (`#OFFENSE_EVENTS - n_advisory`) so operators can read
  it directly without mental subtraction.

### Changed
- `kill-chain.tsv` and `kill-chain.jsonl` will now carry rows with
  verdict values `ADVISORY-PRE-COMPROMISE` / `ADVISORY-ORPHAN` for
  hosts where the v2.4.0 gate demoted Pattern E or 2xx_on_cpsess.
  Aggregator-side: ss-aggregate.py should pattern-match `ADVISORY-*`
  to bucket these separately from the real PRE/POST/UNDEFENDED
  attack-chain rows.
- VERSION 2.4.0 → 2.4.1.

### Notes
- Defense-bypass risk surface — none. Advisory severity is still
  invisible to `ioc_critical` / `ioc_review` aggregation; admitting
  them into the kill-chain renderer does NOT change `host_verdict`,
  exit code, or score. The new `iocs=N` counter in the kill-chain
  block now excludes advisory rows so it matches `#REASONS` accurately.

## sessionscribe-ioc-scan.sh v2.4.0 — 2026-05-02

### Added
- **Pre-compromise temporal gate** for two second-order signals that were
  artificially skewing cluster-onset timeline metrics
  (`ioc_pattern_e_websocket_shell_hits` and
  `ioc_attacker_ip_2xx_on_cpsess`). Both are post-RCE / token-consumption
  evidence — they require a first-order CVE-2026-41940 exploitation
  primitive (`ioc_cve_2026_41940_crlf_access_chain`) as compromise
  anchor. Without one, the hits are most likely shared-infra
  coincidence, recycled-token noise, or pre-disclosure recon (the
  testdev.halcyonplatinum.com pattern: Pattern E 2025-11-24,
  2xx_on_cpsess 2026-03-26, both predating the actual CRLF chain at
  2026-04-30 by months).
- New advisory keys (weight=0; do NOT escalate `host_verdict`; surface
  in ADVISORIES + signals[] for fleet-aggregator visibility):
  - `ioc_attacker_ip_2xx_on_cpsess_pre_compromise` — fired when CRLF
    chain is absent on the host, OR when 2xx_on_cpsess `ts_first`
    PREDATES the first CRLF chain epoch.
  - `ioc_pattern_e_websocket_shell_hits_pre_compromise` — same gate
    against CRLF chain.
  - `ioc_pattern_e_websocket_shell_hits_orphan` — fired when Pattern E
    passes the CRLF gate but is more than `PATTERN_E_2XX_PROXIMITY_SEC`
    (default 7 days) away from the nearest successful token-use event
    (`ioc_attacker_ip_2xx_on_cpsess` first epoch). Operator opened
    shell but never re-entered via cpsess token in the same session
    window — exploitation-detached.
- Each emit now carries `crlf_first_epoch` (and Pattern E adds
  `twoxx_first_epoch` + `proximity_sec`) so downstream consumers
  (ss-aggregate.py, kill-chain readers) have full provenance for the
  gate decision without re-deriving it from the run.
- New constant `PATTERN_E_2XX_PROXIMITY_SEC=604800` (7 days). New
  globals `LOGS_CRLF_CHAIN_FIRST_EPOCH`, `LOGS_2XX_CPSESS_FIRST_EPOCH`
  carry inter-check state (initialized to 0 so `--replay` mode and
  empty-log paths cannot trip `set -u`).
- `ioc_key_to_pattern()` explicit case clauses route the three new keys
  to `init` (not part of the kill-chain pattern alphabet) before the
  `ioc_pattern_e_*` and `ioc_attacker_ip*` globs would catch them.

### Changed
- `check_logs` now calls `check_crlf_access_primitive` BEFORE
  `check_attacker_ips` (was the reverse). Both functions read the
  access_log independently, so the reorder is observation-equivalent
  for hosts where the CRLF chain does not fire; for hosts where it
  does, the CRLF first epoch is now available as the temporal anchor
  for the 2xx_on_cpsess gate at emit time. Pattern E's gate runs in
  `check_destruction_iocs` which already executes after `check_logs`,
  so no reorder is needed there.
- VERSION 2.3.0 → 2.4.0.

### Notes
- The forensic kill-chain reconstruction filters by
  `severity ∈ {strong, warning}` (per `read_iocs_from_envelope`), so
  the new advisory entries are correctly EXCLUDED from
  `kill-chain.jsonl` / `kill-chain.tsv` — pre-compromise events no
  longer pollute the post-hoc attack timeline. They remain in the
  envelope's `signals[]` array for ss-aggregate.py to compute
  pre-compromise threat-intel stats.
- Aggregator-side follow-up: `ss-aggregate.py` should treat
  `_pre_compromise` and `_orphan` keys as their own buckets (not
  collapsed into the strong-tier siblings) so cluster-onset / first-X
  / threat-actor-bucketing analyses see clean post-compromise data.

## sessionscribe-ioc-scan.sh v2.3.0 — 2026-05-02

### Added
- **Gap 10: `session_mtime_vs_ctime_anomaly` IOC** — flags session files
  whose mtime diverges from ctime by `>= SESSION_MTIME_CTIME_THRESHOLD_SEC`
  (default 600s). cpsrvd's session writer sets both timestamps atomically,
  so legitimate sessions have `mtime == ctime` to the second; divergence
  indicates the mtime was modified separately (`touch -d` backdating, or
  `cp -p` / `tar xp` / `rsync -t` restore artifact). Severity is
  `advisory` (weight 0): does NOT escalate `host_verdict` — surfaces in
  ADVISORIES for operator awareness only. Closes the
  `testdev.halcyonplatinum.com` pre-disclosure-outlier investigation:
  the 2025-11-25 first-X anchor that placed cluster-onset 4.5 months
  before the campaign was a session whose mtime was 5+ months earlier
  than ctime; downstream cluster-onset analysis (ss-aggregate.py q5/q8)
  can now discount mtime when this IOC fires.
- `emit_session()` always includes `file_ctime` (ISO-8601 UTC) and
  `mtime_ctime_delta_sec` (signed seconds). Non-breaking schema addition;
  consumers handle missing fields naturally.
- New `analyze_session()` globals `SF_FILE_CTIME`, `SF_FILE_CTIME_ISO`,
  `SF_MTIME_CTIME_DELTA`. `stat -c '%Y %Z'` is a single subprocess call
  (replaces the prior `stat -c %Y` so the new ctime adds zero new
  subprocesses per session).
- Section-level summary `session_mtime_anomaly_summary` (advisory) emits
  when the per-host count is non-zero. The count lets fleet aggregators
  distinguish single-session forgery from fleet-wide restore artifacts
  (mass `cp -p` produces dozens of mtime != ctime sessions).
- `no_session_iocs` all-clear is now gated on `mtime_anomalies == 0` so
  a host with quietly-backdated sessions but no other signals does not
  falsely assert no_session_iocs.

### Changed
- VERSION 2.2.0 → 2.3.0.

## sessionscribe-mitigate.sh v0.5.1 — 2026-05-02

### Fixed
- **EL6 floor regression** — line 470 used `declare -ga SIGNALS_JSON=()`
  which requires bash 4.2+ (the `-g` flag does not exist in bash 4.1.2).
  On CloudLinux 6 / EL6 hosts the script would fail at parse / declare
  time before any phase ran. `SIGNALS_JSON` is declared at top-level
  scope alongside `P_VERDICT`, `P_DETAIL`, `P_NOTES`, `PHASE_ORDER_RUN`
  (lines 464–467, all `declare -A` / `declare -a` without `-g`), so the
  `-g` was redundant. Replaced with `declare -a` to match the rest of
  the top-level declarations and restore bash 4.1.2 compatibility.
  Verified via `bash -n` + `shellcheck -S error` + `--help` smoke test.

### Changed
- VERSION 0.5.0 → 0.5.1.

## sessionscribe-mitigate.sh v0.5.0 — 2026-05-02

### Added
- New `phase_snapshot` runs FIRST in the phase order; captures the
  pre-mitigation state of `/var/cpanel/users/`, `accounting.log[.*]`,
  `audit.log[.*]`, `cpanel.config`, and `sessions/{raw,preauth,cache}/`
  to `<BACKUP_DIR>/pre-mitigate-state.tgz` BEFORE any mutating phase
  perturbs it. Closes Gap 8 from the v3/v4 IOC-scan recommendations:
  rogue WHM API tokens / accounts / accounting-log persistence are no
  longer destroyed by the gap between mitigate-time and forensic-bundle
  capture time.
- `whmapi1 get_tweaksetting` output for `proxysubdomains` and
  `proxysubdomainsfornewaccounts` is captured into
  `pre-mitigate-tweaksettings.txt` next to the tarball, closing the
  per-file backup gap that previously left `phase_proxysub` mutations
  with no undo path.
- `.info` sidecar with sha256 of the tarball, byte size, tier1/tier2
  inventory, sessions-included flag, and tar return code.
- New CLI flags: `--no-snapshot` opt-out, `--max-snapshot-mb MB`
  (default 500) caps the session-corpus tier; tier-1 always captured.
- `ioc-scan`'s `phase_bundle` already includes the entire
  `MITIGATE_BACKUP_ROOT` in `defense-state.tgz`, so the new artifact
  rides into forensic bundles without an ioc-scan-side change.

### Changed
- Phase order now begins with `snapshot`; existing operators relying on
  the prior bare `--apply` behavior should add `--no-snapshot` if they
  want the v0.4.x behavior.

## sessionscribe-mitigate.sh v0.4.2 — 2026-05-02

### Added
- `phase_sessions` IOC-D2: single-line `pass=` on a badpass session with
  no auth markers (well-formed, `pass_count == 1`, not stranded). Closes
  parity gap with the cPanel reference IOC-5. ATTEMPT-class.
- `phase_sessions` standalone IOC-2: `tfa_verified=1` outside known-good
  origins (`handle_form_login`, `create_user_session`,
  `handle_auth_transfer`), non-badpass. Closes parity gap with the
  cPanel reference IOC-2. ATTEMPT-class.
- `tests/sessions/` fixtures + `tests/run-session-tests.sh` harness
  that extracts the awk block from the production script and asserts
  reasons-CSV per fixture. Six cases: two positive, four negative.

### Changed
- `phase_sessions` dry-run output now distinguishes
  `forged session: <path>` (any of A/B/C/D/E/E2/F/H/I fired — confirmed
  forgery) from `attempt session: <path>` (only D2 / 2 fired — session-
  level attempt residue without confirmed forgery markers). Quarantine
  treatment under `--apply` is identical for both classes — the split
  is display-only so operators can read class without parsing reason
  letters.
- `tfa_verified=1` awk anchor tightened to `/^tfa_verified=1$/` (was
  `/^tfa_verified=1/`) so unrelated values like `tfa_verified=10` cannot
  match. Defensive — cpsrvd writes the field as a strict boolean.

### Notes
- Reasons-CSV literal append order in code: A,B-cand,C,D,E,E2,F,H,I,D2,2.
  D2 + 2 are appended after IOC-I to keep the existing prefix stable for
  any downstream consumer that pattern-matches on `reasons:`.
- gawk 3.1.x compat: no `{n}` quantifiers, no 3-arg `match()`, no
  `gensub`/`patsplit`. Verified via the per-release gate.
- has_kg known-good origin list (handle_form_login / create_user_session
  / handle_auth_transfer) was audited against the v0.4.2 patched-tier
  floor: `Cpanel/Security/Authn/TwoFactorAuth/Verify.pm:122` and
  `Cpanel/Server.pm:2295`. Bumping the floor in the future requires
  re-auditing those source files for new tfa-minting code paths.
