# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per the affected component.

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
