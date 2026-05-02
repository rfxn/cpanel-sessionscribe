# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per the affected component.

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
