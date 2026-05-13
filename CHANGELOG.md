# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per affected component.

## ioc-scan v2.8.5 — 2026-05-11

### Fixed
- EL6 floor regression: a global-array primitive aborted on bash
  4.1.2; moved to a floor-safe top-level declaration.
- Pattern M3 FP: LW/Nexcess provisioning sudoers drops demote to
  info-tier; re-image+restore no longer surfaces as a review IOC.
- Patch-state check used exact-equality and FP'd every host above
  the cutoff (post-upcp / direct-update). Now compares build against
  cutoff to match the version gate.
- WP Squared cPanel build series is now parsed and dispatched against
  its own cutoff (11.136.1.7); previously emitted UNKNOWN.
- GSocket shim verdict-gate respects real-root vs CageFS/LVE-jailed
  context; user-jailed root now routes to `*_userland` with
  `affected_user` set.

### Changed
- Pattern M7 wallet scan: batched walk replaces per-file invocation.
- Pattern A `.sorry` enumeration consolidated into a single walk.

### Added
- Defensive walltime caps: 5min on long discovery walks (Pattern A /
  B / G / M7, suspect-IP log scan); 60s on process and socket
  snapshots.
- 30s cap on package-manager health probes, kernel queries, and the
  `needs-restarting` check; 5min cap on the full package inventory.
- Skip the full package inventory when the health probe reports
  anything but `ok` (broken / locked / unknown), avoiding wasted
  timeout budget on a stalled package db.
- `software_inventory_meta.note` adds `query_timeout` and
  `pkgmgr_{broken,locked,unknown}` so consumers can distinguish an
  aborted query from `header_only` (no packages detected). Additive;
  older consumers ignore unknown values.

## ioc-scan v2.8.4 — 2026-05-11

### Fixed
- Bundle envelope written directly to the bundle directory; the
  ledger copy is now the fallback and a diagnostic signal is emitted
  if both fail. Closes a silent-CLEAN cohort affecting all 2.8.x
  bundles when the ledger directory was unwritable.
- Kill-chain bundle meta fields fall back to live globals in `--full`
  mode (previously emitted empty strings outside `--replay`).

## ioc-scan v2.8.3 — 2026-05-11

### Fixed
- Review-tier persistence signals no longer flip `host_root_verdict`
  to COMPROMISED; the soft-variant suffix gate now covers
  `_uncorroborated` / `_documentation` variants.
- Root verdict gate is fully axis-aware: user-attributed evidence
  drives `host_user_verdict` only.
- Self-reference FP — the script's own miner-pattern constants no
  longer trigger detection when the script is copied to operator
  paths (`/root`, `/tmp`, `/opt`).

### Changed
- Miner-wallet search bounded to depth 4 with cache/git/mail prunes.
- C2 IP and image file-reference checks drop `/root/.bash_history`
  to avoid IR-operator FPs; cron and `/etc/cron.d` references stay.

## ioc-scan v2.8.2 — 2026-05-11

### Fixed
- Quarantine demotion now covers external-containment ingestion
  (was only filtering session quarantines); contained-only hosts no
  longer flip COMPROMISED via persistence count.
- Known-bad-username and post-disclosure `.accesshash` checks
  require corroboration; otherwise demote to review-tier.

### Added
- Pattern M extension: monero-wallet literal, known C2 endpoint,
  named docker image — each with live and file-reference variants.
- Documentation-shape heuristic covers IR/runbook/notes paths and
  long-form text/markdown files.

## ioc-scan v2.8.1 — 2026-05-11

### Added
- Pattern M: rogue UID=0 account plus cryptominer botnet cluster.
  Six primitives (UID=0 user, known-bad usernames, NOPASSWD sudoers
  post-disclosure, miner cron/live containers, cron self-heal,
  post-disclosure `/root/.accesshash`). Persistence-class.

### Changed
- Hosts whose only evidence is mitigate-quarantined sessions demote
  to SUSPICIOUS unless a live signal corroborates. Adds advisory
  signal `ioc_quarantine_only_no_live_corroboration`.

## ioc-scan v2.8.0 — 2026-05-10

### Changed (BREAKING)
- `host_verdict` replaced by `host_root_verdict` and
  `host_user_verdict` for multi-tenant attribution. Every signal
  carries `affected_user` and `actor_privilege`.
- Envelope adds a per-user verdict array (cap 50) plus
  `host_user_summary`; JSONL gains `user_summary` events.
- CSV column 6 renamed (`host_verdict` → `host_root_verdict`);
  three new columns inserted (`host_user_verdict`,
  `affected_user_count`, `users_truncated`). Positional consumers
  must update.
- New `--chain-on-root-only` flag scopes `--full` to host-rebuild
  candidates.
- Bundle meta `schema_version` bumps to 5.
- Fleet aggregators and the comp.list endpoint must update in
  lockstep before rollout.

## ioc-scan v2.7.44 — 2026-05-08

### Fixed
- `software_inventory_meta.note` disambiguates `header_only`
  (no packages detected) and `not_collected` (encoder never ran).
  Wire format unchanged; values are additive.

## ioc-scan v2.7.43 — 2026-05-09

### Changed
- Per-host package inventory now embedded inside the JSON envelope
  (gzip+base64) in addition to the bundle sidecar. Unblocks fleet
  CVE/erratum reconciliation for telemetry-only collectors.
- 1 MB encoded cap; oversize payloads emit empty body with a note
  and the sidecar retains the full data.

## ioc-scan v2.7.42 — 2026-05-08

### Added
- Per-host software digest in the JSON envelope and bundle manifest:
  package-manager health (ok/broken/locked/unknown), disk + inode
  pressure, running-kernel version + tainted state, installed
  package inventory sidecar, pending-reboot indicator.

## ioc-scan v2.7.41 — 2026-05-08

### Changed
- `--upload` requires an explicit token (`--upload-token` flag or
  `RFXN_INTAKE_TOKEN` env). Embedded default removed; missing token
  fails fast.
- `--telemetry-cron add` omits `--chain-upload` from the generated
  cron line when no upload token is supplied; install summary prints
  the resulting upload posture.

### Fixed
- Cron-line percent escaping — the previous heredoc emitted a
  literal `%` that cron treated as a stdin separator, silently
  failing every tick on every host using `--telemetry-cron` since
  v2.7.11.
- Cron file now sets `MAILTO=""` so cron-side parse errors stop
  mailing root.

### Added
- Self-heal on script start: writable broken cron files are
  rewritten in-place (idempotent; preserves operator-set MAILTO).

## ioc-scan v2.7.39 — 2026-05-07

### Changed
- Runtime IOC severity is UID-discriminated across the track:
  non-root hits demote from `live_compromise` to `strong`
  (SUSPICIOUS) with a `_userland` key suffix. Root-only LPE binaries
  and the base64-wrapped persistence shim remain at the higher tier.

## ioc-scan v2.7.38 — 2026-05-06

### Changed
- GSocket respawn-shim severity now splits by the embedded UID:
  root-owned stays COMPROMISED; non-root demotes to SUSPICIOUS with
  a `_userland` key.

## ioc-scan v2.7.37 — 2026-05-06

### Fixed
- Bundle `lsof.txt` no longer mixes stderr warnings into data.
- Four envelope signals distinguish empty `lsof.txt` causes
  (captured / timeout / failed / empty / missing).

## ioc-scan v2.7.36 — 2026-05-06

### Fixed
- `code_verdict` is now driven purely by `cpanel -V`. The score-based
  fallback that flipped non-authoritative hosts to VULNERABLE on a
  single runtime hit has been removed. Verdict ladder is
  VULNERABLE / PATCHED / INCONCLUSIVE. `host_verdict` is unaffected.

## ioc-scan v2.7.35 — 2026-05-06

### Added
- Runtime-state IOC track grading live process and connection state
  alongside session forensics. Covers known-bad on-disk paths,
  GSocket relay-keys and respawn shims (plaintext and base64),
  masqueraded miner binaries, miner argv/wallet/pool tells, LPE
  binary names, reverse-shell shapes (perl, bash, nc, ncat, socat,
  python), generic 95-char wallet regex, known C2 IPs/hosts in
  cmdline and ESTAB.
- New `live_compromise` severity tier — single-hit unambiguous
  evidence; bypasses the compromise-class ladder, ranks above
  `[IOC]` in human output.
- Envelope: standardised seven-field forensic fingerprint
  (sha256/md5/size/ctime/mtime/owner/mode) on every flagged file.
- Bundle: `lsof.txt` snapshot (`timeout 30 lsof -nP -X`).

### Fixed
- Patched-table lookup runs before the EOL short-circuit; hosts on
  patched LTS lines below tier 110 no longer scan VULNERABLE.

### Known limitations
- Runtime IOCs not yet rendered in `kill-chain.{tsv,jsonl}` (v2.7.36
  follow-up).

## ioc-scan v2.7.33 — 2026-05-05

### Changed
- Vendor patched-build table refreshed (two new tiers added). No
  scoring or verdict-gate changes.

## mitigate v0.7.4 — 2026-05-04

### Fixed
- EPEL install on CentOS 6/7 now disables rotted MariaDB 10.x repos
  so preflight no longer aborts before reaching `epel-release`.

## ioc-scan v2.7.32 — 2026-05-05

### Changed
- Scoring rebalance: destruction amplifiers by count and subtype,
  cross-pattern letter cluster bonus, persistence multiplier raised
  to ×3 / ×5 / ×8 (cap 4), recon / attempt aggregate evidence
  capped at +20, quarantine reasons-aware emit severity, compromise
  floor anchored to letter count and persistence count.
- Verdict gate unchanged.

## ioc-scan v2.7.31 — 2026-05-05

### Changed
- Pattern J reduced to dossier-only: known-path existence, exact
  process-name match, at-job content reference. Removed the udev
  and systemd shape probes and six unused config knobs.

### Added
- Soft-variant suffix gate: `_review`, `_diagnostic`, `_candidate`,
  `_orphan`, `_pre_compromise`, `_probes_only`, etc. are excluded
  from persistence-class accounting before verdict.

### Fixed
- Pruned write-only state flags and a dead helper; shellcheck clean.

## ioc-scan v2.7.30 — 2026-05-05

### Fixed
- Per-session score inflation: first strong emit per session credits
  base score; repeats bump a reason count only. Confidence-tier
  bonus rewards multi-reason sessions; quarantined sessions reach
  parity via `reasons_ioc`.

### Added
- Envelope summary + CSV columns `session_tiered_count` and
  `session_max_reasons`.

## ioc-scan v2.7.29 — 2026-05-04

- Comment-only changes; no behavioural change.

## ioc-scan v2.7.28 — 2026-05-04

### Fixed
- COMPROMISED gate is now class-aware: only persistence /
  destruction / token-used signals trigger COMPROMISED. Attempt-class
  (CRLF chain, recon, quarantined-only, Pattern E alone) routes to
  SUSPICIOUS.
- Pattern G IP-labelled-key FP: trust-regex filter now applies in
  both phases; a single labelled key cannot flip the host.

### Added
- `summary.compromise_critical` distinguishes compromise-class from
  any-class strong evidence.

## ioc-scan v2.7.27 — 2026-05-04

### Added
- Persistence-cluster scoring: two or more distinct persistence
  patterns on one host multiply persistence weight (×2 / ×3 / ×4
  cap). Warning-tier persistence on its own can escalate to
  COMPROMISED. Score floor of 25 when persistence is present.

## ioc-scan v2.7.26 — 2026-05-04

### Fixed
- VULNERABLE recommended-action block no longer prints `bash bash`
  when the script is invoked via stdin pipe or process substitution.

## mitigate v0.7.3 — 2026-05-03

### Security
- SSH-key prune now re-validates the manifest path at consume-time
  (defense-in-depth for the v0.7.2 trap-injection fix). Refused rows
  record `refused_hostile_path`.

## mitigate v0.7.2 — 2026-05-03

### Security
- Closed a SIGINT/SIGTERM trap-string command-injection vector in
  the SSH-key prune. Paths containing shell metacharacters, control
  characters, or quoting are refused before any trap is set.

### Fixed
- Operator recovery hint shell-quotes both paths.
- Apply-mode sshkey manifest rows now populate `result_detail` and
  `sha256_pre` (previously null on every prune).

## mitigate v0.7.1 — 2026-05-03

### Fixed
- Removed-keys JSONL sidecar properly escapes the comment field.
- Indented `authorized_keys` lines (legal per `sshd(8)`) now count
  in step-10 verification.
- Canonical home-directory walk uses `-maxdepth 1` (was returning
  depth-2 subdirs).

## mitigate v0.7.0 — 2026-05-03

### Added
- `phase_kill` SSH-key surgical prune (`--ssh-prune`) removes
  `authorized_keys` lines whose comment does not match the trust
  regex. Per-line precision with sha256 chain-of-custody; the
  original file is preserved in the quarantine area; a JSONL
  sidecar lists removed keys with a recovery hint.
- Flags: `--ssh-allow REGEX` (site-specific trust extensions;
  repeatable), `--ssh-allow-lockout`, `--ssh-prune-unlabeled`,
  `--ssh-allow-drift`.
- New `kind:sshkey` manifest item class with per-host summary
  counters (files planned/pruned/clean/kept_unlabeled, keys
  pruned/kept, etc).

### Behaviour
- When `--ssh-prune` is active, Pattern G whole-file quarantine is
  suppressed for canonical `authorized_keys` paths with an audit
  marker.
- Gated on `host_verdict==COMPROMISED`; bypass with `--kill-anyway`.

## mitigate v0.6.1 — 2026-05-03

### Fixed
- Path-traversal bypass in the allowlist guard on legacy EL6 floor:
  refuses `..` segments, probes for `realpath -m` support, and falls
  back to a pure-bash path normaliser that collapses `/./` and
  `/../`.

## mitigate v0.6.0 — 2026-05-03

### Added
- `phase_kill`: targeted quarantine plus IP block driven by an
  ioc-scan envelope (default-off; `--kill`). Gated on
  `host_verdict==COMPROMISED` (override: `--kill-anyway`).
- File quarantine *moves* (never deletes) Pattern A/C/D/F/G/H/I/J
  evidence to a mirrored path with sha256 chain-of-custody.
- Per-incident CSF IP blocks (IPv4 + IPv6); private, loopback,
  link-local, multicast, and malformed addresses are refused.
- Optional registration of the rfxn fleet blocklist via
  `/etc/csf/csf.blocklists`; probes and enables `LF_IPSET`.
- Path allowlist plus envelope-injection guards.
- CLI flags: `--kill`, `--envelope PATH`, `--kill-anyway`,
  `--no-kill`.

## ioc-scan v2.7.25 — 2026-05-04

### Fixed
- Suspect-IP correlation now drops RFC1918 / loopback addresses
  (admin operators) before reporting.
- Kill-chain render no longer aborts under `set -u` on hosts whose
  defense state did not set every conditional timer global.

## ioc-scan v2.7.23 — 2026-05-04

### Fixed
- Pattern G no longer emits a duplicate kill-chain row when a file
  trips both forged-mtime and known-bad-comment; rollup note label
  corrected.

## ioc-scan v2.7.22 — 2026-05-04

### Changed
- Pattern G kill-chain noise reduction: per-file rollup gated on a
  high-confidence trigger (forged stamp or known-bad comment).

### Reverted
- Pattern J payload-string-in-history primitive removed; the URL
  was internal sharing infrastructure and tripped on every triage
  host.

## ioc-scan v2.7.20 — 2026-05-04

### Added
- Pattern J dossier-driven primitives: literal known-path existence,
  matching process names, at-job content reference.
- Pattern K paranoid-cleanup chain primitive.
- Quarantined-session signals promote warning → strong when
  `reasons_ioc` indicates one of the canonical exploit shapes.

### Changed
- Pattern J heuristic `_candidate` warning → advisory until
  corroborated by the new literal-path / process / at-job signals.

## ioc-scan v2.7.18 — 2026-05-04

### Changed
- Self-fetch cron line prefers the GitHub raw URL and falls back to
  the CDN. Bootstrap one-liner aligned to the canonical path.

## ioc-scan v2.7.17 — 2026-05-04

### Changed
- `--telemetry-cron add` self-fetches the latest script at every
  tick and atomically installs it before running, eliminating the
  on-disk prerequisite from v2.7.16 and making curl-pipe install
  viable. Bounds fleet version-skew to one interval plus splay.

## ioc-scan v2.7.16 — 2026-05-04

### Added
- `--telemetry-cron add 2h` interval; allowlist now
  `1h | 2h | 6h | 12h | 24h` (default `6h`).

### Changed
- Jitter window widened to 5-300s; scan wrapped in `timeout 300` so
  hung runs cannot accumulate overlapping cron tasks.

## ioc-scan v2.7.15 — 2026-05-04

### Changed
- The CRLF access-primitive (CVE-2026-41940 X stack) demoted from
  strong → warning. ATTEMPT-class only; compound-evidence hosts
  still flip COMPROMISED via Pattern A-L or post-attack 2xx signals.

## ioc-scan v2.7.14 — 2026-05-04

### Changed
- Four review/probe-only Pattern E and attacker-IP keys demoted from
  warning to advisory so they no longer route to SUSPICIOUS.
- Diagnostic-sample emits capped at one per host.

## ioc-scan v2.7.13 — 2026-05-04

### Changed
- The unfixed OIDC operator-precedence bug demoted from bug-kind to
  marker-kind. It is a pre-existing post-auth defense-in-depth issue,
  not the SessionScribe primitive.

## ioc-scan v2.7.12 — 2026-05-03

### Security
- Cron file mode tightened to 0600 (was 0644). The cron line embeds
  the intake token verbatim; world-readable mode allowed any local
  user to read it via `cat`.

## ioc-scan v2.7.11 — 2026-05-03

### Added
- `--telemetry-cron <add|remove> [INTERVAL]` installs or removes a
  system cron entry running the telemetry path on a fixed interval
  with 5-180s random-sleep jitter. Allowed intervals
  `1h|6h|12h|24h`. Pass-through of `--upload-url` / `--upload-token`
  with single-quote rejection; EUID 0 enforced at install time.

## ioc-scan v2.7.10 — 2026-05-03

### Added
- `--telemetry` lite-bundle mode (~50-100 KB per host vs ~50 MB for
  `--full`): keeps every forensic artifact, drops the heavy
  tarballs.
- `--telemetry-url URL` envelope-only POST with curl → wget →
  bash-native (`/dev/tcp`, `openssl s_client`) fallback ladder.
- Knobs: `--telemetry-token`, `--telemetry-timeout` (default 15s),
  `--telemetry-retry` (default 2, backoff 2s/4s),
  `--telemetry-max-bytes` (default 5 MB).
- `telemetry_*` signal vocabulary so transport failures never flip
  `host_verdict`.
- Incompatible with `--no-ledger`.

## ioc-scan v2.7.9 — 2026-05-03

### Added
- CSF firewall posture detector. Validates that CSF/lfd is installed
  AND actively enforcing on every fleet host. Surfaces twelve
  break-modes (kill-switch, TESTING mode, lfd dead, missing iptables
  binary, CSF terminal chains absent, INPUT chain not jumping to
  LOCALINPUT, ipset promised but missing, etc).
- `posture_*` signal prefix — surfaces in section matrix and JSON
  envelope without flipping `host_verdict`.

## ioc-scan v2.7.8 — 2026-05-03

### Added
- Pattern K (Cloudflare-fronted second-stage backdoor): literal
  hostname plus PID-tagged hidden-temp file shape.
- Pattern L (filesystem nuke `rm -rf --no-preserve-root /`):
  primary regex plus command-envelope corroborator.
- Pattern F: additional `__CMD_DONE_<nanosec>__` marker with three
  classification tiers.
- Pattern G lsyncd-amplification corroboration surfaces blast-radius
  when Pattern G fires alongside lsyncd evidence.

### Fixed
- History-match classifier now recognises path-prefixed shell forms
  (`/bin/sh`, `/bin/bash`, `/usr/bin/sh`, `/usr/bin/bash`).
- Standalone K2 / L2 hostile emits no longer swallowed when K1 / L1
  fire diagnostic-only.

## ioc-scan v2.7.7 — 2026-05-03

### Fixed
- Diagnostic-shape FP filter parity for Patterns F, H2, H3, and A
  (v2.7.5's inline classifier hoisted to a shared helper).
  Pattern A qTox ransom note now distinguishes hostile (exact ID
  hash), review (`qtox`/`Sorry-ID` without exact hash), and
  documentation tiers.

## ioc-scan v2.7.5 — 2026-05-03

### Fixed
- Pattern C false-positive on responder-checked hosts: bash_history
  lines are classified before emit. Read-only verbs
  (`history`, `grep`, `cat`, `ls`, `stat`) no longer flip
  COMPROMISED; hostile-shape (download verb, pipe-to-shell, `chmod
  +x`, source/eval/exec adjacent) preserved at strong.

## ioc-scan v2.7.4 — 2026-05-03

### Added
- Pattern J ExecStart allowlist now covers `/usr/local/lp/`
  (operator-deployed Prometheus exporters).

### Fixed
- Bash 4.1 floor regression: negative-substring expression replaced
  with an explicit-offset form; four additional empty-array
  dereference sites guarded.

## ioc-scan v2.7.3 — 2026-05-03

### Fixed
- Bash 4.1 floor regression: empty-array dereferences in the
  Pattern J persistence checker guarded.

## ioc-scan v2.7.2 — 2026-05-03

### Added
- Bundle retention sweep: keeps the three newest bundles, removes
  older ones plus sidecar `.upload.tgz`. Operator-renamed entries
  preserved. Configurable via `BUNDLE_RETENTION` (0 disables).

### Fixed
- Top-of-file version-header drift.

## ioc-scan v2.7.1 — 2026-05-03

### Added
- Pattern J — init-facility persistence detection (udev rules and
  systemd unit shape probes; RPM-ownership gated; snapshot-aware).
- Mitigate-quarantine secondary read: walks the mitigate backup
  area and emits one synthetic warning-tier signal per quarantined
  session sidecar (cap 200 per scan). Falls back to live mtime when
  sidecar is missing.

## ioc-scan v2.6.1 — 2026-05-02

### Fixed
- Globals declared empty but read downstream are now populated: host
  meta (cpanel version, OS, primary IP, LP UID), patched-build map,
  unpatched-tier array.
- Replaced an `eval`-based `/etc/os-release` parser
  (shell-injection-vulnerable) with a data-only `IFS='=' read`
  parser.
- Unpatched-tier scalar iterated as an array misclassified every
  UNPATCHABLE-tier host as UNPATCHED; converted to an array.

### Removed
- Dead epoch helpers; orphan globals; duplicate hostname global.

## ioc-scan v2.5.0 — 2026-05-02

### Added
- `--chain-on-all` / `--chain-always` runs the forensic chain
  (defense + offense + reconcile + kill-chain + bundle) on every
  host regardless of `host_verdict`. Pairs with `--upload`. Does
  not change verdict semantics.

## ioc-scan v2.4.1 — 2026-05-02

### Added
- Kill-chain rendering for advisory entries introduced in v2.4.0:
  new `ADVISORY-PRE-COMPROMISE` and `ADVISORY-ORPHAN` verdict
  values, rendered in cyan; new `advisory=N` counter line that
  remains separate from the `iocs=N` attack-chain count.

### Changed
- `kill-chain.{tsv,jsonl}` may now carry `ADVISORY-*` rows; fleet
  aggregators should bucket separately from PRE/POST/UNDEFENDED.

## ioc-scan v2.4.0 — 2026-05-02

### Added
- Pre-compromise temporal gate for second-order signals (websocket
  shell hits, 2xx-on-cpsess). Both require a first-order CRLF
  access-chain anchor; otherwise emit advisory keys
  (`_pre_compromise` / `_orphan`) at weight 0.

## ioc-scan v2.3.0 — 2026-05-02

### Added
- `session_mtime_vs_ctime_anomaly` advisory (default threshold
  600s) flags `touch -d` backdating and restore-artifact divergence.
  Schema-additive: `file_ctime` and `mtime_ctime_delta_sec` always
  emitted. Does not escalate `host_verdict`.

## mitigate v0.5.1 — 2026-05-02

### Fixed
- EL6 floor regression: bash 4.2+ `declare -ga` replaced with
  top-level `declare -a` so 4.1.2 parses.

## mitigate v0.5.0 — 2026-05-02

### Added
- `phase_snapshot` runs first and captures pre-mitigation state of
  users, accounting/audit logs, cpanel config, and session
  directories to a single tarball with a sha256 sidecar before any
  mutating phase runs.
- Tweaksetting capture for `proxysubdomains[fornewaccounts]` closes
  the per-file backup gap for the proxysub phase.
- Flags: `--no-snapshot`, `--max-snapshot-mb MB` (default 500).

### Changed
- Phase order now begins with `snapshot`; operators relying on bare
  `--apply` should add `--no-snapshot`.

## mitigate v0.4.2 — 2026-05-02

### Added
- Two new session attempt-class IOCs: single-line `pass=` on a
  badpass session with no auth markers; standalone `tfa_verified=1`
  outside known-good origins.
- Session-IOC test harness with six fixture cases.

### Changed
- Dry-run output distinguishes "forged session" from "attempt
  session"; quarantine treatment under `--apply` is identical.
