# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per affected component.

## ioc-scan v2.8.7 — 2026-05-15

### Changed
- MySQL data-directory wipe shape (Pattern B) demoted to informational; too many benign operator causes (manual cleanup, restore-in-progress) to drive a destructive verdict on its own.
- Shell-history-only findings across Patterns C, F, H, L, and M demoted to review-tier; bash_history evidence alone no longer escalates a host to COMPROMISED. Hits sourced from on-disk droppers, persistence files, crontabs, or live sockets are unchanged.

## ioc-scan v2.8.6 — 2026-05-13

### Security
- Patched-build cutoffs refreshed for CVE-2026-41940 across all 11 supported tiers (11.86–11.136) and the WP Squared 136.1 series.

## ioc-scan v2.8.5 — 2026-05-11

### Fixed
- Bash 4.1 floor regression: array handling corrected.
- Pattern M false positive: LW/Nexcess provisioning sudoers demoted to info-tier; re-image+restore no longer surfaces as a review IOC.
- Patch-state check incorrectly classified hosts above the patched cutoff as vulnerable; build comparison corrected.
- WP Squared cPanel build series now classifies correctly; previously emitted UNKNOWN.
- GSocket shim detection respects CageFS/LVE-jailed context; user-space root no longer elevates the host-root verdict.

### Changed
- Pattern M wallet scan uses a batched file walk.
- Walltime caps applied to all long-running discovery walks and process/socket snapshots.

### Added
- Package inventory skipped when the package manager reports as broken, locked, or unknown.
- `software_inventory_meta.note` distinguishes aborted inventory queries from empty results.

## ioc-scan v2.8.4 — 2026-05-11

### Fixed
- Envelope now written to the bundle directory first; a diagnostic signal is emitted if both the bundle and ledger writes fail. Fixes a silent-clean result on hosts where the ledger directory was unwritable.
- Kill-chain bundle meta fields now populate correctly in `--full` mode; previously emitted empty strings.

## ioc-scan v2.8.3 — 2026-05-11

### Fixed
- Review-tier persistence signals no longer elevate the host-root verdict to COMPROMISED.
- Root verdict gate is fully axis-aware: user-attributed evidence drives `host_user_verdict` only.
- Self-reference false positive: the script no longer triggers miner-pattern detection when copied to operator paths.

### Changed
- Miner-wallet search bounded to depth 4 with common cache, git, and mail directories excluded.
- bash_history excluded from C2 and file-reference checks to avoid false positives on IR-operator paths.

## ioc-scan v2.8.2 — 2026-05-11

### Fixed
- Quarantine demotion now covers externally-contained files; contained-only hosts no longer flip COMPROMISED.
- Known-bad-username and post-disclosure access-hash checks require corroboration before escalating.

### Added
- Pattern M extended with additional cryptominer and C2 indicators; live and file-reference variants included.
- Documentation-shape heuristic covers IR, runbook, and notes paths plus long-form markdown files.

## ioc-scan v2.8.1 — 2026-05-11

### Added
- Pattern M: rogue UID=0 account and cryptominer botnet cluster detection; persistence-class evidence.

### Changed
- Hosts with only mitigate-quarantined session evidence demote to SUSPICIOUS unless a live signal corroborates.

## ioc-scan v2.8.0 — 2026-05-10

### Changed
- **Breaking:** `host_verdict` replaced by `host_root_verdict` and `host_user_verdict` for multi-tenant attribution; every signal carries `affected_user` and `actor_privilege`.
- **Breaking:** Envelope adds a per-user verdict array (cap 50) plus `host_user_summary`; JSONL gains `user_summary` events.
- **Breaking:** CSV column 6 renamed (`host_verdict` → `host_root_verdict`); three new columns added (`host_user_verdict`, `affected_user_count`, `users_truncated`). Positional consumers must update.
- New `--chain-on-root-only` flag scopes `--full` forensic chain to host-rebuild candidates.

## ioc-scan v2.7.44 — 2026-05-08

### Fixed
- `software_inventory_meta.note` now distinguishes empty inventory from inventory that was never collected.

## ioc-scan v2.7.43 — 2026-05-09

### Changed
- Per-host package inventory now embedded in the JSON envelope in addition to the bundle sidecar; enables fleet CVE reconciliation for telemetry-only collectors.
- Inventory embedding capped at 1 MB; oversized hosts retain the full inventory only in the bundle sidecar.

## ioc-scan v2.7.42 — 2026-05-08

### Added
- Per-host software digest in the JSON envelope and bundle manifest: package-manager health, disk and inode pressure, running-kernel version and tainted state, installed package inventory, and pending-reboot indicator.

## ioc-scan v2.7.41 — 2026-05-08

### Changed
- `--upload` requires an explicit token (`--upload-token` flag or `RFXN_INTAKE_TOKEN` env); missing token fails fast.
- `--telemetry-cron add` omits upload from the generated cron line when no token is supplied.

### Fixed
- Cron-line percent encoding fixed; a literal `%` was silently failing every telemetry-cron tick.
- Cron file sets `MAILTO=""` to suppress cron-side error mail.

### Added
- On startup, broken cron files are rewritten in place (idempotent; preserves operator-set MAILTO).

## ioc-scan v2.7.39 — 2026-05-07

### Changed
- Runtime IOC severity is privilege-discriminated: non-root process hits demote from `live_compromise` to SUSPICIOUS with a `_userland` key suffix.

## ioc-scan v2.7.38 — 2026-05-06

### Changed
- GSocket respawn-shim severity splits by process UID: root-owned stays COMPROMISED; non-root demotes to SUSPICIOUS.

## ioc-scan v2.7.37 — 2026-05-06

### Fixed
- Bundle `lsof.txt` no longer mixes stderr warnings into captured data.
- Envelope signals now distinguish the cause of an empty `lsof.txt` capture.

## ioc-scan v2.7.36 — 2026-05-06

### Fixed
- `code_verdict` is now driven by the installed cPanel version only; the score-based fallback that incorrectly flagged hosts on a single runtime hit has been removed. Verdict ladder: VULNERABLE / PATCHED / INCONCLUSIVE.

## ioc-scan v2.7.35 — 2026-05-06

### Added
- Runtime-state IOC track: detects live malicious processes, connections, and on-disk artifacts alongside session forensics.
- New `live_compromise` severity tier for single-hit unambiguous evidence; ranks above `[IOC]` in output and bypasses the compromise-class ladder.
- Envelope includes a forensic fingerprint (hash, size, timestamps, ownership) on every flagged file.
- Bundle includes an `lsof` process-connection snapshot.

### Fixed
- Patched-table lookup now runs before the EOL check; patched LTS hosts below tier 110 no longer scan as VULNERABLE.

## ioc-scan v2.7.33 — 2026-05-05

### Changed
- Patched-build table refreshed; no behavior change.

## mitigate v0.7.4 — 2026-05-04

### Fixed
- EPEL install on CentOS 6/7 now disables stale MariaDB repos so preflight no longer aborts before reaching `epel-release`.

## ioc-scan v2.7.32 — 2026-05-05

### Changed
- Scoring rebalance: destruction, persistence, and attempt signals each have updated amplifiers and caps; verdict gate unchanged.

## ioc-scan v2.7.31 — 2026-05-05

### Changed
- Pattern J scope reduced to literal known-path, process-name, and at-job evidence; heuristic udev/systemd probes removed.

### Added
- Review and diagnostic persistence signals no longer elevate the verdict.

## ioc-scan v2.7.30 — 2026-05-05

### Fixed
- Per-session scoring corrected: repeated signals no longer inflate the score; multi-reason sessions receive a confidence bonus.

### Added
- Envelope summary and CSV columns `session_tiered_count` and `session_max_reasons`.

## ioc-scan v2.7.28 — 2026-05-04

### Fixed
- COMPROMISED verdict now requires persistence, destruction, or token-used evidence; attempt-class signals (CRLF chain, recon, Pattern E alone) route to SUSPICIOUS.
- Pattern G false positive: trust filter now applies in all phases; a single labeled key no longer flips COMPROMISED.

### Added
- `summary.compromise_critical` distinguishes compromise-class from any-class strong evidence.

## ioc-scan v2.7.27 — 2026-05-04

### Added
- Persistence-cluster scoring: multiple distinct persistence patterns multiply the score (up to ×4); warning-tier persistence alone can escalate to COMPROMISED.

## ioc-scan v2.7.26 — 2026-05-04

### Fixed
- Recommended-action block no longer prints garbled output when the script is piped or process-substituted.

## mitigate v0.7.3 — 2026-05-03

### Security
- SSH-key prune re-validates the manifest path at consume-time.

## mitigate v0.7.2 — 2026-05-03

### Security
- Command-injection vector in the SSH-key prune closed; paths with shell metacharacters or control characters are refused before any trap is set.

### Fixed
- Recovery hint now correctly quotes paths.

## mitigate v0.7.1 — 2026-05-03

### Fixed
- Removed-keys JSONL sidecar properly escapes the comment field.
- Indented `authorized_keys` lines (legal per sshd) now count during verification.
- Home-directory walk correctly limits to top-level directories.

## mitigate v0.7.0 — 2026-05-03

### Added
- `--ssh-prune` SSH-key surgical prune: removes `authorized_keys` lines whose comment does not match the trust regex. Per-line precision with sha256 chain-of-custody; original file preserved; a JSONL sidecar lists removed keys with a recovery hint.
- Flags: `--ssh-allow REGEX` (repeatable), `--ssh-allow-lockout`, `--ssh-prune-unlabeled`, `--ssh-allow-drift`.
- `kind:sshkey` manifest item class with per-host counters.

### Changed
- When `--ssh-prune` is active, Pattern G whole-file quarantine is suppressed for canonical `authorized_keys` paths.
- Gated on `host_verdict==COMPROMISED`; bypass with `--kill-anyway`.

## mitigate v0.6.1 — 2026-05-03

### Fixed
- Path-traversal bypass in the allowlist guard patched; EL6-compatible path normalization added.

## mitigate v0.6.0 — 2026-05-03

### Added
- `--kill`: targeted quarantine and IP block driven by an ioc-scan envelope (gated on `host_verdict==COMPROMISED`, override: `--kill-anyway`).
- File quarantine moves Pattern A/C/D/F/G/H/I/J evidence to a mirrored path with sha256 chain-of-custody.
- Per-incident CSF IP blocks (IPv4 + IPv6); private, loopback, and malformed addresses refused.
- Optional rfxn fleet blocklist integration via CSF blocklists.
- Path allowlist and envelope-injection guards.
- CLI flags: `--kill`, `--envelope PATH`, `--kill-anyway`, `--no-kill`.

## ioc-scan v2.7.25 — 2026-05-04

### Fixed
- Suspect-IP correlation drops RFC1918 and loopback addresses before reporting.
- Kill-chain render no longer aborts under `set -u` when some defense-state timers are absent.

## ioc-scan v2.7.23 — 2026-05-04

### Fixed
- Pattern G no longer emits duplicate kill-chain rows for files with multiple indicators.

## ioc-scan v2.7.22 — 2026-05-04

### Changed
- Pattern G kill-chain noise reduction: per-file rollup gated on a high-confidence trigger.

### Removed
- Pattern J bash-history payload check; it generated false positives on IR triage hosts.

## ioc-scan v2.7.20 — 2026-05-04

### Added
- Pattern J dossier-driven primitives: literal known-path existence, process-name match, at-job content reference.
- Pattern K paranoid-cleanup chain detection.
- Quarantined-session signals escalate to strong when the session shows canonical exploit indicators.

### Changed
- Pattern J heuristic evidence demoted to advisory until corroborated by literal-path, process, or at-job signals.

## ioc-scan v2.7.18 — 2026-05-04

### Changed
- Cron self-fetch prefers the GitHub raw URL and falls back to the CDN.

## ioc-scan v2.7.17 — 2026-05-04

### Changed
- `--telemetry-cron` self-updates the script at each tick before running; fleet version-skew bounded to one interval.

## ioc-scan v2.7.16 — 2026-05-04

### Added
- `--telemetry-cron add 2h` interval; allowed intervals now `1h|2h|6h|12h|24h` (default `6h`).

### Changed
- Cron jitter widened to 5-300s; scan wrapped in a 300s hard timeout to prevent overlapping runs.

## ioc-scan v2.7.15 — 2026-05-04

### Changed
- CRLF access primitive (CVE-2026-41940 exploit stack) demoted from strong to warning; attempt-class only. Compound-evidence hosts still flip COMPROMISED via Pattern A–L or post-attack 2xx signals.

## ioc-scan v2.7.14 — 2026-05-04

### Changed
- Review and probe-only Pattern E signals demoted to advisory; they no longer route to SUSPICIOUS.
- Diagnostic-sample emits capped at one per host.

## ioc-scan v2.7.13 — 2026-05-04

### Changed
- OIDC operator-precedence advisory reclassified as a pre-existing post-auth defense issue, not a CVE-2026-41940 indicator.

## ioc-scan v2.7.12 — 2026-05-03

### Security
- Cron file mode tightened to 0600; the file embeds the intake token and was previously world-readable.

## ioc-scan v2.7.11 — 2026-05-03

### Added
- `--telemetry-cron <add|remove> [INTERVAL]` installs or removes a system cron entry for the telemetry path; jitter 5-180s, root-only, intervals `1h|6h|12h|24h`.

## ioc-scan v2.7.10 — 2026-05-03

### Added
- `--telemetry` lite-bundle mode (~50-100 KB per host vs ~50 MB for `--full`): retains every forensic artifact, drops heavy tarballs.
- `--telemetry-url URL` envelope POST with curl → wget → bash-native fallback.
- Knobs: `--telemetry-token`, `--telemetry-timeout` (default 15s), `--telemetry-retry` (default 2), `--telemetry-max-bytes` (default 5 MB).
- `telemetry_*` signal vocabulary so transport failures never flip `host_verdict`.

## ioc-scan v2.7.9 — 2026-05-03

### Added
- CSF firewall posture detector: verifies CSF/lfd is installed and actively enforcing; surfaces common misconfiguration and break conditions.
- `posture_*` signals appear in the section matrix and JSON envelope without affecting `host_verdict`.

## ioc-scan v2.7.8 — 2026-05-03

### Added
- Pattern K (Cloudflare-fronted second-stage backdoor): literal hostname and PID-tagged hidden-temp file shape.
- Pattern L (filesystem nuke): primary and corroborating command-envelope indicators.
- Pattern F: additional marker detection with three classification tiers.
- Pattern G lsyncd-amplification corroboration surfaces blast-radius when Pattern G fires alongside lsyncd evidence.

### Fixed
- History-match classifier now recognises path-prefixed shell forms.
- Secondary indicators for Pattern K and L no longer suppressed when the primary fires diagnostic-only.

## ioc-scan v2.7.7 — 2026-05-03

### Fixed
- Diagnostic-shape FP filter applies consistently to Patterns A, F, and H. Pattern A qTox ransom note now distinguishes hostile, review, and documentation tiers.

## ioc-scan v2.7.5 — 2026-05-03

### Fixed
- Pattern C false positive on responder-inspected hosts: bash_history lines are classified before emitting; read-only inspection commands no longer flip COMPROMISED.

## ioc-scan v2.7.4 — 2026-05-03

### Added
- Pattern J ExecStart allowlist extended to cover `/usr/local/lp/` (operator-deployed exporters).

### Fixed
- Bash 4.1 floor regression: substring and empty-array handling corrected.

## ioc-scan v2.7.3 — 2026-05-03

### Fixed
- Bash 4.1 floor regression in Pattern J persistence checker corrected.

## ioc-scan v2.7.2 — 2026-05-03

### Added
- Bundle retention: keeps the three newest bundles; older bundles and sidecars are pruned. Retention count is configurable.

## ioc-scan v2.7.1 — 2026-05-03

### Added
- Pattern J: init-facility persistence detection (udev rules and systemd unit shape probes; RPM-ownership gated).
- Mitigate-quarantine secondary read: emits a warning signal per quarantined session (cap 200), with mtime fallback when the sidecar is absent.

## ioc-scan v2.6.1 — 2026-05-02

### Fixed
- Several host-meta and patched-build globals corrected; affected all scans producing empty fields.
- OS detection parser replaced with a shell-injection-safe implementation.
- UNPATCHABLE-tier hosts were incorrectly classified as UNPATCHED; data structure corrected.

### Removed
- Dead helpers and duplicate globals.

## ioc-scan v2.5.0 — 2026-05-02

### Added
- `--chain-on-all` / `--chain-always` runs the full forensic chain on every host regardless of `host_verdict`; does not change verdict semantics.

## ioc-scan v2.4.1 — 2026-05-02

### Added
- Kill-chain rendering for advisory entries: `ADVISORY-PRE-COMPROMISE` and `ADVISORY-ORPHAN` verdict values rendered in cyan; `advisory=N` counter separate from `iocs=N`.

### Changed
- `kill-chain.{tsv,jsonl}` may carry `ADVISORY-*` rows; fleet aggregators should bucket separately from attack-chain rows.

## ioc-scan v2.4.0 — 2026-05-02

### Added
- Pre-compromise temporal gate for second-order signals (websocket shell hits, 2xx-on-cpsess); both require a first-order CRLF access anchor.

## ioc-scan v2.3.0 — 2026-05-02

### Added
- `session_mtime_vs_ctime_anomaly` advisory flags timestamp backdating and restore-artifact divergence; does not escalate `host_verdict`.

## mitigate v0.5.1 — 2026-05-02

### Fixed
- Bash 4.1 floor regression: array declaration corrected.

## mitigate v0.5.0 — 2026-05-02

### Added
- Pre-mitigation snapshot captures state (users, logs, cPanel config, session directories) to a timestamped tarball before any mutating phase runs.
- Pre-mitigation snapshot covers the proxy-subdomain setting.
- Flags: `--no-snapshot`, `--max-snapshot-mb MB` (default 500).

### Changed
- Phase order now begins with `snapshot`; bare `--apply` users should add `--no-snapshot`.

## mitigate v0.4.2 — 2026-05-02

### Added
- Two session attempt-class IOCs: incomplete-auth badpass sessions and standalone 2FA verification outside known origins.

### Changed
- Dry-run output distinguishes forged sessions from attempt sessions; quarantine treatment under `--apply` is identical.
