# State — 2026-05-02

## Shipped versions

| Script | Version | Notes |
|---|---|---|
| sessionscribe-ioc-scan.sh | **2.4.1** | (kill-chain visibility for v2.4.0 advisory entries) Adds dedicated `ADVISORY-PRE-COMPROMISE` + `ADVISORY-ORPHAN` verdicts in `phase_reconcile` and matching `adv_pre` / `adv_orphan` zones in `render_kill_chain`. Pre-compromise gate keys (`*_pre_compromise`, `*_orphan`) now flow through `read_iocs_from_envelope` via narrow allow-list (specific keys only, not blanket advisory pass) so they appear in the visual kill-chain timeline as cyan-styled bands labeled "ADVISORY (PRE-COMPROMISE CONTEXT)" / "ADVISORY (EXPLOITATION-DETACHED)" — clearly distinct from the red/green/yellow attack-chain palette but visible to operators rather than dropped silently. New `counters` breakout: `advisory=N` row count; existing `iocs=N` now shows attack-chain events only (excludes advisory). Advisory rows do NOT increment `N_PRE` / `N_POST` and do NOT change `host_verdict` / `exit_code` / `score`. kill-chain.tsv/jsonl carry the new verdict values for downstream aggregators (ss-aggregate.py should pattern-match `ADVISORY-*` for separate bucketing). v2.4.0 (pre-compromise temporal gate) Demotes second-order signals (`ioc_pattern_e_websocket_shell_hits`, `ioc_attacker_ip_2xx_on_cpsess`) to advisory when they fire WITHOUT a first-order CVE-2026-41940 anchor (`ioc_cve_2026_41940_crlf_access_chain`) preceding them in time. New advisory keys (weight=0; do NOT escalate `host_verdict`): `ioc_attacker_ip_2xx_on_cpsess_pre_compromise` (no CRLF or ts_first &lt; CRLF first), `ioc_pattern_e_websocket_shell_hits_pre_compromise` (same gate), `ioc_pattern_e_websocket_shell_hits_orphan` (post-CRLF but &gt; `PATTERN_E_2XX_PROXIMITY_SEC` (default 7d) from nearest 2xx_on_cpsess event — exploitation-detached). Resolves the testdev.halcyonplatinum.com timeline-pollution case where Pattern E (2025-11-24) and 2xx_on_cpsess (2026-03-26) both predated the actual CRLF chain (2026-04-30) by months and were polluting cluster-onset analysis. `check_logs` reorder: `check_crlf_access_primitive` runs BEFORE `check_attacker_ips` so the CRLF first epoch is available as the gate anchor at 2xx_on_cpsess emit time. New globals `LOGS_CRLF_CHAIN_FIRST_EPOCH`/`LOGS_2XX_CPSESS_FIRST_EPOCH` (init to 0 for `set -u` safety in --replay mode). Each emit now carries `crlf_first_epoch` + (Pattern E only) `twoxx_first_epoch` + `proximity_sec` for downstream provenance. `ioc_key_to_pattern()` routes new keys to `init` (not part of kill-chain alphabet); kill-chain.jsonl filters advisory severity so pre-compromise events are correctly excluded from post-hoc attack timeline. Aggregator-side follow-up: ss-aggregate.py should treat new keys as separate buckets so cluster-onset / first-X / threat-actor-bucketing see clean post-compromise data. Prior shipped: v2.3.0 (Gap 10 — `session_mtime_vs_ctime_anomaly` IOC), v2.2.0 (verdict-precision refactor — cpsess-token-keyed gating, exit code 3 = SUSPICIOUS, Pattern X TS_EPOCH guard, kill-chain.tsv schema v3). |
| sessionscribe-mitigate.sh | **0.5.1** | EL6 floor fix — line 470 was `declare -ga SIGNALS_JSON=()` which requires bash 4.2+ (the `-g` flag does not exist in bash 4.1.2 / CL6). `SIGNALS_JSON` is at top-level scope alongside `P_VERDICT` / `P_DETAIL` / `P_NOTES` / `PHASE_ORDER_RUN` (all `declare -A` / `declare -a` without `-g`), so `-g` was redundant. Replaced with `declare -a` to restore CloudLinux 6 compatibility. Verified via `bash -n` + `shellcheck -S error` + `--help`. Prior shipped: v0.5.0 (`phase_snapshot` pre-mitigation evidence capture; tarballs `/var/cpanel/users/`, `accounting.log`, `audit.log`, `cpanel.config`, `sessions/{raw,preauth,cache}/` BEFORE any mutating phase, plus `whmapi1 get_tweaksetting` for proxysub keys; closes Gap 8). v0.4.2 (IOC-D2 + standalone IOC-2 in `phase_sessions`). |

CDN sha256 / LOC columns will be re-stamped on next CDN sync. Repo:
`https://github.com/rfxn/cpanel-sessionscribe`. CDN:
`https://sh.rfxn.com/<script>.sh` (currently lags HEAD until republish).

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

The standalone `sessionscribe-forensic.sh` is gone — operators on the
v1.x curl one-liner now get a 404 and should switch to
`sessionscribe-ioc-scan.sh --full` (live capture) or `--replay PATH`
(re-render against a saved envelope/bundle).

## v2.2.0 — verdict-precision refactor (2026-05-02)

### New IOC keys

| Key | Severity | Weight | Pattern | Semantics |
|---|---|---|---|---|
| `ioc_attacker_ip_2xx_on_cpsess` | strong | 8 | X | T1-IP traffic returned 2xx on `/cpsess<10digits>/` path — real exploitation evidence (token-bearing request handled successfully) |
| `ioc_attacker_ip_recon_only` | info | 0 | init | T1-IP traffic returned 2xx on non-cpsess paths only (login enumeration, generic recon) — does not escalate verdict |
| `ioc_failed_exploit_attempt` | warning | 3 | X | cPanel reference IOC 5 analog: session has badpass + token_denied + non-empty `pass=` line + no auth markers + no `cp_security_token` (mutually exclusive with IOC-E `ioc_token_attempt_*` evidence-tier) |

### Severity emit-policy change (Phase 2)

The legacy `ioc_attacker_ip_in_access_log` strong-on-any-2xx emit is REPLACED by a three-way cpsess-keyed split inside `check_attacker_ips()`:

- `h2xx_cpsess > 0` → `ioc_attacker_ip_2xx_on_cpsess` strong (exploitation)
- `h2xx_recon  > 0` → `ioc_attacker_ip_recon_only` info (reconnaissance only)
- 4xx-only         → `ioc_attacker_ip_in_access_log_probes_only` warning (probing rejected)

T1-IP traffic to non-cpsess paths (login enum, `GET /`, scanner pings) demotes to recon-only/info. Only cpsess-bearing 2xx counts as exploitation evidence — matches cPanel's reference IOC checker primitive (token+200 pair).

### Exit code 3 = SUSPICIOUS (Phase 6)

Host-state SUSPICIOUS is disambiguated from code-state INCONCLUSIVE:

| Code | Code-state    | Host-state   | Triage action |
|---|---|---|---|
| 0 | CLEAN/PATCHED | CLEAN | none |
| 1 | VULNERABLE | (any) | patch cpsrvd |
| 2 | INCONCLUSIVE | (any) | manual code-state review (also: tool error - bad args, missing deps) |
| 3 | (any) | SUSPICIOUS | review session/access logs |
| 4 | (any) | COMPROMISED | full IR; bundle + upload |

Tool errors (bad args, missing deps, unreadable replay path) stay at exit 2 (per pre7 fix — 16 sites moved from exit 3 to exit 2). The sole user of exit 3 is now the SUSPICIOUS host-state assignment in `aggregate_verdict()`.

### Phase 4 timestamp guard

Pattern X events refuse to emit when `ts_epoch_first` is unresolvable (the prior fallback to `$TS_EPOCH` scan-time anchor was producing synthetic 2025-11-25 anchors in cluster-onset analysis). Replaced with `ts_unresolvable_pattern_x` warning when no real timestamp is available.

### Phase 5 structured kill-chain fields

Pattern E (`ioc_pattern_e_websocket_shell_hits`) and the new Pattern X (`ioc_attacker_ip_2xx_on_cpsess`) now populate `ip` / `path` / `status` / `cpsess_token` at emit-time — hand-investigation no longer requires re-grepping `access-logs.tgz`. JSONL `schema_version` bumped 2 → 3 with `_schema_changes` entry; kill-chain.tsv now 18 columns with `cpsess_token` at column 18 (column-index stability preserved for external `awk -F'\t'` parsers).

### Fleet validation (Phase 7)

Re-run of `ss-aggregate.py` against the 9659-bundle 2026-05-02 dataset:

- `verdicts.COMPROMISED`: 9659 → **1570** (84% reduction)
- `q1_confirmed_compromised`: **203 / 203 retained** (hard floor — all destruction-pattern, F-harvester, token-used-2xx, D recon-persistence cases preserved)
- `q1_weak_noise: 7611` hosts demoted to SUSPICIOUS (exit 3) or CLEAN (exit 0)

The 1570 figure is above the originally-modeled 250–350 target band because the model under-counted operationally-correct exploitation primitives (CRLF chain, narrow Pattern E websocket-shell hits) which legitimately retain COMPROMISED. The IP-keyed FP class targeted by Phase 2 was eliminated cleanly. Full evidence: `.rdf/work-output/phase-7-result-v2.2.0.md`. A future Gate 1.2 (stricter "post-exploit-activity-required" tier) is reserved for v2.3.x.

## Operator-facing usage

```bash
# triage only (fast, fleet sweep)
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash

# triage + full kill-chain reconstruction
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash /dev/stdin --full

# triage + kill-chain + intake submission
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash /dev/stdin --full --upload

# replay forensic phases against a saved envelope (re-render kill-chain without re-scanning)
bash sessionscribe-ioc-scan.sh --replay /var/cpanel/sessionscribe-ioc/<run_id>.json
bash sessionscribe-ioc-scan.sh --replay /root/.ic5790-forensic/<bundle-dir>
bash sessionscribe-ioc-scan.sh --replay /root/.ic5790-forensic/<bundle>.tgz
```

In `--full` mode, detection and forensic phases run in a single process.
The envelope is written before forensic phases run so `--replay` and `--full`
use the same read path — envelope contract is a same-script invariant.

## Envelope contract

```json
{
  "tool": "sessionscribe-ioc-scan",
  "tool_version": "1.6.x",
  "run_id": "<epoch>-<pid>",
  "host": "...", "ts": "...",
  "code_verdict": "PATCHED|VULNERABLE|INCONCLUSIVE|SKIPPED",
  "host_verdict": "CLEAN|SUSPICIOUS|COMPROMISED",
  "score": N, "exit_code": N,
  "signals": [
    {"host":"...","area":"logs|sessions|destruction|version|...",
     "id":"...","severity":"strong|warning|evidence|info|advisory|error",
     "key":"...","weight":N,
     /* per-signal kv: ts_epoch_first, mtime_epoch, ts_epoch,
        file_mtime, login_time, ip, status, log_file, line, path,
        count, hits_2xx, hits_3xx, hits_4xx, ... */}
  ]
}
```

Forensic's `read_iocs_from_envelope()` filters to `area ∈ {logs,
sessions, destruction}` with `severity ∈ {strong, warning}`. Stage
letter mapped via `ioc_key_to_stage()`. Timestamp resolved via
priority chain: `ts_epoch_first` → `mtime_epoch` → `ts_epoch` →
`file_mtime` ISO → `login_time` ISO → `$TS_EPOCH`.

## Pending

- **schema_version field at envelope root:** future-proofing per the
  v0.9 risk register. Not yet pinned. ioc-scan v2.0.0 reads any v1.6.x, v1.7.x, or v1.8.x
  envelope in --replay mode.
(none open at this revision; sessionscribe-forensic.sh shim has been removed.)

## Bash floor

CL6 / bash 4.1.2. Verified: no `declare -g`, `mapfile`, `readarray`,
`printf -v` array indexing, `${var^^}`/`${var,,}`, `coproc`, or
`${var: -1}` negative substring. Case-in-cmdsubst uses leading-paren
patterns. `$({ … })` always has newline after `$(` for the bash <4.4
parser quirk.
