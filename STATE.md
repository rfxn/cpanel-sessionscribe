# State — 2026-05-02

## Shipped versions

| Script | Version | Notes |
|---|---|---|
| sessionscribe-ioc-scan.sh | **2.0.0** | (architectural break) Merged sessionscribe-forensic.sh inline. Detection runs in default --triage mode (envelope-only); --full adds forensic phases (defense / offense / reconcile / kill-chain / bundle); --replay PATH replays forensic phases against a saved envelope (.json), bundle directory, or tarball (.tgz). Removed: chain_forensic_dispatch, fetch_forensic_remote (no remote fetch needed). --chain-forensic, --chain-upload, --chain-on-critical preserved as back-compat aliases. Envelope written-then-read on every --full run (same code path as --replay) — envelope contract is now a same-script invariant rather than cross-script handshake. Prior shipped: v1.8.2 (gawk-3.x compat at 6 sites + 5 sites), v1.8.0 (CRLF entry primitive + Pattern A anti-forensic), v1.7.0 (Pattern H + Pattern I). |
| sessionscribe-forensic.sh | **0.99.0 (deprecation shim)** | ~50-line shim that prints a one-line deprecation notice and execs `sessionscribe-ioc-scan.sh --replay <path>`. Preserves the CDN URL for grace-period clients on the v1.x curl one-liner. --quiet and --jsonl suppress the banner. Will be removed in a future release. |
| sessionscribe-mitigate.sh | **0.4.0** | (unchanged) anti-forensic awareness in `phase_preflight`. |

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

sessionscribe-forensic.sh is a v0.99.0 deprecation shim that delegates to
--replay; it preserves the v1.x curl one-liner URL during the grace period.

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
- **sessionscribe-forensic.sh removal:** the v0.99.0 deprecation shim will be
  removed in a future release once grace-period operators have migrated to
  `ioc-scan --replay`.

## Bash floor

CL6 / bash 4.1.2. Verified: no `declare -g`, `mapfile`, `readarray`,
`printf -v` array indexing, `${var^^}`/`${var,,}`, `coproc`, or
`${var: -1}` negative substring. Case-in-cmdsubst uses leading-paren
patterns. `$({ … })` always has newline after `$(` for the bash <4.4
parser quirk.
