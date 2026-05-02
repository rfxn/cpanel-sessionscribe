# State — 2026-05-02

## Shipped versions

| Script | Version | Notes |
|---|---|---|
| sessionscribe-ioc-scan.sh | **1.8.2** | gawk-3.x compat fixes for the v1.8.0 awk additions: 2-arg `match()` + substr/split (3-arg form is gawk 4.0+) at 5 sites in v1.8.1; explicit char-class repetition replacing `{n}` interval expressions (gawk 3.x default mode disables them) at 6 sites in v1.8.2. Verified end-to-end on host2 (lab host A) — Pattern X `ioc_cve_2026_41940_crlf_access_chain` now emits 15 chains, lands in PRE-DEFENSE under the actual exploit time. Earlier v1.8.0 (uncommitted shape): Pattern A anti-forensic detection, Pattern D `.sorry` fallback + `/var/cpanel/users/$reseller` second-source, Pattern E per-dimension breakout + 15-min handoff-burst signal, deterministic CRLF auth-bypass primitive in access_log, Pattern F embedded `#<epoch>` parsing, ATTACKER_IPS rev4. Prior shipped: v1.7.0 (Pattern H + Pattern I), v1.6.8, v1.6.7. |
| sessionscribe-forensic.sh | **0.11.0** | `IOC_ANNOTATIONS[]` parallel array; renderer appends `(dim: …)` to Pattern E websocket-shell rows from envelope dimensions field; index alignment maintained at all IOC_PRIMITIVES append sites. Prior shipped: v0.10.1 (Pattern H/I bundle capture), v0.10.0 (stage→pattern vocab refactor + JSONL schema_version=2) |
| sessionscribe-mitigate.sh | **0.4.0** | anti-forensic awareness in `phase_preflight`: detects `accounting.log.sorry` and warns operator that Pattern D detection is lossy; suggests `/var/cpanel/users/$reseller` direct verification |

CDN sha256 / LOC columns will be re-stamped on next CDN sync. Repo:
`https://github.com/rfxn/cpanel-sessionscribe`. CDN:
`https://sh.rfxn.com/<script>.sh` (currently lags HEAD until republish).

## Architecture

Single-source IOC + envelope-driven kill-chain:

```
sessionscribe-ioc-scan.sh ──► /var/cpanel/sessionscribe-ioc/<run_id>.json
                                            │
                                            ▼  SESSIONSCRIBE_IOC_JSON env
sessionscribe-forensic.sh  ──► defense timeline + reconcile + bundle + intake
```

ioc-scan is the canonical IOC detector. forensic consumes the envelope
to construct the kill-chain — it does not re-detect IOCs. Verdict
divergence between the two is structurally impossible.

## Operator-facing usage

```bash
# triage only (fast, fleet sweep)
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash

# triage + kill-chain reconstruction
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash /dev/stdin --chain-forensic

# triage + kill-chain + intake submission
curl -fsSL https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash /dev/stdin --chain-upload
```

When `--chain-forensic` is set, forensic's defense / offense / reconcile
output now flows inline to the operator (suppressed in v0.8.x and earlier).

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

- **Phase 4 verification:** re-run on lab hosts (see INTERNAL-NOTES.md
  for the active roster). Forensic should reproduce ioc-scan's
  host_verdict exactly. Any divergence is an envelope-contract bug.
- **schema_version field at envelope root:** future-proofing per the
  v0.9 risk register. Not yet pinned. forensic v0.10.x+ reads any v1.6.x or v1.7.x or v1.8.x
  envelope.

## Bash floor

CL6 / bash 4.1.2. Verified: no `declare -g`, `mapfile`, `readarray`,
`printf -v` array indexing, `${var^^}`/`${var,,}`, `coproc`, or
`${var: -1}` negative substring. Case-in-cmdsubst uses leading-paren
patterns. `$({ … })` always has newline after `$(` for the bash <4.4
parser quirk.
