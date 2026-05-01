# Plan — v1.6.0 ioc-scan + v0.9.0 forensic — single-source IOC, kill-chain over canonical envelope

> **Status: SHIPPED** (2026-05-01). Final versions: ioc-scan **v1.6.1**,
> forensic **v0.9.2**. Net delta: forensic 2255 → 1667 LOC (-588);
> ioc-scan +400 LOC (port + envelope plumbing). All 4 phases complete.

## Why

Today both scripts independently detect IOCs. They have diverged: on
host2 (2026-05-01), forensic v0.8.1 reported `verdict: CLEAN` while
ioc-scan v1.5.8 — same host, same window — reported COMPROMISED with 4
critical findings (Pattern A `.sorry-encrypted`, Pattern E websocket
2xx from external IPs, Pattern F harvester envelope in
`/root/.bash_history`, attacker-IP cross-ref with 8 returning 2xx).
Forensic also crashed mid-pass on a malformed offense record, losing
every finding after the first bad row (patched defensively in v0.8.2,
root cause off-host).

Two scripts emitting different verdicts on the same host is the worst
possible UX for incident response. The fix is structural: one
canonical IOC source.

## Target architecture

```
ioc-scan ────► /var/cpanel/sessionscribe-ioc/<run_id>.json   (canonical IOC envelope)
                            │
                            ▼
forensic   ◄── envelope-driven kill-chain reconstruction + bundle
                            │
                            ▼
                  intake (--upload)
```

| Layer              | Owner    | Output                                            |
|--------------------|----------|---------------------------------------------------|
| IOC detection      | ioc-scan | run JSON envelope (already exists, signals[])     |
| Defense timeline   | forensic | cpsrvd start, mitigate runs, modsec, CSF, upcp    |
| Kill-chain reconcile | forensic | per-IOC pre/post-defense bucket                |
| Bundle capture     | forensic | tgz of sessions/logs/persistence/state            |
| Intake submission  | forensic | PUT to `https://intake.rfxn.com/`                 |

## Wiring

### ioc-scan v1.6.0

1. Always write the run envelope (currently does, no change).
2. When chaining forensic, export `SESSIONSCRIBE_IOC_JSON=<envelope path>`
   alongside existing `SESSIONSCRIBE_RUN_ID`.
3. Add `--ioc-only` ⇄ `--no-forensic` clarifications in help so the
   relationship between the scripts is explicit.

### forensic v0.9.0

1. **Delete** the entire `# offense extraction` block (the awk pass +
   E_WS / E_FM / D_REC / D_UA / D_IP handling). That's the duplicate
   detector. Functionally ~250 lines.
2. New helper `read_iocs_from_envelope()`:
   - If `SESSIONSCRIBE_IOC_JSON` is set and readable: parse the
     `signals[]` array, materialize each entry whose `severity` is
     strong/warning AND `area` is logs/sessions/destruction into the
     existing `OFFENSE_EVENTS[]` array shape (`epoch|stage|key|desc|defenses`).
   - Else (standalone forensic invocation): exec ioc-scan with
     `--quiet --ioc-only --jsonl > /tmp/ssioc-$$.jsonl`, then parse
     the JSONL stream the same way. ioc-scan must be present locally
     OR fetchable — same resolution chain currently used in
     ioc-scan's `chain_forensic_dispatch`, just inverted.
3. Reconcile pass unchanged in shape — still computes `pre_defense` /
   `post_defense` buckets per IOC against the defense timeline. Only
   the *source* of IOCs changes.
4. Bundle/upload paths unchanged.
5. `verdict` derivation: today forensic computes a CLEAN/COMPROMISED
   verdict from its own offense findings. After the change, it
   inherits the verdict from the envelope (`host_verdict` field) and
   only adds the temporal qualifier (pre/post defense). Forensic
   never disagrees with ioc-scan.

## Envelope contract (frozen for v1.6/v0.9)

The envelope already has the shape we need:

```json
{
  "host": "...", "run_id": "...", "ts": "...", "tool_version": "1.6.0",
  "code_verdict": "...", "host_verdict": "...", "score": N, "exit_code": N,
  "signals": [
    { "host": "...", "run_id": "...", "area": "logs|sessions|destruction|version|...",
      "id": "...", "severity": "strong|evidence|warning|info|advisory|error",
      "key": "...", "weight": N,
      /* per-signal kv: count, hits_2xx, ip, status, log_file, line, path,
         user, src_ip, login_time, file_mtime, etc. */
    },
    ...
  ]
}
```

What forensic needs from each signal for kill-chain construction:
- `area` to filter (only logs/sessions/destruction relevant)
- `severity` to gate (strong + warning only — evidence already too noisy)
- `key` for the canonical event name
- One of: `login_time` / `file_mtime` / `ts` (parsed from `line`)
  for the kill-chain timestamp
- `note` or constructed string for the human-readable description

If any of these is missing for a stage we care about, that's a v1.6.0
ioc-scan emit that needs the field added — caught in dev, not prod.

## Phasing

**Phase 1 — DONE** (forensic v0.8.2, commit `51603c9`)
- Defensive contract enforcement in forensic's offense loop. Validate
  `cnt` is `^[0-9]+$` before `$(( ... ))`, breadcrumb emit on first
  malformed record, count summary on more. Stops the line-1107 crash
  from silently losing every IOC after the first bad row.

**Phase 2 — DONE** (ioc-scan v1.6.0, commit `48bd7ff`)
- `ts_epoch_first` on log-area parents (`ioc_scan`, `ioc_attacker_ip`,
  `ioc_pattern_e_websocket`); `mtime_epoch` on destruction-pattern
  parents (A/B/C/D/F/G).
- Ported forensic-only checks: Pattern A ransom README, Pattern A live
  C2 socket, Pattern C nuclear.x86 binary sha256 + persistence paths.
- `SESSIONSCRIBE_IOC_JSON` exported from `chain_forensic_dispatch`;
  envelope written pre-chain by `write_json` so forensic can read it.
- CDN+repo deployed.

**Phase 3 — DONE** (forensic v0.9.0/0.9.1/0.9.2, commits `b671ad9`,
`11baaab`, `6a9cb06`)
- `read_iocs_from_envelope()` added; `OFFENSE_EVENTS[]` populated from
  signals[]. Stage letters mapped (init/A/B/C/D/E/F/G/X). Timestamp
  resolution priority: `ts_epoch_first` → `mtime_epoch` → `ts_epoch` →
  `file_mtime` ISO → `login_time` ISO → `$TS_EPOCH`. Helpers:
  `json_str_field`, `json_num_field`, `ioc_key_to_stage`,
  `ioc_signal_epoch` — all bash 4.1 + grep, no `jq` required.
- Deleted ~760 LOC of duplicated detection (forged-session ladder,
  Pattern A/B/C/D/F basic checks, the access-log awk pass for E_WS /
  E_FM / D_REC / D_UA / D_IP). Kept the deep checks ioc-scan doesn't
  cover: Pattern G mtime forgery, key-comment validation, ssh-rsa
  material in non-canonical paths; suspect-IP cross-ref.
- v0.9.1 polish dropped 74 LOC of orphan constants (PATTERN_A_README,
  KNOWN_BAD_IPS, PROBE_*, etc.) whose only consumers were the deleted
  detection.
- v0.9.2 chain UX: forensic stderr flows through to operator under
  `--chain-forensic` (was being redirected to /dev/null with stdout);
  banner suppressed when chained (signaled by SESSIONSCRIBE_IOC_JSON).

**Phase 4 — pending operator verification**
- Re-run on host2 / intent-wolves / maple2 / cpanel_client lab hosts.
  Forensic must now reproduce ioc-scan's host_verdict exactly. Any
  divergence is a bug in the envelope contract, not detection drift.

## Risk register

| Risk                                              | Mitigation |
|---------------------------------------------------|------------|
| Envelope schema drift across versions             | Pin a `schema_version` field at envelope root; forensic refuses unknown majors with a clear error |
| Forensic-only IOCs that ioc-scan doesn't have     | Audit; if any are real (e.g. bash_history harvester ENV is currently in forensic only), port them to ioc-scan first |
| Standalone forensic without ioc-scan available    | Same fetch chain ioc-scan uses for forensic — no new dependency |
| Bash 4.1 jq absence (CL6)                         | Parse JSONL, not JSON object — line-delimited records with simple key extractors. Already the format |

## What this fixes

- **Verdict divergence:** structurally impossible after Phase 3 — same input → same verdict.
- **Detection drift:** any new pattern lands in ioc-scan only; forensic gets it for free on next run.
- **Forensic crash blast radius:** even with the v0.8.2 defensive guard, the offense pass has zero IOC-detection logic to crash inside after Phase 3.
- **Code shrinkage:** ~250 LOC removed from forensic, ~30 LOC added (envelope reader). Net negative.
