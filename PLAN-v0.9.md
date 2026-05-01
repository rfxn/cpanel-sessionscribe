# Plan — v1.6.0 ioc-scan + v0.9.0 forensic — single-source IOC, kill-chain over canonical envelope

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

**Phase 1 — already shipped (v0.8.2)**
- Defensive contract enforcement in forensic's offense loop. Prevents
  the line-1107 crash from losing IOCs silently. Still the duplicated
  detector; just no longer crashes. Buys time for the refactor.

**Phase 2 — v1.6.0 ioc-scan**
- Confirm every signal we want in the kill-chain has a usable
  timestamp in its kv pairs. Where missing, add (e.g. parse the
  `[MM/DD/YYYY:HH:MM:SS ±ZZZZ]` bracket from `line` into a `ts_epoch`
  kv on every log-area signal).
- Export `SESSIONSCRIBE_IOC_JSON` from `chain_forensic_dispatch`.
- Bump tool_version. CDN+repo deploy.

**Phase 3 — v0.9.0 forensic**
- Add `read_iocs_from_envelope()`.
- Delete the offense-extraction block.
- Wire `OFFENSE_EVENTS[]` from the envelope reader.
- Verdict inheritance from `host_verdict`.
- Test matrix: (a) chained from ioc-scan (env present),
  (b) standalone (forensic forks ioc-scan), (c) standalone with
  ioc-scan absent + remote-fetch fallback.
- CDN+repo deploy.

**Phase 4 — verification**
- Re-run on host2 (and the cpanel_client lab hosts). Forensic must
  now reproduce ioc-scan's verdict exactly. Any divergence is a bug
  in the envelope contract, not an IOC-detection difference.

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
