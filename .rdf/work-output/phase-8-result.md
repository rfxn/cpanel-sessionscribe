# Phase 8 Result: Docs (STATE.md, CLAUDE.md, README.md) + CDN deploy

## STATUS: DONE

## Summary

Phase 8 docs and CDN deploy complete. All accept criteria pass.

## Changes Made

### STATE.md

- Shipped-versions table: ioc-scan updated to **2.0.0** (architectural break
  description per PLAN.md template), forensic updated to **0.99.0 (deprecation
  shim)**, mitigate remains at **0.4.0 (unchanged)**.
- Architecture section: replaced two-script diagram with single-script
  --triage/--full/--replay diagram and envelope read-after-write invariant
  description.
- Operator-facing usage: replaced --chain-forensic/--chain-upload examples with
  --full/--upload and --replay examples.
- Pending: removed resolved "Phase 4 verification" item; added shim removal note.

### CLAUDE.md

- Appended new `## Merged-script architecture (v2.0.0+)` section at end of file.
- Includes: mode comparison table (triage/full/replay), envelope read-after-write
  contract, back-compat alias mapping, forensic-area signal severity map,
  deprecation shim description.

### README.md

- ioc-scan common patterns: added --full, --replay (envelope/dir/tgz), --no-bundle
  examples; retained --jsonl, --csv, --ioc-only, offline forensics examples.
- ioc-scan --help block: replaced forensic chaining section (--chain-forensic) with
  full --full/--replay/--chain-* back-compat aliases documentation.
- sessionscribe-forensic.sh section: replaced full v0.7.0 reference with
  deprecation shim notice (WARNING callout), migration table, and
  `### Deprecation: sessionscribe-forensic.sh` subsection.
- Fleet usage: updated kill-chain reconciliation examples from
  `sessionscribe-forensic.sh --jsonl --no-bundle` to
  `sessionscribe-ioc-scan.sh --full --no-bundle --jsonl`.

## Accept Criteria Verification

| Criterion | Command | Result |
|---|---|---|
| STATE.md ioc-scan v2.0.0 | `grep -c 'sessionscribe-ioc-scan.sh.*\*\*2\.0\.0\*\*' STATE.md` | 1 |
| STATE.md forensic 0.99.0 shim | `grep -c 'sessionscribe-forensic.sh.*\*\*0\.99\.0.*shim' STATE.md` | 1 |
| CLAUDE.md merged-script section | `grep -c '## Merged-script architecture' CLAUDE.md` | 1 |
| README.md --full count | `grep -c -- '--full' README.md` | 24 (>=3) |
| README.md --replay count | `grep -c -- '--replay' README.md` | 17 (>=2) |
| sha256 parity ioc-scan | sha256sum CDN vs local | MATCH: 3cc0a60ee0d548f4c718a019955884955d0f7ef730077ace1b72901c894459d9 |
| sha256 parity forensic | sha256sum CDN vs local | MATCH: d237288d4a4be71677d651364480e5e8f8d44f161ae2b8267d5c48d192fe7d5d |
| CDN smoke test | curl sh.rfxn.com/ioc-scan | "sessionscribe-ioc-scan v2.0.0", Pattern X PRE-DEFENSE |

## CDN Deploy

- Copied ioc-scan + forensic to /root/admin/work/downloads/
- /root/bin/sync_local-remote: exit 0 (rsync to rfxncom@209.126.24.12)
- CDN verified: HTTP=200, bytes=275173 (ioc-scan), bytes=3484 (forensic)
- sha256 parity: exact match on both scripts

## Git State

- Commit: a754579 docs: v2.0.0 merged-script architecture (STATE + CLAUDE + README)
- origin/main: 216c60d..a754579

## EVIDENCE

- STATE.md grep ioc-scan v2.0.0: grep count = 1
- STATE.md grep forensic 0.99.0 shim: grep count = 1
- CLAUDE.md grep merged-script: grep count = 1
- README.md grep --full: 24; grep --replay: 17
- sha256 ioc-scan: 3cc0a60ee0d548f4c718a019955884955d0f7ef730077ace1b72901c894459d9 (local == CDN)
- sha256 forensic: d237288d4a4be71677d651364480e5e8f8d44f161ae2b8267d5c48d192fe7d5d (local == CDN)
- CDN smoke test: tmux cpanel_client → "sessionscribe-ioc-scan v2.0.0", "[PRE-DEFENSE] pattern=X key=ioc_cve_2026_41940_crlf_access_chain"
- git push: 216c60d..a754579 main -> main
