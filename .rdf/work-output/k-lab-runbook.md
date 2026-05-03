# sessionscribe-mitigate kill-chain operator runbook

**Scope:** Operator-runnable lab E2E for `sessionscribe-mitigate.sh` phase_kill
(`--kill`, `--kill-anyway`, `--envelope`, `--ssh-prune` family). CL6/EL6 floor
target: bash 4.1.2 / gawk 3.1.7 / coreutils 8.4 / util-linux 2.17.

This runbook supersedes the v0.6.0 `k8-lab-runbook.md`. The file was renamed
from `k8-lab-runbook.md` to `k-lab-runbook.md` in v0.7.0 because it is the
kill-chain operator runbook generally, not the K8 phase landing artifact.

**Versions covered:**
- v0.6.0 — phase_kill (file/IP quarantine + CSF blocklists). Scenarios S1-S7.
- v0.7.0 — `--ssh-prune` family (surgical authorized_keys sweep). Scenarios
  S8-S15.

**Verdict gate:** `host_verdict==COMPROMISED` is required for phase_kill to
mutate state. `--kill-anyway` is the operator escape hatch for fleet hygiene
runs against not-yet-COMPROMISED hosts.

---

## Lab access

Lab tmux sessions per memory: `cpanel_client` / `cpanel_client2`. Both are
CL6/EL6 cPanel hosts wired into the live fleet but designated as scratch.

```bash
# attach
tmux attach -t cpanel_client

# panes used in scenarios
tmux split-window -h -t cpanel_client    # right pane = "pane 2" in S15
```

The script under test is staged at `/root/sessionscribe-mitigate.sh` (or wherever
the operator has placed it). Invocations below assume the working directory
contains the script and `sessionscribe-ioc-scan.sh` side-by-side — `phase_kill`
reads the trust regex from the ioc-scan literal at startup (drift gate).

---

## Pre-flight — verify the build under test

```bash
bash -n sessionscribe-mitigate.sh && echo "syntax OK"
bash sessionscribe-mitigate.sh --help | head -3
# expect: "sessionscribe-mitigate.sh v0.7.0" (or current VERSION)
```

Confirm the trust regexes are byte-equal between mitigate and ioc-scan
(otherwise `--ssh-prune` will refuse to run unless `--ssh-allow-drift`):

```bash
trust_re_rhs() {
    grep -oE "^$1=.*" "$2" | head -1 \
        | sed -E "s/^[^=]+=//; s/^['\"]//; s/['\"][[:space:]]*\$//"
}
diff <(trust_re_rhs SSH_KNOWN_GOOD_RE sessionscribe-ioc-scan.sh) \
     <(trust_re_rhs KILL_SSH_TRUST_RE  sessionscribe-mitigate.sh)
# expect: empty diff (zero output)
```

---

## v0.6.0 — phase_kill kill-chain general scenarios (S1-S7)

These rehearse the K1-K7 kill-chain landing (file quarantine + per-incident
csf -d + RFXN blocklist registration + manifest finalization). Target host
must have a recent `sessionscribe-ioc-scan.sh --full` run with a COMPROMISED
verdict so an envelope is on disk at `/var/cpanel/sessionscribe-ioc/*.json`.

### S1 — Opt-in confirmation (gate disabled by default)

```bash
bash sessionscribe-mitigate.sh --check
# expect: phase_kill is SKIPPED (gate not opted in)
# expect: no envelope read, no manifest built
```

`--kill` is opt-in. A bare `--check` run never touches the kill chain.

### S2 — Verdict gate fires (COMPROMISED required)

On a host whose latest envelope is `host_verdict:CLEAN`:

```bash
bash sessionscribe-mitigate.sh --check --kill
# expect: phase_kill SKIPPED with detail
#   "host_verdict=CLEAN; pass --kill-anyway to override"
# expect: no manifest written
```

Re-run with the override:

```bash
bash sessionscribe-mitigate.sh --check --kill-anyway
# expect: phase_kill runs; manifest is built in --check (planned_* results)
```

### S3 — Dry-run (--check) on a COMPROMISED host

Synthesize or use a real COMPROMISED envelope. Verify:

```bash
bash sessionscribe-mitigate.sh --check --kill
# expect:
#   - kill-manifest.json under $BACKUP_DIR/
#   - kind:file items with action=quarantine, result=planned_quarantine_ok
#   - kind:ip items with action=csf_deny, result=planned_block_ok
#   - kind:csf items with action=blocklist_register, result=planned_register_ok
#   - no actual file moves, no csf -d invocations
```

Cross-check the manifest's verdict computation:

```bash
jq -r '.verdict, .summary' "$BACKUP_DIR"/kill-manifest.json
```

### S4 — Full apply on a COMPROMISED host

```bash
bash sessionscribe-mitigate.sh --apply --kill
# expect:
#   - file quarantines moved into $BACKUP_DIR/quarantine/<path-mirror>
#   - csf -d invoked once per attacker IP (skipped for private ranges)
#   - csf.blocklists has the rfxn entry registered (NAME|INTERVAL|MAX|URL)
#   - manifest results promoted from planned_* to bare primary
#     (quarantine_ok, block_ok, register_ok)
```

Spot-check chain-of-custody:

```bash
ls -la "$BACKUP_DIR"/quarantine/
# expect: original paths mirrored under quarantine/, ownership preserved
sha256sum "$BACKUP_DIR"/quarantine/<path>/<file>
# expect: matches the manifest's pre-quarantine sha256 for that item
```

### S5 — Idempotent re-apply

Re-run S4 on the same host without first un-quarantining:

```bash
bash sessionscribe-mitigate.sh --apply --kill
# expect:
#   - quarantine items: result=gone (already moved)
#   - csf items: result=already_registered (rfxn entry present)
#   - ip items: result=already_blocked (csf -d returns "duplicate")
#   - phase_set kill OK with a no-op verdict; no errors
```

### S6 — Allowlist refusal

Manifest builder honors path allowlists (the K2 envelope-injection guard).
A signal whose path resolves outside the canonical allowlisted roots
(`/var/cpanel/`, `/usr/local/cpanel/`, `/etc/`, `/home/*/`, `/root/`,
`/tmp/`, `/var/tmp/`, `/dev/shm/`) is refused at manifest-build time, not
at apply-time. To rehearse:

```bash
# Plant a synthetic envelope with a path outside the allowlist.
# (e.g., signal.path="/proc/self/fd/0" or "/nonexistent-root/foo")
bash sessionscribe-mitigate.sh --check --kill --envelope /tmp/synthetic.json
# expect:
#   - manifest item with action=skipped, result=path_refused_allowlist
#   - phase_set kill WARN (refused signals don't fail the phase)
```

### S7 — Failure-mode rehearsal

Cover the four documented failure modes:

1. **Cross-fs `mv` failure** — quarantine target on a different filesystem
   from the source. The K3 helper falls back to `cp -a + rm`. Plant a file
   on a tmpfs and route `BACKUP_DIR` to a separate mount; verify the
   manifest item lands `quarantine_ok` with `selinux_relabel_warning` if
   SELinux relabel-warning was emitted.
2. **CDN unreachable** — RFXN blocklist URL DNS-fails. The K5 helper
   should record `register_failed` with `detail:"CDN unreachable"` and
   leave csf.blocklists untouched. Verify by blackholing
   `sh.rfxn.com` in `/etc/hosts` to `127.0.0.1` for the run.
3. **Malformed attacker IP** — envelope contains `1.2.3` (no fourth
   octet). K4 should refuse with `result:refused_malformed_ip`; csf
   never invoked. Synthesize via a hand-edited envelope.
4. **Path traversal** — envelope signal path contains `../` or
   non-canonical components. K2 normalizer rejects with
   `result:path_refused_traversal`. Cross-check against
   `path_normalize_safe` in mitigate.

For each: confirm the manifest records the failure, the verdict ladder
honors it (FAIL > ACTION > WARN > OK), and `phase_set kill` reports the
appropriate level.

---

## v0.7.0 — `--ssh-prune` ssh-key scenarios (S8-S15)

These rehearse the new `kind:sshkey` item class. Each scenario plants an
authorized_keys fixture, runs the prune, and verifies the result + chain
of custody.

**Test seam:** the kill-chain phase_kill normally requires a COMPROMISED
envelope. For lab fixtures pass `--kill-anyway` (the gate is bypassed but
the actual prune logic is exercised) or supply a synthetic envelope via
`--envelope` whose `host_verdict` is `COMPROMISED`. Below uses
`--kill-anyway` for brevity.

**Conventions:**
- `BACKUP_DIR=$(ls -1dt /var/lib/sessionscribe-mitigation/*/ | head -1)`
  after each run to grab the freshest run dir.
- `MANIFEST="$BACKUP_DIR"/kill-manifest.json`
- `SIDECAR="$BACKUP_DIR"/kill-actions.jsonl` (apply mode only)

### S8 — Clean fleet host (only Parent Child keys present)

Plant a clean fixture:

```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsynthetickeydataforlabuse Parent Child key for AB12CD
EOF
chmod 600 /root/.ssh/authorized_keys
```

Run:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
jq -r '.items[] | select(.kind=="sshkey") | "\(.path)\t\(.result)"' "$MANIFEST"
# expect: every kind:sshkey item has result=nothing_to_prune
grep -c "nothing_to_prune" "$SIDECAR"
# expect: count matches the number of canonical authorized_keys paths swept
md5sum /root/.ssh/authorized_keys
# expect: unchanged from pre-run md5
```

### S9 — Mixed file (Parent Child + attacker `evil@1.2.3.4`)

Plant:

```bash
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsynthetickeydataforlabuse Parent Child key for AB12CD
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDdifferentsynthetickeydata evil@1.2.3.4
EOF
PRE_SHA=$(sha256sum /root/.ssh/authorized_keys | awk '{print $1}')
```

Run:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
# attacker line removed
grep -c "evil@1.2.3.4" /root/.ssh/authorized_keys
# expect: 0
# Parent Child kept
grep -c "Parent Child key for AB12CD" /root/.ssh/authorized_keys
# expect: 1

# manifest item
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys")' "$MANIFEST"
# expect: result=pruned_ok (or planned_pruned_ok in --check), pruned_keys[]
#         contains one entry with comment="evil@1.2.3.4"

# original preserved at backup
ORIG="$BACKUP_DIR"/quarantine/root/.ssh/authorized_keys.original-pre-prune
test -s "$ORIG" && echo "backup OK"
sha256sum "$ORIG"
# expect: matches PRE_SHA from above

# sidecar JSONL line for the apply
grep -F '/root/.ssh/authorized_keys' "$SIDECAR"
# expect: kind=sshkey, action=prune, result=pruned_ok
```

### S10 — Lockout host (only attacker keys, no Parent Child)

Plant:

```bash
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDevilkey1synthetic evil1@1.2.3.4
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDevilkey2synthetic evil2@5.6.7.8
EOF
```

Default run (no lockout override):

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify lockout-safe default:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: would_lock_out
md5sum /root/.ssh/authorized_keys
# expect: unchanged (file untouched)
```

Re-run with the override:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune --ssh-allow-lockout
```

Verify forced full prune:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: forced_full_prune
wc -l < /root/.ssh/authorized_keys
# expect: 0 (or only blank/comment lines)
jq -r '.verdict' "$MANIFEST"
# expect: WARN (forced_full_prune promotes verdict to WARN)
```

### S11 — Site-extension via `--ssh-allow`

Plant:

```bash
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticpc Parent Child key for AB12CD
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticcontractor contractor@bigco.example
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticevil evil@1.2.3.4
EOF
```

Run with the contractor extension:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune \
    --ssh-allow 'contractor@bigco\.example'
```

Verify:

```bash
grep -c "contractor@bigco.example" /root/.ssh/authorized_keys
# expect: 1
grep -c "Parent Child key for AB12CD" /root/.ssh/authorized_keys
# expect: 1
grep -c "evil@1.2.3.4" /root/.ssh/authorized_keys
# expect: 0

# effective regex recorded in manifest
jq -r '.runtime.ssh_trust_re_effective' "$MANIFEST"
# expect: includes "|contractor@bigco\.example" appended to the base regex
```

Negative case — invalid ERE rejected at parse time:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune --ssh-allow '['
# expect: exit code != 0; stderr mentions "not a valid POSIX ERE"
```

### S12 — Symlink + malformed defenses

**Symlink:**

```bash
useradd -m labtest 2>/dev/null
mkdir -p /home/labtest/.ssh && chmod 700 /home/labtest/.ssh
chown labtest:labtest /home/labtest /home/labtest/.ssh
ln -sf /etc/passwd /home/labtest/.ssh/authorized_keys

bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/home/labtest/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: refused_symlink
test -L /home/labtest/.ssh/authorized_keys && echo "symlink intact"
# expect: prints "symlink intact" (not removed, not dereferenced)
```

**Malformed:**

```bash
rm -f /home/labtest/.ssh/authorized_keys
cat > /home/labtest/.ssh/authorized_keys <<'EOF'
nokeytype garbage line that is not a valid ssh key
EOF
chown labtest:labtest /home/labtest/.ssh/authorized_keys
chmod 600 /home/labtest/.ssh/authorized_keys

bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/home/labtest/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: refused_unparseable
md5sum /home/labtest/.ssh/authorized_keys
# expect: unchanged (whole file refused, no rewrite)
```

Cleanup:

```bash
userdel -rf labtest 2>/dev/null
```

### S13 — Empty-comment defaults

Plant:

```bash
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticpc Parent Child key for AB12CD
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbarekeydatasynthetic
EOF
PRE_SHA=$(sha256sum /root/.ssh/authorized_keys | awk '{print $1}')
```

Default run (KEEP+WARN):

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: kept_unlabeled_warned
sha256sum /root/.ssh/authorized_keys | awk '{print $1}'
# expect: matches PRE_SHA (file untouched)
jq -r '.verdict' "$MANIFEST"
# expect: WARN (kept_unlabeled_warned promotes)
```

Re-run with `--ssh-prune-unlabeled`:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune \
    --ssh-prune-unlabeled
```

Verify:

```bash
grep -c "Parent Child key for AB12CD" /root/.ssh/authorized_keys
# expect: 1 (kept)
wc -l < /root/.ssh/authorized_keys
# expect: 1 (bare key removed)
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: pruned_ok
```

### S14 — Trust-regex drift

Synthesize a divergent ioc-scan via the env-only test seam
`KILL_SSH_TRUST_DRIFT_TEST_PATH` (does NOT require modifying the
canonical script on disk):

```bash
sed -E "s/^SSH_KNOWN_GOOD_RE=.*/SSH_KNOWN_GOOD_RE='(bogus_prefix|lwadmin)'/" \
    sessionscribe-ioc-scan.sh > /tmp/ioc-scan-divergent.sh

KILL_SSH_TRUST_DRIFT_TEST_PATH=/tmp/ioc-scan-divergent.sh \
    bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify the gate fires:

```bash
echo "exit=$?"
# expect: exit != 0; stderr/log shows "trust-regex drift; --ssh-allow-drift to override"
# expect: no manifest written under $BACKUP_DIR (phase_set kill FAIL skips
#         manifest finalization at --check; --apply behavior matches)
```

Re-run with the bypass:

```bash
KILL_SSH_TRUST_DRIFT_TEST_PATH=/tmp/ioc-scan-divergent.sh \
    bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune \
    --ssh-allow-drift
```

Verify:

```bash
echo "exit=$?"
# expect: exit 0 with WARN
jq -r '.runtime.ssh_trust_drift_bypass' "$MANIFEST"
# expect: true (or matching field name in manifest schema)
jq -r '.verdict' "$MANIFEST"
# expect: WARN
```

Cleanup:

```bash
rm -f /tmp/ioc-scan-divergent.sh
```

**Alternative** (no test seam): copy `sessionscribe-ioc-scan.sh` to a
separate directory, edit the `SSH_KNOWN_GOOD_RE` literal, and run mitigate
from that directory. The mitigate side-by-side discovery picks up the
edited copy.

### S15 — Concurrent modification + lock contention

Two-pane test using tmux. Plant a target:

```bash
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticpc Parent Child key for AB12CD
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsyntheticevil evil@1.2.3.4
EOF
```

**Pane 1** — hold an exclusive flock on the target file for 30 seconds:

```bash
flock -x /root/.ssh/authorized_keys sleep 30
```

**Pane 2** — within those 30 seconds, run mitigate:

```bash
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Verify:

```bash
jq -r '.items[] | select(.kind=="sshkey" and .path=="/root/.ssh/authorized_keys") | .result' "$MANIFEST"
# expect: lock_contended
md5sum /root/.ssh/authorized_keys
# expect: unchanged (no rewrite under contention)
jq -r '.verdict' "$MANIFEST"
# expect: WARN (lock_contended promotes)
```

The retry loop is 10 attempts at 1s each (default). If pane 1's `flock`
exits before pane 2 finishes its retries, pane 2 will succeed and emit
`pruned_ok` instead — not a failure mode, just a race-window outcome.
For deterministic `lock_contended` keep pane 1's hold > 10s.

**Alternate variant — concurrent_modification (mid-flight rewrite by a
foreign writer):** harder to stage by hand. The unit-test suite covers
this via the sha256-mismatch injection (test 25 in `MITIGATE_RUN_P1_TESTS`).
For lab rehearsal use:

```bash
# Pane 1: tight loop appending to the file.
while true; do
    echo "ssh-rsa AAAAtmp$$$RANDOM tmp" >> /root/.ssh/authorized_keys
    sleep 0.05
done

# Pane 2: run mitigate. Some runs will land concurrent_modification.
bash sessionscribe-mitigate.sh --apply --kill --kill-anyway --ssh-prune
```

Stop pane 1 when done (`Ctrl-C`).

---

## CL6 floor probes (carry-forward + new for v0.7.0)

These probes belong on every host that runs mitigate, before any
`--apply` invocation against production keys.

### Trust-regex sync gate (must be byte-equal)

```bash
trust_re_rhs() {
    grep -oE "^$1=.*" "$2" | head -1 \
        | sed -E "s/^[^=]+=//; s/^['\"]//; s/['\"][[:space:]]*\$//"
}
diff <(trust_re_rhs SSH_KNOWN_GOOD_RE sessionscribe-ioc-scan.sh) \
     <(trust_re_rhs KILL_SSH_TRUST_RE  sessionscribe-mitigate.sh)
# expect: empty diff (zero output)
```

If non-empty: drift exists. Resolve in source. `--ssh-allow-drift` is the
runtime escape hatch but loud + audit-trailed; it is not a fix.

### util-linux 2.17 floor — no `flock -w`

`flock -w` is util-linux 2.21+. EL6 ships 2.17. Mitigate must use
`flock -x -n` + sleep retry loop instead.

```bash
grep -nE 'flock[[:space:]]+(-[a-zA-Z]*w|-w)' sessionscribe-mitigate.sh
# expect: zero hits
```

If any hit: regression. File a bug — mitigate will silently fail on EL6.

### Library-only unit-test runner (P1+P2+P3 — 44 cases)

```bash
MITIGATE_LIBRARY_ONLY=1 MITIGATE_RUN_P1_TESTS=1 \
    bash sessionscribe-mitigate.sh
# expect tail line:
#   P1+P2+P3 tests: 44/44 passed
```

Any FAIL line is blocking. The tests cover ssh_key parser, classifier,
prune helper, drift gate, manifest emit (--check + --apply), supersede
gate, sidecar shape, and arg-parse for the five new flags.

### v0.6.1 verification gate (carry-forward — must re-pass)

```bash
bash -n sessionscribe-mitigate.sh && echo OK
shellcheck -S error sessionscribe-mitigate.sh
shellcheck sessionscribe-mitigate.sh   # default level (F-15)
bash sessionscribe-mitigate.sh --help >/dev/null && echo OK

# gawk 3.1 floor — character-class interval probe (must say interval-OK)
awk 'BEGIN { if (match("[01/02/2026", /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]/)) print "interval-OK"; else print "interval-BROKEN" }'

# gawk 3.1 floor — no {n} interval expressions in awk regexes
grep -nE 'match.*\{[0-9]|/[^/]*\{[0-9][^/]*/' sessionscribe-mitigate.sh
# expect: zero hits

# gawk 3.1 floor — no 3-arg match()
grep -nE 'match\([^,]+,[^,]+,[^)]+\)' sessionscribe-mitigate.sh
# expect: zero hits
```

---

## Drift-gate operator note (v0.7.0 N-6)

Trust-regex drift causes `phase_set kill FAIL` and skips the manifest
build. Operators expecting a manifest at `--check` time will get nothing
on a drift host. This is by design — drift is a build-integrity bug, not
a runtime decision the operator should be papering over.

Use `--ssh-allow-drift` to test drift behavior intentionally (lab
rehearsal, urgent fleet-wide hygiene during a coordinated update). For
all other cases, resolve the drift in source: edit either
`KILL_SSH_TRUST_RE` in mitigate or `SSH_KNOWN_GOOD_RE` in ioc-scan so the
two literals are byte-equal, then re-run.

---

## `recovery_hint` brittleness note (v0.7.0 N-3)

Each `kind:sshkey` manifest item carries a `recovery_hint` field with
the exact restore command. The path embedded in the hint is baked at
manifest-build time. If you've rotated `BACKUP_DIR` (rsync to archive,
log rotation, manual `mv` of run dirs) between the prune run and the
recovery, the hint path is stale.

Discovery aid (works regardless of run-dir rotation):

```bash
find /var/lib/sessionscribe-mitigation -name '*.original-pre-prune' -ls
```

Match by mtime to pick the run you intend to recover from.

---

## Compound-flag warning (v0.7.0 N-7)

The combination `--kill-anyway --ssh-prune-unlabeled --ssh-allow-lockout`
on a clean host (where every authorized_keys file is unlabeled and has
no Parent Child key) wipes every key from every authorized_keys file
with no trusted key remaining. This is the documented semantics — every
key is unlabeled (would be pruned with `--ssh-prune-unlabeled`), no
trusted key keeps the file alive (`--ssh-allow-lockout` authorizes the
empty result), and the verdict gate is bypassed (`--kill-anyway`).

Reserve this combination for fleet hygiene runs where you have already
confirmed a quarantine target. On an unconfirmed host the result is
equivalent to a remote root lockout. The runbook author has personally
done this once. Do not be the second.

---

## Recovery procedure — undoing a mistaken prune

If `--ssh-prune --apply` removed a key you needed, the original is
preserved at:

```
<BACKUP_DIR>/quarantine/<path-mirror>.original-pre-prune
```

Each `kind:sshkey` manifest item carries a `recovery_hint` field with
the exact restore command for that path.

**Manual recovery** (substitute paths from the manifest):

```bash
BACKUP_DIR=/var/lib/sessionscribe-mitigation/<ts>-<run>
ORIG=$BACKUP_DIR/quarantine/root/.ssh/authorized_keys.original-pre-prune
test -s "$ORIG" || { echo "no backup; cannot recover"; exit 1; }
cp -a "$ORIG" /root/.ssh/authorized_keys
restorecon -F /root/.ssh/authorized_keys 2>/dev/null   # SELinux hosts only
systemctl reload sshd 2>/dev/null || /etc/init.d/sshd reload 2>/dev/null
ssh-keygen -lf /root/.ssh/authorized_keys              # sanity-check parses
```

**Locate every backup on the host** (when you don't know the run timestamp):

```bash
find /var/lib/sessionscribe-mitigation -name '*.original-pre-prune' -ls
```

**Find the manifest that matches a given run:**

```bash
find /var/lib/sessionscribe-mitigation -name kill-manifest.json
```

**Pre-baked recovery hints — grep them out of the manifest:**

```bash
jq -r '.items[] | select(.kind=="sshkey") | "\(.path)\t\(.recovery_hint)"' \
    "$BACKUP_DIR"/kill-manifest.json
```

**Sanity after recovery:**

```bash
# Confirm sshd accepts the restored file.
sshd -t && echo "sshd config OK"
# Confirm at least one expected key is present.
grep -c "Parent Child key for" /root/.ssh/authorized_keys
# Try a fresh ssh login from a known-good source before closing the
# existing console session.
```

---

## `concurrent_modification` — what to do if you see this result

Result `concurrent_modification` means another writer (most commonly
cPanel WHM key-management, less commonly a sysadmin script or a
watchdog) modified the target file between mitigate's pre-rewrite
sha256 and the flock-acquired rewrite window. Mitigate aborts cleanly:
the original file is intact, no rewrite has occurred.

The result is informational, not a failure. The phase verdict is WARN.
The chain of custody is preserved (no partial state on disk).

**Recommended response sequence:**

1. **Block the attacker source.** The IP block is already in your
   manifest from the kill-chain IP-deny step:

   ```bash
   csf -d <attacker_ip>     # belt-and-suspenders if not yet active
   csf --status | grep <attacker_ip>
   ```

   This prevents new attacker writes during recovery.

2. **Stop / suspend the cPanel WHM session if you control it.**
   The K8 manifest may already have flagged active WHM sessions; quiesce
   them before re-running:

   ```bash
   pgrep -af cpsrvd
   # Optionally: /scripts/restartsrv_cpsrvd
   ```

3. **Re-run mitigate once the writer is quiesced.**

   ```bash
   bash sessionscribe-mitigate.sh --apply --kill --ssh-prune
   ```

4. **If `concurrent_modification` recurs, identify the writer.** A
   stable writer pinning the file means a sshd / watchdog / cron job
   is intentionally rewriting it. `lsof` names the writer:

   ```bash
   lsof /root/.ssh/authorized_keys
   lsof /home/*/.ssh/authorized_keys 2>/dev/null
   ```

   Cross-check against the process tree (`ps -ef`, `systemctl list-units`)
   before forcibly killing — a Liquid Web Parent Child provisioning run
   in flight is a benign concurrent writer that should be allowed to
   finish.

---

## Appendix — manifest field reference (v0.7.0 `kind:sshkey`)

```json
{
  "kind": "sshkey",
  "path": "/root/.ssh/authorized_keys",
  "action": "prune",
  "result": "pruned_ok",
  "sha256_pre": "<hex>",
  "sha256_post": "<hex>",
  "sha256_kept_set": "<hex>",
  "pruned_keys": [
    {
      "line_no": 2,
      "keytype": "ssh-rsa",
      "comment": "evil@1.2.3.4",
      "fingerprint": "MD5:aa:bb:...",
      "base64_first_24": "AAAAB3NzaC1yc2EAAAADAQAB"
    }
  ],
  "keys_kept": 1,
  "keys_kept_unlabeled": 0,
  "selinux_relabel_warning": false,
  "recovery_hint": "cp -a /var/lib/sessionscribe-mitigation/<ts>-<run>/quarantine/root/.ssh/authorized_keys.original-pre-prune /root/.ssh/authorized_keys"
}
```

Cross-references: `pruned_keys[].base64_first_24` is the line-identifier
used when `fingerprint` is empty (EL6 OpenSSH 5.3 with ed25519 / FIDO).
Both fields are non-secret — first-24 of base64 is not a key recovery
primitive.
