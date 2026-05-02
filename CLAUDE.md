# cpanel-sessionscribe — Project Floor & Portability Pitfalls

This is a record of the recurring floor and semantic gotchas that have
broken — or silently degraded — releases of this toolkit. Read it
before editing any of the `.sh` scripts. Every item below is a fix
extracted from a real regression we shipped.

## Target floor

The fleet's lowest-common-denominator host is **CloudLinux 6 (EL6)**:
- bash **4.1.2**
- gawk **3.1.7**
- procps **3.2.x** (NOT procps-ng)
- coreutils **8.4**
- glibc **2.12**

Anything that ships under `https://sh.rfxn.com/` and the
`raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/` URLs MUST
run on this floor. `bash -n` and `shellcheck -S error` are necessary
but **not sufficient** — they catch parse errors, not runtime
extension misuse. Validate with the host's own interpreter.

---

## awk / gawk 3.1.x — the most-violated floor

`/usr/bin/awk` on EL6 is `gawk 3.1.7`. The following are gawk-4.0+
extensions that gawk 3.x silently rejects (returns 0/empty, no error
written to stderr). **Every single one has shipped broken at least
once.**

### 1. 3-arg `match(string, /regex/, array)` — gawk 4.0+ only

```awk
# BROKEN on gawk 3.x — silently returns 0, array never populated
if (match(s, /\[([0-9][0-9])\/([0-9][0-9])/, m)) { use(m[1], m[2]) }

# CORRECT — 2-arg match() + RSTART/RLENGTH + substr/split
if (match(s, /\[[0-9][0-9]\/[0-9][0-9]/)) {
    chunk = substr(s, RSTART+1, RLENGTH-1)   # +1/-1 strips the leading [
    n = split(chunk, p, /[\/]/)
    use(p[1], p[2])
}
```

When the captured groups are simple (alternating digits with a fixed
delimiter), `split()` on the delimiter-class is the cleanest decoder.
For complex shapes use anchored substr offsets.

### 2. `{n}` and `{n,m}` interval expressions — disabled by default

gawk 3.x recognizes `{n}` only with `--re-interval` or `--posix`.
Without that flag, `[0-9]{2}` is treated as **literal** `{2}` and
silently fails to match.

```awk
# BROKEN on gawk 3.x default — { is literal
match(s, /\[[0-9]{2}\/[0-9]{2}\/[0-9]{4}/)

# CORRECT — explicit char-class repetition
match(s, /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]/)

# CORRECT for ranges — use + with a length check after extraction
match(s, /^#[0-9]+$/)
```

You cannot pass `--re-interval` from inside a piped one-liner because
operators run `curl … | bash -s -- args` and never see the awk
invocation. **Always write awk regexes without `{n}` quantifiers.**

### 3. `gensub()` — works, but trace-through-stderr quirks

`gensub()` IS available in gawk 3.1.x and is preferred over chained
`sub()` calls when you need a regex backreference. `patsplit()` is
gawk 4.0+ only — don't use it.

### 4. `mktime()` argument format

`mktime()` requires the **exact** string `"YYYY MM DD HH MM SS"`,
space-separated, no leading zeros stripped, all six fields present.
Any other shape returns -1. Don't pass an ISO string or comma-joined
fields.

### 5. Regex literals can't interpolate variables

`/$VAR/` in an awk script is the literal four characters `$`, `V`,
`A`, `R`. To use a runtime regex pass it via `-v` or `ENVIRON[]` and
use the dynamic form: `match(s, ENVIRON["PAT"])`.

### 6. Field index after `split` is 1-based

Standard awk; just a reminder because it bites people coming from
languages with 0-based arrays. Also: `split()` returns the COUNT, not
the array.

---

## bash 4.1.2 — what's missing vs. modern bash

| Feature | Added in | Workaround |
|---|---|---|
| `mapfile` / `readarray` | 4.0 (technically present, but quirky in 4.1) | `while IFS= read -r line; do arr+=("$line"); done < <(cmd)` |
| `printf -v arr[$i] '%s' "$x"` (assignment to array index) | 4.1 (technically) but unreliable; fully reliable in 4.3 | `arr[$i]="$(printf '%s' "$x")"` |
| `${var^^}` / `${var,,}` (case conversion) | 4.0 | `tr '[:lower:]' '[:upper:]'` (extra subprocess but portable) |
| `${var: -1}` (negative substring) | 4.2 | `${var: $((${#var}-1)):1}` |
| `coproc` keyword | 4.0 (broken in 4.1; reliable in 4.2+) | Avoid; use named pipes or background processes |
| `declare -g` | 4.2 | All globals at top level outside functions |
| `local -n` (nameref) | 4.3 | Indirect expansion `${!varname}` |
| `wait -n` | 4.3 | `wait $pid; rc=$?` per-pid loop |
| `${var@Q}` (quoted form) | 4.4 | `printf '%q\n' "$var"` |

### Bash <4.4 parser quirk

`$({ … })` requires a **newline** between `$(` and `{` — without it
the bash 4.1 parser misreads `${` as a parameter expansion. Always
write:

```bash
result=$({
    cmd1
    cmd2
})
```

### Empty-array iteration

`set -u` + empty array iteration crashes on bash 4.1. Guard with the
length check before iterating:

```bash
arr=()
# WRONG — crashes under set -u on bash 4.1
for x in "${arr[@]}"; do …; done
# RIGHT
(( ${#arr[@]} > 0 )) && for x in "${arr[@]}"; do …; done
```

There are 9 such guards in `sessionscribe-ioc-scan.sh` today; verify
your new code adds one if it iterates a possibly-empty array.

### `case` inside `$(…)`

Patterns starting with `(` confuse the bash <4.4 parser inside command
substitution. Always use the leading-paren form:

```bash
# WRONG (parses oddly)
x=$(case "$y" in foo) echo a;; esac)
# RIGHT
x=$(case "$y" in (foo) echo a;; esac)
```

---

## procps / ps — EL6 differences

`pgrep -fa` (the `-a` flag that prints command line) is **procps-ng
only** (EL7+). On EL6's procps-3.2.x it errors out. Replace with:

```bash
ps -eo pid,args | grep -E "$pat" | grep -v grep
```

---

## find / xargs — keep it POSIX where reasonable

- `find -maxdepth N` is POSIX → safe.
- `find … -print0 | xargs -0 …` is widely available (GNU/BSD) → safe
  on any host we target, but document it as a portability assumption.
- Avoid `find -regex` with alternation where the longest alternative
  isn't first (GNU extension; silently drops shorter alternatives).
- `find -newer` is POSIX; `find -newermt` is GNU-only — don't use.

---

## Bash regex (`=~`) vs awk regex

Bash's `=~` operator uses **libc's POSIX ERE** which DOES support
`{n}` interval expressions and most modern features. Bash regexes are
fine — only awk regexes need the gawk-3.x-safe rewrite.

```bash
# OK — bash =~ uses libc, supports {n}
[[ "$s" =~ ^[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4} ]]
```

`grep -E` and `sed -E` similarly use libc and accept `{n}`.

---

## Distribution / CDN gotchas

### GitHub raw cache (Fastly)

`raw.githubusercontent.com` is fronted by Fastly with aggressive edge
caching. After `git push`, the new content can take up to ~5 minutes
to propagate to all edges. To force a miss when validating a fresh
push:

```bash
curl -fsSL "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh?cb=$(date +%s)"
```

The query string is ignored by the file content but breaks the
edge-cache key. **Use this in any post-push verification.**

### sh.rfxn.com — separate canonical CDN

`https://sh.rfxn.com/` lags `raw.githubusercontent.com` because it
requires a manual `rsync` via `/root/bin/sync_local-remote`. After a
push, sh.rfxn.com is **not** updated automatically — see
`reference_cdn_deploy.md` in operator memory.

### Verify what actually ran

The renderer prints the executed `tool_version` in the verdict box
(forensic reads it from the envelope). Always check it after a remote
run — if it doesn't match what you just pushed, you hit a stale edge
cache.

---

## Project-specific runtime semantics

### Verdict, emit weights, and the `reasons:` line

A signal must satisfy ALL of:
1. `severity` ∈ {`strong`, `warning`} (not `info`/`evidence`/`error`)
2. `area` ∈ {`logs`, `sessions`, `destruction`} for forensic to
   ingest it from the envelope
3. `weight ≥ 1` (zero-weight signals don't move the verdict score)

A new IOC that doesn't appear in `reasons:` after firing usually
fails one of these three.

### The CRLF entry-point primitive (Pattern X)

`check_crlf_access_primitive` is the canonical point-of-compromise
detector. It expects:

- POST `/login/?login_only=1` returning 401, then
- GET `/cpsess<digits>/<anything>` returning 2xx as user `root`,
- from the same source IP, within ≤ 2s

The 2-second window assumes cpsrvd minted the token at the POST
side-effect and the operator's tool used it on the next request.
**Don't widen the window without re-verifying** — it would FP on
legitimate browser sessions where the GET-after-401 pattern occurs
during retry/redirect flows.

### Pattern letters → ioc_key prefix mapping

The `ioc_key_to_pattern()` function in forensic maps emit keys to
single-letter pattern codes for the kill-chain renderer. New IOC keys
MUST get a case branch — otherwise they render as `?` and end up in
the "unmapped" bucket. After adding a new `ioc_pattern_*` or
`ioc_cve_*` emit key, grep both files for the mapping:

```bash
grep -E 'ioc_key_to_pattern|PATTERN_ORDER|PATTERN_LABEL' sessionscribe-forensic.sh
```

---

## Workflow rules (carried from global CLAUDE.md)

- **After any naming/vocabulary refactor, grep the WHOLE repo for old
  terms** before declaring done. Stale vocabulary in files not
  covered by the active plan is the most common sentinel finding.
- **Verify shared-lib bug → all consumers** before session ends.
- **One commit per phase** — keeps revert blast radius small.
- **Validate-then-publish:** lab-test (e.g. on `cpanel_client` tmux
  session) before pushing changes that the curl one-liner picks up.
  The fleet pulls main directly.

---

## Verification gate (per release)

Every version bump ships with all of:

```bash
bash -n sessionscribe-ioc-scan.sh && echo OK
shellcheck -S error sessionscribe-ioc-scan.sh
bash sessionscribe-ioc-scan.sh --help >/dev/null && echo OK

# gawk-3.x compat probes — both must pass on a CL6 host
awk 'BEGIN { if (match("[01/02/2026", /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]/)) print "interval-OK"; else print "interval-BROKEN" }'
awk 'BEGIN { if (match("x", /x/, m)) print "3arg-OK"; else print "3arg-FAIL-OR-NOT-AVAILABLE" }'

# Confirm zero {n} intervals in awk regexes (sed/grep/bash regexes are OK)
grep -nE 'match.*\{[0-9]|/[^/]*\{[0-9][^/]*/' sessionscribe-ioc-scan.sh
# expect: zero hits in awk-block context

# Confirm zero 3-arg match() calls
grep -nE 'match\([^,]+,[^,]+,[^)]+\)' sessionscribe-ioc-scan.sh
# expect: only commented references, no live calls
```

Run on a real CL6/EL6 box (cpanel_client tmux session in operator
memory). gawk version on the lab can be confirmed with `awk --version`
— must be `3.1.x` for floor validation.

---

## Merged-script architecture (v2.0.0+)

As of v2.0.0, `sessionscribe-forensic.sh` is merged into
`sessionscribe-ioc-scan.sh`. The two-script chain (with envelope-as-IPC)
is replaced by a single script with three operator-facing modes:

| Mode | Flag | What it does |
|---|---|---|
| Triage (default) | (none) or `--triage` | Detection only; writes envelope to `/var/cpanel/sessionscribe-ioc/<run_id>.json`. No defense timeline, kill-chain, or bundle. |
| Full | `--full` | Detection + forensic phases (defense / offense / reconcile / kill-chain / bundle / upload). |
| Replay | `--replay PATH` | Skip detection; replay forensic against a saved envelope (`.json`), bundle directory, or `.tgz`. |

### Envelope read-after-write contract

In `--full` mode the envelope is written to disk BEFORE forensic phases
run, then `phase_offense` reads it back via the same code path used by
`--replay`. This makes the envelope contract a same-script invariant —
any divergence between detection's signals and forensic's view of them
is impossible by construction (single source, single read path).

### Back-compat aliases

The v1.x chain flags continue to work — they map to `--full` plus the
matching gate flag:

| v1.x flag | v2.0.0 equivalent |
|---|---|
| `--chain-forensic` | `--full` (no host-verdict gate) |
| `--chain-on-critical` | `--full` + `CHAIN_ON_CRITICAL=1` (skip if HOST_VERDICT != COMPROMISED) |
| `--chain-upload` | `--full --upload` |

### Forensic-area signals

Forensic phases emit signals via `emit_signal()` (a thin wrapper around
the canonical `emit()`) under these new `area` values: `defense`,
`offense`, `reconcile`, `bundle`, `upload`, `summary`. The severity
vocabulary maps:

| forensic severity | emit() severity | weight |
|---|---|---|
| `pass`, `info` | `info` | 0 |
| `warn` | `warning` | 4 |
| `fail` | `strong` | 10 |

All forensic findings flow into the unified `SIGNALS[]` stream and
appear in the same envelope as detection signals.

### Deprecation shim

`sessionscribe-forensic.sh` is now a ~50-line v0.99.0 shim that prints
a one-line deprecation notice and `exec`s
`sessionscribe-ioc-scan.sh --replay <path>`. It preserves the
`sh.rfxn.com` and `raw.githubusercontent.com` URLs for operators still
on the v1.x curl one-liner. The shim will be removed in a future release.
