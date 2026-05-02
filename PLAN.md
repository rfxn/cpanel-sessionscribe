# PLAN — IC-5790 Dossier Rev3 Coverage Update

**Started:** 2026-05-01
**Goal:** Align `sessionscribe-ioc-scan.sh` and `sessionscribe-forensic.sh` with the IC-5790 Compromise Pattern List rev 3 (2026-05-01). Close detection gaps for new Patterns H/I, refresh existing Pattern coverage, normalize "Stage → Pattern" vocabulary, and capture the new artifacts in the forensic bundle.
**Open decisions resolved:**
- JSONL `stage` → `pattern` rename: yes, with `schema_version:2` migration hint embedded in the bundle's `kind:"meta"` row.
- Pattern H `ALLDONE` marker: emit as `warning` weight 5 — too generic to drive verdict alone.

---

## Version axis

| Phase | File(s) | Version bump | Risk |
|---|---|---|---|
| 0 | sessionscribe-forensic.sh | v0.9.9 → v0.10.0 | Schema rename; mitigated via schema_version meta hint |
| 1 | sessionscribe-ioc-scan.sh | v1.6.6 → v1.6.7 | List-cardinality only |
| 2 | sessionscribe-ioc-scan.sh | v1.6.7 → v1.6.8 | Localized regex/glob expansions |
| 3+4 | sessionscribe-ioc-scan.sh + sessionscribe-forensic.sh | ioc-scan v1.6.8 → v1.7.0; forensic v0.10.0 → (still) v0.10.0 | New detection coverage; emits new signal keys |
| 5 | sessionscribe-forensic.sh | v0.10.0 → v0.10.1 | New bundle artifacts; mirrors Pattern A capture pattern |
| 6 | both | (verification only — no bump) | — |
| 7 | CDN | (deploy) | rsync to habs.rfxn.com |

5 commits, 4 version bumps.

---

## Phase 0 — Vocabulary refactor (forensic) → **v0.10.0**

### Symbol renames (internal API)

| Site | Old | New |
|---|---|---|
| forensic:902 | `ioc_key_to_stage()` | `ioc_key_to_pattern()` |
| forensic:1429 | `STAGE_ORDER=(init A B C D E F G X "?")` | `PATTERN_ORDER=(init A B C D E F G X "?")` |
| forensic:1430 | `declare -A STAGE_LABEL=(...)` | `declare -A PATTERN_LABEL=(...)` |
| forensic:1041, 1058, 1062, 1956, 1959, 1973, 2053, 2066, 2086 | local var `stage` (callers of the rename) | `pattern` |

All references must be updated atomically — bash will not warn on a stale callsite, only fail at runtime.

### Renderer column header

forensic:1499:
```bash
printf '  %s%s%s  %s  %s%s%s stage %-4s ...' …  →
printf '  %s%s%s  %s  %s%s%s pattern %-4s ...' …
```

(Width 4 still covers `init`/`A`–`I`/`X`/`?`. Header label change only.)

### JSONL schema — v1 → v2

forensic:2086:
```bash
printf '{"kind":"IOC","epoch":%s,"ts":"%s","stage":"%s",…  →
printf '{"kind":"IOC","epoch":%s,"ts":"%s","pattern":"%s",…
```

forensic:2028 (meta-row emitter) — append schema-version + migration hint:
```bash
printf '{"kind":"meta","host":"%s",…,"tool_version":"%s","schema_version":2,'
printf '"_schema_changes":[{"v":2,"since_tool":"0.10.0","renamed":{"stage":"pattern"},'
printf '"note":"IOC pattern letters were emitted as stage in schema v1 (forensic <= 0.9.x)"}],'
…
```

Add a one-line comment block immediately above the printf call so the next reader of the source sees the rename without git archeology:
```bash
# JSONL schema v2 (forensic v0.10.0+): per-IOC field 'stage' renamed to
# 'pattern' to match the IC-5790 dossier vocabulary. Meta row carries
# schema_version=2 and a _schema_changes hint so future readers (operator
# tooling, LLM analyses) can adapt automatically.
```

### Comment cleanup

forensic, comments only — refresh "stage" → "pattern" where the term refers to a Pattern letter (A/B/C/...), NOT where it refers to kill-chain phase abstractions like "destruction stage" or "harvest stage" (those are the phase taxonomy and stay).

Sites to refresh (text-only, no code change):
- forensic:867 ("Pattern G deep checks ioc-scan doesn't perform")
- forensic:901 ("Map ioc-scan emit key -> kill-chain stage letter") → "Map ioc-scan emit key → IC-5790 Pattern letter"
- forensic:1001 ("epoch|stage|key|note|defenses_required") → "epoch|pattern|key|note|defenses_required"
- forensic:1427 ("Order stages canonically for the offense timeline") → "Order patterns canonically for the offense timeline"
- forensic:1956, 2053 ("canonical stage order") → "canonical pattern order"

ioc-scan comments at line 152, 316, 1716 — keep "destruction-stage" wording. That's the kill-chain phase, not a Pattern letter. Verified by `grep -nE 'destruction-stage'` — these are correct.

### Verification gate

Post-edit, full-repo grep:
```bash
grep -nE '\bstage[_ ][A-I]\b|\bSTAGE_(ORDER|LABEL)\b|ioc_key_to_stage' *.sh
# expect zero hits
grep -nE '\bdestruction-stage\b' *.sh
# expect 3 hits (ioc-scan:152, 316, 1716) - kept on purpose
```

A leftover `stage` in non-comment code is an error (per global CLAUDE.md "Refactor vocabulary grep").

---

## Phase 1 — ATTACKER_IPS expansion → **ioc-scan v1.6.7**

### Edit site

ioc-scan:228-232 — replace the 12-IP list with 19 entries, regrouped by role for the comment header:

```bash
# Attacker source IPs consolidated from the IC-5790 dossier (rev 3,
# 2026-05-01). Roles: badpass exploit, JSON-API enum, websocket Shell,
# TLS/HTTP probes, C2/dropper. Some are blackholed; we still want to
# count log hits as a late-stage signal in case rotation didn't take.
# Operators with internal scan boxes can suppress hits via --exclude-ip.
ATTACKER_IPS=(
    # badpass exploitation source IPs
    68.233.238.100   206.189.2.13     137.184.77.0     38.146.25.154
    157.245.204.205  142.93.43.26     5.230.165.16     5.252.177.207
    146.19.24.235
    # JSON-API enum + websocket Shell (operator IPs)
    192.81.219.190   149.102.229.144  183.82.160.147   45.82.78.104
    # TLS/HTTP probes
    94.231.206.39
    # C2 / dropper / payload origin
    68.183.190.253   87.121.84.78     96.30.39.236     68.47.28.118
    # Pattern Unknown (host.coprimemain.com pending classification)
    89.34.18.59
)
```

### Notes

- 183.82.160.147 deserves a header callout for **pre-disclosure exploitation evidence** (DEC 2025 on quickfix17). Add a one-line comment on its row.
- Existing `check_attacker_ips` regex builder (ioc-scan:1058-1062) is list-length agnostic; no functional code change.

### Verification

```bash
bash -n sessionscribe-ioc-scan.sh
# Spot-check on synthetic access_log line containing one of the new IPs:
echo '142.93.43.26 - - [01/05/2026:10:00:00 ...] "GET /json-api/listaccts ...' \
  | grep -E '^(142\.93\.43\.26|...) '
```

---

## Phase 2 — F/B/E refinements + LeakIX UA → **ioc-scan v1.6.8**

Four localized changes; one commit.

### 2a — Pattern F: multi-shell history

ioc-scan:1985-1986:
```bash
f_hit=$(grep -lF "$PATTERN_F_S_MARK" \
            /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
```
→
```bash
# IC-5790 dossier rev3: harvester reads bash/zsh/sh/fish histories
# (Pattern F __S_MARK__/__E_MARK__ envelope). Glob covers all four shells.
f_hit=$(grep -lF "$PATTERN_F_S_MARK" \
            /root/.bash_history /root/.zsh_history /root/.sh_history \
            /root/.local/share/fish/fish_history \
            /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history \
            /home/*/.local/share/fish/fish_history 2>/dev/null | head -1)
```

(Reused by Phase 3 for Pattern H markers — keep the glob list as a reusable variable: declare `HISTORY_FILES_GLOB` near the top of `check_destruction_iocs` and reference it from both the Pattern F and Pattern H blocks.)

### 2b — Pattern B: nested public_html walk

ioc-scan:1844:
```bash
btc_hit=$(grep -lF "$PATTERN_B_BTC_ADDR" /home/*/public_html/index.html 2>/dev/null | head -1)
```
→
```bash
# IC-5790 rev3: graceworkz showed nested drops at
# /home/<user>/public_html/{banks,ois,sales,shop}/index.html. -maxdepth 4
# bounds the walk; -name index.html filters before reading. find -print0 +
# xargs -0 keeps a malicious user dir name from breaking the pipeline.
local btc_hit=""
btc_hit=$(find /home/*/public_html -maxdepth 4 -name index.html -print0 2>/dev/null \
            | xargs -0 grep -lF "$PATTERN_B_BTC_ADDR" 2>/dev/null | head -1)
```

CL6 floor: `find` and `xargs` are POSIX, no bash 4.x dependency. Empty `/home/*/public_html` glob expands literally if no match — `find` errors silently because of `2>/dev/null`. Verified safe.

### 2c — Pattern E: dimension comment refresh

ioc-scan:193-195:
```bash
# Pattern E - websocket/Shell access-log signature. The 24x80 dimension is
# the script-kiddie automated default; 24x120 has been seen too. The path
# regex is dimension-agnostic so any rows=N&cols=M lands here.
```
→
```bash
# Pattern E - websocket/Shell access-log signature. Three operator
# dimensions distinguish actor in the IC-5790 cohort:
#   24x80   - graceworkz / 192.81.219.190 (Pattern E original, automated)
#   24x120  - graceworkz / 149.102.229.144 (secondary operator)
#   24x134  - quickfix17 / 183.82.160.147 (DEC 2025, pre-disclosure)
# The detection regex is dimension-agnostic so any rows=N&cols=M lands here;
# operator attribution comes from the dimension+IP+UA combination at triage.
```

No code change.

### 2d — LeakIX UA in IOC_AUTOMATED_UA

ioc-scan:124:
```bash
IOC_AUTOMATED_UA='python-requests|^curl/|Go-http-client|libwww-perl|aiohttp|okhttp|httpx'
```
→
```bash
IOC_AUTOMATED_UA='python-requests|^curl/|Go-http-client|libwww-perl|aiohttp|okhttp|httpx|l9scan'
```

LeakIX UA pattern is `Mozilla/5.0 (l9scan/2.0.130313e2337313e2532323e27363; +https://leakix.net)`. The `l9scan` substring is unique enough that it won't FP on Mozilla rows from real browsers. Adds the LeakIX-flavored Mozilla traffic to the JSON-API recon detection net.

### Verification

```bash
bash -n sessionscribe-ioc-scan.sh

# Pattern F multi-shell smoke
mkdir -p /tmp/test-pf/{root,home/u}
echo "__S_MARK__ ls __E_MARK__" > /tmp/test-pf/home/u/.zsh_history
# (functional test deferred to live host; smoke is grep idiom check)
grep -lF "__S_MARK__" /tmp/test-pf/home/u/.zsh_history && echo "PF_OK"

# Pattern B nested walk
mkdir -p /tmp/test-pb/u/public_html/banks
echo "bc1q9nh4revv6yqhj2gc5usncrpsfnh7ypwr9h0sp2" > /tmp/test-pb/u/public_html/banks/index.html
find /tmp/test-pb -maxdepth 5 -name index.html -print0 \
  | xargs -0 grep -lF "bc1q9nh4revv6yqhj2gc5usncrpsfnh7ypwr9h0sp2" \
  && echo "PB_NESTED_OK"
rm -rf /tmp/test-pf /tmp/test-pb
```

---

## Phase 3 — Pattern H implementation → **ioc-scan v1.7.0**

### Constants block

Insert after PATTERN_G_FORGED_MTIME (ioc-scan:209):
```bash
# Pattern H - seobot SEO defacement / per-site PHP webshell drop. Surfaced
# 5/1 14:59 CDT on host.quickfix17.com from .bash_history. Distinct actor
# from the nuclear.x86 campaign - actively kills rival infections (xmrig,
# kswapd01) before deploying. Fingerprints below let a triage scan confirm
# Pattern H toolchain across the fleet.
PATTERN_H_DROPPER_FILE="seobot.php"          # planted in every cPanel docroot
PATTERN_H_END_MARKER="ALLDONE"               # operator console end-of-run marker
PATTERN_H_KILL_PRELUDE='pkill -9 nuclear\.x86 kswapd01 xmrig'  # ERE
PATTERN_H_ZIP_PATH="/tmp/seobot.zip"         # dropper archive (self-cleaned, but slow operators leave it)
PATTERN_H_ZIP_MAGIC_B64="UEsDBBQACAAIAMhEkVw" # base64-encoded zip header for the H-specific payload
```

### Detection block

Insert in `check_destruction_iocs` after the Pattern G `oddkeys` block (after ioc-scan:2071), before Pattern E (ioc-scan:2074):

```bash
# ---- Pattern H: seobot defacement / SEO spam dropper -----------------
# Four independent signals - any one is dispositive (strong) except the
# generic "ALLDONE" marker which is warning-tier (the marker string is
# common enough in shell scripts that it can FP without corroboration).

# H1: seobot.php in any cPanel-managed docroot. Derive docroots from
# /var/cpanel/userdata/<user>/main (canonical) with /home/*/public_html
# fallback for hosts where userdata is empty/missing.
local h_seobot_hit=""
local docroot_list; docroot_list=$(mktemp /tmp/ssioc.docroots.XXXXXX)
{
    if [[ -d /var/cpanel/userdata ]]; then
        grep -rh '^documentroot:' /var/cpanel/userdata/*/ 2>/dev/null \
          | awk '{print $2}' | sort -u
    fi
    # Fallback (also catches main public_html sites)
    for d in /home/*/public_html; do
        [[ -d "$d" ]] && printf '%s\n' "$d"
    done
} | sort -u > "$docroot_list"
if [[ -s "$docroot_list" ]]; then
    while IFS= read -r dr; do
        [[ -d "$dr" ]] || continue
        local found
        found=$(find "$dr" -maxdepth 3 -name "$PATTERN_H_DROPPER_FILE" -print -quit 2>/dev/null)
        if [[ -n "$found" ]]; then
            h_seobot_hit="$found"
            break
        fi
    done < "$docroot_list"
fi
rm -f "$docroot_list"
if [[ -n "$h_seobot_hit" ]]; then
    local h_mtime
    h_mtime=$(stat -c %Y "$h_seobot_hit" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_seobot_php" "strong" \
         "ioc_pattern_h_seobot_dropper_present" 10 \
         "sample_path" "$h_seobot_hit" "mtime_epoch" "${h_mtime:-0}" \
         "note" "$PATTERN_H_DROPPER_FILE planted in $h_seobot_hit - Pattern H SEO defacement (CRITICAL)."
    ((hits++))
fi

# H2: kill-prelude (`pkill -9 nuclear.x86 kswapd01 xmrig`) in any history
# file. Reuses HISTORY_FILES_GLOB defined for Pattern F.
local h_kill_hit=""
h_kill_hit=$(grep -lE "$PATTERN_H_KILL_PRELUDE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null | head -1)
if [[ -n "$h_kill_hit" ]]; then
    local h_kill_mtime
    h_kill_mtime=$(stat -c %Y "$h_kill_hit" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_kill_prelude" "strong" \
         "ioc_pattern_h_competitor_kill" 8 \
         "sample_path" "$h_kill_hit" "mtime_epoch" "${h_kill_mtime:-0}" \
         "note" "Pattern H competitor-kill prelude in $h_kill_hit (kills nuclear.x86/kswapd01/xmrig before drop)."
    ((hits++))
fi

# H3: ALLDONE end marker. Warning-tier - generic enough to FP, useful only
# alongside H1/H2/H4.
local h_alldone_hit=""
h_alldone_hit=$(grep -lF "$PATTERN_H_END_MARKER" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null | head -1)
if [[ -n "$h_alldone_hit" ]]; then
    local h_alldone_mtime
    h_alldone_mtime=$(stat -c %Y "$h_alldone_hit" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_alldone" "warning" \
         "ioc_pattern_h_alldone_marker" 5 \
         "sample_path" "$h_alldone_hit" "mtime_epoch" "${h_alldone_mtime:-0}" \
         "note" "Pattern H operator end-marker '$PATTERN_H_END_MARKER' in $h_alldone_hit - review for corroborating signals."
    ((hits++))
fi

# H4: dropper archive on disk. Self-cleans per dossier; this catches slow
# operators or interrupted runs. base64-encode the first 24 bytes (16 raw
# bytes * 4/3 = 21.33 -> 24) and prefix-match against the PATTERN_H_ZIP_MAGIC_B64.
if [[ -f "$PATTERN_H_ZIP_PATH" ]]; then
    local h_zip_b64
    h_zip_b64=$(head -c 16 "$PATTERN_H_ZIP_PATH" 2>/dev/null | base64 -w0 2>/dev/null)
    if [[ "$h_zip_b64" == "$PATTERN_H_ZIP_MAGIC_B64"* ]]; then
        local h_zip_mtime
        h_zip_mtime=$(stat -c %Y "$PATTERN_H_ZIP_PATH" 2>/dev/null)
        emit "destruction" "ioc_pattern_h_zip_dropper" "strong" \
             "ioc_pattern_h_dropper_archive" 10 \
             "path" "$PATTERN_H_ZIP_PATH" "mtime_epoch" "${h_zip_mtime:-0}" \
             "note" "Pattern H dropper archive at $PATTERN_H_ZIP_PATH (base64 zip header matches H signature - operator did not self-clean)."
        ((hits++))
    fi
fi
```

### HISTORY_FILES_GLOB declaration

Hoisted to the top of `check_destruction_iocs` (just after the function header), used by Pattern F (Phase 2a) and Pattern H (H2/H3 above):

```bash
# History files swept by Pattern F harvester and Pattern H markers. Bash,
# zsh, sh, fish - root + every cPanel user. Empty globs expand to literal
# pattern; grep -F handles non-existent paths via 2>/dev/null.
local HISTORY_FILES_GLOB=(
    /root/.bash_history /root/.zsh_history /root/.sh_history
    /root/.local/share/fish/fish_history
    /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history
    /home/*/.local/share/fish/fish_history
)
```

### Help-text + comment updates

ioc-scan `--no-destruction-iocs` help block (around ioc-scan:317): "Patterns A-G" → "Patterns A-I".

ioc-scan top-level header comment (around ioc-scan:152): refresh the patterns enumeration to include H and I.

### Forensic side — pattern mapping

forensic, `ioc_key_to_pattern()` (post-rename in Phase 0) — add cases:
```bash
ioc_pattern_h_*)            echo H ;;
ioc_pattern_i_*)            echo I ;;   # added in Phase 4
```

forensic, `PATTERN_ORDER` — extend:
```bash
PATTERN_ORDER=(init A B C D E F G H I X "?")
```

forensic, `PATTERN_LABEL` — add entries:
```bash
[H]="seobot defacement / SEO spam"
[I]="system-service profile.d backdoor"  # added in Phase 4
```

---

## Phase 4 — Pattern I implementation → **ioc-scan v1.7.0** (same release as Phase 3)

### Constants block

Insert after Pattern H constants:
```bash
# Pattern I - system-service profile.d backdoor (IC-5794 cohort, surfaced
# on web01.guestreservations.com). Persistence vector: profile.d hook
# triggers on every interactive shell login - fires more discreetly than
# cron. Likely Hyper Global-specific (lateral from bastion rather than
# direct CVE-2026-41940 vector), but worth fleet-wide hunting.
PATTERN_I_PROFILED="/etc/profile.d/system_profiled_service.sh"
PATTERN_I_BINARY="/root/.local/bin/system-service"
PATTERN_I_PROCNAME="system-service"
```

### Detection block

Insert in `check_destruction_iocs` after the Pattern H block:

```bash
# ---- Pattern I: system-service profile.d backdoor --------------------
# Three signals - file existence, binary presence, running process. Any
# one is strong; failed-chmod log signature is corroborating evidence
# (warning) that confirms the hook actually fired for non-root logins.

# I1: profile.d hook file. Filename is unique per dossier - no benign
# system component creates this exact filename.
if [[ -f "$PATTERN_I_PROFILED" ]]; then
    local i_hook_mtime
    i_hook_mtime=$(stat -c %Y "$PATTERN_I_PROFILED" 2>/dev/null)
    emit "destruction" "ioc_pattern_i_profiled_hook" "strong" \
         "ioc_pattern_i_profiled_hook_present" 10 \
         "path" "$PATTERN_I_PROFILED" "mtime_epoch" "${i_hook_mtime:-0}" \
         "note" "Pattern I profile.d backdoor hook at $PATTERN_I_PROFILED - fires on every interactive login (CRITICAL)."
    ((hits++))
fi

# I2: binary at non-standard /root/.local/bin path. Capture mtime; sha256
# is a forensic concern (forensic v0.10.1 hashes the binary into bundle
# metadata). Do NOT execute or hash it here - keep ioc-scan cheap.
if [[ -f "$PATTERN_I_BINARY" ]]; then
    local i_bin_mtime
    i_bin_mtime=$(stat -c %Y "$PATTERN_I_BINARY" 2>/dev/null)
    emit "destruction" "ioc_pattern_i_binary" "strong" \
         "ioc_pattern_i_binary_present" 10 \
         "path" "$PATTERN_I_BINARY" "mtime_epoch" "${i_bin_mtime:-0}" \
         "note" "Pattern I binary at $PATTERN_I_BINARY - non-standard daemon path, masquerades as user-installed (CRITICAL)."
    ((hits++))
fi

# I3: running process. pgrep is cheap and won't hang.
if command -v pgrep >/dev/null 2>&1; then
    if pgrep -x "$PATTERN_I_PROCNAME" >/dev/null 2>&1; then
        emit "destruction" "ioc_pattern_i_running" "strong" \
             "ioc_pattern_i_process_running" 10 \
             "procname" "$PATTERN_I_PROCNAME" \
             "note" "Pattern I process '$PATTERN_I_PROCNAME' currently running - active backdoor (CRITICAL)."
        ((hits++))
    fi
fi

# I4: failed-chmod log signature. Eaton's discovery path - non-root user
# logs in via SSH, profile.d hook tries chmod, hits permission-denied,
# logs to /var/log/secure. Confirms hook is actively firing in the wild.
local i_log_hit=""
i_log_hit=$(grep -lF "chmod: cannot access '$PATTERN_I_BINARY'" \
                /var/log/secure /var/log/secure.[0-9]* /var/log/secure-* \
                /var/log/messages /var/log/messages.[0-9]* /var/log/messages-* \
                2>/dev/null | head -1)
if [[ -n "$i_log_hit" ]]; then
    local i_log_mtime
    i_log_mtime=$(stat -c %Y "$i_log_hit" 2>/dev/null)
    emit "destruction" "ioc_pattern_i_failed_chmod" "warning" \
         "ioc_pattern_i_hook_fired_for_non_root" 4 \
         "sample_path" "$i_log_hit" "mtime_epoch" "${i_log_mtime:-0}" \
         "note" "Pattern I hook fire signature in $i_log_hit (failed chmod from non-root login) - corroborating evidence."
    ((hits++))
fi
```

### Forensic mapping

Already covered in Phase 3 (`ioc_pattern_i_*` → I, PATTERN_ORDER includes I, PATTERN_LABEL[I] populated).

---

## Phase 5 — Forensic Pattern H/I bundle capture → **forensic v0.10.1**

Mirror Pattern A binary-metadata pattern (forensic:2389-2398). Two new capture blocks in `phase_bundle`, after the current Pattern A block:

### Pattern H capture block

```bash
# 7b. Pattern H artifacts - seobot.php across cPanel docroots. Capture
# stat + sha256 + first 256 bytes (PHP shells fingerprint via opening
# tag); cap at 50 entries to bound output on big shared hosts.
local h_seobot_meta="$bdir/pattern-h-seobot-metadata.txt"
local h_seobot_count=0
{
    echo "# Pattern H seobot.php capture (IC-5790 dossier rev3)"
    echo "# captured_at=$TS_ISO host=$HOSTNAME_FQDN"
    echo
    while IFS= read -r dr; do
        [[ -d "$dr" ]] || continue
        while IFS= read -r -d '' h; do
            (( h_seobot_count++ ))
            (( h_seobot_count > 50 )) && break 2
            echo "=== seobot.php hit #$h_seobot_count ==="
            stat "$h" 2>&1
            sha256sum "$h" 2>&1
            file "$h" 2>&1
            echo "--- first 256 bytes ---"
            head -c 256 "$h" 2>/dev/null
            echo
            echo
        done < <(find "$dr" -maxdepth 3 -name 'seobot.php' -print0 2>/dev/null)
    done < <({
        if [[ -d /var/cpanel/userdata ]]; then
            grep -rh '^documentroot:' /var/cpanel/userdata/*/ 2>/dev/null \
              | awk '{print $2}' | sort -u
        fi
        for d in /home/*/public_html; do
            [[ -d "$d" ]] && printf '%s\n' "$d"
        done
    } | sort -u)
} > "$h_seobot_meta" 2>/dev/null
if (( h_seobot_count > 0 )); then
    say_warn "Pattern H captured: $h_seobot_count seobot.php hit(s)"
    emit_signal bundle warn pattern_h_seobot_captured \
        "seobot.php captured ($h_seobot_count hits)" \
        path "pattern-h-seobot-metadata.txt" count "$h_seobot_count"
else
    rm -f "$h_seobot_meta"
fi
```

### Pattern I capture block

```bash
# 7c. Pattern I artifacts - system-service binary at /root/.local/bin.
# Capture metadata only (NOT the binary itself - mirrors Pattern A safety
# policy; binary may be a miner/beacon worth quarantining intact).
if [[ -f "$PATTERN_I_BINARY" ]]; then
    local i_meta="$bdir/pattern-i-system-service-metadata.txt"
    {
        echo "# Pattern I system-service binary capture (IC-5790 dossier rev3)"
        echo "# captured_at=$TS_ISO host=$HOSTNAME_FQDN"
        echo "# binary path: $PATTERN_I_BINARY"
        echo
        echo "=== stat ==="
        stat "$PATTERN_I_BINARY" 2>&1
        echo
        echo "=== sha256 ==="
        sha256sum "$PATTERN_I_BINARY" 2>&1
        echo
        echo "=== md5 ==="
        md5sum "$PATTERN_I_BINARY" 2>&1
        echo
        echo "=== file ==="
        file "$PATTERN_I_BINARY" 2>&1
        if have_cmd ldd; then
            echo
            echo "=== ldd ==="
            ldd "$PATTERN_I_BINARY" 2>&1 || echo "(ldd failed - likely statically linked)"
        fi
    } > "$i_meta" 2>/dev/null
    say_warn "Pattern I binary metadata captured (binary itself NOT bundled)"
    emit_signal bundle warn pattern_i_binary_captured \
        "system-service binary metadata captured" \
        path "pattern-i-system-service-metadata.txt" \
        bin "$PATTERN_I_BINARY"
fi
# Note: /etc/profile.d/system_profiled_service.sh already captured in
# persistence.tgz via the existing /etc/profile.d sweep. Emit an explicit
# bundle-info signal so the bundle log records that the IOC artifact is
# present.
if [[ -f "$PATTERN_I_PROFILED" ]]; then
    emit_signal bundle info pattern_i_hook_in_persistence_tgz \
        "system_profiled_service.sh present in persistence.tgz" \
        path "$PATTERN_I_PROFILED"
fi
```

### Forensic constants

forensic needs to either define `PATTERN_I_BINARY` and `PATTERN_I_PROFILED` itself, or read them from the ioc-scan envelope. Cleanest: declare them in forensic's PATTERN_* constants block (around forensic:150) — same source-of-truth pattern as PATTERN_A_BINARY:
```bash
# Pattern I (IC-5794, surfaced 2026-05-01) - file paths mirrored from
# ioc-scan PATTERN_I_* constants for offline-bundle analysis.
PATTERN_I_BINARY="/root/.local/bin/system-service"
PATTERN_I_PROFILED="/etc/profile.d/system_profiled_service.sh"
```

---

## Phase 6 — Verification gate (per phase)

Each version bump ships with all of:

| Check | Tool |
|---|---|
| Bash syntax | `bash -n <file>` |
| Shellcheck error-level | `shellcheck -S error <file>` |
| `--help` smoke | `bash <file> --help >/dev/null && echo OK` |
| CL6 floor preserved | `grep -cE '\(\(\s*\$\{#.*\[@\]\}\s*>\s*0\s*\)\)'` should be ≥ existing count (currently 9 in ioc-scan) |
| Vocabulary cleanup (Phase 0 only) | `grep -nE '\bSTAGE_(ORDER\|LABEL)\b\|ioc_key_to_stage' *.sh` empty |
| New emit keys appear | `grep -c 'ioc_pattern_h_\|ioc_pattern_i_'` ≥ 7 in ioc-scan |
| JSONL schema hint present (Phase 0) | `grep -c '"schema_version"' sessionscribe-forensic.sh` ≥ 1 |
| Behavioral smoke (Pattern H/I) | Synthetic-input runs (PLAN section "Synthetic test harness" below) |

### Synthetic test harness (post-Phase 4)

Stand up a tmpdir that mocks the relevant filesystem layout:

```bash
T=$(mktemp -d)
# Pattern H mocks
mkdir -p "$T/var/cpanel/userdata/u1/site"
printf 'documentroot: %s/home/u1/public_html\n' "$T" > "$T/var/cpanel/userdata/u1/site/main"
mkdir -p "$T/home/u1/public_html"
echo "<?php /* fake seobot */" > "$T/home/u1/public_html/seobot.php"
mkdir -p "$T/root"
echo "pkill -9 nuclear.x86 kswapd01 xmrig" > "$T/root/.bash_history"
echo "ALLDONE" >> "$T/root/.bash_history"
# Pattern H zip-magic
printf '\x50\x4b\x03\x04\x14\x00\x08\x00\x08\x00\xc8\x44\x91\x5c' > "$T/tmp/seobot.zip"
mkdir -p "$T/tmp"
mv "$T/tmp/seobot.zip" "/tmp/seobot.zip.test" 2>/dev/null
# Pattern I mocks
mkdir -p "$T/etc/profile.d" "$T/root/.local/bin"
echo "#!/bin/bash" > "$T/etc/profile.d/system_profiled_service.sh"
echo -e '#!/bin/bash\necho fake' > "$T/root/.local/bin/system-service"
chmod 0755 "$T/root/.local/bin/system-service"
# Run with --root override so ioc-scan walks $T as the host
bash sessionscribe-ioc-scan.sh --root "$T" --no-version --no-static --no-binary --no-logs --no-sessions --jsonl 2>&1 \
  | grep -E '"key":"ioc_pattern_(h|i)_'
# Expect: at least 4 Pattern H emits + 3 Pattern I emits
rm -rf "$T" /tmp/seobot.zip.test
```

(Caveat: ioc-scan's `--root` mode is for snapshot scans and may skip destruction-IOCs entirely per the existing `if [[ -n "$ROOT_OVERRIDE" ]]; then ... return; fi` at ioc-scan:1724-1729. If that's the case, the synthetic run needs to skip `--root` and instead chroot OR we drop the synthetic test in favor of a careful staging-host run. **Resolution: investigate during Phase 6 setup**; if `--root` blocks destruction-IOCs by design we use a real lab host (per the lab tmux memory) and live-test there.)

---

## Phase 7 — CDN deploy

Per the cdn-deploy reference memory:
1. `command cp -fp <repo>/<artifact> /root/admin/work/downloads/<artifact>` (each updated script)
2. `/root/bin/sync_local-remote`
3. Verify: `curl -sS -o /tmp/cdn-<x> -w 'HTTP=%{http_code} bytes=%{size_download}\n' 'https://sh.rfxn.com/<artifact>?nocache=$(date +%s)'`
4. `sha256sum /tmp/cdn-<x> <repo>/<artifact>` — must match
5. Spot-check `head -4` for the new VERSION strings
6. Spot-check fix signatures: `grep -c ioc_pattern_h_ ...` ≥ 4, `grep -c ioc_pattern_i_ ...` ≥ 3, `grep -c '"schema_version"' ...` ≥ 1 (forensic)

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| JSONL schema rename breaks downstream consumer | low | `schema_version:2` migration hint embedded in meta row; intent-violating consumers fail loudly (no `stage` field) rather than silently misinterpret; forensic v0.10.0 minor-version bump signals the break |
| Pattern H/I FP on benign hosts | medium | H1/H4/I1/I2/I3 are dispositive (filename/path/process unique to dossier); H3 (`ALLDONE`) and I4 (`failed_chmod`) are warning-tier so they need corroboration |
| HISTORY_FILES_GLOB on hosts with thousands of /home users | low | grep -lF stops at first match; glob expansion is bounded by /home/*/.bash_history etc; no recursive walk |
| `find /home/*/public_html -maxdepth 4` on big shared hosts | low-medium | -maxdepth 4 + -name index.html is bounded; previously-existing find walks (Pattern A README) use -maxdepth 2 with no reported perf issue. If reports come in we can re-tier as a separate pass |
| `--root` snapshot mode skips destruction IOCs (incl. H/I) | known | Already documented in ioc-scan:1720-1729; H/I are host-state probes, snapshot mode legitimately can't see them. No regression. |
| CL6 (bash 4.1) regressions from new array iteration | low | Phase 6 verification re-greps for length-check guards; new code uses the same idiom (where `local arr=()` declared then iterated) |

---

## Rollback strategy

Each phase is one commit. If any phase causes a deployed-CDN regression:
1. `git revert <commit-sha>`
2. Re-run Phase 7 deploy — restores prior live version
3. The 5-commit structure means a buggy Pattern H detection (Phase 3) can be reverted without rolling back the vocabulary refactor (Phase 0) or the IP-list expansion (Phase 1)

JSONL schema downgrade (rolling forensic back from v0.10.0 to v0.9.9):
- Bundles emitted under v0.10.0 will have `"pattern":` fields; downgrading the script doesn't break those bundles (they're frozen artifacts) but does mean new bundles emit `"stage":` again
- The `_schema_changes` hint still works: a v3 reader could remap both directions if needed
- No data loss

---

## Open items / tracking

- [ ] Phase 0 — Forensic vocab refactor + JSONL schema_version hint
- [ ] Phase 1 — ATTACKER_IPS dossier rev3 expansion
- [ ] Phase 2 — Pattern F multi-shell + Pattern B nested + Pattern E comment + LeakIX UA
- [ ] Phase 3 — Pattern H detection (4 sub-signals)
- [ ] Phase 4 — Pattern I detection (4 sub-signals)
- [ ] Phase 5 — Forensic Pattern H/I bundle capture
- [ ] Phase 6 — Verification gate (per-phase + synthetic harness)
- [ ] Phase 7 — CDN deploy + live sha256 parity check
