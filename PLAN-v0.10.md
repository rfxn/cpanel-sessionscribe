# Plan — v1.7.0 ioc-scan + v0.11.0 forensic — lab host A deep-forensic findings: anti-forensic detection, access-log primitive, Pattern H/I, kill-chain timestamp fix

> **Status: IN-FLIGHT** (2026-05-02). Source: live forensic re-triage of
> `lab host A` (the COMPROMISED canary host whose previous
> divergence drove v1.6.0).
>
> **Drift since plan-write (2 commits landed during draft):**
> - `652e30d` ioc-scan **v1.7.0**: Pattern H + Pattern I — supersedes P4 + P5.
>   Their impl is more thorough than my plan (walks `/var/cpanel/userdata/*/main`,
>   adds I4 failed-chmod from `/var/log/secure`, uses hoisted `HISTORY_FILES_GLOB`).
> - `703d042` forensic **v0.10.1**: Pattern H/I bundle capture — already wired.
>
> **Effective targets bumped:** ioc-scan **v1.8.0**, forensic **v0.11.0**,
> mitigate **v0.4.0**. Remaining patches: P1, P2, P3, P6, P7, P8, P9, P10.

## Why

Re-running `--chain-on-critical` on lab host A produced a structurally
correct verdict (COMPROMISED, score 287) but a **decapitated kill
chain**. The visualization showed Pattern A (destruction) at
2026-04-30T16:41:24Z and labeled Pattern E + Pattern F as
"POST-PARTIAL" (after defenses). Both labels are wrong: the operators
exploited at **2026-04-30T08:41:18Z**, ran Pattern F harvester at
**09:21:30Z**, and the destruction operator returned with a **24×200
websocket Shell** at 16:41:03 — 18 seconds before encryption began.
Stages 1–3 of the dossier kill chain were entirely absent from the
chart even though the access-log evidence is intact.

Two structural failures:

1. **Pattern F timestamp source uses file mtime** instead of parsing
   the `#<epoch>` markers bash writes inside `.bash_history` when
   timestamps are enabled — so any subsequent shell session bumps the
   mtime and pushes the harvester signal into POST-PARTIAL.
2. **No access-log fingerprint for the CRLF auth-bypass primitive
   itself.** Detection only checks session files. `mitigate.sh`
   quarantines forged sessions, so on any host where defenses ran the
   primitive is invisible to the scanner — exactly the case here.

A third gap — silent and dangerous — surfaced during the dig:
**Pattern A's encryptor specifically targets forensic evidence.**
829 `.sorry` files under `/var/log` and `/var/cpanel` on lab host A,
including `accounting.log` (Pattern D evidence), the day-of
`traffic-apache.log.gz`, every `imunify360/*.log`, every
`apache2/archive/access_log-*.gz`, and every `ConsoleKit/history-*`.
The current scanner reads `/var/cpanel/accounting.log` with no fallback
to `.sorry`, so Pattern D fails silently to detect — and the host
gets no signal that the attacker actively destroyed evidence.

This release closes those three gaps, adds Pattern H + Pattern I
(currently uncovered in the scanner), adds the new attacker IPs and
24×200 websocket dimension to the dossier, and tightens Pattern E to
break out per-dimension counts so future operators are flagged the
moment they appear.

---

## Findings (lab host A deep dig, 2026-05-02)

### 1. Reconstructed kill chain (the real one)

| Time (UTC) | IP / actor | Action |
|---|---|---|
| 2026-04-30T00:39:30 | `80.75.212.14` (DigitalOcean) | **Scout** — `GET /` + `GET /login/?login_only=1`, mixed UA (Mozilla browser then Go-http-client/1.1, same second). Not currently a detected primitive. |
| 2026-04-30T08:41:18 | `206.189.227.202` | **CVE-2026-41940 lands** — `POST /login/?login_only=1 → 401`, then immediately `GET /cpsess2456947117/json-api/version → 200` as `- root`. Full Pattern D recon (`version`, `gethostname`, `listaccts`, `getdiskusage`, `systemloadavg`). Drops 24×80 websocket Shell (18 frames over 21s). |
| 2026-04-30T08:44:58 | `159.223.155.255` | Same exploit chain, cpsess8822061745, 24×80. |
| 2026-04-30T08:56:08 | `67.205.134.215` | Same exploit chain, cpsess2228771146, 24×80. |
| 2026-04-30T09:21:30 | (root, via Shell) | Pattern F `__S_MARK__` harvester sweep. Epoch `1777538490` is in `.bash_history` adjacent to the `__S_MARK__` line — **today's scanner ignores it**. |
| **2026-04-30T16:41:03** | **`136.244.66.225`** | **Final operator** — exploit again, cpsess7972022126, **24×200 websocket Shell** (Go-http-client/1.1). New dimension not in PATTERNS.md. |
| 2026-04-30T16:41:24 (+18s) | (root) | Pattern A `.sorry` encryption begins — mass `README.md` drops + targeted log encryption. |
| 2026-04-30T23:48:21 | (defender) | `sessionscribe-mitigate.sh` first run — too late by 7h7m. |

### 2. Anti-forensic encryption inventory (lab host A)

`find /var/log /var/cpanel -name '*.sorry'` returns **829 files**.
Manually reviewed targeting:

- `/var/cpanel/accounting.log.sorry` ← Pattern D evidence
- `/var/log/cpanel-server-traffic/web/2026-04-30-traffic-apache.log.gz.sorry` ← day-of apache traffic
- `/var/log/imunify360/{error,acronis-installer,clamav-purge,console.log.1.gz}.sorry` ← AV/IDS forensic trail
- `/var/log/apache2/archive/access_log-*.gz.sorry` (multiple years)
- `/var/log/ConsoleKit/history-*.gz.sorry` (multiple months)
- `/var/log/{boot,anaconda.yum,tuned/tuned}.log.sorry` ← system trace

The targeting is not random — it's a deliberate forensic-evidence
sweep. Detecting it is itself a strong signal of Pattern A even when
the encryptor binary, README, and `.sorry` files in `/home` have all
been cleaned.

### 3. New IOCs (not in current PATTERNS.md tracker)

- **5 new attacker IPs (DigitalOcean ranges):**
  `80.75.212.14`, `206.189.227.202`, `159.223.155.255`,
  `67.205.134.215`, `136.244.66.225`
- **New websocket Shell dimension: 24×200** (Pattern E variant,
  Go-http-client/1.1 UA, destruction-operator on lab host A). Brings
  known-dimension set to {24×80, 24×120, 24×134, 24×200}.
- **Exploit-handoff burst signature:** 3 distinct DigitalOcean IPs
  CRLF-bypassing the same host within a 15-minute window (08:41 →
  08:56), each minting its own cpsess token, then 8h dwell, then
  return-to-destruction by a 4th operator. Pattern E currently emits
  one aggregated count; the handoff burst is its own kill-chain stage
  worth surfacing.
- **Deterministic CRLF-bypass access-log primitive:** within ≤2s,
  same source IP — `POST /login/?login_only=1 → 401` immediately
  followed by `GET /cpsess<N>/<anything> → 2xx` with the user slot
  populated as `- root`. This is the single most reliable second-source
  signal that survives session-file purging.

### 4. Verified clean on lab host A (negative findings worth recording)

- **Pattern D persistence absent** — `/var/cpanel/users/` has no
  `sptadm`, `/var/cpanel/resellers` empty, no WHM_FullRoot token.
  Operator chose direct destruction over reseller persistence here.
  *Caveat:* `accounting.log.sorry` means the createacct/setacls calls
  could have been issued and the evidence then encrypted; needs a
  cross-verification primitive (see §5).
- **Pattern G clean** — single legit `W9Z2DL` ssh-rsa key, mtime
  Jul 25 2024, no IP-labeled keys, no forged 2019-12-13 mtime.
- **Pattern I clean** — `/etc/profile.d/system_profiled_service.sh`
  not present, `/root/.local/bin/` does not exist, `system-service`
  not in process list.
- **No Pattern H** — no `seobot.php`, no `ALLDONE` in any history.

### 5. Scanner self-audit (gaps confirmed by code-read of v1.6.7)

| # | Location | Bug / gap |
|---|---|---|
| G1 | `check_destruction_iocs()` line 1985 (Pattern F) | `f_mtime=$(stat -c %Y "$f_hit")` — uses bash_history file mtime. Misses bash's embedded `#<epoch>\n<command>` markers. Result: any subsequent shell session reorders Pattern F into POST-PARTIAL. |
| G2 | `check_destruction_iocs()` line 1937 (Pattern D) | `acct_log=/var/cpanel/accounting.log` — no `.sorry` fallback. Encrypted-evidence path silently misses Pattern D entirely. |
| G3 | `check_destruction_iocs()` Pattern A block | Only checks the encryptor binary, README, in-place `.sorry` files under `/home` and `/var/www`, and live C2 socket. Does not flag the **anti-forensic log-targeting** subroutine — strongest residual signal once `/home` has been cleaned by restore. |
| G4 | `check_destruction_iocs()` whole-function | **No Pattern H block.** No grep for `seobot.php` in docroots; no `ALLDONE` / `pkill -9 nuclear.x86 kswapd01 xmrig` / base64 zip header `UEsDBBQACAAIAMhEkVw` history-file scan. |
| G5 | `check_destruction_iocs()` whole-function | **No Pattern I block.** No `/etc/profile.d/system_profiled_service.sh` check, no `/root/.local/bin/system-service` check, no `pgrep -x system-service`. |
| G6 | `check_logs()` / `check_attacker_ips()` | No CRLF-bypass access-log primitive: `POST /login/?login_only=1 → 401` immediately followed by `GET /cpsess<N>/* → 2xx` from same IP within 2s, user slot `- root`. |
| G7 | `check_destruction_iocs()` Pattern E block (line 2074) | All `/cpsess*/websocket/Shell` hits aggregated into one count. Per-dimension breakout (24×80 vs 24×120 vs 24×134 vs 24×200) would catch new operators day-zero. |
| G8 | `check_destruction_iocs()` Pattern E | No "rapid handoff" detection: ≥2 distinct external IPs each minting a cpsess token within a short window. The exploit-burst signature on lab host A (3 ops in 15 min) currently emits as 3 indistinguishable signals. |
| G9 | `check_destruction_iocs()` Pattern D `getent passwd` | The dossier creates `sptadm` via WHM `createacct`, which writes to `/var/cpanel/users/sptadm`, not necessarily `/etc/passwd` (cPanel uses passwd-shadow split; passwd entry may be `/sbin/nologin` or absent depending on tier). Better second source: `[[ -f "/var/cpanel/users/$PATTERN_D_RESELLER" ]]`. |
| G10 | `check_destruction_iocs()` Pattern G | OK on lab host A; non-bug. No change needed. |

---

## Patches

Each patch is presented as a self-contained diff against the
referenced line. Bash floor: CL6 / bash 4.1.2 — no `mapfile`,
no `printf -v` array indexing, no `${var^^}`, no `coproc`. All new
arrays are guarded with `(( ${#arr[@]} > 0 ))` before iteration
(matches the existing pattern at line 1794).

### P1 — Pattern F: parse `#<epoch>` markers in `.bash_history`

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** lines 1983–1996 (Pattern F block)

Replace the simple `grep -lF` + `stat -c %Y` with a two-pass: identify
file, then awk-parse the embedded epoch marker that precedes the
`__S_MARK__` line.

```bash
# ---- Pattern F: __S_MARK__ harvester envelope -----------------------
# bash writes `#<epoch>\n<command>` lines into history when histappend +
# HISTTIMEFORMAT are enabled (CL6 default for root). Use the embedded
# epoch as ts_epoch_first when present; fall back to file mtime so we
# don't lose the signal on hosts with HISTTIMEFORMAT disabled.
local f_hit="" f_mtime=0 f_smark_epoch=0
f_hit=$(grep -lF "$PATTERN_F_S_MARK" \
            /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
if [[ -n "$f_hit" ]]; then
    f_mtime=$(stat -c %Y "$f_hit" 2>/dev/null)
    f_smark_epoch=$(awk -v mark="$PATTERN_F_S_MARK" '
        /^#[0-9]{9,11}$/ { last=substr($0,2); next }
        index($0, mark) { if (last != "") { print last; exit } }
    ' "$f_hit" 2>/dev/null)
    f_smark_epoch="${f_smark_epoch:-0}"
    emit "destruction" "ioc_pattern_f_harvester" "strong" \
         "ioc_pattern_f_smark_envelope" 10 \
         "sample_path" "$f_hit" \
         "ts_epoch_first" "$f_smark_epoch" \
         "mtime_epoch" "${f_mtime:-0}" \
         "note" "$PATTERN_F_S_MARK / $PATTERN_F_E_MARK harvester envelope in $f_hit - automated post-exploit recon (CRITICAL)."
    ((hits++))
fi
```

**Forensic-side change:** none. `ioc_signal_epoch()` already prefers
`ts_epoch_first` over `mtime_epoch` (forensic.sh line 927). The fix
is end-to-end with no consumer change.

### P2 — Pattern A: anti-forensic log-targeting detection

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** new block inside `check_destruction_iocs()`, immediately
after the existing live-C2 socket check (after line 1818).

```bash
# Pattern A anti-forensic subroutine: the .sorry encryptor walks
# /var/log and /var/cpanel encrypting forensic-evidence files
# (accounting.log, day-of traffic-apache, imunify360 trail, apache
# archives, ConsoleKit history). Detection: count .sorry files under
# the forensic-evidence roots. >=10 = strong signal that evidence was
# targeted; <10 with /var/cpanel/accounting.log.sorry present is a
# warning (small footprint or partial run).
local fe_count=0 fe_acct=0 fe_sample=""
if [[ -d /var/log ]]; then
    fe_count=$(find /var/log /var/cpanel -maxdepth 6 -name '*.sorry' \
                  -not -path '*/imunify360/cache/*' 2>/dev/null | wc -l)
    fe_count="${fe_count:-0}"
    fe_count="${fe_count// /}"
fi
[[ -f /var/cpanel/accounting.log.sorry ]] && fe_acct=1
fe_sample=$(find /var/log /var/cpanel -maxdepth 6 -name '*.sorry' 2>/dev/null | head -1)
if (( fe_count >= 10 )) || (( fe_acct == 1 )); then
    local fe_sev="strong" fe_weight=10
    (( fe_count < 10 && fe_acct == 1 )) && { fe_sev="warning"; fe_weight=5; }
    local fe_mtime=0
    [[ -n "$fe_sample" ]] && fe_mtime=$(stat -c %Y "$fe_sample" 2>/dev/null)
    emit "destruction" "ioc_pattern_a_evidence_destruction" "$fe_sev" \
         "ioc_pattern_a_evidence_targeted" "$fe_weight" \
         "count" "$fe_count" "acct_log_encrypted" "$fe_acct" \
         "sample_path" "${fe_sample:-(none)}" \
         "mtime_epoch" "${fe_mtime:-0}" \
         "note" "${fe_count} .sorry-encrypted file(s) under /var/log + /var/cpanel; accounting.log encrypted=${fe_acct}. Pattern A targeted forensic evidence - upstream Pattern D/E/F detection may silently miss (CRITICAL when count>=10)."
    ((hits++))
fi
```

### P3 — Pattern D: `.sorry` fallback + `/var/cpanel/users/` second source

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** lines 1934–1981 (Pattern D block)

Two changes: (a) try `accounting.log.sorry` and emit an evidence-
destruction caveat if found; (b) check `/var/cpanel/users/sptadm` as
a second source for reseller presence (passwd-shadow split tolerant).

```bash
# ---- Pattern D: sptadm reseller / WHM_FullRoot persistence ----------
# accounting.log: try both live and .sorry-encrypted paths. If only
# .sorry exists, emit a Pattern D-suppressed advisory because the
# evidence was targeted by Pattern A.
local acct_log=/var/cpanel/accounting.log
local acct_log_sorry=/var/cpanel/accounting.log.sorry
local acct_target="" acct_destroyed=0
if   [[ -f "$acct_log"        ]]; then acct_target="$acct_log"
elif [[ -f "$acct_log_sorry"  ]]; then acct_target="$acct_log_sorry"; acct_destroyed=1
fi
if (( acct_destroyed )); then
    emit "destruction" "ioc_pattern_d_evidence_destroyed" "warning" \
         "ioc_pattern_d_acctlog_encrypted" 5 \
         "path" "$acct_target" \
         "note" "Pattern D evidence file $acct_target encrypted by Pattern A; reseller-persistence cannot be ruled in or out from this file. Verify via /var/cpanel/users/."
    ((hits++))
fi
if [[ -n "$acct_target" && acct_destroyed -eq 0 ]]; then
    local d_pat="${PATTERN_D_RESELLER}|${PATTERN_D_DOMAIN}|${PATTERN_D_EMAIL}|${PATTERN_D_TOKEN_NAME}"
    local d_count d_sample
    d_count=$(grep -cE "$d_pat" "$acct_target" 2>/dev/null)
    d_count="${d_count:-0}"
    if (( d_count > 0 )); then
        local acct_mtime
        acct_mtime=$(stat -c %Y "$acct_target" 2>/dev/null)
        d_sample=$(grep -E "$d_pat" "$acct_target" 2>/dev/null | head -1)
        emit "destruction" "ioc_pattern_d_acctlog" "strong" \
             "ioc_pattern_d_reseller_persistence" 10 \
             "count" "$d_count" "sample" "${d_sample:0:200}" \
             "mtime_epoch" "${acct_mtime:-0}" \
             "note" "Pattern D persistence fingerprint in $acct_target ($d_count hits) - reseller/API token created post-exploit; revoke before clearing."
        ((hits++))
    fi
fi
# Reseller account presence: prefer /var/cpanel/users/<name> (cpanel's
# canonical record) over getent passwd. The dossier-known sptadm is
# created via createacct which writes /var/cpanel/users/sptadm before
# any /etc/passwd row materializes (and on some tiers the shell is
# /sbin/nologin so getent returns the entry but it's not interactive).
local d_userfile="/var/cpanel/users/$PATTERN_D_RESELLER"
if [[ -f "$d_userfile" ]]; then
    local d_mtime
    d_mtime=$(stat -c %Y "$d_userfile" 2>/dev/null)
    emit "destruction" "ioc_pattern_d_reseller" "strong" \
         "ioc_pattern_d_reseller_user_present" 10 \
         "user" "$PATTERN_D_RESELLER" "path" "$d_userfile" \
         "mtime_epoch" "${d_mtime:-0}" \
         "note" "cPanel user record '$d_userfile' present - attacker reseller (CRITICAL)."
    ((hits++))
elif command -v getent >/dev/null 2>&1 \
     && getent passwd "$PATTERN_D_RESELLER" >/dev/null 2>&1; then
    # Fallback if /var/cpanel/users somehow missing.
    emit "destruction" "ioc_pattern_d_reseller" "strong" \
         "ioc_pattern_d_reseller_user_present" 10 \
         "user" "$PATTERN_D_RESELLER" \
         "note" "user '$PATTERN_D_RESELLER' present in passwd - attacker reseller (CRITICAL)."
    ((hits++))
fi
# WHM_FullRoot token cache (unchanged).
local token_cache=/var/cpanel/whm/api-tokens.cache
if [[ -f "$token_cache" ]]; then
    if grep -qF "\"$PATTERN_D_TOKEN_NAME\"" "$token_cache" 2>/dev/null; then
        local token_mtime
        token_mtime=$(stat -c %Y "$token_cache" 2>/dev/null)
        emit "destruction" "ioc_pattern_d_token" "strong" \
             "ioc_pattern_d_whm_fullroot_token_present" 10 \
             "path" "$token_cache" \
             "mtime_epoch" "${token_mtime:-0}" \
             "note" "WHM_FullRoot api token present in $token_cache - revoke immediately (CRITICAL)."
        ((hits++))
    fi
fi
```

### P4 — Pattern H: seobot detection

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** new constants block at line ~210 + new detection block in
`check_destruction_iocs()`.

Constants:

```bash
# Pattern H - seobot SEO defacement / per-site PHP webshell drop. The
# dropper iterates /var/cpanel/users and unzips a base64-decoded zip
# into every documentroot. Distinctive markers:
#   - filename `seobot.php` in any docroot
#   - history string `ALLDONE` (operator console marker)
#   - history string `pkill -9 nuclear.x86 kswapd01 xmrig` (anti-rival)
#   - base64 zip header `UEsDBBQACAAIAMhEkVw` (specific to the payload)
PATTERN_H_DROPNAME="seobot.php"
PATTERN_H_HIST_ALLDONE="ALLDONE"
PATTERN_H_HIST_KILLRIVAL='pkill -9 nuclear.x86 kswapd01 xmrig'
PATTERN_H_BASE64_ZIP_HDR="UEsDBBQACAAIAMhEkVw"
```

Detection block (insert after Pattern G, before Pattern E):

```bash
# ---- Pattern H: seobot SEO defacement / per-site PHP webshell ------
# Three independent signals; any one is strong.
local h_hits=0 h_sample=""
# (a) seobot.php in any /home/*/public_html docroot. Bounded find
#     under /home -maxdepth 5 -name seobot.php (php files only).
local h_seobot
h_seobot=$(find /home -maxdepth 5 -name "$PATTERN_H_DROPNAME" \
                -type f 2>/dev/null | head -1)
if [[ -n "$h_seobot" ]]; then
    local h_mtime
    h_mtime=$(stat -c %Y "$h_seobot" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_seobot_drop" "strong" \
         "ioc_pattern_h_seobot_php_present" 10 \
         "sample_path" "$h_seobot" \
         "mtime_epoch" "${h_mtime:-0}" \
         "note" "$PATTERN_H_DROPNAME PHP webshell present at $h_seobot - Pattern H per-site drop (CRITICAL)."
    ((hits++)); ((h_hits++))
fi
# (b) operator console marker in any history file. ALLDONE alone is
#     weak (legitimate ALLDONE strings exist in build scripts), so we
#     pair it with the kill-rival pkill string for high specificity.
local h_hist
h_hist=$(grep -lF "$PATTERN_H_HIST_KILLRIVAL" \
              /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
if [[ -n "$h_hist" ]]; then
    local h_hist_mtime h_hist_epoch=0
    h_hist_mtime=$(stat -c %Y "$h_hist" 2>/dev/null)
    h_hist_epoch=$(awk -v mark="$PATTERN_H_HIST_KILLRIVAL" '
        /^#[0-9]{9,11}$/ { last=substr($0,2); next }
        index($0, mark) { if (last != "") { print last; exit } }
    ' "$h_hist" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_seobot_history" "strong" \
         "ioc_pattern_h_killrival_history" 10 \
         "sample_path" "$h_hist" \
         "ts_epoch_first" "${h_hist_epoch:-0}" \
         "mtime_epoch" "${h_hist_mtime:-0}" \
         "note" "Pattern H kill-rival pkill string in $h_hist - operator killed nuclear.x86/kswapd01/xmrig before deploying seobot (CRITICAL)."
    ((hits++)); ((h_hits++))
fi
# (c) base64 zip header in any /tmp dropfile (caught early before
#     self-clean) or any history file (the dropper echoes it inline).
local h_b64
h_b64=$(grep -lF "$PATTERN_H_BASE64_ZIP_HDR" \
             /root/.bash_history /home/*/.bash_history \
             /tmp/*.zip /tmp/seobot.zip 2>/dev/null | head -1)
if [[ -n "$h_b64" ]]; then
    local h_b64_mtime
    h_b64_mtime=$(stat -c %Y "$h_b64" 2>/dev/null)
    emit "destruction" "ioc_pattern_h_seobot_payload" "strong" \
         "ioc_pattern_h_base64_zip_present" 10 \
         "sample_path" "$h_b64" \
         "mtime_epoch" "${h_b64_mtime:-0}" \
         "note" "Pattern H base64 zip header (UEsDBBQACAAIAMhEkVw) in $h_b64 - identifies the seobot payload (CRITICAL)."
    ((hits++)); ((h_hits++))
fi
```

### P5 — Pattern I: system-service profile.d backdoor

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** new constants + new block in `check_destruction_iocs()`.

Constants (append after Pattern H):

```bash
# Pattern I - system-service profile.d persistence backdoor
# (parallel cohort lateral from bastion, not direct CVE vector). Triggers on
# every interactive shell login. Hyper Global cohort to date but
# fleet-wide hunting signature is the exact filename.
PATTERN_I_PROFILED="/etc/profile.d/system_profiled_service.sh"
PATTERN_I_BIN="/root/.local/bin/system-service"
PATTERN_I_PROCNAME="system-service"
```

Detection block:

```bash
# ---- Pattern I: system-service profile.d backdoor ------------------
# Three independent signals; any one is strong.
if [[ -f "$PATTERN_I_PROFILED" ]]; then
    local i_mtime i_ctime
    i_mtime=$(stat -c %Y "$PATTERN_I_PROFILED" 2>/dev/null)
    i_ctime=$(stat -c %Z "$PATTERN_I_PROFILED" 2>/dev/null)
    emit "destruction" "ioc_pattern_i_profiled" "strong" \
         "ioc_pattern_i_profiled_dropfile" 10 \
         "path" "$PATTERN_I_PROFILED" \
         "mtime_epoch" "${i_mtime:-0}" \
         "ctime_epoch" "${i_ctime:-0}" \
         "note" "Pattern I profile.d backdoor at $PATTERN_I_PROFILED - persists via every shell login (CRITICAL)."
    ((hits++))
fi
if [[ -f "$PATTERN_I_BIN" ]]; then
    local i_bin_sha=""
    if command -v sha256sum >/dev/null 2>&1; then
        i_bin_sha=$(sha256sum "$PATTERN_I_BIN" 2>/dev/null | awk '{print $1}')
    fi
    local i_bin_mtime
    i_bin_mtime=$(stat -c %Y "$PATTERN_I_BIN" 2>/dev/null)
    emit "destruction" "ioc_pattern_i_binary" "strong" \
         "ioc_pattern_i_binary_present" 10 \
         "path" "$PATTERN_I_BIN" "sha256" "${i_bin_sha:-unknown}" \
         "mtime_epoch" "${i_bin_mtime:-0}" \
         "note" "Pattern I binary at $PATTERN_I_BIN - capture hash + binary before quarantine (CRITICAL)."
    ((hits++))
fi
if command -v pgrep >/dev/null 2>&1; then
    if pgrep -x "$PATTERN_I_PROCNAME" >/dev/null 2>&1; then
        local i_pid
        i_pid=$(pgrep -x "$PATTERN_I_PROCNAME" 2>/dev/null | head -1)
        emit "destruction" "ioc_pattern_i_process" "strong" \
             "ioc_pattern_i_process_running" 10 \
             "process" "$PATTERN_I_PROCNAME" "pid" "${i_pid:-?}" \
             "note" "Pattern I process '$PATTERN_I_PROCNAME' running (pid=${i_pid:-?}) - active beacon (CRITICAL)."
        ((hits++))
    fi
fi
```

### P6 — CRLF-bypass access-log primitive

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** new function called from the main flow alongside
`check_logs` / `check_attacker_ips` (line 2845–2848 area).

This is the single highest-value new primitive: it's deterministic
(401 followed by 2xx as `- root` from same IP within ≤2s is not
something a legitimate cpanel client does), survives mitigate
purging the session file, and works on any host where the access
log is intact (i.e. before Pattern A's anti-forensic sweep).

```bash
# ---- CRLF auth-bypass primitive in access_log -----------------------
# Deterministic CVE-2026-41940 fingerprint: a `POST /login/?login_only=1`
# returning 401, immediately followed (≤2s, same source IP) by a
# `GET /cpsess<N>/<anything>` returning 2xx with the user slot
# populated as `root`. This is what a real exploit does when the
# CRLF-injected session forgery succeeds: cpsrvd rejects the POST
# at the HTTP layer (401) but the saveSession() side-effect has
# already minted the cpsess token, which the attacker then uses.
#
# The check is bounded to entries within $SINCE_DAYS of $TS_EPOCH
# (matches check_attacker_ips). Probe traffic excluded by UA filter.
check_crlf_access_primitive() {
    local log=/usr/local/cpanel/logs/access_log
    [[ -f "$log" ]] || { emit "logs" "crlf_access_primitive" "info" "log_missing" 0; return; }
    local since_epoch=$(( TS_EPOCH - SINCE_DAYS * 86400 ))
    local result
    result=$(grep -E '^[^ ]+ - (root|-) \[' "$log" 2>/dev/null \
        | grep -vE "$PROBE_UA_RE" \
        | awk -v since="$since_epoch" '
            BEGIN { hits=0; sample=""; ts_first=0 }
            function ts_of(s,    m, t) {
                if (match(s, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
                    return mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
                }
                return 0
            }
            {
                ip = $1; t = ts_of($0)
                if (t == 0 || t < since) next
                # 401 POST /login/?login_only=1
                if (match($0, /"POST \/login\/\?login_only=1[^"]*" 401 /)) {
                    last_post[ip] = t; next
                }
                # 2xx GET /cpsess<N>/* AS root within 2s of last_post[ip]
                if (match($0, /"GET \/cpsess[0-9]+\/[^"]*" 2[0-9][0-9] /) \
                    && $3 == "root" \
                    && (ip in last_post) \
                    && (t - last_post[ip]) <= 2) {
                    hits++
                    if (sample == "") sample = $0
                    if (ts_first == 0 || t < ts_first) ts_first = t
                    delete last_post[ip]   # consume; next 401 starts fresh
                }
            }
            END { printf "%d\t%d\t%s\n", hits, ts_first, sample }')
    local crlf_hits=0 crlf_ts_first=0 crlf_sample=""
    IFS=$'\t' read -r crlf_hits crlf_ts_first crlf_sample <<< "$result"
    crlf_hits="${crlf_hits:-0}"; crlf_ts_first="${crlf_ts_first:-0}"
    if (( crlf_hits > 0 )); then
        emit "logs" "ioc_cve_2026_41940_access_primitive" "strong" \
             "ioc_cve_2026_41940_crlf_access_chain" 10 \
             "count" "$crlf_hits" \
             "ts_epoch_first" "$crlf_ts_first" \
             "log_file" "$log" \
             "line" "${crlf_sample:0:240}" \
             "note" "$crlf_hits CRLF-bypass chain(s) in $log: POST /login → 401 then GET /cpsess<N>/* → 2xx as root within 2s. Deterministic CVE-2026-41940 exploitation evidence (CRITICAL)."
    fi
}
```

Wire into the main flow alongside the other access-log scanners.

### P7 — Pattern E: per-dimension breakout + handoff burst

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** lines 2095–2173 (Pattern E awk block)

Two extensions: (a) extract `rows×cols` from the URL and emit
per-dimension counts; flag any dimension not in the known set;
(b) cluster external-IP hits into time windows to detect rapid handoff
bursts (≥2 distinct external IPs each landing within a 15-minute
window).

Pseudo-diff (replacing the `awk` that backs `ws_result`):

```bash
ws_result=$(grep -E "$PATTERN_E_WS_RE" "$ws_log" 2>/dev/null \
               | grep -vE "$PROBE_UA_RE" \
               | EXCLUDES="$excludes_env" awk '
    BEGIN {
        n = split(ENVIRON["EXCLUDES"], ex_arr, "\n")
        for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
        # Known operator dimensions per IC-5790 dossier (rev 4)
        known["24x80"]=1; known["24x120"]=1; known["24x134"]=1; known["24x200"]=1
        ext_total=0; ext_2xx=0; int_2xx=0; int_other=0
        ext_sample=""; int_sample=""; ts_first_ext=0
        unknown_dim_count=0; unknown_dim_sample=""
    }
    function dim_of(s,    m) {
        if (match(s, /rows=([0-9]+)&cols=([0-9]+)/, m)) return m[1] "x" m[2]
        return ""
    }
    {
        ip=$1; if (ip in ex) next
        st="?"
        if (match($0, /" [0-9]+ /)) {
            s=substr($0, RSTART+2); split(s, ss, " "); st=ss[1]
        }
        ts=0
        if (match($0, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
            ts=mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
        }
        d=dim_of($0)
        is_internal=(ip ~ /^10\./ || ip ~ /^127\./ \
                    || ip ~ /^192\.168\./ \
                    || ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)
        if (is_internal) {
            if (st ~ /^2/) { int_2xx++; if (int_sample=="") int_sample=$0 }
            else int_other++
        } else {
            ext_total++
            if (st ~ /^2/) {
                ext_2xx++
                if (d != "") {
                    dim_count[d]++
                    if (!(d in known)) {
                        if (unknown_dim_sample=="") unknown_dim_sample=$0
                    }
                    # Handoff burst: ts → ip
                    burst_ts[ext_2xx]=ts; burst_ip[ext_2xx]=ip
                }
            }
            if (ext_sample=="") ext_sample=$0
            if (ts>0 && (ts_first_ext==0 || ts<ts_first_ext)) ts_first_ext=ts
        }
    }
    END {
        # Per-dimension breakout - serialized as `dim:count,dim:count,...`
        dim_csv=""
        for (d in dim_count) dim_csv = dim_csv (dim_csv==""?"":",") d ":" dim_count[d]
        # Unknown dims - any d in dim_count that is not in known
        unknown_csv=""
        for (d in dim_count) if (!(d in known)) unknown_csv = unknown_csv (unknown_csv==""?"":",") d
        # Handoff burst: count distinct IPs landing within any 900s window
        burst_max=0
        for (i=1; i<=ext_2xx; i++) {
            window_ips_n=0; delete window_ips
            for (j=1; j<=ext_2xx; j++) {
                if (burst_ts[j] >= burst_ts[i] && burst_ts[j] - burst_ts[i] <= 900) {
                    if (!(burst_ip[j] in window_ips)) {
                        window_ips[burst_ip[j]]=1; window_ips_n++
                    }
                }
            }
            if (window_ips_n > burst_max) burst_max=window_ips_n
        }
        printf "%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\n", \
               ext_total, ext_2xx, int_2xx, int_other, ts_first_ext, dim_csv, unknown_csv, burst_max
        print ext_sample
        print int_sample
    }')
```

Then, after the existing `if (( ext_2xx > 0 ))` emit, add:

```bash
# Per-dimension breakout (info-level: contextual for triage).
if [[ -n "$dim_csv" ]]; then
    emit "destruction" "ioc_pattern_e_dimensions" "info" \
         "ioc_pattern_e_dimension_breakout" 0 \
         "dimensions" "$dim_csv" \
         "note" "Pattern E websocket Shell dimensions seen: $dim_csv"
fi
# Unknown dimension - day-zero new operator detection.
if [[ -n "$unknown_csv" ]]; then
    emit "destruction" "ioc_pattern_e_unknown_dimension" "warning" \
         "ioc_pattern_e_dimension_unknown" 5 \
         "dimensions" "$unknown_csv" \
         "sample" "${unknown_dim_sample:0:200}" \
         "note" "Pattern E websocket Shell with dimension(s) $unknown_csv not in known set {24x80,24x120,24x134,24x200} - new operator? Update PATTERNS.md."
    ((hits++))
fi
# Handoff burst: ≥2 distinct external IPs each minting cpsess in
# a 15-minute window. Strong signal of exploit-toolkit chained operators.
if (( burst_max >= 2 )); then
    emit "destruction" "ioc_pattern_e_handoff_burst" "strong" \
         "ioc_pattern_e_handoff_burst_present" 8 \
         "ip_count" "$burst_max" \
         "note" "Pattern E exploit-handoff burst: $burst_max distinct external IPs each minted cpsess + reached websocket Shell within a 15-minute window. Multi-operator exploit chain (CRITICAL)."
    ((hits++))
fi
```

### P8 — New IPs into the dossier IP cross-ref

**File:** `sessionscribe-ioc-scan.sh`
**Surface:** the `IC5790_KNOWN_IPS` array (location: `check_attacker_ips`,
search for the array literal that includes the existing IPs).

Add the 5 new DigitalOcean IPs:

```
80.75.212.14
206.189.227.202
159.223.155.255
67.205.134.215
136.244.66.225
```

These are in addition to the existing `68.233.238.100`,
`206.189.2.13`, `137.184.77.0`, `38.146.25.154`, `157.245.204.205`,
`192.81.219.190`, `149.102.229.144`, `94.231.206.39`, `45.82.78.104`,
`68.183.190.253`, `87.121.84.78`, `96.30.39.236`, `68.47.28.118`,
`142.93.43.26`, `5.230.165.16`, `5.252.177.207`, `146.19.24.235`,
`183.82.160.147`, `89.34.18.59`. Total grows from 19 → 24.

### P9 — forensic v0.11.0: stage-letter expansion + dimension annotation

**File:** `sessionscribe-forensic.sh`
**Surface:** `ioc_key_to_pattern()` line 904–920 (already maps H + I,
verified). No change needed. **But** the kill-chain renderer
should annotate Pattern E rows with the dimension when the envelope
includes one. Surface: the renderer that emits the
`⚡ stage E ioc_pattern_e_websocket_shell_hits 45 external IP(s)…`
lines (search `stage E` or `pattern_e` in `phase_reconcile` /
`render_kill_chain`).

Pseudo-change: when an OFFENSE_EVENTS row's pattern is `E`, look up
the matching `IOC_PRIMITIVES` row, and if the envelope row carried a
`dimensions` field, append `(dim: 24x80, 24x200)` to the rendered
note. Also append `(handoff: 4 IPs in 12m)` when
`ioc_pattern_e_handoff_burst_present` is in the envelope.

### P10 — mitigate v0.4.0: anti-forensic-aware quarantine

**File:** `sessionscribe-mitigate.sh`

When `accounting.log.sorry` exists, mitigate should:

1. Skip the existing accounting-based Pattern D rule check (no signal
   recoverable from encrypted file).
2. Emit a warning to the operator that Pattern D evidence is
   destroyed and forensic must rely on `/var/cpanel/users/sptadm`
   second-source check.
3. Capture `accounting.log.sorry` to the quarantine sidecar with
   `.info` metadata so forensic can later note "accounting evidence
   destroyed at <ctime>" in the kill-chain.

This is light-touch: a new helper `note_evidence_destruction()`
called once at the start of mitigate's audit phase. Unchanged
otherwise.

---

## PATTERNS.md updates (rev 4)

Append the following sections. Source of truth for new IPs and the
24×200 dimension is lab host A deep dig 2026-05-02; companion log captures
in `/root/.ic5790-forensic/2026-05-02T01:11:04Z-1777684259-2600434/`.

### Pattern E expansion: new operator dimension 24×200

```
Four distinct operator dimensions confirmed:
  - 24×80  (192.81.219.190, Pattern E original)
  - 24×120 (149.102.229.144)
  - 24×134 (183.82.160.147; pre-disclosure DEC 2025)
  - 24×200 (136.244.66.225, Go-http-client/1.1 UA, NEW 2026-05-02)
The 24×200 operator landed at 16:41:03Z and triggered Pattern A
encryption 18 seconds later. Dossier hypothesis: distinct destruction
operator working on top of the recon-operator chain (24×80 from
206.189.227.202/159.223.155.255/67.205.134.215 over 15 minutes).
```

### Pattern A expansion: anti-forensic log targeting

```
The .sorry encryptor is not a blanket /home walk - it deliberately
targets forensic-evidence files. Confirmed targets on lab host A:
  - /var/cpanel/accounting.log         (Pattern D evidence)
  - /var/log/cpanel-server-traffic/web/<DAY-OF>-traffic-apache.log.gz
  - /var/log/imunify360/{error,acronis-installer,clamav-purge,console}.log
  - /var/log/apache2/archive/access_log-*.gz (multiple years)
  - /var/log/ConsoleKit/history-*.gz (multiple months)
  - /var/log/{boot,anaconda.yum,tuned/tuned}.log
lab host A inventory: 829 .sorry files under /var/log + /var/cpanel.
Detection: if accounting.log.sorry exists OR find /var/log
/var/cpanel -name '*.sorry' returns >=10, treat as standalone Pattern
A signal even when /home was restored or Pattern A binary cleaned.
```

### Reconstructed kill-chain on lab host A (canonical example)

(Insert the table from §1 above as "Pattern initial-access example #2"
alongside the existing rev-1 canonical example.)

### Source IPs — append to consolidated table

| IP | Role | UA | Source |
|---|---|---|---|
| 80.75.212.14 | scout (probe + recon) | mixed Mozilla + Go-http-client/1.1 | lab host A access_log 04/30 00:39 |
| 206.189.227.202 | CRLF exploit + Pattern D recon + 24×80 Shell | Go-http-client/1.1 | lab host A access_log 04/30 08:41 |
| 159.223.155.255 | CRLF exploit + 24×80 Shell | Go-http-client/1.1 | lab host A access_log 04/30 08:44 |
| 67.205.134.215 | CRLF exploit + 24×80 Shell | Go-http-client/1.1 | lab host A access_log 04/30 08:56 |
| 136.244.66.225 | destruction operator: CRLF exploit + 24×200 Shell, +18s → Pattern A | Go-http-client/1.1 | lab host A access_log 04/30 16:41 |

### Verification workflow addendum (post-2026-05-02)

```
For any host carrying accounting.log.sorry, do not rely on Pattern D
detection from the standard scanner; check /var/cpanel/users/sptadm
directly and grep /var/cpanel/whm/api-tokens.cache for WHM_FullRoot.
If the access_log is intact, the deterministic CRLF-bypass primitive
(P6) gives a second-source confirmation independent of session files.
```

---

## Test plan

All tests target the v1.7.0 / v0.11.0 candidate built from this plan.
Lab hosts: lab host A (`cpanel_client` tmux). Cross-verify on additional
lab hosts where shell access is available (see INTERNAL-NOTES.md for
the active customer-host roster).

### T1 — Pattern F timestamp fix

On lab host A:
1. Run `bash sessionscribe-ioc-scan.sh --since 14 --chain-on-critical`.
2. Open the kill-chain output. **Expected:** Pattern F row appears
   under PRE-DEFENSE with `2026-04-30T09:21:30Z`, not POST-PARTIAL.
3. Open the run envelope JSON. **Expected:** the
   `ioc_pattern_f_smark_envelope` signal carries
   `"ts_epoch_first":1777538490`.

### T2 — Anti-forensic Pattern A

On lab host A:
1. Run the scan. **Expected:** new
   `ioc_pattern_a_evidence_destruction` signal with
   `count >= 829`, `acct_log_encrypted=1`, severity `strong`.
2. Verify the verdict reasons line includes
   `ioc_pattern_a_evidence_targeted`.

### T3 — Pattern D fallback

On lab host A:
1. Run the scan. **Expected:** `ioc_pattern_d_evidence_destroyed`
   warning emit (because `accounting.log.sorry` exists).
2. **Expected absence:** no `ioc_pattern_d_acctlog` strong emit
   (because the live file is missing — correct, evidence destroyed).
3. **Expected absence:** no `ioc_pattern_d_reseller_user_present`
   (verified `/var/cpanel/users/sptadm` not present on lab host A).
4. On a synthetic host (or any reachable lab host), drop a
   fixture `/var/cpanel/users/sptadm` and re-run; **expected:**
   `ioc_pattern_d_reseller_user_present` strong emit.

### T4 — Pattern H

Build a synthetic host fixture: drop `/home/test/public_html/seobot.php`
+ append `pkill -9 nuclear.x86 kswapd01 xmrig\n` to
`/root/.bash_history`. **Expected:** all three Pattern H signals fire
(`ioc_pattern_h_seobot_php_present`, `ioc_pattern_h_killrival_history`,
and if base64 hdr present, `ioc_pattern_h_base64_zip_present`).

### T5 — Pattern I

Synthetic: write `/etc/profile.d/system_profiled_service.sh` matching
the dossier verbatim, `touch /root/.local/bin/system-service`, run
the scan. **Expected:** `ioc_pattern_i_profiled_dropfile` and
`ioc_pattern_i_binary_present` strong emits. (Process check
exercised separately on a host that actually has the running binary;
no synthetic for that.)

### T6 — CRLF access primitive

On lab host A (real access_log, post-attack):
1. Run the scan. **Expected:**
   `ioc_cve_2026_41940_crlf_access_chain` with `count >= 4` (the four
   exploit landings: 206.189.227.202, 159.223.155.255, 67.205.134.215,
   136.244.66.225).
2. **Expected absence:** no false positive on legitimate cpanel
   sessions (those POST `/login/` returning 200, or returning 401
   without follow-up cpsess token).
3. Inject a synthetic legitimate sequence: `POST /login/?login_only=1
   200` from a known-good operator IP — should NOT match the chain
   (because the gate is on 401-then-2xx).

### T7 — Pattern E dimension breakout + handoff burst

On lab host A:
1. Run the scan. **Expected:** new info emit
   `ioc_pattern_e_dimension_breakout` with
   `dimensions=24x80:N,24x200:M`.
2. **Expected:** new strong emit
   `ioc_pattern_e_handoff_burst_present` with
   `ip_count=4` (the four operators, all within the 15-min window
   from 08:41 → 08:56 + the 16:41 burst).
3. Synthetic: log a 24×500 hit; **expected:**
   `ioc_pattern_e_dimension_unknown` warning with `24x500`.

### T8 — End-to-end kill-chain

On lab host A, after all patches, run with `--chain-on-critical`. Compare
new rendered chain to the table in §1. **Expected:** every row in
the table appears in the chain with the correct stage letter and
timestamp; the headline shows the **08:41** first-IOC time, not
**16:41**.

### T9 — bash 4.1 floor

After implementing all patches, run on a CL6 (bash 4.1.2) host (any
of cp1/cp2/cp3 or a synthetic). **Expected:** no `unbound variable`,
no `bad substitution`, no `mapfile: command not found` errors.
Linter: `checkbashisms` if available, plus the workspace's existing
`bash 4.1 audit` rules in `/root/admin/work/proj/rdf/`.

### T10 — Backwards compatibility

Run forensic v0.10.0 (existing) against an envelope produced by the
new v1.7.0 ioc-scan. **Expected:** kill-chain renders without
errors. New signal keys (`ioc_pattern_a_evidence_targeted`,
`ioc_pattern_h_*`, `ioc_pattern_i_*`, `ioc_cve_2026_41940_*`) map
through `ioc_key_to_pattern()` to A / H / I / X respectively (X for
the access-log primitive — exploitation evidence, not a destruction
stage). Verify by code-read that `ioc_key_to_pattern()` already
handles `ioc_pattern_h_*` and `ioc_pattern_i_*` (it does; line 913–
914) and that `ioc_cve_2026_41940_*` falls into the X bucket via
the regex on line 916. **Expected pass without code change.**

Then run forensic v0.11.0 against an envelope produced by the
old v1.6.7 ioc-scan. **Expected:** kill-chain renders without
errors; new dimension annotation is silently absent (no field).

---

## Versioning + rollout

| Script | Current | Next | Reason |
|---|---|---|---|
| sessionscribe-ioc-scan.sh | 1.6.7 | **1.7.0** | New patterns (H, I, anti-forensic, CRLF primitive); breakout fields. Minor bump. |
| sessionscribe-forensic.sh | 0.10.0 | **0.11.0** | Renderer annotation; no envelope-contract change. Minor bump. |
| sessionscribe-mitigate.sh | 0.3.1 | **0.4.0** | Anti-forensic-aware audit phase. Minor bump. |
| PATTERNS.md | rev 3 | **rev 4** | New IPs, 24×200 dimension, anti-forensic subroutine, lab host A chain example. |
| STATE.md | (stale; lists 1.6.4/0.9.5) | refresh | Bring in line with v1.7.0 / v0.11.0 / v0.4.0 + CDN sha256 re-stamp. |

### CDN republish

After implementation + T1–T10 pass:
1. `git commit -m "ioc-scan v1.7.0 / forensic v0.11.0 / mitigate v0.4.0: …"`
2. Push to `main` on `rfxn/cpanel-sessionscribe`.
3. Run the documented CDN deploy workflow (see memory `reference_cdn_deploy.md`)
   to publish to `https://sh.rfxn.com/<script>.sh`.
4. Validate on a habs host: `curl -fsSL
   https://sh.rfxn.com/sessionscribe-ioc-scan.sh | bash -s -- --version`
   reports `1.7.0`.
5. Update STATE.md sha256 / LOC columns from the published CDN copy.

### LW comms

After CDN sync, ping the IC-5790 incident channel (named recipients
in INTERNAL-NOTES.md):
- New patterns added (H, I, anti-forensic).
- New IPs to push to CSF deny (the 5 lab host A DigitalOcean IPs).
- 24×200 dimension to add to PATTERNS.md (rev 4).
- Re-run ioc-scan v1.7.0 on every previously-flagged COMPROMISED
  host: hosts with `accounting.log.sorry` should now show the new
  evidence-destruction signal AND the CRLF-access primitive should
  resolve a true Stage 1 timestamp (today's verdict is correct but
  the kill-chain is decapitated — operators want the real start
  time for any post-incident analysis).

---

## Out of scope (defer to next plan)

- **Pattern A mass-encryption recovery** — out of scope for the IOC
  detector; that's a recovery pipeline. The dossier already says
  reimage is required for Pattern A.
- **Pre-disclosure exploitation timeline** — DEC 2025 24×134
  websocket Shell hit needs its own analysis; not blocking this
  release.
- **Hyper Global / IC-5794 lateral movement** — Pattern I is now
  detected, but the bastion-pivot vector is upstream of CVE-2026-41940
  and needs its own primitive (probably not in this codebase).
- **schema_version envelope field** — flagged in v0.9 plan; defer
  again. Forensic v0.11.0 still reads any v1.6.x or v1.7.x envelope;
  no contract break in this release.
- **Pre-exploit "scout" primitive** (mixed-UA same-second probes from
  the same IP) — interesting but high false-positive surface (every
  bot scanner does this). Logged for v1.8 with more host data.
