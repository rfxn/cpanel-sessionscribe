#!/bin/bash
#
##
# sessionscribe-forensic.sh v0.9.3
# (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
###############################################################################
# sessionscribe-forensic.sh
#
# Read-only kill-chain reconstruction for CVE-2026-41940 (SessionScribe) and
# the IC-5790 cohort. Companion to sessionscribe-mitigate.sh - this script
# never mutates state. Captures raw artifacts to a bundle, extracts
# timestamps for both DEFENSE activations and OFFENSE events, and reconciles
# the two so each compromise indicator is labeled PRE-DEFENSE, POST-DEFENSE,
# POST-PARTIAL, or UNDEFENDED.
#
# The reconciliation answers the question: "for each indicator of compromise
# we found on this host, was our mitigation present at the time?"
#
# Phases (all read-only):
#   defense    extract timestamps for every defense layer that landed:
#              cpanel patch, cpsrvd restart-after-patch, sessionscribe-
#              mitigate.sh runs, modsec rule 1500030/1500031 install,
#              CSF/APF cpsrvd port closures, proxysub enable, upcp logs
#   offense    extract timestamps for every observed compromise indicator:
#              session files (token_denied + badpass), pattern D reseller
#              persistence (sptadm + WHM_FullRoot tokens + 4ef72197.cpx.local),
#              pattern E websocket Shell + Fileman API harvest, pattern F
#              automated harvester shell fingerprint, pattern G SSH-key
#              persistence, pattern A .sorry encryptor + /root/sshd, pattern
#              B BTC index.html drop + /var/lib/mysql/mysql wipe, pattern C
#              nuclear.x86 references
#   reconcile  per-indicator: was the relevant defense active when the
#              indicator first appeared? Output: PRE-DEFENSE | POST-DEFENSE
#              | POST-PARTIAL | UNDEFENDED, plus the time delta
#   bundle     tarball of raw artifacts for offline analysis (sessions,
#              access logs, accounting log, cron, ssh keys, apache config,
#              modsec config, CSF config, bash history)
#
# Output:
#   default   ANSI sectioned report on stderr + JSONL on stdout
#   --jsonl   JSONL only on stdout (per-finding signals + timeline + verdict)
#   --json    single JSON envelope on stdout
#   --quiet   suppress sectioned report (auto-set by --jsonl/--json)
#
# Exit codes:
#   0  no indicators of compromise found
#   1  indicators found, all post-defense (defense was in place)
#   2  indicators found, ANY pre-defense (defense was not in place at time
#      of first compromise) - this is the high-attention case
#   3  tool error
#
# Fleet usage:
#   xargs -n1 -P64 -I'{}' ansible all -i '{},' -c local.liquid_web.lw_ssh \
#     -m script -a 'sessionscribe-forensic.sh --jsonl --bundle-dir /root/.ic5790-forensic'
#
# Common flags: --no-bundle (Pattern A hosts), --since DAYS (narrow IR
# window), --extra-logs DIR (point at expanded /usr/local/cpanel/logs/
# archive/*.tar.gz to scan log generations older than the rotation window).
#
# Safe to run on hosts marked "encrypted" in column N of the IC-5790 tracker
# only if you accept the risk of touching atime on artifacts. For Pattern A
# (.sorry) hosts, prefer --no-bundle to avoid stat'ing the encryptor.
###############################################################################
set -u

# Require bash 4.0+ (associative arrays). CloudLinux 6 ships bash 4.1.2,
# which is fine. Bash 3.x (RHEL5 / macOS-default) would fail later with
# cryptic `declare -A` errors; emit a clean message and bail instead.
if (( BASH_VERSINFO[0] < 4 )); then
    echo "sessionscribe-forensic: requires bash >= 4.0 (have ${BASH_VERSION:-unknown})" >&2
    exit 3
fi

VERSION="0.9.3"
INCIDENT_ID="IC-5790"

# Default capture window. CVE-2026-41940 was disclosed 2026-04-28; 90d covers
# any pre-disclosure 0-day exploitation back to early February 2026. Bounding
# to 90d keeps the scan + bundle tractable on busy hosts (typical retained
# log volume / session count fits well under 2 GB inside this window).
# Override with --since DAYS or --since all for unbounded.
DEFAULT_SINCE_DAYS=90

# Default bundle size budget (MB), enforced PER-TARBALL (not bundle-wide).
# Each tarball candidate set (sessions, access-logs, system-logs, cpanel-
# state, cpanel-users, persistence, defense-state) is sized via pre-flight
# `du` against this cap; oversize candidates are skipped individually with
# a warning and a per-candidate size emitted as a signal. The bundle dir
# total is the sum of accepted tarballs, typically 0.5-3 GB on a busy host
# inside the 90-day window. To bound the host-wide total instead of per-
# tarball, set --max-bundle-mb low (e.g. 256) so each tarball stays small.
DEFAULT_MAX_BUNDLE_MB=2048

# Default upload endpoint - the R-fx Networks forensic intake. PUT-only,
# token-authenticated, gzip-magic enforced. See:
#   https://github.com/rfxn/cpanel-sessionscribe#bundle-upload
INTAKE_DEFAULT_URL="https://intake.rfxn.com/"

# Convenience token for ad-hoc submissions to the public R-fx intake.
# This is intentionally embedded for one-shot IR use - the server enforces
# a per-token 1000-PUT cap so blast radius is bounded. For fleet-scale or
# recurring use, request your own token from R-fx Networks (proj@rfxn.com)
# and override via --upload-token TOKEN or RFXN_INTAKE_TOKEN env. Sharing
# this token across many hosts will exhaust it quickly; the server returns
# 401 token_expired once the quota is gone, until R-fx rotates the token.
# Upload is opt-in via --upload (NEVER on by default).
INTAKE_DEFAULT_TOKEN="cd88c9970c3176997c9671a2566fadc84904be0b73edd5e3b071452eade796e1"

# Vendor-published patched builds.
PATCHED_BUILDS_CPANEL=(
    "11.86.0.41"  "11.110.0.97"  "11.118.0.63"  "11.126.0.54"
    "11.130.0.19" "11.132.0.29"  "11.134.0.20"  "11.136.0.5"
)
PATCHED_BUILD_WPSQUARED="136.1.7"

# Tiers explicitly excluded from the vendor patch list. Hosts on these tiers
# have NO in-place fix and must be upgraded to a patched major series.
# Operationally distinct from "patched build available but not applied" - the
# response is upgrade/migrate, not upcp.
UNPATCHED_TIERS=(112 114 116 120 122 124 128)

# cpsrvd ports we expect to be closed on unpatched hosts.
CPSRVD_PORTS=(2082 2083 2086 2087 2095 2096)

# Patch artifact - this file changes when CVE-2026-41940 patch lands.
PATCH_CANARY_FILE="/usr/local/cpanel/Cpanel/Session/Load.pm"

# sessionscribe-mitigate.sh backup root.
MITIGATE_BACKUP_ROOT="/var/cpanel/sessionscribe-mitigation"

# modsec config drop paths. Order matters - first existing path wins.
# EA4 is the cPanel default (/etc/apache2/...); the /etc/httpd/ paths cover
# non-EA4 / vendor-relocated installs occasionally seen on hosts that pre-
# date EA4 conversion or that run a side-by-side Apache.
MODSEC_USER_CONFS=(
    "/etc/apache2/conf.d/modsec/modsec2.user.conf"   # EA4 (cPanel default)
    "/etc/httpd/conf.d/modsec/modsec2.user.conf"     # non-EA4 fallback
    "/etc/httpd/conf.d/modsec2.user.conf"            # legacy non-EA4
)
# Resolved at runtime in phase_defense; defaults to first entry so the
# "absent" message references the canonical EA4 location.
MODSEC_USER_CONF="${MODSEC_USER_CONFS[0]}"

# Pattern A encryptor binary - bundled in raw artifacts when present.
# (All other Pattern A/B/C/D/F constants moved to ioc-scan; this script
# consumes their detection results via the run envelope.)
PATTERN_A_BINARY="/root/sshd"

# Pattern G - SSH key persistence anchors. Comments matching these literal
# IP labels are attacker-planted jumphost-mimic keys.
PATTERN_G_BAD_KEY_LABELS=(
    "209.59.141.49"
    "50.28.104.57"
)
# Forged mtime stamp the attackers used (`touch -d "2019-12-13 12:59:16"`).
# date(1) interprets in local TZ so the stored epoch depends on host offset;
# pattern_g_deep_checks compares the wall-clock string under both UTC and
# localtime to catch either interpretation.
PATTERN_G_FORGED_MTIME_WALL="2019-12-13 12:59:16"

# Known-good SSH key comments from legitimate LW/Nexcess provisioning -
# anything else in authorized_keys becomes a Pattern G candidate for review.
SSH_KNOWN_GOOD_RE='(lwadmin|lw-admin|liquidweb|nexcess|Parent Child key for [A-Z0-9]{6})'

###############################################################################
# Argument parsing
###############################################################################

JSON_OUT=0
JSONL_OUT=0
QUIET=0
NO_COLOR_FLAG=0
DO_BUNDLE=1
BUNDLE_DIR_ROOT="/root/.ic5790-forensic"
OUTPUT_FILE=""
INCLUDE_HOMEDIR_HISTORY=1
EXTRA_LOGS_DIR=""
SINCE_DAYS="$DEFAULT_SINCE_DAYS"
SINCE_EPOCH=""
MAX_BUNDLE_MB="$DEFAULT_MAX_BUNDLE_MB"
NO_LOGS=0
DO_UPLOAD=0
INTAKE_URL="$INTAKE_DEFAULT_URL"
INTAKE_TOKEN=""

usage() {
    cat <<EOF
sessionscribe-forensic.sh v${VERSION}

Read-only kill-chain reconstruction for CVE-2026-41940 (IC-5790).

USAGE
  sessionscribe-forensic.sh [OUTPUT] [BUNDLE] [MISC]

OUTPUT
  (default)         ANSI report on stderr + JSONL on stdout
  --jsonl           JSONL only on stdout
  --json            Single JSON envelope on stdout
  --quiet           Suppress sectioned report
  -o, --output FILE Write final JSON envelope to FILE

BUNDLE
  --bundle             Capture artifact tarball (default)
  --no-bundle          Skip artifact tarball (recommended on Pattern A hosts)
  --bundle-dir DIR     Root for bundle output
                       (default: $BUNDLE_DIR_ROOT)
  --max-bundle-mb N    Cap bundle size in MB. Pre-flight \`du\` runs per
                       candidate set; oversize sets are skipped with a
                       warning. (default: $DEFAULT_MAX_BUNDLE_MB MB / 2 GB).
                       Use 0 for no cap.
  --no-history         Skip /home/*/.bash_history capture (privacy)

LOGS / TIME WINDOW
  --no-logs            Skip ALL access-log scans (Pattern E websocket/Fileman,
                       Pattern D recon/bad-UA/bad-IP). Sessions, persistence,
                       Pattern A/B/C/F/G checks still run. Useful on hosts
                       where access-log volume is huge and the operator
                       only needs session+persistence verdicts.
  --extra-logs DIR     Additional access-log directory to scan (e.g. point
                       at an expanded /usr/local/cpanel/logs/archive/*.tar.gz
                       to include rotated logs from older incident windows).
  --since DAYS         Limit log + session-file scans + bundle to last N
                       days. Default: $DEFAULT_SINCE_DAYS days (covers any pre-disclosure
                       exploitation since CVE-2026-41940 was released).
  --since all          Disable the time window - scan every retained
                       session and access-log, no upper bound on bundle.

UPLOAD (off by default - explicit opt-in)
  --upload             Submit the bundle to the R-fx forensic intake after
                       capture. Off by default. Requires --bundle (the
                       default). Single PUT of an outer .tgz archive of
                       the bundle dir; server returns 201 + JSON with the
                       stored filename, sha256, and remaining_uses.
  --upload-url URL     Override intake URL.
                       (default: $INTAKE_DEFAULT_URL)
  --upload-token TOKEN Override token. Resolution order:
                         1. --upload-token TOKEN (CLI flag)
                         2. \$RFXN_INTAKE_TOKEN (environment)
                         3. built-in convenience token (limited use:
                            server enforces a 1000-PUT cap per token;
                            for ongoing fleet use, request your own
                            token from R-fx Networks <proj@rfxn.com>).

MISC
  --no-color        Disable ANSI color (NO_COLOR=1 also honored)
  -h, --help        Show this help

EXIT CODES
  0  no IOCs found
  1  IOCs found, all post-defense
  2  IOCs found, at least one pre-defense (defense was missing)
  3  tool error
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)         JSON_OUT=1; JSONL_OUT=0; shift ;;
        --jsonl)        JSONL_OUT=1; JSON_OUT=0; shift ;;
        --quiet)        QUIET=1; shift ;;
        --no-color)     NO_COLOR_FLAG=1; shift ;;
        --bundle)       DO_BUNDLE=1; shift ;;
        --no-bundle)    DO_BUNDLE=0; shift ;;
        --bundle-dir)   BUNDLE_DIR_ROOT="$2"; shift 2 ;;
        --upload)       DO_UPLOAD=1; shift ;;
        --upload-url)   INTAKE_URL="$2"; shift 2 ;;
        --upload-token) INTAKE_TOKEN="$2"; shift 2 ;;
        --no-history)   INCLUDE_HOMEDIR_HISTORY=0; shift ;;
        --no-logs)      NO_LOGS=1; shift ;;
        --extra-logs)   EXTRA_LOGS_DIR="$2"; shift 2 ;;
        --since)        SINCE_DAYS="$2"; shift 2 ;;
        --max-bundle-mb) MAX_BUNDLE_MB="$2"; shift 2 ;;
        -o|--output)    OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1" >&2; exit 3 ;;
    esac
done

(( JSONL_OUT )) && QUIET=1

# Validate and resolve --since to an absolute epoch. Accepts:
#   N        - positive integer days (the default is DEFAULT_SINCE_DAYS)
#   0|all|none|"" - disable the window (scan everything retained on disk)
case "${SINCE_DAYS,,}" in
    ""|0|all|none|unlimited)
        SINCE_DAYS=""; SINCE_EPOCH="" ;;
    *)
        if ! [[ "$SINCE_DAYS" =~ ^[0-9]+$ ]]; then
            echo "Error: --since requires a positive integer (days) or 'all'" >&2
            exit 3
        fi
        SINCE_EPOCH=$(( $(date -u +%s) - SINCE_DAYS * 86400 ))
        ;;
esac

# Resolve upload token at runtime. Order: --upload-token > $RFXN_INTAKE_TOKEN
# > built-in convenience token. Only matters when DO_UPLOAD is set; we don't
# read $RFXN_INTAKE_TOKEN otherwise so an unrelated env var doesn't influence
# behavior. Token never appears in stdout/stderr (only sent as PUT header).
if (( DO_UPLOAD )); then
    INTAKE_TOKEN="${INTAKE_TOKEN:-${RFXN_INTAKE_TOKEN:-$INTAKE_DEFAULT_TOKEN}}"
fi

# Validate --max-bundle-mb. 0 = no cap. Must be a non-negative integer.
if ! [[ "$MAX_BUNDLE_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --max-bundle-mb requires a non-negative integer (MB)" >&2
    exit 3
fi

###############################################################################
# Host context
###############################################################################

HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)
TS_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TS_EPOCH=$(date -u +%s)
# Honor SESSIONSCRIBE_RUN_ID from the environment so a parent ioc-scan
# chain dispatch produces a correlated run_id across both tools' outputs.
# Falls back to local <epoch>-<pid> for standalone runs.
RUN_ID="${SESSIONSCRIBE_RUN_ID:-${TS_EPOCH}-$$}"

OS_PRETTY="unknown"
if [[ -r /etc/os-release ]]; then
    eval "$(awk -F= '$1=="PRETTY_NAME"{print "OS_PRETTY="$2}' /etc/os-release 2>/dev/null)"
elif [[ -r /etc/redhat-release ]]; then
    OS_PRETTY=$(head -1 /etc/redhat-release 2>/dev/null)
fi
OS_PRETTY="${OS_PRETTY//\"/}"

CPANEL_RAW=""
CPANEL_NORM="unknown"
if [[ -x /usr/local/cpanel/cpanel ]]; then
    CPANEL_RAW=$(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1 | tr -d '\r')
    CPANEL_NORM=$(echo "$CPANEL_RAW" | sed -E 's/^([0-9]+)\.([0-9]+)[[:space:]]+\(build[[:space:]]+([0-9]+)\).*/11.\1.\2.\3/')
    [[ "$CPANEL_NORM" == "$CPANEL_RAW" ]] && CPANEL_NORM="unknown"
fi

LP_UID=""
[[ -r /usr/local/lp/etc/lp-UID ]] && LP_UID=$(cat /usr/local/lp/etc/lp-UID 2>/dev/null | tr -d '\r\n[:space:]')

###############################################################################
# Output primitives
###############################################################################

if [[ -t 2 && "$NO_COLOR_FLAG" -eq 0 && "${NO_COLOR:-0}" = "0" ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[1;33m'
    C_CYN=$'\033[0;36m'; C_BLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_NC=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_CYN=''; C_BLD=''; C_DIM=''; C_NC=''
fi

json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

HOSTNAME_J=$(json_esc "$HOSTNAME_FQDN")
OS_J=$(json_esc "$OS_PRETTY")
CPV_J=$(json_esc "$CPANEL_NORM")
LP_UID_J=$(json_esc "$LP_UID")

# Per-finding accumulators. Module-scope arrays - `declare -a` is enough;
# `-g` (bash 4.2+) is unnecessary here and breaks bash 4.1 (CloudLinux 6).
declare -a SIGNALS=()
declare -a DEFENSE_EVENTS=()   # "epoch|key|note"
declare -a OFFENSE_EVENTS=()   # "epoch|pattern|key|note|defenses_required"
declare -a RECONCILED=()       # "verdict|delta_seconds|epoch|pattern|key"

N_DEF=0; N_OFF=0; N_PRE=0; N_POST=0

emit_signal() {
    # phase severity key note [k=v ...]
    local phase="$1" sev="$2" key="$3" note="${4:-}"
    shift 4 2>/dev/null || shift $#
    local extra=""
    while (( $# >= 2 )); do
        extra+=",\"$(json_esc "$1")\":\"$(json_esc "$2")\""
        shift 2
    done
    local line
    line=$(printf '{"host":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-forensic","tool_version":"%s","mode":"forensic","incident_id":"%s","run_id":"%s","phase":"%s","severity":"%s","key":"%s","note":"%s"%s}' \
        "$HOSTNAME_J" "$LP_UID_J" "$OS_J" "$CPV_J" "$TS_ISO" "$VERSION" "$INCIDENT_ID" "$RUN_ID" \
        "$phase" "$sev" "$(json_esc "$key")" "$(json_esc "$note")" "$extra")
    SIGNALS+=("$line")
    (( JSONL_OUT )) && printf '%s\n' "$line"
}

# Sectioned report helpers.
hdr()       { (( QUIET )) || printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$1" "$C_NC" "$C_DIM" "$2" "$C_NC" >&2; }
# Output severity tags (color + label both telegraph meaning).
#   [OK]        green   - clean / nothing wrong
#   [INFO]      dim     - neutral information
#   [WARN]      yellow  - anomaly worth attention but not a compromise
#   [FAIL]      red     - tool error / inability to run a check
#   [DEF-OK]    green   - defense layer is active (good)
#   [DEF-MISS]  yellow  - defense layer is absent (this host is exposed)
#   [IOC]       red     - indicator of compromise found (BAD - investigate)
say_pass()      { (( QUIET )) || printf '  %s[OK]%s %s\n'        "$C_GRN" "$C_NC" "$*" >&2; }
say_info()      { (( QUIET )) || printf '  %s[INFO]%s %s\n'      "$C_DIM" "$C_NC" "$*" >&2; }
say_warn()      { (( QUIET )) || printf '  %s[WARN]%s %s\n'      "$C_YEL" "$C_NC" "$*" >&2; }
say_fail()      { (( QUIET )) || printf '  %s[FAIL]%s %s\n'      "$C_RED" "$C_NC" "$*" >&2; }
say_def()       { (( QUIET )) || printf '  %s[DEF-OK]%s %s\n'    "$C_GRN" "$C_NC" "$*" >&2; }
say_def_miss()  { (( QUIET )) || printf '  %s[DEF-MISS]%s %s\n'  "$C_YEL" "$C_NC" "$*" >&2; }
say_ioc()       { (( QUIET )) || printf '  %s[IOC]%s %s\n'       "$C_RED" "$C_NC" "$*" >&2; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Convert any of the four timestamp shapes we care about to epoch:
#   1. accounting.log:   "Wed Apr 29 20:42:44 2026"
#   2. apache CLF:       "[30/Apr/2026:09:30:50 +0000]"   DD/Mon/YYYY
#   3. cpanel access_log:"[04/30/2026:09:30:50 -0500]"    MM/DD/YYYY
#   4. ISO-8601:         "2026-04-30T09:30:50Z"
# Returns empty string if unparseable.
#
# Note: cpanel's /usr/local/cpanel/logs/access_log uses MM/DD/YYYY (NOT the
# apache CLF DD/Mon/YYYY). This is documented in the cPanel access-log spec
# and is the format that ioc-scan.sh's awk parser handles. Earlier versions
# of this script only handled the apache form, silently dropping every
# cpanel-log timestamp.
to_epoch() {
    local s="$1"
    [[ -z "$s" ]] && { echo ""; return; }
    # Strip surrounding [] if present.
    s="${s#[}"; s="${s%]}"
    # Apache CLF: 30/Apr/2026:09:30:50 +0000 -> 30 Apr 2026 09:30:50 +0000
    if [[ "$s" =~ ^[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}: ]]; then
        s=$(echo "$s" | sed -E 's|^([0-9]{1,2})/([A-Za-z]{3})/([0-9]{4}):([0-9:]+)([[:space:]]+(.*))?$|\1 \2 \3 \4\5|')
        date -u -d "$s" +%s 2>/dev/null
        return
    fi
    # cpanel: 04/30/2026:09:30:50 -0500. date(1) won't parse MM/DD/YYYY-
    # with the colon separator; rebuild as "YYYY-MM-DD HH:MM:SS TZ".
    if [[ "$s" =~ ^([0-9]{2})/([0-9]{2})/([0-9]{4}):([0-9:]+)([[:space:]]+([+-][0-9]{4}))?$ ]]; then
        local mm="${BASH_REMATCH[1]}" dd="${BASH_REMATCH[2]}" yyyy="${BASH_REMATCH[3]}"
        local hms="${BASH_REMATCH[4]}" tz="${BASH_REMATCH[6]:-+0000}"
        date -u -d "${yyyy}-${mm}-${dd} ${hms} ${tz}" +%s 2>/dev/null
        return
    fi
    date -u -d "$s" +%s 2>/dev/null
}

# Extract a timestamp bracket from an access-log line. Tries cpanel
# MM/DD/YYYY first then apache DD/Mon/YYYY. Returns the inner string
# (without surrounding []) or empty.
extract_log_ts() {
    local line="$1" m
    m=$(grep -oE '\[[0-9]{2}/[0-9]{2}/[0-9]{4}:[0-9:]+( [+-][0-9]{4})?\]' <<< "$line" | head -1)
    [[ -z "$m" ]] && m=$(grep -oE '\[[0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]+( [+-][0-9]{4})?\]' <<< "$line" | head -1)
    echo "$m"
}

# Stat -c %Y wrapper that returns "" for missing files.
mtime_of() {
    local f="$1"
    [[ -e "$f" ]] || { echo ""; return; }
    stat -c %Y "$f" 2>/dev/null
}

# Stream the contents of a (possibly compressed) log file. cPanel rotates
# /usr/local/cpanel/logs/access_log to .gz typically; some sites recompress
# to .xz. Plain text passes through. Failure modes (missing tool, corrupt
# archive) are silent - the caller's grep just sees no input.
cat_log() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    case "$f" in
        *.gz)  have_cmd zcat  && zcat  "$f" 2>/dev/null ;;
        *.xz)  have_cmd xzcat && xzcat "$f" 2>/dev/null ;;
        *.bz2) have_cmd bzcat && bzcat "$f" 2>/dev/null ;;
        *)     cat "$f" 2>/dev/null ;;
    esac
}

epoch_to_iso() {
    local e="$1"
    [[ -z "$e" || "$e" == "0" ]] && { echo ""; return; }
    date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

###############################################################################
# Defense extraction - when did each mitigation layer activate?
###############################################################################

DEF_PATCH_TIME=""        # cpanel patch landed (Load.pm mtime if patched)
DEF_CPSRVD_RESTART=""    # cpsrvd PID start time (epoch)
DEF_MITIGATE_FIRST=""    # earliest sessionscribe-mitigate.sh run dir
DEF_MITIGATE_LAST=""     # most recent sessionscribe-mitigate.sh run dir
DEF_MODSEC_TIME=""       # mtime of modsec2.user.conf if it contains 1500030
DEF_CSF_TIME=""          # mtime of csf.conf if cpsrvd ports stripped
DEF_APF_TIME=""          # mtime of conf.apf if cpsrvd ports stripped
DEF_PROXYSUB_TIME=""     # mtime of cpanel.config if proxysubdomains=1
DEF_UPCP_LATEST_TIME=""  # epoch of most recent successful upcp completion

phase_defense() {
    hdr "defense" "extracting timestamps for every mitigation layer"

    # 1. cpanel patch landing time. PATCH_STATE distinguishes:
    #    PATCHED      build matches vendor cutoff list - upgrade complete
    #    UNPATCHED    sub-cutoff but tier has a patch available - run upcp
    #    UNPATCHABLE  tier in vendor "no in-place patch" list (112/114/116/
    #                 120/122/124/128) - response is upgrade major series
    #    UNKNOWN      cpanel binary missing or build unparseable
    # Mirrors mitigate.sh PATCH_STATE vocabulary so a fleet jq pipeline can
    # join on the same state space.
    PATCH_STATE="UNKNOWN"
    if [[ "$CPANEL_NORM" == "unknown" || -z "$CPANEL_NORM" ]]; then
        say_def_miss "cpanel binary missing or build unparseable - patch defense UNKNOWN"
        emit_signal defense warn patch_unknown "cpanel build unparseable" \
            build "$CPANEL_NORM" patch_state "$PATCH_STATE"
    else
        local patched=0
        for b in "${PATCHED_BUILDS_CPANEL[@]}"; do
            [[ "$CPANEL_NORM" == "$b" ]] && patched=1
        done
        [[ "$CPANEL_NORM" == "$PATCHED_BUILD_WPSQUARED" ]] && patched=1
        if (( patched )) && [[ -f "$PATCH_CANARY_FILE" ]]; then
            PATCH_STATE="PATCHED"
            DEF_PATCH_TIME=$(mtime_of "$PATCH_CANARY_FILE")
            say_def "cpanel patch present: $CPANEL_NORM (Load.pm mtime $(epoch_to_iso "$DEF_PATCH_TIME"))"
            emit_signal defense info patch_active \
                "build=$CPANEL_NORM mtime=$(epoch_to_iso "$DEF_PATCH_TIME")" \
                epoch "$DEF_PATCH_TIME" build "$CPANEL_NORM" patch_state "$PATCH_STATE"
            DEFENSE_EVENTS+=("$DEF_PATCH_TIME|patch|cpanel patched to $CPANEL_NORM")
        else
            # Tier-level classification: is this build in a tier that vendor
            # released a patch for, or one of the no-in-place-patch tiers?
            local tier
            tier=$(echo "$CPANEL_NORM" | awk -F. '{print $2}')
            local is_unpatchable=0 t
            for t in "${UNPATCHED_TIERS[@]}"; do
                [[ "$tier" == "$t" ]] && is_unpatchable=1
            done
            if (( is_unpatchable )); then
                PATCH_STATE="UNPATCHABLE"
                say_def_miss "cpanel tier $tier has NO in-place patch - upgrade major series or migrate"
                emit_signal defense warn patch_unpatchable \
                    "tier=$tier has no vendor patch; must upgrade or migrate" \
                    build "$CPANEL_NORM" tier "$tier" patch_state "$PATCH_STATE"
            else
                PATCH_STATE="UNPATCHED"
                say_def_miss "cpanel build $CPANEL_NORM is below vendor cutoff - upcp will help"
                emit_signal defense warn patch_unpatched \
                    "build=$CPANEL_NORM below vendor cutoff for tier $tier" \
                    build "$CPANEL_NORM" tier "$tier" patch_state "$PATCH_STATE"
            fi
        fi
    fi

    # 2. cpsrvd restart time. The patch isn't fully effective until cpsrvd
    # is restarted post-patch. Check process start.
    local cpsrvd_pid cpsrvd_start
    cpsrvd_pid=$(pgrep -f cpsrvd 2>/dev/null | head -1)
    if [[ -n "$cpsrvd_pid" ]]; then
        cpsrvd_start=$(ps -o lstart= -p "$cpsrvd_pid" 2>/dev/null | xargs -I{} date -d "{}" +%s 2>/dev/null)
        if [[ -n "$cpsrvd_start" ]]; then
            DEF_CPSRVD_RESTART="$cpsrvd_start"
            say_def "cpsrvd pid=$cpsrvd_pid started at $(epoch_to_iso "$cpsrvd_start")"
            emit_signal defense info cpsrvd_running "pid=$cpsrvd_pid started=$(epoch_to_iso "$cpsrvd_start")" \
                epoch "$cpsrvd_start" pid "$cpsrvd_pid"
            # Patch is only effective if cpsrvd restarted AFTER patch landed.
            if [[ -n "$DEF_PATCH_TIME" && "$cpsrvd_start" -lt "$DEF_PATCH_TIME" ]]; then
                say_def_miss "STALE: cpsrvd started BEFORE patch mtime - patch may not be live"
                emit_signal defense warn cpsrvd_stale "cpsrvd started before patch landed" \
                    cpsrvd_start "$cpsrvd_start" patch_mtime "$DEF_PATCH_TIME"
            fi
        fi
    else
        say_def_miss "cpsrvd not running"
        emit_signal defense warn cpsrvd_absent "cpsrvd process not found"
    fi

    # 3. sessionscribe-mitigate.sh execution history. The backup root is the
    # canonical fingerprint - existence of /var/cpanel/sessionscribe-mitigation/
    # subdirectories proves the script ran; their names are ISO timestamps.
    if [[ -d "$MITIGATE_BACKUP_ROOT" ]]; then
        local count
        # Iterate run directories sorted by mtime.
        local dirs
        dirs=$(find "$MITIGATE_BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -n)
        if [[ -n "$dirs" ]]; then
            DEF_MITIGATE_FIRST=$(echo "$dirs" | head -1 | awk '{print int($1)}')
            DEF_MITIGATE_LAST=$(echo "$dirs" | tail -1 | awk '{print int($1)}')
            count=$(echo "$dirs" | wc -l | tr -d ' ')
            say_def "sessionscribe-mitigate.sh ran $count time(s); first=$(epoch_to_iso "$DEF_MITIGATE_FIRST") last=$(epoch_to_iso "$DEF_MITIGATE_LAST")"
            emit_signal defense info mitigate_history "ran=$count first=$(epoch_to_iso "$DEF_MITIGATE_FIRST") last=$(epoch_to_iso "$DEF_MITIGATE_LAST")" \
                first_epoch "$DEF_MITIGATE_FIRST" last_epoch "$DEF_MITIGATE_LAST" count "$count"
            DEFENSE_EVENTS+=("$DEF_MITIGATE_FIRST|mitigate_first|sessionscribe-mitigate.sh first run")
            DEFENSE_EVENTS+=("$DEF_MITIGATE_LAST|mitigate_last|sessionscribe-mitigate.sh last run")
        fi
    else
        say_def_miss "no sessionscribe-mitigate.sh history found at $MITIGATE_BACKUP_ROOT"
        emit_signal defense warn mitigate_absent "$MITIGATE_BACKUP_ROOT does not exist"
    fi

    # 4. modsec rule presence + install time. Rule 1500030 is the primary
    # CRLF-in-Authorization-Basic block. Without it, the host had no
    # exploit-vector defense regardless of cPanel patch state.
    # Match both `id:1500030` and `id:"1500030"` shapes (mitigate.sh
    # convention; either is valid SecRule syntax).
    # Resolve modsec config from candidate paths (EA4 default, then non-EA4
    # fallbacks). First existing path wins; if none exist we keep the
    # canonical EA4 path for the "absent" diagnostic.
    local mc
    for mc in "${MODSEC_USER_CONFS[@]}"; do
        if [[ -f "$mc" ]]; then
            MODSEC_USER_CONF="$mc"
            break
        fi
    done
    if [[ -f "$MODSEC_USER_CONF" ]]; then
        local has_30 has_31
        has_30=$(grep -cE '^[[:space:]]*[^#].*\b(id:1500030\b|id:"1500030")' "$MODSEC_USER_CONF" 2>/dev/null)
        has_31=$(grep -cE '^[[:space:]]*[^#].*\b(id:1500031\b|id:"1500031")' "$MODSEC_USER_CONF" 2>/dev/null)
        if (( has_30 > 0 )); then
            DEF_MODSEC_TIME=$(mtime_of "$MODSEC_USER_CONF")
            say_def "modsec rule 1500030 present (mtime $(epoch_to_iso "$DEF_MODSEC_TIME")); 1500031=$has_31"
            emit_signal defense info modsec_active "1500030=$has_30 1500031=$has_31 mtime=$(epoch_to_iso "$DEF_MODSEC_TIME")" \
                epoch "$DEF_MODSEC_TIME" rule_30 "$has_30" rule_31 "$has_31"
            DEFENSE_EVENTS+=("$DEF_MODSEC_TIME|modsec|modsec rule 1500030 installed")
        else
            say_def_miss "modsec rule 1500030 NOT present in $MODSEC_USER_CONF"
            emit_signal defense warn modsec_absent "rule 1500030 missing"
        fi
    else
        say_def_miss "modsec config $MODSEC_USER_CONF missing - modsec defense ABSENT"
        emit_signal defense warn modsec_conf_absent "$MODSEC_USER_CONF not found"
    fi

    # 5. CSF cpsrvd port closure. The defensive state we want is
    # TCP_IN/TCP6_IN with NO cpsrvd ports (2082/3, 2086/7, 2095/6).
    # Two ways the closure can be defeated: explicit cpsrvd port in the
    # CSV, OR a port range like 2080:2090 that overlaps a cpsrvd port.
    # We treat either as `csf_dirty`.
    if [[ -f /etc/csf/csf.conf ]]; then
        local csf_clean=1 cur p k
        local range_overlaps=()
        for k in TCP_IN TCP6_IN; do
            cur=$(grep -E "^${k}[[:space:]]*=" /etc/csf/csf.conf | head -1 | sed -E 's/^[^"]*"([^"]*)".*/\1/')
            for p in "${CPSRVD_PORTS[@]}"; do
                if grep -qE "(^|,)${p}(,|$)" <<< "$cur"; then
                    csf_clean=0
                fi
            done
            # Range overlap detection (mitigate.sh phase_csf style). A range
            # like 2080:2090 contains 2082/2083/2086/2087 implicitly.
            local rngs
            rngs=$(grep -oE '[0-9]+:[0-9]+' <<< "$cur")
            if [[ -n "$rngs" ]]; then
                while IFS= read -r r; do
                    [[ -z "$r" ]] && continue
                    local lo hi
                    lo=${r%:*}; hi=${r#*:}
                    for p in "${CPSRVD_PORTS[@]}"; do
                        if (( lo <= p && p <= hi )); then
                            csf_clean=0
                            range_overlaps+=("$k:$r overlaps $p")
                        fi
                    done
                done <<< "$rngs"
            fi
        done
        if (( ${#range_overlaps[@]} > 0 )); then
            emit_signal defense warn csf_range_overlap \
                "csf range(s) overlap cpsrvd ports: ${range_overlaps[*]}" \
                overlaps "${range_overlaps[*]}"
        fi
        if (( csf_clean )); then
            DEF_CSF_TIME=$(mtime_of /etc/csf/csf.conf)
            # Prefer the .ic5790.bak file mtime if it exists (Zane's pattern)
            # since that records the original CSF mutation time.
            if [[ -f /etc/csf/csf.conf.ic5790.bak ]]; then
                local bak_time
                bak_time=$(mtime_of /etc/csf/csf.conf.ic5790.bak)
                # The .bak mtime is the pre-mutation original; the conf
                # mtime is when we mutated. We want the mutation time.
                say_def "CSF cpsrvd ports stripped; csf.conf mtime $(epoch_to_iso "$DEF_CSF_TIME") (bak from $(epoch_to_iso "$bak_time"))"
            else
                say_def "CSF cpsrvd ports clean; csf.conf mtime $(epoch_to_iso "$DEF_CSF_TIME")"
            fi
            emit_signal defense info csf_clean "cpsrvd ports stripped, mtime=$(epoch_to_iso "$DEF_CSF_TIME")" \
                epoch "$DEF_CSF_TIME"
            DEFENSE_EVENTS+=("$DEF_CSF_TIME|csf|csf.conf cpsrvd ports stripped")
        else
            say_def_miss "CSF still has cpsrvd ports in TCP_IN/TCP6_IN"
            emit_signal defense warn csf_dirty "cpsrvd ports present in TCP_IN/TCP6_IN"
        fi
        # Verify actual iptables state (the host2.kyroslawgroup.net problem -
        # csf.conf can be clean but iptables wasn't reloaded). cPanel/CSF
        # posture is "explicit ACCEPT allowlist + default DROP via fall-
        # through", so the defense state is checked as the ABSENCE of an
        # ACCEPT 0.0.0.0/0 -> dpt:N rule for each cpsrvd port. We walk
        # INPUT plus secondary chains CSF references (mirrors mitigate.sh
        # phase_runfw logic).
        if have_cmd iptables; then
            local stale_ports=()
            local secondary_chains
            secondary_chains=$(iptables -L INPUT -n 2>/dev/null \
                    | awk 'NR>2 && NF>=2 {print $1}' \
                    | grep -vE '^(ACCEPT|DROP|REJECT|LOG|RETURN|target|Chain)$' \
                    | sort -u)
            for p in "${CPSRVD_PORTS[@]}"; do
                local c open=0
                for c in INPUT $secondary_chains; do
                    if iptables -L "$c" -n 2>/dev/null \
                         | awk -v p="$p" '$1=="ACCEPT" && $5=="0.0.0.0/0" \
                                && index($0,"dpt:"p" ") {found=1} END{exit !found}'
                    then
                        open=1; break
                    fi
                done
                (( open )) && stale_ports+=("$p")
            done
            if (( ${#stale_ports[@]} > 0 )); then
                say_def_miss "iptables INPUT ACCEPTs cpsrvd ports from 0.0.0.0/0: ${stale_ports[*]}"
                emit_signal defense warn csf_not_in_effect \
                    "csf.conf clean but iptables INPUT still ACCEPTs cpsrvd ports from 0.0.0.0/0" \
                    open_ports "${stale_ports[*]}"
            fi
        fi
    fi

    # 6. APF - same logic.
    if [[ -f /etc/apf/conf.apf ]]; then
        local apf_clean=1 cur p
        cur=$(grep -E '^IG_TCP_CPORTS[[:space:]]*=' /etc/apf/conf.apf | head -1 | sed -E 's/^[^"]*"([^"]*)".*/\1/')
        for p in "${CPSRVD_PORTS[@]}"; do
            grep -qE "(^|,)${p}(,|$)" <<< "$cur" && apf_clean=0
        done
        if (( apf_clean )) && [[ -n "$cur" ]]; then
            DEF_APF_TIME=$(mtime_of /etc/apf/conf.apf)
            say_def "APF cpsrvd ports clean; conf.apf mtime $(epoch_to_iso "$DEF_APF_TIME")"
            DEFENSE_EVENTS+=("$DEF_APF_TIME|apf|apf cpsrvd ports stripped")
        fi
    fi

    # 7. proxysubdomains enabled. cpanel.config mtime is the proxy.
    if [[ -r /var/cpanel/cpanel.config ]]; then
        local main new
        main=$(awk -F= '$1=="proxysubdomains"{print $2}' /var/cpanel/cpanel.config)
        new=$(awk -F= '$1=="proxysubdomainsfornewaccounts"{print $2}' /var/cpanel/cpanel.config)
        if [[ "$main" == "1" && "$new" == "1" ]]; then
            DEF_PROXYSUB_TIME=$(mtime_of /var/cpanel/cpanel.config)
            say_def "proxysubdomains enabled; cpanel.config mtime $(epoch_to_iso "$DEF_PROXYSUB_TIME")"
            emit_signal defense info proxysub_enabled "main=$main new=$new" epoch "$DEF_PROXYSUB_TIME"
            DEFENSE_EVENTS+=("$DEF_PROXYSUB_TIME|proxysub|proxysubdomains enabled")
        fi
    fi

    # 8. upcp completion history. summary.log records every successful update.
    if [[ -f /var/cpanel/updatelogs/summary.log ]]; then
        local last_complete
        last_complete=$(grep -E '\[.*\][[:space:]]*Completed update' /var/cpanel/updatelogs/summary.log 2>/dev/null | tail -1 | sed -E 's/^\[([^]]*)\].*/\1/')
        if [[ -n "$last_complete" ]]; then
            DEF_UPCP_LATEST_TIME=$(date -d "$last_complete" +%s 2>/dev/null)
            if [[ -n "$DEF_UPCP_LATEST_TIME" ]]; then
                say_def "last successful upcp: $last_complete (epoch $DEF_UPCP_LATEST_TIME)"
                emit_signal defense info upcp_history "last_complete=$last_complete" \
                    epoch "$DEF_UPCP_LATEST_TIME"
            fi
        fi
    fi
}

###############################################################################
# Offense extraction - reads ioc-scan's canonical IOC envelope and adds the
# kill-chain-relevant deep checks ioc-scan doesn't cover (Pattern G mtime
# forgery + key-comment validation, suspect-IP cross-ref).
#
# v0.9.0 deletion: ~760 lines of duplicated detection (forged session ladder,
# Pattern A/B/C/D/F basic checks, access-log awk pass for E_WS/E_FM/D_REC/
# D_UA/D_IP) - all of these now come via the envelope. Forensic reported
# CLEAN on host2 while ioc-scan v1.5.x reported COMPROMISED on the same
# logs; this refactor makes that divergence structurally impossible.
###############################################################################

# Extract a single string field from a one-line JSON object.
# POSIX-grep + parameter expansion - no jq required (CL6 compatibility).
json_str_field() {
    local line="$1" key="$2" v
    v=$(printf '%s\n' "$line" | grep -oE "\"$key\":\"([^\"\\\\]|\\\\.)*\"" | head -1)
    [[ -z "$v" ]] && return 0
    v="${v#*\":\"}"
    v="${v%\"}"
    v="${v//\\\"/\"}"
    v="${v//\\\\/\\}"
    printf '%s' "$v"
}

# Extract a single numeric (or numeric-string) field. Strips quotes if present.
json_num_field() {
    local line="$1" key="$2" v
    v=$(printf '%s\n' "$line" | grep -oE "\"$key\":(\"[0-9.+-]*\"|-?[0-9]+(\\.[0-9]+)?)" | head -1)
    [[ -z "$v" ]] && return 0
    v="${v#*\":}"
    v="${v#\"}"
    v="${v%\"}"
    printf '%s' "$v"
}

# Map ioc-scan emit key -> kill-chain stage letter for OFFENSE_EVENTS.
ioc_key_to_stage() {
    case "$1" in
        ioc_pattern_a_*)            echo A ;;
        ioc_pattern_b_*)            echo B ;;
        ioc_pattern_c_*)            echo C ;;
        ioc_pattern_d_*)            echo D ;;
        ioc_pattern_e_*)            echo E ;;
        ioc_pattern_f_*)            echo F ;;
        ioc_pattern_g_*)            echo G ;;
        ioc_attacker_ip*|ioc_hits)  echo init ;;
        ioc_token_*|ioc_preauth_*|ioc_short_pass*|ioc_multiline_*|ioc_badpass*|ioc_cve_2026_41940*|ioc_hasroot*|ioc_malformed*|ioc_forged_*|ioc_tfa*|anomalous_root_sessions)
                                    echo X ;;
        *)                          echo ? ;;
    esac
}

# Resolve an event timestamp from a signal's key bag, in priority order:
# ts_epoch_first -> mtime_epoch -> ts_epoch -> file_mtime ISO -> login_time
# ISO -> $TS_EPOCH (run start, last resort).
ioc_signal_epoch() {
    local line="$1" v iso k
    for k in ts_epoch_first mtime_epoch ts_epoch; do
        v=$(json_num_field "$line" "$k")
        [[ -n "$v" && "$v" != "0" ]] && { printf '%s' "$v"; return; }
    done
    for k in file_mtime login_time; do
        iso=$(json_str_field "$line" "$k")
        if [[ -n "$iso" ]]; then
            v=$(date -u -d "$iso" +%s 2>/dev/null)
            [[ -n "$v" ]] && { printf '%s' "$v"; return; }
        fi
    done
    printf '%s' "$TS_EPOCH"
}

# Read kill-chain-relevant signals from $SESSIONSCRIBE_IOC_JSON and append
# to OFFENSE_EVENTS in the shape phase_reconcile expects:
#   "epoch|stage|key|note|defenses_required"
# Sample-row emits are skipped - the parent has the aggregated count + ts.
read_iocs_from_envelope() {
    local env="${SESSIONSCRIBE_IOC_JSON:-}"
    if [[ -z "$env" ]]; then
        say_warn "no SESSIONSCRIBE_IOC_JSON set - run via 'sessionscribe-ioc-scan.sh --chain-forensic' for full IOC coverage"
        emit_signal offense warn no_envelope "envelope unavailable; deep checks only"
        return 1
    fi
    if [[ ! -f "$env" ]]; then
        say_warn "SESSIONSCRIBE_IOC_JSON points to missing file: $env"
        emit_signal offense warn envelope_missing "envelope path unreadable" path "$env"
        return 1
    fi

    local line area severity key note ts stage n_added=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\{\"host\": ]] || continue
        area=$(json_str_field "$line" area)
        severity=$(json_str_field "$line" severity)
        case "$area" in
            logs|sessions|destruction) ;;
            *) continue ;;
        esac
        case "$severity" in
            strong|warning) ;;
            *) continue ;;
        esac
        key=$(json_str_field "$line" key)
        case "$key" in
            ioc_sample|ioc_attacker_ip_sample|session_shape_sample) continue ;;
        esac
        note=$(json_str_field "$line" note)
        ts=$(ioc_signal_epoch "$line")
        stage=$(ioc_key_to_stage "$key")
        OFFENSE_EVENTS+=("$ts|$stage|$key|${note:-$key}|patch,modsec")
        n_added=$((n_added+1))
        emit_signal offense fail "$key" "${note:-$key}" \
            epoch "$ts" stage "$stage" envelope "$(basename "$env")"
    done < "$env"

    say_info "envelope: imported $n_added IOC(s) from $(basename "$env")"
    return 0
}

# Pattern G deep checks ioc-scan doesn't perform: forged-mtime detection
# (touch -d backdating) + per-key-comment validation against the LW
# known-good set + ssh-rsa material in non-canonical paths.
pattern_g_deep_checks() {
    local ak_files=(/root/.ssh/authorized_keys /root/.ssh/authorized_keys2)
    local h
    while IFS= read -r -d '' h; do
        ak_files+=("$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2")
    done < <(find /home -maxdepth 2 -mindepth 1 -type d -print0 2>/dev/null)

    local ak mtime_pre atime_pre ctime_pre mt_utc mt_local
    for ak in "${ak_files[@]}"; do
        [[ -f "$ak" ]] || continue
        mtime_pre=$(stat -c %Y "$ak" 2>/dev/null)
        atime_pre=$(stat -c %X "$ak" 2>/dev/null)
        ctime_pre=$(stat -c %Z "$ak" 2>/dev/null)
        # `touch -d` interprets in local timezone, so the resulting epoch
        # depends on the host's UTC offset. Compare the wall-clock string
        # under both UTC and localtime - either match is the IC-5790 stamp.
        if [[ -n "$mtime_pre" ]]; then
            mt_utc=$(date -u   -d "@$mtime_pre" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
            mt_local=$(date    -d "@$mtime_pre" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
            if [[ "$mt_utc" == "$PATTERN_G_FORGED_MTIME_WALL" \
               || "$mt_local" == "$PATTERN_G_FORGED_MTIME_WALL" ]]; then
                say_ioc "PATTERN-G: $ak mtime matches known forged stamp \"$PATTERN_G_FORGED_MTIME_WALL\""
                emit_signal offense fail pattern_g_forged_mtime \
                    "$ak mtime matches IC-5790 backdate stamp" \
                    file "$ak" forged_mtime_wall "$PATTERN_G_FORGED_MTIME_WALL" \
                    actual_mtime_utc "$mt_utc" actual_mtime_local "$mt_local"
                [[ -n "$ctime_pre" ]] && OFFENSE_EVENTS+=("$ctime_pre|G|pattern_g_forged_mtime|backdated ssh key|patch,modsec")
            fi
        fi

        # ctime is the stronger signal - touch can't backdate ctime.
        local susp_count=0 line comment is_known_bad bad bad_label
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            comment=$(echo "$line" | awk '{print $NF}')
            is_known_bad=0; bad_label=""
            for bad in "${PATTERN_G_BAD_KEY_LABELS[@]}"; do
                [[ "$comment" == *"$bad"* ]] && { is_known_bad=1; bad_label="$bad"; break; }
            done
            if (( is_known_bad )); then
                susp_count=$((susp_count+1))
                emit_signal offense fail pattern_g_known_bad_key \
                    "known-bad ssh key label in $ak: $comment matches $bad_label" \
                    file "$ak" comment "$comment" matches "$bad_label"
            elif [[ ! "$comment" =~ $SSH_KNOWN_GOOD_RE ]]; then
                susp_count=$((susp_count+1))
                emit_signal offense warn pattern_g_ssh_key \
                    "non-standard ssh key in $ak: comment=$comment" \
                    file "$ak" comment "$comment"
            fi
        done < "$ak"
        if (( susp_count > 0 )); then
            say_ioc "PATTERN-G: $susp_count non-standard ssh key(s) in $ak"
            [[ -n "$ctime_pre" ]] && OFFENSE_EVENTS+=("$ctime_pre|G|pattern_g_sshkey|non-standard ssh key (ctime)|patch,modsec")
        fi
    done

    # ssh-rsa / ed25519 material in non-canonical paths (cron, /etc).
    # Excludes sshd host keys, skel templates, our own backups. head -100
    # caps output without truncating busy hosts.
    local ssh_rsa_locations
    ssh_rsa_locations=$(grep -rIlE 'ssh-(rsa|ed25519|ecdsa|dss)[[:space:]]+[A-Za-z0-9+/=]{20,}' \
        /etc /var/spool/cron /var/spool/at /usr/local/etc 2>/dev/null \
        | grep -vE '^(/etc/ssh/ssh_host_|/etc/ssh/sshd_config|/etc/skel/\.ssh/|/etc/cpanel-known-hosts|'"$MITIGATE_BACKUP_ROOT"')' \
        | head -100)
    if [[ -n "$ssh_rsa_locations" ]]; then
        local f m c
        while IFS= read -r f; do
            [[ -z "$f" ]] && continue
            m=$(stat -c %Y "$f" 2>/dev/null)
            c=$(stat -c %Z "$f" 2>/dev/null)
            say_ioc "PATTERN-G: ssh key material in non-canonical location: $f"
            emit_signal offense fail pattern_g_offpath_key \
                "ssh-rsa/ed25519 in $f (out of band of ~/.ssh)" \
                file "$f" mtime_epoch "$m" ctime_epoch "$c"
            [[ -n "$c" ]] && OFFENSE_EVENTS+=("$c|G|pattern_g_offpath|ssh key in non-canonical path|patch,modsec")
        done <<< "$ssh_rsa_locations"
    fi
}

# Suspect inbound IPs: any source seen on /cpsess<id>/(websocket/Shell|
# json-api/(createacct|setupreseller|setacls)). Informational cross-ref
# for fleet correlation. --no-logs skips this scan.
suspect_ip_correlation() {
    (( NO_LOGS )) && return
    local cp_logs=() lg lm
    for lg in /usr/local/cpanel/logs/access_log \
              /usr/local/cpanel/logs/access_log.[0-9]* \
              /usr/local/cpanel/logs/access_log-* \
              /usr/local/apache/logs/access_log \
              /usr/local/apache/logs/access_log.[0-9]* \
              /usr/local/apache/logs/access_log-*; do
        [[ -f "$lg" ]] || continue
        if [[ -n "$SINCE_EPOCH" ]]; then
            lm=$(stat -c %Y "$lg" 2>/dev/null)
            [[ -n "$lm" ]] && (( lm < SINCE_EPOCH )) && continue
        fi
        cp_logs+=("$lg")
    done
    if [[ -n "${EXTRA_LOGS_DIR:-}" && -d "$EXTRA_LOGS_DIR" ]]; then
        while IFS= read -r -d '' lg; do
            cp_logs+=("$lg")
        done < <(find "$EXTRA_LOGS_DIR" -type f \( -name 'access_log*' -o -name '*.log*' \) -print0 2>/dev/null)
    fi
    (( ${#cp_logs[@]} > 0 )) || return

    local suspect_ips
    suspect_ips=$(
        for lg in "${cp_logs[@]}"; do cat_log "$lg"; done \
            | grep -E '"GET /cpsess[0-9]+/(websocket/Shell|json-api/(createacct|setupreseller|setacls))' 2>/dev/null \
            | awk '{print $1}' | sort -u | head -50
    )
    if [[ -n "$suspect_ips" ]]; then
        local ip_list
        ip_list=$(echo "$suspect_ips" | tr '\n' ',' | sed 's/,$//')
        say_ioc "suspect attacker IPs (websocket/createacct hits): $ip_list"
        emit_signal offense info suspect_ips "$ip_list" ips "$ip_list"
    fi
}

phase_offense() {
    hdr "offense" "ingesting IOCs from canonical detector + deep checks"
    read_iocs_from_envelope || true
    pattern_g_deep_checks
    suspect_ip_correlation
    if (( ${#OFFENSE_EVENTS[@]} == 0 )); then
        say_pass "no compromise indicators"
    fi
}

###############################################################################
# Reconciliation - was each defense in place when each indicator first hit?
###############################################################################

phase_reconcile() {
    hdr "reconcile" "comparing defense activation vs compromise timestamps"

    if (( ${#OFFENSE_EVENTS[@]} == 0 )); then
        say_pass "no compromise indicators - nothing to reconcile"
        emit_signal reconcile pass clean "no IOCs to reconcile"
        return
    fi

    # The two defenses every offense event needs to be checked against:
    #   - patch (Load.pm mtime + cpsrvd restart >= patch mtime)
    #   - modsec rule 1500030 install time
    # Both are proxies for "was the host actually defended at this moment?"

    local effective_patch_time=""
    if [[ -n "$DEF_PATCH_TIME" && -n "$DEF_CPSRVD_RESTART" ]]; then
        # Effective patch time = max(patch_mtime, cpsrvd_restart_time).
        # The patch isn't live until cpsrvd has restarted post-patch.
        if (( DEF_CPSRVD_RESTART >= DEF_PATCH_TIME )); then
            effective_patch_time="$DEF_CPSRVD_RESTART"
        else
            # cpsrvd predates the patch landing - patch not yet live.
            effective_patch_time=""
        fi
    fi

    local effective_modsec_time="$DEF_MODSEC_TIME"

    say_info "effective patch time: $(epoch_to_iso "${effective_patch_time:-}")"
    say_info "effective modsec time: $(epoch_to_iso "${effective_modsec_time:-}")"

    local oe verdict delta
    for oe in "${OFFENSE_EVENTS[@]}"; do
        local ev_epoch ev_pat ev_key ev_note
        # Record shape: epoch|pattern|key|note|defenses_required (5 fields).
        # Field 5 (defenses_required) is reserved for future per-pattern
        # reconciliation but currently every offense fires against the same
        # patch+modsec pair, so we discard it.
        #
        # Pipe-tolerant decode: read into an array, then rejoin parts[3..n-2]
        # with '|' so a note that legitimately contains '|' (e.g. a quoted
        # access_log line, a path with embedded '|', a session-attribute
        # value carrying CRLF-injected content) round-trips intact instead
        # of being silently truncated at the first '|' inside the note.
        # Pre-fix `read -r ... ev_note _` set ev_note=<note-prefix> and
        # discarded the rest, dropping the trailing portion of the note.
        local _oe_parts _oe_n _note_start _note_end
        IFS='|' read -r -a _oe_parts <<< "$oe"
        _oe_n=${#_oe_parts[@]}
        ev_epoch="${_oe_parts[0]:-}"
        ev_pat="${_oe_parts[1]:-}"
        ev_key="${_oe_parts[2]:-}"
        if (( _oe_n >= 5 )); then
            # Re-join parts[3..n-2] with '|'. The last element (n-1) is
            # defenses_required and is discarded.
            _note_start=3
            _note_end=$(( _oe_n - 2 ))
            local _note_slice IFS='|'
            _note_slice="${_oe_parts[*]:_note_start:_note_end-_note_start+1}"
            ev_note="$_note_slice"
            unset IFS
        elif (( _oe_n == 4 )); then
            # 4-field record (legacy / no defenses field). Field 4 is the note.
            ev_note="${_oe_parts[3]:-}"
        else
            ev_note=""
        fi

        # Determine verdict:
        #   pre-defense    if event happened before BOTH effective defenses
        #   post-defense   if event happened after AT LEAST ONE effective defense
        #   ambiguous      if defense times unknown
        local pre_patch=0 pre_modsec=0
        if [[ -n "$effective_patch_time" ]]; then
            (( ev_epoch < effective_patch_time )) && pre_patch=1
        else
            pre_patch=1   # no effective patch -> event is "before" patch
        fi
        if [[ -n "$effective_modsec_time" ]]; then
            (( ev_epoch < effective_modsec_time )) && pre_modsec=1
        else
            pre_modsec=1
        fi

        if [[ -z "$effective_patch_time" && -z "$effective_modsec_time" ]]; then
            verdict="UNDEFENDED"
            delta="n/a"
            N_PRE=$((N_PRE+1))
        elif (( pre_patch && pre_modsec )); then
            verdict="PRE-DEFENSE"
            # Delta to whichever defense landed first.
            local first_def
            if [[ -n "$effective_patch_time" && -n "$effective_modsec_time" ]]; then
                first_def=$(( effective_patch_time < effective_modsec_time ? effective_patch_time : effective_modsec_time ))
            elif [[ -n "$effective_patch_time" ]]; then
                first_def="$effective_patch_time"
            else
                first_def="$effective_modsec_time"
            fi
            delta=$(( first_def - ev_epoch ))
            N_PRE=$((N_PRE+1))
        elif (( ! pre_patch && ! pre_modsec )); then
            verdict="POST-DEFENSE"
            delta=$(( ev_epoch - (effective_patch_time > effective_modsec_time ? effective_modsec_time : effective_patch_time) ))
            N_POST=$((N_POST+1))
        else
            verdict="POST-PARTIAL"
            # Only one defense was up. Highlight which.
            local up_def="modsec"
            (( pre_modsec )) && up_def="patch"
            delta="partial:$up_def"
            N_POST=$((N_POST+1))
        fi

        local color
        case "$verdict" in
            PRE-DEFENSE)  color="$C_RED" ;;
            UNDEFENDED)   color="$C_RED" ;;
            POST-DEFENSE) color="$C_GRN" ;;
            POST-PARTIAL) color="$C_YEL" ;;
            *)            color="$C_DIM" ;;
        esac

        if (( ! QUIET )); then
            printf '  %s[%s]%s pattern=%s key=%s when=%s delta=%s\n' \
                "$color" "$verdict" "$C_NC" "$ev_pat" "$ev_key" \
                "$(epoch_to_iso "$ev_epoch")" "$delta" >&2
        fi

        local delta_human="$delta"
        [[ "$delta" =~ ^-?[0-9]+$ ]] && delta_human="${delta}s"
        emit_signal reconcile info kill_chain_event \
            "pattern=$ev_pat verdict=$verdict event=$ev_key when=$(epoch_to_iso "$ev_epoch") delta=$delta_human" \
            verdict "$verdict" pattern "$ev_pat" event_key "$ev_key" \
            event_epoch "$ev_epoch" delta_seconds "$delta"

        RECONCILED+=("$verdict|$delta|$ev_epoch|$ev_pat|$ev_key|$ev_note")
    done

    # Earliest offense vs latest defense - the headline number.
    if (( ${#OFFENSE_EVENTS[@]} > 0 )); then
        local min_off=""
        for oe in "${OFFENSE_EVENTS[@]}"; do
            local ts
            ts=$(echo "$oe" | cut -d'|' -f1)
            [[ -z "$ts" ]] && continue
            if [[ -z "$min_off" ]] || (( ts < min_off )); then
                min_off="$ts"
            fi
        done

        local max_def=""
        for de in "${DEFENSE_EVENTS[@]}"; do
            local ts
            ts=$(echo "$de" | cut -d'|' -f1)
            [[ -z "$ts" ]] && continue
            if [[ -z "$max_def" ]] || (( ts > max_def )); then
                max_def="$ts"
            fi
        done

        if [[ -n "$min_off" ]]; then
            say_info "first compromise indicator: $(epoch_to_iso "$min_off")"
        fi
        if [[ -n "$max_def" ]]; then
            say_info "latest defense activation: $(epoch_to_iso "$max_def")"
        fi
        if [[ -n "$min_off" && -n "$max_def" ]]; then
            local gap=$(( max_def - min_off ))
            if (( gap > 0 )); then
                say_warn "DEFENSE LATE: latest defense ${gap}s ($(( gap / 3600 ))h) AFTER first compromise"
                emit_signal reconcile warn defense_late \
                    "latest defense ${gap}s after first compromise" \
                    gap_seconds "$gap" first_offense "$min_off" last_defense "$max_def"
            else
                say_pass "DEFENSE EARLY: latest defense $(( -gap ))s before first compromise"
            fi
        fi
    fi
}

###############################################################################
# Bundle - tarball of raw artifacts for offline forensics
###############################################################################

# Estimate the on-disk footprint of a path list (MB). Used pre-tar to
# enforce the bundle size budget before we spend wall time compressing.
estimate_size_mb() {
    [[ $# -eq 0 ]] && { echo 0; return; }
    local mb
    mb=$(du -smc "$@" 2>/dev/null | tail -1 | awk '{print $1+0}')
    echo "${mb:-0}"
}

# Build a NUL-delimited path list under SRC restricted to mtime newer than
# SINCE_EPOCH. If SINCE_EPOCH is empty, returns the full subtree as one entry.
collect_recent() {
    local src="$1"
    [[ -e "$src" ]] || return 0
    if [[ -z "$SINCE_EPOCH" ]]; then
        printf '%s\0' "$src"
        return
    fi
    if [[ -f "$src" ]]; then
        local m; m=$(stat -c %Y "$src" 2>/dev/null)
        [[ -n "$m" ]] && (( m >= SINCE_EPOCH )) && printf '%s\0' "$src"
        return
    fi
    find "$src" -type f -newermt "@$SINCE_EPOCH" -print0 2>/dev/null
}

# Tar a candidate set with pre-flight size check.
#   $1 = destination tarball name (relative to bundle dir)
#   $2 = label for messages
#   $3 = mode: "filtered" reads NUL-delimited paths from the file at $4;
#               "raw" tars the literal paths in $4..N.
# Skips with a warning if estimated size exceeds MAX_BUNDLE_MB (when > 0).
bundle_tar() {
    local dest="$1" label="$2" mode="$3"; shift 3
    local bdir="$BUNDLE_BDIR" sz_mb=0 args=() rc=0

    if [[ "$mode" == "filtered" ]]; then
        local list="$1"
        [[ ! -s "$list" ]] && { say_info "skipped: $label (no files in window)"; return; }
        while IFS= read -r -d '' p; do args+=("$p"); done < "$list"
        (( ${#args[@]} == 0 )) && { say_info "skipped: $label (no files in window)"; return; }
        sz_mb=$(estimate_size_mb "${args[@]}")
    else
        args=("$@")
        (( ${#args[@]} == 0 )) && return
        sz_mb=$(estimate_size_mb "${args[@]}")
    fi

    if (( MAX_BUNDLE_MB > 0 && sz_mb > MAX_BUNDLE_MB )); then
        say_warn "$label oversize (~${sz_mb}MB > ${MAX_BUNDLE_MB}MB cap) - SKIPPED"
        emit_signal bundle warn bundle_oversize_skipped \
            "$label estimated ${sz_mb}MB exceeds bundle budget ${MAX_BUNDLE_MB}MB" \
            label "$label" estimate_mb "$sz_mb" cap_mb "$MAX_BUNDLE_MB"
        return
    fi

    if [[ "$mode" == "filtered" ]]; then
        printf '%s\0' "${args[@]}" \
            | tar --null -czf "$bdir/$dest" -T - 2>/dev/null
        rc=$?
    else
        tar -czf "$bdir/$dest" "${args[@]}" 2>/dev/null
        rc=$?
    fi
    if (( rc == 0 )); then
        say_info "captured: $dest (~${sz_mb}MB pre-compress)"
        emit_signal bundle info bundle_captured \
            "$dest captured (~${sz_mb}MB pre-compress)" \
            file "$dest" estimate_mb "$sz_mb"
    else
        say_warn "$dest failed (tar rc=$rc)"
    fi
}

phase_bundle() {
    hdr "bundle" "capturing raw artifacts (window=${SINCE_DAYS:-all}d, cap=${MAX_BUNDLE_MB}MB)"

    if (( ! DO_BUNDLE )); then
        say_info "--no-bundle: skipping artifact capture"
        return
    fi

    local bdir="${BUNDLE_DIR_ROOT}/${TS_ISO}-${RUN_ID}"
    if ! mkdir -p "$bdir" 2>/dev/null; then
        say_fail "could not create bundle dir: $bdir"
        emit_signal bundle fail bundle_dir_failed "mkdir failed: $bdir"
        return
    fi
    # Bundle contains ssh keys, sudoers, raw sessions, api tokens, root
    # history; restrict access. (/etc/shadow intentionally not captured.)
    chmod 0700 "$bdir" 2>/dev/null
    chmod 0700 "$BUNDLE_DIR_ROOT" 2>/dev/null
    BUNDLE_BDIR="$bdir"
    say_info "bundle dir: $bdir (0700)"

    # Manifest first - records what we collected and when.
    {
        echo "host=$HOSTNAME_FQDN"
        echo "uid=$LP_UID"
        echo "os=$OS_PRETTY"
        echo "cpanel_version=$CPANEL_NORM"
        echo "captured_at=$TS_ISO"
        echo "run_id=$RUN_ID"
        echo "tool_version=$VERSION"
        echo "since_days=${SINCE_DAYS:-all}"
        echo "since_epoch=${SINCE_EPOCH:-}"
        echo "max_bundle_mb=$MAX_BUNDLE_MB"
    } > "$bdir/manifest.txt"

    # 1. cPanel sessions - forensically-relevant subtrees only. /var/cpanel/
    # sessions/cache + tmpcache are the bulk of session-dir size on busy
    # hosts and carry no forensic value (encoder cache, not forged-session
    # artifacts). raw/ + preauth/ are where the IOCs live.
    local sess_list; sess_list=$(mktemp /tmp/forensic-sess.XXXXXX)
    {
        collect_recent /var/cpanel/sessions/raw
        collect_recent /var/cpanel/sessions/preauth
    } > "$sess_list" 2>/dev/null
    bundle_tar "sessions.tgz" "sessions (raw+preauth)" filtered "$sess_list"
    rm -f "$sess_list"

    # 2. Apache + cPanel access logs + cpsrvd incoming/error logs, filtered
    # to within the window. incoming_http_requests.log carries the raw
    # CRLF carrier on hosts that have it enabled - the highest-fidelity
    # Pattern X primary source. error_log captures cpsrvd exception
    # traces during exploitation attempts.
    local logs_list; logs_list=$(mktemp /tmp/forensic-logs.XXXXXX)
    {
        local lg
        for lg in /usr/local/cpanel/logs/access_log \
                  /usr/local/cpanel/logs/access_log.[0-9]* \
                  /usr/local/cpanel/logs/access_log-* \
                  /usr/local/cpanel/logs/incoming_http_requests.log \
                  /usr/local/cpanel/logs/incoming_http_requests.log.[0-9]* \
                  /usr/local/cpanel/logs/incoming_http_requests.log-* \
                  /usr/local/cpanel/logs/error_log \
                  /usr/local/cpanel/logs/error_log.[0-9]* \
                  /usr/local/cpanel/logs/error_log-* \
                  /usr/local/apache/logs/access_log \
                  /usr/local/apache/logs/access_log.[0-9]* \
                  /usr/local/apache/logs/access_log-* \
                  /usr/local/apache/logs/error_log \
                  /usr/local/apache/logs/error_log.[0-9]* \
                  /usr/local/apache/logs/error_log-*; do
            [[ -f "$lg" ]] || continue
            if [[ -n "$SINCE_EPOCH" ]]; then
                local lm; lm=$(stat -c %Y "$lg" 2>/dev/null)
                [[ -n "$lm" ]] && (( lm < SINCE_EPOCH )) && continue
            fi
            printf '%s\0' "$lg"
        done
    } > "$logs_list" 2>/dev/null
    bundle_tar "access-logs.tgz" "access logs (cpanel+apache+cpsrvd)" filtered "$logs_list"
    rm -f "$logs_list"

    # 2b. System auth + audit logs. /var/log/secure carries sshd auth events
    # (brute force, key acceptance), /var/log/messages catches sudo + kernel
    # events, /var/log/audit/audit.log records syscall-level evidence of any
    # post-RCE shell-out. Filtered by mtime so historical rotations outside
    # the incident window don't blow the budget. cPanel runs RHEL family,
    # so /var/log/secure is the canonical sshd log; /var/log/auth.log is
    # included as a Debian-family fallback (no-op when absent).
    local sys_logs_list; sys_logs_list=$(mktemp /tmp/forensic-syslogs.XXXXXX)
    {
        local lg
        for lg in /var/log/secure /var/log/secure-* /var/log/secure.[0-9]* \
                  /var/log/messages /var/log/messages-* /var/log/messages.[0-9]* \
                  /var/log/audit/audit.log /var/log/audit/audit.log.[0-9]* \
                  /var/log/auth.log /var/log/auth.log.[0-9]*; do
            [[ -f "$lg" ]] || continue
            if [[ -n "$SINCE_EPOCH" ]]; then
                local lm; lm=$(stat -c %Y "$lg" 2>/dev/null)
                [[ -n "$lm" ]] && (( lm < SINCE_EPOCH )) && continue
            fi
            printf '%s\0' "$lg"
        done
    } > "$sys_logs_list" 2>/dev/null
    bundle_tar "system-logs.tgz" "system auth+audit logs" filtered "$sys_logs_list"
    rm -f "$sys_logs_list"

    # 3. cPanel control-plane state. accounting.log is line-grep'd later;
    # api_tokens_v2 / resellers / cpanel.config are tiny. /var/cpanel/users
    # is split into its own tarball (3b) so an oversize users/ on big
    # shared hosts doesn't take accounting.log + api_tokens down with it.
    local cp_state=()
    [[ -f /var/cpanel/accounting.log ]] && cp_state+=(/var/cpanel/accounting.log)
    [[ -f /var/cpanel/resellers ]]      && cp_state+=(/var/cpanel/resellers)
    [[ -f /var/cpanel/cpanel.config ]]  && cp_state+=(/var/cpanel/cpanel.config)
    [[ -d /var/cpanel/api_tokens_v2 ]]  && cp_state+=(/var/cpanel/api_tokens_v2)
    bundle_tar "cpanel-state.tgz" "cpanel control-plane" raw "${cp_state[@]}"

    # 3b. /var/cpanel/users is per-account JSON-like state (5-50 KB per
    # account, hundreds of MB on shared hosts). Bundled separately so the
    # oversize-skip path only drops users data, not accounting.log + tokens.
    if [[ -d /var/cpanel/users ]]; then
        bundle_tar "cpanel-users.tgz" "cpanel per-account state" raw /var/cpanel/users
    fi

    # 4. Persistence artifacts - SSH keys, cron (all variants), systemd
    # units, init scripts, profile.d (login-time persistence vector),
    # root shell histories (all flavors), passwd/group, sudoers + drop-in.
    # /etc/shadow is NOT bundled (hash material; no Pattern depends on it).
    # Most paths are small; systemd unit + init.d trees can be a few MB on
    # hosts with many services. Worth bundling whole - Pattern C only greps
    # for nuclear.x86 so a hand-crafted backdoor unit (or NOPASSWD sudo
    # rule) would be invisible without the raw files.
    local persist=()
    [[ -d /root/.ssh ]] && persist+=(/root/.ssh)
    [[ -d /var/spool/cron ]] && persist+=(/var/spool/cron)
    [[ -d /etc/cron.d ]] && persist+=(/etc/cron.d)
    [[ -d /etc/cron.hourly ]] && persist+=(/etc/cron.hourly)
    [[ -d /etc/cron.daily ]] && persist+=(/etc/cron.daily)
    [[ -d /etc/cron.weekly ]] && persist+=(/etc/cron.weekly)
    [[ -d /etc/cron.monthly ]] && persist+=(/etc/cron.monthly)
    [[ -f /etc/crontab ]] && persist+=(/etc/crontab)
    [[ -d /etc/systemd/system ]] && persist+=(/etc/systemd/system)
    [[ -d /etc/init.d ]] && persist+=(/etc/init.d)
    [[ -d /etc/profile.d ]] && persist+=(/etc/profile.d)
    [[ -f /etc/rc.local ]] && persist+=(/etc/rc.local)
    [[ -f /root/.bash_history ]] && persist+=(/root/.bash_history)
    [[ -f /root/.zsh_history ]] && persist+=(/root/.zsh_history)
    [[ -f /root/.sh_history ]] && persist+=(/root/.sh_history)
    [[ -f /root/.bash_profile ]] && persist+=(/root/.bash_profile)
    [[ -f /root/.bashrc ]] && persist+=(/root/.bashrc)
    [[ -f /root/.profile ]] && persist+=(/root/.profile)
    [[ -f /root/.local/share/fish/fish_history ]] && persist+=(/root/.local/share/fish/fish_history)
    [[ -f /etc/passwd ]] && persist+=(/etc/passwd)
    [[ -f /etc/group ]] && persist+=(/etc/group)
    # /etc/shadow intentionally NOT bundled - hash material is sensitive and
    # not required for IC-5790 IR (no Pattern relies on shadow). /etc/sudoers
    # + /etc/sudoers.d/ are bundled instead: attacker-planted sudo rules
    # ("user ALL=(ALL) NOPASSWD:ALL") are a common post-RCE persistence
    # vector and the file mtime/ctime brackets the plant time.
    [[ -f /etc/sudoers ]] && persist+=(/etc/sudoers)
    [[ -d /etc/sudoers.d ]] && persist+=(/etc/sudoers.d)
    bundle_tar "persistence.tgz" "persistence artifacts" raw "${persist[@]}"

    # 5. Defense state. updatelogs accumulate per upcp; filter by window so
    # a 5-year-old host doesn't blow the budget on historical update logs
    # irrelevant to the IC-5790 timeline.
    local def_static=()
    [[ -d "$MITIGATE_BACKUP_ROOT" ]] && def_static+=("$MITIGATE_BACKUP_ROOT")
    [[ -f /etc/csf/csf.conf ]] && def_static+=(/etc/csf/csf.conf)
    [[ -f /etc/csf/csf.conf.ic5790.bak ]] && def_static+=(/etc/csf/csf.conf.ic5790.bak)
    [[ -f /etc/apf/conf.apf ]] && def_static+=(/etc/apf/conf.apf)
    [[ -f "$MODSEC_USER_CONF" ]] && def_static+=("$MODSEC_USER_CONF")
    local def_list; def_list=$(mktemp /tmp/forensic-def.XXXXXX)
    {
        local p
        for p in "${def_static[@]}"; do printf '%s\0' "$p"; done
        collect_recent /var/cpanel/updatelogs
    } > "$def_list" 2>/dev/null
    bundle_tar "defense-state.tgz" "defense state" filtered "$def_list"
    rm -f "$def_list"

    # 6. Process + network snapshot.
    ps auxfww > "$bdir/ps.txt" 2>&1 || true
    if have_cmd ss; then
        ss -tnp > "$bdir/connections.txt" 2>&1 || true
    elif have_cmd netstat; then
        netstat -anp > "$bdir/connections.txt" 2>&1 || true
    fi
    if have_cmd iptables; then
        iptables -L -nv > "$bdir/iptables.txt" 2>&1 || true
    fi

    # 7. Pattern A binary - capture metadata only, NOT the binary itself
    # (avoid spreading the encryptor by accident).
    if [[ -f "$PATTERN_A_BINARY" ]]; then
        {
            echo "Pattern A encryptor binary detected at $PATTERN_A_BINARY"
            stat "$PATTERN_A_BINARY" 2>&1
            md5sum "$PATTERN_A_BINARY" 2>&1
            sha256sum "$PATTERN_A_BINARY" 2>&1
            file "$PATTERN_A_BINARY" 2>&1
        } > "$bdir/pattern-a-binary-metadata.txt"
        say_warn "Pattern A binary metadata captured (binary itself NOT bundled)"
    fi

    # 8. Per-user bash histories (optional, gated on --no-history).
    if (( INCLUDE_HOMEDIR_HISTORY )); then
        mkdir -p "$bdir/user-histories"
        local found=0
        while IFS= read -r -d '' h; do
            local user
            user=$(echo "$h" | awk -F/ '{print $3}')
            cp "$h" "$bdir/user-histories/$user.history" 2>/dev/null && found=$((found+1))
        done < <(find /home -maxdepth 3 -name '.bash_history' -type f -print0 2>/dev/null)
        say_info "captured $found user bash histories"
    fi

    # Final sweep: signal what we built.
    local total_size
    total_size=$(du -sh "$bdir" 2>/dev/null | awk '{print $1}')
    say_info "bundle complete: $bdir ($total_size)"
    emit_signal bundle info bundle_complete "dir=$bdir size=$total_size" dir "$bdir" size "$total_size"
}

###############################################################################
# Upload - submit the bundle to the R-fx forensic intake (opt-in, --upload)
#
# Single PUT of an outer .tgz wrapping the entire bundle dir. Server-side
# requirements (see intake spec):
#   - method PUT
#   - X-Upload-Token header
#   - body must start with gzip magic (1f 8b)
#   - body <= 2 GiB (server enforces; tar -cz of the bundle dir is well
#     under that on a 90d-window cap-respecting bundle)
# Server returns 201 + JSON envelope: stored_as, label, bytes, sha256,
# remaining_uses. We log the envelope as a single signal and rm the outer
# tarball on success (the bundle dir itself is preserved for local IR).
###############################################################################

phase_upload() {
    (( DO_UPLOAD )) || return 0
    hdr "upload" "submitting bundle to $INTAKE_URL"

    if (( ! DO_BUNDLE )); then
        say_warn "--no-bundle precludes upload (nothing was captured)"
        emit_signal upload warn upload_no_bundle "--no-bundle was set; skipping upload"
        return
    fi
    if [[ -z "${BUNDLE_BDIR:-}" || ! -d "$BUNDLE_BDIR" ]]; then
        say_warn "no bundle directory present; skipping upload"
        emit_signal upload warn upload_no_bundle_dir "BUNDLE_BDIR unset or missing"
        return
    fi
    if ! have_cmd curl; then
        say_fail "curl(1) not in PATH; cannot upload"
        emit_signal upload fail upload_no_curl "curl is required for --upload"
        return
    fi
    if [[ -z "$INTAKE_TOKEN" ]]; then
        say_fail "no upload token resolved (this should not happen)"
        emit_signal upload fail upload_no_token "INTAKE_TOKEN empty"
        return
    fi

    # Re-archive the bundle directory into a single outer tarball. The
    # individual tarballs inside are already gzipped; tar -cz over them
    # yields very little extra compression but produces one upload artifact
    # per host with valid gzip magic on the outer wrapper.
    local outer="${BUNDLE_BDIR}.upload.tgz"
    if ! tar -C "$BUNDLE_DIR_ROOT" -czf "$outer" "$(basename "$BUNDLE_BDIR")" 2>/dev/null; then
        say_fail "outer tarball build failed: $outer"
        emit_signal upload fail upload_tar_failed "tar -czf $outer"
        return
    fi
    chmod 0600 "$outer" 2>/dev/null
    local outer_size
    outer_size=$(du -sh "$outer" 2>/dev/null | awk '{print $1}')
    say_info "outer tarball: $outer ($outer_size)"

    # PUT to the intake. --max-time 1800 = 30 minute hard ceiling for slow
    # links. -w embeds the response code as a sentinel line so we can split
    # body from status without a second curl call. The token is sent in a
    # header only - never on the command line where ps could see it.
    local resp body http_code rc
    resp=$(curl --silent --show-error \
                --max-time 1800 \
                -H "X-Upload-Token: $INTAKE_TOKEN" \
                -T "$outer" \
                -w '\n__INTAKE_HTTP__=%{http_code}' \
                "$INTAKE_URL" 2>&1)
    rc=$?
    http_code=$(printf '%s' "$resp" | grep -oE '__INTAKE_HTTP__=[0-9]+' | tail -1 | cut -d= -f2)
    body=$(printf '%s' "$resp" | sed -E 's/^__INTAKE_HTTP__=[0-9]+$//' \
           | grep -v '^$' | head -c 2048)

    if (( rc != 0 )) || [[ "$http_code" != "201" ]]; then
        say_fail "upload failed (curl_rc=$rc http=${http_code:-?})"
        [[ -n "$body" ]] && say_fail "  response: $body"
        emit_signal upload fail upload_failed \
            "curl_rc=$rc http=${http_code:-?}" \
            curl_rc "$rc" http_code "${http_code:-}" body "$body"
        # Leave the outer tarball on disk so the operator can retry manually.
        say_info "outer tarball preserved at $outer for manual retry"
        return
    fi

    say_pass "uploaded: http=201"
    [[ -n "$body" ]] && say_info "  $body"
    emit_signal upload info upload_complete \
        "http=201 url=$INTAKE_URL" \
        url "$INTAKE_URL" body "$body" outer "$outer"

    # Success: drop the outer tarball; the bundle dir itself is kept for
    # local IR review.
    rm -f "$outer"
}

###############################################################################
# Run
###############################################################################

# When chained from ioc-scan, ioc-scan already printed the section header
# and host metadata. Suppress our banner to avoid duplicate noise; the
# chain context is unambiguous from SESSIONSCRIBE_IOC_JSON.
if (( ! QUIET )) && [[ -z "${SESSIONSCRIBE_IOC_JSON:-}" ]]; then
    printf '\n%ssessionscribe-forensic%s v%s - %s kill-chain reconstruction\n' \
        "$C_BLD" "$C_NC" "$VERSION" "$INCIDENT_ID" >&2
    printf '  host: %s    os: %s    cpanel: %s\n' \
        "$HOSTNAME_FQDN" "$OS_PRETTY" "${CPANEL_NORM:-unknown}" >&2
    printf '  ts: %s    run_id: %s\n' "$TS_ISO" "$RUN_ID" >&2
    cap_human="${MAX_BUNDLE_MB}MB"
    (( MAX_BUNDLE_MB == 0 )) && cap_human="unlimited"
    if [[ -n "$SINCE_EPOCH" ]]; then
        printf '  window: %s days (since %s)    bundle cap: %s\n' \
            "$SINCE_DAYS" "$(date -u -d @"$SINCE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" \
            "$cap_human" >&2
    else
        printf '  window: unlimited (all retained data)    bundle cap: %s\n' \
            "$cap_human" >&2
    fi
    printf '  legend: %s[OK]%s clean  %s[DEF-OK]%s defense present (good)  %s[DEF-MISS]%s defense absent (bad)  %s[IOC]%s compromise indicator (BAD)\n' \
        "$C_GRN" "$C_NC" "$C_GRN" "$C_NC" "$C_YEL" "$C_NC" "$C_RED" "$C_NC" >&2
fi

phase_defense
phase_offense
phase_reconcile
phase_bundle
phase_upload

###############################################################################
# Final summary
###############################################################################

N_DEF=${#DEFENSE_EVENTS[@]}
N_OFF=${#OFFENSE_EVENTS[@]}

hdr "summary" "kill-chain reconstruction"
if (( ! QUIET )); then
    printf '  defenses_extracted=%d  iocs_found=%d  pre_defense=%d  post_defense=%d\n' \
        "$N_DEF" "$N_OFF" "$N_PRE" "$N_POST" >&2
fi

# Build a final summary signal.
final_verdict="CLEAN"
final_exit=0
if (( N_OFF > 0 )); then
    if (( N_PRE > 0 )); then
        final_verdict="COMPROMISED_PRE_DEFENSE"
        final_exit=2
    else
        final_verdict="COMPROMISED_POST_DEFENSE"
        final_exit=1
    fi
fi

emit_signal summary info verdict "$final_verdict" \
    iocs_total "$N_OFF" \
    pre_defense "$N_PRE" \
    post_defense "$N_POST" \
    defenses_extracted "$N_DEF"

# JSON envelope mode - assemble all signals into one document.
if (( JSON_OUT )); then
    {
        printf '{'
        printf '"host":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s",' \
            "$HOSTNAME_J" "$LP_UID_J" "$OS_J" "$CPV_J" "$TS_ISO"
        printf '"tool":"sessionscribe-forensic","tool_version":"%s","mode":"forensic","incident_id":"%s","run_id":"%s",' \
            "$VERSION" "$INCIDENT_ID" "$RUN_ID"
        printf '"verdict":"%s",' "$final_verdict"
        printf '"defenses_extracted":%d,"iocs_found":%d,"pre_defense":%d,"post_defense":%d,' \
            "$N_DEF" "$N_OFF" "$N_PRE" "$N_POST"
        printf '"signals":['
        first=1
        for s in "${SIGNALS[@]}"; do
            (( first )) || printf ','
            printf '%s' "$s"
            first=0
        done
        printf ']}'
        printf '\n'
    } > "${OUTPUT_FILE:-/dev/stdout}"
fi

if (( ! QUIET )); then
    printf '\n  verdict: %s\n' "$final_verdict" >&2
fi

exit "$final_exit"
