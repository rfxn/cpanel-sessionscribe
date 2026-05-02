#!/bin/bash
#
##
# sessionscribe-forensic.sh v0.10.1
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

VERSION="0.11.0"
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
# (All other Pattern A/B/C/D/F/H constants moved to ioc-scan; this script
# consumes their detection results via the run envelope.)
PATTERN_A_BINARY="/root/sshd"

# Pattern H seobot dropper file - matched against every cPanel docroot
# during phase_bundle for explicit capture into pattern-h-seobot-metadata.txt.
PATTERN_H_DROPPER_FILE="seobot.php"

# Pattern I (IC-5794, surfaced 2026-05-01) - file paths mirrored from the
# ioc-scan PATTERN_I_* constants for offline-bundle metadata capture. The
# binary itself is NOT bundled (mirrors the Pattern A safety policy:
# capture stat + sha256, not the executable).
PATTERN_I_BINARY="/root/.local/bin/system-service"
PATTERN_I_PROFILED="/etc/profile.d/system_profiled_service.sh"

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
# Primary IPv4 - cheap independent tiebreaker for bundles where FQDN is
# stale or generic (localhost.localdomain, post-restore hosts, default
# provider templates). `hostname -I` first (BSD/RHEL/Debian portable);
# fall back to iproute2 for hosts where -I is missing or empty.
PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$PRIMARY_IP" ]] && PRIMARY_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[[ -z "$PRIMARY_IP" ]] && PRIMARY_IP=unknown
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

# Glyph table - unicode for UTF-8 TTYs, ASCII fallback otherwise. Detection
# checks LANG/LC_ALL/LC_CTYPE for a UTF-8 indication AND requires stderr be
# a TTY (so piped output `forensic | grep` and `LANG=C` consoles get plain
# ASCII). The bundle's kill-chain.md inherits whichever set was active at
# render time; both render legibly in modern editors and `less -R`.
if [[ -t 2 ]] && [[ "${LC_ALL:-}${LANG:-}${LC_CTYPE:-}" =~ [Uu][Tt][Ff]-?8 ]]; then
    GLYPH_BOX_TL='┌'; GLYPH_BOX_TR='┐'; GLYPH_BOX_BL='└'; GLYPH_BOX_BR='┘'
    GLYPH_BOX_H='─'; GLYPH_BOX_V='│'
    GLYPH_OFFENSE='⚡'; GLYPH_DEFENSE='✓'; GLYPH_ARROW='↳'
    GLYPH_OK='✓';     GLYPH_BAD='✗';     GLYPH_WARN='⚠'
    GLYPH_ELLIPSIS='…'; GLYPH_TIMES='×'
else
    GLYPH_BOX_TL='+'; GLYPH_BOX_TR='+'; GLYPH_BOX_BL='+'; GLYPH_BOX_BR='+'
    GLYPH_BOX_H='-'; GLYPH_BOX_V='|'
    GLYPH_OFFENSE='!'; GLYPH_DEFENSE='+'; GLYPH_ARROW='->'
    GLYPH_OK='+';     GLYPH_BAD='x';     GLYPH_WARN='!'
    GLYPH_ELLIPSIS='...'; GLYPH_TIMES='x'
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
PRIMARY_IP_J=$(json_esc "$PRIMARY_IP")
OS_J=$(json_esc "$OS_PRETTY")
CPV_J=$(json_esc "$CPANEL_NORM")
LP_UID_J=$(json_esc "$LP_UID")

# Per-finding accumulators. Module-scope arrays - `declare -a` is enough;
# `-g` (bash 4.2+) is unnecessary here and breaks bash 4.1 (CloudLinux 6).
declare -a SIGNALS=()
declare -a DEFENSE_EVENTS=()   # "epoch|key|note"
declare -a OFFENSE_EVENTS=()   # "epoch|pattern|key|note|defenses_required"
declare -a RECONCILED=()       # "verdict|delta_seconds|epoch|pattern|key"

# Parallel to OFFENSE_EVENTS (same index). One row per IOC carrying the
# forensic primitives we surface in the pretty kill-chain renderer and
# persist into the bundle for offline reconstruction. Fields are joined
# with ASCII US (0x1f) so consecutive empties survive `read` (whitespace
# IFS collapses adjacent separators; US is non-whitespace so it doesn't).
# Columns: area | ip | path | log_file | count | hits_2xx | status | line
# Bundle TSV output uses real TABs - this is internal-only.
PRIM_SEP=$'\x1f'
declare -a IOC_PRIMITIVES=()

# Per-row annotations indexed parallel to OFFENSE_EVENTS / RECONCILED.
# Currently populated only for Pattern E websocket-shell rows: holds the
# `dimensions` envelope field (e.g. "24x80:18,24x200:1") when present.
# Empty string for any row without dimension data. Read by
# render_offense_row to append "(dim: ...)" to the detail.
declare -a IOC_ANNOTATIONS=()

# Envelope-root metadata (populated by read_envelope_meta when chained from
# ioc-scan via $SESSIONSCRIBE_IOC_JSON). These are the canonical IOC verdict
# fields - forensic inherits them rather than re-deriving.
ENV_HOST_VERDICT=""
ENV_CODE_VERDICT=""
ENV_SCORE=""
ENV_IOC_TOOL_VERSION=""
ENV_IOC_RUN_ID=""
ENV_IOC_TS=""
ENV_STRONG=""
ENV_FIXED=""
ENV_INCONCLUSIVE=""
ENV_IOC_CRITICAL=""
ENV_IOC_REVIEW=""

# Captured pretty-print of the kill chain (ANSI-stripped) for the bundle
# kill-chain.md sibling. Populated by render_kill_chain.
KILL_CHAIN_RENDERED=""

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
    line=$(printf '{"host":"%s","primary_ip":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-forensic","tool_version":"%s","mode":"forensic","incident_id":"%s","run_id":"%s","phase":"%s","severity":"%s","key":"%s","note":"%s"%s}' \
        "$HOSTNAME_J" "$PRIMARY_IP_J" "$LP_UID_J" "$OS_J" "$CPV_J" "$TS_ISO" "$VERSION" "$INCIDENT_ID" "$RUN_ID" \
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

# Pipe-delimited record decoder for record shapes whose LAST field is
# free-form text that may legitimately contain '|' (notes carrying
# access_log lines, paths, attacker payloads, CRLF-injected session
# attributes). Avoids the silent truncation that bare
# `IFS='|' read -r f1 f2 ... fLAST` produces when the last field has
# embedded pipes.
#
# Usage:
#   IFS=$'\t' read -r f1 f2 ... fN < <(decode_pipe_tail "$record" N)
#
# Output: NFIELDS values TAB-separated on stdout (no trailing newline).
# The first NFIELDS-1 fields map 1:1 with parts[0..NFIELDS-2]; the
# Nth field absorbs parts[NFIELDS-1..end] re-joined with '|'.
#
# Why TAB as output separator: forensic record fields (epochs, key
# tokens, notes from log lines / paths / IOC values) are not expected
# to contain a literal TAB. If a future record ever does, the failure
# mode is a partial decode at the call site, not silent truncation.
#
# Bash 4.1 / EL6 floor compatible (array slice + local IFS for join
# are 3.0+; printf is POSIX).
decode_pipe_tail() {
    local _rec="$1" _nfields="$2"
    local -a _parts
    IFS='|' read -r -a _parts <<< "$_rec"
    local _i
    for (( _i = 0; _i < _nfields - 1; _i++ )); do
        printf '%s\t' "${_parts[_i]:-}"
    done
    if (( ${#_parts[@]} >= _nfields )); then
        local IFS='|'
        printf '%s' "${_parts[*]:_nfields-1}"
    fi
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
        # Verify actual iptables state (cohort observation: csf.conf
        # can be clean but iptables wasn't reloaded - false sense of
        # defense). cPanel/CSF
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

# Map ioc-scan emit key -> IC-5790 Pattern letter for OFFENSE_EVENTS.
# Vocabulary aligns with the dossier (Patterns A-I); init/X/? are pseudo-
# patterns for recon, exploitation evidence, and unmapped keys respectively.
ioc_key_to_pattern() {
    case "$1" in
        ioc_pattern_a_*)            echo A ;;
        ioc_pattern_b_*)            echo B ;;
        ioc_pattern_c_*)            echo C ;;
        ioc_pattern_d_*)            echo D ;;
        ioc_pattern_e_*)            echo E ;;
        ioc_pattern_f_*)            echo F ;;
        ioc_pattern_g_*)            echo G ;;
        ioc_pattern_h_*)            echo H ;;
        ioc_pattern_i_*)            echo I ;;
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

# Extract a root-level (NOT signal-array) JSON field from a pretty-printed
# envelope. Used to read the envelope's host_verdict / score / etc. without
# descending into the signals[] array (where the same field name may
# collide). ioc-scan emits each root field on its own line, but we accept
# the field anywhere outside a signal row by skipping any line that starts
# with `{"host":` (signal rows). String and numeric values are both handled.
envelope_root_field() {
    local env="$1" key="$2" raw v
    raw=$(grep -vE '^[[:space:]]*\{\"host\":' "$env" 2>/dev/null \
          | grep -oE "\"${key}\":[[:space:]]*(\"[^\"]*\"|-?[0-9]+(\.[0-9]+)?)" \
          | head -1)
    [[ -z "$raw" ]] && return 0
    v="${raw#*:}"
    v="${v# }"
    v="${v#\"}"
    v="${v%\"}"
    printf '%s' "$v"
}

# Populate ENV_* globals from the envelope's root section. Cheap (a handful
# of grep + parameter-expansion calls). Idempotent - safe to call twice.
read_envelope_meta() {
    local env="${SESSIONSCRIBE_IOC_JSON:-}"
    [[ -n "$env" && -f "$env" ]] || return 0
    ENV_HOST_VERDICT=$(envelope_root_field "$env" host_verdict)
    ENV_CODE_VERDICT=$(envelope_root_field "$env" code_verdict)
    ENV_SCORE=$(envelope_root_field "$env" score)
    ENV_IOC_TOOL_VERSION=$(envelope_root_field "$env" tool_version)
    ENV_IOC_RUN_ID=$(envelope_root_field "$env" run_id)
    ENV_IOC_TS=$(envelope_root_field "$env" ts)
    # summary block lives on a single line: "summary": {"strong":N,...},
    local summary
    summary=$(grep -E '^[[:space:]]+"summary":' "$env" 2>/dev/null | head -1)
    if [[ -n "$summary" ]]; then
        ENV_STRONG=$(echo "$summary"        | grep -oE '"strong":[0-9]+'        | cut -d: -f2)
        ENV_FIXED=$(echo "$summary"         | grep -oE '"fixed":[0-9]+'         | cut -d: -f2)
        ENV_INCONCLUSIVE=$(echo "$summary"  | grep -oE '"inconclusive":[0-9]+'  | cut -d: -f2)
        ENV_IOC_CRITICAL=$(echo "$summary"  | grep -oE '"ioc_critical":[0-9]+'  | cut -d: -f2)
        ENV_IOC_REVIEW=$(echo "$summary"    | grep -oE '"ioc_review":[0-9]+'    | cut -d: -f2)
    fi
}

# Build an internal-format primitives row for IOC_PRIMITIVES. US-delimited
# (0x1f) so empty middle fields don't collapse on `IFS=US read`. Embedded
# tabs/newlines in `line` are squashed to single spaces so the bundle TSV
# output stays well-formed when this row is later expanded.
ioc_primitive_row() {
    local area="$1" ip="$2" path="$3" log_file="$4" count="$5" h2xx="$6" status="$7" line="$8"
    local clean="${line//$'\t'/ }"
    clean="${clean//$'\n'/ }"
    clean="${clean//$'\r'/ }"
    printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s' \
        "${area:-}"     "$PRIM_SEP" \
        "${ip:-}"       "$PRIM_SEP" \
        "${path:-}"     "$PRIM_SEP" \
        "${log_file:-}" "$PRIM_SEP" \
        "${count:-}"    "$PRIM_SEP" \
        "${h2xx:-}"     "$PRIM_SEP" \
        "${status:-}"   "$PRIM_SEP" \
        "$clean"
}

# Read kill-chain-relevant signals from $SESSIONSCRIBE_IOC_JSON and append
# to OFFENSE_EVENTS in the shape phase_reconcile expects:
#   "epoch|pattern|key|note|defenses_required"
# Also captures envelope-root metadata + per-IOC primitives (ip / path /
# log_file / count / hits_2xx / status / line excerpt) into IOC_PRIMITIVES,
# parallel-indexed with OFFENSE_EVENTS, for the kill-chain renderer + bundle.
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

    read_envelope_meta

    local line area severity key note ts pattern n_added=0
    local p_ip p_path p_log p_count p_h2xx p_status p_line p_row
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
        pattern=$(ioc_key_to_pattern "$key")
        # Forensic primitives - one of these is usually populated per signal,
        # depending on the area:
        #   logs       -> ip, log_file, line, status, count, hits_2xx
        #   sessions   -> path, ip, count
        #   destruction -> path, file_mtime
        p_ip=$(json_str_field "$line" ip)
        [[ -z "$p_ip" ]] && p_ip=$(json_str_field "$line" src_ip)
        p_path=$(json_str_field "$line" path)
        [[ -z "$p_path" ]] && p_path=$(json_str_field "$line" file)
        p_log=$(json_str_field "$line" log_file)
        p_count=$(json_num_field "$line" count)
        p_h2xx=$(json_num_field "$line" hits_2xx)
        p_status=$(json_str_field "$line" status)
        p_line=$(json_str_field "$line" line)
        p_row=$(ioc_primitive_row "$area" "$p_ip" "$p_path" "$p_log" "$p_count" "$p_h2xx" "$p_status" "$p_line")

        # Per-row annotation: Pattern E websocket-shell rows carry a
        # `dimensions` envelope field (rows×cols breakout). Captured
        # parallel-indexed in IOC_ANNOTATIONS for the renderer.
        local p_anno=""
        if [[ "$key" == "ioc_pattern_e_websocket_shell_hits" ]]; then
            p_anno=$(json_str_field "$line" dimensions)
        fi

        OFFENSE_EVENTS+=("$ts|$pattern|$key|${note:-$key}|patch,modsec")
        IOC_PRIMITIVES+=("$p_row")
        IOC_ANNOTATIONS+=("$p_anno")
        n_added=$((n_added+1))
        emit_signal offense fail "$key" "${note:-$key}" \
            epoch "$ts" pattern "$pattern" envelope "$(basename "$env")"
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
                if [[ -n "$ctime_pre" ]]; then
                    OFFENSE_EVENTS+=("$ctime_pre|G|pattern_g_forged_mtime|backdated ssh key|patch,modsec")
                    IOC_PRIMITIVES+=("$(ioc_primitive_row destruction "" "$ak" "" "" "" "" "mtime forged to $PATTERN_G_FORGED_MTIME_WALL")")
                    IOC_ANNOTATIONS+=("")
                fi
            fi
        fi

        # ctime is the stronger signal - touch can't backdate ctime.
        local susp_count=0 line comment is_known_bad bad bad_label
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            # Extract the full multi-word comment field (fields 3..end of
            # `<keytype> <base64> <comment...>`). The prior `awk '{print $NF}'`
            # only returned the last token, breaking the SSH_KNOWN_GOOD_RE
            # whitelist on multi-word comments like
            # "Parent Child key for W9Z2DL" - LW provisioning keys were
            # being flagged as Pattern G IOCs because $NF returned just
            # "W9Z2DL", which doesn't match any known-good prefix.
            comment=$(awk 'NF>=3 {sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, ""); print}' <<< "$line")
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
            if [[ -n "$ctime_pre" ]]; then
                OFFENSE_EVENTS+=("$ctime_pre|G|pattern_g_sshkey|non-standard ssh key (ctime)|patch,modsec")
                IOC_PRIMITIVES+=("$(ioc_primitive_row destruction "" "$ak" "" "$susp_count" "" "" "non-standard ssh key comments")")
                IOC_ANNOTATIONS+=("")
            fi
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
        local f m c f_total f_known f_unknown
        while IFS= read -r f; do
            [[ -z "$f" ]] && continue
            # Filter out files where every ssh-* line is a known-good LW
            # provisioning key (Parent Child key for <PJID>, lwadmin,
            # liquidweb, nexcess). Legitimate placements in /etc and
            # /var/spool/cron should not surface as Pattern G IOCs.
            f_total=$(grep -cE 'ssh-(rsa|ed25519|ecdsa|dss)[[:space:]]+[A-Za-z0-9+/=]{20,}' "$f" 2>/dev/null)
            f_total="${f_total:-0}"
            if (( f_total > 0 )); then
                f_known=$(grep -cE "ssh-(rsa|ed25519|ecdsa|dss)[[:space:]]+[A-Za-z0-9+/=]{20,}.*${SSH_KNOWN_GOOD_RE}" "$f" 2>/dev/null)
                f_known="${f_known:-0}"
                f_unknown=$(( f_total - f_known ))
                (( f_unknown <= 0 )) && continue
            fi
            m=$(stat -c %Y "$f" 2>/dev/null)
            c=$(stat -c %Z "$f" 2>/dev/null)
            say_ioc "PATTERN-G: ssh key material in non-canonical location: $f"
            emit_signal offense fail pattern_g_offpath_key \
                "ssh-rsa/ed25519 in $f (out of band of ~/.ssh)" \
                file "$f" mtime_epoch "$m" ctime_epoch "$c"
            if [[ -n "$c" ]]; then
                OFFENSE_EVENTS+=("$c|G|pattern_g_offpath|ssh key in non-canonical path|patch,modsec")
                IOC_PRIMITIVES+=("$(ioc_primitive_row destruction "" "$f" "" "" "" "" "ssh key out of ~/.ssh")")
                IOC_ANNOTATIONS+=("")
            fi
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
# Kill-chain renderer - presents the reconstructed kill chain in a single
# operator-readable view (defense timeline + offense timeline + verdict +
# defense lag), plus a captured ANSI-stripped copy for the bundle.
#
# All output goes to stderr (like the rest of the sectioned report) so it
# never contaminates --jsonl/--json on stdout. Suppressed under --quiet.
###############################################################################

# Order patterns canonically for the offense timeline. init is the recon
# pre-cursor; A-I map to the IC-5790 dossier Pattern letters; X is forged-
# session evidence that doesn't fit a destruction pattern; ? is anything
# unmapped (a runtime ioc_key_to_pattern gap).
PATTERN_ORDER=(init A B C D E F G H I X "?")
declare -A PATTERN_LABEL=(
    [init]="recon / harvest"
    [A]="ransom / encryptor"
    [B]="data destruction"
    [C]="malware deploy"
    [D]="persistence (reseller token)"
    [E]="websocket / fileman harvest"
    [F]="harvester shell"
    [G]="ssh key persistence"
    [H]="seobot defacement / SEO spam"
    [I]="system-service profile.d backdoor"
    [X]="forged session"
    ["?"]="unmapped"
)

# Strip CSI sequences from a string. Used to capture an ANSI-free copy of
# the rendered kill chain for kill-chain.md inside the bundle. Bash 4.1
# safe (no `${var//pat/repl}` extended regex requirement; uses sed -r).
ansi_strip() {
    sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g'
}

# Format an IOC primitives row into a single detail string for the
# compact renderer. Pulls the most-discriminating field in priority order:
# ip+count+status > path > note. Truncates path/note to keep the renderer
# one-line-per-IOC. Bundle's kill-chain.tsv carries the full primitives.
fmt_offense_detail() {
    local ip="$1" path="$2" count="$3" status="$4" note="$5"
    local d=""
    if [[ -n "$ip" ]]; then
        d="$ip"
        if [[ -n "$count" && "$count" =~ ^[0-9]+$ && "$count" -gt 1 ]]; then
            d="$d ${GLYPH_TIMES}$count"
        fi
        [[ -n "$status" ]] && d="$d $status"
    elif [[ -n "$path" ]]; then
        if (( ${#path} > 50 )); then
            d="${path:0:24}${GLYPH_ELLIPSIS}${path: -25}"
        else
            d="$path"
        fi
    elif [[ -n "$note" ]]; then
        if (( ${#note} > 60 )); then
            d="${note:0:60}${GLYPH_ELLIPSIS}"
        else
            d="$note"
        fi
    fi
    printf '%s' "$d"
}

# Render one offense row in compact single-line form for the chronological
# tree. Caller passes the decomposed reconcile fields and the matching
# IOC_PRIMITIVES TSV row.
# Layout: │ TS  ⚡ pattern X    key                       detail
render_offense_row() {
    local verdict="$1" delta="$2" ts_iso="$3" pattern="$4" key="$5" note="$6" prims="$7" anno="${8:-}"
    local color
    case "$verdict" in
        PRE-DEFENSE|UNDEFENDED) color="$C_RED" ;;
        POST-DEFENSE)           color="$C_GRN" ;;
        POST-PARTIAL)           color="$C_YEL" ;;
        *)                      color="$C_DIM" ;;
    esac

    local area ip path log_file count h2xx status line
    IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line <<< "$prims"
    local detail
    detail=$(fmt_offense_detail "$ip" "$path" "$count" "$status" "$note")
    # Append per-row annotation when populated (e.g. Pattern E dimensions).
    [[ -n "$anno" ]] && detail+="  (dim: $anno)"

    # Pattern column padded to 4 (covers "init"). Key column padded to 22.
    printf '  %s%s%s  %s  %s%s%s pattern %-4s  %s%-22s%s  %s\n' \
        "$C_DIM" "$GLYPH_BOX_V" "$C_NC" \
        "$ts_iso" \
        "$color" "$GLYPH_OFFENSE" "$C_NC" \
        "$pattern" \
        "$C_CYN" "$key" "$C_NC" \
        "$detail"
}

# Render one defense-event row in the same compact form as offense rows.
render_defense_row() {
    local ts_iso="$1" key="$2" note="$3"
    local note_trim="$note"
    if (( ${#note_trim} > 60 )); then
        note_trim="${note_trim:0:60}${GLYPH_ELLIPSIS}"
    fi
    printf '  %s%s%s  %s  %s%s%s DEFENSE     %s%-22s%s  %s\n' \
        "$C_DIM" "$GLYPH_BOX_V" "$C_NC" \
        "$ts_iso" \
        "$C_GRN" "$GLYPH_DEFENSE" "$C_NC" \
        "$C_BLD" "$key" "$C_NC" \
        "$note_trim"
}

# Aggregate attacker IPs from IOC_PRIMITIVES + RECONCILED. Sets globals
# consumed by the HEADLINE renderer:
#   ATTACKER_IP_PLAIN          space-separated top-N for copy-paste
#   ATTACKER_IP_ANNOTATED[]    array of "ip ×count [stages]" annotated forms
#   ATTACKER_IP_OVERFLOW       "+N more — see kill-chain.md", empty if <=top_n
#   ATTACKER_IP_TOTAL          count of unique IPs across the chain
# Sort order: hit-count desc, first-seen epoch asc tiebreak. Top 5 inline,
# remainder rolled into the overflow line - the bundle's kill-chain.md
# carries the full enumerated list (sorted same way).
aggregate_attacker_ips() {
    ATTACKER_IP_PLAIN=""
    ATTACKER_IP_ANNOTATED=()
    ATTACKER_IP_OVERFLOW=""
    ATTACKER_IP_TOTAL=0

    declare -A ip_count ip_stages ip_first

    local idx
    for (( idx=0; idx<${#IOC_PRIMITIVES[@]}; idx++ )); do
        local prims="${IOC_PRIMITIVES[$idx]:-}"
        local rec="${RECONCILED[$idx]:-}"
        [[ -z "$prims" || -z "$rec" ]] && continue

        local area ip path log_file count h2xx status line
        IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line <<< "$prims"
        [[ -z "$ip" ]] && continue

        local r_verdict r_delta r_epoch r_stage r_key r_note
        IFS=$'\t' read -r r_verdict r_delta r_epoch r_stage r_key r_note \
            < <(decode_pipe_tail "$rec" 6)

        # Hit count = count primitive when numeric (multi-hit IOC), else 1.
        local hits=1
        [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]] && hits="$count"
        ip_count[$ip]=$(( ${ip_count[$ip]:-0} + hits ))

        # Track stages per IP, deduped via comma-bracketed substring match.
        local prev="${ip_stages[$ip]:-}"
        if [[ ",$prev," != *",$r_stage,"* ]]; then
            ip_stages[$ip]="${prev:+$prev,}$r_stage"
        fi

        if [[ -z "${ip_first[$ip]:-}" ]] || (( r_epoch < ${ip_first[$ip]} )); then
            ip_first[$ip]="$r_epoch"
        fi
    done

    ATTACKER_IP_TOTAL="${#ip_count[@]}"
    (( ATTACKER_IP_TOTAL == 0 )) && return 0

    local sorted
    sorted=$(
        local _ip
        for _ip in "${!ip_count[@]}"; do
            printf '%d\t%d\t%s\n' "${ip_count[$_ip]}" "${ip_first[$_ip]:-0}" "$_ip"
        done | sort -k1,1nr -k2,2n
    )

    local top_n=5 i=0
    local plain=()
    local _cnt _first _ip
    while IFS=$'\t' read -r _cnt _first _ip; do
        [[ -z "$_ip" ]] && continue
        if (( i < top_n )); then
            plain+=("$_ip")
            ATTACKER_IP_ANNOTATED+=("$(printf '%s %s%d [%s]' "$_ip" "$GLYPH_TIMES" "$_cnt" "${ip_stages[$_ip]}")")
        fi
        (( i++ ))
    done <<< "$sorted"

    ATTACKER_IP_PLAIN="${plain[*]}"
    if (( ATTACKER_IP_TOTAL > top_n )); then
        local sep="--"
        [[ "$GLYPH_BOX_H" == "─" ]] && sep="—"
        ATTACKER_IP_OVERFLOW=$(printf '+%d more %s see kill-chain.md for full list' \
            "$(( ATTACKER_IP_TOTAL - top_n ))" "$sep")
    fi
}

# Format a delta of seconds into "Xd Yh" / "Xh Ym" / "Xm Ys" / "Xs".
fmt_delta_human() {
    local abs="$1"
    (( abs < 0 )) && abs=$(( -abs ))
    if   (( abs >= 86400 )); then printf '%dd %dh' "$(( abs / 86400 ))" "$(( (abs % 86400) / 3600 ))"
    elif (( abs >= 3600  )); then printf '%dh %dm' "$(( abs / 3600 ))"  "$(( (abs % 3600) / 60 ))"
    elif (( abs >= 60    )); then printf '%dm %ds' "$(( abs / 60 ))"    "$(( abs % 60 ))"
    else                          printf '%ds' "$abs"
    fi
}

render_kill_chain() {
    (( QUIET )) && return 0

    # Aggregate attacker IPs once for the HEADLINE section. Walks
    # IOC_PRIMITIVES + RECONCILED; sets ATTACKER_IP_* globals.
    aggregate_attacker_ips

    # Build a single chronologically-merged event list (defense + offense)
    # so the timeline reads as one story instead of two parallel sections.
    # Each entry: epoch \t kind \t payload, where kind is DEF or OFF and
    # payload is the index into DEFENSE_EVENTS or RECONCILED.
    # Group both loops in `{ ... }` so the trailing `| sort` applies to the
    # combined output, not just the second loop. Without the brace group,
    # bash parses the pipe as binding to the immediately preceding compound
    # statement, leaving DEFENSE rows unsorted in front of OFFENSE rows.
    local merged
    merged=$(
        {
            local _i _ts _rec _de
            for (( _i=0; _i<${#DEFENSE_EVENTS[@]}; _i++ )); do
                _de="${DEFENSE_EVENTS[$_i]}"
                _ts=$(printf '%s' "$_de" | cut -d'|' -f1)
                [[ -z "$_ts" ]] && continue
                printf '%s\tDEF\t%d\n' "$_ts" "$_i"
            done
            for (( _i=0; _i<${#RECONCILED[@]}; _i++ )); do
                _rec="${RECONCILED[$_i]}"
                _ts=$(printf '%s' "$_rec" | cut -d'|' -f3)
                [[ -z "$_ts" ]] && continue
                printf '%s\tOFF\t%d\n' "$_ts" "$_i"
            done
        } | sort -n -k1,1
    )

    # Buffer the entire render once so we can both print to stderr AND
    # capture an ANSI-stripped copy for the bundle in a single pass.
    local buf
    buf=$({
        # ── Banner ──────────────────────────────────────────────────────
        # Open box: top has title embedded in a horizontal bar, bottom is
        # plain bar. Content lines have left bar only - skipping the right
        # close-bar avoids width-counting around variable-length FQDNs and
        # unicode combining chars.
        local W=72
        local title="CVE-2026-41940 / IC-5790"
        # Title takes (3 left bar+space) + len(title) + 1 trailing space
        # visual columns; remainder fills with horizontal bars.
        local title_used=$(( 4 + ${#title} ))
        local right_len=$(( W - title_used ))
        (( right_len < 4 )) && right_len=4
        local right_bar="" _bi
        for (( _bi=0; _bi<right_len; _bi++ )); do right_bar+="$GLYPH_BOX_H"; done
        local full_bar="" _bi2
        for (( _bi2=0; _bi2<W; _bi2++ )); do full_bar+="$GLYPH_BOX_H"; done

        # Verdict color + display text.
        local hv="${ENV_HOST_VERDICT:-}"
        local hv_color="$C_GRN" hv_text="$hv"
        case "$hv" in
            COMPROMISED) hv_color="$C_RED" ;;
            SUSPICIOUS)  hv_color="$C_YEL" ;;
            CLEAN)       hv_color="$C_GRN" ;;
            "")          hv_color="$C_DIM"; hv_text="(no envelope - re-run from ioc-scan for verdict)" ;;
        esac

        # Defense layer badges - inline glyphs (✓ up / ✗ absent / ⚠ dirty).
        local def_patch="$GLYPH_BAD absent" def_modsec="$GLYPH_BAD absent"
        local def_csf="$GLYPH_WARN dirty"   def_mitigate="$GLYPH_BAD never"
        [[ -n "$DEF_PATCH_TIME"     ]] && def_patch="$GLYPH_OK up"
        [[ -n "$DEF_MODSEC_TIME"    ]] && def_modsec="$GLYPH_OK up"
        [[ -n "$DEF_CSF_TIME"       ]] && def_csf="$GLYPH_OK clean"
        [[ -n "$DEF_MITIGATE_LAST"  ]] && def_mitigate="$GLYPH_OK ran"

        # Compose verdict + score + ioc-scan version into one column line.
        local verdict_line="$hv_text"
        [[ -n "$ENV_SCORE" ]]            && verdict_line+="   score $ENV_SCORE"
        [[ -n "$ENV_IOC_TOOL_VERSION" ]] && verdict_line+="   ioc-scan v$ENV_IOC_TOOL_VERSION"

        printf '\n%s%s%s%s %s%s%s %s%s%s\n' \
            "$C_BLD" "$GLYPH_BOX_TL" "$GLYPH_BOX_H" "$GLYPH_BOX_H" \
            "$C_BLD" "$title" "$C_NC" \
            "$C_BLD" "$right_bar" "$C_NC"
        printf '%s%s%s host         %s%s%s (%s)\n'   "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$C_BLD" "$HOSTNAME_FQDN" "$C_NC" "$PRIMARY_IP"
        printf '%s%s%s cpanel       %s   os %s\n'    "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "${CPANEL_NORM:-unknown}" "${OS_PRETTY:-unknown}"
        printf '%s%s%s verdict      %s%s%s\n'        "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$hv_color" "$verdict_line" "$C_NC"
        printf '%s%s%s defenses     patch %s   modsec %s   csf %s   mitigate %s\n' \
            "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$def_patch" "$def_modsec" "$def_csf" "$def_mitigate"
        printf '%s%s%s%s\n' "$C_BLD" "$GLYPH_BOX_BL" "$full_bar" "$C_NC"

        # ── Chronological tree ──────────────────────────────────────────
        # Single merged stream: defense + offense events, time-sorted, with
        # zone separators when verdict-class transitions (PRE→DEF→POST).
        if [[ -z "$merged" ]]; then
            printf '\n  %s%s no events to render (no offenses, no defenses)%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_NC"
        else
            # First pass: bucket merged entries into zones by current verdict
            # class. Zone IDs: pre / def / post / undef. Defense rows sit in
            # their own def zone; consecutive offense rows of same class
            # accumulate; class transitions emit a zone header before the
            # first row of the new zone with the zone size in the label.
            local _line _ts _kind _idx
            local zones=() rows=()
            local cur_zone="" cur_count=0 cur_first=-1

            # Pre-walk to compute zone boundaries + counts. We collect rows
            # into the rows[] array (one entry per event with all data baked
            # in) and zones[] as parallel "zone_id|first_row|last_row|count"
            # records, indexed by appearance order.
            local row_idx=0
            while IFS=$'\t' read -r _ts _kind _idx; do
                [[ -z "$_ts" ]] && continue
                local row_zone=""
                if [[ "$_kind" == "DEF" ]]; then
                    row_zone="def"
                else
                    local _rec="${RECONCILED[$_idx]}"
                    local _v
                    _v=$(printf '%s' "$_rec" | cut -d'|' -f1)
                    case "$_v" in
                        PRE-DEFENSE)             row_zone="pre"   ;;
                        UNDEFENDED)              row_zone="undef" ;;
                        POST-DEFENSE)            row_zone="post"  ;;
                        POST-PARTIAL)            row_zone="partial" ;;
                        *)                       row_zone="other" ;;
                    esac
                fi

                rows+=("$_ts|$_kind|$_idx|$row_zone")

                if [[ "$row_zone" != "$cur_zone" ]]; then
                    # Close previous zone if any.
                    if [[ -n "$cur_zone" ]]; then
                        zones+=("$cur_zone|$cur_first|$(( row_idx - 1 ))|$cur_count")
                    fi
                    cur_zone="$row_zone"
                    cur_first=$row_idx
                    cur_count=1
                else
                    cur_count=$(( cur_count + 1 ))
                fi
                row_idx=$(( row_idx + 1 ))
            done <<< "$merged"
            # Close the trailing zone.
            if [[ -n "$cur_zone" ]]; then
                zones+=("$cur_zone|$cur_first|$(( row_idx - 1 ))|$cur_count")
            fi

            # Second pass: emit zone headers + rows. Each zone starts with a
            # "── ZONE-LABEL (N events) ──" separator; rows render compactly.
            local zone_rec z_id z_first z_last z_count
            local r_str r_ts r_kind r_idx r_zone
            local row_i=0

            for zone_rec in "${zones[@]}"; do
                IFS='|' read -r z_id z_first z_last z_count <<< "$zone_rec"
                local z_color="$C_DIM" z_label="$z_id"
                case "$z_id" in
                    pre)     z_color="$C_RED";  z_label="PRE-DEFENSE"   ;;
                    undef)   z_color="$C_RED";  z_label="UNDEFENDED"    ;;
                    def)     z_color="$C_GRN";  z_label="DEFENSES"      ;;
                    post)    z_color="$C_GRN";  z_label="POST-DEFENSE"  ;;
                    partial) z_color="$C_YEL";  z_label="POST-PARTIAL"  ;;
                    *)       z_color="$C_DIM";  z_label="$z_id"         ;;
                esac
                local zone_count_str=""
                if [[ "$z_id" != "def" ]]; then
                    zone_count_str=$(printf ' (%d event%s)' "$z_count" "$( (( z_count == 1 )) && echo '' || echo s)")
                fi

                # Zone header line.
                printf '\n  %s%s%s  %s%s%s %s%s%s\n' \
                    "$C_DIM" "$GLYPH_BOX_V" "$C_NC" \
                    "$z_color$C_BLD" "${GLYPH_BOX_H}${GLYPH_BOX_H} $z_label$zone_count_str ${GLYPH_BOX_H}${GLYPH_BOX_H}" "$C_NC" \
                    "" "" ""

                # Emit rows in this zone.
                local r
                for (( r=z_first; r<=z_last; r++ )); do
                    r_str="${rows[$r]}"
                    IFS='|' read -r r_ts r_kind r_idx r_zone <<< "$r_str"
                    if [[ "$r_kind" == "DEF" ]]; then
                        local _de="${DEFENSE_EVENTS[$r_idx]}"
                        local de_epoch de_key de_note
                        IFS=$'\t' read -r de_epoch de_key de_note \
                            < <(decode_pipe_tail "$_de" 3)
                        render_defense_row "$(epoch_to_iso "$de_epoch")" "$de_key" "$de_note"
                    else
                        local _rec="${RECONCILED[$r_idx]}"
                        local _prims="${IOC_PRIMITIVES[$r_idx]:-}"
                        local _anno="${IOC_ANNOTATIONS[$r_idx]:-}"
                        local r_verdict r_delta r_epoch r_stage r_key r_note
                        IFS=$'\t' read -r r_verdict r_delta r_epoch r_stage r_key r_note \
                            < <(decode_pipe_tail "$_rec" 6)
                        render_offense_row "$r_verdict" "$r_delta" \
                            "$(epoch_to_iso "$r_epoch")" "$r_stage" "$r_key" \
                            "$r_note" "$_prims" "$_anno"
                    fi
                done
            done
        fi

        # ── HEADLINE ────────────────────────────────────────────────────
        # Verdict + defense lag + attacker IPs. The plain-IP line is the
        # copy-paste artifact - space-separated, no decorations, ready for
        # `csf -d`, ipset, or abuse-report pasting.
        printf '\n  %s%s %sHEADLINE%s\n' "$C_DIM" "$GLYPH_BOX_V" "$C_BLD" "$C_NC"

        # Verdict line.
        printf '  %s%s   verdict       %s%s%s' \
            "$C_DIM" "$GLYPH_BOX_V" "$hv_color" "${hv:-(no envelope)}" "$C_NC"
        [[ -n "$ENV_SCORE" ]] && printf '  (score %s)' "$ENV_SCORE"
        printf '\n'

        # Defense lag line. Computed from min(offense epoch) vs max(defense
        # epoch) - matches phase_reconcile's calculation.
        local min_off="" max_def="" _oe _de _ts
        for _oe in "${OFFENSE_EVENTS[@]}"; do
            _ts=$(printf '%s' "$_oe" | cut -d'|' -f1)
            [[ -z "$_ts" ]] && continue
            [[ -z "$min_off" ]] || (( _ts < min_off )) && min_off="$_ts"
        done
        for _de in "${DEFENSE_EVENTS[@]}"; do
            _ts=$(printf '%s' "$_de" | cut -d'|' -f1)
            [[ -z "$_ts" ]] && continue
            [[ -z "$max_def" ]] || (( _ts > max_def )) && max_def="$_ts"
        done
        if [[ -n "$min_off" && -n "$max_def" ]]; then
            local gap=$(( max_def - min_off ))
            local lag_color="$C_GRN" lag_word="EARLY"
            local tail_clause
            if (( gap > 0 )); then
                lag_color="$C_RED"; lag_word="LATE"
                tail_clause=$(printf 'first IOC %s, defense up %s later' \
                    "$(epoch_to_iso "$min_off")" "$(fmt_delta_human "$gap")")
            else
                tail_clause=$(printf 'defenses up %s before first IOC at %s' \
                    "$(fmt_delta_human "$gap")" "$(epoch_to_iso "$min_off")")
            fi
            printf '  %s%s   defense lag   %s%s %s%s  (%s)\n' \
                "$C_DIM" "$GLYPH_BOX_V" \
                "$lag_color" "$(fmt_delta_human "$gap")" "$lag_word" "$C_NC" \
                "$tail_clause"
        elif [[ -n "$max_def" && -z "$min_off" ]]; then
            printf '  %s%s   defense lag   %sEARLY%s  (defenses up, no IOCs reconciled)\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_GRN" "$C_NC"
        elif [[ -n "$min_off" && -z "$max_def" ]]; then
            printf '  %s%s   defense lag   %sno defense events captured%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_RED" "$C_NC"
        else
            printf '  %s%s   defense lag   %sno offense or defense events%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_DIM" "$C_NC"
        fi

        # Attacker IP line(s). Plain copyable string first, annotated form
        # below with ↳ glyph. Empty case prints "—" so grep always returns
        # one line per host.
        if (( ATTACKER_IP_TOTAL == 0 )); then
            local empty_reason="no source IPs in evidence"
            (( ${#OFFENSE_EVENTS[@]} == 0 )) && empty_reason="no offense events"
            (( ${#OFFENSE_EVENTS[@]} > 0 ))  && empty_reason="filesystem-only IOCs"
            printf '  %s%s   attackers     %s—  (%s)%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_DIM" "$empty_reason" "$C_NC"
        else
            printf '  %s%s   attackers     %s%s%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_BLD" "$ATTACKER_IP_PLAIN" "$C_NC"
            [[ -n "$ATTACKER_IP_OVERFLOW" ]] && \
                printf '  %s%s                 %s%s%s\n' \
                    "$C_DIM" "$GLYPH_BOX_V" "$C_DIM" "$ATTACKER_IP_OVERFLOW" "$C_NC"
            local ann
            for ann in "${ATTACKER_IP_ANNOTATED[@]}"; do
                printf '  %s%s                 %s%s%s %s\n' \
                    "$C_DIM" "$GLYPH_BOX_V" "$C_DIM" "$GLYPH_ARROW" "$C_NC" "$ann"
            done
        fi

        # ── Counters ────────────────────────────────────────────────────
        # Surface UNDEFENDED separately - rolled into N_PRE during reconcile
        # but the operator wants to see it broken out. Walk RECONCILED.
        local n_undef=0 _r _v
        for _r in "${RECONCILED[@]}"; do
            _v=$(printf '%s' "$_r" | cut -d'|' -f1)
            [[ "$_v" == "UNDEFENDED" ]] && n_undef=$(( n_undef + 1 ))
        done
        printf '\n  %scounters%s defenses=%d  iocs=%d  pre=%d  undef=%d  post=%d  attackers=%d\n' \
            "$C_BLD" "$C_NC" \
            "${#DEFENSE_EVENTS[@]}" "${#OFFENSE_EVENTS[@]}" \
            "$(( N_PRE - n_undef ))" "$n_undef" "$N_POST" "$ATTACKER_IP_TOTAL"
    } 2>&1)

    printf '%s\n' "$buf" >&2
    KILL_CHAIN_RENDERED=$(printf '%s\n' "$buf" | ansi_strip)
}

###############################################################################
# Kill-chain primitives writer - persists the inputs the renderer consumed
# into the bundle dir so the chain can be reconstructed offline (no need to
# re-run forensic on the host). Three siblings:
#
#   kill-chain.tsv    grep/awk-friendly: one row per IOC plus DEF-* rows
#   kill-chain.jsonl  one JSON object per row, machine-parseable
#   kill-chain.md     ANSI-stripped copy of render_kill_chain output for humans
#
# Called from phase_bundle so it lives next to the tarballs and is included
# in the outer upload tarball.
###############################################################################

write_kill_chain_primitives() {
    local bdir="${BUNDLE_BDIR:-}"
    [[ -z "$bdir" || ! -d "$bdir" ]] && return 0

    local tsv="$bdir/kill-chain.tsv"
    local jsonl="$bdir/kill-chain.jsonl"
    local md="$bdir/kill-chain.md"

    # Effective defense times mirror phase_reconcile's calculation - kept
    # local so we don't leak globals or re-shape RECONCILED.
    local eff_patch="" eff_modsec="$DEF_MODSEC_TIME"
    if [[ -n "$DEF_PATCH_TIME" && -n "$DEF_CPSRVD_RESTART" ]]; then
        if (( DEF_CPSRVD_RESTART >= DEF_PATCH_TIME )); then
            eff_patch="$DEF_CPSRVD_RESTART"
        fi
    fi

    # TSV header + DEF rows + IOC rows.
    {
        printf 'kind\tts_epoch\tts_iso\tpattern\tverdict\tdelta\tdefenses_at_ioc\tkey\tnote\tarea\tip\tpath\tlog_file\tcount\thits_2xx\tstatus\tline\n'

        # Defense rows.
        local de de_epoch de_key de_note _de_line
        local sorted_def
        sorted_def=$(
            local d
            for d in "${DEFENSE_EVENTS[@]}"; do printf '%s\n' "$d"; done | sort -t'|' -k1,1n
        )
        # Pipe-tolerant decode (notes may contain '|').
        while IFS= read -r _de_line; do
            [[ -z "$_de_line" ]] && continue
            IFS=$'\t' read -r de_epoch de_key de_note < <(decode_pipe_tail "$_de_line" 3)
            [[ -z "$de_epoch" ]] && continue
            printf 'DEF\t%s\t%s\t-\t-\t-\t-\t%s\t%s\t-\t\t\t\t\t\t\t\n' \
                "$de_epoch" "$(epoch_to_iso "$de_epoch")" "$de_key" "$de_note"
        done <<< "$sorted_def"

        # Offense rows. Iterate parallel arrays in canonical pattern order.
        local pattern_iter idx
        local -a pattern_indices
        for pattern_iter in "${PATTERN_ORDER[@]}"; do
            pattern_indices=()
            for (( idx=0; idx<${#RECONCILED[@]}; idx++ )); do
                local r_pat
                r_pat=$(echo "${RECONCILED[$idx]}" | cut -d'|' -f4)
                [[ "$r_pat" == "$pattern_iter" ]] || continue
                pattern_indices+=("$idx")
            done
            (( ${#pattern_indices[@]} == 0 )) && continue

            local i_sorted
            i_sorted=$(
                local i ts
                for i in "${pattern_indices[@]}"; do
                    ts=$(echo "${RECONCILED[$i]}" | cut -d'|' -f3)
                    printf '%s\t%s\n' "${ts:-0}" "$i"
                done | sort -n -k1,1 | cut -f2
            )

            local i
            while IFS= read -r i; do
                [[ -z "$i" ]] && continue
                local rec="${RECONCILED[$i]}"
                local prims="${IOC_PRIMITIVES[$i]:-}"
                local r_verdict r_delta r_epoch r_pat r_key r_note
                # Pipe-tolerant decode: r_note absorbs trailing parts so
                # notes containing '|' round-trip intact. The pre-fix
                # `cut -d'|' -f4` band-aid is removed; it had the same
                # truncation bug as the original IFS='|' read.
                IFS=$'\t' read -r r_verdict r_delta r_epoch r_pat r_key r_note \
                    < <(decode_pipe_tail "$rec" 6)

                # Compute defenses_at_ioc - which were already up at the
                # time this IOC fired. Comma-list, "" when undefended.
                local dactive=""
                [[ -n "$eff_patch"  ]] && (( r_epoch >= eff_patch  )) && dactive+="patch,"
                [[ -n "$eff_modsec" ]] && (( r_epoch >= eff_modsec )) && dactive+="modsec,"
                dactive="${dactive%,}"

                # Primitives are PRIM_SEP-separated internally. Squash any
                # embedded newlines for safety - ioc_primitive_row already
                # cleaned line, but be defensive at write time too.
                local clean="${prims//$'\n'/ }"
                clean="${clean//$'\r'/ }"

                local area ip path log_file count h2xx status line
                IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line <<< "$clean"
                # Embedded literal tabs (rare) would collide with the bundle
                # TSV column separator; flatten to spaces.
                line="${line//$'\t'/ }"
                # r_note may contain literal tabs from upstream emit - sanitize.
                local nclean="${r_note//$'\t'/ }"
                nclean="${nclean//$'\n'/ }"

                printf 'IOC\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$r_epoch" "$(epoch_to_iso "$r_epoch")" \
                    "$r_pat" "$r_verdict" "$r_delta" "$dactive" \
                    "$r_key" "$nclean" \
                    "${area:-}" "${ip:-}" "${path:-}" "${log_file:-}" \
                    "${count:-}" "${h2xx:-}" "${status:-}" "${line:-}"
            done <<< "$i_sorted"
        done
    } > "$tsv"
    chmod 0600 "$tsv" 2>/dev/null

    # JSONL - same data, machine-parseable. Header row replaced by a single
    # "meta" object on line 1; each subsequent line is a kind=DEF or kind=IOC
    # record with envelope-root metadata embedded for self-attribution.
    #
    # Schema version tracking:
    #   v1 (forensic <= 0.9.x): per-IOC field name was "stage"
    #   v2 (forensic >= 0.10.0): per-IOC field renamed to "pattern" to align
    #     with the IC-5790 dossier vocabulary. The _schema_changes hint in
    #     the meta row makes the rename machine-discoverable for future
    #     readers (operator tooling, LLM analyses).
    {
        printf '{"kind":"meta","host":"%s","primary_ip":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-forensic","tool_version":"%s","schema_version":2,"_schema_changes":[{"v":2,"since_tool":"0.10.0","renamed":{"stage":"pattern"},"note":"IOC pattern letters were emitted as stage in schema v1 (forensic <= 0.9.x)"}],"incident_id":"%s","run_id":"%s","ioc_scan_run_id":"%s","ioc_scan_tool_version":"%s","ioc_scan_ts":"%s","host_verdict":"%s","code_verdict":"%s","score":"%s","effective_patch_epoch":"%s","effective_modsec_epoch":"%s"}\n' \
            "$HOSTNAME_J" "$PRIMARY_IP_J" "$LP_UID_J" "$OS_J" "$CPV_J" "$TS_ISO" \
            "$VERSION" "$INCIDENT_ID" "$RUN_ID" \
            "$(json_esc "$ENV_IOC_RUN_ID")" "$(json_esc "$ENV_IOC_TOOL_VERSION")" "$(json_esc "$ENV_IOC_TS")" \
            "$(json_esc "$ENV_HOST_VERDICT")" "$(json_esc "$ENV_CODE_VERDICT")" "$(json_esc "$ENV_SCORE")" \
            "${eff_patch:-}" "${eff_modsec:-}"

        local de de_epoch de_key de_note _de_line
        local sorted_def
        sorted_def=$(
            local d
            for d in "${DEFENSE_EVENTS[@]}"; do printf '%s\n' "$d"; done | sort -t'|' -k1,1n
        )
        # Pipe-tolerant decode (notes may contain '|').
        while IFS= read -r _de_line; do
            [[ -z "$_de_line" ]] && continue
            IFS=$'\t' read -r de_epoch de_key de_note < <(decode_pipe_tail "$_de_line" 3)
            [[ -z "$de_epoch" ]] && continue
            printf '{"kind":"DEF","epoch":%s,"ts":"%s","key":"%s","note":"%s"}\n' \
                "$de_epoch" "$(epoch_to_iso "$de_epoch")" \
                "$(json_esc "$de_key")" "$(json_esc "$de_note")"
        done <<< "$sorted_def"

        local pattern_iter idx
        local -a pattern_indices
        for pattern_iter in "${PATTERN_ORDER[@]}"; do
            pattern_indices=()
            for (( idx=0; idx<${#RECONCILED[@]}; idx++ )); do
                local r_pat
                r_pat=$(echo "${RECONCILED[$idx]}" | cut -d'|' -f4)
                [[ "$r_pat" == "$pattern_iter" ]] || continue
                pattern_indices+=("$idx")
            done
            (( ${#pattern_indices[@]} == 0 )) && continue
            local i_sorted
            i_sorted=$(
                local i ts
                for i in "${pattern_indices[@]}"; do
                    ts=$(echo "${RECONCILED[$i]}" | cut -d'|' -f3)
                    printf '%s\t%s\n' "${ts:-0}" "$i"
                done | sort -n -k1,1 | cut -f2
            )
            local i
            while IFS= read -r i; do
                [[ -z "$i" ]] && continue
                local rec="${RECONCILED[$i]}"
                local prims="${IOC_PRIMITIVES[$i]:-}"
                local r_verdict r_delta r_epoch r_pat r_key r_note
                # Pipe-tolerant decode (notes may contain '|').
                IFS=$'\t' read -r r_verdict r_delta r_epoch r_pat r_key r_note \
                    < <(decode_pipe_tail "$rec" 6)
                local dactive=""
                [[ -n "$eff_patch"  ]] && (( r_epoch >= eff_patch  )) && dactive+="patch,"
                [[ -n "$eff_modsec" ]] && (( r_epoch >= eff_modsec )) && dactive+="modsec,"
                dactive="${dactive%,}"
                local area ip path log_file count h2xx status line
                IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line <<< "$prims"

                # JSONL schema v2 (forensic v0.10.0+): per-IOC field 'stage'
                # renamed to 'pattern' to match the IC-5790 dossier vocabulary.
                # Meta row carries schema_version=2 + a _schema_changes hint
                # so future readers (operator tooling, LLM analyses) can
                # auto-detect the rename and adapt.
                printf '{"kind":"IOC","epoch":%s,"ts":"%s","pattern":"%s","verdict":"%s","delta":"%s","defenses_at_ioc":"%s","key":"%s","note":"%s","area":"%s","ip":"%s","path":"%s","log_file":"%s","count":"%s","hits_2xx":"%s","status":"%s","line":"%s"}\n' \
                    "$r_epoch" "$(epoch_to_iso "$r_epoch")" \
                    "$(json_esc "$r_pat")" "$(json_esc "$r_verdict")" \
                    "$(json_esc "$r_delta")" "$(json_esc "$dactive")" \
                    "$(json_esc "$r_key")" "$(json_esc "$r_note")" \
                    "$(json_esc "$area")" "$(json_esc "$ip")" \
                    "$(json_esc "$path")" "$(json_esc "$log_file")" \
                    "$(json_esc "$count")" "$(json_esc "$h2xx")" \
                    "$(json_esc "$status")" "$(json_esc "$line")"
            done <<< "$i_sorted"
        done
    } > "$jsonl"
    chmod 0600 "$jsonl" 2>/dev/null

    # Pretty-printed copy (ANSI-stripped) for human review from the bundle.
    if [[ -n "$KILL_CHAIN_RENDERED" ]]; then
        printf '%s\n' "$KILL_CHAIN_RENDERED" > "$md"
        chmod 0600 "$md" 2>/dev/null
    fi

    say_info "kill-chain primitives: kill-chain.tsv kill-chain.jsonl kill-chain.md"
    emit_signal bundle info kill_chain_primitives \
        "wrote kill-chain.tsv/jsonl/md to bundle dir" \
        tsv "kill-chain.tsv" jsonl "kill-chain.jsonl" md "kill-chain.md"
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
        echo "primary_ip=$PRIMARY_IP"
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

    # Stash the upstream ioc-scan JSON envelope. Only the canonical structured
    # record is preserved (operator-facing stdout is not captured); without
    # this, an offline analyst can see the kill-chain reconciliation but not
    # the source per-signal evidence ioc-scan emitted. KB-sized, always safe
    # to bundle. Only present when chained from ioc-scan.
    if [[ -n "${SESSIONSCRIBE_IOC_JSON:-}" && -f "$SESSIONSCRIBE_IOC_JSON" ]]; then
        if cp "$SESSIONSCRIBE_IOC_JSON" "$bdir/ioc-scan-envelope.json" 2>/dev/null; then
            chmod 0600 "$bdir/ioc-scan-envelope.json" 2>/dev/null
            local env_size
            env_size=$(stat -c %s "$bdir/ioc-scan-envelope.json" 2>/dev/null)
            emit_signal bundle info ioc_envelope_captured \
                "ioc-scan envelope copied to bundle (${env_size:-?} bytes)" \
                src "$SESSIONSCRIBE_IOC_JSON" dest "ioc-scan-envelope.json" bytes "${env_size:-0}"
        else
            emit_signal bundle warn ioc_envelope_copy_failed \
                "could not copy ioc-scan envelope into bundle" src "$SESSIONSCRIBE_IOC_JSON"
        fi
    fi

    # Kill-chain primitives next to the manifest. These are tiny (KB-scale)
    # so they're always written - independent of any per-tarball size cap.
    write_kill_chain_primitives

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

    # 7b. Pattern H artifacts - seobot.php across cPanel docroots. Capture
    # stat + sha256 + first 256 bytes (PHP shells fingerprint via opening
    # tag); cap at 50 entries to bound output on big shared hosts. Docroot
    # discovery mirrors ioc-scan's H1 logic.
    local h_seobot_meta="$bdir/pattern-h-seobot-metadata.txt"
    local h_seobot_count=0
    {
        echo "# Pattern H seobot.php capture (IC-5790 dossier rev3)"
        echo "# captured_at=$TS_ISO host=$HOSTNAME_FQDN"
        echo
        local _dr_list_inner
        _dr_list_inner=$({
            if [[ -d /var/cpanel/userdata ]]; then
                grep -rh '^documentroot:' /var/cpanel/userdata/*/ 2>/dev/null \
                  | awk '{print $2}' | sort -u
            fi
            local _d
            for _d in /home/*/public_html; do
                [[ -d "$_d" ]] && printf '%s\n' "$_d"
            done
        } | sort -u)
        local _dr _h
        while IFS= read -r _dr; do
            [[ -d "$_dr" ]] || continue
            while IFS= read -r -d '' _h; do
                h_seobot_count=$((h_seobot_count + 1))
                if (( h_seobot_count > 50 )); then
                    echo "# (capture capped at 50 entries; more present on host)"
                    break 2
                fi
                echo "=== seobot.php hit #$h_seobot_count ==="
                stat "$_h" 2>&1
                sha256sum "$_h" 2>&1
                file "$_h" 2>&1
                echo "--- first 256 bytes ---"
                head -c 256 "$_h" 2>/dev/null
                echo
                echo
            done < <(find "$_dr" -maxdepth 3 -name "$PATTERN_H_DROPPER_FILE" -print0 2>/dev/null)
        done <<< "$_dr_list_inner"
    } > "$h_seobot_meta" 2>/dev/null
    if (( h_seobot_count > 0 )); then
        say_warn "Pattern H captured: $h_seobot_count seobot.php hit(s)"
        emit_signal bundle warn pattern_h_seobot_captured \
            "seobot.php captured ($h_seobot_count hits)" \
            path "pattern-h-seobot-metadata.txt" count "$h_seobot_count"
    else
        rm -f "$h_seobot_meta"
    fi

    # 7c. Pattern I artifacts - system-service binary at /root/.local/bin.
    # Capture metadata only (NOT the binary itself - mirrors Pattern A
    # safety policy; binary may be a miner or beacon worth quarantining
    # intact rather than spreading via bundle copies).
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
                ldd "$PATTERN_I_BINARY" 2>&1 || echo "(ldd failed - likely statically linked or non-ELF)"
            fi
        } > "$i_meta" 2>/dev/null
        say_warn "Pattern I binary metadata captured (binary itself NOT bundled)"
        emit_signal bundle warn pattern_i_binary_captured \
            "system-service binary metadata captured" \
            path "pattern-i-system-service-metadata.txt" \
            bin "$PATTERN_I_BINARY"
    fi
    # Pattern I profile.d hook - already swept into persistence.tgz via the
    # /etc/profile.d directory bundle. Emit an explicit info signal so the
    # bundle log records the IOC artifact is present without re-bundling.
    if [[ -f "$PATTERN_I_PROFILED" ]]; then
        emit_signal bundle info pattern_i_hook_in_persistence_tgz \
            "system_profiled_service.sh present in persistence.tgz" \
            path "$PATTERN_I_PROFILED"
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
render_kill_chain
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
