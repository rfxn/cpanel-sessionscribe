#!/bin/bash
#
##
# sessionscribe-mitigate.sh v0.3.1
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
###############################################################################
# sessionscribe-mitigate.sh
#
# DISCLAIMER / USE AT YOUR OWN RISK
#   Active mitigation tool. Modifies firewall configuration, repo files,
#   tweak settings, Apache config, and may launch /scripts/upcp. Provided
#   as-is, without warranty of any kind. Default mode is --check (read-only);
#   --apply is required to mutate state. Validate against your own
#   change-control before running --apply on production.
###############################################################################
#
# ============================================================================
# Attribution
# ============================================================================
#
# CVE-2026-41940 (SessionScribe)
#   Researcher: Sina Kheirkhah (@SinSinology) / watchTowr Labs.
#   Public PoC: github.com/watchtowrlabs/watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py
#
# Mitigation tooling + companion ModSec WhmScribe-A coverage
#   Author: Ryan MacDonald, Nexcess Engineering <rmacdonald@nexcess.net>
#           Ryan MacDonald, rfxn | forged in prod | <ryan@rfxn.com>
#   Project: https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940
#
# ============================================================================
#
# Defense-in-depth active mitigation for CVE-2026-41940 (SessionScribe) and
# the related cPanel/WHM exposure surface. One phased pass that brings a
# host into the documented "patched + proxy-endpoint enforcement + ModSec"
# posture. Idempotent - safe to run repeatedly. All mutations write
# timestamped backups to /var/cpanel/sessionscribe-mitigation/<TS>/.
#
# Phases (in order; selectable via --only, --no-PHASE, or --list-phases):
#
#   patch       cpanel -V vs published patched-build cutoffs
#   preflight   epel-release present; threatdown.repo absent; broken
#               non-base repos disabled (centos/alma/rocky baseos/appstream/
#               extras/etc untouched even if currently broken)
#   upcp        if patch=UNPATCHED, kick off /scripts/upcp --force --bg
#   proxysub    enable proxysubdomains + proxysubdomainsfornewaccounts
#   csf         /etc/csf/csf.conf TCP_IN/TCP6_IN scrubbed of cpsrvd ports
#   apf         /etc/apf/conf.apf IG_TCP_CPORTS scrubbed of cpsrvd ports
#   runfw       running iptables/ip6tables INPUT chain inspection
#   apache      httpd active + security2_module loaded
#   modsec      modsec2.user.conf contains 1500030 + 1500031
#   sessions    /var/cpanel/sessions/raw IOC ladder; quarantine forged
#               sessions to backup dir w/ .info metadata (preserves ctime
#               that cp -a cannot carry); rm originals so leaked
#               cp_security_token cannot be reused
#   probe       (opt-in via --probe) self-test via remote-probe against
#               127.0.0.1; expect SAFE/blocked verdict
#
# Output:
#   default     ANSI sectioned report on stderr
#   --json      single JSON envelope on stdout (per-host)
#   --jsonl     stream one JSON signal per line on stdout (per-phase
#               signals + final summary). Each line carries host, os,
#               cpanel_version for fleet aggregation.
#   --csv       single CSV summary row on stdout (header + one row).
#               Same host-context columns. Designed for fleet roll-up.
#   --quiet     suppress sectioned report
#
# Exit codes (highest priority wins):
#   0  clean - patched + posture ok, no action needed
#   1  remediation applied successfully (--apply made changes)
#   2  manual intervention required (warns in --check, or fail in --apply)
#   3  tool error (bad args, missing dependencies, not root for --apply)
#
# Fleet usage:
#   ansible -i hosts all -m script -a 'sessionscribe-mitigate.sh --jsonl'
#   pdsh -w cpanel-fleet 'bash -s --' -- --csv < sessionscribe-mitigate.sh
#
# Run as root for full coverage (--check tolerates non-root with reduced
# fidelity; --apply requires root).
###############################################################################

set -u

VERSION="0.4.1"

###############################################################################
# Constants
###############################################################################

# Vendor-published patched builds (cPanel KB 40073787579671, post-04/29
# advisory revision: tier 130 added at .19; tier 124 .35 added; EL6 path
# 11.86.0.41 included). WP Squared product line: separate patch at build
# 136.1.7.
PATCHED_BUILDS_CPANEL=(
  "11.86.0.41"
  "11.110.0.97"
  "11.118.0.63"
  "11.124.0.35"
  "11.126.0.54"
  "11.130.0.19"
  "11.132.0.29"
  "11.134.0.20"
  "11.136.0.5"
)
PATCHED_BUILD_WPSQUARED="136.1.7"

# Tiers explicitly excluded from the patch list - no in-place fix exists.
# Tier 124 was here pre-advisory; given a .35 in-place patch and moved
# into PATCHED_BUILDS_CPANEL above.
UNPATCHED_TIERS=(112 114 116 120 122 128)

# cpsrvd direct-listener ports. cPanel/WHM/Webmail (non-SSL/SSL pairs).
CPSRVD_PORTS=(2082 2083 2086 2087 2095 2096)

# Repos that must NOT be disabled even if metadata is currently unreachable.
# Loose match on purpose - covers Rocky/Alma/CentOS variants, source/debug
# companions, and the EL6 base set. Vendor prefix (almalinux-, rocky-,
# centos-, el-, rhel-) is stripped before matching.
PROTECTED_REPO_RE='^(baseos|base|appstream|extras|updates|powertools|crb|plus|highavailability|nfv|rt|resilientstorage|saphana|sap|addons|fasttrack|contrib|cr|devel|cs|cs-debug|cs-source|c8s|c9s)([_-](source|debuginfo|rpms))?$'

# Repos always removed if present.
REMOVE_REPO_FILES=(/etc/yum.repos.d/threatdown.repo)

# Modsec drop path on cPanel.
MODSEC_USER_CONF="/etc/apache2/conf.d/modsec/modsec2.user.conf"

# Required modsec rule IDs for CVE-2026-41940 coverage.
REQUIRED_MODSEC_IDS=(1500030 1500031)
# Adjacent (WhmScribe-A) WHM-token rule IDs - informational, not required for CVE.
INFORMATIONAL_MODSEC_IDS=(1500010 1500020 1500021)

# Source candidate for the modsec config.
MODSEC_SRC_CANDIDATES=(
  "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/modsec-sessionscribe.conf"
)

# Backup root for any mutating action.
BACKUP_ROOT_DEFAULT="/var/cpanel/sessionscribe-mitigation"

# Marker tag stamped into every backup path so undo logic can find them.
BACKUP_MARKER='nxesec-sessionscribe-mitigate'

# Session-store IOC ladder constants (mirrors sessionscribe-ioc-scan.sh).
# Used by phase_sessions to detect/quarantine forged sessions left behind
# by CRLF injection. Keep in sync with the IOC scanner so a session that
# trips ioc-scan also trips mitigate's quarantine.
SESSIONS_DIR="${SESSIONS_DIR:-/var/cpanel/sessions}"
PASS_FORGERY_MAX_LEN=12
# nxesec_canary_<nonce>= sessions are sessionscribe-remote-probe collateral
# (probe artifacts) - never quarantine these.
PROBE_CANARY_PAT='^nxesec_canary_[A-Za-z0-9]+='

###############################################################################
# Phase registry - ordered list of (id, function, description, default-on)
###############################################################################

PHASE_IDS=(patch preflight upcp proxysub csf apf runfw apache modsec sessions probe)
PHASE_DEFAULT_ON=(1     1         1    1        1   1   1     1      1      1        0)
declare -A PHASE_DESC=(
    [patch]="cpanel -V vs published patched-build cutoffs"
    [preflight]="epel-release; threatdown.repo absent; broken-repo sweep"
    [upcp]="if patch=UNPATCHED, kick off /scripts/upcp --force --bg"
    [proxysub]="enable proxysubdomains + proxysubdomainsfornewaccounts"
    [csf]="csf TCP_IN/TCP6_IN scrubbed of cpsrvd ports"
    [apf]="apf IG_TCP_CPORTS scrubbed of cpsrvd ports"
    [runfw]="running iptables INPUT chain inspection"
    [apache]="httpd active + security2_module loaded"
    [modsec]="modsec2.user.conf contains required CVE rule IDs"
    [sessions]="quarantine forged session files (CRLF-injection IOC ladder)"
    [probe]="(opt-in) self-probe against 127.0.0.1 via remote-probe"
)

###############################################################################
# Argument parsing
###############################################################################

MODE="check"            # check | apply
ONLY_LIST=""            # CSV phase IDs; empty = all defaults-on
DO_PROBE=0              # --probe opt-in
declare -A PHASE_DISABLED=()
JSON_OUT=0
JSONL_OUT=0
CSV_OUT=0
QUIET=0
NO_COLOR_FLAG=0
OUTPUT_FILE=""
BACKUP_ROOT="$BACKUP_ROOT_DEFAULT"
ASSUME_YES=0

usage() {
    cat <<EOF
sessionscribe-mitigate.sh v${VERSION}
Defense-in-depth active mitigation for CVE-2026-41940 (SessionScribe).

USAGE
    sessionscribe-mitigate.sh [MODE] [PHASE-SELECTION] [OUTPUT] [MISC]

    Read-only by default (--check). Use --apply to mutate state. All
    enabled phases run in order unless restricted via --only or excluded
    via --no-PHASE. Idempotent: re-running on a healthy host is a no-op.

MODES
    --check                Read-only audit (default). No state changes.
    --apply                Execute remediations. Requires root.
    --dry-run              Alias for --check.

PHASE SELECTION
    --only LIST            Run only the named phases (CSV, or "all").
                           Phases: $(IFS=,; echo "${PHASE_IDS[*]}")
    --no-PHASE             Skip a phase. Per-phase opt-outs:
                             --no-patch     --no-preflight   --no-upcp
                             --no-proxysub  --no-csf         --no-apf
                             --no-runfw     --no-apache      --no-modsec
                             --no-sessions
    --no-fw                Shorthand for --no-csf --no-apf --no-runfw.
    --probe                Enable the optional probe phase (opt-in).
                           Runs sessionscribe-remote-probe.sh against
                           127.0.0.1:2087; expects SAFE/blocked verdict.
    --list-phases          Print phase IDs + descriptions, then exit.

OUTPUT (mutually exclusive on stdout - last flag wins)
    (default)              ANSI sectioned report on stderr.
    --json                 Single JSON envelope on stdout.
    --jsonl                Stream one JSON signal per line on stdout. Every
                           line carries host, os, cpanel_version, ts,
                           tool_version, mode, phase, severity, key, note.
    --csv                  Single CSV summary row on stdout (header + one
                           data row). One row per host - designed for
                           fleet roll-up via cat *.csv | awk ...
    -o, --output FILE      Write final JSON envelope (or CSV row if --csv
                           is set) to FILE.

MISC
    --quiet                Suppress sectioned report. Auto-set by --jsonl/--csv.
    --no-color             Disable ANSI color. NO_COLOR=1 env also honored.
    --backup-root DIR      Backup directory for any mutation
                           (default: $BACKUP_ROOT_DEFAULT).
    --yes, -y              Non-interactive; assume yes (no prompts).
    -h, --help             Show this help.

EXIT CODES
    0    clean - patched + posture ok, no action needed
    1    remediation applied successfully (--apply made changes)
    2    manual intervention required (warns in --check, or fail in --apply)
    3    tool error (bad args, missing dependencies, not root for --apply)

EXAMPLES
    Audit a single host (read-only):
        sessionscribe-mitigate.sh

    Full remediation:
        sessionscribe-mitigate.sh --apply

    Skip the cPanel upgrade phase:
        sessionscribe-mitigate.sh --apply --no-upcp

    Check just the firewall + modsec posture (drift watch):
        sessionscribe-mitigate.sh --only csf,apf,runfw,modsec

    Apply only modsec, then verify end-to-end with the self-probe:
        sessionscribe-mitigate.sh --apply --only modsec --probe

    Fleet aggregation - one CSV row or JSONL stream per host:
        sessionscribe-mitigate.sh --csv   > host.csv
        sessionscribe-mitigate.sh --jsonl > host.jsonl

    Pre-upcp wave gate (preflight only, exit nonzero if anything broken):
        sessionscribe-mitigate.sh --apply --only patch,preflight
EOF
    exit 0
}

list_phases() {
    printf '%-12s  %-3s  %s\n' "PHASE" "ON" "DESCRIPTION"
    local i
    for i in "${!PHASE_IDS[@]}"; do
        printf '%-12s  %-3s  %s\n' "${PHASE_IDS[$i]}" \
            "$( ((${PHASE_DEFAULT_ON[$i]})) && echo yes || echo no)" \
            "${PHASE_DESC[${PHASE_IDS[$i]}]}"
    done
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check|--dry-run)  MODE="check";  shift ;;
        --apply)            MODE="apply";  shift ;;
        --only)             ONLY_LIST="$2"; shift 2 ;;
        --probe)            DO_PROBE=1; shift ;;
        --no-upcp)          PHASE_DISABLED[upcp]=1; shift ;;
        --no-modsec)        PHASE_DISABLED[modsec]=1; shift ;;
        --no-sessions)      PHASE_DISABLED[sessions]=1; shift ;;
        --no-fw)            PHASE_DISABLED[csf]=1; PHASE_DISABLED[apf]=1; PHASE_DISABLED[runfw]=1; shift ;;
        --no-csf)           PHASE_DISABLED[csf]=1; shift ;;
        --no-apf)           PHASE_DISABLED[apf]=1; shift ;;
        --no-runfw)         PHASE_DISABLED[runfw]=1; shift ;;
        --no-apache)        PHASE_DISABLED[apache]=1; shift ;;
        --no-patch)         PHASE_DISABLED[patch]=1; shift ;;
        --no-preflight)     PHASE_DISABLED[preflight]=1; shift ;;
        --no-proxysub)      PHASE_DISABLED[proxysub]=1; shift ;;
        --list-phases)      list_phases ;;
        --json)             JSON_OUT=1; JSONL_OUT=0; CSV_OUT=0; shift ;;
        --jsonl)            JSONL_OUT=1; JSON_OUT=0; CSV_OUT=0; shift ;;
        --csv)              CSV_OUT=1; JSON_OUT=0; JSONL_OUT=0; shift ;;
        --quiet)            QUIET=1; shift ;;
        --no-color)         NO_COLOR_FLAG=1; shift ;;
        -o|--output)        OUTPUT_FILE="$2"; shift 2 ;;
        --backup-root)      BACKUP_ROOT="$2"; shift 2 ;;
        --yes|-y)           ASSUME_YES=1; shift ;;
        -h|--help)          usage ;;
        *) echo "Unknown option: $1" >&2; echo "Try --help" >&2; exit 3 ;;
    esac
done

# JSONL/CSV/JSON consumers want clean stdout. Force --quiet for JSONL/CSV.
(( JSONL_OUT || CSV_OUT )) && QUIET=1

# Apply requires root.
if [[ "$MODE" == "apply" && $EUID -ne 0 ]]; then
    echo "Error: --apply must be run as root" >&2
    exit 3
fi

# Resolve which phases will run.
declare -A PHASE_ACTIVE=()
if [[ -n "$ONLY_LIST" ]]; then
    if [[ "$ONLY_LIST" == "all" ]]; then
        for _i in "${!PHASE_IDS[@]}"; do
            PHASE_ACTIVE[${PHASE_IDS[$_i]}]=1
        done
    else
        # Validate every token is a known phase id. Use IFS-replacement for
        # the CSV split (top-level scope - `local` would error here).
        _OLDIFS="$IFS"; IFS=','
        for _tok in $ONLY_LIST; do
            _tok="${_tok// /}"
            [[ -z "$_tok" ]] && continue
            if [[ -z "${PHASE_DESC[$_tok]:-}" ]]; then
                IFS="$_OLDIFS"
                echo "Error: unknown phase '$_tok' (try --list-phases)" >&2
                exit 3
            fi
            PHASE_ACTIVE[$_tok]=1
        done
        IFS="$_OLDIFS"
    fi
else
    # Defaults: every phase whose default-on flag is 1, minus --no-PHASE list.
    for _i in "${!PHASE_IDS[@]}"; do
        _pid="${PHASE_IDS[$_i]}"
        if (( PHASE_DEFAULT_ON[_i] )) && [[ -z "${PHASE_DISABLED[$_pid]:-}" ]]; then
            PHASE_ACTIVE[$_pid]=1
        fi
    done
fi
# --probe opt-in toggles probe phase regardless of defaults.
if (( DO_PROBE )) && [[ -z "${PHASE_DISABLED[probe]:-}" ]]; then
    PHASE_ACTIVE[probe]=1
fi

###############################################################################
# Host context (computed once, embedded in every emit)
###############################################################################

HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)
TS_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TS_EPOCH=$(date -u +%s)
RUN_ID="${TS_EPOCH}-$$"

# OS detection. Read os-release in a subshell so its VERSION/ID variables
# do not clobber our own VERSION constant in this scope.
OS_ID="unknown"; OS_VER="unknown"; OS_PRETTY="unknown"
if [[ -r /etc/os-release ]]; then
    eval "$(awk -F= '
        $1 == "ID"           { print "OS_ID="$2 }
        $1 == "VERSION_ID"   { print "OS_VER="$2 }
        $1 == "PRETTY_NAME"  { print "OS_PRETTY="$2 }
        $1 == "NAME"         { print "_OS_NAME="$2 }
    ' /etc/os-release 2>/dev/null)"
    [[ "$OS_PRETTY" == "unknown" || -z "$OS_PRETTY" ]] && \
        OS_PRETTY="${_OS_NAME:-unknown} ${OS_VER:-}"
elif [[ -r /etc/redhat-release ]]; then
    OS_PRETTY=$(head -1 /etc/redhat-release 2>/dev/null)
fi
unset _OS_NAME

# cPanel version (raw + normalized).
CPANEL_RAW=""
CPANEL_NORM=""
if [[ -x /usr/local/cpanel/cpanel ]]; then
    CPANEL_RAW=$(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1 | tr -d '\r')
    # "122.0 (build 17)" -> "11.122.0.17"
    CPANEL_NORM=$(echo "$CPANEL_RAW" | sed -E 's/^([0-9]+)\.([0-9]+)[[:space:]]+\(build[[:space:]]+([0-9]+)\).*/11.\1.\2.\3/')
    [[ "$CPANEL_NORM" == "$CPANEL_RAW" ]] && CPANEL_NORM="unknown"
fi

###############################################################################
# Output primitives - colors, json_esc, csv_field, signal emit
###############################################################################

if [[ -t 2 && "$NO_COLOR_FLAG" -eq 0 && "${NO_COLOR:-0}" = "0" ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[1;33m'
    C_CYN=$'\033[0;36m'; C_BLD=$'\033[1m';    C_DIM=$'\033[2m'
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

csv_field() {
    local v="${1//\"/\"\"}"
    printf '"%s"' "$v"
}

HOSTNAME_J=$(json_esc "$HOSTNAME_FQDN")
OS_J=$(json_esc "$OS_PRETTY")
CPV_J=$(json_esc "${CPANEL_NORM:-unknown}")

# Per-phase storage. Each phase emits one verdict via phase_set.
declare -A P_VERDICT=()        # phase -> OK|ACTION|WARN|FAIL|SKIPPED
declare -A P_DETAIL=()
declare -A P_NOTES=()          # phase -> "; " joined extra notes (info)
declare -a PHASE_ORDER_RUN=()  # the actual phases that ran, in order

# Per-signal storage (for JSONL streaming and end-of-run summary).
declare -ga SIGNALS_JSON=()    # JSONL strings (already escaped + assembled)

N_OK=0; N_WARN=0; N_FAIL=0; N_ACTION=0; N_SKIPPED=0

# Emit a structured signal. Streaming JSONL writes immediately; otherwise
# accumulated for end-of-run summary.
#
# Args: phase severity key kvargs...
#   phase    short id (patch/preflight/etc)
#   severity info|action|warn|fail|skip (lowercase, plus 'pass' for success)
#   key      machine-readable specifier (e.g. "cpsrvd_port_clean")
#   note     human note (one positional after key, optional)
#   extra k=v pairs (optional, after note)
emit_signal() {
    local phase="$1" sev="$2" key="$3" note="${4:-}"
    shift 4 || shift $#
    local extra_kv=""
    while (( $# >= 2 )); do
        extra_kv+=",\"$(json_esc "$1")\":\"$(json_esc "$2")\""
        shift 2
    done
    local line
    line=$(printf '{"host":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-mitigate","tool_version":"%s","mode":"%s","phase":"%s","severity":"%s","key":"%s","note":"%s"%s}' \
        "$HOSTNAME_J" "$OS_J" "$CPV_J" "$TS_ISO" "$VERSION" "$MODE" \
        "$phase" "$sev" "$(json_esc "$key")" "$(json_esc "$note")" "$extra_kv")
    SIGNALS_JSON+=("$line")
    if (( JSONL_OUT )); then
        printf '%s\n' "$line"
    fi
}

phase_set() {
    # phase_set <phase> <verdict> <detail>
    local p="$1" v="$2" d="${3:-}"
    P_VERDICT[$p]="$v"
    P_DETAIL[$p]="$d"
    case "$v" in
        OK)      N_OK=$((N_OK+1)) ;;
        WARN)    N_WARN=$((N_WARN+1)) ;;
        FAIL)    N_FAIL=$((N_FAIL+1)) ;;
        ACTION)  N_ACTION=$((N_ACTION+1)) ;;
        SKIPPED) N_SKIPPED=$((N_SKIPPED+1)) ;;
    esac
}

phase_note() {
    local p="$1" n="$2"
    P_NOTES[$p]="${P_NOTES[$p]:-}${P_NOTES[$p]:+; }${n}"
}

phase_begin() {
    local p="$1"
    PHASE_ORDER_RUN+=("$p")
    P_VERDICT[$p]=""
    P_DETAIL[$p]=""
    P_NOTES[$p]=""
    if (( QUIET == 0 )); then
        printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$p" "$C_NC" "$C_DIM" \
            "${PHASE_DESC[$p]}" "$C_NC" >&2
    fi
}

# Human-readable per-line printers (also drive emit_signal for JSONL).
say_pass()   { (( QUIET )) || printf '  %s[OK]%s     %s\n'   "$C_GRN" "$C_NC" "$*" >&2; emit_signal "$P_CUR" pass     "$P_KEY" "$*" "${P_KV[@]:-}"; }
say_action() { (( QUIET )) || printf '  %s[ACTION]%s %s\n'   "$C_CYN" "$C_NC" "$*" >&2; emit_signal "$P_CUR" action   "$P_KEY" "$*" "${P_KV[@]:-}"; }
say_warn()   { (( QUIET )) || printf '  %s[WARN]%s   %s\n'   "$C_YEL" "$C_NC" "$*" >&2; emit_signal "$P_CUR" warn     "$P_KEY" "$*" "${P_KV[@]:-}"; }
say_fail()   { (( QUIET )) || printf '  %s[FAIL]%s   %s\n'   "$C_RED" "$C_NC" "$*" >&2; emit_signal "$P_CUR" fail     "$P_KEY" "$*" "${P_KV[@]:-}"; }
say_info()   { (( QUIET )) || printf '  %s[..]%s     %s\n'   "$C_DIM" "$C_NC" "$*" >&2; emit_signal "$P_CUR" info     "$P_KEY" "$*" "${P_KV[@]:-}"; }
say_skip()   { (( QUIET )) || printf '  %s[SKIP]%s   %s\n'   "$C_DIM" "$C_NC" "$*" >&2; emit_signal "$P_CUR" skip     "$P_KEY" "$*" "${P_KV[@]:-}"; }

# Phase context for emit_signal (the say_* helpers reference these).
P_CUR=""
P_KEY=""
declare -a P_KV=()

# Set the per-line key + extras. Convenience wrapper for callers.
sk()  { P_KEY="$1"; shift; P_KV=("$@"); }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Epoch -> ISO-8601 UTC. Empty input or non-numeric -> empty output. Used
# by phase_sessions for .info-file timestamp serialization. Bash 4.1
# compatible: relies on GNU coreutils `date -d @<epoch>` (CentOS 6+).
epoch_to_iso() {
    local e="${1:-}"
    [[ -z "$e" ]] && { echo ""; return; }
    [[ "$e" =~ ^[0-9]+$ ]] || { echo ""; return; }
    date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

###############################################################################
# Backup root
###############################################################################

BACKUP_DIR="${BACKUP_ROOT}/${TS_ISO}-${RUN_ID}"

ensure_backup_dir() {
    if [[ "$MODE" == "apply" && ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR" 2>/dev/null || {
            say_fail "could not create backup dir: $BACKUP_DIR"
            return 1
        }
    fi
    return 0
}

backup_file() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    ensure_backup_dir || return 1
    local rel; rel=$(echo "$f" | sed 's|/|_|g; s/^_//')
    cp -a "$f" "$BACKUP_DIR/${rel}" 2>/dev/null
}

###############################################################################
# 1. patch
###############################################################################

build_is_patched() {
    local b="$1" p
    for p in "${PATCHED_BUILDS_CPANEL[@]}"; do
        [[ "$b" == "$p" ]] && return 0
    done
    [[ "$b" == "$PATCHED_BUILD_WPSQUARED" ]] && return 0
    return 1
}

build_is_unpatchable_tier() {
    local b="$1" tier t
    tier=$(echo "$b" | awk -F. '{print $2}')
    for t in "${UNPATCHED_TIERS[@]}"; do
        [[ "$tier" == "$t" ]] && return 0
    done
    return 1
}

phase_patch() {
    P_CUR=patch
    phase_begin patch

    if [[ -z "$CPANEL_RAW" ]]; then
        sk no_cpanel
        say_fail "cpanel binary not found at /usr/local/cpanel/cpanel"
        phase_set patch FAIL "cpanel missing"
        PATCH_STATE="UNKNOWN"
        return
    fi

    sk version_detected
    say_info "raw: $CPANEL_RAW"
    say_info "normalized: $CPANEL_NORM"

    # Last upcp result - informational.
    local last_upcp_log last_upcp_exit
    if [[ -d /var/cpanel/updatelogs ]]; then
        last_upcp_log=$(ls -t /var/cpanel/updatelogs/ 2>/dev/null | head -1)
        if [[ -n "$last_upcp_log" ]]; then
            # Logs end with "Update completed" or non-zero "exited X". Loose match.
            if grep -qE 'Update completed|complete\.$' \
                 "/var/cpanel/updatelogs/$last_upcp_log" 2>/dev/null; then
                last_upcp_exit="ok"
            elif grep -qE 'failed|aborted|error' \
                 "/var/cpanel/updatelogs/$last_upcp_log" 2>/dev/null; then
                last_upcp_exit="error"
            else
                last_upcp_exit="unknown"
            fi
            sk last_upcp last_log "$last_upcp_log" last_status "$last_upcp_exit"
            say_info "last upcp: $last_upcp_log ($last_upcp_exit)"
        fi
    fi

    if build_is_patched "$CPANEL_NORM"; then
        sk patched build "$CPANEL_NORM"
        say_pass "build $CPANEL_NORM is on the published patched list"
        phase_set patch OK "$CPANEL_NORM"
        PATCH_STATE="PATCHED"
        return
    fi

    if build_is_unpatchable_tier "$CPANEL_NORM"; then
        sk unpatchable_tier build "$CPANEL_NORM"
        say_warn "tier in UNPATCHED_TIERS list - no in-place fix"
        say_warn "manual action: upgrade major series or migrate this host"
        phase_set patch WARN "tier unpatchable: $CPANEL_NORM"
        PATCH_STATE="UNPATCHABLE"
        return
    fi

    sk below_cutoff build "$CPANEL_NORM"
    say_warn "build $CPANEL_NORM is NOT on the patched list and is below tier cutoff"
    phase_set patch ACTION "$CPANEL_NORM below cutoff"
    PATCH_STATE="UNPATCHED"
}

###############################################################################
# 2. preflight
###############################################################################

repo_is_healthy() {
    local r="$1"
    if have_cmd dnf; then
        dnf -q -y --disablerepo='*' --enablerepo="$r" makecache --refresh \
            >/dev/null 2>&1
    elif have_cmd yum; then
        yum -q -y --disablerepo='*' --enablerepo="$r" makecache fast \
            >/dev/null 2>&1
    else
        return 0  # no pkg manager - assume healthy (can't tell)
    fi
}

repo_is_protected() {
    local r="$1" stripped
    stripped=$(echo "$r" | sed -E 's/^(almalinux|rocky|centos|el|rhel)[-_]//i')
    [[ "${stripped,,}" =~ $PROTECTED_REPO_RE ]] && return 0
    [[ "${r,,}" =~ $PROTECTED_REPO_RE ]] && return 0
    return 1
}

phase_preflight() {
    P_CUR=preflight
    phase_begin preflight

    local actions=0 warns=0

    # Anti-forensic awareness: Pattern A's encryptor specifically targets
    # forensic-evidence files in /var/log + /var/cpanel. The most load-
    # bearing of these for our detection chain is /var/cpanel/accounting.log
    # (Pattern D persistence evidence: createacct/setupreseller/setacls
    # rows for the attacker reseller). If the live file is missing but the
    # .sorry-encrypted variant exists, surface a strong operator advisory
    # so they don't trust a clean Pattern D verdict; ioc-scan v1.8.0+
    # emits ioc_pattern_d_acctlog_encrypted as a parallel signal.
    sk evidence_destruction
    local acct_live=/var/cpanel/accounting.log
    local acct_sorry=/var/cpanel/accounting.log.sorry
    if [[ ! -f "$acct_live" && -f "$acct_sorry" ]]; then
        local sorry_count=0
        sorry_count=$(find /var/log /var/cpanel -maxdepth 6 -name '*.sorry' \
                          -not -path '*/imunify360/cache/*' 2>/dev/null | wc -l)
        sorry_count="${sorry_count// /}"
        say_warn "Pattern A evidence destruction: $acct_sorry exists (${sorry_count} .sorry files in /var/log+/var/cpanel) - Pattern D detection lossy on this host; verify reseller via /var/cpanel/users/sptadm directly."
        warns=$((warns+1))
    elif [[ -f "$acct_live" ]]; then
        say_pass "$acct_live present (no Pattern A evidence destruction detected)"
    else
        say_info "$acct_live not present (host may not have run reseller-creating WHM operations)"
    fi

    # 2a: threatdown.repo (and similar) removal.
    local f
    for f in "${REMOVE_REPO_FILES[@]}"; do
        sk remove_repo file "$f"
        if [[ -e "$f" ]]; then
            if [[ "$MODE" == "apply" ]]; then
                backup_file "$f"
                if rm -f "$f"; then
                    say_action "removed $f"
                    actions=$((actions+1))
                else
                    say_fail "rm failed: $f"
                fi
            else
                say_warn "$f present (would remove)"
                warns=$((warns+1))
            fi
        else
            say_pass "$f absent"
        fi
    done

    # 2b: epel-release installed.
    sk epel
    if rpm -q epel-release >/dev/null 2>&1; then
        say_pass "epel-release installed"
    else
        if [[ "$MODE" == "apply" ]]; then
            local pkg_ok=0
            if have_cmd dnf; then
                dnf install -y epel-release >/dev/null 2>&1 && pkg_ok=1
            elif have_cmd yum; then
                yum install -y epel-release >/dev/null 2>&1 && pkg_ok=1
            fi
            if (( pkg_ok )); then
                say_action "installed epel-release"
                actions=$((actions+1))
            else
                say_fail "could not install epel-release"
            fi
        else
            say_warn "epel-release missing (would install)"
            warns=$((warns+1))
        fi
    fi

    # 2c: invalidate cached repo metadata. `clean metadata` is the surgical
    # form - removes only the cached repodata XML so subsequent makecache
    # calls test live upstream health rather than honoring a stale 304 hit.
    # Leaves packages/, dbcache/, and downloaded RPMs intact (vs `clean all`).
    sk repo_clean
    if have_cmd dnf; then
        if dnf clean metadata >/dev/null 2>&1; then
            say_info "dnf clean metadata (cached repodata invalidated)"
        else
            say_warn "dnf clean metadata failed; sweep may use stale cache"
        fi
    elif have_cmd yum; then
        if yum clean metadata >/dev/null 2>&1; then
            say_info "yum clean metadata (cached repodata invalidated)"
        else
            say_warn "yum clean metadata failed; sweep may use stale cache"
        fi
    fi

    # 2d: broken-repo sweep.
    sk repo_sweep
    if have_cmd dnf; then
        local enabled_repos r
        enabled_repos=$(dnf repolist --enabled -q 2>/dev/null \
                        | awk 'NR>1 && $1 != "" {print $1}')
        if [[ -z "$enabled_repos" ]]; then
            say_skip "no enabled repos enumerated by dnf"
        else
            while IFS= read -r r; do
                [[ -z "$r" ]] && continue
                sk repo_probe repo "$r"
                if repo_is_healthy "$r"; then
                    say_info "repo OK: $r"
                else
                    if repo_is_protected "$r"; then
                        say_warn "repo BROKEN but PROTECTED (left enabled): $r"
                        warns=$((warns+1))
                    else
                        if [[ "$MODE" == "apply" ]]; then
                            if dnf config-manager --set-disabled "$r" \
                                    >/dev/null 2>&1; then
                                say_action "disabled broken repo: $r"
                                actions=$((actions+1))
                            else
                                say_fail "could not disable: $r"
                            fi
                        else
                            say_warn "repo BROKEN: $r (would disable)"
                            warns=$((warns+1))
                        fi
                    fi
                fi
            done <<< "$enabled_repos"
        fi
    else
        say_skip "no dnf/yum; broken-repo sweep skipped"
    fi

    sk preflight_summary actions "$actions" warnings "$warns"
    if (( actions > 0 )); then
        phase_set preflight ACTION "$actions changed, $warns warns"
    elif (( warns > 0 )); then
        phase_set preflight WARN "$warns issues need --apply"
    else
        phase_set preflight OK "all green"
    fi
}

###############################################################################
# 3. upcp
###############################################################################

phase_upcp() {
    P_CUR=upcp
    phase_begin upcp

    case "${PATCH_STATE:-}" in
        PATCHED)
            sk skip_patched
            say_pass "patched build; no upcp needed"
            phase_set upcp OK "already patched"
            return
            ;;
        UNPATCHABLE)
            sk skip_unpatchable
            say_warn "tier has no in-place patch; upcp will not help"
            phase_set upcp WARN "tier unpatchable"
            return
            ;;
        UNKNOWN)
            sk skip_unknown
            say_skip "patch state unknown (cpanel missing or unparseable)"
            phase_set upcp SKIPPED "no cpanel"
            return
            ;;
    esac

    sk upcp_target
    if [[ ! -x /scripts/upcp ]]; then
        say_fail "/scripts/upcp not executable"
        phase_set upcp FAIL "upcp missing"
        return
    fi

    # pgrep -f (no -a): output is discarded; -a is procps-ng 3.3.4+ only
    # (not present in EL6 procps-3.2.x).
    if pgrep -f '/scripts/upcp' >/dev/null 2>&1; then
        sk upcp_already_running
        say_warn "/scripts/upcp already running; not relaunching"
        phase_set upcp WARN "upcp in flight"
        return
    fi

    # Disk space sanity (upcp needs several GB free under /usr).
    local free_mb
    free_mb=$(df -Pm /usr 2>/dev/null | awk 'NR==2{print $4}')
    if [[ -n "$free_mb" && "$free_mb" -lt 2048 ]]; then
        sk upcp_low_disk free_mb "$free_mb"
        say_warn "/usr has only ${free_mb}MB free; upcp may fail (recommend >2GB)"
    fi

    if [[ "$MODE" == "apply" ]]; then
        nohup /scripts/upcp --force --bg >/dev/null 2>&1 &
        local pid=$!
        sleep 1
        sk upcp_launched pid "$pid"
        say_action "launched: /scripts/upcp --force --bg (pid hint $pid)"
        say_info "tail progress: ls -t /var/cpanel/updatelogs/ | head -1 | xargs -I{} tail -f /var/cpanel/updatelogs/{}"
        phase_set upcp ACTION "upcp launched"
    else
        sk upcp_pending
        say_warn "would launch /scripts/upcp --force --bg (use --apply)"
        phase_set upcp WARN "upcp pending --apply"
    fi
}

###############################################################################
# 4. proxysub
###############################################################################

phase_proxysub() {
    P_CUR=proxysub
    phase_begin proxysub

    local cfg=/var/cpanel/cpanel.config
    if [[ ! -r "$cfg" ]]; then
        sk no_cpanel_config
        say_fail "$cfg not readable"
        phase_set proxysub FAIL "config missing"
        return
    fi

    local cur_main cur_new
    cur_main=$(awk -F= '$1=="proxysubdomains"{print $2}' "$cfg")
    cur_new=$(awk -F= '$1=="proxysubdomainsfornewaccounts"{print $2}' "$cfg")
    sk current main "${cur_main:-unset}" newacct "${cur_new:-unset}"
    say_info "proxysubdomains=${cur_main:-<unset>}, proxysubdomainsfornewaccounts=${cur_new:-<unset>}"

    if [[ "$cur_main" == "1" && "$cur_new" == "1" ]]; then
        sk enabled
        say_pass "proxy subdomains enabled (existing + new accounts)"
        phase_set proxysub OK "enabled"
        return
    fi

    if [[ "$MODE" == "apply" ]]; then
        sk applying
        if have_cmd whmapi1; then
            local ok=1
            whmapi1 set_tweaksetting key=proxysubdomains value=1 \
                >/dev/null 2>&1 || ok=0
            whmapi1 set_tweaksetting key=proxysubdomainsfornewaccounts value=1 \
                >/dev/null 2>&1 || ok=0
            if (( ok )); then
                say_action "enabled proxysubdomains via whmapi1"
                # Trigger Apache vhost rebuild so proxy subdomains land in vhost
                # config. Idempotent - rebuildhttpdconf is safe to re-run.
                if [[ -x /scripts/rebuildhttpdconf ]]; then
                    /scripts/rebuildhttpdconf >/dev/null 2>&1 \
                        && say_action "rebuilt httpd conf" \
                        || say_warn "rebuildhttpdconf returned nonzero"
                fi
                phase_set proxysub ACTION "enabled"
            else
                say_fail "whmapi1 set_tweaksetting failed"
                phase_set proxysub FAIL "whmapi1 error"
            fi
        else
            say_fail "whmapi1 not available"
            phase_set proxysub FAIL "no whmapi1"
        fi
    else
        sk pending
        say_warn "proxy subdomains not fully enabled (would set both keys)"
        phase_set proxysub WARN "needs --apply"
    fi
}

###############################################################################
# 5/6. csf / apf
###############################################################################

# Strip cpsrvd ports from a CSV port list. Echoes cleaned list.
strip_cpsrvd_csv() {
    local csv="$1" p out
    out="$csv"
    for p in "${CPSRVD_PORTS[@]}"; do
        out=$(echo "$out" | sed -E "s/(^|,)${p}(,|$)/\1\2/g; s/^,//; s/,$//; s/,,/,/g")
    done
    echo "$out"
}

phase_csf() {
    P_CUR=csf
    phase_begin csf
    if ! [[ -f /etc/csf/csf.conf ]]; then
        sk csf_absent
        say_skip "csf not installed"
        phase_set csf SKIPPED "no csf"
        return
    fi

    local cfg=/etc/csf/csf.conf changed=0 key cur new found_any=""
    for key in TCP_IN TCP6_IN; do
        # Pull quoted value: KEY ="..."
        cur=$(grep -E "^${key}[[:space:]]*=" "$cfg" | head -1 | sed -E 's/^[^"]*"([^"]*)".*/\1/')
        if [[ -z "$cur" ]]; then
            sk csf_key_missing key "$key"
            say_warn "$key: not found in $cfg"
            continue
        fi
        local found="" p
        for p in "${CPSRVD_PORTS[@]}"; do
            if grep -qE "(^|,)${p}(,|$)" <<< "$cur"; then
                found+="$p "
            fi
        done
        sk csf_key_state key "$key" current "$cur"
        if [[ -z "$found" ]]; then
            say_pass "$key clean (no cpsrvd ports listed)"
            continue
        fi
        found_any+="$found"
        say_warn "$key contains cpsrvd ports: $found"
        if [[ "$MODE" == "apply" ]]; then
            new=$(strip_cpsrvd_csv "$cur")
            backup_file "$cfg"
            sed -i -E "s|^(${key}[[:space:]]*=[[:space:]]*\")[^\"]*(\".*)$|\1${new}\2|" "$cfg"
            sk csf_key_rewritten key "$key" new "$new"
            say_action "$key rewritten: $cur -> $new"
            changed=1
        else
            sk csf_key_pending key "$key"
            say_warn "would strip ports from $key (use --apply)"
        fi
    done

    # Range-overlap detection (informational; never auto-rewritten).
    local p
    for p in "${CPSRVD_PORTS[@]}"; do
        local rngs
        rngs=$(grep -E "^TCP_IN[[:space:]]*=" "$cfg" \
               | grep -oE '[0-9]+:[0-9]+' \
               | awk -F: -v p="$p" '$1<=p && p<=$2 {print}')
        if [[ -n "$rngs" ]]; then
            sk csf_range_overlap port "$p" range "$rngs"
            say_warn "TCP_IN range overlaps cpsrvd port $p: $rngs (manual review)"
        fi
    done

    if (( changed )); then
        sk csf_reload
        if have_cmd csf; then
            if csf -r >/dev/null 2>&1; then
                say_action "csf -r reloaded"
                phase_set csf ACTION "csf rewritten + reloaded"
            else
                say_fail "csf -r reload failed; review $cfg"
                phase_set csf FAIL "reload failed"
            fi
        else
            say_warn "csf binary missing; reload manually"
            phase_set csf WARN "rewritten, no reload"
        fi
    elif [[ -n "$found_any" && "$MODE" != "apply" ]]; then
        phase_set csf WARN "needs --apply"
    else
        phase_set csf OK "clean"
    fi
}

phase_apf() {
    P_CUR=apf
    phase_begin apf
    if ! [[ -f /etc/apf/conf.apf ]]; then
        sk apf_absent
        say_skip "apf not installed"
        phase_set apf SKIPPED "no apf"
        return
    fi

    local cfg=/etc/apf/conf.apf changed=0 cur new found="" p
    cur=$(grep -E '^IG_TCP_CPORTS[[:space:]]*=' "$cfg" | head -1 \
          | sed -E 's/^[^"]*"([^"]*)".*/\1/')
    if [[ -z "$cur" ]]; then
        sk apf_key_missing
        say_warn "IG_TCP_CPORTS not found in $cfg"
        phase_set apf WARN "key missing"
        return
    fi

    for p in "${CPSRVD_PORTS[@]}"; do
        grep -qE "(^|,)${p}(,|$)" <<< "$cur" && found+="$p "
    done
    sk apf_state current "$cur"
    if [[ -z "$found" ]]; then
        say_pass "IG_TCP_CPORTS clean"
        phase_set apf OK "clean"
        return
    fi

    say_warn "IG_TCP_CPORTS contains cpsrvd ports: $found"
    if [[ "$MODE" == "apply" ]]; then
        new=$(strip_cpsrvd_csv "$cur")
        backup_file "$cfg"
        sed -i -E "s|^(IG_TCP_CPORTS[[:space:]]*=[[:space:]]*\")[^\"]*(\".*)$|\1${new}\2|" "$cfg"
        sk apf_rewritten new "$new"
        say_action "IG_TCP_CPORTS rewritten: $cur -> $new"
        sk apf_reload
        if have_cmd apf; then
            if apf -r >/dev/null 2>&1; then
                say_action "apf -r reloaded"
                phase_set apf ACTION "apf rewritten + reloaded"
            else
                say_fail "apf -r reload failed"
                phase_set apf FAIL "reload failed"
            fi
        else
            phase_set apf WARN "rewritten, no apf reload"
        fi
    else
        sk apf_pending
        say_warn "would strip ports from IG_TCP_CPORTS (use --apply)"
        phase_set apf WARN "needs --apply"
    fi
}

###############################################################################
# 7. runfw - live netfilter inspection
###############################################################################

phase_runfw() {
    P_CUR=runfw
    phase_begin runfw

    local hits=0 p

    if have_cmd iptables; then
        # Walk INPUT plus all secondary chains it references. CSF puts the
        # cpsrvd-port ACCEPT rules in ALLOWIN-style chains; nft-aware iptables
        # may surface a deny but a stale rule could still ACCEPT.
        local secondary_chains
        secondary_chains=$(iptables -L INPUT -n 2>/dev/null \
                | awk 'NR>2 && NF>=2 {print $1}' \
                | grep -vE '^(ACCEPT|DROP|REJECT|LOG|RETURN|target|Chain)$' \
                | sort -u)
        for p in "${CPSRVD_PORTS[@]}"; do
            local c
            for c in INPUT $secondary_chains; do
                if iptables -L "$c" -n 2>/dev/null \
                     | awk -v p="$p" '$1=="ACCEPT" && $5=="0.0.0.0/0" \
                            && index($0,"dpt:"p" ") {found=1} END{exit !found}'
                then
                    sk iptables_open chain "$c" port "$p"
                    say_warn "iptables/$c allows tcp/$p from 0.0.0.0/0"
                    hits=$((hits+1))
                fi
            done
        done
        if (( hits == 0 )); then
            sk iptables_clean
            say_pass "iptables INPUT chain does not ACCEPT cpsrvd ports from 0.0.0.0/0"
        fi
    else
        sk no_iptables
        say_skip "iptables not present"
    fi

    if have_cmd ip6tables; then
        for p in "${CPSRVD_PORTS[@]}"; do
            if ip6tables -L INPUT -n 2>/dev/null \
                 | grep -E '^(ACCEPT)' \
                 | grep -E "::/0[[:space:]]+::/0[[:space:]].*dpt:${p}([[:space:]]|$)" \
                 | grep -q .
            then
                sk ip6tables_open port "$p"
                say_warn "ip6tables INPUT allows tcp/$p from ::/0"
                hits=$((hits+1))
            fi
        done
    fi

    if (( hits > 0 )); then
        say_warn "fix: edit csf TCP_IN/TCP6_IN or apf IG_TCP_CPORTS (phases csf/apf) and reload"
        phase_set runfw WARN "$hits open cpsrvd ports"
    else
        phase_set runfw OK "no open cpsrvd ports"
    fi
}

###############################################################################
# 8. apache
###############################################################################

phase_apache() {
    P_CUR=apache
    phase_begin apache

    # Apache process running.
    sk httpd_running
    local httpd_alive=0
    if pgrep -x httpd >/dev/null 2>&1 || pgrep -x apache2 >/dev/null 2>&1; then
        say_pass "httpd is running"
        httpd_alive=1
    elif have_cmd systemctl && systemctl is-active --quiet httpd 2>/dev/null; then
        say_pass "httpd is active (systemd)"
        httpd_alive=1
    else
        say_warn "httpd not running - modsec rules cannot fire"
        phase_set apache FAIL "httpd down"
        return
    fi

    # mod_security loaded.
    sk modsec_module
    local httpd_bin
    httpd_bin=$(command -v httpd 2>/dev/null \
        || ls /usr/local/apache/bin/httpd 2>/dev/null \
        || command -v apache2 2>/dev/null)
    if [[ -z "$httpd_bin" ]]; then
        say_fail "httpd binary not found"
        phase_set apache FAIL "no httpd binary"
        return
    fi
    if "$httpd_bin" -M 2>&1 | grep -qiE 'security2_module'; then
        say_pass "security2_module loaded"
        phase_set apache OK "loaded"
    else
        say_fail "security2_module NOT loaded"
        say_warn "fix: WHM > Security Center > ModSecurity Configuration > Install"
        say_warn "or:  yum install ea-apache24-mod_security2 && /scripts/restartsrv_httpd"
        phase_set apache FAIL "modsec not loaded"
    fi
}

###############################################################################
# 9. modsec
###############################################################################

# Locate a usable source for modsec-sessionscribe.conf. Echoes path; rc=1 if none.
locate_modsec_source() {
    local cand out
    for cand in "${MODSEC_SRC_CANDIDATES[@]}"; do
        if [[ "$cand" == http* ]]; then
            have_cmd curl || continue
            out=$(mktemp /tmp/sessionscribe-modsec.XXXXXX)
            if curl -fsSL --max-time 15 -o "$out" "$cand" 2>/dev/null \
                 && [[ -s "$out" ]]; then
                echo "$out"; return 0
            fi
            rm -f "$out"
        else
            [[ -r "$cand" ]] && { echo "$cand"; return 0; }
        fi
    done
    return 1
}

# Check rule presence: matches `id:NNN` shape but skips fully-commented lines.
modsec_has_rule() {
    local id="$1" file="$2"
    grep -E "^[[:space:]]*[^#].*\bid:${id}\b" "$file" >/dev/null 2>&1 \
        || grep -E "^[[:space:]]*[^#].*\bid:\"${id}\"" "$file" >/dev/null 2>&1
}

phase_modsec() {
    P_CUR=modsec
    phase_begin modsec

    if [[ ! -d "$(dirname "$MODSEC_USER_CONF")" ]]; then
        sk no_modsec_dir
        say_warn "$(dirname "$MODSEC_USER_CONF") missing - mod_security not configured"
        phase_set modsec WARN "no modsec dir"
        return
    fi

    local missing=() id present_info=()
    if [[ -f "$MODSEC_USER_CONF" ]]; then
        for id in "${REQUIRED_MODSEC_IDS[@]}"; do
            modsec_has_rule "$id" "$MODSEC_USER_CONF" || missing+=("$id")
        done
        for id in "${INFORMATIONAL_MODSEC_IDS[@]}"; do
            modsec_has_rule "$id" "$MODSEC_USER_CONF" && present_info+=("$id")
        done
    else
        missing=("${REQUIRED_MODSEC_IDS[@]}")
    fi

    sk required required_ids "${REQUIRED_MODSEC_IDS[*]}" missing "${missing[*]:-}"
    if (( ${#missing[@]} == 0 )); then
        say_pass "rules ${REQUIRED_MODSEC_IDS[*]} present in $MODSEC_USER_CONF"
        if (( ${#present_info[@]} == ${#INFORMATIONAL_MODSEC_IDS[@]} )); then
            sk informational_present ids "${present_info[*]}"
            say_info "informational rules ${present_info[*]} also present"
        elif (( ${#present_info[@]} > 0 )); then
            sk informational_partial ids "${present_info[*]}"
            say_info "partial WhmScribe-A coverage: ${present_info[*]}"
        fi
        phase_set modsec OK "all required rules present"
        return
    fi

    say_warn "missing required rule IDs: ${missing[*]}"

    if [[ "$MODE" != "apply" ]]; then
        sk pending
        say_warn "would deploy modsec-sessionscribe.conf (use --apply)"
        phase_set modsec WARN "needs --apply"
        return
    fi

    sk locate_source
    local src
    if ! src=$(locate_modsec_source); then
        say_fail "no modsec-sessionscribe.conf source available"
        say_fail "tried: ${MODSEC_SRC_CANDIDATES[*]}"
        phase_set modsec FAIL "no source"
        return
    fi
    say_info "source: $src"

    if [[ -s "$MODSEC_USER_CONF" ]]; then
        backup_file "$MODSEC_USER_CONF"
        # Append everything after the "# === RULES ===" anchor (matches the
        # repo convention). If anchor is missing, fall back to whole-file
        # append.
        if grep -q '^# === RULES ===' "$src"; then
            sed -n '/^# === RULES ===/,$p' "$src" >> "$MODSEC_USER_CONF"
        else
            cat "$src" >> "$MODSEC_USER_CONF"
        fi
        say_action "appended rules to $MODSEC_USER_CONF (backup: $BACKUP_DIR)"
    else
        cp "$src" "$MODSEC_USER_CONF"
        say_action "deployed $src to $MODSEC_USER_CONF"
    fi

    # Validate apache config.
    sk validate_apachectl
    local httpd_bin
    httpd_bin=$(command -v httpd 2>/dev/null || ls /usr/local/apache/bin/httpd 2>/dev/null)
    if [[ -z "$httpd_bin" ]] || ! "$httpd_bin" -t >/dev/null 2>&1; then
        say_fail "httpd -t failed after deploy; review $MODSEC_USER_CONF (backup: $BACKUP_DIR)"
        phase_set modsec FAIL "httpd -t failed"
        return
    fi
    say_pass "httpd -t validated"

    sk reload_apache
    if [[ -x /usr/local/cpanel/scripts/restartsrv_httpd ]]; then
        if /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1; then
            say_action "restarted httpd"
        else
            say_warn "restartsrv_httpd returned nonzero"
        fi
    elif have_cmd apachectl; then
        if apachectl graceful >/dev/null 2>&1; then
            say_action "apachectl graceful"
        else
            say_warn "apachectl graceful failed"
        fi
    fi
    phase_set modsec ACTION "rules deployed"
}

###############################################################################
# 10. sessions - forged-session IOC ladder + quarantine
###############################################################################
#
# Symmetric with sessionscribe-ioc-scan.sh's session-store IOC ladder. Walks
# /var/cpanel/sessions/raw/* and identifies forged sessions left behind by
# CRLF injection (CVE-2026-41940). The patch closes the *vector* for new
# forgeries, but a leaked cp_security_token survives until the session
# expires - so a host that was exploited pre-patch may still be reachable
# via the previously-forged token. This phase:
#
#   1. Detects forged sessions via the strong-IOC ladder
#      (A/B/C/D/E/E2/F/H/I; matches ioc-scan.sh strong signals).
#   2. In --apply mode: copies each forged session AND its sibling
#      companions (preauth/<sname>, cache/<sname>) into the run's backup
#      dir under `quarantined-sessions/{raw,preauth,cache}/`, writes a
#      sibling .info file preserving every metadata field that `cp -a`
#      cannot carry (most importantly ctime), then removes the originals
#      so the attacker cannot reuse the leaked token.
#
#      Why all three subdirs: cpsrvd's stage-3 listaccts handler in the
#      exploit chain propagates raw -> cache; subsequent token-bearing
#      requests read from cache. Removing raw alone leaves the cache copy
#      live and the cp_security_token still useful. preauth holds the
#      pre-promotion marker (IOC-B). The remote-probe --cleanup helper
#      already cleans all three for canary collateral; mitigation does
#      the same for actual forgeries.
#   3. In --check mode: reports what would be quarantined, no mutation.
#
# Probe-canary sessions (sessionscribe-remote-probe collateral, line
# matching ^nxesec_canary_<nonce>=) are skipped and counted separately so
# probe runs do not trigger mitigation.
#
# Bash floor: 4.1 (CentOS 6 ships bash-4.1.2). Avoids `[[ -v ]]` (4.2+),
# `declare -g` (4.2+), `printf '%(...)T'` (4.2+), `mapfile -d` (4.4+).
# Relies on GNU coreutils 8.4+ (`stat -c %Y/%X/%Z`, `date -d @<epoch>`)
# and findutils 4.4+ - both shipped with EL6.

phase_sessions() {
    P_CUR=sessions
    phase_begin sessions

    local raw_dir="$SESSIONS_DIR/raw"
    local preauth_dir="$SESSIONS_DIR/preauth"
    local cache_dir="$SESSIONS_DIR/cache"

    if [[ ! -d "$raw_dir" ]]; then
        sk no_session_dir
        say_skip "no $raw_dir"
        phase_set sessions SKIPPED "no session dir"
        return
    fi

    local now_epoch
    now_epoch=$(date -u +%s 2>/dev/null || echo 0)

    local scanned=0 forged=0 quarantined=0 partial=0 failed=0 probe_artifacts=0
    local f session_shape reasons sname preauth_file cache_file has_b q_rc

    # Iterate. nullglob is not enabled globally, so guard with -f.
    for f in "$raw_dir"/*; do
        [[ -f "$f" ]] || continue
        scanned=$((scanned+1))

        # Single awk pass extracts the session shape and emits one of:
        #   PROBE_ARTIFACT          - skip (probe collateral)
        #   FORGED:<reason-list>    - forged; reasons is CSV of A/B-cand/C/D/E/E2/F/H/I
        #   OK                      - clean
        # B-cand is "candidate IOC-B" - confirmed in bash by checking for
        # a paired preauth companion file (cpsrvd's write_session removes
        # the preauth marker on auth promotion, so paired existence is
        # structurally impossible in benign flow).
        session_shape=$(awk -v now="$now_epoch" -v floor="$PASS_FORGERY_MAX_LEN" \
                            -v canary_re="$PROBE_CANARY_PAT" '
            BEGIN { line_idx=0; pass_count=0; pass_at=0 }
            { line_idx++ }
            /^token_denied=/        { has_td=1 }
            /^cp_security_token=/   { has_cp=1 }
            /^origin_as_string=/ {
                origin=substr($0, index($0,"=")+1)
                if (origin ~ /method=badpass/) has_bp=1
            }
            /^successful_external_auth_with_timestamp=/ {
                has_ext=1; ts_val=substr($0, index($0,"=")+1)
            }
            /^successful_internal_auth_with_timestamp=/ {
                has_int=1; ts_val=substr($0, index($0,"=")+1)
            }
            /^tfa_verified=1/       { has_tfa=1 }
            /^hasroot=1/            { has_hasroot=1 }
            $0 ~ canary_re          { has_canary=1 }
            /^pass=/ {
                if (pass_count == 0) {
                    pass_val = substr($0, index($0,"=")+1)
                    pass_at = line_idx
                }
                pass_count++; next
            }
            pass_at > 0 && line_idx == pass_at + 1 && /./ \
                && !/^[A-Za-z_][A-Za-z0-9_]*=/ { stranded=1 }
            $0 != "" && $0 !~ /^[A-Za-z_][A-Za-z0-9_]*=/ { malformed=1 }
            END {
                if (has_canary) { print "PROBE_ARTIFACT"; exit }
                pass_len = length(pass_val)
                reasons = ""
                # IOC-A: token_denied + cp_security_token + badpass origin.
                if (has_td && has_cp && has_bp) reasons = reasons "A,"
                # IOC-B candidate (preauth companion verified by bash).
                if (has_ext || has_int) reasons = reasons "B-cand,"
                # IOC-C: short pass + auth_ts.
                if ((has_ext || has_int) && pass_len > 0 && pass_len <= floor+0)
                    reasons = reasons "C,"
                # IOC-D: multi-line / stranded pass.
                if (pass_count > 1 || stranded) reasons = reasons "D,"
                # IOC-E: badpass origin + any auth marker.
                if (has_bp && (has_ext || has_int || has_hasroot || has_tfa))
                    reasons = reasons "E,"
                # IOC-E2: 4-way co-occurrence (canonical exploit shape).
                if (has_hasroot && has_tfa && (has_ext || has_int) && has_bp)
                    reasons = reasons "E2,"
                # IOC-F: forged-future timestamp (>now+1y).
                if (ts_val ~ /^[0-9]+$/ && now+0 > 0 \
                    && ts_val+0 > now+0+31536000) reasons = reasons "F,"
                # IOC-H: standalone hasroot (not in cpsrvd _SESSION_PARTS
                # whitelist - conclusive injection footprint).
                if (has_hasroot) reasons = reasons "H,"
                # IOC-I: malformed (non-blank line not matching key=value).
                if (malformed) reasons = reasons "I,"
                sub(/,$/, "", reasons)
                if (reasons == "") print "OK"
                else print "FORGED:" reasons
            }
        ' "$f" 2>/dev/null)

        if [[ "$session_shape" == "PROBE_ARTIFACT" ]]; then
            probe_artifacts=$((probe_artifacts+1))
            continue
        fi
        [[ "$session_shape" == FORGED:* ]] || continue

        reasons="${session_shape#FORGED:}"
        sname=$(basename -- "$f")
        preauth_file="$preauth_dir/$sname"
        cache_file="$cache_dir/$sname"
        has_b=0

        # Resolve B-cand against preauth companion existence.
        if [[ ",$reasons," == *",B-cand,"* ]]; then
            if [[ -f "$preauth_file" ]]; then
                has_b=1
                # Promote B-cand -> B in the reasons string.
                reasons="${reasons//B-cand/B}"
            else
                # Drop B-cand: not by itself proof of forgery.
                reasons=$(echo "$reasons" \
                    | sed -e 's/^B-cand$//' \
                          -e 's/^B-cand,//' \
                          -e 's/,B-cand,/,/g' \
                          -e 's/,B-cand$//')
            fi
        fi

        # If reasons collapsed to empty after B downgrade, it was a
        # B-cand-only hit with no companion - not actionable.
        [[ -z "$reasons" ]] && continue

        forged=$((forged+1))
        # Cache companion presence is informational - quarantined uncondi-
        # tionally (cpsrvd raw->cache propagation makes it the live token
        # store; leaving it lets the forged session keep working).
        local has_cache=0
        [[ -f "$cache_file" ]] && has_cache=1
        sk forged_session path "$f" reasons "$reasons" \
           pre_companion "$has_b" cache_companion "$has_cache"

        if [[ "$MODE" != "apply" ]]; then
            local would_msg="ioc=$reasons; would quarantine"
            (( has_b ))     && would_msg+=" + preauth"
            (( has_cache )) && would_msg+=" + cache"
            say_warn "forged session: $f ($would_msg)"
            continue
        fi

        quarantine_session "$f" "$reasons" "$preauth_file" "$has_b" "$cache_file"
        q_rc=$?
        case "$q_rc" in
            0) quarantined=$((quarantined+1))
               say_action "quarantined $f (ioc=$reasons)"
               ;;
            2) partial=$((partial+1))
               say_warn "copy ok but rm failed: $f (manual cleanup needed)"
               ;;
            *) failed=$((failed+1))
               say_fail "quarantine failed: $f"
               ;;
        esac
    done

    sk sessions_summary \
       scanned "$scanned" forged "$forged" quarantined "$quarantined" \
       partial "$partial" failed "$failed" probe_artifacts "$probe_artifacts"

    if (( probe_artifacts > 0 )); then
        say_info "skipped $probe_artifacts probe-canary session(s) (sessionscribe-remote-probe collateral)"
    fi

    # Verdict: ACTION on clean apply, WARN on partial / check-mode finds,
    # FAIL on apply-mode failures, OK when nothing forged.
    if (( forged == 0 )); then
        say_pass "no forged sessions found ($scanned scanned)"
        phase_set sessions OK "$scanned scanned, clean"
    elif [[ "$MODE" != "apply" ]]; then
        say_warn "$forged forged session(s); needs --apply to quarantine"
        phase_set sessions WARN "$forged forged sessions"
    elif (( failed > 0 )); then
        phase_set sessions FAIL "$failed quarantine error(s); $quarantined ok, $partial partial"
    elif (( partial > 0 )); then
        say_warn "quarantined $quarantined; $partial partial (copy ok, rm failed)"
        phase_set sessions WARN "$quarantined ok, $partial partial"
    else
        say_action "quarantined $quarantined of $forged forged session(s) -> $BACKUP_DIR/quarantined-sessions/"
        phase_set sessions ACTION "$quarantined sessions quarantined"
    fi
}

# Move a forged session (and any sibling companion files) into the run's
# backup dir. Strategy:
#   - cp -a    -> preserves mode / owner / mtime / atime in the copy.
#   - .info    -> sibling text file recording fields cp -a cannot carry,
#                 most importantly ctime (which is the inode-change time
#                 and is unset-only-bumpable in POSIX). Also captures
#                 sha256, size, octal mode, uid/gid, and the IOC reasons.
#   - rm       -> remove the original so the leaked cp_security_token
#                 cannot be reused by the attacker.
#
# Companions handled:
#   - preauth/<sname>: pre-promotion marker (IOC-B). Quarantined when the
#     IOC ladder fired IOC-B (i.e. has_b=1).
#   - cache/<sname>:   cpsrvd's propagated copy. Quarantined whenever the
#     file exists - removing only raw/ leaves the live token store intact.
#
# Return codes (highest priority wins across raw + companions):
#   0 - all copies + .info + rm succeeded
#   2 - copies + .info ok but at least one rm of an original FAILED
#   1 - the raw copy itself failed (no .info written, original untouched)
#
# Bash 4.1 / coreutils 8.4 compatible.
quarantine_session() {
    local src="$1" reasons="$2" preauth_companion="$3" has_b="$4"
    local cache_companion="${5:-}"
    ensure_backup_dir || return 1

    local qdir="$BACKUP_DIR/quarantined-sessions"
    local qraw="$qdir/raw" qpre="$qdir/preauth" qcache="$qdir/cache"
    if ! mkdir -p "$qraw" "$qpre" "$qcache" 2>/dev/null; then
        return 1
    fi
    # Quarantine subtree contains forged-session bodies (which may carry
    # cp_security_token values, hex-encoded passwords, etc). Lock down to
    # 0700 so only root can read - same posture as sessionscribe-forensic
    # bundle dirs. No-op if the dirs were already created on a prior run.
    chmod 0700 "$qdir" "$qraw" "$qpre" "$qcache" 2>/dev/null || true

    local sname dest info
    sname=$(basename -- "$src")
    dest="$qraw/$sname"
    info="$qraw/${sname}.info"

    # Copy first; preserves mode/owner/mtime/atime.
    if ! cp -a -- "$src" "$dest" 2>/dev/null; then
        return 1
    fi

    # Metadata sidecar - written from the ORIGINAL's stat (not the copy)
    # so ctime reflects the attacker's write, not our cp.
    write_session_info "$src" "$dest" "$reasons" > "$info" 2>/dev/null

    # Track whether any rm step failed across raw + companions. The raw
    # rm at the bottom may also flip this; partial-success (rc=2) wins
    # over full success but is dominated by an earlier rc=1 (which
    # already returned).
    local partial=0

    # Companion preauth file. Only quarantined if IOC-B fired (i.e. the
    # raw session was paired with a preauth marker that should not exist
    # post-promotion in a benign flow).
    if [[ "$has_b" == "1" && -f "$preauth_companion" ]]; then
        local pdest="$qpre/$sname"
        local pinfo="$qpre/${sname}.info"
        if cp -a -- "$preauth_companion" "$pdest" 2>/dev/null; then
            write_session_info "$preauth_companion" "$pdest" \
                "preauth-companion-of:$sname" > "$pinfo" 2>/dev/null
            rm -f -- "$preauth_companion" 2>/dev/null || partial=1
        fi
    fi

    # Companion cache file. Always quarantined when present - this is the
    # live token store cpsrvd reads on subsequent requests. Leaving it
    # would let the leaked cp_security_token continue to authenticate
    # even after raw/ removal.
    if [[ -n "$cache_companion" && -f "$cache_companion" ]]; then
        local cdest="$qcache/$sname"
        local cinfo="$qcache/${sname}.info"
        if cp -a -- "$cache_companion" "$cdest" 2>/dev/null; then
            write_session_info "$cache_companion" "$cdest" \
                "cache-companion-of:$sname" > "$cinfo" 2>/dev/null
            rm -f -- "$cache_companion" 2>/dev/null || partial=1
        fi
    fi

    # Final step: remove the original raw session. If this fails (read-only
    # mount, immutable bit, etc.) the attacker can still reuse the token,
    # so we report partial-success (rc=2) rather than success. Same logic
    # if a companion (preauth/cache) rm failed earlier in the function.
    if ! rm -f -- "$src" 2>/dev/null; then
        return 2
    fi
    (( partial )) && return 2
    return 0
}

# Build the .info sidecar content. Captures every field that cp -a cannot
# carry across a copy (ctime above all), plus integrity fingerprints
# (sha256, size) and the IOC reasons that triggered the quarantine.
#
# Fields are key=value per line, no quoting, intended for cheap awk/sed
# consumption by recovery scripts. Values come from stat / sha256sum /
# script constants - none are unbounded user input - but printf '%s\n'
# is used over heredoc to dodge any $() / backtick interpretation if a
# session filename ever does contain shell metacharacters.
write_session_info() {
    local orig="$1" copy="$2" reasons="$3"

    local mtime_e atime_e ctime_e size mode uid gid sha=""
    mtime_e=$(stat -c %Y "$orig" 2>/dev/null)
    atime_e=$(stat -c %X "$orig" 2>/dev/null)
    ctime_e=$(stat -c %Z "$orig" 2>/dev/null)
    size=$(stat -c %s "$orig" 2>/dev/null)
    mode=$(stat -c %a "$orig" 2>/dev/null)
    uid=$(stat -c %u "$orig" 2>/dev/null)
    gid=$(stat -c %g "$orig" 2>/dev/null)

    if have_cmd sha256sum; then
        sha=$(sha256sum -- "$orig" 2>/dev/null | awk '{print $1}')
    fi

    printf '%s\n' \
        "# sessionscribe-mitigate quarantine record" \
        "# Preserves metadata that cp -a cannot carry (notably ctime)." \
        "tool=sessionscribe-mitigate" \
        "tool_version=$VERSION" \
        "run_id=$RUN_ID" \
        "quarantine_ts=$TS_ISO" \
        "host=$HOSTNAME_FQDN" \
        "original_path=$orig" \
        "quarantined_path=$copy" \
        "reasons_ioc=$reasons" \
        "sha256=$sha" \
        "size_bytes=${size:-}" \
        "mode_octal=${mode:-}" \
        "uid=${uid:-}" \
        "gid=${gid:-}" \
        "mtime_epoch=${mtime_e:-}" \
        "mtime_iso=$(epoch_to_iso "${mtime_e:-}")" \
        "atime_epoch=${atime_e:-}" \
        "atime_iso=$(epoch_to_iso "${atime_e:-}")" \
        "ctime_epoch=${ctime_e:-}" \
        "ctime_iso=$(epoch_to_iso "${ctime_e:-}")"
}

###############################################################################
# 11. probe (opt-in self-test)
###############################################################################

phase_probe() {
    P_CUR=probe
    phase_begin probe

    if (( DO_PROBE == 0 )); then
        sk probe_optout
        say_skip "--probe not specified (opt-in)"
        phase_set probe SKIPPED "opt-in"
        return
    fi

    # Locate a probe binary. Prefer a sibling next to this script, then /tmp,
    # then fall back to fetching from the CDN below.
    local probe_bin=""
    local self_dir
    self_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || self_dir=""
    for cand in "${self_dir:+$self_dir/sessionscribe-remote-probe.sh}" \
                /tmp/sessionscribe-remote-probe.sh; do
        [[ -n "$cand" && -r "$cand" ]] && { probe_bin="$cand"; break; }
    done
    if [[ -z "$probe_bin" ]] && have_cmd curl; then
        probe_bin=$(mktemp /tmp/sessionscribe-probe.XXXXXX)
        curl -fsSL --max-time 15 \
             -o "$probe_bin" \
             https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-remote-probe.sh \
             2>/dev/null && [[ -s "$probe_bin" ]] || probe_bin=""
    fi
    if [[ -z "$probe_bin" ]]; then
        sk probe_no_source
        say_fail "no remote-probe binary available locally"
        phase_set probe FAIL "no probe"
        return
    fi
    say_info "probe: $probe_bin"

    sk probe_run target "127.0.0.1" port "2087"
    local out rc
    out=$(bash "$probe_bin" --target 127.0.0.1 --port 2087 \
              --quiet --no-color --no-progress 2>&1)
    rc=$?
    say_info "probe exit=$rc"
    case "$rc" in
        0) say_pass "probe verdict CLEAN (no VULN)"; phase_set probe OK "no VULN" ;;
        1) say_warn "probe inconclusive"; phase_set probe WARN "inconclusive" ;;
        2) say_fail "probe verdict VULN - mitigation incomplete"
           echo "$out" | sed 's/^/    /' >&2
           phase_set probe FAIL "VULN" ;;
        *) say_fail "probe error rc=$rc"; phase_set probe FAIL "rc=$rc" ;;
    esac
}

###############################################################################
# Output: summary, JSON envelope, CSV row
###############################################################################

print_summary_text() {
    (( QUIET )) && return
    printf '\n%s== summary ==%s\n' "$C_BLD" "$C_NC" >&2
    printf '  host: %s   os: %s   cpanel: %s\n' \
        "$HOSTNAME_FQDN" "$OS_PRETTY" "${CPANEL_NORM:-unknown}" >&2
    local p v col
    for p in "${PHASE_ORDER_RUN[@]}"; do
        v="${P_VERDICT[$p]:-?}"
        col="$C_DIM"
        case "$v" in
            OK)     col="$C_GRN" ;;
            ACTION) col="$C_CYN" ;;
            WARN)   col="$C_YEL" ;;
            FAIL)   col="$C_RED" ;;
        esac
        printf '  %s%-9s%s %-12s %s\n' "$col" "$v" "$C_NC" "$p" \
            "${P_DETAIL[$p]:-}" >&2
    done
    printf '\n  %d ok / %d action / %d warn / %d fail / %d skipped\n\n' \
        "$N_OK" "$N_ACTION" "$N_WARN" "$N_FAIL" "$N_SKIPPED" >&2
}

write_json_envelope() {
    local out="$1"
    {
        printf '{\n'
        printf '  "tool": "sessionscribe-mitigate",\n'
        printf '  "tool_version": "%s",\n' "$VERSION"
        printf '  "host": "%s",\n' "$HOSTNAME_J"
        printf '  "os": "%s",\n' "$OS_J"
        printf '  "cpanel_version": "%s",\n' "$CPV_J"
        printf '  "cpanel_version_raw": "%s",\n' "$(json_esc "$CPANEL_RAW")"
        printf '  "ts": "%s",\n' "$TS_ISO"
        printf '  "mode": "%s",\n' "$MODE"
        printf '  "exit_code": %d,\n' "$EXIT_CODE"
        printf '  "summary": {"ok":%d,"action":%d,"warn":%d,"fail":%d,"skipped":%d},\n' \
            "$N_OK" "$N_ACTION" "$N_WARN" "$N_FAIL" "$N_SKIPPED"
        printf '  "phases": [\n'
        local i p first=1
        for p in "${PHASE_ORDER_RUN[@]}"; do
            (( first )) || printf ',\n'
            first=0
            printf '    {"phase":"%s","verdict":"%s","detail":"%s"}' \
                "$p" "${P_VERDICT[$p]:-?}" \
                "$(json_esc "${P_DETAIL[$p]:-}")"
        done
        printf '\n  ],\n'
        printf '  "signals": [\n'
        local first=1 line
        for line in "${SIGNALS_JSON[@]:-}"; do
            [[ -z "$line" ]] && continue
            (( first )) || printf ',\n'
            first=0
            printf '    %s' "$line"
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

write_csv_row() {
    local out="$1"
    local p details=""
    for p in "${PHASE_ORDER_RUN[@]}"; do
        details+="${details:+;}${p}=${P_VERDICT[$p]:-?}"
        if [[ -n "${P_DETAIL[$p]:-}" ]]; then
            details+="(${P_DETAIL[$p]})"
        fi
    done
    {
        # Static columns + per-phase columns. Phase columns are dynamic
        # based on PHASE_ORDER_RUN to keep schema stable across --only runs.
        printf 'host,os,cpanel_version,cpanel_version_raw,ts,tool_version,mode,exit_code,ok,action,warn,fail,skipped'
        for p in "${PHASE_ORDER_RUN[@]}"; do printf ',%s' "$p"; done
        printf ',details\n'
        printf '%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d' \
            "$(csv_field "$HOSTNAME_FQDN")" \
            "$(csv_field "$OS_PRETTY")" \
            "$(csv_field "${CPANEL_NORM:-unknown}")" \
            "$(csv_field "$CPANEL_RAW")" \
            "$(csv_field "$TS_ISO")" \
            "$(csv_field "$VERSION")" \
            "$(csv_field "$MODE")" \
            "$EXIT_CODE" \
            "$N_OK" "$N_ACTION" "$N_WARN" "$N_FAIL" "$N_SKIPPED"
        for p in "${PHASE_ORDER_RUN[@]}"; do
            printf ',%s' "$(csv_field "${P_VERDICT[$p]:-?}")"
        done
        printf ',%s\n' "$(csv_field "$details")"
    } > "$out"
}

emit_summary_signal() {
    # One trailing JSONL summary signal so consumers can drive on a single
    # line per host without needing the envelope.
    P_CUR="run"
    sk run_summary \
       ok "$N_OK" \
       action "$N_ACTION" \
       warn "$N_WARN" \
       fail "$N_FAIL" \
       skipped "$N_SKIPPED" \
       exit_code "$EXIT_CODE"
    local sev="info"
    case "$EXIT_CODE" in
        0) sev="pass" ;;
        1) sev="action" ;;
        2) sev="warn" ;;
        *) sev="fail" ;;
    esac
    emit_signal run "$sev" "run_summary" \
        "exit=$EXIT_CODE ok=$N_OK action=$N_ACTION warn=$N_WARN fail=$N_FAIL skipped=$N_SKIPPED" \
        "${P_KV[@]}"
}

###############################################################################
# Main
###############################################################################

run_phase() {
    local pid="$1"
    if [[ -z "${PHASE_ACTIVE[$pid]:-}" ]]; then
        return 0
    fi
    case "$pid" in
        patch)      phase_patch ;;
        preflight)  phase_preflight ;;
        upcp)       phase_upcp ;;
        proxysub)   phase_proxysub ;;
        csf)        phase_csf ;;
        apf)        phase_apf ;;
        runfw)      phase_runfw ;;
        apache)     phase_apache ;;
        modsec)     phase_modsec ;;
        sessions)   phase_sessions ;;
        probe)      phase_probe ;;
    esac
}

if (( QUIET == 0 )); then
    printf '\n%ssessionscribe-mitigate%s v%s - CVE-2026-41940 defense-in-depth\n' \
        "$C_BLD" "$C_NC" "$VERSION" >&2
    printf '  host: %s    os: %s    cpanel: %s\n' \
        "$HOSTNAME_FQDN" "$OS_PRETTY" "${CPANEL_NORM:-unknown}" >&2
    printf '  mode: %s    ts: %s    run_id: %s\n' \
        "$MODE" "$TS_ISO" "$RUN_ID" >&2
fi

PATCH_STATE="UNKNOWN"

for pid in "${PHASE_IDS[@]}"; do
    run_phase "$pid"
done

# Compute exit code.
EXIT_CODE=0
if (( N_FAIL > 0 )); then
    EXIT_CODE=2
elif [[ "$MODE" == "check" && $N_WARN -gt 0 ]]; then
    EXIT_CODE=2
elif (( N_ACTION > 0 )); then
    EXIT_CODE=1
fi

# Trailing JSONL summary signal (also added to SIGNALS_JSON for envelope).
emit_summary_signal

print_summary_text

# stdout streaming output.
if (( CSV_OUT )); then
    write_csv_row /dev/stdout
fi

# File output (-o FILE). Format follows --csv if set, JSON envelope otherwise.
if [[ -n "$OUTPUT_FILE" ]]; then
    if (( CSV_OUT )); then
        write_csv_row "$OUTPUT_FILE"
    else
        write_json_envelope "$OUTPUT_FILE"
    fi
fi

# --json single envelope on stdout.
if (( JSON_OUT )); then
    write_json_envelope /dev/stdout
fi

exit $EXIT_CODE
