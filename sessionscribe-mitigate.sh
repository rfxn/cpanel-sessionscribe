#!/bin/bash
#
##
# sessionscribe-mitigate.sh v0.6.1
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
###############################################################################
# sessionscribe-mitigate.sh
#
# DISCLAIMER / USE AT YOUR OWN RISK
#   Active mitigation. Modifies firewall, repos, tweaksettings, Apache
#   config; may launch /scripts/upcp. Default --check is read-only;
#   --apply mutates. Validate against change-control first.
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
#   snapshot    pre-mitigation evidence capture (users/, accounting.log,
#               sessions/, cpanel.config, tweaksettings) BEFORE mutation.
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
#   sessions    sessions/raw IOC ladder; quarantine forged sessions to
#               backup dir w/ .info (ctime); rm originals
#   probe       (opt-in via --probe) self-test via remote-probe against
#               127.0.0.1; expect SAFE/blocked verdict
#   kill        (opt-in via --kill) targeted quarantine + IP block from
#               an IOC envelope (sessionscribe-ioc-scan output). Reads
#               the latest /var/cpanel/sessionscribe-ioc/*.json (or
#               --envelope PATH), builds a manifest of file quarantines
#               + attacker IP blocks, and (with --apply) executes them:
#               files moved to <BACKUP_DIR>/quarantine/<mirrored-path>
#               with sha256 chain-of-custody; per-incident IPs added via
#               csf -d; rfxn fleet blocklist registered in
#               /etc/csf/csf.blocklists with LF_IPSET=1. Path allowlist
#               refuses anything outside /root/, /home/*/, /etc/profile.d/,
#               /etc/systemd/system/, /etc/udev/rules.d/, /etc/cron.{d,*}/,
#               /var/spool/cron/, /usr/local/cpanel/var/. Gated on
#               host_verdict == COMPROMISED (override: --kill-anyway).
#
# Output:
#   default     ANSI sectioned report on stderr
#   --json      single JSON envelope on stdout (per-host)
#   --jsonl     stream one JSON signal per line on stdout
#   --csv       single CSV summary row on stdout (header + one row)
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

VERSION="0.6.1"

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

# Pre-mitigation snapshot tier-2 (sessions corpus) size cap. Tier-1
# (accounts/accounting/audit) is always captured (typically <1MB). The
# session corpus can grow to hundreds of MB on busy hosts; cap so a
# runaway session store doesn't blow the BACKUP_ROOT filesystem.
MAX_SNAPSHOT_MB_DEFAULT=500

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

PHASE_IDS=(snapshot patch preflight upcp proxysub csf apf runfw apache modsec sessions probe kill)
PHASE_DEFAULT_ON=(1        1     1         1    1        1   1   1     1      1      1        0     0)
declare -A PHASE_DESC=(
    [snapshot]="pre-mitigation evidence capture (sessions, users, accounting.log)"
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
    [kill]="(opt-in) targeted quarantine + IP block from IOC envelope (--kill)"
)

###############################################################################
# Argument parsing
###############################################################################

MODE="check"            # check | apply
ONLY_LIST=""            # CSV phase IDs; empty = all defaults-on
DO_PROBE=0              # --probe opt-in
RUN_KILL=0              # --kill opt-in (phase_kill from IOC envelope)
KILL_ENVELOPE=""        # --envelope PATH override; empty = auto-discover
KILL_ANYWAY=0           # --kill-anyway: bypass host_verdict gate
declare -A PHASE_DISABLED=()
JSON_OUT=0
JSONL_OUT=0
CSV_OUT=0
QUIET=0
NO_COLOR_FLAG=0
OUTPUT_FILE=""
BACKUP_ROOT="$BACKUP_ROOT_DEFAULT"
MAX_SNAPSHOT_MB="$MAX_SNAPSHOT_MB_DEFAULT"
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
                             --no-snapshot  --no-patch       --no-preflight
                             --no-upcp      --no-proxysub    --no-csf
                             --no-apf       --no-runfw       --no-apache
                             --no-modsec    --no-sessions    --no-kill
    --no-fw                Shorthand for --no-csf --no-apf --no-runfw.
    --probe                Enable the optional probe phase (opt-in).
                           Runs sessionscribe-remote-probe.sh against
                           127.0.0.1:2087; expects SAFE/blocked verdict.
    --kill                 Enable the optional kill-chain phase (opt-in).
                           Reads the latest sessionscribe-ioc-scan envelope,
                           builds a manifest of quarantine actions + attacker
                           IP blocks, and (with --apply) executes them.
                           Gated on host_verdict == COMPROMISED unless
                           --kill-anyway is set.
    --envelope PATH        Use this IOC envelope JSON instead of auto-
                           discovering the newest under /var/cpanel/
                           sessionscribe-ioc/*.json. Implies --kill.
    --kill-anyway          Run the kill chain even if host_verdict is not
                           COMPROMISED (operator-confirmed override).
                           Implies --kill.
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
    --max-snapshot-mb MB   Cap on the pre-mitigation session-tier snapshot
                           (default: $MAX_SNAPSHOT_MB_DEFAULT). Tier-1 (accounts,
                           accounting.log, audit.log, cpanel.config) is
                           always captured. If sessions/{raw,preauth,cache}
                           combined size exceeds the cap, the session tier
                           is skipped with a WARN; other tiers proceed.
                           0 = skip session tier entirely.
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
        --kill)             RUN_KILL=1; shift ;;
        --envelope)         KILL_ENVELOPE="$2"; RUN_KILL=1; shift 2 ;;
        --kill-anyway)      KILL_ANYWAY=1; RUN_KILL=1; shift ;;
        --no-kill)          PHASE_DISABLED[kill]=1; shift ;;
        --no-snapshot)      PHASE_DISABLED[snapshot]=1; shift ;;
        --no-upcp)          PHASE_DISABLED[upcp]=1; shift ;;
        --no-modsec)        PHASE_DISABLED[modsec]=1; shift ;;
        --no-sessions)      PHASE_DISABLED[sessions]=1; shift ;;
        --max-snapshot-mb)  MAX_SNAPSHOT_MB="$2"; shift 2 ;;
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

# Validate --max-snapshot-mb is a non-negative integer (0 = skip session
# tier entirely; tier1 still captured).
if ! [[ "$MAX_SNAPSHOT_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --max-snapshot-mb requires a non-negative integer (MB)" >&2
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
# --kill opt-in toggles the kill-chain phase regardless of defaults.
if (( RUN_KILL )) && [[ -z "${PHASE_DISABLED[kill]:-}" ]]; then
    PHASE_ACTIVE[kill]=1
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
declare -a SIGNALS_JSON=()     # JSONL strings (already escaped + assembled)

N_OK=0; N_WARN=0; N_FAIL=0; N_ACTION=0; N_SKIPPED=0

# Emit a structured signal. JSONL streams immediately; else buffered.
# Args: phase severity key [note] [k v ...]
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
# Kill-chain (phase_kill) helpers - read IOC envelope, build manifest of
# intended quarantine + IP-block actions. Manifest is the audit-trail source
# of truth. K1 deliverable: read-only manifest construction. Mutating actions
# land in K3 (file quarantine), K4 (CSF deny), K5 (rfxn blocklist register).
# Field-extraction helpers mirror sessionscribe-ioc-scan.sh primitives so
# producer/consumer parsing is a single shared contract.
###############################################################################

KILL_ENVELOPE_DIR="/var/cpanel/sessionscribe-ioc"

# Trust regex for ssh-key prune. MUST KEEP IN BYTE-EQUAL SYNC with
# sessionscribe-ioc-scan.sh:285 (SSH_KNOWN_GOOD_RE). The
# kill_sshkey_check_trust_drift() gate enforces this at phase_kill startup.
KILL_SSH_TRUST_RE='(lwadmin|lw-admin|liquidweb|nexcess|Parent Child key for [A-Z0-9]{6})'

# Recognized SSH keytype tokens (awk-portable ERE; gawk 3.x — no `{n}`
# intervals; `[.]` instead of `\.` to avoid gawk 3.x "escape sequence
# treated as plain" warnings). Standard: ssh-rsa, ssh-ed25519, ssh-dss,
# ecdsa-sha2-*. FIDO (OpenSSH 8.2+): sk-ssh-ed25519, sk-ecdsa-sha2-nistp*
# with optional @openssh.com suffix.
KILL_SSH_KEYTYPE_RE='(sk-)?(ssh-(rsa|ed25519|dss)|ecdsa-sha2-[a-zA-Z0-9._-]+)(@openssh[.]com)?'

# Newest envelope JSON by mtime; empty if dir absent or no JSON files.
kill_find_envelope() {
    [[ -d "$KILL_ENVELOPE_DIR" ]] || return 0
    ls -1t "$KILL_ENVELOPE_DIR"/*.json 2>/dev/null | head -1
}

# Extract a top-level scalar (host_verdict, run_id, ts, tool_version, score).
# Skips signal-array lines (those start with {"host":). Mirrors ioc-scan's
# envelope_root_field exactly.
kill_envelope_root_field() {
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

# String-field extraction from a single signal line. Mirrors ioc-scan's
# json_str_field. Handles \\ and \" via parameter expansion.
kill_json_str_field() {
    local line="$1" key="$2" v
    v=$(printf '%s\n' "$line" | grep -oE "\"$key\":\"([^\"\\\\]|\\\\.)*\"" | head -1)
    [[ -z "$v" ]] && return 0
    v="${v#*\":\"}"
    v="${v%\"}"
    v="${v//\\\"/\"}"
    v="${v//\\\\/\\}"
    printf '%s' "$v"
}

# Numeric-or-stringified-numeric field from a signal line.
kill_json_num_field() {
    local line="$1" key="$2" v
    v=$(printf '%s\n' "$line" | grep -oE "\"$key\":(\"[0-9.+-]*\"|-?[0-9]+(\.[0-9]+)?)" | head -1)
    [[ -z "$v" ]] && return 0
    v="${v#*\":}"
    v="${v#\"}"
    v="${v%\"}"
    printf '%s' "$v"
}

# Pattern-letter mapping. Patterns A/C/D/F/G/H/I/J emit on-disk evidence
# (eligible for quarantine). B is structural (mysql wipe = absent dir, no
# fs target). E is log/session-resident (handled by phase_sessions). The
# pre-compromise advisory keys map to "skip" so they never enter the manifest.
kill_pattern_for_key() {
    case "$1" in
        (ioc_pattern_e_websocket_shell_hits_pre_compromise) echo skip ;;
        (ioc_pattern_e_websocket_shell_hits_orphan)         echo skip ;;
        (ioc_attacker_ip_2xx_on_cpsess_pre_compromise)      echo skip ;;
        (ioc_pattern_a_*)              echo A ;;
        (ioc_pattern_b_*)              echo B ;;
        (ioc_pattern_c_*)              echo C ;;
        (ioc_pattern_d_*)              echo D ;;
        (ioc_pattern_e_*)              echo E ;;
        (ioc_pattern_f_*)              echo F ;;
        (ioc_pattern_g_*)              echo G ;;
        (ioc_pattern_h_*)              echo H ;;
        (ioc_pattern_i_*)              echo I ;;
        (ioc_pattern_j_*)              echo J ;;
        (ioc_attacker_ip_2xx_on_cpsess) echo ip ;;
        (ioc_attacker_ip_in_access_log_probes_only) echo ip ;;
        (ioc_attacker_ip*)             echo skip ;;
        (*)                            echo skip ;;
    esac
}

# Per-pattern action policy. Returns "quarantine" for patterns that emit
# on-disk evidence we should move to BACKUP_DIR/quarantine/, "skip" otherwise.
kill_action_for_pattern() {
    case "$1" in
        (A|C|D|F|G|H|I|J) echo quarantine ;;
        (*) echo skip ;;
    esac
}

###############################################################################
# SSH-key prune helpers (v0.7.0 phase_kill --ssh-prune family). Implements
# the parser + classifier + surgical-prune contract from PLAN-sshkey-prune.md.
# All helpers are callable under MITIGATE_LIBRARY_ONLY=1 for unit testing.
###############################################################################

# ssh_key_parse_line LINE — emit "<keytype>\t<comment>\t<base64>" on stdout
# for a parseable key line. rc=1 (no output) for blank/comment/unparseable.
# Handles options-prefix lines via FIRST-MATCH-WINS keytype detection
# (whole-line scan via gawk 2-arg `match()`; the keytype regex is anchored
# only by what appears in the source — substring matching is intentional
# so options-prefix syntax like `from="..." ssh-rsa AAAA user` works).
# Empty comment is a valid result (rc=0 with "<keytype>\t\t<base64>"); the
# classifier applies policy.
ssh_key_parse_line() {
    local line="${1-}"
    [[ -z "$line" ]] && return 1
    # Strip leading whitespace; refuse comment-only lines.
    local trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" ]] && return 1
    [[ "$trimmed" == \#* ]] && return 1
    # gawk 3.x 2-arg match() sets RSTART/RLENGTH globally. We locate the
    # FIRST keytype substring on the line, then take the next whitespace
    # token after it as the base64 blob and the remainder (joined by
    # single spaces) as the comment. The 3rd field (base64) is the
    # load-bearing identity for ssh_key_fingerprint.
    awk -v keyre="$KILL_SSH_KEYTYPE_RE" '
        {
            if (! match($0, keyre)) exit 1
            kt = substr($0, RSTART, RLENGTH)
            rest = substr($0, RSTART + RLENGTH)
            # Strip leading whitespace from rest, then split into base64
            # + comment-tail.
            sub(/^[[:space:]]+/, "", rest)
            if (rest == "") exit 1
            # The base64 blob is the first whitespace-delimited token of
            # the remainder. Everything after the next whitespace run is
            # the (joined-by-single-space) comment.
            i = match(rest, /[[:space:]]+/)
            if (i == 0) {
                b64 = rest
                cmt = ""
            } else {
                b64 = substr(rest, 1, i - 1)
                cmt = substr(rest, i + RLENGTH)
                # Collapse internal whitespace runs to single spaces and
                # strip trailing whitespace.
                gsub(/[[:space:]]+/, " ", cmt)
                sub(/[[:space:]]+$/, "", cmt)
            }
            printf "%s\t%s\t%s\n", kt, cmt, b64
        }
    ' <<< "$line"
}

# ssh_key_fingerprint LINE — emit a non-cryptographic identifier. Tries
# ssh-keygen MD5 first (EL6 OpenSSH 5.3 baseline) and falls back to a
# base64-decoded sha256 of the key blob (B64SHA256:<hex>). Always returns
# rc=0; empty output if both methods fail or the line is unparseable.
ssh_key_fingerprint() {
    local line="${1-}" parsed b64 fp
    parsed=$(ssh_key_parse_line "$line") || { printf ''; return 0; }
    b64=$(printf '%s' "$parsed" | awk -F'\t' '{print $3}')
    [[ -z "$b64" ]] && { printf ''; return 0; }
    if have_cmd ssh-keygen; then
        fp=$(ssh-keygen -lf <(printf '%s\n' "$line") 2>/dev/null | awk '{print $2}')
        if [[ -n "$fp" ]]; then
            # ssh-keygen 5.3+ emits "<bits> <fp> <comment>". Older
            # versions print bare hex; normalize to MD5: prefix when
            # the value is colon-quad without a prefix.
            case "$fp" in
                (MD5:*|SHA256:*) printf '%s' "$fp" ;;
                (*:*:*)          printf 'MD5:%s' "$fp" ;;
                (*)              printf '%s' "$fp" ;;
            esac
            return 0
        fi
    fi
    if have_cmd base64 && have_cmd sha256sum; then
        fp=$(printf '%s' "$b64" | base64 -d 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')
        if [[ -n "$fp" ]]; then
            printf 'B64SHA256:%s' "$fp"
            return 0
        fi
    fi
    printf ''
    return 0
}

# ssh_keys_classify FILE TRUST_RE [--include-unlabeled-as-prune] — stream
# a file as TSV: action<TAB>line_no<TAB>keytype<TAB>comment<TAB>fingerprint
# <TAB>base64_first_24. action ∈ {keep, prune, keep_unlabeled, skip}. rc:
#   0 — successful classification
#   2 — symlink refused
#   3 — at least one non-blank/non-comment line failed to parse
ssh_keys_classify() {
    local file="$1" trust_re="$2" flag="${3-}"
    local include_unlabeled=0
    [[ "$flag" == "--include-unlabeled-as-prune" ]] && include_unlabeled=1
    [[ -L "$file" ]] && return 2
    [[ -r "$file" ]] || return 3
    local lineno=0 line trimmed parsed kt cmt b64 fp first24 action
    local parse_failed=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))
        trimmed="${line#"${line%%[![:space:]]*}"}"
        if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
            printf 'skip\t%d\t\t\t\t\n' "$lineno"
            continue
        fi
        parsed=$(ssh_key_parse_line "$line") || { parse_failed=1; continue; }
        kt=$(printf '%s' "$parsed" | awk -F'\t' '{print $1}')
        cmt=$(printf '%s' "$parsed" | awk -F'\t' '{print $2}')
        b64=$(printf '%s' "$parsed" | awk -F'\t' '{print $3}')
        first24="${b64:0:24}"
        fp=$(ssh_key_fingerprint "$line")
        if [[ -z "$cmt" ]]; then
            if (( include_unlabeled )); then
                action=prune
            else
                action=keep_unlabeled
            fi
        elif [[ "$cmt" =~ $trust_re ]]; then
            action=keep
        else
            action=prune
        fi
        printf '%s\t%d\t%s\t%s\t%s\t%s\n' \
            "$action" "$lineno" "$kt" "$cmt" "$fp" "$first24"
    done < "$file"
    (( parse_failed )) && return 3
    return 0
}

# ssh_keys_prune FILE TRUST_RE BACKUP_DEST FLAGS — surgical rewrite per
# the contract in PLAN-sshkey-prune.md (steps 1-14). FLAGS is a CSV
# subset of {allow_lockout, prune_unlabeled}. Caller-visible globals:
#   KILL_LAST_PRUNE_RESULT  — bare primary from result vocabulary
#   KILL_LAST_PRUNE_DETAIL  — human-readable detail line
#   KILL_LAST_PRUNE_KEEP    — count of effective-kept keys
#   KILL_LAST_PRUNE_PRUNED  — count of pruned keys
#   KILL_LAST_PRUNE_SHA_PRE — sha256 of source before rewrite
#   KILL_LAST_PRUNE_SHA_POST — sha256 of result after mv (apply only)
#   KILL_LAST_PRUNE_BACKUP  — backup path on apply
#   KILL_LAST_PRUNE_SIDECAR — removed-keys sidecar path on apply
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_RESULT=""
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_DETAIL=""
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_KEEP=0
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_PRUNED=0
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_SHA_PRE=""
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_SHA_POST=""
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_BACKUP=""
# shellcheck disable=SC2034  # consumed by P2 manifest emit-site + apply path
KILL_LAST_PRUNE_SIDECAR=""

# shellcheck disable=SC2034  # KILL_LAST_PRUNE_* globals consumed by P2/P3
ssh_keys_prune() {
    local path="$1" trust_re="$2" backup_dest="$3" flags="${4-}"
    KILL_LAST_PRUNE_RESULT=""
    KILL_LAST_PRUNE_DETAIL=""
    KILL_LAST_PRUNE_KEEP=0
    KILL_LAST_PRUNE_PRUNED=0
    KILL_LAST_PRUNE_SHA_PRE=""
    KILL_LAST_PRUNE_SHA_POST=""
    KILL_LAST_PRUNE_BACKUP=""
    KILL_LAST_PRUNE_SIDECAR=""

    # Step 1: refuse symlink + missing file BEFORE any I/O.
    if [[ -L "$path" ]]; then
        KILL_LAST_PRUNE_RESULT=refused_symlink
        return 0
    fi
    if [[ ! -f "$path" ]]; then
        KILL_LAST_PRUNE_RESULT=gone
        return 0
    fi

    # Step 2: pre-rewrite sha256 (used by step 8 concurrent_modification
    # detection + step 6 backup integrity check).
    local sha_pre
    sha_pre=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    if [[ -z "$sha_pre" ]]; then
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="cannot read source sha256"
        return 1
    fi
    KILL_LAST_PRUNE_SHA_PRE="$sha_pre"

    # Step 3: classify (read-only).
    local class_tmp
    class_tmp=$(mktemp /tmp/sessionscribe-sshkey-class-XXXXXX 2>/dev/null) || {
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="mktemp class failed"
        return 1
    }
    local include_arg=""
    [[ "$flags" == *prune_unlabeled* ]] && include_arg="--include-unlabeled-as-prune"
    # Capture rc without `if !` (which masks $? to 1 in some bash 4.1
    # contexts). Direct invocation + explicit rc capture is portable.
    ssh_keys_classify "$path" "$trust_re" $include_arg > "$class_tmp"
    local cls_rc=$?
    if (( cls_rc != 0 )); then
        rm -f "$class_tmp"
        case "$cls_rc" in
            (2) KILL_LAST_PRUNE_RESULT=refused_symlink ;;
            (3) KILL_LAST_PRUNE_RESULT=refused_unparseable ;;
            (*) KILL_LAST_PRUNE_RESULT=prune_failed
                KILL_LAST_PRUNE_DETAIL="classify rc=$cls_rc" ;;
        esac
        return 0
    fi

    # Step 4: counts → decision.
    local n_keep n_prune n_keep_unlabeled
    n_keep=$(awk -F'\t' '$1=="keep"{n++} END{print n+0}' "$class_tmp")
    n_prune=$(awk -F'\t' '$1=="prune"{n++} END{print n+0}' "$class_tmp")
    n_keep_unlabeled=$(awk -F'\t' '$1=="keep_unlabeled"{n++} END{print n+0}' "$class_tmp")
    KILL_LAST_PRUNE_PRUNED="$n_prune"

    if (( n_prune == 0 )); then
        rm -f "$class_tmp"
        KILL_LAST_PRUNE_KEEP=$(( n_keep + n_keep_unlabeled ))
        if (( n_keep_unlabeled > 0 )); then
            KILL_LAST_PRUNE_RESULT=kept_unlabeled_warned
            KILL_LAST_PRUNE_DETAIL="$n_keep_unlabeled unlabeled key(s) kept; review"
        else
            KILL_LAST_PRUNE_RESULT=nothing_to_prune
        fi
        return 0
    fi

    # Lockout gate. Effective "kept" = n_keep + n_keep_unlabeled (the
    # latter remain under default policy).
    local n_effective_kept=$(( n_keep + n_keep_unlabeled ))
    KILL_LAST_PRUNE_KEEP="$n_effective_kept"
    if (( n_effective_kept == 0 )); then
        if [[ "$flags" != *allow_lockout* ]]; then
            rm -f "$class_tmp"
            KILL_LAST_PRUNE_RESULT=would_lock_out
            KILL_LAST_PRUNE_DETAIL="$n_prune key(s) would be pruned, none kept; pass --ssh-allow-lockout to proceed"
            return 0
        fi
        # Operator-authorized full prune; promote AFTER successful rewrite.
    fi

    # Step 5: --check short-circuit. Emits BARE primary; the manifest
    # emit-site in P2 prefixes "planned_".
    if [[ "${MODE:-check}" != "apply" ]]; then
        rm -f "$class_tmp"
        if (( n_effective_kept == 0 )); then
            KILL_LAST_PRUNE_RESULT=forced_full_prune
        else
            KILL_LAST_PRUNE_RESULT=pruned_ok
        fi
        KILL_LAST_PRUNE_DETAIL="$n_prune planned to prune, $n_effective_kept to keep"
        return 0
    fi

    # Step 6: backup precondition chain.
    local backup_orig="${backup_dest}.original-pre-prune"
    if ! mkdir -p "$(dirname "$backup_dest")" 2>/dev/null; then
        rm -f "$class_tmp"
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="backup_mkdir failed: $(dirname "$backup_dest")"
        return 1
    fi
    if ! cp -a "$path" "$backup_orig" 2>/dev/null; then
        rm -f "$class_tmp"
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="backup_failed: cp -a $path -> $backup_orig"
        return 1
    fi
    if [[ ! -s "$backup_orig" && -s "$path" ]]; then
        rm -f "$class_tmp"
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="backup_zero_byte: source non-empty but backup is 0 bytes"
        return 1
    fi
    local sha_backup
    sha_backup=$(sha256sum "$backup_orig" 2>/dev/null | awk '{print $1}')
    if [[ "$sha_backup" != "$sha_pre" ]]; then
        rm -f "$class_tmp"
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="backup_integrity: sha256 mismatch source vs backup"
        return 1
    fi
    KILL_LAST_PRUNE_BACKUP="$backup_orig"

    # Step 7: lock + rewrite. flock -x -n retry loop (no -w on EL6
    # util-linux 2.17). On signal, clean up tmp+class_tmp and exit
    # 130/143 explicitly; bash 4.1's signal-queue semantics make
    # `kill -INT $$` non-portable.
    local lock_attempts=0 lock_max=10 lock_acquired=0
    local tmp="$path.kill-prune-tmp.$$"

    # shellcheck disable=SC2064  # expand $tmp/$class_tmp now (signal-time scope)
    trap "rm -f \"$tmp\" \"$class_tmp\" 2>/dev/null; exit 130" INT
    # shellcheck disable=SC2064  # expand $tmp/$class_tmp now
    trap "rm -f \"$tmp\" \"$class_tmp\" 2>/dev/null; exit 143" TERM

    exec 200<>"$path"
    while (( lock_attempts < lock_max )); do
        if flock -x -n 200; then
            lock_acquired=1
            break
        fi
        sleep 1
        lock_attempts=$((lock_attempts + 1))
    done
    if (( lock_acquired == 0 )); then
        exec 200>&-
        rm -f "$class_tmp"
        trap - INT TERM
        KILL_LAST_PRUNE_RESULT=lock_contended
        KILL_LAST_PRUNE_DETAIL="flock contended after ${lock_max}s; another writer holds $path"
        return 0
    fi

    # Step 8: concurrent-modification check #1 (post-lock sha re-read).
    local sha_now
    sha_now=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    if [[ "$sha_now" != "$sha_pre" ]]; then
        flock -u 200; exec 200>&-
        rm -f "$class_tmp"
        trap - INT TERM
        KILL_LAST_PRUNE_RESULT=concurrent_modification
        KILL_LAST_PRUNE_DETAIL="source modified between sha256_pre and lock acquisition"
        return 0
    fi

    # Step 9: seed tmp with original metadata, then truncate + rewrite.
    if ! cp --preserve=all "$path" "$tmp" 2>/dev/null; then
        flock -u 200; exec 200>&-
        rm -f "$tmp" "$class_tmp"
        trap - INT TERM
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="cp --preserve=all failed (seed tmp)"
        return 1
    fi
    : > "$tmp"

    # Stream from class_tmp; emit only skip|keep|keep_unlabeled lines,
    # re-reading the original line at line_no from $path so attacker-
    # crafted comments don't get round-tripped through awk's tab
    # escaping.
    local cls ln_no _kt _cmt _fp _b24 orig_line
    while IFS=$'\t' read -r cls ln_no _kt _cmt _fp _b24; do
        case "$cls" in
            (skip|keep|keep_unlabeled)
                orig_line=$(sed -n "${ln_no}p" "$path")
                printf '%s\n' "$orig_line" >> "$tmp"
                ;;
            (prune)
                ;;  # drop
        esac
    done < "$class_tmp"

    sync "$tmp" 2>/dev/null || true

    # Step 10: line-count verify of tmp before mv.
    local tmp_keep_count
    tmp_keep_count=$(grep -cE '^[^[:space:]#]' "$tmp" 2>/dev/null || true)
    tmp_keep_count="${tmp_keep_count:-0}"
    if (( tmp_keep_count != n_effective_kept )); then
        flock -u 200; exec 200>&-
        rm -f "$tmp" "$class_tmp"
        trap - INT TERM
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="tmp line-count $tmp_keep_count != expected $n_effective_kept"
        return 1
    fi

    # Step 11: atomic-mv.
    if ! mv "$tmp" "$path" 2>/dev/null; then
        flock -u 200; exec 200>&-
        rm -f "$tmp" "$class_tmp"
        trap - INT TERM
        KILL_LAST_PRUNE_RESULT=prune_failed
        KILL_LAST_PRUNE_DETAIL="mv $tmp -> $path failed"
        return 1
    fi
    flock -u 200; exec 200>&-

    # Step 12: post-mv concurrent-modification check #2.
    local sha_post
    sha_post=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    KILL_LAST_PRUNE_SHA_POST="$sha_post"
    local post_class_tmp
    post_class_tmp=$(mktemp /tmp/sessionscribe-sshkey-postclass-XXXXXX 2>/dev/null || true)
    if [[ -n "$post_class_tmp" ]]; then
        ssh_keys_classify "$path" "$trust_re" $include_arg > "$post_class_tmp" 2>/dev/null || true
        local n_prune_post
        n_prune_post=$(awk -F'\t' '$1=="prune"{n++} END{print n+0}' "$post_class_tmp")
        rm -f "$post_class_tmp"
        if (( n_prune_post > 0 )); then
            rm -f "$class_tmp"
            trap - INT TERM
            KILL_LAST_PRUNE_RESULT=clobbered_post_mv
            KILL_LAST_PRUNE_DETAIL="$n_prune_post suspect key(s) re-appeared post-rewrite; another writer (likely WHM) overwrote our changes"
            return 1
        fi
    fi

    # Step 13: SELinux relabel if enforcing + restorecon present.
    local relabel_warn=""
    if have_cmd getenforce && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]] \
       && have_cmd restorecon; then
        if ! restorecon -F "$path" 2>/dev/null; then
            relabel_warn="restorecon_failed"
        fi
    fi

    # Step 14: write removed-keys JSONL sidecar.
    local removed_sidecar="${backup_dest}.removed-keys"
    {
        printf '# sessionscribe v0.7.0 ssh-key prune — removed keys for %s\n' "$path"
        printf '# run_id=%s ts=%s sha256_pre=%s sha256_post=%s\n' \
            "${RUN_ID:-unknown}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$sha_pre" "$sha_post"
        awk -F'\t' '$1=="prune" {
            printf "{\"line_no\":%s,\"type\":\"%s\",\"comment\":\"%s\",\"fingerprint\":\"%s\"}\n",
                   $2, $3, $4, $5
        }' "$class_tmp"
    } > "$removed_sidecar" 2>/dev/null || true
    KILL_LAST_PRUNE_SIDECAR="$removed_sidecar"

    rm -f "$class_tmp"
    trap - INT TERM

    if (( n_effective_kept == 0 )); then
        KILL_LAST_PRUNE_RESULT=forced_full_prune
        KILL_LAST_PRUNE_DETAIL="$n_prune key(s) pruned; file empty (operator-authorized)"
    else
        KILL_LAST_PRUNE_RESULT=pruned_ok
        KILL_LAST_PRUNE_DETAIL="$n_prune key(s) pruned; $n_effective_kept kept"
    fi
    [[ -n "$relabel_warn" ]] && KILL_LAST_PRUNE_DETAIL+=" (selinux: $relabel_warn)"
    return 0
}

# kill_sshkey_canonical_paths — emit canonical authorized_keys paths one
# per line. Used by both the orphan-tmp sweep and the P2 manifest
# enumerator. Root home discovered via getent passwd; /root fallback.
kill_sshkey_canonical_paths() {
    local root_home
    root_home=$(getent passwd root 2>/dev/null | cut -d: -f6)
    [[ -z "$root_home" || "$root_home" == "/" ]] && root_home="/root"
    printf '%s/.ssh/authorized_keys\n'  "$root_home"
    printf '%s/.ssh/authorized_keys2\n' "$root_home"
    if [[ -d /home ]]; then
        local h
        while IFS= read -r -d '' h; do
            printf '%s/.ssh/authorized_keys\n'  "$h"
            printf '%s/.ssh/authorized_keys2\n' "$h"
        done < <(find /home -maxdepth 2 -mindepth 1 -type d -print0 2>/dev/null)
    fi
}

# kill_sshkey_check_trust_drift — refuse phase_kill if the trust regex
# literal in this file has drifted from sessionscribe-ioc-scan.sh's
# SSH_KNOWN_GOOD_RE. KILL_SSH_ALLOW_DRIFT=1 bypasses with loud WARN.
# KILL_SSH_TRUST_DRIFT_TEST_PATH is an env-only test seam (not a flag).
kill_sshkey_check_trust_drift() {
    local mitigate_dir ioc_path=""
    mitigate_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null)" 2>/dev/null)
    [[ -z "$mitigate_dir" ]] && mitigate_dir="."
    if [[ -n "${KILL_SSH_TRUST_DRIFT_TEST_PATH:-}" && -f "${KILL_SSH_TRUST_DRIFT_TEST_PATH}" ]]; then
        ioc_path="$KILL_SSH_TRUST_DRIFT_TEST_PATH"
    else
        local cand
        for cand in \
            "${mitigate_dir}/sessionscribe-ioc-scan.sh" \
            "/usr/local/sbin/sessionscribe-ioc-scan.sh" \
            "$(command -v sessionscribe-ioc-scan.sh 2>/dev/null)"; do
            if [[ -n "$cand" && -f "$cand" ]]; then
                ioc_path="$cand"
                break
            fi
        done
    fi

    if [[ -z "$ioc_path" ]]; then
        if (( ${KILL_SSH_ALLOW_DRIFT:-0} )); then
            say_warn "ioc-scan companion not found; --ssh-allow-drift bypasses trust-regex sync check"
            return 0
        fi
        say_fail "cannot verify trust-regex sync: sessionscribe-ioc-scan.sh not found in $mitigate_dir, /usr/local/sbin/, or PATH. Install ioc-scan alongside mitigate, or pass --ssh-allow-drift to bypass (operator-authorized)."
        return 1
    fi

    # Paired-quote strip: only strip leading + trailing quote when they
    # match. Avoids stripping a meaningful trailing quote that's part of
    # the regex literal.
    local rhs_ioc rhs_mit
    rhs_ioc=$(grep -oE "^SSH_KNOWN_GOOD_RE=.*" "$ioc_path" | head -1 \
              | sed -E "s/^[^=]+=//; s/^'(.*)'[[:space:]]*\$/\1/; s/^\"(.*)\"[[:space:]]*\$/\1/")
    rhs_mit=$(grep -oE "^KILL_SSH_TRUST_RE=.*" "${BASH_SOURCE[0]:-$0}" | head -1 \
              | sed -E "s/^[^=]+=//; s/^'(.*)'[[:space:]]*\$/\1/; s/^\"(.*)\"[[:space:]]*\$/\1/")

    if [[ -z "$rhs_ioc" ]]; then
        if (( ${KILL_SSH_ALLOW_DRIFT:-0} )); then
            say_warn "ioc-scan SSH_KNOWN_GOOD_RE not found at expected line; --ssh-allow-drift bypasses"
            return 0
        fi
        say_fail "cannot extract SSH_KNOWN_GOOD_RE from $ioc_path"
        return 1
    fi

    if [[ "$rhs_ioc" != "$rhs_mit" ]]; then
        if (( ${KILL_SSH_ALLOW_DRIFT:-0} )); then
            say_warn "trust-regex DRIFT vs ioc-scan: mit=$rhs_mit ioc=$rhs_ioc; --ssh-allow-drift bypassing (operator-authorized)"
            return 0
        fi
        say_fail "trust-regex drift detected: mitigate=$rhs_mit vs ioc-scan=$rhs_ioc. Pruning would mis-classify operator keys. Update mitigate's KILL_SSH_TRUST_RE to match, OR pass --ssh-allow-drift if the divergence is intentional."
        return 1
    fi
    return 0
}

# kill_sshkey_orphan_tmp_sweep — at phase_kill startup, detect leftover
# .kill-prune-tmp.* files from a prior interrupted run. Logged as WARN;
# NOT auto-deleted (could be operator recovery material).
kill_sshkey_orphan_tmp_sweep() {
    local p tmps t
    local -a orphans=()
    while IFS= read -r p; do
        [[ -z "$p" ]] && continue
        tmps=$(find "$(dirname "$p")" -maxdepth 1 \
                    -name "$(basename "$p").kill-prune-tmp.*" 2>/dev/null)
        if [[ -n "$tmps" ]]; then
            while IFS= read -r t; do
                [[ -n "$t" ]] && orphans+=("$t")
            done <<< "$tmps"
        fi
    done < <(kill_sshkey_canonical_paths)
    if (( ${#orphans[@]} > 0 )); then
        local o
        for o in "${orphans[@]}"; do
            say_warn "orphan ssh-prune tmp from prior interrupted run: $o (manual review; do NOT auto-delete)"
        done
    fi
}

# Pure-bash absolute-path normalizer. Collapses /./ and /../ segments
# without touching the filesystem; needed when neither realpath -m nor
# readlink -m is available (EL6 coreutils 8.4) AND the path's parent
# directories may not exist (a traversal probe like
# /home/foo/../../etc/shadow where /home/foo is absent makes
# `readlink -f` return empty). Returns 1 on relative input or on
# above-root traversal (e.g. /../etc -> error). bash 4.1 / set -u safe.
kill_normalize_abs_path() {
    local input="$1" segment out p
    local -a parts=()
    [[ -n "$input" ]] || return 1
    [[ "$input" == /* ]] || return 1
    local IFS=/
    # shellcheck disable=SC2206  # word-splitting on / is intentional
    local raw=( $input )
    # Guard empty-array iteration under set -u + bash 4.1.
    if (( ${#raw[@]} > 0 )); then
        for segment in "${raw[@]}"; do
            case "$segment" in
                (""|".") continue ;;
                ("..")
                    if (( ${#parts[@]} > 0 )); then
                        unset 'parts[${#parts[@]}-1]'
                    else
                        return 1
                    fi
                    ;;
                (*) parts+=("$segment") ;;
            esac
        done
    fi
    out=""
    if (( ${#parts[@]} > 0 )); then
        for p in "${parts[@]}"; do
            out+="/$p"
        done
    else
        out="/"
    fi
    printf '%s' "$out"
}

# Path-allowlist gate. Refuses any path outside the documented allowlist
# of mutable roots; protects against (a) malformed envelopes, (b) path
# traversal from a compromised ioc-scan, (c) operator misconfiguration.
#
# Allowlist:
#   /root/                              user home (root operator)
#   /home/*/                            cPanel user homes (incl. .ssh, public_html)
#   /etc/profile.d/                     login-time hooks (Pattern I)
#   /etc/systemd/system/                unit files (Pattern J)
#   /etc/udev/rules.d/                  udev rules (Pattern J)
#   /etc/cron.d/, cron.{hourly,daily,weekly,monthly}/  scheduled tasks
#   /var/spool/cron/                    user crontabs
#   /usr/local/cpanel/var/              cPanel reseller token files (Pattern D)
#
# Shape probes (envelope-injection defense):
#   - Path must be absolute (envelope contract; relative is operator
#     error).
#   - No control chars (NUL, newline, tab, ESC).
#   - No `..` segments. The IOC scanner writes paths absolute + already
#     normalized at source; any `..` here is intent-hidden traversal
#     (operator misconfig or compromised upstream). Refusing on
#     presence is stricter than collapse-then-match, because a path
#     like /home/x/../etc/shadow would collapse to /home/etc/shadow
#     and slip past the case below.
#
# Resolution chain (after shape probes pass): prefer `realpath -m`
# (handles symlinks + non-existent paths), fall back to `readlink -f`
# (handles symlinks but needs every intermediate dir to exist), fall
# back to the pure-bash normalizer (no symlink resolution, but
# collapses /. and absorbs an absolute-path no-op). `realpath -m` is
# coreutils 8.15+; the EL6 floor (coreutils 8.4) may have realpath
# without `-m` OR no realpath at all - probe before relying on -m so
# we don't fail-open on every path with a misleading "invalid option".
kill_path_in_allowlist() {
    local path="$1" resolved=""
    [[ -n "$path" ]] || return 1
    [[ "$path" == /* ]] || return 1
    [[ "$path" =~ [[:cntrl:]] ]] && return 1
    # Refuse any path containing a `..` segment outright. The envelope
    # writes IOC paths absolute + normalized at source; any `..` in a
    # path here is intent-hidden traversal (operator misconfiguration
    # or compromised upstream). Match leading "../", embedded "/../",
    # and trailing "/..".
    case "$path" in
        (*/../*|*/..) return 1 ;;
    esac

    if have_cmd realpath && realpath -m / >/dev/null 2>&1; then
        resolved=$(realpath -m "$path" 2>/dev/null)
    fi
    if [[ -z "$resolved" ]] && have_cmd readlink; then
        resolved=$(readlink -f "$path" 2>/dev/null)
    fi
    if [[ -z "$resolved" ]]; then
        resolved=$(kill_normalize_abs_path "$path") || return 1
    fi
    [[ -n "$resolved" ]] || return 1
    [[ "$resolved" == /* ]] || return 1

    case "$resolved" in
        (/root|/root/*)                                                                                  return 0 ;;
        (/home/*)                                                                                        return 0 ;;
        (/etc/profile.d/*)                                                                               return 0 ;;
        (/etc/systemd/system/*)                                                                          return 0 ;;
        (/etc/udev/rules.d/*)                                                                            return 0 ;;
        (/etc/cron.d/*|/etc/cron.hourly/*|/etc/cron.daily/*|/etc/cron.weekly/*|/etc/cron.monthly/*)      return 0 ;;
        (/var/spool/cron/*)                                                                              return 0 ;;
        (/usr/local/cpanel/var/*)                                                                        return 0 ;;
        (*)                                                                                              return 1 ;;
    esac
}

# Append one action-result record to the kill-actions sidecar JSONL.
# Args: sidecar kind path ioc_key pattern sha256_pre sha256_post size dest result
# All values are json-escaped via json_esc; size is a numeric or empty string.
# K6 reads this sidecar to merge results into the final manifest.
kill_action_record() {
    local sidecar="$1" kind="$2" path="$3" key="$4" pattern="$5"
    local sha_pre="$6" sha_post="$7" size="$8" dest="$9" result="${10}"
    {
        printf '{"kind":"%s","path":"%s","ioc_key":"%s","pattern":"%s",' \
            "$(json_esc "$kind")" "$(json_esc "$path")" \
            "$(json_esc "$key")" "$(json_esc "$pattern")"
        printf '"sha256_pre":"%s","sha256_post":"%s",' \
            "$(json_esc "$sha_pre")" "$(json_esc "$sha_post")"
        if [[ -n "$size" && "$size" =~ ^[0-9]+$ ]]; then
            printf '"size":%s,' "$size"
        else
            printf '"size":null,'
        fi
        printf '"dest":"%s","result":"%s","ts":"%s"}\n' \
            "$(json_esc "$dest")" "$(json_esc "$result")" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$sidecar"
}

# Quarantine one file: stat -> sha256 -> mv (with cp+rm cross-fs fallback)
# -> sha256 verify. Records action via kill_action_record. Returns 0 on
# success or benign skip (gone / refused_special_file), 1 on failure.
# Result vocabulary:
#   ok                      moved + sha256 verified
#   gone                    file already absent (no action needed)
#   refused_special_file    not a regular file (block/char/fifo/socket)
#   mv_failed               both mv and cp+rm failed
#   rm_failed_after_copy    cp succeeded but rm failed (incomplete quarantine)
#   corrupt_during_move     sha256 mismatch between source and dest
kill_quarantine_one() {
    local path="$1" key="$2" pattern="$3" sidecar="$4"
    local sha_pre="" sha_post="" size="" dest="" result=""
    local mv_rc cp_rc rm_rc

    if [[ ! -e "$path" && ! -L "$path" ]]; then
        kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "" "" "" "" "gone"
        return 0
    fi

    if [[ ! -f "$path" || -L "$path" ]]; then
        # Symlinks are "special" in this context: even though backdoor
        # symlinks (eg /home/x/.ssh -> /etc) are interesting, quarantining
        # the link without resolving the target leaves the target intact;
        # quarantining via realpath would cross the allowlist boundary.
        # Refuse and surface to operator for hand-handling.
        kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "" "" "" "" "refused_special_file"
        return 0
    fi

    sha_pre=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
    size=$(stat -c '%s' "$path" 2>/dev/null)
    dest="$BACKUP_DIR/quarantine/${path#/}"

    if ! mkdir -p "$(dirname "$dest")" 2>/dev/null; then
        kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "$sha_pre" "" "$size" "$dest" "mv_failed"
        return 1
    fi

    mv "$path" "$dest" 2>/dev/null
    mv_rc=$?

    if (( mv_rc != 0 )); then
        # Cross-filesystem mv fails with EXDEV; fall back to cp+rm. Same
        # pattern phase_sessions uses for the session-quarantine path.
        cp -a "$path" "$dest" 2>/dev/null
        cp_rc=$?
        if (( cp_rc != 0 )); then
            kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "$sha_pre" "" "$size" "$dest" "mv_failed"
            return 1
        fi
        rm -f "$path" 2>/dev/null
        rm_rc=$?
        if (( rm_rc != 0 )); then
            sha_post=$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')
            kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "$sha_pre" "$sha_post" "$size" "$dest" "rm_failed_after_copy"
            return 1
        fi
    fi

    sha_post=$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')
    if [[ -n "$sha_pre" && -n "$sha_post" && "$sha_pre" != "$sha_post" ]]; then
        result="corrupt_during_move"
    else
        result="ok"
    fi
    kill_action_record "$sidecar" "file" "$path" "$key" "$pattern" "$sha_pre" "$sha_post" "$size" "$dest" "$result"
    return 0
}

# IP routability gate. Refuses private (RFC1918), loopback, link-local,
# multicast, reserved, and shape-malformed IPs. Bash =~ uses libc ERE
# which supports {n} per CLAUDE.md note. Returns 0 if the IP is a
# globally routable unicast address worth blocking, 1 otherwise.
kill_ip_is_routable() {
    local ip="$1" ip_lc a b c d n
    [[ -n "$ip" ]] || return 1

    # IPv4: four 1-3 digit octets.
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"
        c="${BASH_REMATCH[3]}"; d="${BASH_REMATCH[4]}"
        for n in "$a" "$b" "$c" "$d"; do
            (( n >= 0 && n <= 255 )) || return 1
        done
        # 0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 224/4+
        case "$a" in
            (0|10|127) return 1 ;;
        esac
        if [[ "$a" == "169" && "$b" == "254" ]]; then return 1; fi
        if [[ "$a" == "172" ]] && (( b >= 16 && b <= 31 )); then return 1; fi
        if [[ "$a" == "192" && "$b" == "168" ]]; then return 1; fi
        if (( a >= 224 )); then return 1; fi
        return 0
    fi

    # IPv6: at least one colon, hex digits + colons only. Coarse-grained;
    # CSF will reject malformed shapes itself, but we filter the obvious
    # private/reserved blocks here so we don't push them into csf.deny.
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" == *:* ]]; then
        ip_lc=$(printf '%s' "$ip" | tr '[:upper:]' '[:lower:]')
        case "$ip_lc" in
            (::1|::) return 1 ;;
            (fe8?:*|fe9?:*|fea?:*|feb?:*) return 1 ;;     # fe80::/10 link-local
            (fc??:*|fd??:*) return 1 ;;                    # fc00::/7 unique-local
            (ff*) return 1 ;;                              # ff00::/8 multicast
        esac
        return 0
    fi

    return 1
}

# Append one IP-action record to the sidecar JSONL.
kill_ip_action_record() {
    local sidecar="$1" ip="$2" src="$3" comment="$4" result="$5"
    {
        printf '{"kind":"ip","ip":"%s","source_signal":"%s","comment":"%s","result":"%s","ts":"%s"}\n' \
            "$(json_esc "$ip")" "$(json_esc "$src")" \
            "$(json_esc "$comment")" "$(json_esc "$result")" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$sidecar"
}

# Append one CSF-action record to the sidecar JSONL.
kill_csf_action_record() {
    local sidecar="$1" key="$2" value="$3" result="$4"
    {
        printf '{"kind":"csf","key":"%s","value":"%s","result":"%s","ts":"%s"}\n' \
            "$(json_esc "$key")" "$(json_esc "$value")" \
            "$(json_esc "$result")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$sidecar"
}

# Read a CSF config scalar (KEY = "value" form). Empty if absent. Mirrors
# phase_csf's existing extraction shape (mitigate line 1156 pattern).
kill_csf_conf_get() {
    local conf="$1" key="$2"
    [[ -f "$conf" ]] || return 0
    grep -E "^${key}[[:space:]]*=" "$conf" | head -1 | sed -E 's/^[^"]*"([^"]*)".*/\1/'
}

# Set a CSF config scalar in place via sed -i. Backs up first via
# backup_file. Returns sed's rc.
kill_csf_conf_set() {
    local conf="$1" key="$2" value="$3"
    [[ -f "$conf" ]] || return 1
    backup_file "$conf"
    sed -i -E "s|^(${key}[[:space:]]*=[[:space:]]*\")[^\"]*(\".*)$|\1${value}\2|" "$conf"
}

# Register the rfxn fleet blocklist as a CSF-managed ipset. Idempotent.
# Verifies LF_IPSET=1 (flips to 1 on --apply if 0, warns in --check).
# Optional 2nd arg: csf root dir (default /etc/csf) - used for testing.
#
# Side effects (only in --apply):
#   - /etc/csf/csf.conf: LF_IPSET 0 -> 1 (with backup_file)
#   - /etc/csf/csf.blocklists: append RFXN_FH_L2L3|86400|0|<url> (with backup)
register_rfxn_blocklist() {
    local manifest="$1"
    local csf_dir="${2:-/etc/csf}"
    [[ -n "$manifest" && -f "$manifest" ]] || return 1
    local sidecar="${manifest%.json}.actions.jsonl"
    local conf="$csf_dir/csf.conf"
    local blocklists="$csf_dir/csf.blocklists"
    local name="RFXN_FH_L2L3"
    local url="https://cdn.rfxn.com/downloads/rfxn_fh-l2_l3_webserver.netset"
    local entry="${name}|86400|0|${url}"

    if [[ ! -f "$conf" ]]; then
        kill_csf_action_record "$sidecar" "csf_present" "no" "csf_not_installed"
        return 0
    fi

    # 1. LF_IPSET probe + flip if needed.
    local cur_lf
    cur_lf=$(kill_csf_conf_get "$conf" LF_IPSET)
    if [[ "$cur_lf" == "0" ]]; then
        if [[ "$MODE" == "apply" ]]; then
            if kill_csf_conf_set "$conf" LF_IPSET 1; then
                kill_csf_action_record "$sidecar" "LF_IPSET" "0->1" "ok"
            else
                kill_csf_action_record "$sidecar" "LF_IPSET" "0" "config_set_failed"
                return 1
            fi
        else
            kill_csf_action_record "$sidecar" "LF_IPSET" "0" "needs_apply_to_flip"
        fi
    elif [[ "$cur_lf" == "1" ]]; then
        kill_csf_action_record "$sidecar" "LF_IPSET" "1" "already_enabled"
    else
        kill_csf_action_record "$sidecar" "LF_IPSET" "${cur_lf:-(absent)}" "missing_or_unexpected"
    fi

    # 2. LF_IPSET_MAXELEM (informational; default 65536 fits the netset's
    # ~11,642 entries with 5x headroom).
    local maxelem
    maxelem=$(kill_csf_conf_get "$conf" LF_IPSET_MAXELEM)
    kill_csf_action_record "$sidecar" "LF_IPSET_MAXELEM" "${maxelem:-default}" "noted"

    # 3. csf.blocklists registration.
    if [[ ! -f "$blocklists" ]]; then
        if [[ "$MODE" == "apply" ]]; then
            {
                printf '# sessionscribe-managed entries\n'
                printf '%s\n' "$entry"
            } > "$blocklists"
            chmod 0600 "$blocklists" 2>/dev/null
            kill_csf_action_record "$sidecar" "blocklist_register" "$name" "created_new_file"
        else
            kill_csf_action_record "$sidecar" "blocklist_register" "$name" "needs_apply_to_create"
        fi
        return 0
    fi

    if grep -qE "^${name}\|" "$blocklists" 2>/dev/null; then
        kill_csf_action_record "$sidecar" "blocklist_register" "$name" "already_registered"
        return 0
    fi

    if [[ "$MODE" == "apply" ]]; then
        backup_file "$blocklists"
        printf '%s\n' "$entry" >> "$blocklists"
        kill_csf_action_record "$sidecar" "blocklist_register" "$name" "ok"
    else
        kill_csf_action_record "$sidecar" "blocklist_register" "$name" "needs_apply_to_register"
    fi

    return 0
}

# Walk a manifest, csf -d every kind=ip action=csf-deny item. Skips
# private/loopback/link-local/multicast IPs (envelope-injection guard).
# Skips IPs already present in /etc/csf/csf.deny (idempotent re-runs).
# Returns 0 if all ok or all benign skips, non-zero on csf_failed.
#
# Result vocabulary:
#   ok                  csf -d succeeded
#   already_blocked     IP already on first whitespace-delimited field of csf.deny
#   private_skipped     RFC1918 / loopback / link-local / multicast / malformed
#   csf_failed          csf binary returned non-zero
#   csf_not_installed   csf binary absent (skipped, not failed)
apply_csf_blocks() {
    local manifest="$1"
    [[ -n "$manifest" && -f "$manifest" ]] || return 1
    local sidecar="${manifest%.json}.actions.jsonl"
    local deny_file=/etc/csf/csf.deny

    if ! have_cmd csf; then
        kill_ip_action_record "$sidecar" "" "" "" "csf_not_installed"
        return 0
    fi

    local line ip src_signal hits comment fails=0
    while IFS= read -r line; do
        [[ "$line" =~ \"kind\":\"ip\" ]] || continue
        [[ "$line" =~ \"action\":\"csf-deny\" ]] || continue

        ip=$(kill_json_str_field "$line" ip)
        src_signal=$(kill_json_str_field "$line" source_signal)
        hits=$(kill_json_num_field "$line" hits)
        [[ -z "$ip" ]] && continue

        if ! kill_ip_is_routable "$ip"; then
            kill_ip_action_record "$sidecar" "$ip" "$src_signal" "" "private_skipped"
            continue
        fi

        # Idempotency: csf.deny is one IP per line, optionally with
        # whitespace/# comment. awk handles this without regex-escaping
        # the IP (gawk-3.x safe; literal first-field equality).
        if [[ -f "$deny_file" ]] && \
           awk -v ip="$ip" '$1==ip {found=1} END{exit !found}' "$deny_file" 2>/dev/null; then
            kill_ip_action_record "$sidecar" "$ip" "$src_signal" "" "already_blocked"
            continue
        fi

        comment="sessionscribe run=$RUN_ID src=$src_signal hits=${hits:-0}"
        if csf -d "$ip" "$comment" >/dev/null 2>&1; then
            kill_ip_action_record "$sidecar" "$ip" "$src_signal" "$comment" "ok"
        else
            kill_ip_action_record "$sidecar" "$ip" "$src_signal" "$comment" "csf_failed"
            fails=$((fails+1))
        fi
    done < "$manifest"

    return $fails
}

# Walk a manifest, quarantine every kind=file action=quarantine item.
# Refused items (action=refused) are skipped. Returns the number of
# failures (0 = all ok or all benign skips).
quarantine_from_manifest() {
    local manifest="$1"
    [[ -n "$manifest" && -f "$manifest" ]] || return 1
    local sidecar="${manifest%.json}.actions.jsonl"
    : > "$sidecar"

    local line path key pattern fails=0
    while IFS= read -r line; do
        [[ "$line" =~ \"kind\":\"file\" ]] || continue
        [[ "$line" =~ \"action\":\"quarantine\" ]] || continue
        path=$(kill_json_str_field "$line" path)
        key=$(kill_json_str_field "$line" ioc_key)
        pattern=$(kill_json_str_field "$line" pattern)
        [[ -z "$path" ]] && continue
        if ! kill_quarantine_one "$path" "$key" "$pattern" "$sidecar"; then
            fails=$((fails+1))
        fi
    done < "$manifest"

    return $fails
}

# Build a sidecar lookup. Streams the *.actions.jsonl into stdout as
# tab-delimited rows: lookup_kind <TAB> lookup_key <TAB> field <TAB> value.
# Consumed by finalize_manifest's awk merger.
kill_sidecar_to_lookup() {
    local sidecar="$1"
    [[ -f "$sidecar" ]] || return 0

    local line kind key
    local path sha_pre sha_post size dest result
    local ip src comment
    local csf_key value
    while IFS= read -r line; do
        kind=$(kill_json_str_field "$line" kind)
        result=$(kill_json_str_field "$line" result)
        case "$kind" in
            file)
                path=$(kill_json_str_field "$line" path)
                sha_pre=$(kill_json_str_field "$line" sha256_pre)
                sha_post=$(kill_json_str_field "$line" sha256_post)
                size=$(kill_json_num_field "$line" size)
                dest=$(kill_json_str_field "$line" dest)
                printf 'file\t%s\tresult\t%s\n'     "$path" "$result"
                printf 'file\t%s\tsha256_pre\t%s\n' "$path" "$sha_pre"
                printf 'file\t%s\tsha256_post\t%s\n' "$path" "$sha_post"
                printf 'file\t%s\tsize\t%s\n'       "$path" "${size:-}"
                printf 'file\t%s\tdest\t%s\n'       "$path" "$dest"
                ;;
            ip)
                ip=$(kill_json_str_field "$line" ip)
                src=$(kill_json_str_field "$line" source_signal)
                comment=$(kill_json_str_field "$line" comment)
                printf 'ip\t%s\tresult\t%s\n'         "$ip" "$result"
                printf 'ip\t%s\tsource_signal\t%s\n'  "$ip" "$src"
                printf 'ip\t%s\tcomment\t%s\n'        "$ip" "$comment"
                ;;
            csf)
                csf_key=$(kill_json_str_field "$line" key)
                value=$(kill_json_str_field "$line" value)
                printf 'csf\t%s\tresult\t%s\n' "$csf_key" "$result"
                printf 'csf\t%s\tvalue\t%s\n'  "$csf_key" "$value"
                ;;
        esac
    done < "$sidecar"
}

# Compute the phase_kill verdict from sidecar action results + manifest
# refused items. Sets the global LAST_KILL_VERDICT and LAST_KILL_DETAIL
# so the caller can phase_set kill ${verdict} "${detail}".
#
# Verdict logic:
#   FAIL    - any mv_failed / corrupt_during_move / rm_failed_after_copy
#             / csf_failed / config_set_failed
#   ACTION  - at least one ok action and no failures
#   WARN    - --check mode finds work, OR --apply with non-fatal skips
#             (private_skipped, already_blocked, gone, needs_apply_*)
#   OK      - nothing planned, nothing done
#   SKIPPED - set by caller before this fn (gate-not-met)
LAST_KILL_VERDICT=""
LAST_KILL_DETAIL=""
kill_compute_verdict() {
    local manifest="$1"
    local sidecar="${manifest%.json}.actions.jsonl"

    local files_q=0 files_f=0 files_g=0 files_special=0 files_refused=0
    local ips_ok=0 ips_skip=0 ips_fail=0
    local csf_failed=0 csf_changed=0 csf_pending=0

    # grep -c always emits a number (0 when no match) but rc=1 when zero -
    # do NOT chain `|| echo 0` here, that would append a second "0\n".
    files_refused=$(grep -cE '"action":"refused"' "$manifest" 2>/dev/null)
    files_refused="${files_refused:-0}"

    if [[ -f "$sidecar" ]]; then
        local line k r kc
        while IFS= read -r line; do
            k=$(kill_json_str_field "$line" kind)
            r=$(kill_json_str_field "$line" result)
            case "$k" in
                file)
                    case "$r" in
                        (ok)                                                          files_q=$((files_q+1)) ;;
                        (gone)                                                        files_g=$((files_g+1)) ;;
                        (refused_special_file)                                        files_special=$((files_special+1)) ;;
                        (mv_failed|corrupt_during_move|rm_failed_after_copy)          files_f=$((files_f+1)) ;;
                    esac
                    ;;
                ip)
                    case "$r" in
                        (ok)                                                          ips_ok=$((ips_ok+1)) ;;
                        (already_blocked|private_skipped|csf_not_installed)           ips_skip=$((ips_skip+1)) ;;
                        (csf_failed)                                                  ips_fail=$((ips_fail+1)) ;;
                    esac
                    ;;
                csf)
                    kc=$(kill_json_str_field "$line" key)
                    case "$r" in
                        (ok|created_new_file)
                            case "$kc" in
                                (LF_IPSET|blocklist_register) csf_changed=$((csf_changed+1)) ;;
                            esac
                            ;;
                        (config_set_failed)        csf_failed=$((csf_failed+1)) ;;
                        (needs_apply_to_flip|needs_apply_to_register|needs_apply_to_create)
                                                   csf_pending=$((csf_pending+1)) ;;
                    esac
                    ;;
            esac
        done < "$sidecar"
    fi

    local total_fail=$(( files_f + ips_fail + csf_failed ))
    local total_ok=$(( files_q + ips_ok + csf_changed ))
    local total_pending=$(( csf_pending ))

    # Read planned counts from the manifest - K1 wrote them. In --check
    # mode the manifest is the only source of truth; sidecar records are
    # absent (K3/K4 didn't run) or are limited to K5's would-* records.
    local files_planned ips_planned
    files_planned=$(grep -oE '"files_planned":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    ips_planned=$(grep -oE '"ips_planned":[0-9]+'   "$manifest" | head -1 | grep -oE '[0-9]+')
    files_planned="${files_planned:-0}"
    ips_planned="${ips_planned:-0}"

    if (( total_fail > 0 )); then
        LAST_KILL_VERDICT="FAIL"
        LAST_KILL_DETAIL="${files_f} file fail(s), ${ips_fail} csf-deny fail(s), ${csf_failed} csf-conf fail(s)"
    elif (( total_ok > 0 )); then
        LAST_KILL_VERDICT="ACTION"
        LAST_KILL_DETAIL="${files_q} quarantined, ${ips_ok} blocked, ${csf_changed} csf change(s); skips=${files_g}+${files_special}+${ips_skip}+${files_refused}"
    elif [[ "$MODE" != "apply" ]] && (( files_planned + ips_planned > 0 || total_pending > 0 )); then
        LAST_KILL_VERDICT="WARN"
        LAST_KILL_DETAIL="${files_planned} file(s) + ${ips_planned} ip(s) planned; ${total_pending} csf change(s) pending; needs --apply"
    elif (( total_pending > 0 )); then
        LAST_KILL_VERDICT="WARN"
        LAST_KILL_DETAIL="${total_pending} csf change(s) need --apply; ${files_refused} path(s) refused"
    elif (( files_refused > 0 || files_g > 0 || files_special > 0 || ips_skip > 0 )); then
        LAST_KILL_VERDICT="WARN"
        LAST_KILL_DETAIL="all skips/refused; ${files_refused} refused, ${files_g} gone, ${files_special} special, ${ips_skip} ip skips"
    else
        LAST_KILL_VERDICT="OK"
        LAST_KILL_DETAIL="nothing to do"
    fi
}

# Merge sidecar action results into the manifest, populate ts_applied,
# csf{} block, and summary{} counters. Output replaces the manifest in
# place via temp + mv. Pure bash/awk - no jq dependency.
finalize_manifest() {
    local manifest="$1"
    [[ -n "$manifest" && -f "$manifest" ]] || return 1
    local sidecar="${manifest%.json}.actions.jsonl"
    local lookup tmp
    lookup=$(mktemp /tmp/sessionscribe-kill-lookup-XXXXXX) || return 1
    tmp="${manifest}.tmp.$$"

    kill_sidecar_to_lookup "$sidecar" > "$lookup"

    local ts_applied
    ts_applied=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # awk merger: streams the manifest, looking up file/ip patches by path/ip
    # from the lookup file. CSF block and summary are emitted from scratch
    # using sidecar aggregates. gawk-3.x compatible (no 3-arg match, no {n},
    # split on tab is portable).
    awk -v lookup="$lookup" -v ts_applied="$ts_applied" '
        BEGIN {
            # Load lookup: lookup_kind<TAB>lookup_key<TAB>field<TAB>value
            while ((getline ll < lookup) > 0) {
                n = split(ll, a, "\t")
                if (n < 4) continue
                lkind = a[1]; lkey = a[2]; field = a[3]; value = a[4]
                store[lkind, lkey, field] = value
            }
            close(lookup)

            # Aggregate counters from the lookup map for the summary block.
            files_q = 0; files_f = 0; files_g = 0; files_special = 0
            ips_ok = 0; ips_skip = 0; ips_fail = 0
            for (k in store) {
                split(k, p, SUBSEP)
                if (p[3] != "result") continue
                v = store[k]
                if (p[1] == "file") {
                    if (v == "ok") files_q++
                    else if (v == "gone") files_g++
                    else if (v == "refused_special_file") files_special++
                    else if (v == "mv_failed" || v == "corrupt_during_move" || v == "rm_failed_after_copy") files_f++
                } else if (p[1] == "ip") {
                    if (v == "ok") ips_ok++
                    else if (v == "already_blocked" || v == "private_skipped" || v == "csf_not_installed") ips_skip++
                    else if (v == "csf_failed") ips_fail++
                }
            }
            in_items = 0; in_csf = 0; in_summary = 0; depth = 0
        }

        # Detect block boundaries by line content.
        /^  "items":\[$/                  { in_items = 1; print; next }
        /^  \],$/ && in_items             { in_items = 0; print; next }
        /^  "csf":\{$/                    { in_csf = 1
                                            print
                                            print "    \"blocklist_url\":\"https://cdn.rfxn.com/downloads/rfxn_fh-l2_l3_webserver.netset\","
                                            print "    \"blocklist_name\":\"RFXN_FH_L2L3\","
                                            printf "    \"registered\":%s,\n", csf_registered_value()
                                            printf "    \"lf_ipset\":\"%s\",\n", store["csf","LF_IPSET","value"] != "" ? store["csf","LF_IPSET","value"] : "unknown"
                                            printf "    \"lf_ipset_maxelem\":\"%s\",\n", store["csf","LF_IPSET_MAXELEM","value"] != "" ? store["csf","LF_IPSET_MAXELEM","value"] : "unknown"
                                            printf "    \"config_changed\":%s\n", csf_changed_value()
                                            next }
        /^  \},$/ && in_csf               { in_csf = 0; print; next }
        /^  "summary":\{$/                { in_summary = 1
                                            print
                                            # files_planned / ips_planned / files_refused
                                            # are emitted as "0" placeholders here; the
                                            # sed pass after awk re-extracts the real K1
                                            # values from the source manifest and patches
                                            # them in. Source of truth = the original
                                            # summary block on disk.
                                            printf "    \"files_planned\":0,\n"
                                            printf "    \"ips_planned\":0,\n"
                                            printf "    \"files_refused\":0,\n"
                                            printf "    \"files_quarantined\":%d,\n", files_q
                                            printf "    \"files_failed\":%d,\n",      files_f
                                            printf "    \"files_gone\":%d,\n",        files_g
                                            printf "    \"files_special\":%d,\n",     files_special
                                            printf "    \"ips_blocked\":%d,\n",       ips_ok
                                            printf "    \"ips_skipped\":%d,\n",       ips_skip
                                            printf "    \"ips_failed\":%d\n",         ips_fail
                                            next }
        /^  \}$/ && in_summary            { in_summary = 0; print; next }

        # Inside csf block / summary block: skip the original lines (we re-emit).
        in_csf == 1                        { next }
        in_summary == 1                    { next }

        # ts_applied patch.
        /^  "ts_applied":null,$/           { printf "  \"ts_applied\":\"%s\",\n", ts_applied; next }

        # Inside items: patch file/ip lines based on lookup. The lines are
        # the ones K1 wrote ({"kind":"file",...} or {"kind":"ip",...}).
        in_items == 1 && /\{"kind":"file","pattern"/ {
            line = $0
            # Skip refused items - K2 already set their result; do not patch.
            if (line ~ /"action":"refused"/) { print; next }
            # Extract path and look up.
            path = json_str(line, "path")
            r = store["file", path, "result"]
            if (r == "") {
                # No sidecar record (action ran in --check or path was
                # somehow missed). Leave nulls.
                print
                next
            }
            sha_pre  = store["file", path, "sha256_pre"]
            sha_post = store["file", path, "sha256_post"]
            sz       = store["file", path, "size"]
            dst      = store["file", path, "dest"]
            # Replace the trailing nulls with the populated values.
            line = patch_field(line, "sha256_pre", quoted(sha_pre))
            line = patch_field(line, "sha256_post", quoted(sha_post))
            line = patch_field_raw(line, "size", (sz == "" ? "null" : sz))
            line = patch_field(line, "dest", quoted(dst))
            line = patch_field(line, "result", quoted(r))
            print line
            next
        }
        in_items == 1 && /\{"kind":"ip"/ {
            line = $0
            ip = json_str(line, "ip")
            r = store["ip", ip, "result"]
            if (r == "") { print; next }
            line = patch_field(line, "result", quoted(r))
            print line
            next
        }

        # Default: passthrough.
        { print }

        # Helpers.
        function quoted(s) {
            if (s == "" || s == "null") return "null"
            gsub(/\\/, "\\\\", s)
            gsub(/"/, "\\\"", s)
            return "\"" s "\""
        }
        function patch_field(line, key, val,    pat) {
            pat = "\"" key "\":null"
            sub(pat, "\"" key "\":" val, line)
            # Also patch when an existing string is present (legacy nulls).
            return line
        }
        function patch_field_raw(line, key, val,    pat) {
            pat = "\"" key "\":null"
            sub(pat, "\"" key "\":" val, line)
            return line
        }
        function json_str(line, key,    re, m) {
            re = "\"" key "\":\""
            i = index(line, re)
            if (i == 0) return ""
            rest = substr(line, i + length(re))
            j = index(rest, "\"")
            if (j == 0) return ""
            return substr(rest, 1, j - 1)
        }
        function csf_registered_value() {
            br = store["csf", "blocklist_register", "result"]
            if (br == "ok" || br == "created_new_file" || br == "already_registered") return "true"
            if (br == "") return "null"
            return "false"
        }
        function csf_changed_value() {
            n = 0
            v1 = store["csf", "LF_IPSET", "value"]
            if (v1 == "0->1") n = 1
            v2 = store["csf", "blocklist_register", "result"]
            if (v2 == "ok" || v2 == "created_new_file") n = 1
            return (n ? "true" : "false")
        }
    ' "$manifest" > "$tmp" || { rm -f "$tmp" "$lookup"; return 1; }

    # Source of truth for files_planned / ips_planned / files_refused is
    # the original "summary":{} block written by K1. The awk pass above
    # emits "0" placeholders for these three keys (because the summary
    # block sits at the end of the manifest, awk has already re-emitted
    # its replacement before the original lines arrive). Re-extract the
    # K1 values from the on-disk manifest and patch the placeholders.
    local fp ip_p fr
    fp=$(grep -oE '"files_planned":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    ip_p=$(grep -oE '"ips_planned":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    fr=$(grep -oE '"files_refused":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    fp="${fp:-0}"; ip_p="${ip_p:-0}"; fr="${fr:-0}"
    sed -i -E \
        -e "s|\"files_planned\":[0-9]+,|\"files_planned\":${fp},|" \
        -e "s|\"ips_planned\":[0-9]+,|\"ips_planned\":${ip_p},|" \
        -e "s|\"files_refused\":[0-9]+,|\"files_refused\":${fr},|" \
        "$tmp"

    mv "$tmp" "$manifest"
    rm -f "$lookup"

    kill_compute_verdict "$manifest"
    return 0
}

# Build the manifest. Walks signals, applies pattern->action policy,
# aggregates attacker IPs, writes JSON to OUT_FILE. Returns 0 on success,
# 1 if envelope is missing/unreadable. K3/K4/K5/K6 patch the manifest
# in place to record results.
kill_build_manifest() {
    local env="$1" out="$2"
    [[ -n "$env" && -f "$env" ]] || return 1
    [[ -n "$out" ]] || return 1

    local hv run_id ioc_tv host
    hv=$(kill_envelope_root_field "$env" host_verdict)
    run_id=$(kill_envelope_root_field "$env" run_id)
    ioc_tv=$(kill_envelope_root_field "$env" tool_version)
    host=$(kill_envelope_root_field "$env" host)

    local ts_planned
    ts_planned=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    local files_tmp ips_tmp refused_tmp
    files_tmp=$(mktemp /tmp/sessionscribe-kill-files-XXXXXX) || return 1
    ips_tmp=$(mktemp /tmp/sessionscribe-kill-ips-XXXXXX) || { rm -f "$files_tmp"; return 1; }
    refused_tmp=$(mktemp /tmp/sessionscribe-kill-refused-XXXXXX) || { rm -f "$files_tmp" "$ips_tmp"; return 1; }

    local line area severity key pattern path ip ts_first count action
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\{\"host\": ]] || continue
        area=$(kill_json_str_field "$line" area)
        case "$area" in
            (logs|destruction) ;;
            (*) continue ;;
        esac
        severity=$(kill_json_str_field "$line" severity)
        case "$severity" in
            (strong|warning) ;;
            (*) continue ;;
        esac
        key=$(kill_json_str_field "$line" key)
        case "$key" in
            (ioc_sample|ioc_attacker_ip_sample|session_shape_sample) continue ;;
        esac
        pattern=$(kill_pattern_for_key "$key")
        [[ "$pattern" == "skip" ]] && continue

        if [[ "$pattern" == "ip" ]]; then
            ip=$(kill_json_str_field "$line" ip)
            [[ -z "$ip" ]] && continue
            ts_first=$(kill_json_num_field "$line" ts_epoch_first)
            [[ -z "$ts_first" ]] && ts_first=0
            count=$(kill_json_num_field "$line" count)
            [[ -z "$count" ]] && count=1
            printf '%s\t%s\t%s\t%s\n' "$ip" "$ts_first" "$count" "$key" >> "$ips_tmp"
            continue
        fi

        action=$(kill_action_for_pattern "$pattern")
        [[ "$action" == "skip" ]] && continue

        path=$(kill_json_str_field "$line" path)
        [[ -z "$path" ]] && path=$(kill_json_str_field "$line" sample_path)
        # "(none)" is a documented placeholder some emits use when no real
        # evidence path was captured (pattern_a_evidence_destruction etc).
        [[ "$path" == "(none)" || -z "$path" ]] && continue

        if ! kill_path_in_allowlist "$path"; then
            printf '%s\t%s\t%s\t%s\n' "$pattern" "$key" "$path" "path_outside_allowlist" >> "$refused_tmp"
            continue
        fi

        printf '%s\t%s\t%s\t%s\n' "$pattern" "$key" "$path" "$action" >> "$files_tmp"
    done < "$env"

    # IP aggregation: group by IP, sum hits, take min(ts_first), keep first
    # observed source_signal. gawk-3.x compatible (assoc array, no 3-arg
    # match, no {n} intervals).
    local ips_agg
    ips_agg=$(awk -F'\t' '
        {
            ip=$1; ts=$2+0; hits=$3+0; key=$4
            if (!(ip in seen)) {
                seen[ip]=1; first_ts[ip]=ts; first_key[ip]=key; tot_hits[ip]=hits
            } else {
                if (ts > 0 && (first_ts[ip] == 0 || ts < first_ts[ip])) first_ts[ip]=ts
                tot_hits[ip] += hits
            }
        }
        END {
            for (ip in seen) {
                printf "%s\t%d\t%d\t%s\n", ip, first_ts[ip], tot_hits[ip], first_key[ip]
            }
        }
    ' "$ips_tmp" | sort -t$'\t' -k2,2n -k1,1)

    local files_planned ips_planned refused_count
    files_planned=$(wc -l < "$files_tmp" | tr -d ' ')
    if [[ -z "$ips_agg" ]]; then
        ips_planned=0
    else
        ips_planned=$(printf '%s\n' "$ips_agg" | grep -c .)
    fi
    refused_count=$(wc -l < "$refused_tmp" | tr -d ' ')

    # Hand-formatted JSON. jq is opportunistic later for in-place patching
    # during K3/K4/K6; K1 itself emits valid JSON without depending on jq.
    local first
    {
        printf '{\n'
        printf '  "tool":"sessionscribe-mitigate",\n'
        printf '  "tool_version":"%s",\n' "$VERSION"
        printf '  "envelope":"%s",\n' "$(json_esc "$env")"
        printf '  "envelope_run_id":"%s",\n' "$(json_esc "$run_id")"
        printf '  "envelope_tool_version":"%s",\n' "$(json_esc "$ioc_tv")"
        printf '  "host":"%s",\n' "$(json_esc "$host")"
        printf '  "host_verdict":"%s",\n' "$(json_esc "$hv")"
        printf '  "run_id":"%s",\n' "$RUN_ID"
        printf '  "ts_planned":"%s",\n' "$ts_planned"
        printf '  "ts_applied":null,\n'
        printf '  "items":[\n'

        first=1
        local p k pp aa
        while IFS=$'\t' read -r p k pp aa; do
            [[ -z "$p" ]] && continue
            (( first )) || printf ',\n'
            first=0
            printf '    {"kind":"file","pattern":"%s","ioc_key":"%s","path":"%s","action":"%s","sha256_pre":null,"sha256_post":null,"size":null,"dest":null,"result":null}' \
                "$(json_esc "$p")" "$(json_esc "$k")" "$(json_esc "$pp")" "$(json_esc "$aa")"
        done < "$files_tmp"

        local rp rk rpath rres
        while IFS=$'\t' read -r rp rk rpath rres; do
            [[ -z "$rp" ]] && continue
            (( first )) || printf ',\n'
            first=0
            printf '    {"kind":"file","pattern":"%s","ioc_key":"%s","path":"%s","action":"refused","result":"%s"}' \
                "$(json_esc "$rp")" "$(json_esc "$rk")" "$(json_esc "$rpath")" "$(json_esc "$rres")"
        done < "$refused_tmp"

        if [[ -n "$ips_agg" ]]; then
            local ip_a ts_a hits_a key_a
            while IFS=$'\t' read -r ip_a ts_a hits_a key_a; do
                [[ -z "$ip_a" ]] && continue
                (( first )) || printf ',\n'
                first=0
                printf '    {"kind":"ip","ip":"%s","first_seen_epoch":%s,"hits":%s,"source_signal":"%s","action":"csf-deny","result":null}' \
                    "$(json_esc "$ip_a")" "${ts_a:-0}" "${hits_a:-0}" "$(json_esc "$key_a")"
            done <<< "$ips_agg"
        fi

        printf '\n  ],\n'
        printf '  "csf":{\n'
        printf '    "blocklist_url":"https://cdn.rfxn.com/downloads/rfxn_fh-l2_l3_webserver.netset",\n'
        printf '    "blocklist_name":"RFXN_FH_L2L3",\n'
        printf '    "registered":null,\n'
        printf '    "lf_ipset":null,\n'
        printf '    "lf_ipset_maxelem":null,\n'
        printf '    "config_changed":null\n'
        printf '  },\n'
        printf '  "summary":{\n'
        printf '    "files_planned":%d,\n' "$files_planned"
        printf '    "ips_planned":%d,\n' "$ips_planned"
        printf '    "files_refused":%d,\n' "$refused_count"
        printf '    "files_quarantined":null,\n'
        printf '    "files_failed":null,\n'
        printf '    "files_gone":null,\n'
        printf '    "ips_blocked":null,\n'
        printf '    "ips_skipped":null,\n'
        printf '    "ips_failed":null\n'
        printf '  }\n'
        printf '}\n'
    } > "$out"

    rm -f "$files_tmp" "$ips_tmp" "$refused_tmp"
    return 0
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
# 0. snapshot - pre-mitigation evidence capture. Runs FIRST so state is
# frozen before mutating phases. tier1: users/, accounting.log[.*],
# audit.log[.*], cpanel.config, pre-mitigate-tweaksettings.txt (proxysub
# mutation has no per-file backup). tier2 (capped): sessions/{raw,preauth,
# cache}/. Output rides into forensic bundles via defense-state.tgz.
###############################################################################

phase_snapshot() {
    P_CUR=snapshot
    phase_begin snapshot

    # Tier-1 path inventory. Hardcoded set + rotated logs from glob.
    local tier1_paths=(
        /var/cpanel/users
        /var/cpanel/accounting.log
        /var/cpanel/audit.log
        /var/cpanel/cpanel.config
    )
    if [[ -d /var/cpanel ]]; then
        local rot
        while IFS= read -r -d '' rot; do
            tier1_paths+=("$rot")
        done < <(find /var/cpanel -maxdepth 1 -type f \
                       \( -name 'accounting.log.*' -o -name 'audit.log.*' \) \
                       -print0 2>/dev/null)
    fi

    local snap_targets=()
    local total_kb=0
    local p kb
    local tier1_present=0
    # Empty-array guard for set -u + bash 4.1: tier1_paths is hardcoded
    # non-empty above, but consistency with the project's empty-array
    # discipline (see CLAUDE.md "Empty-array iteration") - cheap and safe.
    if (( ${#tier1_paths[@]} > 0 )); then
        for p in "${tier1_paths[@]}"; do
            if [[ -e "$p" ]]; then
                kb=$(du -sk "$p" 2>/dev/null | awk '{print $1+0}')
                snap_targets+=("$p")
                total_kb=$((total_kb + kb))
                tier1_present=$((tier1_present+1))
            fi
        done
    fi

    # Tier-2: session corpus.
    local sess_dirs=("$SESSIONS_DIR/raw" "$SESSIONS_DIR/preauth" "$SESSIONS_DIR/cache")
    local sessions_targets=()
    local sess_kb=0
    for p in "${sess_dirs[@]}"; do
        if [[ -d "$p" ]]; then
            kb=$(du -sk "$p" 2>/dev/null | awk '{print $1+0}')
            sessions_targets+=("$p")
            sess_kb=$((sess_kb + kb))
        fi
    done

    local cap_kb=$((MAX_SNAPSHOT_MB * 1024))
    sk inventory \
       tier1_paths "$tier1_present" \
       tier1_kb "$total_kb" \
       sessions_paths "${#sessions_targets[@]}" \
       sessions_kb "$sess_kb" \
       cap_mb "$MAX_SNAPSHOT_MB"

    say_info "tier1 (accounts/accounting/audit/cpanel.config): $tier1_present paths, $((total_kb/1024)) MB"
    say_info "sessions corpus: ${#sessions_targets[@]} paths, $((sess_kb/1024)) MB (cap: ${MAX_SNAPSHOT_MB} MB)"

    # Apply size cap to sessions tier. tier1 is never capped.
    local include_sessions=1
    if (( sess_kb > cap_kb )); then
        include_sessions=0
        sk sessions_oversize sess_kb "$sess_kb" cap_kb "$cap_kb"
        say_warn "sessions corpus $((sess_kb/1024)) MB exceeds cap ${MAX_SNAPSHOT_MB} MB; skipping (raise with --max-snapshot-mb)"
    fi
    if (( include_sessions )) && (( ${#sessions_targets[@]} > 0 )); then
        local s
        for s in "${sessions_targets[@]}"; do snap_targets+=("$s"); done
    fi

    # whmapi1 get_tweaksetting capture for proxysub keys (closes the
    # phase_proxysub backup gap). Written to a temp file inside BACKUP_DIR
    # in --apply mode; in --check mode just informational.
    local tweak_lines=""
    if have_cmd whmapi1; then
        local tk tv
        tweak_lines+="# whmapi1 get_tweaksetting snapshot ${TS_ISO}"$'\n'
        tweak_lines+="# host=${HOSTNAME_FQDN} run_id=${RUN_ID} tool_version=${VERSION}"$'\n'
        for tk in proxysubdomains proxysubdomainsfornewaccounts; do
            tv=$(whmapi1 get_tweaksetting key="$tk" 2>/dev/null \
                 | awk -F: '/^[[:space:]]+value:/ {sub(/^[[:space:]]+value:[[:space:]]*/,""); print; exit}')
            tweak_lines+="${tk}=${tv:-<unset>}"$'\n'
        done
    fi

    if [[ "$MODE" != "apply" ]]; then
        if (( ${#snap_targets[@]} == 0 )); then
            say_skip "no captureable paths present (host has no /var/cpanel/users etc)"
            phase_set snapshot SKIPPED "nothing to snapshot"
            return
        fi
        say_warn "would write pre-mitigate-state.tgz ($((total_kb/1024)) MB tier1$( ((include_sessions)) && echo " + $((sess_kb/1024)) MB sessions" || echo ""))"
        phase_set snapshot WARN "needs --apply"
        return
    fi

    ensure_backup_dir || { phase_set snapshot FAIL "backup dir creation failed"; return; }

    if (( ${#snap_targets[@]} == 0 )); then
        say_skip "no captureable paths present (host has no /var/cpanel/users etc)"
        phase_set snapshot SKIPPED "nothing to snapshot"
        return
    fi

    local snap_tgz="$BACKUP_DIR/pre-mitigate-state.tgz"
    local snap_info="$BACKUP_DIR/pre-mitigate-state.info"
    local list_file
    list_file=$(mktemp /tmp/sessionscribe-snap.XXXXXX) || {
        say_fail "mktemp failed for snapshot list"
        phase_set snapshot FAIL "mktemp failed"
        return
    }

    # Null-delimited path list for tar --null -T -. Avoids quoting issues.
    local sp
    for sp in "${snap_targets[@]}"; do
        printf '%s\0' "$sp"
    done > "$list_file"

    # Write the tweaksettings capture into BACKUP_DIR and add to the tar
    # list. Lives next to the tgz so it's visible without extracting.
    local tweak_file=""
    if [[ -n "$tweak_lines" ]]; then
        tweak_file="$BACKUP_DIR/pre-mitigate-tweaksettings.txt"
        printf '%s' "$tweak_lines" > "$tweak_file" 2>/dev/null
        chmod 0600 "$tweak_file" 2>/dev/null
        printf '%s\0' "$tweak_file" >> "$list_file"
    fi

    # tar rc=1 ("file changed/removed during read") is expected — sessions
    # churn during capture. rc>=2 is real failure.
    # No -h/--dereference: attacker-planted symlinks in sessions/ must
    # archive as symlinks, not their targets.
    local tar_rc=0
    tar --null -czf "$snap_tgz" -T "$list_file" 2>/dev/null || tar_rc=$?
    rm -f "$list_file" 2>/dev/null

    if (( tar_rc != 0 && tar_rc != 1 )); then
        say_fail "tar failed (rc=$tar_rc) writing $snap_tgz"
        phase_set snapshot FAIL "tar rc=$tar_rc"
        return
    fi

    chmod 0600 "$snap_tgz" 2>/dev/null
    local snap_bytes
    snap_bytes=$(stat -c %s "$snap_tgz" 2>/dev/null)
    snap_bytes="${snap_bytes:-0}"

    local snap_sha=""
    if have_cmd sha256sum; then
        snap_sha=$(sha256sum -- "$snap_tgz" 2>/dev/null | awk '{print $1}')
    fi

    {
        printf '%s\n' \
            "# sessionscribe-mitigate pre-mitigation snapshot record" \
            "tool=sessionscribe-mitigate" \
            "tool_version=$VERSION" \
            "run_id=$RUN_ID" \
            "snapshot_ts=$TS_ISO" \
            "host=$HOSTNAME_FQDN" \
            "snapshot_path=$snap_tgz" \
            "snapshot_bytes=$snap_bytes" \
            "snapshot_sha256=${snap_sha:-}" \
            "tier1_paths_count=$tier1_present" \
            "tier1_kb=$total_kb" \
            "sessions_paths_count=${#sessions_targets[@]}" \
            "sessions_kb=$sess_kb" \
            "sessions_included=$include_sessions" \
            "max_snapshot_mb=$MAX_SNAPSHOT_MB" \
            "tar_rc=$tar_rc"
    } > "$snap_info" 2>/dev/null
    chmod 0600 "$snap_info" 2>/dev/null

    sk wrote bytes "$snap_bytes" sha256 "${snap_sha:-}" path "$snap_tgz" \
       tar_rc "$tar_rc" sessions_included "$include_sessions"
    say_action "wrote pre-mitigate-state.tgz ($((snap_bytes/1024/1024)) MB, sha256 ${snap_sha:0:12}...) to $BACKUP_DIR/"
    phase_set snapshot ACTION "snapshot $((snap_bytes/1024/1024)) MB"
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
        timeout 5m dnf -q -y --disablerepo='*' --enablerepo="$r" makecache --refresh \
            >/dev/null 2>&1
    elif have_cmd yum; then
        timeout 5m yum -q -y --disablerepo='*' --enablerepo="$r" makecache fast \
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

    # Pattern A's encryptor targets accounting.log → .sorry. Without the
    # live file, Pattern D detection is lossy — surface an advisory.
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
    if timeout 5m rpm -q epel-release >/dev/null 2>&1; then
        say_pass "epel-release installed"
    else
        if [[ "$MODE" == "apply" ]]; then
            local pkg_ok=0
            if have_cmd dnf; then
                timeout 5m dnf install -y epel-release >/dev/null 2>&1 && pkg_ok=1
            elif have_cmd yum; then
                timeout 5m yum install -y epel-release >/dev/null 2>&1 && pkg_ok=1
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
        if timeout 5m dnf clean metadata >/dev/null 2>&1; then
            say_info "dnf clean metadata (cached repodata invalidated)"
        else
            say_warn "dnf clean metadata failed; sweep may use stale cache"
        fi
    elif have_cmd yum; then
        if timeout 5m yum clean metadata >/dev/null 2>&1; then
            say_info "yum clean metadata (cached repodata invalidated)"
        else
            say_warn "yum clean metadata failed; sweep may use stale cache"
        fi
    fi

    # 2d: broken-repo sweep.
    sk repo_sweep
    if have_cmd dnf; then
        local enabled_repos r
        enabled_repos=$(timeout 5m dnf repolist --enabled -q 2>/dev/null \
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
                            if timeout 5m dnf config-manager --set-disabled "$r" \
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
# 10. sessions - forged-session IOC ladder + quarantine. Mirrors
# ioc-scan.sh's ladder. Patch closes the vector; leaked tokens survive
# until session expiry, so quarantine is still required. --apply moves
# raw + preauth + cache copies (listaccts propagates raw → cache, so
# removing only raw leaves the token live). Probe-canary sessions
# (^nxesec_canary_<nonce>=) skipped + counted separately.
###############################################################################

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

        # awk emits PROBE_ARTIFACT / FORGED:<csv> / OK. B-cand confirmed in
        # bash via paired preauth companion (cpsrvd removes preauth on
        # promotion). IOC-D2: single-line pass= on a badpass session is
        # injection footprint (saveSession writes pass= only length>0;
        # badpass call site doesn't pass `pass`). IOC-2: re-audit
        # Cpanel/Security/Authn/TwoFactorAuth/Verify.pm + Cpanel/Server.pm
        # on patch tier bump — extend has_kg if a new legitimate origin
        # appears, else FP.
        session_shape=$(awk -v now="$now_epoch" -v floor="$PASS_FORGERY_MAX_LEN" \
                            -v canary_re="$PROBE_CANARY_PAT" '
            BEGIN { line_idx=0; pass_count=0; pass_at=0 }
            { line_idx++ }
            /^token_denied=/        { has_td=1 }
            /^cp_security_token=/   { has_cp=1 }
            /^origin_as_string=/ {
                origin=substr($0, index($0,"=")+1)
                if (origin ~ /method=badpass/)              has_bp=1
                if (origin ~ /method=handle_form_login/)    has_kg=1
                if (origin ~ /method=create_user_session/)  has_kg=1
                if (origin ~ /method=handle_auth_transfer/) has_kg=1
                has_origin=1
            }
            /^successful_external_auth_with_timestamp=/ {
                has_ext=1; ts_val=substr($0, index($0,"=")+1)
            }
            /^successful_internal_auth_with_timestamp=/ {
                has_int=1; ts_val=substr($0, index($0,"=")+1)
            }
            /^tfa_verified=1$/      { has_tfa=1 }
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
                # IOC-D2: single-line pass= on badpass session, structurally
                # well-formed, no auth markers. Distinct from IOC-D which
                # requires pass_count>1 || stranded. Closes parity gap with
                # the cPanel reference IOC-5.
                if (has_bp && pass_count == 1 && !stranded \
                    && !has_ext && !has_int) reasons = reasons "D2,"
                # IOC-2: tfa_verified=1 with non-badpass non-known-good
                # origin. The badpass+tfa case is covered by IOC-E. Closes
                # parity gap with the cPanel reference IOC-2.
                if (has_tfa && has_origin && !has_bp && !has_kg)
                    reasons = reasons "2,"
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
            # ATTEMPT-class shapes (D2-only / 2-only) tag as "attempt
            # session:" so operators can tell forensic-grade hits from
            # session-level attempt residue without parsing reason letters.
            # Display-only split: confirmed-class (A/B/C/D/E/E2/F/H/I) =
            # forged; D2/2 alone = attempt. Quarantine action identical.
            local class_tag="forged"
            case ",$reasons," in
                (*,A,*|*,B,*|*,C,*|*,D,*|*,E,*|*,E2,*|*,F,*|*,H,*|*,I,*) ;;
                (*,D2,*|*,2,*) class_tag="attempt" ;;
            esac
            say_warn "$class_tag session: $f ($would_msg)"
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

# Quarantine a forged session + companions (preauth/<sname> if IOC-B
# fired; cache/<sname> always when present — leaving cache leaves the
# token live). cp -a + .info sidecar (ctime, sha256, mode, IOC reasons),
# then rm. Returns 0 ok, 1 raw cp failed, 2 partial rm failure.
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
    # 0700 so only root can read - same posture as ioc-scan --full bundle
    # dirs (/root/.ic5790-forensic/...). No-op if the dirs were already
    # created on a prior run.
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

# Build .info sidecar (key=value, no quoting). Captures ctime + sha256 +
# size + IOC reasons. printf used over heredoc to neutralize any shell
# metacharacters in session filenames.
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

# phase_kill - targeted quarantine + IP block from an IOC envelope. Opt-in
# via --kill. Default-off; never runs unless RUN_KILL=1. Gated on
# host_verdict == COMPROMISED unless --kill-anyway is set.
#
# Pipeline: K1 manifest build -> K3 file quarantine -> K4 csf -d ->
# K5 csf.blocklists register -> K6 finalize manifest + verdict. K3/K4/K5
# are mutating and require --apply. csf -ra reload at end if any csf
# state changed.
phase_kill() {
    P_CUR=kill
    phase_begin kill

    if (( RUN_KILL == 0 )); then
        sk kill_optout
        say_skip "--kill not specified (opt-in)"
        phase_set kill SKIPPED "opt-in"
        return
    fi

    # Resolve the envelope.
    local env="$KILL_ENVELOPE"
    if [[ -z "$env" ]]; then
        env=$(kill_find_envelope)
    fi
    if [[ -z "$env" || ! -f "$env" ]]; then
        sk kill_no_envelope path "$env"
        say_skip "no IOC envelope (looked at: ${env:-$KILL_ENVELOPE_DIR/*.json}; run sessionscribe-ioc-scan --full first or pass --envelope PATH)"
        phase_set kill SKIPPED "no envelope"
        return
    fi
    say_info "envelope: $env"

    # Gate on host_verdict.
    local hv
    hv=$(kill_envelope_root_field "$env" host_verdict)
    sk kill_gate envelope "$env" host_verdict "$hv"
    if [[ "$hv" != "COMPROMISED" && $KILL_ANYWAY -eq 0 ]]; then
        say_skip "host_verdict=$hv (need COMPROMISED, or pass --kill-anyway)"
        phase_set kill SKIPPED "host_verdict=$hv"
        return
    fi
    if [[ "$hv" != "COMPROMISED" ]]; then
        say_warn "host_verdict=$hv but --kill-anyway is set (operator override)"
    fi

    # Phase needs BACKUP_DIR; create only on --apply.
    if [[ "$MODE" == "apply" ]]; then
        ensure_backup_dir || { phase_set kill FAIL "backup-dir create failed"; return; }
    else
        # In --check we still need a path for the manifest; use BACKUP_DIR
        # under a deterministic-but-not-yet-created location.
        mkdir -p "$BACKUP_DIR" 2>/dev/null || true
    fi

    local manifest="$BACKUP_DIR/kill-manifest.json"

    # K1: build manifest.
    if ! kill_build_manifest "$env" "$manifest"; then
        sk kill_manifest_failed
        say_fail "manifest build failed"
        phase_set kill FAIL "manifest build failed"
        return
    fi
    local files_planned ips_planned files_refused
    files_planned=$(grep -oE '"files_planned":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    ips_planned=$(grep -oE '"ips_planned":[0-9]+'   "$manifest" | head -1 | grep -oE '[0-9]+')
    files_refused=$(grep -oE '"files_refused":[0-9]+' "$manifest" | head -1 | grep -oE '[0-9]+')
    say_info "manifest: $manifest (files=${files_planned:-0}, ips=${ips_planned:-0}, refused=${files_refused:-0})"

    if [[ "$MODE" == "apply" ]]; then
        # K3: file quarantine.
        quarantine_from_manifest "$manifest" || true
        # K4: csf -d per attacker IP.
        apply_csf_blocks "$manifest" || true
        # K5: rfxn blocklist register (mutates csf.conf + csf.blocklists).
        register_rfxn_blocklist "$manifest" || true

        # csf -ra reload if anything csf-related changed.
        local sidecar="${manifest%.json}.actions.jsonl"
        local need_reload=0
        if [[ -f "$sidecar" ]]; then
            if grep -qE '"kind":"ip","[^}]*"result":"ok"' "$sidecar"; then need_reload=1; fi
            if grep -qE '"kind":"csf","[^}]*"result":"ok"' "$sidecar"; then need_reload=1; fi
            if grep -qE '"kind":"csf","[^}]*"result":"created_new_file"' "$sidecar"; then need_reload=1; fi
        fi
        if (( need_reload )) && have_cmd csf; then
            sk kill_csf_reload
            if csf -ra >/dev/null 2>&1; then
                say_action "csf -ra reloaded"
            else
                say_warn "csf -ra reload failed; review manually"
            fi
        fi
    else
        # K5 in check mode reports needs-apply but mutates nothing. Useful
        # for dry-run reporting against the same manifest.
        register_rfxn_blocklist "$manifest" || true
    fi

    # K6: finalize manifest + compute verdict.
    finalize_manifest "$manifest" || {
        say_fail "manifest finalize failed"
        phase_set kill FAIL "finalize failed"
        return
    }

    sk kill_summary manifest "$manifest" verdict "$LAST_KILL_VERDICT"
    case "$LAST_KILL_VERDICT" in
        ACTION)  say_action "$LAST_KILL_DETAIL" ;;
        FAIL)    say_fail   "$LAST_KILL_DETAIL" ;;
        WARN)    say_warn   "$LAST_KILL_DETAIL" ;;
        OK|*)    say_pass   "$LAST_KILL_DETAIL" ;;
    esac
    phase_set kill "$LAST_KILL_VERDICT" "$LAST_KILL_DETAIL"
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
        snapshot)   phase_snapshot ;;
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
        kill)       phase_kill ;;
    esac
}

# Library-only mode for unit-testing kill-chain helpers without running the
# phase chain. When MITIGATE_LIBRARY_ONLY=1, all globals are initialized and
# every helper function is in scope, but the banner, phases, and exit logic
# below are skipped. Used by K1+ test harnesses; never set in production.
if [[ "${MITIGATE_LIBRARY_ONLY:-0}" == "1" ]]; then
    if [[ "${MITIGATE_RUN_P1_TESTS:-0}" == "1" ]]; then
        # P1 test harness — 29 cases from PLAN-sshkey-prune.md lines 488-525.
        # Each test prints OK(<n> <description>) or FAIL(<n> <description>:
        # <diagnostic>) on stdout. Exits 0 on all-OK, 1 on any FAIL.
        _t_pass=0
        _t_fail=0
        _t_dir=$(mktemp -d /tmp/sessionscribe-p1-tests-XXXXXX)
        _t_ok()   { _t_pass=$((_t_pass+1)); printf 'OK(%s %s)\n' "$1" "$2"; }
        _t_fail() { _t_fail=$((_t_fail+1)); printf 'FAIL(%s %s: %s)\n' "$1" "$2" "$3"; }

        # Tests 1-11: ssh_key_parse_line
        _r=$(ssh_key_parse_line "ssh-rsa AAAAB3 ryan@laptop")
        if [[ "$_r" == $'ssh-rsa\tryan@laptop\tAAAAB3' ]]; then
            _t_ok 1 "parse_line basic rsa"
        else
            _t_fail 1 "parse_line basic rsa" "got: $_r"
        fi

        _r=$(ssh_key_parse_line "ssh-ed25519 AAAA Parent Child key for W9Z2DL")
        if [[ "$_r" == $'ssh-ed25519\tParent Child key for W9Z2DL\tAAAA' ]]; then
            _t_ok 2 "parse_line Parent Child comment"
        else
            _t_fail 2 "parse_line Parent Child comment" "got: $_r"
        fi

        _r=$(ssh_key_parse_line 'from="1.2.3.4",no-pty ssh-rsa AAAA user@host')
        if [[ "$_r" == $'ssh-rsa\tuser@host\tAAAA' ]]; then
            _t_ok 3 "parse_line options-prefix"
        else
            _t_fail 3 "parse_line options-prefix" "got: $_r"
        fi

        _r=$(ssh_key_parse_line "ssh-rsa AAAA")
        if [[ "$_r" == $'ssh-rsa\t\tAAAA' ]]; then
            _t_ok 4 "parse_line empty comment"
        else
            _t_fail 4 "parse_line empty comment" "got: $_r"
        fi

        if ssh_key_parse_line "" >/dev/null 2>&1; then
            _t_fail 5 "parse_line empty input" "rc=0 expected rc=1"
        else
            _t_ok 5 "parse_line empty input"
        fi

        if ssh_key_parse_line "# a comment" >/dev/null 2>&1; then
            _t_fail 6 "parse_line comment-only line" "rc=0 expected rc=1"
        else
            _t_ok 6 "parse_line comment-only line"
        fi

        if ssh_key_parse_line "garbage line no-keytype" >/dev/null 2>&1; then
            _t_fail 7 "parse_line no keytype" "rc=0 expected rc=1"
        else
            _t_ok 7 "parse_line no keytype"
        fi

        _r=$(ssh_key_parse_line "ecdsa-sha2-nistp256 AAAA legit")
        if [[ "$_r" == $'ecdsa-sha2-nistp256\tlegit\tAAAA' ]]; then
            _t_ok 8 "parse_line ecdsa keytype"
        else
            _t_fail 8 "parse_line ecdsa keytype" "got: $_r"
        fi

        _r=$(ssh_key_parse_line "sk-ssh-ed25519@openssh.com AAAA fido-key")
        if [[ "$_r" == $'sk-ssh-ed25519@openssh.com\tfido-key\tAAAA' ]]; then
            _t_ok 9 "parse_line FIDO sk-ed25519"
        else
            _t_fail 9 "parse_line FIDO sk-ed25519" "got: $_r"
        fi

        _r=$(ssh_key_parse_line 'command="echo a b" ssh-rsa AAAA c')
        if [[ "$_r" == $'ssh-rsa\tc\tAAAA' ]]; then
            _t_ok 10 "parse_line options with quoted command"
        else
            _t_fail 10 "parse_line options with quoted command" "got: $_r"
        fi

        # Test 11: documented edge case — first-keytype-token-match wins.
        # `command="ssh-rsa fake" ssh-rsa AAAA real` — the first keytype
        # token is the `ssh-rsa` inside the quoted command, so the parsed
        # base64 is `fake"` and the comment is `ssh-rsa AAAA real`.
        _r=$(ssh_key_parse_line 'command="ssh-rsa fake" ssh-rsa AAAA real')
        _expected_11=$'ssh-rsa\tssh-rsa AAAA real\tfake"'
        if [[ "$_r" == "$_expected_11" ]]; then
            _t_ok 11 "parse_line first-token-wins edge"
        else
            _t_fail 11 "parse_line first-token-wins edge" "got: $_r"
        fi

        # Test 12: classify on 4-line file
        _f12="$_t_dir/12.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'ssh-rsa BBBB evil@host\n'
            printf '\n'
            printf '# a comment\n'
        } > "$_f12"
        _out12=$(ssh_keys_classify "$_f12" "$KILL_SSH_TRUST_RE")
        _actions12=$(printf '%s\n' "$_out12" | awk -F'\t' '{print $1}' | tr '\n' ',' | sed 's/,$//')
        if [[ "$_actions12" == "keep,prune,skip,skip" ]]; then
            _t_ok 12 "classify 4-line mixed"
        else
            _t_fail 12 "classify 4-line mixed" "actions=$_actions12"
        fi

        # Test 13: classify on file with a malformed line → rc=3
        _f13="$_t_dir/13.keys"
        {
            printf 'ssh-rsa AAAA legit@nexcess\n'
            printf 'garbage line no-keytype here\n'
        } > "$_f13"
        ssh_keys_classify "$_f13" "$KILL_SSH_TRUST_RE" >/dev/null 2>&1
        _rc13=$?
        if (( _rc13 == 3 )); then
            _t_ok 13 "classify malformed -> rc=3"
        else
            _t_fail 13 "classify malformed -> rc=3" "rc=$_rc13"
        fi

        # Test 14: classify on a symlink → rc=2
        _f14_target="$_t_dir/14.target"
        _f14_link="$_t_dir/14.link"
        printf 'ssh-rsa AAAA legit@nexcess\n' > "$_f14_target"
        ln -s "$_f14_target" "$_f14_link"
        ssh_keys_classify "$_f14_link" "$KILL_SSH_TRUST_RE" >/dev/null 2>&1
        _rc14=$?
        if (( _rc14 == 2 )); then
            _t_ok 14 "classify symlink -> rc=2"
        else
            _t_fail 14 "classify symlink -> rc=2" "rc=$_rc14"
        fi

        # Test 15: classify with empty-comment, default policy -> keep_unlabeled
        _f15="$_t_dir/15.keys"
        printf 'ssh-rsa AAAA\n' > "$_f15"
        _out15=$(ssh_keys_classify "$_f15" "$KILL_SSH_TRUST_RE" | awk -F'\t' '{print $1}')
        if [[ "$_out15" == "keep_unlabeled" ]]; then
            _t_ok 15 "classify empty-comment default -> keep_unlabeled"
        else
            _t_fail 15 "classify empty-comment default -> keep_unlabeled" "got=$_out15"
        fi

        # Test 16: classify with --include-unlabeled-as-prune
        _out16=$(ssh_keys_classify "$_f15" "$KILL_SSH_TRUST_RE" --include-unlabeled-as-prune \
                  | awk -F'\t' '{print $1}')
        if [[ "$_out16" == "prune" ]]; then
            _t_ok 16 "classify empty-comment with flag -> prune"
        else
            _t_fail 16 "classify empty-comment with flag -> prune" "got=$_out16"
        fi

        # Test 17: ssh_keys_prune mixed file -> pruned_ok (under MODE=apply).
        # `grep -c PAT FILE` always prints a count and exits 0 (match) or
        # 1 (no-match); both cases give a clean integer on stdout. Don't
        # chain `|| echo 0` — it doubles the output on no-match.
        MODE="apply"
        _f17="$_t_dir/17.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'ssh-rsa BBBB evil@host\n'
        } > "$_f17"
        _b17="$_t_dir/17-backup/keys"
        ssh_keys_prune "$_f17" "$KILL_SSH_TRUST_RE" "$_b17" "" >/dev/null 2>&1
        _kept17=$(grep -c 'Parent Child' "$_f17" 2>/dev/null)
        _pruned17=$(grep -c 'evil@host' "$_f17" 2>/dev/null)
        _backup_has=$(grep -c 'evil@host' "${_b17}.original-pre-prune" 2>/dev/null)
        _sidecar_has=$(grep -c 'evil@host' "${_b17}.removed-keys" 2>/dev/null)
        if [[ "$KILL_LAST_PRUNE_RESULT" == "pruned_ok" \
              && "$_kept17" == "1" && "$_pruned17" == "0" \
              && "$_backup_has" == "1" && "$_sidecar_has" == "1" ]]; then
            _t_ok 17 "prune mixed -> pruned_ok"
        else
            _t_fail 17 "prune mixed -> pruned_ok" \
                "result=$KILL_LAST_PRUNE_RESULT kept=$_kept17 pruned=$_pruned17 backup=$_backup_has sidecar=$_sidecar_has"
        fi

        # Test 18: all-suspect file, no allow_lockout -> would_lock_out
        _f18="$_t_dir/18.keys"
        printf 'ssh-rsa AAAA evil1@host\nssh-rsa BBBB evil2@host\n' > "$_f18"
        _f18_pre=$(sha256sum "$_f18" | awk '{print $1}')
        _b18="$_t_dir/18-backup/keys"
        ssh_keys_prune "$_f18" "$KILL_SSH_TRUST_RE" "$_b18" "" >/dev/null 2>&1
        _f18_post=$(sha256sum "$_f18" | awk '{print $1}')
        if [[ "$KILL_LAST_PRUNE_RESULT" == "would_lock_out" \
              && "$_f18_pre" == "$_f18_post" ]]; then
            _t_ok 18 "prune all-suspect default -> would_lock_out"
        else
            _t_fail 18 "prune all-suspect default -> would_lock_out" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f18_pre post=$_f18_post"
        fi

        # Test 19: all-suspect with allow_lockout -> forced_full_prune
        _f19="$_t_dir/19.keys"
        printf 'ssh-rsa AAAA evil1@host\nssh-rsa BBBB evil2@host\n' > "$_f19"
        _b19="$_t_dir/19-backup/keys"
        ssh_keys_prune "$_f19" "$KILL_SSH_TRUST_RE" "$_b19" "allow_lockout" >/dev/null 2>&1
        _f19_size=$(wc -c < "$_f19" | tr -d ' ')
        _b19_has=$(grep -c 'evil1@host' "${_b19}.original-pre-prune" 2>/dev/null)
        if [[ "$KILL_LAST_PRUNE_RESULT" == "forced_full_prune" \
              && "$_f19_size" == "0" && "$_b19_has" == "1" ]]; then
            _t_ok 19 "prune all-suspect allow_lockout -> forced_full_prune"
        else
            _t_fail 19 "prune all-suspect allow_lockout -> forced_full_prune" \
                "result=$KILL_LAST_PRUNE_RESULT size=$_f19_size backup_has_evil=$_b19_has"
        fi

        # Test 20: all-trusted file -> nothing_to_prune
        _f20="$_t_dir/20.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'ssh-rsa BBBB lwadmin@bastion\n'
        } > "$_f20"
        _f20_pre=$(sha256sum "$_f20" | awk '{print $1}')
        ssh_keys_prune "$_f20" "$KILL_SSH_TRUST_RE" "$_t_dir/20-backup/keys" "" >/dev/null 2>&1
        _f20_post=$(sha256sum "$_f20" | awk '{print $1}')
        if [[ "$KILL_LAST_PRUNE_RESULT" == "nothing_to_prune" \
              && "$_f20_pre" == "$_f20_post" ]]; then
            _t_ok 20 "prune all-trusted -> nothing_to_prune"
        else
            _t_fail 20 "prune all-trusted -> nothing_to_prune" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f20_pre post=$_f20_post"
        fi

        # Test 21: only-unlabeled keys, default -> kept_unlabeled_warned
        _f21="$_t_dir/21.keys"
        printf 'ssh-rsa AAAA\nssh-rsa BBBB\n' > "$_f21"
        _f21_pre=$(sha256sum "$_f21" | awk '{print $1}')
        ssh_keys_prune "$_f21" "$KILL_SSH_TRUST_RE" "$_t_dir/21-backup/keys" "" >/dev/null 2>&1
        _f21_post=$(sha256sum "$_f21" | awk '{print $1}')
        if [[ "$KILL_LAST_PRUNE_RESULT" == "kept_unlabeled_warned" \
              && "$_f21_pre" == "$_f21_post" ]]; then
            _t_ok 21 "prune only-unlabeled default -> kept_unlabeled_warned"
        else
            _t_fail 21 "prune only-unlabeled default -> kept_unlabeled_warned" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f21_pre post=$_f21_post"
        fi

        # Test 22: missing path -> gone
        ssh_keys_prune "$_t_dir/does-not-exist" "$KILL_SSH_TRUST_RE" "$_t_dir/22-backup/keys" "" >/dev/null 2>&1
        if [[ "$KILL_LAST_PRUNE_RESULT" == "gone" ]]; then
            _t_ok 22 "prune missing path -> gone"
        else
            _t_fail 22 "prune missing path -> gone" "result=$KILL_LAST_PRUNE_RESULT"
        fi

        # Test 23: symlink -> refused_symlink, target untouched
        _f23_target="$_t_dir/23.target"
        _f23_link="$_t_dir/23.link"
        printf 'sentinel-content\n' > "$_f23_target"
        _f23_pre=$(sha256sum "$_f23_target" | awk '{print $1}')
        ln -s "$_f23_target" "$_f23_link"
        ssh_keys_prune "$_f23_link" "$KILL_SSH_TRUST_RE" "$_t_dir/23-backup/keys" "" >/dev/null 2>&1
        _f23_post=$(sha256sum "$_f23_target" | awk '{print $1}')
        if [[ "$KILL_LAST_PRUNE_RESULT" == "refused_symlink" \
              && "$_f23_pre" == "$_f23_post" ]]; then
            _t_ok 23 "prune symlink -> refused_symlink"
        else
            _t_fail 23 "prune symlink -> refused_symlink" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f23_pre post=$_f23_post"
        fi

        # Test 24: malformed line -> refused_unparseable, no mutation
        _f24="$_t_dir/24.keys"
        {
            printf 'ssh-rsa AAAA legit@nexcess\n'
            printf 'nokeytype garbage here\n'
        } > "$_f24"
        _f24_pre=$(sha256sum "$_f24" | awk '{print $1}')
        ssh_keys_prune "$_f24" "$KILL_SSH_TRUST_RE" "$_t_dir/24-backup/keys" "" >/dev/null 2>&1
        _f24_post=$(sha256sum "$_f24" | awk '{print $1}')
        if [[ "$KILL_LAST_PRUNE_RESULT" == "refused_unparseable" \
              && "$_f24_pre" == "$_f24_post" ]]; then
            _t_ok 24 "prune malformed -> refused_unparseable"
        else
            _t_fail 24 "prune malformed -> refused_unparseable" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f24_pre post=$_f24_post"
        fi

        # Test 25: sha256-mismatch-injection via a sha256sum SHIM on PATH.
        # An on-disk wrapper script intercepts every sha256sum invocation
        # — including pipeline-fork subshells where in-process function
        # overrides are unreliable on bash 4.1 (function-table inheritance
        # across pipeline stages is implementation-defined). The shim
        # uses a file-counter to fabricate a non-matching sha on the 3rd
        # call (step 8's post-lock re-read), causing
        # concurrent_modification.
        _real_sha256sum=$(command -v sha256sum)
        _shim_dir="$_t_dir/shim"
        mkdir -p "$_shim_dir"
        # Shim source body: $vars must NOT expand at WRITE time (they are
        # the shim's own runtime state, not the harness's). Single quotes
        # are intentional. shellcheck disable=SC2016.
        # shellcheck disable=SC2016
        {
            printf '#!/bin/bash\n'
            printf 'set -u\n'
            printf 'COUNTER="%s/count"\n' "$_t_dir"
            printf 'TRIGGER="%s/trigger"\n' "$_t_dir"
            printf 'REAL="%s"\n' "$_real_sha256sum"
            printf 'n=$(cat "$COUNTER" 2>/dev/null || printf 0)\n'
            printf 'n=$((n + 1))\n'
            printf 'printf "%%d\\n" "$n" > "$COUNTER"\n'
            printf 't=$(cat "$TRIGGER" 2>/dev/null || printf 0)\n'
            printf 'if (( n == t )); then\n'
            printf '  if [[ -n "${1-}" ]]; then\n'
            printf '    printf "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  %%s\\n" "$1"\n'
            printf '  else\n'
            printf '    printf "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  -\\n"\n'
            printf '  fi\n'
            printf '  exit 0\n'
            printf 'fi\n'
            printf 'exec "$REAL" "$@"\n'
        } > "$_shim_dir/sha256sum"
        chmod +x "$_shim_dir/sha256sum"
        _orig_PATH="$PATH"

        _f25="$_t_dir/25.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'ssh-rsa BBBB evil@host\n'
        } > "$_f25"
        _f25_pre=$(command "$_real_sha256sum" "$_f25" | awk '{print $1}')
        printf '0\n' > "$_t_dir/count"
        # Call sequence on a 2-key file when ssh-keygen lacks the
        # algorithm and falls back to base64-decoded sha256:
        #   1 = step 2 (sha_pre)
        #   2,3 = ssh_key_fingerprint per key during classify
        #   4 = step 6 (backup integrity)
        #   5 = step 8 (post-lock sha_now) ← target the abort path here
        #   6 = step 12 (sha_post)
        # Trigger=5 fabricates step 8's sha_now → concurrent_modification.
        printf '5\n' > "$_t_dir/trigger"
        # PATH-shimmed sha256sum is now active. ssh_keys_prune will hit
        # the wrapper at every step 2/6/8/12 invocation.
        PATH="$_shim_dir:$_orig_PATH"
        hash -r 2>/dev/null || true
        ssh_keys_prune "$_f25" "$KILL_SSH_TRUST_RE" "$_t_dir/25-backup/keys" "" >/dev/null 2>&1
        PATH="$_orig_PATH"
        hash -r 2>/dev/null || true
        _f25_post=$(command "$_real_sha256sum" "$_f25" | awk '{print $1}')
        # Expected: step 8 catches sha_now != sha_pre → concurrent_modification.
        # Original preserved (no rewrite — step 8 aborts pre-mv).
        if [[ "$KILL_LAST_PRUNE_RESULT" == "concurrent_modification" \
              && "$_f25_pre" == "$_f25_post" ]]; then
            _t_ok 25 "prune sha-mismatch injection -> concurrent_modification"
        else
            _t_fail 25 "prune sha-mismatch injection -> concurrent_modification" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f25_pre post=$_f25_post"
        fi

        # Test 26: mid-flight modification — fabricate sha_pre on the
        # 1st call (step 2). Step 6's backup integrity check (call 2 =
        # sha of backup) returns the real sha, which won't match the
        # fabricated sha_pre → prune_failed (backup_integrity). Original
        # preserved.
        _f26="$_t_dir/26.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'ssh-rsa BBBB evil@host\n'
        } > "$_f26"
        _f26_pre=$(command "$_real_sha256sum" "$_f26" | awk '{print $1}')
        printf '0\n' > "$_t_dir/count"
        printf '1\n' > "$_t_dir/trigger"   # fabricate on call 1 (sha_pre)
        PATH="$_shim_dir:$_orig_PATH"
        hash -r 2>/dev/null || true
        ssh_keys_prune "$_f26" "$KILL_SSH_TRUST_RE" "$_t_dir/26-backup/keys" "" >/dev/null 2>&1
        PATH="$_orig_PATH"
        hash -r 2>/dev/null || true
        _f26_post=$(command "$_real_sha256sum" "$_f26" | awk '{print $1}')
        # Step 6 backup_integrity fires → prune_failed; OR step 8 fires
        # → concurrent_modification. Either is the abort path; the
        # load-bearing invariant is "original preserved".
        if [[ ( "$KILL_LAST_PRUNE_RESULT" == "prune_failed" \
                || "$KILL_LAST_PRUNE_RESULT" == "concurrent_modification" ) \
              && "$_f26_pre" == "$_f26_post" ]]; then
            _t_ok 26 "prune mid-flight modification -> abort+preserve"
        else
            _t_fail 26 "prune mid-flight modification -> abort+preserve" \
                "result=$KILL_LAST_PRUNE_RESULT pre=$_f26_pre post=$_f26_post"
        fi

        # Test 27: FIDO key + Parent Child mix
        _f27="$_t_dir/27.keys"
        {
            printf 'ssh-rsa AAAA Parent Child key for W9Z2DL\n'
            printf 'sk-ssh-ed25519@openssh.com BBBB lwadmin-yubikey-01\n'
            printf 'sk-ecdsa-sha2-nistp256 CCCC\n'
        } > "$_f27"
        ssh_keys_prune "$_f27" "$KILL_SSH_TRUST_RE" "$_t_dir/27-backup/keys" "" >/dev/null 2>&1
        # Default policy: Parent Child kept, lwadmin-yubikey kept
        # (matches lwadmin), unlabeled FIDO kept_unlabeled. n_prune=0
        # → kept_unlabeled_warned (because there's an unlabeled key).
        _kept_pc=$(grep -c 'Parent Child' "$_f27" 2>/dev/null)
        _kept_yk=$(grep -c 'lwadmin-yubikey' "$_f27" 2>/dev/null)
        if [[ "$KILL_LAST_PRUNE_RESULT" == "kept_unlabeled_warned" \
              && "$_kept_pc" == "1" && "$_kept_yk" == "1" ]]; then
            _t_ok 27 "prune FIDO+ParentChild+unlabeled -> kept_unlabeled_warned"
        else
            _t_fail 27 "prune FIDO+ParentChild+unlabeled -> kept_unlabeled_warned" \
                "result=$KILL_LAST_PRUNE_RESULT pc=$_kept_pc yk=$_kept_yk"
        fi

        # Test 28: trust-drift gate, identical regex -> rc=0
        _f28="$_t_dir/28-iocscan.sh"
        {
            printf '#!/bin/bash\n'
            printf "SSH_KNOWN_GOOD_RE='%s'\n" "$KILL_SSH_TRUST_RE"
        } > "$_f28"
        KILL_SSH_TRUST_DRIFT_TEST_PATH="$_f28"
        if kill_sshkey_check_trust_drift >/dev/null 2>&1; then
            _t_ok 28 "drift gate identical -> rc=0"
        else
            _t_fail 28 "drift gate identical -> rc=0" "rc=$?"
        fi
        unset KILL_SSH_TRUST_DRIFT_TEST_PATH

        # Test 29: trust-drift gate, different regex -> rc=1 (and rc=0 with KILL_SSH_ALLOW_DRIFT=1)
        _f29="$_t_dir/29-iocscan.sh"
        {
            printf '#!/bin/bash\n'
            printf "SSH_KNOWN_GOOD_RE='(bogus|prefix|here)'\n"
        } > "$_f29"
        KILL_SSH_TRUST_DRIFT_TEST_PATH="$_f29"
        KILL_SSH_ALLOW_DRIFT=0
        kill_sshkey_check_trust_drift >/dev/null 2>&1
        _rc29a=$?
        KILL_SSH_ALLOW_DRIFT=1
        kill_sshkey_check_trust_drift >/dev/null 2>&1
        _rc29b=$?
        if (( _rc29a == 1 )) && (( _rc29b == 0 )); then
            _t_ok 29 "drift gate divergent rc=1; bypass with allow_drift rc=0"
        else
            _t_fail 29 "drift gate divergent" "no_bypass=$_rc29a with_bypass=$_rc29b"
        fi
        unset KILL_SSH_TRUST_DRIFT_TEST_PATH
        KILL_SSH_ALLOW_DRIFT=0

        rm -rf "$_t_dir"
        printf '\n'
        printf 'P1 tests: %d/%d passed\n' "$_t_pass" $(( _t_pass + _t_fail ))
        if (( _t_fail > 0 )); then
            exit 1
        fi
        exit 0
    fi
    return 0 2>/dev/null || exit 0
fi

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
