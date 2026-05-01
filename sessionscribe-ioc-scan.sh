#!/bin/bash
#
##
# sessionscribe-ioc-scan.sh v1.3.0
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
###############################################################################
# sessionscribe-ioc-scan.sh
#
# DISCLAIMER / USE AT YOUR OWN RISK
#   This script is provided as-is, without warranty of any kind, express or
#   implied. The authors accept no responsibility for any loss, damage,
#   downtime, or service impact arising from use, misuse, or modification of
#   this script. The validator is read-only by design, but you are solely
#   responsible for verifying suitability before running it on production
#   hosts and for interpreting its output. Validate against your own
#   change-control process.
###############################################################################
#
# ============================================================================
# Researcher credits
# ============================================================================
#
# Two surfaces under the cPanel/WHM auth-bypass disclosure cluster (2026-04-28):
#
#   CVE-2026-41940 (SessionScribe)
#     Researcher: Sina Kheirkhah (@SinSinology) / watchTowr Labs.
#     Public PoC: github.com/watchtowrlabs/watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py
#     Surface: unauthenticated session forgery via CRLF injection into the
#     password field of a preauth session. Outcome: full root.
#     Detected here via session-store IOC scan, multi-line `pass=` heuristic,
#     and code-state fingerprints (version, Perl modules, cpsrvd binary).
#
#   WhmScribe-A
#     Researcher: Ryan MacDonald, Nexcess Engineering <rmacdonald@nexcess.net>
#                 Ryan MacDonald, rfxn | forged in prod | <ryan@rfxn.com>
#     Surface: Authorization: WHM <user>:<token> commits username to the
#     access_log identity slot before token validation. ACL gate holds -
#     bounded to log-level identity injection (no privilege escalation).
#     Surfaced here by the localhost-marker check (logged user=root with no
#     auth) when --probe is passed.
#
# ============================================================================
#
# On-host validator for SessionScribe (CVE-2026-41940) - the 2026-04-28
# cPanel/WHM unauthenticated session-forgery bypass (vendor KB 40073787579671).
#
# Primitive: an attacker mints a preauth session, strips the ,<obhex> ob_part
# from the cookie, and sends Authorization: Basic <base64(user:CRLF-laced-pw)>
# against any URL. cpsrvd's saveSession() writes the multi-line password
# verbatim into the session file (the encoder short-circuits when ob_part is
# missing), promoting attacker-supplied key=value lines into authenticated
# session attributes. A follow-up /scripts2/listaccts propagates raw -> cache;
# the leaked /cpsess<token> from the 307 Location header is then root.
#
# Local-only design: assumes shell access on the cPanel host. Converging
# signals from version metadata, Perl module patterns, the cpsrvd binary,
# and the on-disk session/log stores. Vendor's published session IOCs are
# folded in alongside a multi-line-pass detector and a CVE-2026-41940
# co-occurrence fingerprint. Companion remote detection probe ships as
# sessionscribe-remote-probe.sh.
#
# Output styles:
#   default     ANSI sectioned report on stderr; stdout empty
#   --output    write structured JSON to FILE (also prints sectioned report)
#   --jsonl     stream one JSON signal per line on stdout (suppresses sectioned)
#   --csv       one summary row per host on stdout (suppresses sectioned)
#   --quiet     suppress sectioned report
#
# Verdict axes (independent):
#   code_verdict  PATCHED / VULNERABLE / INCONCLUSIVE   - derived from version,
#                 Perl patterns, cpsrvd binary fingerprint
#   host_verdict  CLEAN / SUSPICIOUS / COMPROMISED      - derived from session
#                 IOC scan (vendor + CVE-2026-41940 ladder) and access-log scan.
#                 Sessions tagged with the companion probe's canary attribute
#                 are bucketed as PROBE_ARTIFACT and do NOT escalate to
#                 COMPROMISED.
#
# Exit codes (highest priority wins):
#   0  PATCHED  + CLEAN
#   1  VULNERABLE                       (code-state vulnerable)
#   2  INCONCLUSIVE
#   3  Tool error (bad args, missing dependencies)
#   4  COMPROMISED                      (host-state IOC hit; overrides 0/1/2 -
#                                        a patched host can still be compromised
#                                        from prior exploitation)
#
# Usage:
#   bash sessionscribe-ioc-scan.sh                                       # report only (default)
#   bash sessionscribe-ioc-scan.sh --probe                               # + localhost marker GET
#   bash sessionscribe-ioc-scan.sh --since 90                            # narrow log/heuristic to 90d
#   bash sessionscribe-ioc-scan.sh -o /root/sessionscribe-scan.json --jsonl  # JSON file + JSONL stream
#
# Fleet (Ansible/Salt/SSH wrap of local mode):
#   ansible -i hosts all -m script -a 'sessionscribe-ioc-scan.sh --jsonl --quiet'
#   pdsh -w cpanel-fleet 'bash -s' < sessionscribe-ioc-scan.sh

set -u

###############################################################################
# Constants - vendor patch cutoffs and signal definitions
###############################################################################

VERSION="1.4.0"

# Vendor patched-build cutoff per tier (cPanel KB 40073787579671). Tier 130
# moved from "no in-place patch" to patched (11.130.0.18) in the post-disclosure
# advisory revision. WP Squared product line: separate patch at build 136.1.7.
PATCHED_TIERS_KEYS=(110 118 126 130 132 134 136)
PATCHED_TIERS_VALS=(97  63  54  18  29  20  5)

# Tiers explicitly excluded from the vendor patch list. In-place patch
# unavailable; hosts must be upgraded to a patched tier.
UNPATCHED_TIERS="112 114 116 120 122 124 128"

# cpsrvd ACL machinery strings - present (>=8 unique) in patched cpsrvd,
# absent (0) in vulnerable cpsrvd we examined.
ACL_STRINGS_PATTERN='init_acls|checkacl|clear_acls|filter_acls|_dynamic_acl_update|acls_are_initialized|load_dynamic_acl_cache_if_current|_get_dynamic_acl_lists|get_default_acls|Whostmgr::ACLS'

# Automated user-agent pattern for the IOC log scan. Loose-match any of these
# on /json-api/* against cpsrvd ports.
IOC_AUTOMATED_UA='python-requests|^curl/|Go-http-client|libwww-perl|aiohttp|okhttp|httpx'

# cpsrvd ports that the WebPros-published IOC pattern landed on.
CPSRVD_PORT_RE='^(2082|2083|2086|2087|2095|2096)$'

# UA used by the marker probe (--probe). Distinctive so an IDS / log search
# can identify the validator's own traffic.
PROBE_UA='sessionscribe-validator/'"$VERSION"' (local marker; not an exploit)'

# Probe-collateral marker. The companion sessionscribe-remote-probe.sh tags
# every forged session with `nxesec_canary_<nonce>=1` so operators can
# distinguish probe artifacts from real exploitation. Sessions matching this
# attribute are bucketed as PROBE_ARTIFACT and do NOT escalate host_verdict.
PROBE_CANARY_PAT='^nxesec_canary_[A-Za-z0-9]+='

# Length floor for a legitimate `pass=` field. Patched format is
# `pass=no-ob:<hex>` (>=14 chars); pre-patch encoder output is similar length.
# Forgery cleartext like `pass=x` is single-digit. Anything below this floor
# combined with successful_*_auth_with_timestamp is treated as forgery evidence.
PASS_FORGERY_MAX_LEN=12

# Probe-traffic exclusion. Both the local-marker probe (this script) and the
# remote probe (sessionscribe-remote-probe.sh) emit distinctive UAs so their
# own access-log entries don't get mistaken for attacker traffic by --chain-
# forensic or the attacker-IP cross-check. Updated when probe UAs change.
PROBE_UA_RE='sessionscribe-validator|nxesec-cve-2026-41940-probe'

###############################################################################
# Destruction-stage IOCs (Patterns A-G). Cheap host-state probes - bounded
# stat / hash / grep checks suitable for fleet triage. Heavyweight kill-chain
# reconstruction lives in sessionscribe-forensic.sh; this set just answers
# "does this host carry visible compromise residue?"
#
# Last updated from incident dossier: 2026-05-01.
###############################################################################

# Pattern A - .sorry encryptor + qTox ransom note. Encryptor masquerades as
# /root/sshd; sha256 from VirusTotal sample. C2 IP (68.183.190.253) lives
# in ATTACKER_IPS below for log cross-reference.
PATTERN_A_BINARY="/root/sshd"
PATTERN_A_SHA256="2fc0a056fd4eff5d31d06c103af3298d711f33dbcd5d122cae30b571ac511e5a"

# Pattern B - DB wipe + index.html BTC note. BTC address is the one stable
# fingerprint across all observed drops (the per-user note iterates with the
# attacker's reseller harvest). mysql wipe = /var/lib/mysql/mysql directory
# removed but /var/lib/mysql kept (DB engine fails to start).
PATTERN_B_BTC_ADDR="bc1q9nh4revv6yqhj2gc5usncrpsfnh7ypwr9h0sp2"
PATTERN_B_MYSQL_DIR="/var/lib/mysql"
PATTERN_B_MYSQL_DB="/var/lib/mysql/mysql"

# Pattern C - Mirai/nuclear.x86 botnet drop. Dropper deletes binary after
# launch; the literal string survives in shell history. C2 host signal is
# independent (in case the binary was renamed). C2 IP (87.121.84.78) is in
# ATTACKER_IPS below.
PATTERN_C_BIN="nuclear.x86"
PATTERN_C_C2_HOST="raw.flameblox.com"

# Pattern D - WHM JSON-API recon + reseller-as-persistence. The sptadm
# reseller, exploit.local contact, and 4ef72197.cpx.local domain are the
# universal fingerprints across host.graceworkz.com and the cohort. The
# WHM_FullRoot API token they create persists post-patch unless revoked,
# so a clean host_verdict isn't enough - this string in accounting.log
# means the attacker had root via API token at some point.
PATTERN_D_RESELLER="sptadm"
PATTERN_D_DOMAIN="4ef72197.cpx.local"
PATTERN_D_EMAIL="a@exploit.local"
PATTERN_D_TOKEN_NAME="WHM_FullRoot"

# Pattern E - websocket/Shell access-log signature. The 24x80 dimension is
# the script-kiddie automated default; 24x120 has been seen too. The path
# pattern (cpsess token + /websocket/Shell) is what matters.
PATTERN_E_WS_RE='GET /cpsess[0-9]+/websocket/Shell'

# Pattern F - automated harvester wrap. The __S_MARK__/__E_MARK__ envelope
# is a strong actor fingerprint; only a single grep needed across bash
# histories to confirm the same toolchain ran.
PATTERN_F_S_MARK="__S_MARK__"
PATTERN_F_E_MARK="__E_MARK__"

# Pattern G - SSH key persistence. Suspect keys appear with mtime forged
# to 2019-12-13 12:59:16 but a recent atime (Apr-May 2026). They masquerade
# as LW-internal keys with IP-labeled comments. Real LW provisioning keys
# carry "Parent Child key for <PJID>" comments - anything else in roots
# /etc/, /var/spool/cron/ is a candidate.
PATTERN_G_FORGED_MTIME="2019-12-13"
SSH_KEY_FILES=(
    "/root/.ssh/authorized_keys"
    "/root/.ssh/authorized_keys2"
)

# Attacker source IPs consolidated from the IC-5790 dossier (2026-05-01).
# Roles: badpass exploit, JSON-API enum, websocket Shell, TLS/HTTP probes,
# C2/dropper. Some are blackholed; we still want to count log hits as a
# late-stage signal in case rotation didn't take. Operators with internal
# scan boxes can suppress hits via --exclude-ip CIDR.
ATTACKER_IPS=(
    68.233.238.100   206.189.2.13     137.184.77.0     38.146.25.154
    157.245.204.205  192.81.219.190   149.102.229.144  94.231.206.39
    45.82.78.104     68.183.190.253   87.121.84.78     96.30.39.236
)

###############################################################################
# Argument parsing
###############################################################################

PROBE=0
OUTPUT_FILE=""
JSONL=0
CSV=0
QUIET=0
NO_COLOR=0
NO_LOGS=0
NO_SESSIONS=0
IOC_ONLY=0
TIMEOUT=8
ROOT_OVERRIDE=""
VERSION_OVERRIDE=""
CPSRVD_OVERRIDE=""
SINCE_DAYS=""            # default: no time filter - scan all retained logs/sessions
SINCE_EPOCH=""           # computed from SINCE_DAYS at parse time

# Destruction-IOC scan (Patterns A-G). Cheap host-state probes; default ON
# because the late-stage payload may be all that survives if initial-access
# sessions have rotated out of /var/cpanel/sessions/raw/.
NO_DESTRUCTION_IOCS=0

# Run ledger. /var/cpanel/sessionscribe-ioc/ holds an append-only JSONL
# of every run plus a per-run JSON envelope. Default ON so operators get
# local history without an aggregator; --no-ledger opts out for paranoid
# runs that must leave no host residue. Sibling to sessionscribe-mitigate's
# /var/cpanel/sessionscribe-mitigation/ - both stay under /var/cpanel/
# so cpanel-tool state is co-located.
NO_LEDGER=0
LEDGER_DIR_DEFAULT="/var/cpanel/sessionscribe-ioc"
LEDGER_DIR=""            # resolved at run time; --ledger-dir overrides

# Optional syslog one-liner for SIEM ingestion. Off by default.
SYSLOG=0

# --chain-forensic: when host_verdict != CLEAN, exec sessionscribe-forensic.sh
# with the same RUN_ID for correlation. Default off; opt-in only.
CHAIN_FORENSIC=0

# --exclude-ip CIDR (repeatable). Suppress attacker-IP cross-ref hits from
# operator scan boxes / known-good IR sources.
declare -ga EXCLUDE_IPS=()

usage() {
    cat <<'EOF'
Usage: bash sessionscribe-ioc-scan.sh [OPTIONS]

Scan options:
      --probe                Send a single marker GET to 127.0.0.1:2087
                             (does not attempt the bypass - confirms cpsrvd
                             is responsive and access logs are flowing).
      --no-logs              Skip access-log IOC scan.
      --no-sessions          Skip session-store IOC + anomaly scan.
      --no-destruction-iocs  Skip destruction-stage probes (Patterns A-G:
                             /root/sshd encryptor, mysql-wipe, BTC index,
                             nuclear.x86, sptadm reseller, __S_MARK__
                             harvester, suspect SSH keys). Use for the
                             original-shape ioc-scan triage when only
                             session/log signals are wanted.
      --ioc-only             Run only the host-state IOC scans (logs +
                             sessions + destruction probes + optional
                             marker probe). Skip version, static-pattern,
                             and cpsrvd-binary code-state checks. The
                             code_verdict is reported as SKIPPED; the exit
                             code reflects host_verdict only. Useful for
                             periodic post-patch sweeps.
      --exclude-ip CIDR      Suppress attacker-IP cross-ref hits for this
                             address (single IP only - no CIDR mask
                             matching). Repeatable. Use for operator scan
                             boxes / known-good IR sources.
      --since DAYS           Limit log + session-anomaly scans to last N days.
                             Default: no filter (scan all retained data).
                             Vendor session IOCs (token-injection / preauth-
                             extauth / tfa / multiline-pass) always scan the
                             full /var/cpanel/sessions/raw/ regardless.

Snapshot-testing overrides (offline forensics on extracted tarballs):
      --root DIR             Override /usr/local/cpanel.
      --version-string S     Override `cpanel -V` output.
      --cpsrvd-path P        Override cpsrvd binary path.

Output:
  -o, --output FILE          Write structured output to FILE. Format follows
                             the streaming flag in effect: CSV when --csv
                             is set, JSON otherwise (default).
      --jsonl                Stream JSONL on stdout (one signal per line,
                             each prefixed with host=<fqdn> for fleet
                             aggregation). Suppresses sectioned report.
      --csv                  Stream per-host summary CSV on stdout (one
                             header row + one data row). Designed for fleet
                             roll-up: pipe many hosts through `awk 'NR==1
                             || FNR>1'` or import into SQL/Excel. Mutually
                             exclusive with --jsonl. Suppresses sectioned
                             report.
      --quiet                Suppress sectioned report.
      --no-color             Disable ANSI color codes.

Run ledger (default ON):
      --no-ledger            Skip the /var/cpanel/sessionscribe-ioc/ run
                             ledger. Use on hosts where you must not
                             leave residue.
      --ledger-dir DIR       Override default ledger directory
                             (/var/cpanel/sessionscribe-ioc/).
      --syslog               Emit a one-line summary via logger -t
                             sessionscribe-ioc -p auth.notice on completion.

Forensic chaining:
      --chain-forensic       After scan, if host_verdict != CLEAN, exec
                             sessionscribe-forensic.sh with
                             --since/--no-color/--quiet inherited and a
                             shared RUN_ID. Resolution order: (1) sibling
                             of this script, (2) PATH, (3) GitHub raw
                             (rfxn/cpanel-sessionscribe@main), (4) CDN
                             (sh.rfxn.com). Forensic exit code is
                             reported as a chain.forensic_exit signal
                             but does not override this script's
                             exit code.

Misc:
      --timeout N            Probe timeout in seconds (default 8).
  -h, --help                 Show this help.

Exit codes: 0=PATCHED+CLEAN, 1=VULNERABLE, 2=INCONCLUSIVE, 3=tool error,
            4=COMPROMISED (host IOC hit - overrides patch verdict).
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --probe)              PROBE=1; shift ;;
        -o|--output)          OUTPUT_FILE="$2"; shift 2 ;;
        --jsonl)              JSONL=1; shift ;;
        --csv)                CSV=1; shift ;;
        --quiet)              QUIET=1; shift ;;
        --no-color)           NO_COLOR=1; shift ;;
        --no-logs)            NO_LOGS=1; shift ;;
        --no-sessions)        NO_SESSIONS=1; shift ;;
        --no-destruction-iocs) NO_DESTRUCTION_IOCS=1; shift ;;
        --ioc-only|--iocs-only) IOC_ONLY=1; shift ;;
        --since)              SINCE_DAYS="$2"; shift 2 ;;
        --exclude-ip)         EXCLUDE_IPS+=("$2"); shift 2 ;;
        --no-ledger)          NO_LEDGER=1; shift ;;
        --ledger-dir)         LEDGER_DIR="$2"; shift 2 ;;
        --syslog)             SYSLOG=1; shift ;;
        --chain-forensic)     CHAIN_FORENSIC=1; shift ;;
        --root)               ROOT_OVERRIDE="$2"; shift 2 ;;
        --version-string)     VERSION_OVERRIDE="$2"; shift 2 ;;
        --cpsrvd-path)        CPSRVD_OVERRIDE="$2"; shift 2 ;;
        --timeout)            TIMEOUT="$2"; shift 2 ;;
        -h|--help)            usage ;;
        *) echo "Unknown option: $1" >&2; echo "Try --help" >&2; exit 3 ;;
    esac
done

# --csv and --jsonl both want stdout - mutual exclusion.
if (( CSV && JSONL )); then
    echo "Error: --csv and --jsonl both stream to stdout; pick one." >&2
    exit 3
fi

# Compute --since cutoff from days-back if requested.
if [[ -n "$SINCE_DAYS" ]]; then
    if ! [[ "$SINCE_DAYS" =~ ^[0-9]+$ ]]; then
        echo "Error: --since requires a positive integer (days)" >&2; exit 3
    fi
    SINCE_EPOCH=$(( $(date -u +%s) - SINCE_DAYS * 86400 ))
fi

# RUN_ID: <epoch>-<pid>. Mirrors sessionscribe-mitigate.sh convention so
# chained ioc->forensic outputs and operator log greps line up. Inherits
# from SESSIONSCRIBE_RUN_ID env if set (chain entry from another wrapper).
TS_EPOCH=$(date -u +%s)
RUN_ID="${SESSIONSCRIBE_RUN_ID:-${TS_EPOCH}-$$}"

# Resolve ledger directory once - --ledger-dir wins, otherwise default.
[[ -z "$LEDGER_DIR" ]] && LEDGER_DIR="$LEDGER_DIR_DEFAULT"

# Streaming output formats own stdout; suppress the sectioned report (which
# the say/sayf/section helpers would otherwise emit on stderr) so the run
# stays machine-readable end-to-end.
if (( JSONL || CSV )); then QUIET=1; fi

# High-level host gate: /var/cpanel is the canonical cPanel state directory.
# Its absence means we're not on a cPanel/WHM host. Bail before doing anything
# that would emit confusing "no log dir / no cpsrvd / no sessions" boilerplate.
# Snapshot/offline forensic runs use --root / --version-string / --cpsrvd-path
# to override; in that case, skip the gate (the operator opted in explicitly).
if [[ -z "${ROOT_OVERRIDE}${VERSION_OVERRIDE}${CPSRVD_OVERRIDE}" ]] \
   && [[ ! -d /var/cpanel ]]; then
    echo "Error: /var/cpanel not found - this host does not appear to run cPanel/WHM." >&2
    echo "       For offline snapshot forensics use --root / --version-string / --cpsrvd-path." >&2
    exit 3
fi

###############################################################################
# Color and logging
###############################################################################

if (( NO_COLOR )) || [[ ! -t 2 ]]; then
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
else
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
fi

# All decorative output goes to stderr; stdout is reserved for JSONL.
say() {  (( QUIET )) || printf '%s\n' "$*" >&2; }
sayf() { (( QUIET )) || printf "$@" >&2; }
section() { (( QUIET )) || printf '\n %s━━━ %s%s\n\n' "$BOLD" "$1" "$NC" >&2; }
banner() {
    (( QUIET )) && return
    printf '\n %ssessionscribe-ioc-scan%s v%s - SessionScribe / CVE-2026-41940 local IR\n' "$BOLD" "$NC" "$VERSION" >&2
    printf ' host: %s    ts: %s\n' "$HOSTNAME_FQDN" "$TS_ISO" >&2
    if [[ -n "$SINCE_EPOCH" ]]; then
        printf ' lookback: %s days (since %s)\n' "$SINCE_DAYS" \
            "$(date -u -d @"$SINCE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)" >&2
    else
        printf ' lookback: unlimited (all retained logs/sessions)\n' >&2
    fi
}

###############################################################################
# Signal accumulator
#
# Each signal is one line in the SIGNALS array, fields tab-delimited:
#   area<TAB>id<TAB>severity<TAB>key<TAB>weight<TAB>jsonkv
# jsonkv is a comma-separated list of "key":"value" pairs already JSON-escaped.
###############################################################################

declare -ga SIGNALS=()

# JSON-escape an arbitrary string for embedding in JSON values.
# Handles \, ", \n, \r, \t, and control chars.
json_esc() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Build a JSON kv fragment from var=value pairs (positional after the 5 fixed
# fields). Caller passes pairs as: key value key value ...
build_jsonkv() {
    local first=1 k v
    while (( $# >= 2 )); do
        k="$1"; v="$2"; shift 2
        (( first )) || printf ','
        first=0
        printf '"%s":"%s"' "$(json_esc "$k")" "$(json_esc "$v")"
    done
}

# severity ∈ {info, evidence, strong, warning, error}
# Each JSONL line is prefixed with "host":"<fqdn>" so fleet aggregators can
# attribute every signal to a source host without joining against an enclosing
# envelope. The same prefix is added to every entry in the structured JSON
# file's signals[] array (write_json) for the same reason.
emit() {
    local area="$1" id="$2" severity="$3" key="$4" weight="$5"; shift 5
    local jsonkv; jsonkv=$(build_jsonkv "$@")
    SIGNALS+=("${area}"$'\t'"${id}"$'\t'"${severity}"$'\t'"${key}"$'\t'"${weight}"$'\t'"${jsonkv}")
    print_signal_human "$area" "$id" "$severity" "$key" "$@"
    if (( JSONL )); then
        printf '{"host":"%s","run_id":"%s","area":"%s","id":"%s","severity":"%s","key":"%s","weight":%s%s}\n' \
            "$HOSTNAME_JSON" "$RUN_ID" "$area" "$id" "$severity" "$key" "${weight:-0}" \
            "${jsonkv:+,${jsonkv}}"
    fi
}

# Map (severity, key) → (icon, color) for human-readable rows.
# "good info" keys (patched_per_build, pattern_fixed, ...) get a check.
print_signal_human() {
    (( QUIET )) && return
    local area="$1" id="$2" severity="$3" key="$4"; shift 4
    local icon color note=""
    case "$severity" in
        strong)   icon="✗"; color="$RED" ;;
        evidence) icon="!"; color="$YELLOW" ;;
        warning)  icon="⚠"; color="$YELLOW" ;;
        advisory) icon="⚐"; color="$CYAN" ;;
        error)    icon="X"; color="$RED" ;;
        info)
            case "$key" in
                patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs)
                    icon="✓"; color="$GREEN" ;;
                *) icon="·"; color="$DIM" ;;
            esac
            ;;
        *) icon=" "; color="$DIM" ;;
    esac

    # Pull a note out of the kv pairs for inline display
    while (( $# >= 2 )); do
        if [[ "$1" == note ]]; then note="$2"; fi
        shift 2
    done

    if [[ -n "$note" ]]; then
        printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$note" "$NC" >&2
    else
        printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$key" "$NC" >&2
    fi
}

###############################################################################
# Local-mode checks
###############################################################################

# Defaults for local paths (overridable via --root / --cpsrvd-path).
# Snapshot/offline runs use --root and stay confined to that root - no
# fallback to live-host /usr/local/cpanel.
local_init() {
    CPANEL_ROOT="${ROOT_OVERRIDE:-/usr/local/cpanel}"
    if [[ -n "$CPSRVD_OVERRIDE" ]]; then
        CPSRVD_BIN="$CPSRVD_OVERRIDE"
    elif [[ -f "${CPANEL_ROOT}/cpsrvd" ]]; then
        CPSRVD_BIN="${CPANEL_ROOT}/cpsrvd"
    else
        CPSRVD_BIN=""
    fi
}

# ---- version --------------------------------------------------------------
check_version() {
    section "Version"
    local raw=""
    if [[ -n "$VERSION_OVERRIDE" ]]; then
        raw="$VERSION_OVERRIDE"
    elif [[ -x "${CPANEL_ROOT}/cpanel" ]]; then
        raw=$("${CPANEL_ROOT}/cpanel" -V 2>&1 | head -1)
    elif [[ -f "${CPANEL_ROOT}/version" ]]; then
        raw=$(< "${CPANEL_ROOT}/version")
    elif [[ -f "${CPANEL_ROOT}/../meta/cpanel-version-raw.txt" ]]; then
        # Snapshot layout
        raw=$(< "${CPANEL_ROOT}/../meta/cpanel-version-raw.txt")
    else
        emit "version" "version_detect" "error" "no_cpanel_binary" 0 \
             "note" "No cpanel binary or version file under ${CPANEL_ROOT}"
        return
    fi

    local tier="" build=""
    if [[ "$raw" =~ ([0-9]{2,3})\.0[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        tier="${BASH_REMATCH[1]}"; build="${BASH_REMATCH[2]}"
    elif [[ "$raw" =~ (11\.)?([0-9]{2,3})\.0\.([0-9]+) ]]; then
        tier="${BASH_REMATCH[2]}"; build="${BASH_REMATCH[3]}"
    fi

    if [[ -z "$tier" || -z "$build" ]]; then
        emit "version" "version_detect" "error" "unparseable" 0 \
             "raw" "$raw"
        return
    fi

    emit "version" "version_detect" "info" "detected" 0 \
         "version" "${tier}.0.${build}" "tier" "$tier" "build" "$build" "raw" "$raw"

    # Classify
    if (( tier < 110 )); then
        emit "version" "tier_class" "strong" "vulnerable_eol" 5 \
             "tier" "$tier" "note" "Pre-LTS - no vendor patch will be issued. Migrate or decommission."
        return
    fi
    if [[ " $UNPATCHED_TIERS " == *" $tier "* ]]; then
        emit "version" "tier_class" "strong" "vulnerable_no_vendor_patch" 5 \
             "tier" "$tier" \
             "note" "Tier excluded from vendor patch list. In-place patch unavailable - must upgrade tier."
        return
    fi
    if (( tier % 2 == 1 )); then
        emit "version" "tier_class" "warning" "dev_tier" 0 \
             "tier" "$tier" "note" "Odd-major dev/EDGE tier; not in vendor patch list."
        return
    fi
    # Lookup cutoff
    local i cutoff=""
    for i in "${!PATCHED_TIERS_KEYS[@]}"; do
        if [[ "${PATCHED_TIERS_KEYS[$i]}" == "$tier" ]]; then
            cutoff="${PATCHED_TIERS_VALS[$i]}"; break
        fi
    done
    if [[ -z "$cutoff" ]]; then
        emit "version" "tier_class" "warning" "cutoff_unknown" 0 \
             "tier" "$tier" "note" "No published cutoff for this tier - verify manually."
        return
    fi
    if (( build >= cutoff )); then
        emit "version" "tier_class" "info" "patched_per_build" 5 \
             "tier" "$tier" "build" "$build" "cutoff" "$cutoff" \
             "note" "${tier}.0.${build} ≥ vendor cutoff ${tier}.0.${cutoff}"
    else
        emit "version" "tier_class" "strong" "vulnerable_per_build" 5 \
             "tier" "$tier" "build" "$build" "cutoff" "$cutoff" \
             "note" "${tier}.0.${build} < vendor cutoff ${tier}.0.${cutoff}"
    fi
}

# ---- static patterns -------------------------------------------------------
# Parallel arrays - pipe delimiter would collide with | inside regex alternations.
STATIC_IDS=(
    'alg_length_optrec_bug'
    'start_authorize_in_die'
    'service_name_fallback'
    'session_no_ob_branch'
    'session_hex_decode_only'
    'accessids_normalize_die_usernotfound'
    'comet_state_bypass_branch'
    'cve_41940_set_pass_crlf_strip'
)
STATIC_FILES=(
    'Cpanel/Security/Authn/Provider/OpenIdConnectBase.pm'
    'Cpanel/Security/Authn/Provider/OpenIdConnectBase.pm'
    'Cpanel/Security/Authn/Provider/OpenIdConnectBase.pm'
    'Cpanel/Session/Load.pm'
    'Cpanel/Session/Encoder.pm'
    'Cpanel/AccessIds/Normalize.pm'
    'Cpanel/Server/Handlers/OpenIdConnect.pm'
    'Cpanel/Session.pm'
)
STATIC_VULN_PATS=(
    'if[[:space:]]*![[:space:]]*length[[:space:]]+\$algorithm[[:space:]]*>[[:space:]]*2'
    '\[[[:space:]]*\$self->start_authorize\(\)[[:space:]]*,[[:space:]]*\$self->\{.client.\}->errstr'
    ''
    ''
    ''
    ''
    ''
    ''
)
STATIC_FIXED_PATS=(
    'if[[:space:]]+length[[:space:]]+\$algorithm[[:space:]]*<=[[:space:]]*2'
    '\[[[:space:]]*.\$self->(get_access_token|refresh_access_token)\(\).[[:space:]]*,[[:space:]]*\$self->\{.client.\}->errstr'
    '\$service_name[[:space:]]*\|\|=[[:space:]]*\$self->\{.service_name.\}'
    '\$session_ref->\{.pass.\}[[:space:]]*=~[[:space:]]*s/\^no-ob:'
    'sub[[:space:]]+hex_decode_only'
    'die[[:space:]]+Cpanel::Exception::create\([[:space:]]*.UserNotFound.'
    'comet_backup_license_verification'
    'tr/[^/]*\\r[^/]*\\n[^/]*//[a-z]*|tr/[^/]*\\n[^/]*\\r[^/]*//[a-z]*|s/\[[^]]*\\[rn][^]]*\]//[a-z]*|s/\\r/[^/]*/[a-z]*[[:space:]]*[;}].*s/\\n/[^/]*/[a-z]*'
)
# Pattern kind: 'bug' = a real ancillary bug surfaced as advisory when unpatched
#               'marker' = build-line patch marker, informational only.
# None of these patterns are the load-bearing fix itself - that lives in the
# patched cpsrvd binary's compiled logic. The cve_41940_set_pass_crlf_strip
# marker IS the CVE-2026-41940 fix in source: set_pass() / saveSession() now
# strips \r and \n in addition to NUL.
STATIC_KINDS=(bug bug marker marker marker marker marker marker)
STATIC_EXPLAINS=(
    'OpenIdConnectBase.pm:795 operator-precedence trap (`if !length $algorithm > 2` is always false). Pre-existing OIDC bug, NOT the SessionScribe primitive; post-auth defense-in-depth, fixed on the 134-line and not backported to 110/118/126/132. Resolves on tier upgrade.'
    'OpenIdConnectBase.pm start_authorize() invoked inside a die() arg list mutates session-state on the error path. Pre-existing OIDC bug, NOT the SessionScribe primitive; post-auth oracle, fixed on the 134-line and not backported. Resolves on tier upgrade.'
    'Patched build adds the $service_name fallback in get_display_configuration().'
    'Patched session loader has the no-ob: prefix branch (WebPros plumbing).'
    'Patched encoder adds hex_decode_only / hex_encode_only methods (WebPros plumbing).'
    'Patched Normalize.pm dies with UserNotFound on missing uid (defense-in-depth).'
    'Patched handler contains the Comet-state branch (WebPros feature).'
    'CVE-2026-41940 source-level fix: Cpanel/Session.pm set_pass()/saveSession() now strips CR/LF from the pass field in addition to NUL. Absence on a sub-cutoff build means the host is vulnerable to the Authorization: Basic CRLF-injection chain.'
)

check_static() {
    section "Static patterns (ancillary; not primary CVE-2026-41940 verdict drivers)"
    local i id kind file vuln_pat fixed_pat explain fpath vhit fhit
    for i in "${!STATIC_IDS[@]}"; do
        id="${STATIC_IDS[$i]}"
        kind="${STATIC_KINDS[$i]}"
        file="${STATIC_FILES[$i]}"
        vuln_pat="${STATIC_VULN_PATS[$i]}"
        fixed_pat="${STATIC_FIXED_PATS[$i]}"
        explain="${STATIC_EXPLAINS[$i]}"
        fpath="${CPANEL_ROOT}/${file}"
        if [[ ! -f "$fpath" ]]; then
            emit "static" "$id" "info" "file_missing" 0 \
                 "file" "$file" "note" "file not present (may be a snapshot gap)"
            continue
        fi
        vhit=0; fhit=0
        if [[ -n "$vuln_pat" ]]  && grep -qE -- "$vuln_pat"  "$fpath" 2>/dev/null; then vhit=1; fi
        if [[ -n "$fixed_pat" ]] && grep -qE -- "$fixed_pat" "$fpath" 2>/dev/null; then fhit=1; fi

        case "$kind" in
            bug)
                # Real ancillary bug: surface as advisory when vuln form is
                # present and fixed form is absent. Never affects code_verdict.
                if (( vhit && ! fhit )); then
                    emit "static" "$id" "advisory" "ancillary_bug_unpatched" 0 \
                         "file" "$file" "note" "$explain"
                elif (( fhit && ! vhit )); then
                    emit "static" "$id" "info" "ancillary_bug_fixed" 0 \
                         "file" "$file" "note" "$explain"
                elif (( vhit && fhit )); then
                    emit "static" "$id" "warning" "pattern_both" 0 \
                         "file" "$file" "note" "Both vuln + fixed forms present - inspect manually."
                else
                    emit "static" "$id" "warning" "pattern_neither" 0 \
                         "file" "$file" "note" "Neither form found - file may have diverged from upstream."
                fi
                ;;
            marker)
                # Build-line patch marker: pure informational. Tells you
                # whether this build's Perl modules are on the modern (134-line)
                # tree or the older backport tree. Never affects verdicts and
                # never an advisory - its absence isn't actionable.
                if (( fhit )); then
                    emit "static" "$id" "info" "patch_marker_present" 0 \
                         "file" "$file" "note" "$explain"
                else
                    emit "static" "$id" "info" "patch_marker_absent" 0 \
                         "file" "$file" "note" "Marker not present (older Perl line; expected on 110/118/126/132 backport tiers)."
                fi
                ;;
        esac
    done
}

# ---- cpsrvd binary --------------------------------------------------------
check_binary() {
    section "cpsrvd binary"
    if [[ -z "$CPSRVD_BIN" || ! -f "$CPSRVD_BIN" ]]; then
        emit "binary" "cpsrvd_locate" "error" "cpsrvd_not_found" 0 \
             "note" "could not locate cpsrvd under ${CPANEL_ROOT}"
        return
    fi
    local size; size=$(stat -c%s "$CPSRVD_BIN" 2>/dev/null || echo 0)
    emit "binary" "cpsrvd_locate" "info" "cpsrvd_path" 0 \
         "path" "$CPSRVD_BIN" "size" "$size"

    if ! command -v strings >/dev/null 2>&1; then
        emit "binary" "acl_strings" "warning" "strings_missing" 0 \
             "note" "strings(1) not available - install binutils to enable this check"
        return
    fi

    # Field-observed limit on the binary fingerprint signal (2026-04-29):
    # on 134-tier, BOTH vulnerable (134.0.17) and patched (134.0.20) binaries
    # carry these strings - they entered via feature evolution before patch
    # release, not as part of the patch itself. So a nonzero strings count
    # CANNOT discriminate vuln from patched on 134+. The version-string check
    # is the authoritative verdict driver; the binary check is informational
    # only when strings are present.
    #
    # Surfaced signals:
    #   - both counts 0       → strong vuln evidence (very old / non-cpsrvd
    #                            binary; consistent with pre-130 vulnerable)
    #   - either count > 0    → informational only, no score impact (could
    #                            be patched OR vuln-on-newer-tier; defer to
    #                            version-string verdict)
    local strings_dump; strings_dump=$(mktemp /tmp/ssioc.strs.XXXXXX)
    strings -a -n 8 "$CPSRVD_BIN" 2>/dev/null > "$strings_dump"

    local acl_count token_count
    acl_count=$(grep -cE -- "$ACL_STRINGS_PATTERN" "$strings_dump" 2>/dev/null || true)
    token_count=$(grep -cE -- '_TOKENS_DIR|look_up_by_token|read_tokens|_token_object_class' "$strings_dump" 2>/dev/null || true)
    acl_count="${acl_count:-0}"; token_count="${token_count:-0}"
    rm -f "$strings_dump"

    if (( acl_count == 0 && token_count == 0 )); then
        emit "binary" "acl_strings" "strong" "acl_machinery_absent" 5 \
             "acl_count" "$acl_count" "token_count" "$token_count" \
             "note" "0 ACL + 0 token-reader strings - pre-130 vulnerable cpsrvd shape."
    else
        emit "binary" "acl_strings" "info" "acl_machinery_present_informational" 0 \
             "acl_count" "$acl_count" "token_count" "$token_count" \
             "note" "${acl_count} ACL + ${token_count} token-reader strings - informational only; on 134+ both vuln and patched binaries carry these. Defer to version-string verdict."
    fi
}

# ---- IOC log scan ---------------------------------------------------------
check_logs() {
    (( NO_LOGS )) && return
    section "IOC access-log scan"
    local logdir=/usr/local/cpanel/logs
    if [[ ! -d "$logdir" ]]; then
        emit "logs" "logs_dir" "info" "no_log_dir" 0 \
             "note" "no $logdir - skipping"
        return
    fi
    local total=0 hits_2xx=0 unique_ips=0
    local tmp; tmp=$(mktemp /tmp/ssioc.logs.XXXXXX)
    {
        [[ -f "$logdir/access_log" ]] && cat "$logdir/access_log"
        for f in "$logdir"/access_log-*; do
            [[ -f "$f" ]] || continue
            case "$f" in
                *.gz) zcat "$f" 2>/dev/null ;;
                *.xz) xzcat "$f" 2>/dev/null ;;
                *)    cat "$f" ;;
            esac
        done
    } | awk -v floor="${SINCE_EPOCH:-0}" -v ua_re="$IOC_AUTOMATED_UA" -v port_re="$CPSRVD_PORT_RE" '
        /\/json-api\// {
            # Apache combined log format. We need:
            #   $1 = ip ; $3 = user ; $4 = [date:time ; $7 = path ;
            #   $9 = status; UA from quoted field; port at $NF.
            if ($0 !~ /"GET[[:space:]]+\/json-api\//) next
            if ($0 !~ ua_re) next
            n = split($0, t, " ")
            user = t[3]; status = t[9]; port = t[n]
            if (port !~ port_re) next
            # Optional time filter: floor=0 means no filter.
            # cpanel access_log timestamp is [MM/DD/YYYY:HH:MM:SS ...] (NOT
            # Apache CLF DD/Mon/YYYY). m[1]=MM, m[2]=DD, m[3]=YYYY.
            if (floor > 0 && match($0, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
                ts = mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
                if (ts > 0 && ts < floor) next
            }
            print user "\t" status "\t" t[1] "\t" port "\t" $0
        }
    ' > "$tmp" 2>/dev/null

    total=$(wc -l < "$tmp" 2>/dev/null || echo 0)
    local window_note=""
    if [[ -n "$SINCE_EPOCH" ]]; then
        window_note=" (last ${SINCE_DAYS}d)"
    else
        window_note=" (all retained logs)"
    fi
    if (( total > 0 )); then
        hits_2xx=$(awk -F'\t' '$2 ~ /^2/' "$tmp" | wc -l)
        unique_ips=$(awk -F'\t' '{print $3}' "$tmp" | sort -u | wc -l)
        local sev="evidence"
        if (( hits_2xx > 0 )); then sev="strong"; fi
        emit "logs" "ioc_scan" "$sev" "ioc_hits" 4 \
             "count" "$total" "hits_2xx" "$hits_2xx" "unique_src_ips" "$unique_ips" \
             "note" "$total IOC-pattern hits$window_note ($hits_2xx returned 2xx)"
        # Process substitution (NOT a pipeline) so emit() updates the
        # parent shell's SIGNALS array. With `head | while` the loop body
        # runs in a subshell and array appends are silently dropped from
        # the JSON file output.
        local u st ip pt line trim
        while IFS=$'\t' read -r u st ip pt line; do
            trim="${line:0:200}"
            emit "logs" "ioc_sample" "info" "ioc_sample" 0 \
                 "ip" "$ip" "user" "$u" "status" "$st" "port" "$pt" "line" "$trim"
        done < <(head -5 "$tmp")
    else
        emit "logs" "ioc_scan" "info" "no_ioc_hits" 0 \
             "note" "no IOC-pattern hits in access logs${window_note}."
    fi
    rm -f "$tmp"

    # ---- attacker-IP cross-ref -------------------------------------------
    # Independent signal: count access_log hits from the consolidated
    # IC-5790 attacker IP list. Excludes probe-UA traffic and any
    # operator-supplied --exclude-ip values. A hit here doesn't imply
    # successful exploitation (the IP may have been blackholed before
    # request landed) but does mean the attacker reached this host.
    check_attacker_ips "$logdir"
}

# Cross-reference access_log against the dossier attacker-IP list. Pulled
# out of check_logs() to keep that function readable; called immediately
# after.
check_attacker_ips() {
    local logdir="$1"
    local atmp; atmp=$(mktemp /tmp/ssioc.aip.XXXXXX)
    {
        [[ -f "$logdir/access_log" ]] && cat "$logdir/access_log"
        for f in "$logdir"/access_log-*; do
            [[ -f "$f" ]] || continue
            case "$f" in
                *.gz) zcat "$f" 2>/dev/null ;;
                *.xz) xzcat "$f" 2>/dev/null ;;
                *)    cat "$f" ;;
            esac
        done
    } > "$atmp" 2>/dev/null
    # Build IP alternation. Escape dots so 1.2.3.4 only matches that literal.
    local ip ip_re=""
    for ip in "${ATTACKER_IPS[@]}"; do
        ip_re+="${ip_re:+|}${ip//./\\.}"
    done
    # Anchored to "^IP " so we don't match an IP buried inside a URL/UA.
    ip_re="^(${ip_re}) "
    # Build exclude-IP filter (post-grep awk so we don't have to recompile
    # the alternation when EXCLUDE_IPS is empty).
    local total_hits unique_attackers
    total_hits=$(grep -cE "$ip_re" "$atmp" 2>/dev/null)
    total_hits="${total_hits:-0}"
    if (( total_hits == 0 )); then
        rm -f "$atmp"
        return
    fi
    # Apply probe-UA exclusion + EXCLUDE_IPS filter via awk. The awk match
    # against ip_re replaces the second grep -c so we walk the file once.
    local filtered_count
    filtered_count=$(awk -v probe_re="$PROBE_UA_RE" \
                         -v ip_re="$ip_re" \
                         -v excludes="$(printf '%s\n' "${EXCLUDE_IPS[@]:-}")" '
        BEGIN {
            n = split(excludes, ex_arr, "\n")
            for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
            count = 0
        }
        $0 ~ probe_re      { next }
        $0 !~ ip_re        { next }
        { if (!($1 in ex)) count++ }
        END { print count + 0 }
    ' "$atmp")
    filtered_count="${filtered_count:-0}"
    if (( filtered_count > 0 )); then
        local sample
        sample=$(grep -E "$ip_re" "$atmp" 2>/dev/null \
                    | grep -vE "$PROBE_UA_RE" | head -1)
        emit "logs" "ioc_attacker_ip" "strong" \
             "ioc_attacker_ip_in_access_log" 8 \
             "count" "$filtered_count" "sample" "${sample:0:200}" \
             "note" "$filtered_count access_log hit(s) from IC-5790 attacker IPs (CRITICAL)."
    fi
    rm -f "$atmp"
}

# ---- session-store analyzer ----------------------------------------------
# Single awk pass over a session file. Sets SF_* globals describing the
# CVE-2026-41940-relevant attribute shape. One subprocess per file replaces
# 6+ greps; the awk reads the file once and emits structured key=value pairs
# the bash side parses with a single read loop.
analyze_session() {
    SF_TOKEN_DENIED=0; SF_CP_TOKEN=0; SF_BADPASS=0; SF_LEGIT_LOGIN=0
    SF_EXT_AUTH=0;     SF_INT_AUTH=0; SF_TFA=0;     SF_HASROOT=0
    SF_CANARY=0;       SF_ROOT_USER=0; SF_ACLLIST=0; SF_STRANDED=0
    SF_MALFORMED=0;    SF_MALFORMED_SAMPLE=""
    SF_PASS_COUNT=0;   SF_PASS_LEN=0
    SF_TD_VAL="";      SF_CP_VAL="";   SF_ORIGIN="";  SF_AUTH_TS=""

    local _k _v
    while IFS='=' read -r _k _v; do
        case "$_k" in
            token_denied)    SF_TOKEN_DENIED=$_v ;;
            td_val)          SF_TD_VAL=$_v ;;
            cp_token)        SF_CP_TOKEN=$_v ;;
            cp_val)          SF_CP_VAL=$_v ;;
            badpass_origin)  SF_BADPASS=$_v ;;
            legit_login)     SF_LEGIT_LOGIN=$_v ;;
            origin)          SF_ORIGIN=$_v ;;
            ext_auth_ts)     SF_EXT_AUTH=$_v ;;
            int_auth_ts)     SF_INT_AUTH=$_v ;;
            auth_ts_val)     SF_AUTH_TS=$_v ;;
            tfa)             SF_TFA=$_v ;;
            hasroot)         SF_HASROOT=$_v ;;
            probe_canary)    SF_CANARY=$_v ;;
            pass_count)      SF_PASS_COUNT=$_v ;;
            pass_len)        SF_PASS_LEN=$_v ;;
            stranded)        SF_STRANDED=$_v ;;
            malformed)       SF_MALFORMED=$_v ;;
            malformed_sample) SF_MALFORMED_SAMPLE=$_v ;;
            root_user)       SF_ROOT_USER=$_v ;;
            acllist)         SF_ACLLIST=$_v ;;
        esac
    done < <(awk -v canary_re="$PROBE_CANARY_PAT" '
        BEGIN { line_idx=0; pass_at=0; pass_count=0 }
        { line_idx++ }
        /^token_denied=/        { has_td=1;        td_val=substr($0,index($0,"=")+1) }
        /^cp_security_token=/   { has_cp=1;        cp_val=substr($0,index($0,"=")+1) }
        /^origin_as_string=/    {
            origin=substr($0,index($0,"=")+1)
            if (origin ~ /method=badpass/) has_badpass=1
            if (origin ~ /method=(handle_form_login|create_user_session|handle_auth_transfer)/) has_legit=1
        }
        /^successful_external_auth_with_timestamp=/ { has_ext=1; auth_ts=substr($0,index($0,"=")+1) }
        /^successful_internal_auth_with_timestamp=/ { has_int=1; auth_ts=substr($0,index($0,"=")+1) }
        /^tfa_verified=1/       { has_tfa=1 }
        /^hasroot=1/            { has_hasroot=1 }
        $0 ~ canary_re          { has_canary=1 }
        /^pass=/ {
            if (pass_count == 0) { pass_val=substr($0,index($0,"=")+1); pass_at=line_idx }
            pass_count++; next
        }
        pass_at > 0 && line_idx == pass_at + 1 && /./ && !/^[a-zA-Z_][a-zA-Z0-9_]*=/ { stranded=1 }
        # Broader malformed-line detector (per WebPros IOC-3): any non-blank
        # line that does not match key=value. cpsrvd serializes via
        # FlushConfig with `=` separator and a fixed _SESSION_PARTS key
        # whitelist (Cpanel/Server.pm:2216-2247), and Cpanel::Session::
        # filter_sessiondata strips \r\n from values - so legitimate
        # sessions cannot produce non-conforming lines. Any hit here is
        # injection footprint that bypassed those invariants.
        $0 != "" && $0 !~ /^[A-Za-z_][A-Za-z0-9_]*=/ {
            malformed=1
            if (malformed_sample == "") malformed_sample=substr($0,1,80)
        }
        /^(user|whm_user|user_id|cp_security_token_user)=root[[:space:]]*$/ { root_user=1 }
        /^(acllist|acl_list)=/  { has_acllist=1 }
        END {
            # neutralize stray CR/LF/TAB in values so they cannot break the
            # bash key=value parser downstream.
            gsub(/[\r\n\t]/, " ", td_val); gsub(/[\r\n\t]/, " ", cp_val)
            gsub(/[\r\n\t]/, " ", origin); gsub(/[\r\n\t]/, " ", auth_ts)
            gsub(/[\r\n\t]/, " ", malformed_sample)
            print "token_denied=" (has_td?1:0)
            print "td_val=" td_val
            print "cp_token=" (has_cp?1:0)
            print "cp_val=" cp_val
            print "badpass_origin=" (has_badpass?1:0)
            print "legit_login=" (has_legit?1:0)
            print "origin=" origin
            print "ext_auth_ts=" (has_ext?1:0)
            print "int_auth_ts=" (has_int?1:0)
            print "auth_ts_val=" auth_ts
            print "tfa=" (has_tfa?1:0)
            print "hasroot=" (has_hasroot?1:0)
            print "probe_canary=" (has_canary?1:0)
            print "pass_count=" (pass_count+0)
            print "pass_len=" length(pass_val)
            print "stranded=" (stranded?1:0)
            print "malformed=" (malformed?1:0)
            print "malformed_sample=" malformed_sample
            print "root_user=" (root_user?1:0)
            print "acllist=" (has_acllist?1:0)
        }
    ' "$1" 2>/dev/null)
}

# ---- access_log token-use cross-ref --------------------------------------
# When session-store IOCs detect a forged cp_security_token, this helper
# checks whether the same token was actually used in access_log with a
# 2xx response. A hit escalates the actionable shape from "session was
# forged" to "session was forged AND used" - meaningful for IR scoping
# (token revocation urgency, blast-radius assessment).
#
# Uses the same access_log root the rest of the script reads from. The
# closing-quote-then-status pattern ('" 2[0-9][0-9] ') is the apache
# combined-log marker for the request-line/status boundary - more
# robust than a bare " 200 " grep which would false-positive on IPs
# beginning with 200, response-byte-counts of 200, etc.
check_token_used() {
    local session_path="$1" token_val="$2" session_name="$3"
    local log=/usr/local/cpanel/logs/access_log
    [[ -f "$log" && -n "$token_val" ]] || return 1
    local hit
    hit=$(grep -aF -- "$token_val" "$log" 2>/dev/null \
            | grep -E '" 2[0-9][0-9] ' | head -1)
    [[ -z "$hit" ]] && return 1
    emit "sessions" "ioc_token_used_$session_name" "strong" \
         "ioc_injected_token_used_with_2xx" 10 \
         "path" "$session_path" "cp_security_token" "$token_val" \
         "access_log_line" "${hit:0:200}" \
         "note" "Injected security token observed in access_log with 2xx response - attacker successfully used the forged session (CRITICAL)."
    return 0
}

# ---- session-store IOC scan ----------------------------------------------
# Two-pass scan against /var/cpanel/sessions:
#   (a) IOC ladder over raw/   - deterministic forgery signals; no time bound
#                                (a stale forgery hit in 2-year-old session
#                                data is still a real hit).
#   (b) Heuristic over $d      - root-named sessions lacking expected authz
#                                fields. Time-bounded by --since because the
#                                anomalous-shape signal is lower confidence
#                                and only useful within an investigation window.
#
# Sessions tagged with the companion remote probe's canary attribute
# (nxesec_canary_<nonce>=1) are bucketed as PROBE_ARTIFACT and skipped from
# the IOC ladder - they are known test collateral, not exploitation.
check_sessions() {
    (( NO_SESSIONS )) && return
    section "Session-store IOC scan"
    local d=/var/cpanel/sessions
    if [[ ! -d "$d" ]]; then
        emit "sessions" "sess_dir" "info" "no_session_dir" 0 "note" "no $d"
        return
    fi
    local raw_dir="$d/raw" preauth_dir="$d/preauth"
    local scanned=0 ioc_hits=0 anomalous=0 probe_artifacts=0
    local f session_name preauth_file
    local now_epoch; now_epoch=$(date -u +%s 2>/dev/null || echo 0)

    # ---- (a) IOC ladder over raw/ ----------------------------------------
    if [[ -d "$raw_dir" ]]; then
        for f in "$raw_dir"/*; do
            [[ -f "$f" ]] || continue
            ((scanned++))
            session_name=$(basename "$f")
            preauth_file="$preauth_dir/$session_name"
            analyze_session "$f"

            # PROBE_ARTIFACT: known sessionscribe-remote-probe collateral.
            # Skip the IOC ladder; surface as a probe-artifact signal so
            # operators can clean up via the probe's --cleanup helper.
            if (( SF_CANARY )); then
                ((probe_artifacts++))
                emit "sessions" "probe_artifact_$session_name" "info" "probe_canary_session" 0 \
                     "path" "$f" \
                     "note" "Session tagged with sessionscribe-remote-probe canary - probe collateral, not exploitation evidence."
                continue
            fi

            # IOC-A: token_denied + cp_security_token co-occur. badpass-origin
            # variant is the exploit fingerprint; otherwise may be an expired
            # bookmark - downgrade to warning.
            if (( SF_TOKEN_DENIED && SF_CP_TOKEN )); then
                if (( SF_BADPASS )); then
                    emit "sessions" "ioc_token_inject_$session_name" "strong" \
                         "ioc_token_denied_with_badpass_origin" 10 \
                         "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                         "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                         "note" "Pre-auth session with attacker-injected security token (CRITICAL)."
                else
                    emit "sessions" "ioc_token_review_$session_name" "warning" \
                         "ioc_token_denied_with_cp_security_token" 0 \
                         "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                         "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                         "note" "token_denied + cp_security_token co-exist - review (may be expired bookmark)."
                fi
                ((ioc_hits++))
            fi

            # IOC-B: pre-auth-paired session with successful_*_auth_with_timestamp.
            # Both external (original PoC) and internal (watchtowr poc/poc_
            # watchtowr.py:35) variants are caught - cpsrvd's write_session
            # removes the preauth marker on auth promotion, so any session
            # carrying both is structurally impossible in a benign flow.
            if [[ -f "$preauth_file" ]] && (( SF_EXT_AUTH || SF_INT_AUTH )); then
                local _which="external"
                (( SF_INT_AUTH && ! SF_EXT_AUTH )) && _which="internal"
                (( SF_EXT_AUTH && SF_INT_AUTH ))   && _which="external+internal"
                emit "sessions" "ioc_preauth_extauth_$session_name" "strong" \
                     "ioc_preauth_with_auth_attribute" 10 \
                     "path" "$f" "preauth_path" "$preauth_file" "marker" "$_which" \
                     "note" "Pre-auth session carries successful_${_which}_auth_with_timestamp - injected (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-C: short pass= + successful_*_auth_with_timestamp. Replaces
            # the loose "any auth-timestamp present" detector. Legitimate pass=
            # is encoder output (`no-ob:<hex>` post-patch, hex-encoded ciphertext
            # pre-patch), always >>PASS_FORGERY_MAX_LEN chars. CRLF-injection
            # writes single-byte cleartext like `pass=x` because the basic-auth
            # password is consumed as the literal first line before the CRLF.
            # Short pass + injected timestamp is the canonical primitive shape.
            if (( (SF_INT_AUTH || SF_EXT_AUTH) && SF_PASS_LEN > 0 && SF_PASS_LEN <= PASS_FORGERY_MAX_LEN )); then
                emit "sessions" "ioc_short_pass_$session_name" "strong" \
                     "ioc_short_pass_with_auth_timestamp" 10 \
                     "path" "$f" "pass_len" "$SF_PASS_LEN" "auth_ts" "$SF_AUTH_TS" \
                     "note" "pass= length ${SF_PASS_LEN} (cleartext shape) co-occurs with successful_*_auth_with_timestamp - CVE-2026-41940 forgery primitive (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-D: structural multi-line pass= - duplicate pass= lines or
            # a stranded continuation line right after pass=. Catches sloppy
            # CRLF injection where the encoder write left detritus.
            if (( SF_PASS_COUNT > 1 || SF_STRANDED )); then
                emit "sessions" "ioc_multiline_pass_$session_name" "strong" \
                     "ioc_multiline_pass_value" 10 \
                     "path" "$f" "pass_count" "$SF_PASS_COUNT" "stranded" "$SF_STRANDED" \
                     "note" "Multi-line pass= structure (duplicate or stranded continuation) - CRLF injection artifact (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-E: badpass origin combined with ANY auth marker (per
            # WebPros code-path analysis: the badpass call site at
            # Cpanel/Server.pm:1244-1252 cannot legitimately set
            # successful_*_auth_with_timestamp, hasroot=1, or tfa_verified=1).
            # Catches any single-field injection that promotes the badpass
            # session, including watchtowr's internal_auth variant.
            if (( SF_BADPASS && (SF_EXT_AUTH || SF_INT_AUTH || SF_HASROOT || SF_TFA) )); then
                local _markers=""
                (( SF_EXT_AUTH )) && _markers+="${_markers:+,}ext_auth_ts"
                (( SF_INT_AUTH )) && _markers+="${_markers:+,}int_auth_ts"
                (( SF_HASROOT )) && _markers+="${_markers:+,}hasroot=1"
                (( SF_TFA ))     && _markers+="${_markers:+,}tfa_verified=1"
                emit "sessions" "ioc_badpass_authmarkers_$session_name" "strong" \
                     "ioc_badpass_with_auth_markers" 10 \
                     "path" "$f" "origin" "$SF_ORIGIN" "markers" "$_markers" \
                     "note" "method=badpass origin co-occurs with auth markers ($_markers) - badpass call site cannot set these legitimately (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-E2: high-confidence 4-way co-occurrence. The canonical
            # exploit shape sets hasroot=1 + tfa_verified=1 + auth_timestamp
            # + badpass-origin in one CRLF-injection write. Effectively
            # zero-FP; emitted as a separate signal so the dedicated
            # ioc_cve_2026_41940_combo key remains in fleet aggregations.
            if (( SF_HASROOT && SF_TFA && (SF_INT_AUTH || SF_EXT_AUTH) && SF_BADPASS )); then
                emit "sessions" "ioc_cve41940_$session_name" "strong" \
                     "ioc_cve_2026_41940_combo" 10 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "hasroot=1 + tfa_verified=1 + successful_*_auth_with_timestamp + method=badpass origin co-occur - CVE-2026-41940 forged session (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-H: standalone hasroot=1. Per WebPros code-path analysis,
            # `hasroot` is NOT in cpsrvd's _SESSION_PARTS whitelist
            # (Cpanel/Server.pm:2216-2247) and a repo-wide grep finds no
            # caller of Cpanel::Session::Modify->set('hasroot', ...). Its
            # presence in any session is conclusive newline-injection
            # evidence, regardless of other markers. Emitted in addition
            # to IOC-E / IOC-E2 (which already cover the badpass+hasroot
            # subset) so a session with only hasroot smuggled in still
            # surfaces.
            if (( SF_HASROOT )); then
                emit "sessions" "ioc_hasroot_$session_name" "strong" \
                     "ioc_hasroot_in_session" 10 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "hasroot=1 present in session - not in cpsrvd _SESSION_PARTS whitelist; conclusive injection footprint (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-I: malformed session line. Any non-blank line not matching
            # ^[A-Za-z_][A-Za-z0-9_]*= is structurally impossible in a
            # legitimate session (FlushConfig serialization + filter_sessiondata
            # CR/LF strip + _SESSION_PARTS whitelist exclude this shape).
            # Catches injection footprints where smuggled bytes did not
            # form valid key=value pairs. Distinct from IOC-D (multiline
            # pass=) which is the specific pass-continuation subset.
            if (( SF_MALFORMED )); then
                emit "sessions" "ioc_malformed_line_$session_name" "strong" \
                     "ioc_malformed_session_line" 10 \
                     "path" "$f" "sample" "${SF_MALFORMED_SAMPLE:0:80}" \
                     "note" "Session contains a non-blank line not matching key=value - injection footprint (CRITICAL)."
                ((ioc_hits++))
            fi

            # Token-use cross-ref. If any token-injection IOC fired AND
            # we have the cp_security_token value, grep access_log for
            # that token paired with a 2xx response. A hit means the
            # forged session was actually USED by the attacker - escalates
            # the actionable shape from "forged" to "forged AND used".
            if [[ -n "$SF_CP_VAL" ]] \
               && (( (SF_TOKEN_DENIED && SF_CP_TOKEN && SF_BADPASS) \
                     || (SF_BADPASS && (SF_EXT_AUTH || SF_INT_AUTH || SF_HASROOT || SF_TFA)) \
                     || SF_HASROOT )); then
                check_token_used "$f" "$SF_CP_VAL" "$session_name" && ((ioc_hits++))
            fi

            # IOC-F: forged-future timestamp (e.g. 9999999999 = year 2286).
            # Legitimate timestamp is time() at write, so >now+1yr is a clear
            # forgery marker.
            if (( now_epoch > 0 )) && [[ "$SF_AUTH_TS" =~ ^[0-9]+$ ]] \
               && (( SF_AUTH_TS > now_epoch + 31536000 )); then
                emit "sessions" "ioc_forged_timestamp_$session_name" "strong" \
                     "ioc_forged_auth_timestamp" 10 \
                     "path" "$f" "timestamp" "$SF_AUTH_TS" \
                     "note" "successful_*_auth_with_timestamp=$SF_AUTH_TS is more than a year in the future - clear CVE-2026-41940 forgery (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-G: tfa_verified=1 without a recognized login origin
            # (warning - may be a stale/migrated session, may be injection).
            if (( SF_TFA && ! SF_LEGIT_LOGIN )); then
                emit "sessions" "ioc_tfa_$session_name" "warning" \
                     "ioc_tfa_verified_without_login_origin" 3 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "tfa_verified=1 but origin is not a valid login flow - review."
                ((ioc_hits++))
            fi
        done
    fi

    # ---- (b) anomalous-shape heuristic ----------------------------------
    # Root-named session lacking acllist or with a too-short pass=. Lower
    # confidence than the IOC ladder; surfaces as `evidence` not `strong`.
    # Time-bounded by --since.
    local atmp; atmp=$(mktemp /tmp/ssioc.sess.XXXXXX)
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        analyze_session "$f"
        (( SF_CANARY )) && continue
        if (( SF_ROOT_USER )) && { (( ! SF_ACLLIST )) || (( SF_PASS_LEN > 0 && SF_PASS_LEN < 8 )); }; then
            ((anomalous++))
            echo "$f" >> "$atmp"
        fi
    done < <(
        if [[ -n "$SINCE_EPOCH" ]]; then
            find "$d" -type f -newermt "@$SINCE_EPOCH" 2>/dev/null
        else
            find "$d" -type f 2>/dev/null
        fi
    )

    if (( anomalous > 0 )); then
        local window_note=""
        [[ -n "$SINCE_EPOCH" ]] && window_note=" in last ${SINCE_DAYS}d"
        emit "sessions" "session_shape_scan" "evidence" "anomalous_root_sessions" 4 \
             "count" "$anomalous" "scanned" "$scanned" \
             "note" "$anomalous root-named sessions${window_note} lacking expected authz fields"
        local path
        while read -r path; do
            emit "sessions" "session_shape_sample" "info" "anomalous_session_path" 0 "path" "$path"
        done < <(head -10 "$atmp")
    fi
    rm -f "$atmp"

    if (( probe_artifacts > 0 )); then
        emit "sessions" "probe_artifact_summary" "info" "probe_artifact_count" 0 \
             "count" "$probe_artifacts" \
             "note" "$probe_artifacts session(s) tagged with sessionscribe-remote-probe canary - clear with: sessionscribe-remote-probe.sh --cleanup | ssh root@host"
    fi

    if (( ioc_hits == 0 && anomalous == 0 )); then
        emit "sessions" "session_scan" "info" "no_session_iocs" 0 \
             "scanned" "$scanned" "probe_artifacts" "$probe_artifacts" \
             "note" "no IOCs or anomalous-shape sessions found"
    fi
}

# ---- destruction-stage IOC scan (Patterns A-G) ---------------------------
# Cheap, bounded host-state probes for late-stage compromise residue.
# Scoped to /home, /var/www, /root, /etc, /var/spool/cron, /tmp, /var/tmp -
# operator-overrideable via $CPANEL_ROOT? No: these paths are filesystem
# constants, not cpanel-prefixed. Snapshot mode (--root) skips this whole
# block (we don't have meaningful destruction traces in a snapshot).
check_destruction_iocs() {
    (( NO_DESTRUCTION_IOCS )) && return
    if [[ -n "$ROOT_OVERRIDE" ]]; then
        section "Destruction IOC scan (Patterns A-G)"
        emit "destruction" "destruction_scan" "info" "skipped_snapshot_mode" 0 \
             "note" "destruction probes skip snapshot/--root mode (no host filesystem)"
        return
    fi
    section "Destruction IOC scan (Patterns A-G)"
    local hits=0

    # ---- Pattern A: /root/sshd encryptor + .sorry files -------------------
    if [[ -f "$PATTERN_A_BINARY" ]]; then
        local actual_sha=""
        if command -v sha256sum >/dev/null 2>&1; then
            actual_sha=$(sha256sum "$PATTERN_A_BINARY" 2>/dev/null | awk '{print $1}')
        fi
        if [[ "$actual_sha" == "$PATTERN_A_SHA256" ]]; then
            emit "destruction" "ioc_pattern_a_encryptor" "strong" \
                 "ioc_pattern_a_encryptor_match" 10 \
                 "path" "$PATTERN_A_BINARY" "sha256" "$actual_sha" \
                 "note" "$PATTERN_A_BINARY sha256 matches IC-5790 .sorry encryptor (CRITICAL)."
            ((hits++))
        else
            # Binary present at the encryptor's masquerade path but hash
            # mismatched. Still suspicious - could be a variant - but
            # downgrade to warning so we don't false-positive on a
            # legitimate /root/sshd that some operator put there.
            emit "destruction" "ioc_pattern_a_unknown" "warning" \
                 "ioc_pattern_a_binary_present_unknown_hash" 4 \
                 "path" "$PATTERN_A_BINARY" "sha256" "${actual_sha:-unknown}" \
                 "note" "$PATTERN_A_BINARY exists but sha256 differs from known sample - review."
            ((hits++))
        fi
    fi
    # .sorry files. Bounded find: -maxdepth 6 keeps it cheap on /home with
    # many users; -print -quit early-exits on first hit (we just want a yes/no
    # for triage; forensic does the full enumeration).
    local first_sorry=""
    local sorry_root
    for sorry_root in /home /var/www; do
        [[ -d "$sorry_root" ]] || continue
        first_sorry=$(find "$sorry_root" -maxdepth 6 -name '*.sorry' -print -quit 2>/dev/null)
        [[ -n "$first_sorry" ]] && break
    done
    if [[ -n "$first_sorry" ]]; then
        emit "destruction" "ioc_pattern_a_sorry" "strong" \
             "ioc_pattern_a_sorry_files_present" 10 \
             "sample_path" "$first_sorry" \
             "note" "found .sorry-encrypted files (Pattern A); use sessionscribe-forensic for full enumeration (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern B: mysql wipe + BTC-note index drop ---------------------
    # Wipe heuristic: /var/lib/mysql/ exists, mysql/ system-table subdir is
    # gone, AND there's still innodb residue (ibdata1, ib_logfile*, etc).
    # The innodb residue check rules out fresh-install hosts where mysql/
    # legitimately doesn't exist yet. On a real wipe the attacker rm -rf's
    # mysql/ but leaves the larger innodb files intact.
    if [[ -d "$PATTERN_B_MYSQL_DIR" && ! -d "$PATTERN_B_MYSQL_DB" ]]; then
        local has_innodb=0
        if compgen -G "${PATTERN_B_MYSQL_DIR}/ibdata*" >/dev/null 2>&1 \
           || compgen -G "${PATTERN_B_MYSQL_DIR}/ib_logfile*" >/dev/null 2>&1 \
           || compgen -G "${PATTERN_B_MYSQL_DIR}/ib_buffer_pool" >/dev/null 2>&1; then
            has_innodb=1
        fi
        if (( has_innodb )); then
            emit "destruction" "ioc_pattern_b_mysql_wipe" "strong" \
                 "ioc_pattern_b_mysql_dir_missing" 10 \
                 "expected" "$PATTERN_B_MYSQL_DB" \
                 "note" "${PATTERN_B_MYSQL_DIR}/ exists with innodb residue but mysql/ subdir is gone - matches Pattern B DB wipe (CRITICAL)."
            ((hits++))
        fi
    fi
    # BTC-note index.html drops. Limit glob to public_html/index.html across
    # /home users; one grep handles all per-user drops without walking deep.
    local btc_hit=""
    btc_hit=$(grep -lF "$PATTERN_B_BTC_ADDR" /home/*/public_html/index.html 2>/dev/null | head -1)
    if [[ -n "$btc_hit" ]]; then
        emit "destruction" "ioc_pattern_b_btc_note" "strong" \
             "ioc_pattern_b_btc_index_present" 10 \
             "sample_path" "$btc_hit" \
             "note" "BTC ransom note in $btc_hit - Pattern B index drop (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern C: nuclear.x86 dropper traces ---------------------------
    # Binary is rm'd post-launch; the literal string survives in shell history
    # and may briefly survive in /tmp / /var/tmp. Fast: compgen -G + grep -lF.
    local nuke_hit=""
    nuke_hit=$(grep -lF "$PATTERN_C_BIN" \
                  /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -z "$nuke_hit" ]]; then
        nuke_hit=$(grep -lF "$PATTERN_C_BIN" /tmp/*.log /var/tmp/*.log 2>/dev/null | head -1)
    fi
    if [[ -n "$nuke_hit" ]]; then
        emit "destruction" "ioc_pattern_c_nuke_trace" "strong" \
             "ioc_pattern_c_nuclear_x86_referenced" 10 \
             "sample_path" "$nuke_hit" \
             "note" "$PATTERN_C_BIN dropper string in $nuke_hit (Mirai botnet drop, Abuse 46488376)."
        ((hits++))
    fi
    # raw.flameblox.com C2 reference (independent signal in case the literal
    # binary name was renamed but C2 was reused).
    local flame_hit=""
    flame_hit=$(grep -lF "$PATTERN_C_C2_HOST" \
                   /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$flame_hit" ]]; then
        emit "destruction" "ioc_pattern_c_c2_ref" "strong" \
             "ioc_pattern_c_c2_referenced" 8 \
             "sample_path" "$flame_hit" \
             "note" "Mirai C2 host $PATTERN_C_C2_HOST referenced in $flame_hit."
        ((hits++))
    fi

    # ---- Pattern D: sptadm reseller / WHM_FullRoot persistence ----------
    # accounting.log scan: any of three universal fingerprints (sptadm,
    # 4ef72197.cpx.local, WHM_FullRoot, exploit.local). One grep over the
    # whole file - the file is line-oriented and bounded.
    local acct_log=/var/cpanel/accounting.log
    if [[ -f "$acct_log" ]]; then
        local d_pat="${PATTERN_D_RESELLER}|${PATTERN_D_DOMAIN}|${PATTERN_D_EMAIL}|${PATTERN_D_TOKEN_NAME}"
        local d_count d_sample
        # grep -c writes "0" with exit=1 on no-match - command substitution
        # captures stdout cleanly; no `|| echo 0` (that would yield "0\n0"
        # if grep wrote 0 then echo wrote 0).
        d_count=$(grep -cE "$d_pat" "$acct_log" 2>/dev/null)
        d_count="${d_count:-0}"
        if (( d_count > 0 )); then
            d_sample=$(grep -E "$d_pat" "$acct_log" 2>/dev/null | head -1)
            emit "destruction" "ioc_pattern_d_acctlog" "strong" \
                 "ioc_pattern_d_reseller_persistence" 10 \
                 "count" "$d_count" "sample" "${d_sample:0:200}" \
                 "note" "Pattern D persistence fingerprint in $acct_log ($d_count hits) - reseller/API token created post-exploit; revoke before clearing."
            ((hits++))
        fi
    fi
    # Reseller account presence (independent signal: the row may have been
    # rotated out of accounting.log on long-lived hosts).
    if command -v getent >/dev/null 2>&1; then
        if getent passwd "$PATTERN_D_RESELLER" >/dev/null 2>&1; then
            emit "destruction" "ioc_pattern_d_reseller" "strong" \
                 "ioc_pattern_d_reseller_user_present" 10 \
                 "user" "$PATTERN_D_RESELLER" \
                 "note" "user '$PATTERN_D_RESELLER' present in passwd - attacker reseller (CRITICAL)."
            ((hits++))
        fi
    fi
    # WHM_FullRoot api token cache. Path varies across cpanel versions; the
    # token-issuance machinery records the friendly name in api-tokens.cache.
    # Single grep is cheap; if the file isn't where we expect, skip silently.
    local token_cache=/var/cpanel/whm/api-tokens.cache
    if [[ -f "$token_cache" ]]; then
        if grep -qF "\"$PATTERN_D_TOKEN_NAME\"" "$token_cache" 2>/dev/null; then
            emit "destruction" "ioc_pattern_d_token" "strong" \
                 "ioc_pattern_d_whm_fullroot_token_present" 10 \
                 "path" "$token_cache" \
                 "note" "WHM_FullRoot api token present in $token_cache - revoke immediately (CRITICAL)."
            ((hits++))
        fi
    fi

    # ---- Pattern F: __S_MARK__ harvester envelope -----------------------
    local f_hit=""
    f_hit=$(grep -lF "$PATTERN_F_S_MARK" \
                /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$f_hit" ]]; then
        emit "destruction" "ioc_pattern_f_harvester" "strong" \
             "ioc_pattern_f_smark_envelope" 10 \
             "sample_path" "$f_hit" \
             "note" "$PATTERN_F_S_MARK / $PATTERN_F_E_MARK harvester envelope in $f_hit - automated post-exploit recon (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern G: suspect SSH keys ------------------------------------
    # Heuristic fingerprint for the IC-5790 wave: forged mtime around
    # 2019-12-13 with a recent atime AND an IP-shaped key comment.
    # Both conditions required to keep FPs down (legitimate IP-labeled keys
    # exist - LW provisioning uses them sometimes).
    local key_file
    for key_file in "${SSH_KEY_FILES[@]}"; do
        [[ -f "$key_file" ]] || continue
        # mtime check: stat the file once.
        local key_mtime_iso
        key_mtime_iso=$(stat -c '%y' "$key_file" 2>/dev/null | cut -d' ' -f1)
        local has_forged_mtime=0
        [[ "$key_mtime_iso" == "$PATTERN_G_FORGED_MTIME" ]] && has_forged_mtime=1
        # Comment scan: an IP-labeled "ssh-rsa ... IPv4" line is a strong
        # tell when paired with the forged mtime.
        local ip_labeled_lines
        ip_labeled_lines=$(grep -cE '^(ssh-(rsa|ed25519|ecdsa|dsa))[[:space:]]+[A-Za-z0-9+/=]+[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}([[:space:]]|$)' \
                              "$key_file" 2>/dev/null)
        ip_labeled_lines="${ip_labeled_lines:-0}"
        if (( has_forged_mtime && ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ssh_key" "strong" \
                 "ioc_pattern_g_suspect_ssh_keys" 10 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "mtime" "$key_mtime_iso" \
                 "note" "$key_file mtime forged to $key_mtime_iso + $ip_labeled_lines IP-labeled key(s) - Pattern G persistence (CRITICAL)."
            ((hits++))
        elif (( ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ip_keys_review" "warning" \
                 "ioc_pattern_g_ip_labeled_keys_present" 3 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "note" "$ip_labeled_lines IP-labeled SSH key comment(s) in $key_file - review (may be legitimate provisioning)."
            ((hits++))
        fi
    done
    # Keys planted in non-standard locations (cron, /etc).
    local oddkey_count=0
    if command -v find >/dev/null 2>&1; then
        # -path prune to keep this bounded; we explicitly want files under
        # /etc and /var/spool/cron only, never /var/cpanel/userdata or noisy
        # configs.
        oddkey_count=$(find /etc /var/spool/cron -type f \
                          \( -name 'authorized_keys' -o -name 'authorized_keys2' \) \
                          2>/dev/null | wc -l)
        if (( oddkey_count > 0 )); then
            local oddkey_sample
            oddkey_sample=$(find /etc /var/spool/cron -type f \
                              \( -name 'authorized_keys' -o -name 'authorized_keys2' \) \
                              2>/dev/null | head -1)
            emit "destruction" "ioc_pattern_g_oddpath_keys" "warning" \
                 "ioc_pattern_g_keys_in_unexpected_paths" 3 \
                 "count" "$oddkey_count" "sample" "${oddkey_sample:-}" \
                 "note" "$oddkey_count authorized_keys file(s) in /etc or /var/spool/cron - non-standard, review."
            ((hits++))
        fi
    fi

    # ---- Pattern E: websocket/Shell access-log signature ---------------
    # Cheap one-liner over the same access_log set check_logs walks. We
    # specifically want this in the triage path (forensic also has it but
    # forensic is opt-in via --chain-forensic; the triage scanner shouldn't
    # miss this just because the operator skipped chaining).
    local ws_log=/usr/local/cpanel/logs/access_log
    if [[ -f "$ws_log" ]]; then
        # Exclude PROBE_UA_RE so our own scan traffic can never trip this
        # (probes don't currently hit /websocket/Shell, but the filter is
        # defensive across future probe iterations).
        local ws_count ws_sample
        ws_count=$(grep -E "$PATTERN_E_WS_RE" "$ws_log" 2>/dev/null \
                      | grep -vcE "$PROBE_UA_RE" 2>/dev/null || true)
        ws_count="${ws_count:-0}"
        if (( ws_count > 0 )); then
            ws_sample=$(grep -E "$PATTERN_E_WS_RE" "$ws_log" 2>/dev/null \
                           | grep -vE "$PROBE_UA_RE" | head -1)
            emit "destruction" "ioc_pattern_e_websocket" "strong" \
                 "ioc_pattern_e_websocket_shell_hits" 10 \
                 "count" "$ws_count" "sample" "${ws_sample:0:200}" \
                 "note" "$ws_count GET /cpsess*/websocket/Shell hit(s) in access_log - Pattern E interactive RCE (CRITICAL)."
            ((hits++))
        fi
    fi

    if (( hits == 0 )); then
        emit "destruction" "destruction_scan" "info" "no_destruction_iocs" 0 \
             "note" "no destruction-stage residue (Patterns A-G) found"
    fi
}

# ---- localhost marker probe ----------------------------------------------
check_localhost_probe() {
    (( PROBE )) || return
    section "Localhost marker probe (--probe)"
    if ! command -v curl >/dev/null 2>&1; then
        emit "probe" "probe" "warning" "curl_missing" 0 "note" "curl required"
        return
    fi
    local status
    status=$(curl -sk --max-time "$TIMEOUT" -o /dev/null \
                -w '%{http_code}' \
                -A "$PROBE_UA" \
                "https://127.0.0.1:2087/json-api/loadavg" 2>/dev/null) || status="000"
    emit "probe" "probe_request" "info" "request_complete" 0 \
         "url" "https://127.0.0.1:2087/json-api/loadavg" "http" "$status"

    # Look for the marker in the access log tail
    local log=/usr/local/cpanel/logs/access_log
    sleep 0.5  # give cpsrvd time to flush
    if [[ ! -f "$log" ]]; then
        emit "probe" "probe_log" "warning" "log_missing" 0 "note" "no $log"
        return
    fi
    local marker_line
    marker_line=$(tail -c 32768 "$log" 2>/dev/null | grep -F -- "${PROBE_UA%% *}" | tail -1)
    if [[ -z "$marker_line" ]]; then
        emit "probe" "probe_log" "warning" "marker_not_in_log" 0 \
             "note" "probe completed but marker UA not found in access log"
        return
    fi
    local logged_user
    logged_user=$(awk '{print $3}' <<< "$marker_line")
    emit "probe" "probe_log" "info" "marker_logged" 0 \
         "logged_user" "$logged_user" "line" "${marker_line:0:200}"
    if [[ "$logged_user" == "root" ]]; then
        emit "probe" "probe_log" "strong" "marker_logged_as_root" 5 \
             "note" "Localhost marker request logged with user=root despite no auth - strong identity-spoof signal."
    fi
}

###############################################################################
# Verdict aggregation
###############################################################################

aggregate_verdict() {
    local score=0 strong_count=0 fixed_count=0 inconclusive_count=0
    local ioc_critical=0 ioc_review=0 advisory_count=0 probe_artifact_count=0
    # Version-string authority flags. Set when check_version emits one of the
    # build-comparison signals - these are the single load-bearing signal for
    # patch-state determination because the binary fingerprint can't
    # discriminate vuln from patched on 134+ tier.
    local version_says_vuln=0 version_says_patched=0
    local row area id sev key weight kv
    declare -ga REASONS=()
    declare -ga IOC_KEYS=()
    declare -ga ADVISORIES=()
    for row in "${SIGNALS[@]}"; do
        IFS=$'\t' read -r area id sev key weight kv <<< "$row"
        # Authoritative version-string check - record presence regardless of
        # severity. These keys come from check_version's tier_class emit.
        case "$key" in
            vulnerable_per_build|vulnerable_no_vendor_patch|vulnerable_eol)
                version_says_vuln=1 ;;
            patched_per_build)
                version_says_patched=1 ;;
            probe_canary_session|probe_artifact_count)
                ((probe_artifact_count++)) ;;
        esac
        weight="${weight:-0}"
        case "$sev" in
            strong)
                score=$((score + (weight > 0 ? weight : 5)))
                ((strong_count++))
                REASONS+=("$key")
                # Host-state axis: IOC-prefixed strong signals are exploitation
                # evidence, not code-state evidence.
                if [[ "$key" == ioc_* ]]; then
                    ((ioc_critical++))
                    IOC_KEYS+=("$key")
                fi
                ;;
            evidence)
                score=$((score + 2))
                REASONS+=("$key")
                ;;
            warning)
                ((inconclusive_count++))
                if [[ "$key" == ioc_* ]]; then
                    ((ioc_review++))
                    IOC_KEYS+=("$key")
                fi
                ;;
            info)
                # acl_machinery_present_informational is NOT in this list:
                # the binary strings signal cannot discriminate vuln vs patched
                # on 134+ tier; version-string patched_per_build carries the
                # verdict.
                case "$key" in
                    patched_per_build|no_ioc_hits|no_session_iocs)
                        score=$((score - (weight > 0 ? weight : 3)))
                        ((fixed_count++))
                        ;;
                esac
                ;;
            advisory)
                # Ancillary findings - never affect code_verdict, never count
                # toward inconclusive. Surfaced separately for operator awareness.
                ((advisory_count++))
                # Extract human-readable note from the json kv blob for display.
                local note=""
                if [[ "$kv" == *'"note":"'* ]]; then
                    note="${kv#*\"note\":\"}"
                    note="${note%%\"*}"
                fi
                ADVISORIES+=("${id}|${key}|${note}")
                ;;
        esac
    done

    SCORE="$score"
    STRONG_COUNT="$strong_count"
    FIXED_COUNT="$fixed_count"
    INCONCLUSIVE_COUNT="$inconclusive_count"
    ADVISORY_COUNT="$advisory_count"
    IOC_CRITICAL="$ioc_critical"
    IOC_REVIEW="$ioc_review"
    PROBE_ARTIFACT_COUNT="$probe_artifact_count"

    # Code-state axis (the patch question).
    #
    # Version-string is AUTHORITATIVE: on 134+ tier, both vulnerable and
    # patched cpsrvd binaries carry the same ACL/token-reader strings (the
    # machinery entered via feature evolution before the patch release), so
    # the binary fingerprint cannot discriminate. Override hierarchy:
    #
    #   1. --ioc-only            → SKIPPED (operator opted out of code-state)
    #   2. Version says VULN     → VULNERABLE (always; binary/Perl signals
    #      can't contradict a sub-cutoff build)
    #   3. Version says PATCHED + score strongly disagrees (score >= 5) →
    #      INCONCLUSIVE (something else is off - tampered binary, anomalous
    #      Perl, IOC hit shape - needs human review)
    #   4. Version says PATCHED + score within tolerance → PATCHED
    #   5. No version verdict (parse failure / unknown tier) → fall through
    #      to score-based verdict
    if (( IOC_ONLY )); then
        VERDICT="SKIPPED"
        EXIT_CODE=0
    elif (( version_says_vuln )); then
        VERDICT="VULNERABLE"
        EXIT_CODE=1
    elif (( version_says_patched )); then
        if (( score >= 5 )); then
            VERDICT="INCONCLUSIVE"
            EXIT_CODE=2
        else
            VERDICT="PATCHED"
            EXIT_CODE=0
        fi
    elif (( score >= 5 )); then
        VERDICT="VULNERABLE"
        EXIT_CODE=1
    elif (( score <= -5 )); then
        VERDICT="PATCHED"
        EXIT_CODE=0
    else
        VERDICT="INCONCLUSIVE"
        EXIT_CODE=2
    fi

    # Host-state axis (the exploitation question). COMPROMISED dominates the
    # exit code: a patched host can still carry forensic evidence of prior
    # exploitation, and we want fleet-aggregation to triage these first.
    if (( ioc_critical > 0 )); then
        HOST_VERDICT="COMPROMISED"
        EXIT_CODE=4
    elif (( ioc_review > 0 )); then
        HOST_VERDICT="SUSPICIOUS"
        # In --ioc-only mode there is no code-state exit code competing for
        # the slot, so SUSPICIOUS bumps to 2 instead of being silently 0.
        (( IOC_ONLY )) && EXIT_CODE=2
    else
        HOST_VERDICT="CLEAN"
    fi
}

print_verdict() {
    (( QUIET )) && return
    section "Summary"
    sayf '   strong-vuln signals : %s%d%s\n' "$RED" "$STRONG_COUNT" "$NC"
    sayf '   patched signals     : %s%d%s\n' "$GREEN" "$FIXED_COUNT" "$NC"
    sayf '   inconclusive        : %s%d%s\n' "$YELLOW" "$INCONCLUSIVE_COUNT" "$NC"
    sayf '   host IOC hits       : %s%d critical%s, %s%d review%s\n' \
         "$RED" "$IOC_CRITICAL" "$NC" "$YELLOW" "$IOC_REVIEW" "$NC"
    sayf '   advisories          : %s%d%s (ancillary; not CVE-2026-41940)\n' \
         "$CYAN" "${ADVISORY_COUNT:-0}" "$NC"
    if (( ${PROBE_ARTIFACT_COUNT:-0} > 0 )); then
        sayf '   probe artifacts     : %s%d%s (sessionscribe-remote-probe collateral; ignored for host_verdict)\n' \
             "$DIM" "$PROBE_ARTIFACT_COUNT" "$NC"
    fi

    local code_color=""
    case "$VERDICT" in
        VULNERABLE)   code_color="$RED" ;;
        PATCHED)      code_color="$GREEN" ;;
        INCONCLUSIVE) code_color="$YELLOW" ;;
        SKIPPED)      code_color="$DIM" ;;
    esac
    local host_color=""
    case "$HOST_VERDICT" in
        COMPROMISED) host_color="$RED" ;;
        SUSPICIOUS)  host_color="$YELLOW" ;;
        CLEAN)       host_color="$GREEN" ;;
    esac

    say ""
    sayf ' %sCode verdict:%s %s%s%s    score=%+d\n' "$BOLD" "$NC" "$code_color" "$VERDICT" "$NC" "$SCORE"
    sayf ' %sHost verdict:%s %s%s%s\n' "$BOLD" "$NC" "$host_color" "$HOST_VERDICT" "$NC"

    if (( ${#REASONS[@]} > 0 )); then
        local uniq_reasons; uniq_reasons=$(printf '%s\n' "${REASONS[@]}" | sort -u | tr '\n' ',' | sed 's/,$//')
        sayf '   reasons: %s%s%s\n' "$DIM" "$uniq_reasons" "$NC"
    fi

    if (( ${#ADVISORIES[@]} > 0 )); then
        say ""
        sayf ' %sAdvisories%s (ancillary findings - separate from CVE-2026-41940 verdict):\n' "$BOLD" "$NC"
        local entry adv_id adv_key adv_note
        for entry in "${ADVISORIES[@]}"; do
            IFS='|' read -r adv_id adv_key adv_note <<< "$entry"
            sayf '   %s⚐%s %s (%s)\n' "$CYAN" "$NC" "$adv_id" "$adv_key"
            [[ -n "$adv_note" ]] && sayf '       %s%s%s\n' "$DIM" "$adv_note" "$NC"
        done
    fi

    if [[ "$HOST_VERDICT" == "COMPROMISED" ]]; then
        say ""
        sayf ' %s!! HOST SHOWS EXPLOITATION ARTIFACTS - IR REQUIRED !!%s\n' "$RED$BOLD" "$NC"
        say "   Vendor-recommended response (KB 40073787579671):"
        say "     1. Purge all affected sessions under /var/cpanel/sessions/raw/"
        say "     2. Force password reset for root and all WHM users"
        say "     3. Audit /var/log/wtmp and WHM access logs for unauthorized access"
        say "     4. Check for persistence (cron, SSH authorized_keys, sudoers, backdoors)"
        say "     5. Apply vendor patch (/scripts/upcp --force) before restoring service"
    fi

    case "$VERDICT" in
        VULNERABLE)
            say ""
            say "   Recommended action:"
            say "     /usr/local/cpanel/scripts/upcp --force"
            say "     /usr/local/cpanel/scripts/restartsrv_cpsrvd"
            say "     bash $0                                # confirm verdict flips to PATCHED"
            say "   If on an unpatched tier (no in-place patch available), restrict cpsrvd"
            say "   ports 2082/2083/2086/2087/2095/2096 to a management CIDR until upgrade."
            ;;
        INCONCLUSIVE)
            say "   Some signals couldn't be evaluated - check 'pattern_neither' or 'file_missing' rows."
            ;;
    esac
    say ""
}

###############################################################################
# JSON output
###############################################################################

write_json() {
    local out="$1"
    local i first
    {
        printf '{\n'
        printf '  "tool": "sessionscribe-ioc-scan",\n'
        printf '  "tool_version": "%s",\n' "$VERSION"
        printf '  "run_id": "%s",\n' "$RUN_ID"
        printf '  "host": "%s",\n' "$(json_esc "$HOSTNAME_FQDN")"
        printf '  "ts": "%s",\n' "$TS_ISO"
        if [[ -n "$SINCE_EPOCH" ]]; then
            printf '  "since_days": %d,\n' "$SINCE_DAYS"
            printf '  "since_epoch": %d,\n' "$SINCE_EPOCH"
        fi
        printf '  "code_verdict": "%s",\n' "$VERDICT"
        printf '  "host_verdict": "%s",\n' "$HOST_VERDICT"
        printf '  "score": %d,\n' "$SCORE"
        printf '  "exit_code": %d,\n' "$EXIT_CODE"
        printf '  "summary": {"strong":%d,"fixed":%d,"inconclusive":%d,"ioc_critical":%d,"ioc_review":%d,"advisories":%d,"probe_artifacts":%d},\n' \
            "$STRONG_COUNT" "$FIXED_COUNT" "$INCONCLUSIVE_COUNT" "$IOC_CRITICAL" "$IOC_REVIEW" "${ADVISORY_COUNT:-0}" "${PROBE_ARTIFACT_COUNT:-0}"
        printf '  "advisories": [\n'
        first=1
        local entry adv_id adv_key adv_note
        for entry in "${ADVISORIES[@]}"; do
            IFS='|' read -r adv_id adv_key adv_note <<< "$entry"
            (( first )) || printf ',\n'
            first=0
            printf '    {"id":"%s","key":"%s","note":"%s"}' \
                "$(json_esc "$adv_id")" "$(json_esc "$adv_key")" "$(json_esc "$adv_note")"
        done
        printf '\n  ],\n'
        printf '  "signals": [\n'
        first=1
        for row in "${SIGNALS[@]}"; do
            IFS=$'\t' read -r area id sev key weight kv <<< "$row"
            (( first )) || printf ',\n'
            first=0
            # Per-signal host prefix mirrors the JSONL stream so each row is
            # self-attributing when the signals[] array is flattened across hosts.
            printf '    {"host":"%s","area":"%s","id":"%s","severity":"%s","key":"%s","weight":%s%s}' \
                "$HOSTNAME_JSON" "$area" "$id" "$sev" "$key" "${weight:-0}" "${kv:+,$kv}"
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$out"
}

###############################################################################
# CSV output - one summary row per host, header row included.
#
# Schema: host, ts, tool_version, code_verdict, host_verdict, score, exit_code,
#         strong, fixed, inconclusive, ioc_critical, ioc_review, advisories,
#         probe_artifacts, reasons, advisory_ids
#
# Designed for fleet roll-up: `cat *.csv | awk -F, ...` or import into SQL/Excel.
# Use `--csv /dev/stdout` to stream. Multi-value columns (reasons, advisory_ids)
# are semicolon-separated to keep the comma-delimited shape stable.
###############################################################################

# CSV field: wrap in double quotes, double any embedded quotes (RFC 4180).
csv_field() {
    local v="${1//\"/\"\"}"
    printf '"%s"' "$v"
}

write_csv() {
    local out="$1"
    local reasons="" adv_ids=""
    if (( ${#REASONS[@]} > 0 )); then
        reasons=$(printf '%s\n' "${REASONS[@]}" | sort -u | tr '\n' ';' | sed 's/;$//')
    fi
    local entry adv_id adv_key adv_note
    for entry in "${ADVISORIES[@]:-}"; do
        [[ -z "$entry" ]] && continue
        IFS='|' read -r adv_id adv_key adv_note <<< "$entry"
        adv_ids="${adv_ids:+${adv_ids};}${adv_id}"
    done
    {
        printf 'host,run_id,ts,tool_version,code_verdict,host_verdict,score,exit_code,strong,fixed,inconclusive,ioc_critical,ioc_review,advisories,probe_artifacts,reasons,advisory_ids\n'
        printf '%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s\n' \
            "$(csv_field "$HOSTNAME_FQDN")" \
            "$(csv_field "$RUN_ID")" \
            "$(csv_field "$TS_ISO")" \
            "$(csv_field "$VERSION")" \
            "$(csv_field "$VERDICT")" \
            "$(csv_field "$HOST_VERDICT")" \
            "$SCORE" \
            "$EXIT_CODE" \
            "$STRONG_COUNT" \
            "$FIXED_COUNT" \
            "$INCONCLUSIVE_COUNT" \
            "$IOC_CRITICAL" \
            "$IOC_REVIEW" \
            "${ADVISORY_COUNT:-0}" \
            "${PROBE_ARTIFACT_COUNT:-0}" \
            "$(csv_field "$reasons")" \
            "$(csv_field "$adv_ids")"
    } > "$out"
}

###############################################################################
# Run ledger
#
# Append-only JSONL at $LEDGER_DIR/runs.jsonl - one line per run, plus a
# per-run JSON envelope at $LEDGER_DIR/<RUN_ID>.json (skipped when -o was
# supplied; the operator gets their own copy at the requested path).
# Defaults ON; --no-ledger opts out for paranoid runs that must leave no
# host residue. Soft-fail if the directory isn't writable - do not let
# logging-permission issues interfere with the scan exit code.
###############################################################################

ledger_write() {
    (( NO_LEDGER )) && return 0
    if ! mkdir -p "$LEDGER_DIR" 2>/dev/null; then
        emit "ledger" "ledger_write" "warning" "ledger_dir_unwritable" 0 \
             "path" "$LEDGER_DIR" \
             "note" "could not create ledger directory; skipping run history"
        return 0
    fi
    chmod 0700 "$LEDGER_DIR" 2>/dev/null || true
    local end_epoch duration
    end_epoch=$(date -u +%s)
    duration=$(( end_epoch - TS_EPOCH ))
    local line
    line=$(printf '{"ts":"%s","run_id":"%s","host":"%s","tool_version":"%s","code_verdict":"%s","host_verdict":"%s","score":%d,"exit_code":%d,"duration_s":%d,"ioc_critical":%d,"ioc_review":%d}' \
        "$TS_ISO" "$RUN_ID" "$HOSTNAME_JSON" "$VERSION" \
        "$VERDICT" "$HOST_VERDICT" "$SCORE" "$EXIT_CODE" "$duration" \
        "$IOC_CRITICAL" "$IOC_REVIEW")
    # Append - flock would be ideal but introduces a util-linux dependency
    # we don't want for fleet portability. The single-line atomic write
    # is good enough for this access pattern (one writer per host per run).
    printf '%s\n' "$line" >> "$LEDGER_DIR/runs.jsonl" 2>/dev/null || true
    chmod 0600 "$LEDGER_DIR/runs.jsonl" 2>/dev/null || true
    # Per-run envelope. Skip if -o was given (operator captured their own).
    if [[ -z "$OUTPUT_FILE" ]]; then
        local envelope="$LEDGER_DIR/${RUN_ID}.json"
        write_json "$envelope" 2>/dev/null || true
        chmod 0600 "$envelope" 2>/dev/null || true
    fi
}

# Optional syslog one-liner. Logger tag matches the script name minus .sh.
# auth.notice is the right facility for a security-tool summary; operators
# can rsyslog-route on tag.
syslog_emit() {
    (( SYSLOG )) || return 0
    command -v logger >/dev/null 2>&1 || return 0
    local msg
    msg=$(printf 'run_id=%s host=%s code=%s host_verdict=%s exit=%d ioc_critical=%d ioc_review=%d' \
        "$RUN_ID" "$HOSTNAME_FQDN" "$VERDICT" "$HOST_VERDICT" \
        "$EXIT_CODE" "$IOC_CRITICAL" "$IOC_REVIEW")
    logger -t sessionscribe-ioc -p auth.notice -- "$msg" 2>/dev/null || true
}

###############################################################################
# --chain-forensic dispatch
#
# When host_verdict != CLEAN and --chain-forensic is set, locate
# sessionscribe-forensic.sh and exec it with --since/--no-color/--quiet
# inherited and the same RUN_ID exported via SESSIONSCRIBE_RUN_ID.
#
# Resolution order (matches sessionscribe-mitigate.sh's modsec-config
# resolution pattern):
#   1. Sibling of this script on disk
#   2. sessionscribe-forensic.sh on PATH
#   3. https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/...
#   4. https://sh.rfxn.com/sessionscribe-forensic.sh (CDN fallback)
#
# Remote fetches land in a mktemp file under /tmp with chmod 0700 so the
# operator can re-use it without re-fetching. We do NOT verify a shasum
# (no upstream-published hash to pin to yet); the caller is implicitly
# trusting the same TLS pinning as `curl -fsSLO`.
#
# Forensic exit code is captured into a chain.forensic_exit signal (so
# the JSON envelope and ledger record it) but does NOT override this
# script's exit code - ioc-scan's exit code contract (0/1/2/3/4) is
# what fleet wrappers consume.
###############################################################################

# Mirror sessionscribe-mitigate.sh's source-candidate convention.
FORENSIC_SRC_CANDIDATES=(
    "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-forensic.sh"
    "https://sh.rfxn.com/sessionscribe-forensic.sh"
)

# Fetch the forensic script from one of the canonical URLs into a tempfile.
# Echoes the path on success; returns non-zero on failure.
fetch_forensic_remote() {
    command -v curl >/dev/null 2>&1 || return 1
    local dest; dest=$(mktemp /tmp/sessionscribe-forensic.XXXXXX.sh) || return 1
    chmod 0700 "$dest" 2>/dev/null
    local url
    for url in "${FORENSIC_SRC_CANDIDATES[@]}"; do
        if curl -fsSL --max-time 30 -o "$dest" "$url" 2>/dev/null; then
            # Sanity-check: must be a bash script. Reject HTML/empty bodies.
            if head -1 "$dest" 2>/dev/null | grep -qE '^#!/(usr/bin/env[[:space:]]+)?bash'; then
                printf '%s\t%s' "$dest" "$url"
                return 0
            fi
        fi
    done
    rm -f "$dest"
    return 1
}

chain_forensic_dispatch() {
    (( CHAIN_FORENSIC )) || return 0
    if [[ "$HOST_VERDICT" == "CLEAN" ]]; then
        emit "chain" "forensic_skip" "info" "chain_forensic_skipped_clean" 0 \
             "note" "host_verdict=CLEAN; not chaining forensic."
        return 0
    fi
    local self_dir; self_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)
    local forensic_path="" forensic_origin="local"
    if [[ -n "$self_dir" && -f "$self_dir/sessionscribe-forensic.sh" ]]; then
        forensic_path="$self_dir/sessionscribe-forensic.sh"
        forensic_origin="sibling"
    elif command -v sessionscribe-forensic.sh >/dev/null 2>&1; then
        forensic_path=$(command -v sessionscribe-forensic.sh)
        forensic_origin="path"
    else
        # Remote fetch fallback. Returns "<path>\t<url>" so we can record
        # which mirror served us.
        local fetch_result fetched_path fetched_url
        if fetch_result=$(fetch_forensic_remote); then
            fetched_path="${fetch_result%%$'\t'*}"
            fetched_url="${fetch_result#*$'\t'}"
            forensic_path="$fetched_path"
            forensic_origin="remote:$fetched_url"
            emit "chain" "forensic_fetch" "info" "chain_forensic_fetched_remote" 0 \
                 "url" "$fetched_url" "path" "$fetched_path" \
                 "note" "forensic script not present locally; pulled from $fetched_url"
        fi
    fi
    if [[ -z "$forensic_path" ]]; then
        emit "chain" "forensic_locate" "warning" "chain_forensic_not_found" 0 \
             "note" "sessionscribe-forensic.sh not found locally and remote fetch failed; skipping chain."
        return 0
    fi
    local args=(--quiet --no-color)
    [[ -n "$SINCE_DAYS" ]] && args+=(--since "$SINCE_DAYS")
    section "Chaining sessionscribe-forensic.sh (run_id=$RUN_ID, origin=$forensic_origin)"
    emit "chain" "forensic_dispatch" "info" "chain_forensic_started" 0 \
         "path" "$forensic_path" "origin" "$forensic_origin" "run_id" "$RUN_ID"
    local fexit=0
    SESSIONSCRIBE_RUN_ID="$RUN_ID" \
        bash "$forensic_path" "${args[@]}" >/dev/null 2>&1 || fexit=$?
    emit "chain" "forensic_exit" "info" "chain_forensic_complete" 0 \
         "exit_code" "$fexit" \
         "note" "forensic chain exit=$fexit (does not override ioc exit_code)"
}

###############################################################################
# Main
###############################################################################

HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname || echo unknown)
HOSTNAME_JSON=$(json_esc "$HOSTNAME_FQDN")    # pre-escaped, used by emit/write_json
TS_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

banner

local_init
if (( IOC_ONLY )); then
    section "IOC-only mode (--ioc-only): code-state checks skipped"
else
    check_version
    check_static
    check_binary
fi
check_logs
check_sessions
check_destruction_iocs
check_localhost_probe

aggregate_verdict

# Chain to forensic BEFORE printing the verdict / writing outputs so the
# chain.forensic_* signals make it into the JSON envelope, CSV row, and
# ledger entry. Forensic exit captured into signals; never overrides ours.
chain_forensic_dispatch

print_verdict

# Streaming: --csv to stdout (--jsonl is already streamed line-by-line during
# emit() so no end-of-run write is needed for that mode).
(( CSV )) && write_csv /dev/stdout

# File output (-o FILE). Format follows the streaming flag: CSV if --csv,
# structured JSON otherwise (the JSON envelope is the natural file analog
# of --jsonl too, since JSONL is signal-by-signal).
if [[ -n "$OUTPUT_FILE" ]]; then
    if (( CSV )); then
        write_csv "$OUTPUT_FILE"
    else
        write_json "$OUTPUT_FILE"
    fi
fi

# Run ledger - write before exit so a failed exit code still records the
# run. Soft-fails on permission issues; never alters the exit code.
ledger_write
syslog_emit

exit "$EXIT_CODE"
