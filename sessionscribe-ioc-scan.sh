#!/bin/bash
#
##
# sessionscribe-ioc-scan.sh v1.6.3
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

VERSION="1.6.3"

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
# /root/sshd; sha256 from VirusTotal sample.
PATTERN_A_BINARY="/root/sshd"
PATTERN_A_SHA256="2fc0a056fd4eff5d31d06c103af3298d711f33dbcd5d122cae30b571ac511e5a"
PATTERN_A_README="/root/README.md"
PATTERN_A_C2_IP="68.183.190.253"
PATTERN_A_TOX_ID="3D7889AEC00F2325E1A3FBC0ACA4E521670497F11E47FDE13EADE8FED3144B5EB56D6B198724"

# Pattern B - DB wipe + index.html BTC note. mysql wipe = /var/lib/mysql/mysql
# removed but /var/lib/mysql kept (DB engine fails to start).
PATTERN_B_BTC_ADDR="bc1q9nh4revv6yqhj2gc5usncrpsfnh7ypwr9h0sp2"
PATTERN_B_MYSQL_DIR="/var/lib/mysql"
PATTERN_B_MYSQL_DB="/var/lib/mysql/mysql"

# Pattern C - Mirai/nuclear.x86 botnet drop. Dropper deletes the binary after
# launch but the string survives in shell history; C2 host/IP independent so
# rename of the binary doesn't hide the drop.
PATTERN_C_BIN="nuclear.x86"
PATTERN_C_C2_HOST="raw.flameblox.com"
PATTERN_C_C2_IP="87.121.84.78"
PATTERN_C_SHA256="c04d526eb0f7c7660a19871d1675383c8eaf5336651b255c15f4da4708835eb7"

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

# Known-good SSH key labels - must mirror sessionscribe-forensic.sh's
# SSH_KNOWN_GOOD_RE. Real LW provisioning keys carry "Parent Child key
# for <PJID>" comments (the PJID is a 6-char alnum project tag). The
# lwadmin / lw-admin / liquidweb / nexcess prefixes cover the operator-
# tooling key cohort. A line whose key-comment matches this pattern is
# legitimate and should NOT trigger Pattern G.
SSH_KNOWN_GOOD_RE='(lwadmin|lw-admin|liquidweb|nexcess|Parent Child key for [A-Z0-9]{6})'
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

# --chain-upload: forward --upload to the chained forensic so its bundle is
# PUT to the R-fx intake (default https://intake.rfxn.com/, overridable).
# Implies --chain-forensic. CLEAN hosts still skip the entire chain (and
# thus the upload) - we don't ship empty bundles.
# --upload-url / --upload-token: pass-through for forensic's --upload-url /
# --upload-token. Empty defaults => forensic uses its own built-in defaults
# and RFXN_INTAKE_TOKEN env resolution.
CHAIN_UPLOAD=0
CHAIN_UPLOAD_URL=""
CHAIN_UPLOAD_TOKEN=""

# --chain-on-critical: narrow the chain gate from "host_verdict != CLEAN"
# to "host_verdict == COMPROMISED" (i.e. only when at least one strong
# host-state IOC fired - ioc_critical > 0). SUSPICIOUS hosts (review-
# severity hits like stale tfa, IP-labeled keys without forged mtime,
# token_denied+cp_security_token without badpass) skip the chain in
# this mode. Implies --chain-forensic. Useful for fleet runs where
# forensic's per-host time + bundle size matters and operators only
# want full kill-chain reconstruction on hosts with conclusive
# exploitation evidence.
CHAIN_ON_CRITICAL=0

# --exclude-ip CIDR (repeatable). Suppress attacker-IP cross-ref hits from
# operator scan boxes / known-good IR sources.
# Declared with -a (not -ga) for bash 4.1 / EL6 compatibility - declared
# once at top-level scope so the global is already established when
# functions append to it.
declare -a EXCLUDE_IPS=()

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
                             (rfxn/cpanel-sessionscribe@main). Forensic
                             exit code is reported as a chain.forensic_exit
                             signal but does not override this script's
                             exit code.
      --chain-upload         Forward --upload to the chained forensic so
                             its bundle is submitted to the R-fx intake.
                             Implies --chain-forensic. CLEAN hosts skip
                             the chain (and the upload) - empty bundles
                             are not shipped.
      --upload-url URL       Forward --upload-url URL to forensic
                             (default https://intake.rfxn.com/).
      --upload-token TOKEN   Forward --upload-token TOKEN to forensic.
                             Resolution: this flag > $RFXN_INTAKE_TOKEN
                             env > forensic's built-in convenience token.
      --chain-on-critical    Narrow the chain gate to host_verdict==
                             COMPROMISED (strong host-state IOC fired).
                             SUSPICIOUS hosts skip forensic in this mode.
                             Implies --chain-forensic. Useful for fleet
                             runs where you only want kill-chain
                             reconstruction on conclusively-exploited
                             hosts. Combine with --chain-upload for
                             COMPROMISED-only bundle submission.

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
        --chain-upload)       CHAIN_UPLOAD=1; CHAIN_FORENSIC=1; shift ;;
        --upload-url)         CHAIN_UPLOAD_URL="$2"; shift 2 ;;
        --upload-token)       CHAIN_UPLOAD_TOKEN="$2"; shift 2 ;;
        --chain-on-critical)  CHAIN_ON_CRITICAL=1; CHAIN_FORENSIC=1; shift ;;
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

# Resolved by write_ledger() to the per-run JSON envelope path. Forensic
# v0.9+ reads this via SESSIONSCRIBE_IOC_JSON instead of re-detecting IOCs.
ENVELOPE_PATH=""

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

# Bash 4.1 / EL6: -a (not -ga) at top-level scope.
declare -a SIGNALS=()
# Aggregation outputs from aggregate_verdict() consumed by print_verdict /
# write_json / write_csv. Declared at top-level so they remain in global
# scope without needing `declare -g` (bash 4.2+) inside the producer.
declare -a REASONS=()
declare -a IOC_KEYS=()
declare -a ADVISORIES=()

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
    local icon color
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

    # Extract the display-relevant fields from kv pairs. Operators need
    # explicit pointers (path / log line / IP / user) to verify every
    # finding without having to re-grep. Three sub-line groups:
    #   1. WHERE  - path / sample_path / file   ("→ /…/<file>")
    #   2. WHO    - user / src_ip / login_time / file_mtime / sha256
    #   3. WHAT   - sample / access_log_line / line / raw  (the evidence
    #               itself, truncated for terminal readability)
    # All three are optional; rendered only when populated. Full content
    # always lands in JSONL (this function only formats the human view).
    local note="" path="" sample_path="" file="" log_file=""
    local user="" src_ip="" login_time="" file_mtime="" mtime=""
    local sample="" access_log_line="" line="" raw=""
    local sha256="" count="" status="" port=""
    while (( $# >= 2 )); do
        case "$1" in
            note)             note="$2" ;;
            path)             path="$2" ;;
            sample_path)      sample_path="$2" ;;
            file)             file="$2" ;;
            log_file)         log_file="$2" ;;
            user)             user="$2" ;;
            src_ip|ip)        src_ip="$2" ;;
            login_time)       login_time="$2" ;;
            file_mtime)       file_mtime="$2" ;;
            mtime)            mtime="$2" ;;
            sample)           sample="$2" ;;
            access_log_line)  access_log_line="$2" ;;
            line)             line="$2" ;;
            raw)              raw="$2" ;;
            sha256)           sha256="$2" ;;
            count)            count="$2" ;;
            status)           status="$2" ;;
            port)             port="$2" ;;
        esac
        shift 2
    done

    # Header line: id + note (or key as fallback)
    if [[ -n "$note" ]]; then
        printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$note" "$NC" >&2
    else
        printf '   %s%s%s %-44s %s%s%s\n' "$color" "$icon" "$NC" "$id" "$DIM" "$key" "$NC" >&2
    fi

    # Suppress detail for known-clean info rows whose payload is meaningless.
    # Per-row IOC samples are NOT suppressed - operators need ip/status/log_file/
    # raw line to triage. anomalous_session_path samples are NOT suppressed
    # because emit_session populates user/src_ip/login_time/file_mtime which
    # are exactly the forensic fields that distinguish injection from a benign
    # root-named session.
    case "$key" in
        no_ioc_hits|no_session_iocs|patched_per_build|patch_marker_present| \
        ancillary_bug_fixed|acl_machinery_present_informational)
            return ;;
    esac

    # 1. WHERE - filesystem pointer the operator can stat/read/grep directly.
    # log_file (rotated access_log) takes precedence for IOC-sample rows: the
    # operator's first action is "grep this in <file>", and we want to show
    # the exact file rather than the live access_log they may have already
    # checked.
    local location="${log_file:-${path:-${sample_path:-$file}}}"
    if [[ -n "$location" ]]; then
        printf '       %s→ %s%s\n' "$DIM" "$location" "$NC" >&2
    fi

    # 2. WHO - identity + provenance KPIs (compact one-liner)
    local kpi=""
    [[ -n "$user" ]]        && kpi+="user=$user  "
    [[ -n "$src_ip" ]]      && kpi+="src=$src_ip  "
    [[ -n "$status" ]]      && kpi+="status=$status  "
    [[ -n "$port" ]]        && kpi+="port=$port  "
    [[ -n "$login_time" ]]  && kpi+="login=$login_time  "
    if [[ -n "$file_mtime" ]]; then
        kpi+="mtime=$file_mtime  "
    elif [[ -n "$mtime" ]]; then
        kpi+="mtime=$mtime  "
    fi
    if [[ -n "$sha256" ]]; then
        kpi+="sha256=${sha256:0:16}…  "
    fi
    [[ -n "$count" && "$count" != "1" ]] && kpi+="count=$count  "
    if [[ -n "$kpi" ]]; then
        printf '       %s%s%s\n' "$DIM" "${kpi% }" "$NC" >&2
    fi

    # 3. WHAT - the actual evidence (log line / matched content). Truncate
    # to 160 chars for terminal-friendliness; full content stays in JSONL.
    local ev="${sample:-${access_log_line:-${line:-$raw}}}"
    if [[ -n "$ev" ]]; then
        local ev_short="$ev"
        if (( ${#ev} > 160 )); then
            ev_short="${ev:0:160} …"
        fi
        printf '       %s| %s%s\n' "$DIM" "$ev_short" "$NC" >&2
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
    local total=0 hits_2xx=0 unique_ips=0 ts_first=""
    local tmp; tmp=$(mktemp /tmp/ssioc.logs.XXXXXX)
    # Per-line src-file tag (ASCII US, \x1f) so the consumer awk knows which
    # rotated log each match came from - operators need that for zgrep.
    local SEP=$'\x1f'
    {
        if [[ -f "$logdir/access_log" ]]; then
            awk -v src="access_log" -v sep="$SEP" \
                '{ printf "%s%s%s\n", src, sep, $0 }' "$logdir/access_log"
        fi
        local f src
        for f in "$logdir"/access_log-*; do
            [[ -f "$f" ]] || continue
            src=$(basename "$f")
            case "$f" in
                (*.gz) zcat "$f" 2>/dev/null \
                          | awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' ;;
                (*.xz) xzcat "$f" 2>/dev/null \
                          | awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' ;;
                (*)    awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' "$f" ;;
            esac
        done
    } | awk -v floor="${SINCE_EPOCH:-0}" -v ua_re="$IOC_AUTOMATED_UA" -v port_re="$CPSRVD_PORT_RE" -v sep="$SEP" '
        BEGIN { FS = sep }
        $2 ~ /\/json-api\// {
            src  = $1
            line = $2
            if (line !~ /"GET[[:space:]]+\/json-api\//) next
            if (line !~ ua_re) next
            n = split(line, t, " ")
            user = t[3]; status = t[9]; port = t[n]
            if (port !~ port_re) next
            ts = 0
            # cpanel timestamp [MM/DD/YYYY:HH:MM:SS ...] (NOT Apache CLF
            # DD/Mon/YYYY). gawk mktime needs "YYYY MM DD HH MM SS".
            if (match(line, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
                ts = mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
                if (floor > 0 && ts > 0 && ts < floor) next
            }
            print user "\t" status "\t" t[1] "\t" port "\t" src "\t" ts "\t" line
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
        # Earliest non-zero ts across hits - drives the kill-chain reconcile
        # in forensic v0.9+ via ts_epoch_first.
        ts_first=$(awk -F'\t' '$6 != "" && $6 != "0" {print $6}' "$tmp" | sort -n | head -1)
        local sev="evidence"
        if (( hits_2xx > 0 )); then sev="strong"; fi
        emit "logs" "ioc_scan" "$sev" "ioc_hits" 4 \
             "count" "$total" "hits_2xx" "$hits_2xx" "unique_src_ips" "$unique_ips" \
             "ts_epoch_first" "${ts_first:-0}" \
             "note" "$total IOC-pattern hits$window_note ($hits_2xx returned 2xx)"
        # Process substitution (not a pipeline) so emit() reaches the parent
        # SIGNALS array. `head | while` would lose appends in a subshell.
        local u st ip pt src_log ts line trim req
        while IFS=$'\t' read -r u st ip pt src_log ts line; do
            trim="${line:0:200}"
            req=""
            if [[ "$line" =~ \"([A-Z]+)[[:space:]]+([^\"\ ]+) ]]; then
                req="${BASH_REMATCH[1]} ${BASH_REMATCH[2]:0:60}"
            fi
            emit "logs" "ioc_sample" "info" "ioc_sample" 0 \
                 "ip" "$ip" "user" "$u" "status" "$st" "port" "$pt" \
                 "log_file" "$logdir/$src_log" "ts_epoch" "${ts:-0}" \
                 "line" "$trim" \
                 "note" "$ip → $st  ${req}"
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

    # Build IP alternation. Escape dots so 1.2.3.4 only matches that literal.
    local ip ip_re=""
    for ip in "${ATTACKER_IPS[@]}"; do
        ip_re+="${ip_re:+|}${ip//./\\.}"
    done
    # Anchored to "^IP " so we don't match an IP buried inside a URL/UA.
    ip_re="^(${ip_re}) "

    # Single-pass streaming scan: filter+count+sample in one awk over the
    # concatenated logs. Previous implementation wrote ALL logs to a /tmp
    # file (often multi-GB on busy hosts) then ran TWO passes over it
    # (grep -c + awk). New version streams once - halves IO and eliminates
    # the /tmp footprint.
    #
    # Regexes pass via the environment: `awk -v ip_re='...'` would
    # interpret `\.` as the escape sequence "." (any char) AND emit a
    # per-line `warning: escape sequence \. treated as plain .` - a real
    # correctness + noise bug. ENVIRON[] delivers the variable byte-for-
    # byte without escape processing.
    # Build the EXCLUDES env var separately. ${EXCLUDE_IPS[@]:-} on an
    # empty array under `set -u` is brittle on bash 4.1 (CL6); compute
    # the value with explicit length-check for portability.
    local excludes_env=""
    if (( ${#EXCLUDE_IPS[@]} > 0 )); then
        excludes_env=$(printf '%s\n' "${EXCLUDE_IPS[@]}")
    fi

    # Per-line src tagging (ASCII US \x1f) preserves rotated-log attribution
    # through the consumer awk so operators see the exact file each hit
    # came from.
    # Bash 4.1 quirks inside the case below:
    #   - newline after $( required: $({ is a parser bug pre-4.4
    #   - leading-paren case patterns required: bash <4.4 miscounts the
    #     closing ) inside $(...) and aborts on ;;
    local SEP=$'\x1f'
    local tmp; tmp=$(mktemp /tmp/ssioc.atk.XXXXXX)
    {
        if [[ -f "$logdir/access_log" ]]; then
            awk -v src="access_log" -v sep="$SEP" \
                '{ printf "%s%s%s\n", src, sep, $0 }' "$logdir/access_log"
        fi
        local f src
        for f in "$logdir"/access_log-*; do
            [[ -f "$f" ]] || continue
            src=$(basename "$f")
            case "$f" in
                (*.gz) zcat "$f" 2>/dev/null \
                          | awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' ;;
                (*.xz) xzcat "$f" 2>/dev/null \
                          | awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' ;;
                (*)    awk -v src="$src" -v sep="$SEP" \
                              '{ printf "%s%s%s\n", src, sep, $0 }' "$f" ;;
            esac
        done
    } | IP_RE="$ip_re" PROBE_RE="$PROBE_UA_RE" EXCLUDES="$excludes_env" \
        awk -v sep="$SEP" '
        BEGIN {
            FS       = sep
            ip_re    = ENVIRON["IP_RE"]
            probe_re = ENVIRON["PROBE_RE"]
            n = split(ENVIRON["EXCLUDES"], ex_arr, "\n")
            for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
            total = 0; h2xx = 0; h3xx = 0; h4xx = 0; hother = 0
            nsamp = 0; ts_first = 0
        }
        {
            src  = $1
            line = $2
            if (line !~ ip_re) next
            if (line ~ probe_re) next
            split(line, lf, " ")
            ip = lf[1]
            if (ip in ex) next

            st = "?"
            if (match(line, /" [0-9]+ /)) {
                s = substr(line, RSTART + 2)
                split(s, ss, " ")
                st = ss[1]
            }

            ts = 0
            if (match(line, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
                ts = mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
                if (ts > 0 && (ts_first == 0 || ts < ts_first)) ts_first = ts
            }

            total++
            if      (st ~ /^2/) h2xx++
            else if (st ~ /^3/) h3xx++
            else if (st ~ /^4/) h4xx++
            else                hother++

            if (nsamp < 5) {
                nsamp++
                printf "S\t%s\t%s\t%s\t%d\t%s\n", src, ip, st, ts, line
            }
        }
        END {
            printf "TOTALS\t%d\t%d\t%d\t%d\t%d\t%d\n", total, h2xx, h3xx, h4xx, hother, ts_first
        }' > "$tmp" 2>/dev/null

    local total=0 h2xx=0 h3xx=0 h4xx=0 hother=0 ts_first=0
    local totals_line; totals_line=$(grep '^TOTALS' "$tmp" 2>/dev/null | head -1)
    if [[ -n "$totals_line" ]]; then
        IFS=$'\t' read -r _ total h2xx h3xx h4xx hother ts_first <<< "$totals_line"
    fi
    total="${total:-0}"; h2xx="${h2xx:-0}"
    h3xx="${h3xx:-0}"; h4xx="${h4xx:-0}"; hother="${hother:-0}"; ts_first="${ts_first:-0}"

    if (( total > 0 )); then
        # Only 2xx is exploitation. 4xx/3xx is probing - SUSPICIOUS, not
        # COMPROMISED.
        local sev parent_note
        if (( h2xx > 0 )); then
            sev="strong"
            parent_note="$total hit(s) from IC-5790 IPs - $h2xx returned 2xx (EXPLOITATION EVIDENCE - CRITICAL)"
        else
            sev="warning"
            parent_note="$total hit(s) from IC-5790 IPs - all rejected ($h4xx 4xx, $h3xx 3xx, $hother other) - probing only, no successful response (REVIEW)"
        fi
        emit "logs" "ioc_attacker_ip" "$sev" \
             "ioc_attacker_ip_in_access_log" 8 \
             "count" "$total" "hits_2xx" "$h2xx" "hits_3xx" "$h3xx" \
             "hits_4xx" "$h4xx" "hits_other" "$hother" \
             "ts_epoch_first" "$ts_first" \
             "note" "$parent_note"

        local tag src ip st ts line trim
        while IFS=$'\t' read -r tag src ip st ts line; do
            [[ "$tag" == "S" ]] || continue
            trim="${line:0:200}"
            emit "logs" "ioc_attacker_ip_sample" "info" "ioc_attacker_ip_sample" 0 \
                 "ip" "$ip" "status" "$st" "log_file" "$logdir/$src" \
                 "ts_epoch" "${ts:-0}" "line" "$trim" \
                 "note" "$ip → $st  ($src)"
        done < "$tmp"
    fi
    rm -f "$tmp"
}

# ---- session-store analyzer ----------------------------------------------
# Single awk pass over a session file. Sets SF_* globals describing the
# CVE-2026-41940-relevant attribute shape. One subprocess per file replaces
# 6+ greps; the awk reads the file once and emits structured key=value pairs
# the bash side parses with a single read loop.
# Wrapper around emit() that always includes the four identity / provenance
# KPIs from the most recent analyze_session() call. Use this for EVERY
# session-IOC emit so fleet aggregators see {user, src_ip, login_time,
# file_mtime} on every record without having to re-grep the session file.
#
#   user         cPanel/WHM account (user= or whm_user=, first occurrence)
#   src_ip       peer IP (address= or remote_addr=, first occurrence)
#   login_time   login_time= as ISO-8601 UTC (CAN be forged via injection;
#                compare against file_mtime to detect)
#   file_mtime   session file mtime as ISO-8601 UTC (NOT forgeable in
#                this exploit class - reflects actual cpsrvd write)
#
# Args identical to emit() minus the area (always "sessions"):
#   emit_session <key> <severity> <signal> <weight> [k v ...]
emit_session() {
    local key="$1" sev="$2" sig="$3" weight="$4"
    shift 4
    emit "sessions" "$key" "$sev" "$sig" "$weight" \
        "user"       "${SF_USER:-}" \
        "src_ip"     "${SF_REMOTE_ADDR:-}" \
        "login_time" "${SF_LOGIN_ISO:-}" \
        "file_mtime" "${SF_FILE_MTIME_ISO:-}" \
        "$@"
}

analyze_session() {
    SF_TOKEN_DENIED=0; SF_CP_TOKEN=0; SF_BADPASS=0; SF_LEGIT_LOGIN=0
    SF_EXT_AUTH=0;     SF_INT_AUTH=0; SF_TFA=0;     SF_HASROOT=0
    SF_CANARY=0;       SF_ROOT_USER=0; SF_ACLLIST=0; SF_STRANDED=0
    SF_MALFORMED=0;    SF_MALFORMED_SAMPLE=""
    SF_PASS_COUNT=0;   SF_PASS_LEN=0
    SF_TD_VAL="";      SF_CP_VAL="";   SF_ORIGIN="";  SF_AUTH_TS=""
    # Identity + provenance KPIs - always populated when present in the
    # session file. These travel with EVERY ioc_* emit so fleet aggregators
    # can answer "which user / which source IP / when" without having to
    # re-grep the session file.
    #   SF_USER         user= (cPanel account) or whm_user= (WHM account)
    #   SF_REMOTE_ADDR  address= (peer IP) or remote_addr= (legacy)
    #   SF_LOGIN_TIME   login_time= epoch (when cpsrvd recorded the login)
    #   SF_LOGIN_ISO    login_time formatted as ISO-8601 UTC (operator-friendly)
    #   SF_FILE_MTIME   file mtime epoch (last write to disk)
    #   SF_FILE_MTIME_ISO   file mtime as ISO-8601 UTC
    SF_USER="";        SF_REMOTE_ADDR=""
    SF_LOGIN_TIME="";  SF_LOGIN_ISO=""
    SF_FILE_MTIME="";  SF_FILE_MTIME_ISO=""

    # Capture file mtime BEFORE reading the file content (stat is read-only
    # so atime is unaffected, but pull both file timestamps now so they're
    # available for every emit downstream).
    local _sf_path="$1"
    if [[ -e "$_sf_path" ]]; then
        SF_FILE_MTIME=$(stat -c %Y "$_sf_path" 2>/dev/null)
        if [[ -n "$SF_FILE_MTIME" ]]; then
            SF_FILE_MTIME_ISO=$(date -u -d "@$SF_FILE_MTIME" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        fi
    fi

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
            user_val)        SF_USER=$_v ;;
            remote_addr_val) SF_REMOTE_ADDR=$_v ;;
            login_time_val)  SF_LOGIN_TIME=$_v ;;
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

        # Identity / provenance fields. Capture the FIRST occurrence of each
        # so injected duplicates do not overwrite the legitimate value (CRLF
        # injection commonly stamps a second user= line; the first is the
        # original / un-tampered one).
        /^(user|whm_user)=/ {
            if (user_val == "") {
                user_val=substr($0,index($0,"=")+1)
            }
        }
        /^(address|remote_addr)=/ {
            if (remote_addr_val == "") {
                remote_addr_val=substr($0,index($0,"=")+1)
            }
        }
        /^login_time=/ {
            if (login_time_val == "") {
                login_time_val=substr($0,index($0,"=")+1)
            }
        }

        END {
            # neutralize stray CR/LF/TAB in values so they cannot break the
            # bash key=value parser downstream.
            gsub(/[\r\n\t]/, " ", td_val); gsub(/[\r\n\t]/, " ", cp_val)
            gsub(/[\r\n\t]/, " ", origin); gsub(/[\r\n\t]/, " ", auth_ts)
            gsub(/[\r\n\t]/, " ", malformed_sample)
            gsub(/[\r\n\t]/, " ", user_val); gsub(/[\r\n\t]/, " ", remote_addr_val)
            gsub(/[\r\n\t]/, " ", login_time_val)
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
            print "user_val=" user_val
            print "remote_addr_val=" remote_addr_val
            print "login_time_val=" login_time_val
        }
    ' "$1" 2>/dev/null)

    # Convert login_time epoch to ISO-8601 if numeric. Implausible values
    # (forged-future timestamps like 9999999999) still convert cleanly via
    # date(1) and the consumer can compare against file mtime to detect
    # the forgery shape.
    if [[ "$SF_LOGIN_TIME" =~ ^[0-9]+$ ]]; then
        SF_LOGIN_ISO=$(date -u -d "@$SF_LOGIN_TIME" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    fi
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
    emit_session "ioc_token_used_$session_name" "strong" \
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
                    emit_session "ioc_token_inject_$session_name" "strong" \
                         "ioc_token_denied_with_badpass_origin" 10 \
                         "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                         "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                         "note" "Pre-auth session with attacker-injected security token (CRITICAL)."
                else
                    emit_session "ioc_token_review_$session_name" "warning" \
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
                emit_session "ioc_preauth_extauth_$session_name" "strong" \
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
                emit_session "ioc_short_pass_$session_name" "strong" \
                     "ioc_short_pass_with_auth_timestamp" 10 \
                     "path" "$f" "pass_len" "$SF_PASS_LEN" "auth_ts" "$SF_AUTH_TS" \
                     "note" "pass= length ${SF_PASS_LEN} (cleartext shape) co-occurs with successful_*_auth_with_timestamp - CVE-2026-41940 forgery primitive (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-D: structural multi-line pass= - duplicate pass= lines or
            # a stranded continuation line right after pass=. Catches sloppy
            # CRLF injection where the encoder write left detritus.
            if (( SF_PASS_COUNT > 1 || SF_STRANDED )); then
                emit_session "ioc_multiline_pass_$session_name" "strong" \
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
                emit_session "ioc_badpass_authmarkers_$session_name" "strong" \
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
                emit_session "ioc_cve41940_$session_name" "strong" \
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
                emit_session "ioc_hasroot_$session_name" "strong" \
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
                emit_session "ioc_malformed_line_$session_name" "strong" \
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
                emit_session "ioc_forged_timestamp_$session_name" "strong" \
                     "ioc_forged_auth_timestamp" 10 \
                     "path" "$f" "timestamp" "$SF_AUTH_TS" \
                     "note" "successful_*_auth_with_timestamp=$SF_AUTH_TS is more than a year in the future - clear CVE-2026-41940 forgery (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-G: tfa_verified=1 without a recognized login origin
            # (warning - may be a stale/migrated session, may be injection).
            if (( SF_TFA && ! SF_LEGIT_LOGIN )); then
                emit_session "ioc_tfa_$session_name" "warning" \
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
        # Re-analyze each sample so emit_session can stamp user/src_ip/login_time/
        # file_mtime - those four KPIs are the operator's primary forensic
        # surface ("when was this written, from where, claiming what user").
        # analyze_session is one awk pass per file; bounded at 10 samples.
        local path reason
        while read -r path; do
            analyze_session "$path"
            reason=""
            (( ! SF_ACLLIST )) && reason="missing acllist"
            if (( SF_PASS_LEN > 0 && SF_PASS_LEN < 8 )); then
                reason="${reason:+$reason; }short pass=${SF_PASS_LEN}"
            fi
            emit_session "session_shape_sample" "info" "anomalous_session_path" 0 \
                 "path" "$path" \
                 "note" "${reason:-anomalous root-named session}"
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

    # ---- Pattern A: /root/sshd encryptor + .sorry + ransom README + C2 ---
    if [[ -f "$PATTERN_A_BINARY" ]]; then
        local actual_sha="" bin_mtime
        bin_mtime=$(stat -c %Y "$PATTERN_A_BINARY" 2>/dev/null)
        if command -v sha256sum >/dev/null 2>&1; then
            actual_sha=$(sha256sum "$PATTERN_A_BINARY" 2>/dev/null | awk '{print $1}')
        fi
        if [[ "$actual_sha" == "$PATTERN_A_SHA256" ]]; then
            emit "destruction" "ioc_pattern_a_encryptor" "strong" \
                 "ioc_pattern_a_encryptor_match" 10 \
                 "path" "$PATTERN_A_BINARY" "sha256" "$actual_sha" \
                 "mtime_epoch" "${bin_mtime:-0}" \
                 "note" "$PATTERN_A_BINARY sha256 matches IC-5790 .sorry encryptor (CRITICAL)."
            ((hits++))
        else
            # Same path, different hash - variant or unrelated /root/sshd.
            # Warning, not strong, to avoid FPs on legitimate operator drops.
            emit "destruction" "ioc_pattern_a_unknown" "warning" \
                 "ioc_pattern_a_binary_present_unknown_hash" 4 \
                 "path" "$PATTERN_A_BINARY" "sha256" "${actual_sha:-unknown}" \
                 "mtime_epoch" "${bin_mtime:-0}" \
                 "note" "$PATTERN_A_BINARY exists but sha256 differs from known sample - review."
            ((hits++))
        fi
    fi
    # .sorry files. Depth 5 + prune of bulky-and-irrelevant subtrees that the
    # encryptor never touches (Maildir, .cagefs, node_modules, caches, tmp,
    # .trash) keeps the find bounded on shared hosts with 500+ accounts.
    # -print -quit returns the first hit; forensic does the full enumeration.
    local first_sorry=""
    local sorry_root
    for sorry_root in /home /var/www; do
        [[ -d "$sorry_root" ]] || continue
        first_sorry=$(find "$sorry_root" -maxdepth 5 \
            \( -name 'mail' -o -name '.cagefs' -o -name 'node_modules' \
               -o -name '.composer' -o -name '.npm' -o -name '.cache' \
               -o -name '.trash' -o -name 'tmp' \) -prune \
            -o -name '*.sorry' -print -quit 2>/dev/null)
        [[ -n "$first_sorry" ]] && break
    done
    if [[ -n "$first_sorry" ]]; then
        local sorry_mtime
        sorry_mtime=$(stat -c %Y "$first_sorry" 2>/dev/null)
        emit "destruction" "ioc_pattern_a_sorry" "strong" \
             "ioc_pattern_a_sorry_files_present" 10 \
             "sample_path" "$first_sorry" \
             "mtime_epoch" "${sorry_mtime:-0}" \
             "note" "found .sorry-encrypted files (Pattern A); use sessionscribe-forensic for full enumeration (CRITICAL)."
        ((hits++))
    fi
    # qTox ransom README. Drop locations: /root/README.md (canonical) +
    # /home/*/README.md (per-user). Either qtox/TOX ID/Sorry-ID strings or
    # the dossier-known TOX ID hex.
    local readme_hits=()
    [[ -f "$PATTERN_A_README" ]] && readme_hits+=("$PATTERN_A_README")
    while IFS= read -r rf; do
        [[ -f "$rf" ]] && readme_hits+=("$rf")
    done < <(find /home -maxdepth 2 -name 'README.md' 2>/dev/null)
    local rf
    for rf in "${readme_hits[@]}"; do
        if grep -qE "qtox|TOX ID|Sorry-ID|${PATTERN_A_TOX_ID}" "$rf" 2>/dev/null; then
            local rf_mtime tox_match=0
            rf_mtime=$(stat -c %Y "$rf" 2>/dev/null)
            grep -qF "$PATTERN_A_TOX_ID" "$rf" 2>/dev/null && tox_match=1
            emit "destruction" "ioc_pattern_a_readme" "strong" \
                 "ioc_pattern_a_ransom_readme" 10 \
                 "path" "$rf" "tox_id_match" "$tox_match" \
                 "mtime_epoch" "${rf_mtime:-0}" \
                 "note" "qTox ransom README at $rf (tox_id_exact_match=$tox_match) - Pattern A drop (CRITICAL)."
            ((hits++))
        fi
    done
    # Live socket to .sorry C2. Cheap if `ss` exists; silently skip otherwise.
    if command -v ss >/dev/null 2>&1; then
        if ss -tn 2>/dev/null | grep -qF "$PATTERN_A_C2_IP"; then
            emit "destruction" "ioc_pattern_a_c2_live" "strong" \
                 "ioc_pattern_a_live_c2_socket" 10 \
                 "c2" "$PATTERN_A_C2_IP" \
                 "note" "live TCP connection to encryptor C2 $PATTERN_A_C2_IP - active infection (CRITICAL)."
            ((hits++))
        fi
    fi

    # ---- Pattern B: mysql wipe + BTC-note index drop ---------------------
    # Wipe heuristic: /var/lib/mysql/ exists, mysql/ subdir is gone, AND
    # innodb residue (ibdata1, ib_logfile*) is still present. The innodb
    # check rules out fresh-install hosts that legitimately have no mysql/.
    if [[ -d "$PATTERN_B_MYSQL_DIR" && ! -d "$PATTERN_B_MYSQL_DB" ]]; then
        local has_innodb=0
        if compgen -G "${PATTERN_B_MYSQL_DIR}/ibdata*" >/dev/null 2>&1 \
           || compgen -G "${PATTERN_B_MYSQL_DIR}/ib_logfile*" >/dev/null 2>&1 \
           || compgen -G "${PATTERN_B_MYSQL_DIR}/ib_buffer_pool" >/dev/null 2>&1; then
            has_innodb=1
        fi
        if (( has_innodb )); then
            local mysql_parent_mtime
            mysql_parent_mtime=$(stat -c %Y "$PATTERN_B_MYSQL_DIR" 2>/dev/null)
            emit "destruction" "ioc_pattern_b_mysql_wipe" "strong" \
                 "ioc_pattern_b_mysql_dir_missing" 10 \
                 "expected" "$PATTERN_B_MYSQL_DB" \
                 "mtime_epoch" "${mysql_parent_mtime:-0}" \
                 "note" "${PATTERN_B_MYSQL_DIR}/ exists with innodb residue but mysql/ subdir is gone - matches Pattern B DB wipe (CRITICAL)."
            ((hits++))
        fi
    fi
    # BTC index.html drops across /home users. One glob, one grep.
    local btc_hit=""
    btc_hit=$(grep -lF "$PATTERN_B_BTC_ADDR" /home/*/public_html/index.html 2>/dev/null | head -1)
    if [[ -n "$btc_hit" ]]; then
        local btc_mtime
        btc_mtime=$(stat -c %Y "$btc_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_b_btc_note" "strong" \
             "ioc_pattern_b_btc_index_present" 10 \
             "sample_path" "$btc_hit" \
             "mtime_epoch" "${btc_mtime:-0}" \
             "note" "BTC ransom note in $btc_hit - Pattern B index drop (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern C: nuclear.x86 botnet drop ------------------------------
    # Three independent signals: literal binary name in shell history,
    # binary still on disk in known drop paths (sha256 anchored), or C2
    # host/IP referenced in history or persistence files.
    local nuke_hit=""
    nuke_hit=$(grep -lF "$PATTERN_C_BIN" \
                  /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -z "$nuke_hit" ]]; then
        nuke_hit=$(grep -lF "$PATTERN_C_BIN" /tmp/*.log /var/tmp/*.log 2>/dev/null | head -1)
    fi
    if [[ -n "$nuke_hit" ]]; then
        local nuke_mtime
        nuke_mtime=$(stat -c %Y "$nuke_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_c_nuke_trace" "strong" \
             "ioc_pattern_c_nuclear_x86_referenced" 10 \
             "sample_path" "$nuke_hit" \
             "mtime_epoch" "${nuke_mtime:-0}" \
             "note" "$PATTERN_C_BIN dropper string in $nuke_hit (Mirai botnet drop, Abuse 46488376)."
        ((hits++))
    fi
    # Live binary on disk - hash anchor distinguishes confirmed sample from
    # a same-named variant.
    local nx
    for nx in /tmp/nuclear.x86 /var/tmp/nuclear.x86 /dev/shm/nuclear.x86; do
        [[ -f "$nx" ]] || continue
        local nx_sha="" nx_mtime
        nx_mtime=$(stat -c %Y "$nx" 2>/dev/null)
        if command -v sha256sum >/dev/null 2>&1; then
            nx_sha=$(sha256sum "$nx" 2>/dev/null | awk '{print $1}')
        fi
        if [[ "$nx_sha" == "$PATTERN_C_SHA256" ]]; then
            emit "destruction" "ioc_pattern_c_binary" "strong" \
                 "ioc_pattern_c_nuclear_binary_match" 10 \
                 "path" "$nx" "sha256" "$nx_sha" \
                 "mtime_epoch" "${nx_mtime:-0}" \
                 "note" "$nx sha256 matches IC-5790 nuclear.x86 sample (CRITICAL)."
            ((hits++))
        else
            emit "destruction" "ioc_pattern_c_binary_variant" "warning" \
                 "ioc_pattern_c_nuclear_binary_variant" 4 \
                 "path" "$nx" "sha256" "${nx_sha:-unknown}" \
                 "mtime_epoch" "${nx_mtime:-0}" \
                 "note" "$nx present (sha256 differs from known sample - variant?)."
            ((hits++))
        fi
    done
    # C2 host/IP references in shell history or persistence paths. Anchor
    # the search to where attackers stash the re-pull command (cron, rc.local,
    # profile.d, systemd unit files).
    local flame_hit=""
    flame_hit=$(grep -lE "${PATTERN_C_C2_HOST}|${PATTERN_C_C2_IP//./\\.}" \
                   /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$flame_hit" ]]; then
        local flame_mtime
        flame_mtime=$(stat -c %Y "$flame_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_c_c2_ref" "strong" \
             "ioc_pattern_c_c2_referenced" 8 \
             "sample_path" "$flame_hit" \
             "mtime_epoch" "${flame_mtime:-0}" \
             "note" "Mirai C2 ($PATTERN_C_C2_HOST / $PATTERN_C_C2_IP) referenced in $flame_hit."
        ((hits++))
    fi
    local persist_hit=""
    persist_hit=$(grep -rIlE "nuclear\.x86|${PATTERN_C_C2_HOST}|${PATTERN_C_C2_IP//./\\.}" \
                     /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily \
                     /var/spool/cron /etc/profile.d /etc/rc.local \
                     /etc/systemd/system /etc/init.d 2>/dev/null | head -1)
    if [[ -n "$persist_hit" ]]; then
        local persist_mtime
        persist_mtime=$(stat -c %Y "$persist_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_c_persistence" "strong" \
             "ioc_pattern_c_persistence_path" 10 \
             "sample_path" "$persist_hit" \
             "mtime_epoch" "${persist_mtime:-0}" \
             "note" "nuclear.x86/flameblox reference in persistence path $persist_hit (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern D: sptadm reseller / WHM_FullRoot persistence ----------
    # accounting.log: any of sptadm/4ef72197.cpx.local/exploit.local/
    # WHM_FullRoot fingerprints. Bounded line-oriented file; single grep.
    local acct_log=/var/cpanel/accounting.log
    if [[ -f "$acct_log" ]]; then
        local d_pat="${PATTERN_D_RESELLER}|${PATTERN_D_DOMAIN}|${PATTERN_D_EMAIL}|${PATTERN_D_TOKEN_NAME}"
        local d_count d_sample
        d_count=$(grep -cE "$d_pat" "$acct_log" 2>/dev/null)
        d_count="${d_count:-0}"
        if (( d_count > 0 )); then
            local acct_mtime
            acct_mtime=$(stat -c %Y "$acct_log" 2>/dev/null)
            d_sample=$(grep -E "$d_pat" "$acct_log" 2>/dev/null | head -1)
            emit "destruction" "ioc_pattern_d_acctlog" "strong" \
                 "ioc_pattern_d_reseller_persistence" 10 \
                 "count" "$d_count" "sample" "${d_sample:0:200}" \
                 "mtime_epoch" "${acct_mtime:-0}" \
                 "note" "Pattern D persistence fingerprint in $acct_log ($d_count hits) - reseller/API token created post-exploit; revoke before clearing."
            ((hits++))
        fi
    fi
    # Reseller account presence - the accounting.log row may have rotated.
    if command -v getent >/dev/null 2>&1; then
        if getent passwd "$PATTERN_D_RESELLER" >/dev/null 2>&1; then
            local home_mtime=""
            [[ -d "/home/$PATTERN_D_RESELLER" ]] && home_mtime=$(stat -c %Y "/home/$PATTERN_D_RESELLER" 2>/dev/null)
            emit "destruction" "ioc_pattern_d_reseller" "strong" \
                 "ioc_pattern_d_reseller_user_present" 10 \
                 "user" "$PATTERN_D_RESELLER" \
                 "mtime_epoch" "${home_mtime:-0}" \
                 "note" "user '$PATTERN_D_RESELLER' present in passwd - attacker reseller (CRITICAL)."
            ((hits++))
        fi
    fi
    # WHM_FullRoot api token cache. Path stable across recent cpanel versions.
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

    # ---- Pattern F: __S_MARK__ harvester envelope -----------------------
    local f_hit=""
    f_hit=$(grep -lF "$PATTERN_F_S_MARK" \
                /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$f_hit" ]]; then
        local f_mtime
        f_mtime=$(stat -c %Y "$f_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_f_harvester" "strong" \
             "ioc_pattern_f_smark_envelope" 10 \
             "sample_path" "$f_hit" \
             "mtime_epoch" "${f_mtime:-0}" \
             "note" "$PATTERN_F_S_MARK / $PATTERN_F_E_MARK harvester envelope in $f_hit - automated post-exploit recon (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern G: suspect SSH keys ------------------------------------
    # IC-5790 fingerprint: mtime forged to 2019-12-13 + IP-shaped key
    # comment. Both required (LW provisioning legitimately uses IP-labeled
    # keys) so we don't FP on real ops.
    local key_file
    for key_file in "${SSH_KEY_FILES[@]}"; do
        [[ -f "$key_file" ]] || continue
        local key_mtime_epoch key_mtime_iso
        key_mtime_epoch=$(stat -c %Y "$key_file" 2>/dev/null)
        key_mtime_iso=$(stat -c '%y' "$key_file" 2>/dev/null | cut -d' ' -f1)
        local has_forged_mtime=0
        [[ "$key_mtime_iso" == "$PATTERN_G_FORGED_MTIME" ]] && has_forged_mtime=1
        local ip_labeled_lines
        ip_labeled_lines=$(grep -cE '^(ssh-(rsa|ed25519|ecdsa|dsa))[[:space:]]+[A-Za-z0-9+/=]+[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}([[:space:]]|$)' \
                              "$key_file" 2>/dev/null)
        ip_labeled_lines="${ip_labeled_lines:-0}"
        if (( has_forged_mtime && ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ssh_key" "strong" \
                 "ioc_pattern_g_suspect_ssh_keys" 10 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "mtime" "$key_mtime_iso" \
                 "mtime_epoch" "${key_mtime_epoch:-0}" \
                 "note" "$key_file mtime forged to $key_mtime_iso + $ip_labeled_lines IP-labeled key(s) - Pattern G persistence (CRITICAL)."
            ((hits++))
        elif (( ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ip_keys_review" "warning" \
                 "ioc_pattern_g_ip_labeled_keys_present" 3 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "mtime_epoch" "${key_mtime_epoch:-0}" \
                 "note" "$ip_labeled_lines IP-labeled SSH key comment(s) in $key_file - review (may be legitimate provisioning)."
            ((hits++))
        fi
    done
    # Keys planted in non-canonical locations (cron, /etc). Single find walk
    # populates the bash array; -maxdepth 5 covers /etc/<svc>/.ssh and
    # /var/spool/cron/<user>/.ssh. Bulky cpanel/exim/dovecot subtrees pruned.
    if command -v find >/dev/null 2>&1; then
        local oddkeys=()
        local _odd _odd_total _odd_known _odd_unknown
        while IFS= read -r _odd; do
            [[ -z "$_odd" ]] && continue
            # Filter out files where every key entry is a known-good LW
            # provisioning key (Parent Child key for <PJID>, lwadmin,
            # liquidweb, nexcess). These are legitimate placements in
            # /etc and /var/spool/cron and should not surface as IOCs.
            _odd_total=$(grep -cE '^[[:space:]]*(ssh-(rsa|ed25519|ecdsa|dsa)|ecdsa-sha2-)[[:space:]]+[A-Za-z0-9+/=]+' "$_odd" 2>/dev/null)
            _odd_total="${_odd_total:-0}"
            if (( _odd_total > 0 )); then
                _odd_known=$(grep -cE "^[[:space:]]*(ssh-(rsa|ed25519|ecdsa|dsa)|ecdsa-sha2-)[[:space:]]+[A-Za-z0-9+/=]+.*${SSH_KNOWN_GOOD_RE}" "$_odd" 2>/dev/null)
                _odd_known="${_odd_known:-0}"
                _odd_unknown=$(( _odd_total - _odd_known ))
                if (( _odd_unknown <= 0 )); then
                    # All keys in this file are known-good; skip.
                    continue
                fi
            fi
            oddkeys+=("$_odd")
        done < <(find /etc /var/spool/cron -maxdepth 5 \
            \( -path '/etc/cpanel/userdata' -o -path '/etc/cpanel/users' \
               -o -path '/etc/exim*' -o -path '/etc/dovecot' \
               -o -path '/etc/mail' -o -path '/etc/skel' \) -prune \
            -o -type f \( -name 'authorized_keys' -o -name 'authorized_keys2' \) \
            -print 2>/dev/null)
        local oddkey_count=${#oddkeys[@]}
        if (( oddkey_count > 0 )); then
            local odd_mtime=""
            [[ -n "${oddkeys[0]:-}" ]] && odd_mtime=$(stat -c %Y "${oddkeys[0]}" 2>/dev/null)
            emit "destruction" "ioc_pattern_g_oddpath_keys" "warning" \
                 "ioc_pattern_g_keys_in_unexpected_paths" 3 \
                 "count" "$oddkey_count" "sample_path" "${oddkeys[0]}" \
                 "mtime_epoch" "${odd_mtime:-0}" \
                 "note" "$oddkey_count authorized_keys file(s) in /etc or /var/spool/cron - non-standard, review."
            ((hits++))
        fi
    fi

    # ---- Pattern E: websocket/Shell access-log signature ---------------
    # cPanel exposes an interactive shell via /cpsess<id>/websocket/Shell -
    # the WHM "Terminal" feature. ANY hit was previously flagged CRITICAL,
    # but the canonical legitimate caller is RFC1918/loopback admin traffic
    # (operators, internal jump hosts, mgmt VLAN). True Pattern-E
    # exploitation requires an EXTERNAL IP getting a 2xx response.
    #
    # Categorize per (origin, status):
    #   external + 2xx     → strong (RCE landed)
    #   external + non-2xx → warning (probing, host repelled)
    #   internal + 2xx     → info    (admin Terminal session, benign)
    #   internal + non-2xx → ignore  (noise)
    # EXCLUDE_IPS applies here too so operators can suppress known-good
    # external admin IPs (home VPN exit, monitoring egress, etc).
    local ws_log=/usr/local/cpanel/logs/access_log
    if [[ -f "$ws_log" ]]; then
        local excludes_env=""
        if (( ${#EXCLUDE_IPS[@]} > 0 )); then
            excludes_env=$(printf '%s\n' "${EXCLUDE_IPS[@]}")
        fi
        local ws_result
        ws_result=$(grep -E "$PATTERN_E_WS_RE" "$ws_log" 2>/dev/null \
                       | grep -vE "$PROBE_UA_RE" \
                       | EXCLUDES="$excludes_env" awk '
            BEGIN {
                n = split(ENVIRON["EXCLUDES"], ex_arr, "\n")
                for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
                ext_total = 0; ext_2xx = 0; int_2xx = 0; int_other = 0
                ext_sample = ""; int_sample = ""
                ts_first_ext = 0
            }
            {
                ip = $1
                if (ip in ex) next
                st = "?"
                if (match($0, /" [0-9]+ /)) {
                    s = substr($0, RSTART + 2)
                    split(s, ss, " ")
                    st = ss[1]
                }
                ts = 0
                if (match($0, /\[([0-9]{2})\/([0-9]{2})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})/, m)) {
                    ts = mktime(m[3]" "m[1]" "m[2]" "m[4]" "m[5]" "m[6])
                }
                is_internal = (ip ~ /^10\./ \
                               || ip ~ /^127\./ \
                               || ip ~ /^192\.168\./ \
                               || ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)
                if (is_internal) {
                    if (st ~ /^2/) {
                        int_2xx++
                        if (int_sample == "") int_sample = $0
                    } else int_other++
                } else {
                    ext_total++
                    if (st ~ /^2/) ext_2xx++
                    if (ext_sample == "") ext_sample = $0
                    if (ts > 0 && (ts_first_ext == 0 || ts < ts_first_ext)) ts_first_ext = ts
                }
            }
            END {
                printf "%d\t%d\t%d\t%d\t%d\n", ext_total, ext_2xx, int_2xx, int_other, ts_first_ext
                print ext_sample
                print int_sample
            }')
        local ext_total=0 ext_2xx=0 int_2xx=0 int_other=0 ts_first_ext=0
        local ext_sample="" int_sample=""
        {
            IFS=$'\t' read -r ext_total ext_2xx int_2xx int_other ts_first_ext
            IFS= read -r ext_sample
            IFS= read -r int_sample
        } <<< "$ws_result"
        ext_total="${ext_total:-0}"; ext_2xx="${ext_2xx:-0}"
        int_2xx="${int_2xx:-0}"; int_other="${int_other:-0}"
        ts_first_ext="${ts_first_ext:-0}"

        if (( ext_2xx > 0 )); then
            emit "destruction" "ioc_pattern_e_websocket" "strong" \
                 "ioc_pattern_e_websocket_shell_hits" 10 \
                 "count" "$ext_2xx" "external_total" "$ext_total" \
                 "internal_2xx" "$int_2xx" \
                 "ts_epoch_first" "$ts_first_ext" \
                 "sample" "${ext_sample:0:200}" \
                 "note" "$ext_2xx external IP(s) reached /cpsess*/websocket/Shell with 2xx - Pattern E interactive RCE (CRITICAL)."
            ((hits++))
        elif (( ext_total > 0 )); then
            emit "destruction" "ioc_pattern_e_websocket" "warning" \
                 "ioc_pattern_e_websocket_shell_probes" 3 \
                 "count" "$ext_total" "internal_2xx" "$int_2xx" \
                 "ts_epoch_first" "$ts_first_ext" \
                 "sample" "${ext_sample:0:200}" \
                 "note" "$ext_total external IP probe(s) of /cpsess*/websocket/Shell - all rejected, no 2xx (REVIEW)."
            ((hits++))
        elif (( int_2xx > 0 )); then
            emit "destruction" "websocket_shell_internal_admin" "info" \
                 "websocket_shell_internal_admin" 0 \
                 "count" "$int_2xx" "internal_other" "$int_other" \
                 "sample" "${int_sample:0:200}" \
                 "note" "$int_2xx /cpsess*/websocket/Shell hit(s) from RFC1918/loopback - WHM Terminal admin sessions, benign."
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
    # Reset (don't redeclare) - the arrays are top-level globals; using
    # `declare -ga` here would require bash 4.2. Reassigning to () clears
    # the array contents while preserving the global binding.
    REASONS=()
    IOC_KEYS=()
    ADVISORIES=()
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
                    # Surface review-tier IOCs in the verdict reasons line
                    # so operators see "ioc_attacker_ip_in_access_log" even
                    # when host_verdict is SUSPICIOUS not COMPROMISED.
                    REASONS+=("$key")
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
    # Path is exported on the global ENVELOPE_PATH so chain_forensic_dispatch
    # can hand it to forensic via SESSIONSCRIBE_IOC_JSON.
    local envelope=""
    if [[ -z "$OUTPUT_FILE" ]]; then
        envelope="$LEDGER_DIR/${RUN_ID}.json"
        write_json "$envelope" 2>/dev/null || true
        chmod 0600 "$envelope" 2>/dev/null || true
    elif [[ "$OUTPUT_FILE" != "-" ]]; then
        envelope="$OUTPUT_FILE"
    fi
    ENVELOPE_PATH="$envelope"

    # Tell the operator where the structured record landed. Without this,
    # only people who read the source know the ledger exists. Suppressed
    # in QUIET mode (JSONL/CSV consumers don't need the hint) and only
    # printed once after the verdict.
    if (( ! QUIET )); then
        sayf '\n %sResults stored:%s\n' "$BOLD" "$NC"
        sayf '   %srun ledger:%s     %s/runs.jsonl   %s(append-only, one line per run)%s\n' \
             "$DIM" "$NC" "$LEDGER_DIR" "$DIM" "$NC"
        if [[ -n "$envelope" ]]; then
            sayf '   %srun envelope:%s   %s   %s(full per-run JSON; this run only)%s\n' \
                 "$DIM" "$NC" "$envelope" "$DIM" "$NC"
        fi
        if [[ -n "$OUTPUT_FILE" ]]; then
            sayf '   %s--output file:%s  %s   %s(operator-requested)%s\n' \
                 "$DIM" "$NC" "$OUTPUT_FILE" "$DIM" "$NC"
        fi
        sayf '   %srun_id:%s         %s\n' "$DIM" "$NC" "$RUN_ID"
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
#   3. https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-forensic.sh
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
# Order: raw GitHub first (canonical, always-current); sh.rfxn.com as
# a CDN-mirror fallback (occasionally returns 200+empty during sync,
# which we detect via the shebang sanity-check below). Adding both
# means a transient empty body or TLS hiccup on either origin doesn't
# kill the chain.
FORENSIC_SRC_CANDIDATES=(
    "https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-forensic.sh"
    "https://sh.rfxn.com/sessionscribe-forensic.sh"
)

# Last-attempt diagnostic state. Populated by fetch_forensic_remote on
# failure so the warning emit can include the curl exit codes + URLs we
# tried. Cleared on success.
FORENSIC_FETCH_DIAG=""
FORENSIC_FETCHED_PATH=""
FORENSIC_FETCHED_URL=""

# Fetch the forensic script from one of the canonical URLs into a tempfile.
# On success: sets FORENSIC_FETCHED_PATH + FORENSIC_FETCHED_URL, returns 0.
# On failure: sets FORENSIC_FETCH_DIAG with a per-URL "<url>:<rc>:<reason>"
# trace, returns non-zero.
#
# Globals (not stdout) are used because the caller would otherwise have to
# capture the result via $(...), which runs the function in a subshell -
# any FORENSIC_FETCH_DIAG set on failure would be lost when $(...) exits,
# defaulting the operator-visible diagnostic to "no_attempt" and hiding
# whether curl was missing, the URL 404'd, the body was empty, etc.
fetch_forensic_remote() {
    FORENSIC_FETCH_DIAG=""
    FORENSIC_FETCHED_PATH=""
    FORENSIC_FETCHED_URL=""
    if ! command -v curl >/dev/null 2>&1; then
        FORENSIC_FETCH_DIAG="curl_missing"
        return 1
    fi
    local dest; dest=$(mktemp /tmp/sessionscribe-forensic.XXXXXX.sh) || {
        FORENSIC_FETCH_DIAG="mktemp_failed"; return 1
    }
    chmod 0700 "$dest" 2>/dev/null
    local url rc diag=""
    for url in "${FORENSIC_SRC_CANDIDATES[@]}"; do
        rc=0
        curl -fsSL --max-time 30 -o "$dest" "$url" 2>/dev/null || rc=$?
        if (( rc == 0 )); then
            # Sanity-check: must be a bash script. Reject HTML/empty bodies
            # (sh.rfxn.com served HTTP 200 + 0 bytes during a CDN sync window).
            # Accept any reasonable bash shebang: #!/bin/bash, #!/usr/bin/bash,
            # #!/usr/local/bin/bash, #!/usr/bin/env bash. The earlier regex
            # `^#!/(usr/bin/env[[:space:]]+)?bash` only matched #!/bash and
            # #!/usr/bin/env bash, so #!/bin/bash (canonical) failed the
            # check and every fetched script was rejected.
            if head -1 "$dest" 2>/dev/null | grep -qE '^#![[:space:]]*/[^[:space:]]*bash([[:space:]]|$)|^#![[:space:]]*/[^[:space:]]*env[[:space:]]+bash([[:space:]]|$)'; then
                FORENSIC_FETCHED_PATH="$dest"
                FORENSIC_FETCHED_URL="$url"
                return 0
            else
                diag+="$url:200:bad_shebang_or_empty;"
            fi
        else
            diag+="$url:curl_rc=$rc;"
        fi
    done
    rm -f "$dest"
    FORENSIC_FETCH_DIAG="$diag"
    return 1
}

chain_forensic_dispatch() {
    (( CHAIN_FORENSIC )) || return 0
    if [[ "$HOST_VERDICT" == "CLEAN" ]]; then
        emit "chain" "forensic_skip" "info" "chain_forensic_skipped_clean" 0 \
             "note" "host_verdict=CLEAN; not chaining forensic."
        return 0
    fi
    # --chain-on-critical narrows the gate to COMPROMISED only. SUSPICIOUS
    # hosts (review-severity IOCs without a critical hit) emit a distinct
    # skip signal so fleet aggregations can still see the host needed
    # forensic attention - just not auto-dispatched.
    if (( CHAIN_ON_CRITICAL )) && [[ "$HOST_VERDICT" != "COMPROMISED" ]]; then
        emit "chain" "forensic_skip" "info" "chain_forensic_skipped_below_critical" 0 \
             "host_verdict" "$HOST_VERDICT" \
             "note" "host_verdict=$HOST_VERDICT; --chain-on-critical limits chain to COMPROMISED."
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
        # Remote fetch fallback. Direct call (no $()) so the function's
        # diagnostic globals reach this scope on failure.
        if fetch_forensic_remote; then
            forensic_path="$FORENSIC_FETCHED_PATH"
            forensic_origin="remote:$FORENSIC_FETCHED_URL"
            emit "chain" "forensic_fetch" "info" "chain_forensic_fetched_remote" 0 \
                 "url" "$FORENSIC_FETCHED_URL" "path" "$FORENSIC_FETCHED_PATH" \
                 "note" "forensic script not present locally; pulled from $FORENSIC_FETCHED_URL"
        fi
    fi
    if [[ -z "$forensic_path" ]]; then
        local diag="${FORENSIC_FETCH_DIAG:-no_attempt}"
        emit "chain" "forensic_locate" "warning" "chain_forensic_not_found" 0 \
             "note" "sessionscribe-forensic.sh not found locally and remote fetch failed; skipping chain. Diagnostic: $diag" \
             "diag" "$diag"
        return 0
    fi
    # Mirror ioc-scan's quiet state into forensic so a quiet ioc-scan run
    # gives a quiet chain. Otherwise let forensic's human report flow
    # through to stderr - that's the value-add of chaining (defense
    # timeline, kill-chain reconcile, bundle status). --no-color always
    # set because ioc-scan's output is often piped to logs.
    local args=(--no-color)
    (( QUIET )) && args+=(--quiet)
    [[ -n "$SINCE_DAYS" ]] && args+=(--since "$SINCE_DAYS")
    if (( CHAIN_UPLOAD )); then
        args+=(--upload)
        [[ -n "$CHAIN_UPLOAD_URL" ]]   && args+=(--upload-url   "$CHAIN_UPLOAD_URL")
        [[ -n "$CHAIN_UPLOAD_TOKEN" ]] && args+=(--upload-token "$CHAIN_UPLOAD_TOKEN")
    fi
    # Write a preliminary envelope BEFORE forensic runs so it can read our
    # IOCs via SESSIONSCRIBE_IOC_JSON (forensic v0.9+ uses this as its
    # canonical IOC source). ledger_write rewrites the same path at the
    # very end with the chain.forensic_* signals included.
    local envelope_path=""
    if [[ -z "$OUTPUT_FILE" && -n "${LEDGER_DIR:-}" ]]; then
        envelope_path="$LEDGER_DIR/${RUN_ID}.json"
        mkdir -p "$LEDGER_DIR" 2>/dev/null
        write_json "$envelope_path" 2>/dev/null || envelope_path=""
        [[ -n "$envelope_path" ]] && chmod 0600 "$envelope_path" 2>/dev/null
    elif [[ -n "$OUTPUT_FILE" && "$OUTPUT_FILE" != "-" ]]; then
        envelope_path="$OUTPUT_FILE"
    fi
    ENVELOPE_PATH="$envelope_path"

    section "Chaining sessionscribe-forensic.sh (run_id=$RUN_ID, origin=$forensic_origin)"
    local upload_note=""
    (( CHAIN_UPLOAD )) && upload_note=" upload=on(${CHAIN_UPLOAD_URL:-default})"
    emit "chain" "forensic_dispatch" "info" "chain_forensic_started" 0 \
         "path" "$forensic_path" "origin" "$forensic_origin" "run_id" "$RUN_ID" \
         "upload" "$CHAIN_UPLOAD" "envelope" "$ENVELOPE_PATH" \
         "note" "dispatching forensic chain${upload_note}"
    # Suppress forensic's stdout (its JSONL stream would interleave with
    # ours and break a piping consumer); let stderr through so the
    # operator sees the kill-chain reconstruction inline.
    local fexit=0
    SESSIONSCRIBE_RUN_ID="$RUN_ID" \
    SESSIONSCRIBE_IOC_JSON="$ENVELOPE_PATH" \
        bash "$forensic_path" "${args[@]}" >/dev/null || fexit=$?
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
