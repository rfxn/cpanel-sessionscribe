#!/bin/bash
# sessionscribe-ioc-scan.sh — (C) 2026, R-fx Networks <proj@rfxn.com> / GPL v2
# On-host validator for CVE-2026-41940 (cPanel/WHM SessionScribe).
# Read-only; provided as-is, no warranty. Validate against your own change control.
#
# Modes:
#   --triage      detection only (default)
#   --full        detection + forensic + bundle
#   --replay PATH re-render forensic against a saved envelope/bundle/.tgz
#
# Output:
#   default       ANSI sectioned report on stderr
#   -o FILE       structured output (JSON or CSV with --csv)
#   --jsonl       one JSON signal per line on stdout
#   --csv         one per-host summary row on stdout
#   --quiet       suppress sectioned report
#   --verbose     expand matrix detail
#
# Verdict axes (independent):
#   code_verdict       PATCHED / VULNERABLE / INCONCLUSIVE
#   host_root_verdict  CLEAN / SUSPICIOUS / COMPROMISED  (actor had root)
#   host_user_verdict  CLEAN / SUSPICIOUS / COMPROMISED  (user-account scope)
#
# Exit codes (highest wins):
#   0 PATCHED+CLEAN  1 VULNERABLE  2 INCONCLUSIVE  3 SUSPICIOUS  4 COMPROMISED
#
# Usage:
#   bash sessionscribe-ioc-scan.sh                    # triage
#   bash sessionscribe-ioc-scan.sh --full             # + forensic + bundle
#   bash sessionscribe-ioc-scan.sh --full --upload    # + ship to intake
#   bash sessionscribe-ioc-scan.sh --replay PATH      # re-render saved bundle
#   bash sessionscribe-ioc-scan.sh --since 90 --jsonl # 90d window, stream
#
# Fleet:
#   ansible all -m script -a 'sessionscribe-ioc-scan.sh --full --jsonl --quiet'
#   pdsh -w cpanel-fleet 'bash -s' < sessionscribe-ioc-scan.sh

set -u

###############################################################################
# Constants - vendor patch cutoffs and signal definitions
###############################################################################

VERSION="2.8.8"

# Vendor patched-build cutoffs per tier (cPanel KB 40073787579671). WP Squared
# tracked separately in PATCHED_BUILD_WPSQUARED below.
PATCHED_TIERS_KEYS=(86 94 102 110 118 124 126 130 132 134 136)
PATCHED_TIERS_VALS=(44 31 42  118 67  38  59  23  32  26  10)

# Tiers with no in-place vendor patch — hosts must upgrade. Both call sites
# (phase_defense, check_version) match via ` $UNPATCHED_TIERS_STR ` == *" $tier "*.
UNPATCHED_TIERS=(112 114 116 120 122 128)
UNPATCHED_TIERS_STR="${UNPATCHED_TIERS[*]}"

# cpsrvd ACL machinery strings - present (>=8 unique) in patched cpsrvd,
# absent (0) in vulnerable cpsrvd we examined.
ACL_STRINGS_PATTERN='init_acls|checkacl|clear_acls|filter_acls|_dynamic_acl_update|acls_are_initialized|load_dynamic_acl_cache_if_current|_get_dynamic_acl_lists|get_default_acls|Whostmgr::ACLS'

# Automated user-agent pattern for the IOC log scan. Loose-match any of these
# on /json-api/* against cpsrvd ports. l9scan catches LeakIX-flavored
# Mozilla UAs (full UA: "Mozilla/5.0 (l9scan/...; +https://leakix.net)") -
# the substring is unique enough to not FP on real-browser Mozilla rows.
IOC_AUTOMATED_UA='python-requests|^curl/|Go-http-client|libwww-perl|aiohttp|okhttp|httpx|l9scan'

# cpsrvd-served ports.
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

# Pattern E ↔ 2xx_on_cpsess proximity window. 7d captures multi-day
# attacker sessions while excluding unrelated months-apart events.
PATTERN_E_2XX_PROXIMITY_SEC=604800

# Session-file mtime/ctime divergence threshold. cpsrvd writes both
# atomically; divergence is `touch -d` forgery. Advisory only (cp -p /
# tar xp / rsync -t restore artifacts also diverge).
SESSION_MTIME_CTIME_THRESHOLD_SEC=600

# Probe UAs (this script + remote-probe) — excluded from attacker-IP
# cross-check so we don't tag ourselves.
PROBE_UA_RE='sessionscribe-validator|nxesec-cve-2026-41940-probe'

# Destruction-stage IOCs (Patterns A-I). Bounded host-state probes for
# fleet triage; full kill-chain runs inline under --full / --replay.

# Pattern A - .sorry encryptor + qTox ransom note. Masquerades as /root/sshd.
PATTERN_A_BINARY="/root/sshd"
PATTERN_A_SHA256="2fc0a056fd4eff5d31d06c103af3298d711f33dbcd5d122cae30b571ac511e5a"
PATTERN_A_README="/root/README.md"
PATTERN_A_C2_IP="68.183.190.253"
PATTERN_A_TOX_ID="3D7889AEC00F2325E1A3FBC0ACA4E521670497F11E47FDE13EADE8FED3144B5EB56D6B198724"

# Pattern B - DB wipe + index.html BTC note. /var/lib/mysql/mysql removed,
# parent kept (engine fails to start).
PATTERN_B_BTC_ADDR="bc1q9nh4revv6yqhj2gc5usncrpsfnh7ypwr9h0sp2"
PATTERN_B_MYSQL_DIR="/var/lib/mysql"
PATTERN_B_MYSQL_DB="/var/lib/mysql/mysql"

# Pattern C - Mirai/nuclear.x86. Dropper deletes binary; string survives
# in shell history. C2 host/IP catch the drop even after rename.
# _IP_2 is the second binary host (same /24, same actor infra).
PATTERN_C_BIN="nuclear.x86"
PATTERN_C_C2_HOST="raw.flameblox.com"
PATTERN_C_C2_IP="87.121.84.78"
PATTERN_C_C2_IP_2="87.121.84.243"
PATTERN_C_SHA256="c04d526eb0f7c7660a19871d1675383c8eaf5336651b255c15f4da4708835eb7"

# Pattern D - WHM JSON-API recon + reseller-as-persistence. WHM_FullRoot
# token persists post-patch unless revoked — accounting.log hit means
# root-via-API at some point, regardless of host_verdict.
PATTERN_D_RESELLER="sptadm"
PATTERN_D_DOMAIN="4ef72197.cpx.local"
PATTERN_D_EMAIL="a@exploit.local"
PATTERN_D_TOKEN_NAME="WHM_FullRoot"

# Pattern E - websocket/Shell. KNOWN_DIMS are observed-attacker terminal
# sizes; unknown dims warn day-zero on new operators.
PATTERN_E_WS_RE='GET /cpsess[0-9]+/websocket/Shell'
PATTERN_E_KNOWN_DIMS="24x80,24x120,24x134,24x200"

# Pattern F - harvester wrap (actor fingerprint). __S_MARK__/__E_MARK__
# wraps recon; __CMD_DONE_<nanos>__ is an additional same-actor marker.
PATTERN_F_S_MARK="__S_MARK__"
PATTERN_F_E_MARK="__E_MARK__"
PATTERN_F_CMD_DONE_RE='__CMD_DONE_[0-9]+__'

# Pattern G - SSH key persistence. Forged mtime 2019-12-13 12:59:16
# masquerading as LW-internal keys with IP-labeled comments.
PATTERN_G_FORGED_MTIME="2019-12-13"

# Pattern H - seobot SEO defacement. Distinct actor from nuclear.x86;
# kills rival infections (xmrig/kswapd01) before deploying.
PATTERN_H_DROPPER_FILE="seobot.php"
PATTERN_H_END_MARKER="ALLDONE"
PATTERN_H_KILL_PRELUDE='pkill -9 nuclear\.x86 kswapd01 xmrig'
PATTERN_H_ZIP_PATH="/tmp/seobot.zip"
# Catches interrupted runs that didn't self-clean /tmp/seobot.zip.
PATTERN_H_ZIP_MAGIC_B64="UEsDBBQACAAIAMhEkVw"

# Pattern I - system-service profile.d backdoor. Likely lateral-movement
# secondary, not direct CVE-2026-41940; filename/binary unique to dossier.
PATTERN_I_PROFILED="/etc/profile.d/system_profiled_service.sh"
PATTERN_I_BINARY="/root/.local/bin/system-service"
PATTERN_I_PROCNAME="system-service"

# Pattern J — dossier-only persistence IOCs (paths/processes/at-jobs).
# `-helper` suffix is the discriminator vs legitimate counterparts on
# stock cPanel; heuristic removed (see CHANGELOG).
PATTERN_J_KNOWN_PATHS=(
    "/etc/udev/rules.d/89-cdrom-id-helper.rules"
    "/usr/lib/udev/cdrom-id-helper"
    "/etc/systemd/system/dbus-broker-helper.service"
    "/usr/lib/systemd/system/dbus-broker-helper.service"
    "/usr/share/dbus-1/dbus-broker-helper"
)
# Pattern J process names — exact matches via pgrep -x (no substring FP).
PATTERN_J_PROCESS_NAMES=(cdrom-id-helper dbus-broker-helper)

# Pattern K - Cloudflare-fronted /Update second-stage backdoor. Hostname
# is Cloudflare shared anycast - do NOT blocklist at edge (coordinate
# Cloudflare T&S for zone takedown). _TMP_RE [$][$] char-class matches
# both literal `$$` (as-typed) and `[0-9]+` (echo-expanded) forms.
PATTERN_K_BACKDOOR_HOST="cp.dene.de.com"
PATTERN_K_TMP_RE='F=/tmp/\.u([$][$]|[0-9]+)'
# Pattern K dropper paranoid-cleanup shape — single-line wget+chmod+exec+rm.
# Catches Pattern K from a renamed/rotated C2 where the host literal no longer applies.
PATTERN_K_DROPPER_SHAPE_RE='wget[[:space:]]+-q[[:space:]]+-O[[:space:]].*&&[[:space:]]*chmod[[:space:]]+755.*&&.*-s[[:space:]]*;[[:space:]]*rm[[:space:]]+-f'

# Pattern L filesystem-nuke. --no-preserve-root is the load-bearing IOC.
# Trailing-`/` anchor (ws/special/EOL after) avoids FP on non-root targets.
PATTERN_L_NUKE_RE="rm[[:space:]]+-rf[[:space:]]+--no-preserve-root[[:space:]]+/([[:space:]&;\"']|\$)"
PATTERN_L_CMD_START="__CMD_START__"
PATTERN_L_CMD_END="__CMD_END__"
PATTERN_L_CMD_ENVELOPE_RE="${PATTERN_L_CMD_START}|${PATTERN_L_CMD_END}"

# Pattern M — UID=0 backdoor user + amco_ docker botnet. See PATTERNS.md.
PATTERN_M_KNOWN_USERS=(pakchoi alexisa)
PATTERN_M_AMCO_RE="amco_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
PATTERN_M_CRON_SELF_HEAL_RE='\(id[[:space:]]+[a-zA-Z_][a-zA-Z0-9_-]*[[:space:]]+>/dev/null.*\|\|.*useradd.*chpasswd.*sudoers\.d'
# 2026-04-28 = CVE-2026-41940 public disclosure; pre-date M3/M6 artifacts.
PATTERN_M_POST_DISCLOSURE_EPOCH=$(date -u -d '2026-04-28T00:00:00Z' +%s 2>/dev/null || echo 1745798400)
PATTERN_M_ACCESSHASH_PATH="/root/.accesshash"
PATTERN_M_XMR_WALLET="4AypWi9xNQvSy11FT5yr7Ajnyz2XuoUD7LGEJw4ZTRUHLrWjH1x5KoZUp9FTS4s9a5Y6Q7d4jSze4E6tq64aJTD2L7hnCrL"
PATTERN_M_C2_IP="144.172.116.48"
PATTERN_M_C2_PORT="8080"
PATTERN_M_DOCKER_IMAGE="negoroo/amco"

# Runtime-state IOC tables — post-exploitation residue (gsocket, miners,
# loaders, C2). See CHANGELOG.
RUNTIME_KNOWN_BAD_PATHS=(
    "/dev/shm/.gs"
    "/root/c3pool/xmrig"
    "/root/c3pool/config.json"
    "/root/moneroocean/xmrig"
    "/root/moneroocean/config.json"
    "/tmp/codeItems3"
)
RUNTIME_KEYFILE_GLOBS=(
    "/home/*/.config/htop/defunct.dat"
    "/home/*/.config/htop/lscgib.dat"
    "/home/*/.config/dbus/gs-dbus.dat"
    "/root/.config/htop/defunct.dat"
    "/root/.config/htop/lscgib.dat"
    "/root/.config/dbus/gs-dbus.dat"
)
RUNTIME_C2_IPS=(
    "147.182.224.216"
    "45.140.17.40"
    "45.140.17.23"
    "157.245.235.139"
    "57.129.119.218"
    "209.14.84.37"
)
RUNTIME_C2_HOSTS=(
    "u.lihq.me"
)
# 16-char prefixes — match both full and ps-truncated XMR addresses.
RUNTIME_WALLET_PREFIXES=(
    "423Gvxk9VMFH3FUy"
    "4AypWi9xNQvSy11F"
    "47eqhWc4e88EVdqb"
)
RUNTIME_MASQ_RESPAWN_RE='pkill[[:space:]]+-0[[:space:]]+-U[0-9]+[[:space:]]+(defunct|gs-dbus|lscgib)'
_RT_CTX_USER=""
_RT_CTX_PID=""
_RT_CTX_JAILED=0
_RT_CTX_OWNER=""
RUNTIME_LDLINUX_MASQ_RE='\./\.?ld-linux\.so[^[:space:]]*[[:space:]]+(-c[[:space:]]+config\.json|--config=)'
RUNTIME_HTTPS_MASQ_RE='\./https[[:space:]]+(-a[[:space:]]+rx/0|-o[[:space:]].*pool\.|--url=.*pool\.)'
RUNTIME_PYTHON_MASQ_RE='\./python[0-9]*([[:space:]]|$)'
RUNTIME_PYTHON_MASQ_ARGS_RE='(--donate-level|--url[[:space:]]+(stratum\+)?[a-z]+://.*(pool|c3pool|moneroocean|supportxmr)|-o[[:space:]]+.*pool\.|--threads[[:space:]].*--url[[:space:]].*pool)'
RUNTIME_LOADER_PIPE_RE='(c3pool/setup_c3pool_miner|c3pool/xmrig_setup|setup_c3pool_miner\.sh|/atdu([^a-zA-Z0-9_]|$)|/start\.php\?v=|/s/xminstall)'
RUNTIME_TMP_HEX_RE='/\.[a-fA-F0-9]{32,}$'

# CloudLinux LVE / Imunify360 / Postgres lock-file exemptions applied at
# the call site (see check_destruction_iocs).
RUNTIME_REVERSE_SHELL_RES=(
    'perl[[:space:]]+(/tmp/|/dev/shm/|/var/tmp/|/home/[^/[:space:]]+/)[^[:space:]]+\.(pl|sh)[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+[0-9]+'
    'bash[[:space:]]+-[ic]+[[:space:]].*/dev/tcp/([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+'
    '(^|[[:space:]])nc[[:space:]].*-e[[:space:]]+/bin/(ba)?sh'
    '(^|[[:space:]])ncat[[:space:]].*(--exec|--sh-exec)[[:space:]]+'
    '(^|[[:space:]])socat[[:space:]]+.*TCP-(LISTEN|CONNECT):[0-9]+'
    'python[0-9]*[[:space:]]+-c[[:space:]].*(pty\.spawn|\.connect[[:space:]]*\(|os\.dup2|subprocess\.[^=]*shell=True|asyncio\.open_connection|pwn[[:space:]]+import|paramiko\..*connect|(os\.exec[a-z]*|subprocess\.(call|run|Popen)|os\.system|os\.popen)\(([[:space:]]*\[)?[[:space:]]*['\''"]?/bin/(ba)?sh)'
)

# LPE PoC binaries — cwd-relative argv[0] match.
RUNTIME_LPE_BINARIES=(
    "./dirty" "./dirtycow" "./dirtypipe" "./can_bcm" "./exploit"
    "./poc" "./pwnkit" "./0day" "./local-root"
)

# 95-char XMR wallet, boundary-anchored.
RUNTIME_XMR_WALLET_RE='[ /=][48][0-9A-Za-z]{94}([[:space:]]|$)'

# Base64 prefix of "/usr/bin/pkill" — catches base64-wrapped GSocket shim.
RUNTIME_GS_B64_PREFIX='L3Vzci9iaW4vcGtpbGw'

# Attacker-planted jumphost-mimic SSH key labels.
PATTERN_G_BAD_KEY_LABELS=(
    "209.59.141.49"
    "50.28.104.57"
)
# date(1) parses in local TZ; pattern_g_deep_checks compares the wall-
# clock string under both UTC and localtime.
PATTERN_G_FORGED_MTIME_WALL="2019-12-13 12:59:16"

# Real LW provisioning keys carry "Parent Child key for <PJID>"; lwadmin
# / lw-admin / liquidweb / nexcess prefixes cover operator-tooling keys.
SSH_KNOWN_GOOD_RE='(lwadmin|lw-admin|liquidweb|nexcess|Parent Child key for [A-Z0-9]{6})'
SSH_KEY_FILES=(
    "/root/.ssh/authorized_keys"
    "/root/.ssh/authorized_keys2"
)

# Attacker IPs. Some blackholed — still count hits in case rotation
# didn't take. --exclude-ip suppresses operator scan boxes.
ATTACKER_IPS=(
    # badpass exploitation source IPs (initial-access wave)
    68.233.238.100   206.189.2.13     137.184.77.0     38.146.25.154
    157.245.204.205  142.93.43.26     5.230.165.16     5.252.177.207
    146.19.24.235
    # JSON-API enum + websocket Shell operators (Pattern D/E)
    192.81.219.190   149.102.229.144  183.82.160.147   45.82.78.104
    # TLS/HTTP probes
    94.231.206.39
    # C2 / dropper / payload origin (Pattern A/C/D/H)
    68.183.190.253   87.121.84.78     96.30.39.236     68.47.28.118
    # Pattern Unknown (unclassified)
    89.34.18.59
    # DigitalOcean operator cluster (CRLF exploit handoff → 24x200 websocket Shell)
    80.75.212.14     206.189.227.202  159.223.155.255  67.205.134.215
    136.244.66.225
    # Pattern J operator — udev/systemd persistence with OOB payload
    45.92.1.188
    # Pattern C active-process mode (same /24 cluster)
    87.121.84.243
    # badpass exploit IP (null-routed)
    67.205.166.246
)

###############################################################################
# Argument parsing
###############################################################################

PROBE=0
OUTPUT_FILE=""
JSONL=0
CSV=0
QUIET=0
VERBOSE=0
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

# Destruction-IOC scan (Patterns A-I). Cheap host-state probes; default ON
# because the late-stage payload may be all that survives if initial-access
# sessions have rotated out of /var/cpanel/sessions/raw/.
NO_DESTRUCTION_IOCS=0

# Run ledger: append-only JSONL + per-run envelope under /var/cpanel/.
# Default ON; --no-ledger opts out for runs that must leave no residue.
NO_LEDGER=0
LEDGER_DIR_DEFAULT="/var/cpanel/sessionscribe-ioc"
LEDGER_DIR=""            # resolved at run time; --ledger-dir overrides

# Forensic phase defaults — used when --full or --replay
# is supplied; no-op in default --triage mode.
DEFAULT_BUNDLE_DIR_ROOT="/root/.cve-2026-41940-forensic"
LEGACY_BUNDLE_DIR_ROOT="/root/.ic5790-forensic"
DEFAULT_MAX_BUNDLE_MB=2048      # per-tarball cap (NOT bundle-wide)
DEFAULT_FORENSIC_SINCE_DAYS=90  # forensic-mode default --since when unspecified
# Bundle retention: keep N newest in $BUNDLE_DIR_ROOT; older pruned at
# end of phase_bundle. Override via $BUNDLE_RETENTION (0 = no prune).
DEFAULT_BUNDLE_RETENTION=3
INTAKE_DEFAULT_URL="https://intake.rfxn.com/"
# No embedded default token — --upload requires an explicit token from
# --upload-token or $RFXN_INTAKE_TOKEN. Mirror of the telemetry-token
# model. Contact proj@rfxn.com for a fleet token.

# Sentinel file whose mtime phase_defense uses to estimate when a host
# adopted the vendor cPanel patch (Load.pm is the file the patch rewrites).
# Empty/missing canary => host has never been patched in-place.
PATCH_CANARY_FILE="/usr/local/cpanel/Cpanel/Session/Load.pm"
MITIGATE_BACKUP_ROOT="/var/cpanel/sessionscribe-mitigation"

# External-containment ingestion. Replay operator IR per-run dirs
# (hashes.txt + ssh-pruned-keys.log) so a contained host still scores.
# Glob must be root-owned + single-token; empty disables.
EXTERNAL_QUARANTINE_GLOB="/root/quarantine-*"
MAX_EXTERNAL_QUARANTINE_HITS="${MAX_EXTERNAL_QUARANTINE_HITS:-200}"
MAX_EXTERNAL_QUARANTINE_FILE_BYTES="${MAX_EXTERNAL_QUARANTINE_FILE_BYTES:-1048576}"
MODSEC_USER_CONFS=(
    "/etc/apache2/conf.d/modsec/modsec2.user.conf"   # EA4 (cPanel default)
    "/etc/httpd/conf.d/modsec/modsec2.user.conf"     # non-EA4 fallback
    "/etc/httpd/conf.d/modsec2.user.conf"            # legacy non-EA4
)
MODSEC_USER_CONF="${MODSEC_USER_CONFS[0]}"
CPSRVD_PORTS=(2082 2083 2086 2087 2095 2096)

# Optional syslog one-liner for SIEM ingestion. Off by default.
SYSLOG=0

# --chain-upload pass-through: --upload-url / --upload-token populate
# CHAIN_UPLOAD_URL / CHAIN_UPLOAD_TOKEN, consumed by the upload helper.
# Empty defaults => upload uses RFXN_INTAKE_TOKEN env resolution.
CHAIN_UPLOAD_URL=""
CHAIN_UPLOAD_TOKEN=""

# --chain-on-critical: only run forensic when ioc_critical > 0
# (skips SUSPICIOUS hosts). Implies --chain-forensic.
CHAIN_ON_CRITICAL=0

# --chain-on-all: always run forensic regardless of host verdicts.
# Wins over --chain-on-critical. Implies --chain-forensic.
CHAIN_ON_ALL=0

# --chain-on-root-only: chain only when host_root_verdict==COMPROMISED.
# Lets IR scope forensic to host-rebuild candidates and skip user-only
# compromises (per-account cleanup queue).
CHAIN_ON_ROOT_ONLY=0

# Forensic / merged-mode defaults.
FULL_MODE=0                             # 1 if --full set (or back-compat chain flag)
REPLAY_PATH=""                          # set by --replay PATH
REPLAY_MODE=0                           # 1 if --replay PATH set (skip detection)
DO_BUNDLE=1                             # default ON when --full active; --no-bundle disables
BUNDLE_DIR_ROOT="$DEFAULT_BUNDLE_DIR_ROOT"
BUNDLE_DIR_OVERRIDDEN=0
MAX_BUNDLE_MB="$DEFAULT_MAX_BUNDLE_MB"
EXTRA_LOGS_DIR=""
INCLUDE_HOMEDIR_HISTORY=1
DO_UPLOAD=0
INTAKE_URL="$INTAKE_DEFAULT_URL"
INTAKE_TOKEN=""

# Telemetry mode — lite bundle (envelope + kill-chain + KB-scale snapshots
# only; no sessions/access-logs/persistence tarballs). ~50-100 KB per host.
# Optional envelope POST via --telemetry-url; transport ladder curl > wget >
# bash /dev/tcp + openssl.
TELEMETRY_MODE=0
TELEMETRY_URL=""
TELEMETRY_TOKEN=""
TELEMETRY_TIMEOUT=15
TELEMETRY_RETRY=2
# 5 MB cap. Envelopes rarely exceed 50 KB on a clean host, but a destruction-
# heavy host with hundreds of A/B/C/H pattern hits can grow into double-digit
# KB; the cap is a defense-in-depth ceiling against pathological cases.
TELEMETRY_MAX_BYTES=$((5 * 1024 * 1024))

# --telemetry-cron <add|remove> [1h|2h|6h|12h|24h]: manages /etc/cron.d/
# entry. Cron line self-fetches latest script (GitHub raw → sh.rfxn.com
# fallback) every tick.
TELEMETRY_CRON_ACTION=""
TELEMETRY_CRON_INTERVAL="6h"
TELEMETRY_CRON_FILE="/etc/cron.d/sessionscribe-telemetry"
# Cron self-fetch sources (GitHub canonical, CDN fallback) + install dest.
TELEMETRY_CRON_GITHUB_URL="https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh"
TELEMETRY_CRON_CDN_URL="https://sh.rfxn.com/sessionscribe-ioc-scan.sh"
TELEMETRY_CRON_INSTALL_PATH="/usr/local/bin/sessionscribe-ioc-scan.sh"

# --exclude-ip CIDR (repeatable). Suppress attacker-IP hits from
# operator scan boxes / known-good IR sources. -a (not -ga) for bash 4.1.
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
      --no-destruction-iocs  Skip destruction-stage probes (Patterns A-I:
                             /root/sshd encryptor, mysql-wipe, BTC index,
                             nuclear.x86, sptadm reseller, __S_MARK__
                             harvester, suspect SSH keys, seobot dropper,
                             system-service backdoor). Use for the
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

External quarantine workflow:
      --containment-glob G   Glob of operator containment dirs holding
                             hashes.txt + (optional) ssh-pruned-keys.log
                             (default /root/quarantine-*). Empty disables.
                             Must be root-owned, single-token (no spaces).
                             Env: same as flag.
      --max-containment-hits N
                             Cap on signals per run, shared across both
                             files (default 200). Env:
                             MAX_EXTERNAL_QUARANTINE_HITS.
      --max-containment-file-bytes B
                             Per-file size cap (default 1048576). Files
                             over the cap emit a warning and are skipped.
                             Env: MAX_EXTERNAL_QUARANTINE_FILE_BYTES.

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
      --verbose, -v          Expand the per-section verdict matrix to
                             include matching IOC keys per row. Reserved
                             for future renderer changes that elide
                             operator-relevant detail.
      --no-color             Disable ANSI color codes.

Run ledger (default ON):
      --no-ledger            Skip the /var/cpanel/sessionscribe-ioc/ run
                             ledger. Use on hosts where you must not
                             leave residue.
      --ledger-dir DIR       Override default ledger directory
                             (/var/cpanel/sessionscribe-ioc/).
      --syslog               Emit a one-line summary via logger -t
                             sessionscribe-ioc -p auth.notice on completion.

Mode (post-merge v2.0.0):
      --triage               Detection only (default). Writes envelope to
                             run-ledger; no defense timeline / kill-chain /
                             bundle. Same shape as ioc-scan v1.x.
      --full                 Detection + forensic phases (defense / offense /
                             reconcile / kill-chain / bundle). Artifact
                             capture on by default; disable with no-bundle
                             for kill-chain reconstruction without a tar.
      --replay PATH          Skip detection; replay forensic phases against
                             a saved envelope (.json file), bundle directory
                             (containing the envelope), or bundle tarball
                             (.tgz / .tar.gz -- envelope extracted to /tmp).
                             Bundle and upload flags still respected if set.
                             Useful for re-rendering the kill chain or
                             re-submitting a captured bundle without re-
                             scanning the host.

Bundle (active in full or replay mode):
      --bundle               Capture artifact tarball to $BUNDLE_DIR_ROOT/
                             <ts>-<run_id>/ (default ON in full mode).
                             Retains the 3 newest bundles; older ones are
                             pruned at end of phase_bundle. Override via
                             $BUNDLE_RETENTION env (0 = disable pruning).
      --no-bundle            Skip bundle capture (recommended on Pattern A
                             hosts where du+tar would compete with the
                             encryptor for IO)
      --bundle-dir DIR       Override $BUNDLE_DIR_ROOT
                             (default: /root/.cve-2026-41940-forensic;
                             pre-rename hosts: /root/.ic5790-forensic
                             auto-detected when present)
      --max-bundle-mb N      Per-tarball size cap in MB (0 = no cap;
                             default: 2048)
      --extra-logs DIR       Additional access-log directory to scan (e.g.
                             an expanded archive of rotated logs)
      --no-history           Skip /home/*/.bash_history bundle capture

Upload (off by default):
      --upload               Submit bundle to $INTAKE_URL after capture.
                             Requires an explicit token via --upload-token
                             or $RFXN_INTAKE_TOKEN env (no embedded
                             default; mirrors the telemetry-token model).
                             Intake URL/token may also be overridden via
                             the upload-url / upload-token flags documented
                             in the Misc section below. Token resolution
                             order: flag > $RFXN_INTAKE_TOKEN env. Server
                             enforces 1000-PUT cap per token; contact
                             proj@rfxn.com for a fleet token.

Telemetry (low-disk-usage fleet collection):
      --telemetry            Lite bundle: envelope.json + kill-chain.{tsv,
                             jsonl,md} + manifest.txt + KB-scale forensic
                             snapshots (ps/connections/iptables + Pattern
                             A/H/I attacker-binary metadata). Skips heavy
                             tarballs (sessions, access-logs, system-logs,
                             cpanel-state, persistence, defense-state) and
                             per-user histories. Implies --full
                             --chain-on-all --bundle. ~50-100 KB on-disk
                             per host vs ~50 MB for --full bundles. Pair
                             with --telemetry-url to POST the envelope to
                             a fleet collector. Compatible with --upload
                             (ships the lite bundle to intake).
      --telemetry-url URL    POST envelope JSON to URL after lite bundle
                             writes. Implies --telemetry. Transport ladder:
                             curl > wget > bash native (/dev/tcp for HTTP,
                             openssl s_client for HTTPS). Bash on RHEL/CL6+
                             is built --enable-net-redirections so the
                             /dev/tcp pseudo-path works without any
                             external HTTP client. Must be http:// or
                             https://; HTTPS requires curl, wget with SSL,
                             or openssl(1).
      --telemetry-token TOK  Bearer token sent as 'Authorization: Bearer'
                             header on telemetry POST. Optional; omit for
                             unauthenticated endpoints.
      --telemetry-timeout N  Per-attempt HTTP timeout in seconds (default
                             15). Applies to each retry attempt
                             individually, not to the cumulative wall.
      --telemetry-retry N    Retry count on transient failure (default 2;
                             total attempts = 1 + N). Exponential backoff:
                             2s after attempt 1, 4s after attempt 2.
      --telemetry-max-bytes B Cap envelope size for transmission (default
                             5MB / 5242880). Larger envelopes skip the POST
                             and emit a warning signal; the lite bundle on
                             disk is unaffected.
      --telemetry-cron add [INTERVAL]
                             Install a system cron entry at
                             /etc/cron.d/sessionscribe-telemetry. Each
                             cron tick:
                               (1) sleeps 5-300s for fleet splay,
                               (2) mktemp creates a tempfile in the install
                                   directory (same fs for atomic rename),
                               (3) curl-fetches the latest script — primary
                                   source is GitHub raw
                                   (raw.githubusercontent.com/rfxn/cpanel-
                                   sessionscribe), fallback is the rfxn CDN
                                   (sh.rfxn.com); if GitHub is unreachable
                                   the second curl runs automatically,
                               (4) size-guards (catches Caddy 200+0 fallback
                                   for missing files on the CDN tree),
                               (5) validates with bash -n,
                               (6) atomic-installs to /usr/local/bin/ at
                                   mode 0755 root:root,
                               (7) runs the scan under 'timeout 300'.
                             Self-bootstrapping: works via curl-pipe (no
                             on-disk script required at install time);
                             always-current (each tick pulls the latest
                             release; GitHub raw updates within ~5 min of
                             every git push, so the maximum fleet drift
                             window is one cron interval + ~5 min).
                             Allowed: 1h | 2h | 6h | 12h | 24h. Default: 6h.
                             Requires root (writes /etc/cron.d/). If
                             --upload-url and/or --upload-token are also
                             passed on this command line, they're embedded
                             in the generated cron entry so the cron run
                             ships to your custom intake. Idempotent —
                             running 'add' again overwrites the file.
                             Floor: curl 7.10+, coreutils 7.0+ (timeout(1)),
                             present on CL6/EL6 (curl 7.19.7, coreutils 8.4).
      --telemetry-cron remove
                             Remove /etc/cron.d/sessionscribe-telemetry.
                             No-op if not installed. Requires root.

Back-compat aliases (deprecated; set full-mode + the relevant gate):
      --chain-forensic       equivalent to full mode (no host-verdict gate)
      --chain-on-critical    full mode only if host_root_verdict OR
                             host_user_verdict == COMPROMISED
                             (CLEAN/SUSPICIOUS skip forensic phases)
      --chain-on-root-only   like --chain-on-critical but skips hosts
                             where only host_user_verdict==COMPROMISED
                             (host-rebuild candidates only)
      --chain-on-all         full mode for EVERY host, including
      --chain-always         CLEAN (overrides default CLEAN-skip + overrides
                             --chain-on-critical). Pair with --upload to
                             ship every bundle to intake (fleet baseline /
                             threat-intel data-lake collection).
      --chain-upload         full mode with upload enabled

Misc:
      --timeout N            Probe timeout in seconds (default 8).
  -h, --help                 Show this help.

Exit codes:
  0  PATCHED+CLEAN       host clean, no IOCs, code state patched
  1  VULNERABLE          code-state: cpsrvd binary unpatched
  2  INCONCLUSIVE        code-state: version ambiguous; also tool error
                         (bad args, missing dependencies - exits before scan)
  3  SUSPICIOUS          host-state: ioc_review > 0 (warning-tier IOC;
                         includes ioc_failed_exploit_attempt, recon-only
                         attacker-IP traffic, anomalous root sessions)
  4  COMPROMISED         host-state: ioc_critical > 0 (strong-tier IOC;
                         includes destruction patterns, cpsess-bearing 2xx
                         from T1 IPs, session-side injection markers;
                         overrides all lower exit codes)
EOF
    exit 0
}

# Telemetry cron management.

# Self-heal legacy cron files (unescaped %, MAILTO=root).
repair_telemetry_cron_file() {
    local f="$TELEMETRY_CRON_FILE" tmp
    [[ -f "$f" && -w "$f" ]] || return 0
    local has_pct_bug=0 has_root_mailto=0 has_any_mailto=0
    grep -q 'RANDOM % '       "$f" 2>/dev/null && has_pct_bug=1
    grep -Eq '^MAILTO=root\>' "$f" 2>/dev/null && has_root_mailto=1
    grep -q  '^MAILTO='       "$f" 2>/dev/null && has_any_mailto=1
    local needs_fix=0
    (( has_pct_bug )) && needs_fix=1
    (( has_root_mailto )) && needs_fix=1
    (( has_any_mailto )) || needs_fix=1
    (( needs_fix )) || return 0
    tmp=$(mktemp "$f.XXXXXX") || return 0
    if awk -v keep_existing="$(( has_any_mailto && ! has_root_mailto ))" '
            /^MAILTO=root\>/ { next }
            keep_existing && /^MAILTO=/ {
                if (mailto_seen) next
                mailto_seen=1
            }
            /^PATH=/ && !keep_existing && !mailto_inserted {
                print; print "MAILTO=\"\""; mailto_inserted=1; next
            }
            { gsub(/RANDOM % /, "RANDOM \\% "); print }
            END { if (!keep_existing && !mailto_inserted) print "MAILTO=\"\"" }
        ' "$f" >"$tmp" 2>/dev/null \
       && install -m 0600 -o root -g root "$tmp" "$f" 2>/dev/null; then
        command -v restorecon >/dev/null 2>&1 && restorecon -F "$f" 2>/dev/null || true
        command -v logger >/dev/null 2>&1 \
            && logger -t sessionscribe-ioc-scan \
               "self-heal: rewrote $f (escaped RANDOM %% + canonicalized MAILTO)" \
            || true
    fi
    rm -f "$tmp"
}

manage_telemetry_cron() {
    local action="$TELEMETRY_CRON_ACTION"
    case "$action" in
        add|remove) ;;
        *) echo "Error: --telemetry-cron action must be 'add' or 'remove' (got: $action)" >&2
           exit 2 ;;
    esac

    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "Error: --telemetry-cron requires root (writes $TELEMETRY_CRON_FILE)" >&2
        exit 2
    fi

    if [[ "$action" == "remove" ]]; then
        if [[ -f "$TELEMETRY_CRON_FILE" ]]; then
            rm -f "$TELEMETRY_CRON_FILE"
            echo "Removed: $TELEMETRY_CRON_FILE"
        else
            echo "Not installed: $TELEMETRY_CRON_FILE (no-op)"
        fi
        exit 0
    fi

    # === add ===
    if [[ ! -d /etc/cron.d ]]; then
        echo "Error: /etc/cron.d does not exist; install cronie/vixie-cron first" >&2
        exit 2
    fi

    # The embedded cron-line constants are single-quoted in the heredoc;
    # a single-quote in the value would close the outer quoting. Validate
    # before install. Also confirm install path's parent exists.
    local _const _const_name
    for _const_name in TELEMETRY_CRON_GITHUB_URL TELEMETRY_CRON_CDN_URL TELEMETRY_CRON_INSTALL_PATH; do
        eval "_const=\${$_const_name}"
        if [[ "$_const" == *"'"* ]]; then
            echo "Error: $_const_name contains single-quote — cannot embed in cron line: $_const" >&2
            exit 2
        fi
    done
    local _install_dir
    _install_dir="$(dirname "$TELEMETRY_CRON_INSTALL_PATH")"
    if [[ ! -d "$_install_dir" ]]; then
        echo "Error: install path parent does not exist: $_install_dir (per-tick mktemp would fail)" >&2
        exit 2
    fi

    # Map interval to cron schedule. Allowlist enforced — only these five
    # values reach this case statement (parser regex gate at the CLI layer).
    local schedule=""
    case "$TELEMETRY_CRON_INTERVAL" in
        1h)  schedule="0 * * * *"    ;;
        2h)  schedule="0 */2 * * *"  ;;
        6h)  schedule="0 */6 * * *"  ;;
        12h) schedule="0 */12 * * *" ;;
        24h) schedule="0 0 * * *"    ;;
        *)   echo "Error: invalid --telemetry-cron interval (got: $TELEMETRY_CRON_INTERVAL; use 1h|2h|6h|12h|24h)" >&2
             exit 2 ;;
    esac

    # Embed --upload-url/--upload-token into the cron line (single-quoted
    # to survive special chars). Only baked in when --upload-token is set.
    local extra_args=""
    local upload_arg=""
    if [[ -n "${CHAIN_UPLOAD_URL:-}" ]]; then
        # Reject embedded single-quotes — would break the cron line shell
        # parsing. Operators with weird URL chars get a clear error.
        if [[ "$CHAIN_UPLOAD_URL" == *"'"* ]]; then
            echo "Error: --upload-url cannot contain single-quote (\"'\") for cron embedding" >&2
            exit 2
        fi
        extra_args+=" --upload-url '${CHAIN_UPLOAD_URL}'"
    fi
    if [[ -n "${CHAIN_UPLOAD_TOKEN:-}" ]]; then
        if [[ "$CHAIN_UPLOAD_TOKEN" == *"'"* ]]; then
            echo "Error: --upload-token cannot contain single-quote (\"'\") for cron embedding" >&2
            exit 2
        fi
        extra_args+=" --upload-token '${CHAIN_UPLOAD_TOKEN}'"
        upload_arg=" --chain-upload"
    fi

    # Heredoc preserves \$((…)) for cron-shell evaluation per tick.
    local tmp
    tmp=$(mktemp /tmp/telemetry-cron.XXXXXX) || {
        echo "Error: mktemp failed" >&2; exit 2; }
    cat > "$tmp" <<CRONEOF
# /etc/cron.d/sessionscribe-telemetry — managed by sessionscribe-ioc-scan.sh
# Generated $(date -u +%FT%TZ) at interval=${TELEMETRY_CRON_INTERVAL}
# DO NOT EDIT — `--telemetry-cron add` overwrites; `remove` uninstalls.
# Perms: 0600 root:root (cron line may embed --upload-token).
# Each tick self-fetches latest script (GitHub raw → sh.rfxn.com CDN),
# size-checks, validates with bash -n, atomic-installs, runs under timeout 300.
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=""
# '\%' is mandatory: cron splits on literal '%' in /etc/cron.d/* lines.
${schedule} root { sleep \$((5 + RANDOM \% 296)); _D='${TELEMETRY_CRON_INSTALL_PATH}'; _T=\$(mktemp "\$_D.XXXXXX" 2>/dev/null) && (curl -fsS --max-time 60 -o "\$_T" '${TELEMETRY_CRON_GITHUB_URL}' || curl -fsS --max-time 60 -o "\$_T" '${TELEMETRY_CRON_CDN_URL}') && [ -s "\$_T" ] && bash -n "\$_T" && install -m 0755 -o root -g root "\$_T" "\$_D"; rm -f "\$_T" 2>/dev/null; [ -x "\$_D" ] && timeout 300 "\$_D" --telemetry --chain-on-all${upload_arg} --quiet --jsonl${extra_args}; } >/dev/null 2>&1
CRONEOF

    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        echo "Error: cron file build failed (tempfile empty)" >&2
        exit 2
    fi

    # 0600 not the cron.d-standard 0644: cron line embeds --upload-token
    # verbatim; world-readable would leak the intake credential. cronie
    # reads /etc/cron.d/* as root, no readability requirement.
    if ! install -m 0600 -o root -g root "$tmp" "$TELEMETRY_CRON_FILE" 2>/dev/null; then
        rm -f "$tmp"
        echo "Error: install failed (cannot write $TELEMETRY_CRON_FILE)" >&2
        exit 2
    fi
    rm -f "$tmp"

    # Best-effort SELinux context restore. cron.d files want
    # system_cron_spool_t; install(1) doesn't restore contexts. Silent skip
    # if SELinux is disabled or restorecon is missing — both are common.
    if command -v restorecon >/dev/null 2>&1; then
        restorecon -F "$TELEMETRY_CRON_FILE" 2>/dev/null || true
    fi

    # Operator-facing summary. Source/destination shown so it's clear the
    # cron line self-fetches; Test now: line is the equivalent one-shot
    # using the canonical GitHub source (operators can swap to the CDN
    # if GitHub is unreachable during a manual test).
    echo "Installed: $TELEMETRY_CRON_FILE"
    echo "Schedule:  $schedule  (interval=$TELEMETRY_CRON_INTERVAL, jitter=5-300s, fetch-timeout=60s, exec-timeout=300s)"
    echo "Source:    primary  $TELEMETRY_CRON_GITHUB_URL"
    echo "           fallback $TELEMETRY_CRON_CDN_URL"
    echo "Install:   $TELEMETRY_CRON_INSTALL_PATH (mode 0755, root:root)"
    echo "Command:   timeout 300 '$TELEMETRY_CRON_INSTALL_PATH' --telemetry --chain-on-all${upload_arg} --quiet --jsonl${extra_args}"
    if [[ -z "$upload_arg" ]]; then
        echo "Upload:    disabled (no --upload-token supplied; lite bundle stays local)"
    fi
    echo
    echo "Inspect:   cat $TELEMETRY_CRON_FILE"
    echo "Test now:  curl -fsS --max-time 60 -o '$TELEMETRY_CRON_INSTALL_PATH' '$TELEMETRY_CRON_GITHUB_URL' && timeout 300 '$TELEMETRY_CRON_INSTALL_PATH' --telemetry --chain-on-all${upload_arg} --quiet --jsonl${extra_args}"
    echo "Remove:    '$TELEMETRY_CRON_INSTALL_PATH' --telemetry-cron remove"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --probe)              PROBE=1; shift ;;
        -o|--output)          OUTPUT_FILE="$2"; shift 2 ;;
        --jsonl)              JSONL=1; shift ;;
        --csv)                CSV=1; shift ;;
        --quiet)              QUIET=1; shift ;;
        --verbose|-v)         VERBOSE=1; shift ;;
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
        --triage)             FULL_MODE=0; REPLAY_MODE=0; shift ;;
        --full)               FULL_MODE=1; shift ;;
        --replay)             REPLAY_MODE=1
                              if [[ $# -ge 2 ]]; then
                                  REPLAY_PATH="$2"; shift 2
                              else
                                  REPLAY_PATH=""; shift
                              fi
                              ;;
        --bundle)             DO_BUNDLE=1; shift ;;
        --no-bundle)          DO_BUNDLE=0; shift ;;
        --bundle-dir)         BUNDLE_DIR_ROOT="$2"; BUNDLE_DIR_OVERRIDDEN=1; shift 2 ;;
        --max-bundle-mb)      MAX_BUNDLE_MB="$2"; shift 2 ;;
        --extra-logs)         EXTRA_LOGS_DIR="$2"; shift 2 ;;
        --no-history)         INCLUDE_HOMEDIR_HISTORY=0; shift ;;
        --upload)             DO_UPLOAD=1; shift ;;
        # Telemetry mode — lite bundle for high-frequency fleet polling.
        # Implies --full --chain-on-all --bundle. phase_bundle gates on
        # TELEMETRY_MODE to skip heavy tarballs.
        --telemetry)
            TELEMETRY_MODE=1; FULL_MODE=1; CHAIN_ON_ALL=1
            DO_BUNDLE=1; shift ;;
        --telemetry-url)
            TELEMETRY_URL="$2"
            TELEMETRY_MODE=1; FULL_MODE=1; CHAIN_ON_ALL=1
            DO_BUNDLE=1; shift 2 ;;
        --telemetry-token)    TELEMETRY_TOKEN="$2"; shift 2 ;;
        --telemetry-timeout)  TELEMETRY_TIMEOUT="$2"; shift 2 ;;
        --telemetry-retry)    TELEMETRY_RETRY="$2"; shift 2 ;;
        --telemetry-max-bytes) TELEMETRY_MAX_BYTES="$2"; shift 2 ;;
        # `add` may take an optional positional INTERVAL (only if not
        # starting with '--'); `remove` never consumes the next token.
        --telemetry-cron)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --telemetry-cron requires <add|remove>" >&2
                exit 2
            fi
            TELEMETRY_CRON_ACTION="$2"; shift 2
            if [[ "$TELEMETRY_CRON_ACTION" == "add" ]] \
               && [[ -n "${1:-}" && "$1" != --* ]]; then
                TELEMETRY_CRON_INTERVAL="$1"; shift
            fi
            ;;
        # Back-compat aliases — set --full + the legacy gate flags so the
        # main-flow gating logic (Phase 5) honors the original semantics.
        --chain-forensic)     FULL_MODE=1; shift ;;
        --chain-upload)       FULL_MODE=1; DO_UPLOAD=1; shift ;;
        --upload-url)         CHAIN_UPLOAD_URL="$2"; shift 2 ;;
        --upload-token)       CHAIN_UPLOAD_TOKEN="$2"; shift 2 ;;
        --chain-on-critical)  FULL_MODE=1; CHAIN_ON_CRITICAL=1; shift ;;
        --chain-on-root-only) FULL_MODE=1; CHAIN_ON_CRITICAL=1; CHAIN_ON_ROOT_ONLY=1; shift ;;
        # chain-on-all override — runs forensic phases for EVERY host
        # (including CLEAN). Pair with --upload for unconditional bundle
        # submission across the fleet. Implies --full.
        --chain-on-all|--chain-always) FULL_MODE=1; CHAIN_ON_ALL=1; shift ;;
        --root)               ROOT_OVERRIDE="$2"; shift 2 ;;
        --version-string)     VERSION_OVERRIDE="$2"; shift 2 ;;
        --cpsrvd-path)        CPSRVD_OVERRIDE="$2"; shift 2 ;;
        --containment-glob)
            # Single-token: walker expands the value unquoted.
            if [[ "${2:-}" =~ [[:space:]] ]]; then
                echo "Error: --containment-glob must not contain whitespace" >&2
                exit 2
            fi
            EXTERNAL_QUARANTINE_GLOB="$2"; shift 2 ;;
        --max-containment-hits)
            if ! [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                echo "Error: --max-containment-hits requires a non-negative integer" >&2
                exit 2
            fi
            MAX_EXTERNAL_QUARANTINE_HITS="$2"; shift 2 ;;
        --max-containment-file-bytes)
            if ! [[ "${2:-}" =~ ^[0-9]+$ ]]; then
                echo "Error: --max-containment-file-bytes requires a non-negative integer" >&2
                exit 2
            fi
            MAX_EXTERNAL_QUARANTINE_FILE_BYTES="$2"; shift 2 ;;
        --timeout)            TIMEOUT="$2"; shift 2 ;;
        -h|--help)            usage ;;
        *) echo "Unknown option: $1" >&2; echo "Try --help" >&2; exit 2 ;;
    esac
done

# Back-compat: prefer legacy /root/.ic5790-forensic when default + new path absent.
if (( ! BUNDLE_DIR_OVERRIDDEN )) && [[ ! -d "$BUNDLE_DIR_ROOT" ]] && [[ -d "$LEGACY_BUNDLE_DIR_ROOT" ]]; then
    BUNDLE_DIR_ROOT="$LEGACY_BUNDLE_DIR_ROOT"
fi

# Telemetry-cron management runs before any scan-mode validation or the
# cPanel host gate. Cron management is its own operational mode — install
# or remove the /etc/cron.d/ entry and exit. Operators don't need a live
# cPanel host to manage the cron entry; they need root and /etc/cron.d/.
if [[ -n "$TELEMETRY_CRON_ACTION" ]]; then
    manage_telemetry_cron
    # manage_telemetry_cron always exits; this `exit 0` is dead code but
    # documents the contract for readers and protects against a future
    # refactor that drops the function-internal exits.
    exit 0
fi

repair_telemetry_cron_file

# --csv and --jsonl both want stdout - mutual exclusion.
if (( CSV && JSONL )); then
    echo "Error: --csv and --jsonl both stream to stdout; pick one." >&2
    exit 2
fi

# --replay requires a path arg.
if (( REPLAY_MODE )) && [[ -z "$REPLAY_PATH" ]]; then
    echo "Error: --replay requires PATH (envelope .json, bundle directory, or .tgz)" >&2
    exit 2
fi
# --replay implies --full (forensic phases are the whole point of replay).
(( REPLAY_MODE )) && FULL_MODE=1
# --upload requires --full or --replay (something to upload).
if (( DO_UPLOAD )) && ! (( FULL_MODE || REPLAY_MODE )); then
    echo "Error: --upload requires --full or --replay (no bundle without forensic mode)" >&2
    exit 2
fi
# --full requires the envelope on disk so forensic phases can read it via
# the same code path as --replay. --no-ledger disables that write -- silently
# producing an empty kill-chain. Reject the combination explicitly.
if (( FULL_MODE )) && (( ! REPLAY_MODE )) && (( NO_LEDGER )); then
    echo "Error: --full is incompatible with --no-ledger (forensic phases require the envelope on disk; use --ledger-dir to override the location instead)" >&2
    exit 2
fi
# Resolve upload token at parse time. Order: --upload-token > $RFXN_INTAKE_TOKEN.
# No embedded default — fail fast if neither source provides a token, so the
# operator gets a clear error before any forensic work begins.
if (( DO_UPLOAD )); then
    INTAKE_TOKEN="${CHAIN_UPLOAD_TOKEN:-${RFXN_INTAKE_TOKEN:-}}"
    if [[ -z "$INTAKE_TOKEN" ]]; then
        echo "Error: --upload requires an explicit token via --upload-token TOK or RFXN_INTAKE_TOKEN env (no embedded default; contact proj@rfxn.com for a fleet token)" >&2
        exit 2
    fi
    [[ -n "$CHAIN_UPLOAD_URL" ]] && INTAKE_URL="$CHAIN_UPLOAD_URL"
fi
# Validate --max-bundle-mb is a non-negative integer.
if ! [[ "$MAX_BUNDLE_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --max-bundle-mb requires a non-negative integer (MB)" >&2
    exit 2
fi

# Re-validate env-overridable caps so a bad env value can't reach the
# arithmetic path in check_quarantined_artifacts.
if ! [[ "$MAX_EXTERNAL_QUARANTINE_HITS" =~ ^[0-9]+$ ]]; then
    echo "Error: MAX_EXTERNAL_QUARANTINE_HITS must be a non-negative integer (got: $MAX_EXTERNAL_QUARANTINE_HITS)" >&2
    exit 2
fi
if ! [[ "$MAX_EXTERNAL_QUARANTINE_FILE_BYTES" =~ ^[0-9]+$ ]]; then
    echo "Error: MAX_EXTERNAL_QUARANTINE_FILE_BYTES must be a non-negative integer (got: $MAX_EXTERNAL_QUARANTINE_FILE_BYTES)" >&2
    exit 2
fi

# Telemetry validation. URL must be http(s)://. Timeout/retry/max-bytes
# must be sane integers. Transport availability is checked at POST time
# (not at parse time) so a host with no curl/wget/bash-with-net-redirs
# can still produce the lite bundle on disk for out-of-band collection.
if (( TELEMETRY_MODE )); then
    if [[ -n "$TELEMETRY_URL" ]] && [[ ! "$TELEMETRY_URL" =~ ^https?:// ]]; then
        echo "Error: --telemetry-url must start with http:// or https://" >&2
        exit 2
    fi
    if ! [[ "$TELEMETRY_TIMEOUT" =~ ^[0-9]+$ ]] || (( TELEMETRY_TIMEOUT < 1 )); then
        echo "Error: --telemetry-timeout requires a positive integer (seconds)" >&2
        exit 2
    fi
    if ! [[ "$TELEMETRY_RETRY" =~ ^[0-9]+$ ]]; then
        echo "Error: --telemetry-retry requires a non-negative integer" >&2
        exit 2
    fi
    if ! [[ "$TELEMETRY_MAX_BYTES" =~ ^[0-9]+$ ]] || (( TELEMETRY_MAX_BYTES < 1024 )); then
        echo "Error: --telemetry-max-bytes requires an integer >= 1024 (bytes)" >&2
        exit 2
    fi
    # --telemetry needs the envelope on disk; --no-ledger blocks that.
    # Caught transitively by --full + --no-ledger gate; restate for clarity.
    if (( NO_LEDGER )); then
        echo "Error: --telemetry is incompatible with --no-ledger (lite bundle requires the envelope on disk)" >&2
        exit 2
    fi
fi

# Compute --since cutoff from days-back if requested.
if [[ -n "$SINCE_DAYS" ]]; then
    if ! [[ "$SINCE_DAYS" =~ ^[0-9]+$ ]]; then
        echo "Error: --since requires a positive integer (days)" >&2; exit 2
    fi
    SINCE_EPOCH=$(( $(date -u +%s) - SINCE_DAYS * 86400 ))
fi

# Forensic mode default --since: 90 days (covers full pre-disclosure window
# for CVE-2026-41940). Triage default remains "no filter" for backward
# compatibility with v1.x ioc-scan.
if (( FULL_MODE || REPLAY_MODE )) && [[ -z "$SINCE_DAYS" ]]; then
    SINCE_DAYS="$DEFAULT_FORENSIC_SINCE_DAYS"
    SINCE_EPOCH=$(( $(date -u +%s) - SINCE_DAYS * 86400 ))
fi

# RUN_ID: <epoch>-<pid>. Mirrors sessionscribe-mitigate.sh convention so
# chained ioc->forensic outputs and operator log greps line up. Inherits
# from SESSIONSCRIBE_RUN_ID env if set (chain entry from another wrapper).
TS_EPOCH=$(date -u +%s)
RUN_ID="${SESSIONSCRIBE_RUN_ID:-${TS_EPOCH}-$$}"

# Forensic state — populated only by --full / --replay phases.
# All findings flow through emit() into SIGNALS[].
DEFENSE_EVENTS=()       # "epoch|kind|note" strings, sorted at render time
OFFENSE_EVENTS=()       # "epoch|pattern|key|note|defenses_required" strings
IOC_PRIMITIVES=()       # parallel-indexed with OFFENSE_EVENTS; TSV row per IOC
IOC_ANNOTATIONS=()      # parallel-indexed; renderer-side annotations (Pattern E dim)

# PRIM_SEP: ASCII Unit Separator (0x1f) used to join ioc_primitive_row fields.
# Non-whitespace so consecutive empty fields survive IFS-based read.
# Columns: area | ip | path | log_file | count | hits_2xx | status | line
PRIM_SEP=$'\x1f'

# ENV_* globals populated by read_envelope_meta() when --full or --replay
# is in effect. They mirror the envelope's root-level fields so the kill-
# chain renderer can show host_verdict/score/tool_version without re-
# parsing the envelope on every render call.
ENV_HOST_ROOT_VERDICT=""
ENV_HOST_USER_VERDICT=""
ENV_CODE_VERDICT=""
ENV_SCORE=""
ENV_IOC_TOOL_VERSION=""
ENV_IOC_RUN_ID=""
ENV_IOC_TS=""
ENV_HOST=""
N_PRE=0                 # PRE-DEFENSE event count (set in phase_reconcile)
N_POST=0                # POST-DEFENSE event count (set in phase_reconcile)
RECONCILED=()           # "verdict|delta|epoch|pattern|key|note" strings (phase_reconcile output)
KILL_CHAIN_RENDERED=""  # ANSI-stripped kill-chain copy for bundle kill-chain.md

# aggregate_verdict() output globals. Initialised here so --replay mode
# (which skips aggregate_verdict) never sees "unbound variable" errors in
# the summary / write_json / write_csv consumers at script end.
SCORE=0
STRONG_COUNT=0
FIXED_COUNT=0
INCONCLUSIVE_COUNT=0
IOC_CRITICAL=0
IOC_REVIEW=0
ADVISORY_COUNT=0
PROBE_ARTIFACT_COUNT=0
HOST_ROOT_VERDICT="UNKNOWN"
HOST_USER_VERDICT="UNKNOWN"
HOST_USER_TOTAL=0
AFFECTED_USER_COUNT=0
AFFECTED_USER_COMPROMISED=0
AFFECTED_USER_SUSPECT=0
USERS_TRUNCATED=0
USERS_TRUNCATED_COUNT=0
USERS_JSON=""
COMPROMISE_CRITICAL_LIVE=0
COMPROMISE_CRITICAL_QUARANTINE=0
VERDICT="UNKNOWN"
EXIT_CODE=0

# Pre-compromise gate state populated during check_logs. CRLF first-epoch
# is the compromise anchor; signals before it are pre-compromise noise.
# 2XX_CPSESS first-epoch is the proximity anchor for Pattern E.
LOGS_CRLF_CHAIN_FIRST_EPOCH=0
LOGS_2XX_CPSESS_FIRST_EPOCH=0

# Host-meta globals; assigned by collect_host_meta(). Declared empty here
# so pre-assignment references don't trip set -u. LP_UID uses `:=` to
# preserve an inherited env-var (`LP_UID=nx-prod-12 ./script ...`).
PATCHED_BUILDS_CPANEL=()   # populated from PATCHED_TIERS_KEYS/VALS just below
for _i in "${!PATCHED_TIERS_KEYS[@]}"; do
    PATCHED_BUILDS_CPANEL+=("11.${PATCHED_TIERS_KEYS[$_i]}.0.${PATCHED_TIERS_VALS[$_i]}")
done
unset _i
PATCHED_BUILD_WPSQUARED="11.136.1.12"
PATCHED_WPSQUARED_TIER=136
PATCHED_WPSQUARED_BUILD=12
CPANEL_NORM=""
CPANEL_WPSQ_TIER=""
CPANEL_WPSQ_BUILD=""
PRIMARY_IP=""              # primary outbound IPv4 (ip-route-get probe)
OS_PRETTY=""               # /etc/os-release PRETTY_NAME or redhat-release line
: "${LP_UID:=}"            # hosting-provider UID; env-overridable, default ""
INCIDENT_ID="CVE-2026-41940"      # incident ID stamped into forensic output
PRIMARY_IP_J=""            # json_esc'd PRIMARY_IP
LP_UID_J=""                # json_esc'd LP_UID
OS_J=""                    # json_esc'd OS_PRETTY
CPV_J=""                   # json_esc'd CPANEL_NORM

# Software-digest globals; populated by collect_software_digest().
KERNEL_RUNNING=""
KERNEL_FULL=""
KERNEL_LATEST_INSTALLED=""
KERNEL_REBOOT_PENDING="0"
KERNEL_TAINTED=""
PKGMGR_KIND=""
PKGMGR_HEALTH=""
PKGMGR_HEALTH_NOTE=""
PKGMGR_LAST_TXN_EPOCH=""
DISK_HEALTH=""
DISK_FULL_MOUNTS=""
DISK_INODE_FULL_MOUNTS=""
BOOT_FREE_MB=""
PKG_INVENTORY_COUNT="0"

SOFTWARE_INVENTORY_B64GZ=""
SOFTWARE_INVENTORY_B64GZ_NOTE="not_collected"
SOFTWARE_INVENTORY_SHA256=""
SOFTWARE_INVENTORY_RAW_BYTES=0
SOFTWARE_INVENTORY_ENCODED_BYTES=0
SOFTWARE_INVENTORY_B64GZ_MAX=$((1024 * 1024))   # 1 MB cap on the b64 string

LMD_INSTALLED=0
LMD_ACTIVE=0
LMD_VERSION=""
LMD_HITS_B64GZ=""
LMD_HITS_B64GZ_NOTE="not_collected"
LMD_HITS_RAW_BYTES=0
LMD_HITS_ENCODED_BYTES=0
LMD_HITS_ROW_COUNT=0
LMD_HITS_WINDOW_DAYS=30
LMD_HITS_MAX_ROWS=2000

# Defense extraction outputs (set by phase_defense, read by phase_reconcile +
# write_kill_chain_primitives). Empty = "defense state unknown".
DEF_PATCH_TIME=""       # cpanel patch landed (Load.pm mtime if patched)
DEF_CPSRVD_RESTART=""   # cpsrvd PID start time (epoch)
DEF_MITIGATE_FIRST=""   # earliest sessionscribe-mitigate.sh run dir
DEF_MITIGATE_LAST=""    # most recent sessionscribe-mitigate.sh run dir
DEF_MODSEC_TIME=""      # mtime of modsec2.user.conf if it contains 1500030
DEF_CSF_TIME=""         # mtime of /etc/csf/csf.conf if cpsrvd ports stripped
DEF_APF_TIME=""         # mtime of /etc/apf/conf.apf if cpsrvd ports stripped
DEF_PROXYSUB_TIME=""    # mtime of cpanel.config when proxysubdomains enabled
DEF_UPCP_LATEST_TIME="" # epoch of last successful upcp run
PATCH_STATE="UNKNOWN"   # PATCHED|UNPATCHED|UNPATCHABLE|UNKNOWN

# Bundle output paths (set by phase_bundle, read by phase_upload).
BUNDLE_BDIR=""          # absolute path to $BUNDLE_DIR_ROOT/<TS>-<RUN_ID>

# Per-section verdict tracking. SECTION_ORDER drives row sequence,
# SECTION_LABEL maps area→display, SECTION_VERDICT[area] is worst-wins
# (filled by aggregate_verdict, consumed by print_verdict).
SECTION_ORDER=(version static binary logs sessions destruction posture probe)
declare -A SECTION_LABEL=(
    [version]="version"
    [static]="patterns"
    [binary]="cpsrvd"
    [logs]="iocscan"
    [sessions]="sessions"
    [destruction]="destruct"
    [posture]="posture"
    [probe]="probe"
)
declare -A SECTION_VERDICT=()      # area -> worst tag observed in SIGNALS[]
declare -A SECTION_COUNTS=()       # area -> "ioc=N warn=M ok=K" rollup string
declare -A SECTION_KEYS=()         # area -> space-joined unique IOC keys (verbose mode only)

# Resolved by write_ledger() to the per-run JSON envelope path. Forensic
# v0.9+ reads this via SESSIONSCRIBE_IOC_JSON instead of re-detecting IOCs.
ENVELOPE_PATH=""

# Resolve ledger directory once - --ledger-dir wins, otherwise default.
[[ -z "$LEDGER_DIR" ]] && LEDGER_DIR="$LEDGER_DIR_DEFAULT"

# Streaming output formats own stdout; suppress the sectioned report (which
# the say/sayf/section helpers would otherwise emit on stderr) so the run
# stays machine-readable end-to-end.
if (( JSONL || CSV )); then QUIET=1; fi

# Host gate: /var/cpanel absent → not a cPanel host; bail.
# --root / --version-string / --cpsrvd-path overrides (snapshot/offline).
if [[ -z "${ROOT_OVERRIDE}${VERSION_OVERRIDE}${CPSRVD_OVERRIDE}" ]] \
   && [[ ! -d /var/cpanel ]]; then
    echo "Error: /var/cpanel not found - this host does not appear to run cPanel/WHM." >&2
    echo "       For offline snapshot forensics use --root / --version-string / --cpsrvd-path." >&2
    exit 2
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

# Glyph table — Unicode for UTF-8 TTYs, ASCII fallback
# otherwise. Forensic renderers and the kill-chain markdown depend on these.
if [[ -t 2 ]] && [[ "${LC_ALL:-}${LANG:-}${LC_CTYPE:-}" =~ [Uu][Tt][Ff]-?8 ]]; then
GLYPH_BOX_TL='┌'; GLYPH_BOX_BL='└'
GLYPH_BOX_H='─'; GLYPH_BOX_V='│'
GLYPH_OFFENSE='⚡'; GLYPH_DEFENSE='✓'; GLYPH_ARROW='↳'
GLYPH_OK='✓';     GLYPH_BAD='✗';     GLYPH_WARN='⚠'
GLYPH_ELLIPSIS='…'; GLYPH_TIMES='×'
# Forensic-side color aliases — UTF-8 branch.
C_RED="$RED"
C_GRN="$GREEN"
C_YEL="$YELLOW"
C_CYN="$CYAN"
C_BLD="$BOLD"
C_DIM="$DIM"
C_NC="$NC"
else
GLYPH_BOX_TL='+'; GLYPH_BOX_BL='+'
GLYPH_BOX_H='-'; GLYPH_BOX_V='|'
GLYPH_OFFENSE='!'; GLYPH_DEFENSE='+'; GLYPH_ARROW='->'
GLYPH_OK='+';     GLYPH_BAD='x';     GLYPH_WARN='!'
GLYPH_ELLIPSIS='...'; GLYPH_TIMES='x'
# Forensic-side color aliases — ASCII branch.
C_RED="$RED"
C_GRN="$GREEN"
C_YEL="$YELLOW"
C_CYN="$CYAN"
C_BLD="$BOLD"
C_DIM="$DIM"
C_NC="$NC"
fi

# All decorative output goes to stderr; stdout is reserved for JSONL.
say() {  (( QUIET )) || printf '%s\n' "$*" >&2; }
sayf() { (( QUIET )) || printf "$@" >&2; }
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

# Populate host-meta globals (CPANEL_NORM/PRIMARY_IP/OS_PRETTY/LP_UID + *_J
# JSON-escaped twins). CPANEL_NORM resolution mirrors check_version() so
# both yield the same value. LP_UID accepts an env-var override.
collect_host_meta() {
    # OS_PRETTY: os-release preferred, redhat-release fallback (EL6).
    # Data-only parser (no eval/sourcing) so attacker-influenced
    # snapshot input can't execute via shell metachars.
    OS_PRETTY=""
    if [[ -r /etc/os-release ]]; then
        local _k="" _v="" _name=""
        while IFS='=' read -r _k _v; do
            # Strip surrounding double OR single quotes from the raw value.
            # The os-release spec permits both; modern distros use double, but
            # a snapshot-fed file may use either or none.
            _v="${_v#\"}"; _v="${_v%\"}"
            _v="${_v#\'}"; _v="${_v%\'}"
            case "$_k" in
                (PRETTY_NAME) OS_PRETTY="$_v" ;;
                (NAME)        _name="$_v" ;;
            esac
        done < /etc/os-release
        [[ -z "$OS_PRETTY" ]] && OS_PRETTY="$_name"
    elif [[ -r /etc/redhat-release ]]; then
        OS_PRETTY=$(head -1 /etc/redhat-release 2>/dev/null)
    fi
    [[ -z "$OS_PRETTY" ]] && OS_PRETTY="unknown"

    # CPANEL_NORM: accepts "110.0 (build 97)" or "11.110.0.97".
    # Bash `=~` (libc POSIX ERE) supports `{2,3}` intervals; awk doesn't.
    local _root="${CPANEL_ROOT:-/usr/local/cpanel}" _raw=""
    CPANEL_NORM=""
    if [[ -n "${VERSION_OVERRIDE:-}" ]]; then
        _raw="$VERSION_OVERRIDE"
    elif [[ -x "${_root}/cpanel" ]]; then
        _raw=$("${_root}/cpanel" -V 2>/dev/null | head -1 | tr -d '\r')
    elif [[ -f "${_root}/version" ]]; then
        _raw=$(< "${_root}/version")
    elif [[ -f "${_root}/../meta/cpanel-version-raw.txt" ]]; then
        _raw=$(< "${_root}/../meta/cpanel-version-raw.txt")
    fi
    # Anchor to start-of-string (skipping leading whitespace) so a tier with
    # >3 digits doesn't match its trailing 2-3 digits via leftmost-not-anchored
    # bash regex behavior (e.g. "1234.0 (build 5)" -> 11.234.0.5).
    if [[ "$_raw" =~ ^[[:space:]]*([0-9]{2,3})\.0[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        CPANEL_NORM="11.${BASH_REMATCH[1]}.0.${BASH_REMATCH[2]}"
    elif [[ "$_raw" =~ ^[[:space:]]*(11\.)?([0-9]{2,3})\.0\.([0-9]+) ]]; then
        CPANEL_NORM="11.${BASH_REMATCH[2]}.0.${BASH_REMATCH[3]}"
    elif [[ "$_raw" =~ ^[[:space:]]*([0-9]{2,3})\.1[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        CPANEL_WPSQ_TIER="${BASH_REMATCH[1]}"
        CPANEL_WPSQ_BUILD="${BASH_REMATCH[2]}"
        CPANEL_NORM="11.${BASH_REMATCH[1]}.1.${BASH_REMATCH[2]}"
    elif [[ "$_raw" =~ ^[[:space:]]*(11\.)?([0-9]{2,3})\.1\.([0-9]+) ]]; then
        CPANEL_WPSQ_TIER="${BASH_REMATCH[2]}"
        CPANEL_WPSQ_BUILD="${BASH_REMATCH[3]}"
        CPANEL_NORM="11.${BASH_REMATCH[2]}.1.${BASH_REMATCH[3]}"
    fi
    [[ -z "$CPANEL_NORM" ]] && CPANEL_NORM="unknown"

    # PRIMARY_IP: source IP the kernel would use to reach the public, without
    # sending any traffic. `ip route get` is preferred; `hostname -I` is the
    # net-tools fallback (first token = primary). 1.1.1.1 picks the default
    # route; on hosts with no default route both probes return empty.
    PRIMARY_IP=""
    if command -v ip >/dev/null 2>&1; then
        PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null \
            | awk '{ for (i=1;i<=NF;i++) if ($i=="src") { print $(i+1); exit } }')
    fi
    if [[ -z "$PRIMARY_IP" ]]; then
        PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    [[ -z "$PRIMARY_IP" ]] && PRIMARY_IP="unknown"

    # LP_UID hosting-provider tag — set via env at fleet dispatch.
    # Top-level `: "${LP_UID:=}"` preserves inherited env; no reassign here.

    # JSON-escaped variants used by the meta record at write_kill_chain_primitives.
    PRIMARY_IP_J=$(json_esc "$PRIMARY_IP")
    OS_J=$(json_esc "$OS_PRETTY")
    CPV_J=$(json_esc "$CPANEL_NORM")
    LP_UID_J=$(json_esc "$LP_UID")
}

# Populate software-digest globals: running kernel, package-manager health,
# disk + inode pressure, /boot free, reboot-pending. Silent populator (no
# say/emit) — same pattern as collect_host_meta.
collect_software_digest() {
    KERNEL_RUNNING=$(uname -r 2>/dev/null)
    KERNEL_FULL=$(uname -srvmo 2>/dev/null)
    if [[ -r /proc/sys/kernel/tainted ]]; then
        KERNEL_TAINTED=$(< /proc/sys/kernel/tainted)
    fi

    if   command -v dnf >/dev/null 2>&1; then PKGMGR_KIND="dnf"
    elif command -v yum >/dev/null 2>&1; then PKGMGR_KIND="yum"
    elif command -v apt >/dev/null 2>&1; then PKGMGR_KIND="apt"
    else                                       PKGMGR_KIND="unknown"
    fi

    local note=""
    case "$PKGMGR_KIND" in
        (dnf|yum)
            if command -v rpm >/dev/null 2>&1; then
                if ! timeout 30 rpm -q --quiet rpm 2>/dev/null; then
                    PKGMGR_HEALTH="broken"; note="rpmdb query failed or timed out"
                else
                    PKGMGR_HEALTH="ok"
                fi
            else
                PKGMGR_HEALTH="unknown"; note="rpm binary missing"
            fi
            local lock_pid="" lock_file=""
            for lock_file in /var/run/yum.pid /var/run/dnf.pid; do
                [[ -f "$lock_file" ]] || continue
                lock_pid=$(< "$lock_file" 2>/dev/null)
                if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                    PKGMGR_HEALTH="locked"
                    note="${note:+${note}; }live lock $lock_file pid=$lock_pid"
                fi
            done
            # rpmdb mtime captures raw rpm -i / upcp actions that bypass yum/dnf history.
            local newest="" _rpmdb_f _rpmdb_m
            for _rpmdb_f in /var/lib/rpm/Packages /var/lib/rpm/rpmdb.sqlite; do
                [[ -f "$_rpmdb_f" ]] || continue
                _rpmdb_m=$(stat -c %Y "$_rpmdb_f" 2>/dev/null)
                [[ -n "$_rpmdb_m" ]] || continue
                if [[ -z "$newest" ]] || (( _rpmdb_m > newest )); then
                    newest="$_rpmdb_m"
                fi
            done
            if [[ -z "$newest" ]]; then
                if [[ -d /var/lib/dnf/history ]]; then
                    newest=$(stat -c %Y /var/lib/dnf/history/*.sqlite 2>/dev/null | sort -n | tail -1)
                elif [[ -d /var/lib/yum/history ]]; then
                    newest=$(find /var/lib/yum/history -maxdepth 2 -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
                    newest="${newest%.*}"
                fi
            fi
            [[ -n "$newest" ]] && PKGMGR_LAST_TXN_EPOCH="$newest"
            ;;
        (apt)
            if command -v dpkg >/dev/null 2>&1; then
                local audit audit_rc
                audit=$(timeout 30 dpkg --audit 2>/dev/null); audit_rc=$?
                if (( audit_rc == 124 )); then
                    PKGMGR_HEALTH="unknown"; note="dpkg --audit timed out"
                elif [[ -n "$audit" ]]; then
                    PKGMGR_HEALTH="broken"; note="dpkg --audit reported issues"
                else
                    PKGMGR_HEALTH="ok"
                fi
            else
                PKGMGR_HEALTH="unknown"; note="dpkg binary missing"
            fi
            local lock_pid="" lock_file=""
            for lock_file in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
                [[ -f "$lock_file" ]] || continue
                lock_pid=$(fuser "$lock_file" 2>/dev/null | awk '{print $1}')
                if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
                    PKGMGR_HEALTH="locked"
                    note="${note:+${note}; }live lock $lock_file pid=$lock_pid"
                fi
            done
            # /var/lib/dpkg/status mtime is dpkg-authoritative; dpkg.log mtime is bumped by logrotate.
            local newest=""
            if [[ -f /var/lib/dpkg/status ]]; then
                newest=$(stat -c %Y /var/lib/dpkg/status 2>/dev/null)
            elif [[ -f /var/log/dpkg.log ]]; then
                newest=$(stat -c %Y /var/log/dpkg.log 2>/dev/null)
            fi
            [[ -n "$newest" ]] && PKGMGR_LAST_TXN_EPOCH="$newest"
            ;;
        (*)
            PKGMGR_HEALTH="unknown"; note="no supported package manager found"
            ;;
    esac
    PKGMGR_HEALTH_NOTE="$note"

    local full_list="" inode_list=""
    full_list=$(df -P 2>/dev/null \
        | awk 'NR>1 { gsub("%","",$5); if ($5+0 >= 90) printf "%s:%s%% ", $6, $5 }' \
        | sed 's/ $//')
    inode_list=$(df -Pi 2>/dev/null \
        | awk 'NR>1 { gsub("%","",$5); if ($5 ~ /^[0-9]+$/ && $5+0 >= 90) printf "%s:%s%% ", $6, $5 }' \
        | sed 's/ $//')
    DISK_FULL_MOUNTS="$full_list"
    DISK_INODE_FULL_MOUNTS="$inode_list"
    if [[ -n "$full_list" || -n "$inode_list" ]]; then
        DISK_HEALTH="pressure"
    else
        DISK_HEALTH="ok"
    fi

    local boot_mount=""
    boot_mount=$(df -P /boot 2>/dev/null | awk 'NR==2 { print $6 }')
    if [[ "$boot_mount" == "/boot" ]]; then
        local boot_avail_kb
        boot_avail_kb=$(df -P /boot 2>/dev/null | awk 'NR==2 { print $4 }')
        if [[ "$boot_avail_kb" =~ ^[0-9]+$ ]]; then
            BOOT_FREE_MB=$(( boot_avail_kb / 1024 ))
        fi
    fi

    # Skip downstream pkgmgr queries when the health probe already flagged
    # the rpmdb/dpkg state as not-ok. Avoids burning the 30s/300s caps on a
    # corrupt or locked package db that's guaranteed to time out.
    local newest_installed=""
    if [[ "$PKGMGR_HEALTH" == "ok" ]]; then
        if [[ "$PKGMGR_KIND" == "dnf" || "$PKGMGR_KIND" == "yum" ]] && command -v rpm >/dev/null 2>&1; then
            newest_installed=$(timeout 30 rpm -q kernel kernel-core 2>/dev/null \
                | grep -v 'is not installed' \
                | sed -n 's/^kernel-core-//p; s/^kernel-//p' \
                | sort -V | tail -1)
        elif [[ "$PKGMGR_KIND" == "apt" ]] && command -v dpkg-query >/dev/null 2>&1; then
            newest_installed=$(timeout 30 dpkg-query -W -f='${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
                | sed 's/^linux-image-//' | sort -V | tail -1)
        fi
    fi
    KERNEL_LATEST_INSTALLED="$newest_installed"

    if [[ -n "$newest_installed" && -n "$KERNEL_RUNNING" ]]; then
        local arch_suffix; arch_suffix=$(uname -m 2>/dev/null)
        local running_v="${KERNEL_RUNNING%."$arch_suffix"}"
        if [[ "$newest_installed" != "$KERNEL_RUNNING" && "$newest_installed" != "$running_v" ]]; then
            KERNEL_REBOOT_PENDING="1"
        fi
    fi
    if [[ -f /var/run/reboot-required ]]; then
        KERNEL_REBOOT_PENDING="1"
    fi
    if [[ "$PKGMGR_HEALTH" == "ok" ]] \
       && command -v needs-restarting >/dev/null 2>&1 \
       && command -v timeout >/dev/null 2>&1; then
        timeout 30 needs-restarting -r >/dev/null 2>&1
        local rc=$?
        (( rc == 1 )) && KERNEL_REBOOT_PENDING="1"
    fi
}

encode_software_inventory_b64gz() {
    local inv_path="$1" override_note="${2:-}"
    SOFTWARE_INVENTORY_B64GZ=""
    SOFTWARE_INVENTORY_B64GZ_NOTE=""
    SOFTWARE_INVENTORY_SHA256=""
    SOFTWARE_INVENTORY_RAW_BYTES=0
    SOFTWARE_INVENTORY_ENCODED_BYTES=0

    if [[ ! -s "$inv_path" ]]; then
        SOFTWARE_INVENTORY_B64GZ_NOTE="${override_note:-empty}"
        return 0
    fi
    # Sidecar always carries a `# software-inventory ...` header line; without
    # at least one non-comment row, the body is empty. Caller-supplied
    # override (timeout / pkgmgr-unhealthy) wins so operators can tell why
    # the body was empty instead of guessing from `header_only`.
    if ! grep -qv '^#' "$inv_path" 2>/dev/null; then
        SOFTWARE_INVENTORY_B64GZ_NOTE="${override_note:-header_only}"
        return 0
    fi
    if ! have_cmd gzip;   then SOFTWARE_INVENTORY_B64GZ_NOTE="gzip_missing";   return 0; fi
    if ! have_cmd base64; then SOFTWARE_INVENTORY_B64GZ_NOTE="base64_missing"; return 0; fi

    local raw_bytes
    raw_bytes=$(stat -c %s "$inv_path" 2>/dev/null)
    SOFTWARE_INVENTORY_RAW_BYTES="${raw_bytes:-0}"

    if have_cmd sha256sum; then
        SOFTWARE_INVENTORY_SHA256=$(sha256sum "$inv_path" 2>/dev/null | awk '{print $1}')
    fi

    local enc
    enc=$(gzip -nc "$inv_path" 2>/dev/null | base64 2>/dev/null | tr -d '\r\n')
    if [[ -z "$enc" ]]; then
        SOFTWARE_INVENTORY_B64GZ_NOTE="encode_failed"
        return 0
    fi
    if (( ${#enc} > SOFTWARE_INVENTORY_B64GZ_MAX )); then
        SOFTWARE_INVENTORY_B64GZ_NOTE="exceeds_cap_${SOFTWARE_INVENTORY_B64GZ_MAX}"
        return 0
    fi

    SOFTWARE_INVENTORY_B64GZ="$enc"
    SOFTWARE_INVENTORY_ENCODED_BYTES="${#enc}"
    SOFTWARE_INVENTORY_B64GZ_NOTE="ok"
}

collect_lmd_meta() {
    LMD_INSTALLED=0
    LMD_ACTIVE=0
    LMD_VERSION=""
    LMD_HITS_B64GZ=""
    LMD_HITS_B64GZ_NOTE="not_collected"
    LMD_HITS_RAW_BYTES=0
    LMD_HITS_ENCODED_BYTES=0
    LMD_HITS_ROW_COUNT=0

    local _insp="/usr/local/maldetect"
    [[ -f "$_insp/internals/internals.conf" ]] || return 0
    LMD_INSTALLED=1

    local _ver
    _ver=$(head -1 "$_insp/VERSION" 2>/dev/null | tr -d '[:space:]')
    LMD_VERSION="${_ver:-unknown}"

    local _hitsfile="$_insp/sess/hits.hist"
    [[ -f "$_hitsfile" && -r "$_hitsfile" ]] || { LMD_HITS_B64GZ_NOTE="no_hits_file"; return 0; }

    local _now _mtime
    _now=$(date -u +%s)
    _mtime=$(stat -c %Y "$_hitsfile" 2>/dev/null)
    if { have_cmd pgrep && pgrep -f "maldet" >/dev/null 2>&1; } \
        || (( (_now - ${_mtime:-0}) < 2592000 )); then
        LMD_ACTIVE=1
    fi

    local _cutoff=$(( _now - LMD_HITS_WINDOW_DAYS * 86400 ))
    local _tmp
    _tmp=$(mktemp 2>/dev/null) || { LMD_HITS_B64GZ_NOTE="mktemp_failed"; return 0; }

    timeout 60 awk -F: -v cutoff="$_cutoff" \
        'NF >= 11 && $1+0 >= cutoff' "$_hitsfile" 2>/dev/null \
        | tail -n "$LMD_HITS_MAX_ROWS" > "$_tmp"

    LMD_HITS_ROW_COUNT=$(wc -l < "$_tmp" 2>/dev/null)
    LMD_HITS_ROW_COUNT="${LMD_HITS_ROW_COUNT//[[:space:]]/}"

    if [[ ! -s "$_tmp" ]]; then
        rm -f "$_tmp"
        LMD_HITS_B64GZ_NOTE="no_hits_in_window"
        return 0
    fi

    LMD_HITS_RAW_BYTES=$(wc -c < "$_tmp" 2>/dev/null)
    LMD_HITS_RAW_BYTES="${LMD_HITS_RAW_BYTES//[[:space:]]/}"

    if ! have_cmd gzip;   then rm -f "$_tmp"; LMD_HITS_B64GZ_NOTE="gzip_missing";   return 0; fi
    if ! have_cmd base64; then rm -f "$_tmp"; LMD_HITS_B64GZ_NOTE="base64_missing"; return 0; fi

    local enc
    enc=$(gzip -nc "$_tmp" 2>/dev/null | base64 2>/dev/null | tr -d '\r\n')
    rm -f "$_tmp"

    if [[ -z "$enc" ]]; then
        LMD_HITS_B64GZ_NOTE="encode_failed"
        return 0
    fi

    LMD_HITS_B64GZ="$enc"
    LMD_HITS_ENCODED_BYTES="${#enc}"
    LMD_HITS_B64GZ_NOTE="ok"
}

# Signal accumulator. One line per signal, tab-delimited:
#   area<TAB>id<TAB>severity<TAB>key<TAB>weight<TAB>jsonkv
# jsonkv = comma-separated "key":"value" pairs (pre-JSON-escaped).

# Bash 4.1 / EL6: -a (not -ga) at top-level scope.
declare -a SIGNALS=()
# Aggregation outputs from aggregate_verdict() consumed by print_verdict /
# write_json / write_csv. Declared at top-level so they remain in global
# scope without needing `declare -g` (bash 4.2+) inside the producer.
declare -a REASONS=()
declare -a IOC_KEYS=()
declare -a ADVISORIES=()
# Per-user attribution maps populated by aggregate_verdict() and consumed by
# aggregate_per_user_verdict() / write_json. Same rule: top-level -A, reset
# by reassignment inside the producer (declare -gA is bash 4.2+).
declare -A USER_SEVERITY=()
declare -A USER_PATTERNS=()
declare -A USER_KEYS=()
declare -A USER_PRIV_MAX=()
declare -A USER_FIRST_EPOCH=()
declare -A USER_LAST_EPOCH=()
declare -A USER_COUNT=()

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
# Each JSONL line + every signals[] entry is prefixed with "host":"<fqdn>"
# so fleet aggregators can attribute without joining the envelope.
emit() {
    local area="$1" id="$2" severity="$3" key="$4" weight="$5"; shift 5
    local _has_au=0 _has_ap=0 _i
    for (( _i = 1; _i <= $#; _i += 2 )); do
        case "${!_i}" in
            affected_user)   _has_au=1 ;;
            actor_privilege) _has_ap=1 ;;
        esac
    done
    if (( ! _has_au )); then set -- "$@" affected_user "_root"; fi
    if (( ! _has_ap )); then set -- "$@" actor_privilege "root"; fi
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
    local tag color
    case "$severity" in
        live_compromise) tag="[LIVE]"; color="${BOLD}${RED}" ;;
        strong)   tag="[IOC]";      color="$RED"    ;;
        evidence) tag="[EVIDENCE]"; color="$YELLOW" ;;
        warning)  tag="[WARN]";     color="$YELLOW" ;;
        advisory) tag="[ADVISORY]"; color="$CYAN"   ;;
        error)    tag="[ERR]";      color="$RED"    ;;
        info)
            case "$key" in
                patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs|posture_csf_active)
                    tag="[OK]"; color="$GREEN" ;;
                *)  tag="[..]"; color="$DIM"   ;;
            esac
            ;;
        *) tag="[..]"; color="$DIM" ;;
    esac

    # WHERE / WHO / WHAT sub-lines, all optional. Full kv lands in JSONL.
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

    # Header line: tag + id + note (or key as fallback)
    if [[ -n "$note" ]]; then
        printf '  %s%-10s%s %-44s %s%s%s\n' "$color" "$tag" "$NC" "$id" "$DIM" "$note" "$NC" >&2
    else
        printf '  %s%-10s%s %-44s %s%s%s\n' "$color" "$tag" "$NC" "$id" "$DIM" "$key" "$NC" >&2
    fi

    # Suppress detail only on info rows whose payload is meaningless;
    # per-row IOC + anomalous_session_path samples stay (triage fields).
    case "$key" in
        no_ioc_hits|no_session_iocs|patched_per_build|patch_marker_present| \
        ancillary_bug_fixed|acl_machinery_present_informational)
            return ;;
    esac

    # WHERE field — operator-stat-able file pointer. log_file (rotated
    # access_log) wins over live access_log for IOC-sample rows.
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

# Forensic output primitives. say_*/hdr() use status-prefixed tags
# (visually distinct from detection); all output → stderr.

hdr_section()   { (( QUIET )) || printf '\n%s== %s ==%s %s%s%s\n' "$C_BLD" "$1" "$C_NC" "$C_DIM" "$2" "$C_NC" >&2; }
say_pass()      { (( QUIET )) || printf '  %s[OK]%s %s\n'        "$C_GRN" "$C_NC" "$*" >&2; }
say_info()      { (( QUIET )) || printf '  %s[INFO]%s %s\n'      "$C_DIM" "$C_NC" "$*" >&2; }
say_warn()      { (( QUIET )) || printf '  %s[WARN]%s %s\n'      "$C_YEL" "$C_NC" "$*" >&2; }
say_fail()      { (( QUIET )) || printf '  %s[FAIL]%s %s\n'      "$C_RED" "$C_NC" "$*" >&2; }
say_def()       { (( QUIET )) || printf '  %s[DEF-OK]%s %s\n'    "$C_GRN" "$C_NC" "$*" >&2; }
say_def_miss()  { (( QUIET )) || printf '  %s[DEF-MISS]%s %s\n'  "$C_YEL" "$C_NC" "$*" >&2; }
say_ioc()       { (( QUIET )) || printf '  %s[IOC]%s %s\n'       "$C_RED" "$C_NC" "$*" >&2; }

###############################################################################
# Forensic signal emitter — wraps emit(). pass/info → info(0), warn →
# warning(4), fail → strong(10). Forensic signals reuse `key` for `id`.
###############################################################################

emit_signal() {
    local area="$1" sev="$2" key="$3" note="$4"
    shift 4
    local ioc_sev="info" weight=0
    case "$sev" in
        (pass|info)  ioc_sev="info";            weight=0  ;;
        (warn)       ioc_sev="warning";         weight=4  ;;
        (fail)       ioc_sev="strong";          weight=10 ;;
        (live)       ioc_sev="live_compromise"; weight=10 ;;
        (*)          ioc_sev="info";            weight=0  ;;
    esac
    emit "$area" "$key" "$ioc_sev" "$key" "$weight" "note" "$note" "$@"
}

# Forensic helpers — used by phase_defense/offense/reconcile + render_kill_chain
# + phase_bundle/upload. No-op in --triage (phase funcs aren't called).

have_cmd() { command -v "$1" >/dev/null 2>&1; }

mtime_of() {
    local f="$1"
    [[ -e "$f" ]] || { echo ""; return; }
    stat -c %Y "$f" 2>/dev/null
}

# Populates META_KV[] with sha256/md5/size/ctime/mtime/owner/mode for $1.
META_KV=()
META_SHA256=""
known_bad_meta() {
    local f="$1" v
    META_KV=()
    META_SHA256=""
    [[ -f "$f" ]] || return 0
    if have_cmd sha256sum; then
        v=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        if [[ -n "$v" ]]; then
            META_KV+=(sha256 "$v")
            META_SHA256="$v"
        fi
    fi
    if have_cmd md5sum; then
        v=$(md5sum "$f" 2>/dev/null | awk '{print $1}')
        [[ -n "$v" ]] && META_KV+=(md5 "$v")
    fi
    v=$(stat -c %s "$f" 2>/dev/null); [[ -n "$v" ]] && META_KV+=(size_bytes "$v")
    v=$(stat -c %Z "$f" 2>/dev/null); [[ -n "$v" ]] && META_KV+=(ctime_epoch "$v")
    v=$(stat -c %Y "$f" 2>/dev/null); [[ -n "$v" ]] && META_KV+=(mtime_epoch "$v")
    v=$(stat -c %U "$f" 2>/dev/null); [[ -n "$v" ]] && META_KV+=(owner "$v")
    v=$(stat -c %a "$f" 2>/dev/null); [[ -n "$v" ]] && META_KV+=(mode "$v")
}

epoch_to_iso() {
    local e="$1"
    [[ -z "$e" || "$e" == "0" ]] && { echo ""; return; }
    date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null
}

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
        printf '%s' "${_parts[*]:$(( _nfields - 1 ))}"
    fi
}

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

json_num_field() {
    local line="$1" key="$2" v
    v=$(printf '%s\n' "$line" | grep -oE "\"$key\":(\"[0-9.+-]*\"|-?[0-9]+(\.[0-9]+)?)" | head -1)
    [[ -z "$v" ]] && return 0
    v="${v#*\":}"
    v="${v#\"}"
    v="${v%\"}"
    printf '%s' "$v"
}

ioc_key_to_pattern() {
    # Specific keys MUST appear before the ioc_attacker_ip* glob — case is
    # first-match, not best-match.
    case "$1" in
        # Pre-compromise advisory keys: route to init so kill-chain skips
        # them. MUST precede the ioc_pattern_e_* + ioc_attacker_ip* globs.
        (ioc_pattern_e_websocket_shell_hits_pre_compromise) echo init ;;
        (ioc_pattern_e_websocket_shell_hits_orphan)         echo init ;;
        (ioc_attacker_ip_2xx_on_cpsess_pre_compromise)      echo init ;;
        (ioc_pattern_a_*)                       echo A ;;
        (ioc_pattern_b_*)                       echo B ;;
        (ioc_pattern_c_*)                       echo C ;;
        (ioc_pattern_d_*)                       echo D ;;
        (ioc_pattern_e_*)                       echo E ;;
        (ioc_pattern_f_*)                       echo F ;;
        (ioc_pattern_g_*)                       echo G ;;
        (ioc_pattern_h_*)                       echo H ;;
        (ioc_pattern_i_*)                       echo I ;;
        (ioc_pattern_j_*)                       echo J ;;
        (ioc_pattern_k_*)                       echo K ;;
        (ioc_pattern_l_*)                       echo L ;;
        (ioc_runtime_*)                         echo R ;;
        # Mitigate-quarantine secondary-read replay signals - synthetic
        # emits derived from sidecar fields, NOT from re-running the live
        # IOC ladder. Routed to X (forged-session evidence) since that's
        # what the source data is.
        (ioc_quarantined_session_*)             echo X ;;
        (ioc_attacker_ip_2xx_on_cpsess)         echo X ;;
        (ioc_attacker_ip_recon_only)            echo init ;;
        (ioc_failed_exploit_attempt)            echo X ;;
        (ioc_attacker_ip*|ioc_hits)             echo init ;;
        (ioc_token_*|ioc_preauth_*|ioc_short_pass*|ioc_multiline_*|ioc_badpass*|ioc_cve_2026_41940*|ioc_hasroot*|ioc_malformed*|ioc_forged_*|ioc_tfa*|anomalous_root_sessions)
                                                echo X ;;
        (*)                                     echo ? ;;
    esac
}

# Soft-variant suffix gate — explicit low-confidence emits don't escalate
# via prefix-match in the persist/compromise classifiers below.
ioc_key_is_soft_variant() {
    case "$1" in
        *_review|*_review_*|*_diagnostic|*_diagnostic_only|*_candidate|*_undetermined \
        |*_orphan|*_pre_compromise|*_probes_only|*_unknown_dim_only|*_unknown_hash \
        |*_uncorroborated|*_documentation|*_documentation_*) return 0 ;;
    esac
    return 1
}

# Persistence-class letter for cluster scoring. "" for non-persistence.
# G ssh-keys · I profile.d · J cdrom-id-helper/dbus-broker-helper dossier
# paths · F harvester · D reseller-token · H seobot/alldone.
ioc_key_to_persist_pattern() {
    ioc_key_is_soft_variant "$1" && { echo ""; return; }
    case "$1" in
        (ioc_pattern_g_*)                       echo G ;;
        (ioc_pattern_j_*)                       echo J ;;
        (ioc_pattern_i_*)                       echo I ;;
        (ioc_pattern_f_cmd_done*|ioc_pattern_f_smark*) echo F ;;
        (ioc_pattern_d_reseller*|ioc_pattern_d_token*|ioc_pattern_d_whm_fullroot*) echo D ;;
        (ioc_pattern_h_seobot*|ioc_pattern_h_alldone*|ioc_pattern_h_contained_*) echo H ;;
        (ioc_pattern_m_*)                       echo M ;;
        (*)                                     echo "" ;;
    esac
}

# Section grouping for kill-chain PERSISTENCE/DESTRUCTION render blocks.
# Returns: persistence | destruction | "".
ioc_section_group() {
    ioc_key_is_soft_variant "$1" && { echo ""; return; }
    local cls
    cls=$(ioc_compromise_class "$1")
    case "$cls" in
        persistence)            echo persistence; return ;;
        destruction|token_used) echo destruction; return ;;
    esac
    case "$1" in
        ioc_runtime_gsocket_keyfile_present|ioc_runtime_gsocket_persistence_shim)
            echo persistence ;;
        ioc_runtime_known_bad_path_present|ioc_runtime_xmrig_masquerade| \
        ioc_runtime_xmrig_visible_active|ioc_runtime_xmr_wallet_in_cmdline| \
        ioc_runtime_wallet_in_cmdline|ioc_runtime_known_loader_in_flight| \
        ioc_runtime_c2_callback|ioc_runtime_c2_callback_active| \
        ioc_runtime_reverse_shell_active|ioc_runtime_lpe_binary_running| \
        ioc_runtime_tmp_hex_blob_present)
            echo destruction ;;
        *) echo "" ;;
    esac
}

# Demote IOC string hits in IR docs/runbooks/dossiers + sessionscribe-*
# toolkit self-references.
_is_doc_shape() {
    local _p="${1:-}"
    [[ -n "$_p" ]] || return 1
    case "${_p##*/}" in
        sessionscribe-*|nxesec-whmscribe-*) return 0 ;;
    esac
    local _doc_re='^/root/(IR|notes|runbooks|\.claude|\.cache|admin)/|/docs/|IR-notes|runbook|notes-[0-9]|findings-|dossier|ps-hunt|/proj/.*\.(md|txt|rst|adoc)$'
    [[ "$_p" =~ $_doc_re ]] && return 0
    local _lines
    _lines=$(wc -l < "$_p" 2>/dev/null | tr -d ' ')
    _lines="${_lines:-0}"
    if (( _lines > 200 )) && [[ "$_p" == *.md || "$_p" == *.txt || "$_p" == *.rst || "$_p" == *.adoc ]]; then
        return 0
    fi
    return 1
}

# Historical/quarantine evidence — both sources.
_is_quarantine_signal() {
    case "$1" in
        (ioc_quarantined_session_*)      return 0 ;;
        (ioc_pattern_*_contained_*)      return 0 ;;
        (ioc_contained_evidence*|ioc_contained_unclassified*) return 0 ;;
    esac
    return 1
}

# Compromise class for verdict gating: persistence / destruction /
# token_used / "" (attempt). v3 ladder — see CHANGELOG.
ioc_compromise_class() {
    ioc_key_is_soft_variant "$1" && { echo ""; return; }
    case "$1" in
        # Persistence — mirrors ioc_key_to_persist_pattern().
        (ioc_pattern_g_*|ioc_pattern_j_*|ioc_pattern_i_*) echo persistence ;;
        (ioc_pattern_f_cmd_done*|ioc_pattern_f_smark*)    echo persistence ;;
        (ioc_pattern_d_reseller*|ioc_pattern_d_token*|ioc_pattern_d_whm_fullroot*) echo persistence ;;
        (ioc_pattern_h_seobot*|ioc_pattern_h_alldone*|ioc_pattern_h_contained_*) echo persistence ;;
        (ioc_pattern_m_*)                                 echo persistence ;;
        # Destruction / deployment — confirmed post-RCE action.
        (ioc_pattern_a_*|ioc_pattern_b_*|ioc_pattern_c_*) echo destruction ;;
        (ioc_pattern_d_acctlog*|ioc_pattern_d_evidence_destroyed) echo destruction ;;
        (ioc_pattern_h_kill_prelude*|ioc_pattern_h_competitor_kill*|ioc_pattern_h_zip_dropper|ioc_pattern_h_dropper_archive) echo destruction ;;
        (ioc_pattern_k_*|ioc_pattern_l_*) echo destruction ;;
        # Token consumption (post-CRLF, in proximity to 2xx_on_cpsess).
        # Pre-compromise variants stay attempt-class via the route below.
        (ioc_attacker_ip_2xx_on_cpsess) echo token_used ;;
        # Default: attempt-class (Pattern E entry, X CRLF, recon, X-forged
        # sessions, _pre_compromise variants, _orphan, _probes_only, etc.).
        (*) echo "" ;;
    esac
}

ioc_signal_epoch() {
    local line="$1" v iso k key pattern
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

    # pattern=X requires a real ts (synthesizing TS_EPOCH corrupts q5/q8
    # patient-zero anchor); file-on-disk patterns (A/B/C/D/F/G/H/I) retain
    # TS_EPOCH fallback — they're real on-disk evidence regardless of ts.
    key=$(json_str_field "$line" "key")
    pattern=$(ioc_key_to_pattern "$key")
    if [[ "$pattern" == "X" ]]; then
        printf '0'
        return
    fi
    printf '%s' "$TS_EPOCH"
}

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

# Modified from forensic: takes envelope path as $1 with
# $SESSIONSCRIBE_IOC_JSON as fallback, so --replay can pass any envelope
# path without exporting the env var. Body otherwise verbatim.
read_envelope_meta() {
    local env="${1:-${SESSIONSCRIBE_IOC_JSON:-}}"
    [[ -n "$env" && -f "$env" ]] || return 0
    ENV_HOST_ROOT_VERDICT=$(envelope_root_field "$env" host_root_verdict)
    ENV_HOST_USER_VERDICT=$(envelope_root_field "$env" host_user_verdict)
    ENV_CODE_VERDICT=$(envelope_root_field "$env" code_verdict)
    ENV_SCORE=$(envelope_root_field "$env" score)
    ENV_IOC_TOOL_VERSION=$(envelope_root_field "$env" tool_version)
    ENV_IOC_RUN_ID=$(envelope_root_field "$env" run_id)
    ENV_IOC_TS=$(envelope_root_field "$env" ts)
    ENV_HOST=$(envelope_root_field "$env" host)
}

ioc_primitive_row() {
    local area="$1" ip="$2" path="$3" log_file="$4" count="$5" h2xx="$6" status="$7" line="$8"
    local cpsess_token="${9:-}"
    local clean="${line//$'\t'/ }"
    clean="${clean//$'\n'/ }"
    clean="${clean//$'\r'/ }"
    printf '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s' \
        "${area:-}"         "$PRIM_SEP" \
        "${ip:-}"           "$PRIM_SEP" \
        "${path:-}"         "$PRIM_SEP" \
        "${log_file:-}"     "$PRIM_SEP" \
        "${count:-}"        "$PRIM_SEP" \
        "${h2xx:-}"         "$PRIM_SEP" \
        "${status:-}"       "$PRIM_SEP" \
        "$clean"            "$PRIM_SEP" \
        "${cpsess_token:-}"
}

# Reads envelope ($1 or $SESSIONSCRIBE_IOC_JSON), populates OFFENSE_EVENTS/
# IOC_PRIMITIVES/IOC_ANNOTATIONS. Returns 1 + non-fatal say_warn if absent.
read_iocs_from_envelope() {
    local env="${1:-${SESSIONSCRIBE_IOC_JSON:-}}"
    if [[ -z "$env" ]]; then
        say_warn "no envelope path - run via --full or --replay PATH"
        emit_signal offense warn no_envelope "envelope unavailable; deep checks only"
        return 1
    fi
    if [[ ! -f "$env" ]]; then
        say_warn "envelope path missing: $env"
        emit_signal offense warn envelope_missing "envelope path unreadable" path "$env"
        return 1
    fi

    read_envelope_meta "$env"

    local line area severity key note ts pattern n_added=0
    local p_ip p_path p_log p_count p_h2xx p_status p_line p_row p_anno
    local p_cpsess_token key_for_warn
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\{\"host\": ]] || continue
        area=$(json_str_field "$line" area)
        severity=$(json_str_field "$line" severity)
        # $key must be assigned before the advisory allow-list below
        # checks it (prior layout assigned $key after the severity case,
        # which silently filtered out every advisory line).
        key=$(json_str_field "$line" key)
        case "$area" in
            (logs|sessions|destruction) ;;
            (*) continue ;;
        esac
        # Narrow allow-list for the three pre-compromise advisory keys so
        # they appear as PRE-COMPROMISE / EXPLOITATION-DETACHED zones in
        # the kill-chain. Advisory does not escalate host_verdict; any
        # future advisory keys default to filtered-out.
        case "$severity" in
            (strong|warning|live_compromise) ;;
            (advisory)
                case "$key" in
                    (ioc_pattern_e_websocket_shell_hits_pre_compromise|ioc_pattern_e_websocket_shell_hits_orphan|ioc_attacker_ip_2xx_on_cpsess_pre_compromise) ;;
                    (*) continue ;;
                esac
                ;;
            (*) continue ;;
        esac
        case "$key" in
            (ioc_sample|ioc_attacker_ip_sample|session_shape_sample) continue ;;
        esac
        note=$(json_str_field "$line" note)
        ts=$(ioc_signal_epoch "$line")
        # Pattern X with no resolvable ts is refused — a scan-time
        # anchor via TS_EPOCH would corrupt q8_patient_zero_x.
        if [[ "$ts" == "0" ]]; then
            key_for_warn=$(json_str_field "$line" key)
            emit_signal offense warn ts_unresolvable_pattern_x \
                "Pattern X event refused (no resolvable timestamp) - prevents synthetic scan-time anchor; pattern=meta informational only" \
                key "${key_for_warn:-unknown}"
            continue
        fi
        pattern=$(ioc_key_to_pattern "$key")
        p_ip=$(json_str_field "$line" ip)
        [[ -z "$p_ip" ]] && p_ip=$(json_str_field "$line" src_ip)
        p_path=$(json_str_field "$line" path)
        [[ -z "$p_path" ]] && p_path=$(json_str_field "$line" file)
        p_log=$(json_str_field "$line" log_file)
        p_count=$(json_num_field "$line" count)
        p_h2xx=$(json_num_field "$line" hits_2xx)
        p_status=$(json_str_field "$line" status)
        p_line=$(json_str_field "$line" line)
        p_cpsess_token=$(json_str_field "$line" cpsess_token)
        p_row=$(ioc_primitive_row "$area" "$p_ip" "$p_path" "$p_log" "$p_count" "$p_h2xx" "$p_status" "$p_line" "$p_cpsess_token")
        p_anno=""
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

# Forensic phases (defense/offense/reconcile) — run under --full/--replay.
# In: envelope on disk. Out: DEFENSE_EVENTS/OFFENSE_EVENTS/IOC_PRIMITIVES/
# IOC_ANNOTATIONS/RECONCILED/N_PRE/N_POST + emit() signals.

# Pattern G deep checks ioc-scan doesn't perform: forged-mtime detection
# (touch -d backdating) + per-key-comment validation against the LW
# known-good set + ssh-rsa material in non-canonical paths.
pattern_g_deep_checks() {
    local ak_files=(/root/.ssh/authorized_keys /root/.ssh/authorized_keys2)
    local h
    # -maxdepth 1 (NOT 2): canonical paths are at depth-1 only. -maxdepth 2
    # also returned depth-2 subdirs (/home/<user>/sub), and appending
    # /.ssh/authorized_keys to those produced non-canonical probe targets.
    # Mirrors the same fix in mitigate's kill_sshkey_canonical_paths.
    while IFS= read -r -d '' h; do
        ak_files+=("$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2")
    done < <(find /home -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)

    local ak mtime_pre ctime_pre mt_utc mt_local
    for ak in "${ak_files[@]}"; do
        [[ -f "$ak" ]] || continue
        mtime_pre=$(stat -c %Y "$ak" 2>/dev/null)
        ctime_pre=$(stat -c %Z "$ak" 2>/dev/null)
        local _g_known_bad=0
        # `touch -d` interprets in local timezone, so the resulting epoch
        # depends on the host's UTC offset. Compare wall-clock under
        # both UTC and localtime — either match is the forged stamp.
        if [[ -n "$mtime_pre" ]]; then
            mt_utc=$(date -u   -d "@$mtime_pre" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
            mt_local=$(date    -d "@$mtime_pre" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
            if [[ "$mt_utc" == "$PATTERN_G_FORGED_MTIME_WALL" \
               || "$mt_local" == "$PATTERN_G_FORGED_MTIME_WALL" ]]; then
                say_ioc "PATTERN-G: $ak mtime matches known forged stamp \"$PATTERN_G_FORGED_MTIME_WALL\""
                emit_signal offense fail pattern_g_forged_mtime \
                    "$ak mtime matches CVE-2026-41940 backdate stamp" \
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
            # Extract the FULL multi-word comment (fields 3..end);
            # `$NF` alone breaks SSH_KNOWN_GOOD_RE on "Parent Child key
            # for XXXXXX"-style LW provisioning keys.
            comment=$(awk 'NF>=3 {sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, ""); print}' <<< "$line")
            is_known_bad=0; bad_label=""
            for bad in "${PATTERN_G_BAD_KEY_LABELS[@]}"; do
                [[ "$comment" == *"$bad"* ]] && { is_known_bad=1; bad_label="$bad"; break; }
            done
            if (( is_known_bad )); then
                susp_count=$((susp_count+1))
                _g_known_bad=1
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
            # Gate on _g_known_bad only — forged_mtime emits its own row above.
            if (( _g_known_bad )) && [[ -n "$ctime_pre" ]]; then
                OFFENSE_EVENTS+=("$ctime_pre|G|pattern_g_sshkey|known-bad ssh key label|patch,modsec")
                IOC_PRIMITIVES+=("$(ioc_primitive_row destruction "" "$ak" "$susp_count" "" "" "" "known-bad ssh key label")")
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

    # Drop RFC1918 + loopback (WHM admin); same regex shape as Pattern E is_internal.
    # 5min cap on the full log scan — multi-year access_log corpora on busy
    # fleets can exceed an hour of grep/awk wall-time.
    local suspect_ips
    suspect_ips=$(timeout 300 bash -c '
        for lg in "$@"; do
            case "$lg" in
                *.gz)  command -v zcat  >/dev/null 2>&1 && zcat  "$lg" 2>/dev/null ;;
                *.xz)  command -v xzcat >/dev/null 2>&1 && xzcat "$lg" 2>/dev/null ;;
                *.bz2) command -v bzcat >/dev/null 2>&1 && bzcat "$lg" 2>/dev/null ;;
                *)     cat "$lg" 2>/dev/null ;;
            esac
        done \
            | grep -E "\"GET /cpsess[0-9]+/(websocket/Shell|json-api/(createacct|setupreseller|setacls))" 2>/dev/null \
            | awk "\$1 !~ /^10\\./ && \$1 !~ /^127\\./ && \$1 !~ /^192\\.168\\./ && \$1 !~ /^172\\.(1[6-9]|2[0-9]|3[01])\\./ {print \$1}" \
            | sort -u | head -50
    ' _ "${cp_logs[@]}" 2>/dev/null)
    if [[ -n "$suspect_ips" ]]; then
        local ip_list
        ip_list=$(echo "$suspect_ips" | tr '\n' ',' | sed 's/,$//')
        say_ioc "suspect attacker IPs (websocket/createacct hits): $ip_list"
        emit_signal offense info suspect_ips "$ip_list" ips "$ip_list"
    fi
}

phase_defense() {
    hdr_section "defense" "extracting timestamps for every mitigation layer"

    PATCH_STATE="UNKNOWN"
    if [[ "$CPANEL_NORM" == "unknown" || -z "$CPANEL_NORM" ]]; then
        say_def_miss "cpanel binary missing or build unparseable - patch defense UNKNOWN"
        emit_signal defense warn patch_unknown "cpanel build unparseable" \
            build "$CPANEL_NORM" patch_state "$PATCH_STATE"
    else
        # PATCHED iff build >= vendor cutoff for the host's tier.
        local patched=0 _pd_tier="" _pd_build="" _pd_i
        if [[ "$CPANEL_NORM" =~ ^11\.([0-9]+)\.0\.([0-9]+)$ ]]; then
            _pd_tier="${BASH_REMATCH[1]}"; _pd_build="${BASH_REMATCH[2]}"
            for _pd_i in "${!PATCHED_TIERS_KEYS[@]}"; do
                if [[ "${PATCHED_TIERS_KEYS[$_pd_i]}" == "$_pd_tier" ]] \
                   && (( _pd_build >= ${PATCHED_TIERS_VALS[$_pd_i]} )); then
                    patched=1; break
                fi
            done
        elif [[ "$CPANEL_NORM" =~ ^11\.([0-9]+)\.1\.([0-9]+)$ ]]; then
            _pd_tier="${BASH_REMATCH[1]}"; _pd_build="${BASH_REMATCH[2]}"
            if [[ "$_pd_tier" == "$PATCHED_WPSQUARED_TIER" ]] \
               && (( _pd_build >= PATCHED_WPSQUARED_BUILD )); then
                patched=1
            fi
        fi
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
            local is_unpatchable=0
            [[ " $UNPATCHED_TIERS_STR " == *" $tier "* ]] && is_unpatchable=1
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

    # ModSec rule 1500030 is the primary CRLF-in-Authorization-Basic block;
    # absent → no exploit-vector defense regardless of cPanel patch state.
    # Match both `id:1500030` and `id:"1500030"` (both valid SecRule shapes).
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

    # CSF cpsrvd port closure: TCP_IN/TCP6_IN must NOT carry 2082-2096.
    # Defeated by explicit port OR overlap range (e.g. 2080:2090) → csf_dirty.
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
            # Operator pre-mutation backup; .ic5790.bak honored for back-compat.
            local _csf_bak="" _bak_name
            for _bak_name in /etc/csf/csf.conf.cve-2026-41940.bak /etc/csf/csf.conf.ic5790.bak; do
                [[ -f "$_bak_name" ]] && { _csf_bak="$_bak_name"; break; }
            done
            if [[ -n "$_csf_bak" ]]; then
                local bak_time
                bak_time=$(mtime_of "$_csf_bak")
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
        # Verify actual iptables state — csf.conf clean ≠ rules reloaded.
        # Defense = ABSENCE of ACCEPT 0.0.0.0/0 → dpt:N for each cpsrvd port.
        # Walk INPUT + secondary CSF chains (mirrors mitigate.sh phase_runfw).
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

phase_offense() {
    hdr_section "offense" "ingesting IOCs from canonical detector + deep checks"
    read_iocs_from_envelope "${ENVELOPE_PATH:-}" || true
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
    hdr_section "reconcile" "comparing defense activation vs compromise timestamps"

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
        # Record: epoch|pattern|key|note|defenses_required (field 5 unused).
        # Pipe-tolerant: rejoin parts[3..n-2] so notes containing '|'
        # (access_log lines, CRLF-injected values) round-trip intact.
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

        # Reset per-iteration verdict/delta — function-scope locals that
        # would otherwise carry over if the advisory short-circuit branch
        # below does not assign them.
        verdict=""
        delta=""

        # Pre-compromise advisory keys short-circuit the defense comparison
        # (they're advisory by design — host wasn't compromised by these
        # events) and route to dedicated verdict slots. They do NOT
        # increment N_PRE / N_POST (those count real attack events).
        case "$ev_key" in
            (*_pre_compromise)
                verdict="ADVISORY-PRE-COMPROMISE"
                delta="n/a"
                ;;
            (*_orphan)
                verdict="ADVISORY-ORPHAN"
                delta="n/a"
                ;;
        esac

        if [[ -z "$verdict" ]]; then
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
        fi

        local color
        case "$verdict" in
            PRE-DEFENSE)              color="$C_RED" ;;
            UNDEFENDED)               color="$C_RED" ;;
            POST-DEFENSE)             color="$C_GRN" ;;
            POST-PARTIAL)             color="$C_YEL" ;;
            ADVISORY-PRE-COMPROMISE|ADVISORY-ORPHAN) color="$C_CYN" ;;
            *)                        color="$C_DIM" ;;
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
        # bash 4.1 (CL6/EL6 floor) + set -u: empty array deref crashes;
        # guard with project length-check idiom.
        if (( ${#DEFENSE_EVENTS[@]} > 0 )); then
            for de in "${DEFENSE_EVENTS[@]}"; do
                local ts
                ts=$(echo "$de" | cut -d'|' -f1)
                [[ -z "$ts" ]] && continue
                if [[ -z "$max_def" ]] || (( ts > max_def )); then
                    max_def="$ts"
                fi
            done
        fi

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
# Kill-chain renderer + primitives writer.
###############################################################################

# Canonical pattern order for the offense timeline. init=recon pre-cursor;
# A-I=destruction patterns; X=forged-session evidence; ?=unmapped.
PATTERN_ORDER=(init A B C D E F G H I J X "?")

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
            # bash 4.1 (CL6/EL6 floor) lacks ${var: -N} negative-substring;
            # compute the offset explicitly. Guard above ensures len > 50.
            d="${path:0:24}${GLYPH_ELLIPSIS}${path:$((${#path}-25)):25}"
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
        PRE-DEFENSE|UNDEFENDED)                  color="$C_RED" ;;
        POST-DEFENSE)                            color="$C_GRN" ;;
        POST-PARTIAL)                            color="$C_YEL" ;;
        # Advisory verdicts render in cyan — distinct from the
        # red/green/yellow attack-chain palette so operators can tell at
        # a glance which rows are real exploitation evidence.
        ADVISORY-PRE-COMPROMISE|ADVISORY-ORPHAN) color="$C_CYN" ;;
        *)                                       color="$C_DIM" ;;
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

# Aggregate attacker IPs from IOC_PRIMITIVES + RECONCILED. Sort: hit-count
# desc, first-seen asc. Top 5 inline; rest in kill-chain.md overflow.
aggregate_attacker_ips() {
    ATTACKER_IP_PLAIN=""
    ATTACKER_IP_ANNOTATED=()
    ATTACKER_IP_OVERFLOW=""
    ATTACKER_IP_TOTAL=0

    # Two-step init: bash 4 + set -u trips on empty-assoc deref otherwise.
    declare -A ip_count ip_stages ip_first
    ip_count=(); ip_stages=(); ip_first=()

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

# Partition OFFENSE_EVENTS+IOC_PRIMITIVES into KC_*_ROWS and KC_*_LETTERS.
KC_PERSIST_ROWS=()
KC_DESTRUCT_ROWS=()
declare -A KC_PERSIST_LETTERS
declare -A KC_DESTRUCT_LETTERS
build_kc_section_rows() {
    KC_PERSIST_ROWS=()
    KC_DESTRUCT_ROWS=()
    KC_PERSIST_LETTERS=()
    KC_DESTRUCT_LETTERS=()
    (( ${#OFFENSE_EVENTS[@]} == 0 )) && return 0
    local i _oe pattern key note _rec _path _ip _ _grp
    for (( i=0; i<${#OFFENSE_EVENTS[@]}; i++ )); do
        _oe="${OFFENSE_EVENTS[$i]}"
        pattern=$(printf '%s' "$_oe" | cut -d'|' -f2)
        key=$(printf '%s' "$_oe" | cut -d'|' -f3)
        note=$(printf '%s' "$_oe" | cut -d'|' -f4)
        _grp=$(ioc_section_group "$key")
        [[ -z "$_grp" ]] && continue
        _rec="${IOC_PRIMITIVES[$i]:-}"
        IFS="$PRIM_SEP" read -r _ _ip _path _ <<< "$_rec"
        case "$_grp" in
            persistence)
                KC_PERSIST_ROWS+=("${pattern}|${key}|${_path:-}|${note}")
                KC_PERSIST_LETTERS["$pattern"]=1
                ;;
            destruction)
                KC_DESTRUCT_ROWS+=("${pattern}|${key}|${_path:-}|${note}")
                KC_DESTRUCT_LETTERS["$pattern"]=1
                ;;
        esac
    done
}

# Args: title, color, rows... (each row is pipe-delimited pattern|key|path|note).
render_kc_section() {
    local title="$1" hdr_color="$2"
    shift 2
    (( $# == 0 )) && return 0

    local count=$#
    local plural; (( count == 1 )) && plural="" || plural="s"
    printf '\n  %s%s%s  %s%s── %s (%d indicator%s) ──%s\n' \
        "$C_DIM" "$GLYPH_BOX_V" "$C_NC" \
        "$hdr_color" "$C_BLD" "$title" "$count" "$plural" "$C_NC"

    local row p k pth n display
    for row in "$@"; do
        IFS='|' read -r p k pth n <<< "$row"
        display="${pth:-$n}"
        if (( ${#display} > 80 )); then
            display="${display:0:77}${GLYPH_ELLIPSIS}"
        fi
        # %-30.30s pads + truncates so long keys keep column alignment.
        printf '  %s%s     %s%s%s pattern %-4s  %s%-30.30s%s  %s\n' \
            "$C_DIM" "$GLYPH_BOX_V" "$C_NC" \
            "$hdr_color" "$GLYPH_ARROW" \
            "$p" \
            "$C_CYN" "$k" "$C_NC" \
            "$display"
    done
}

render_kill_chain() {
    (( QUIET )) && return 0

    # Aggregate attacker IPs once for the HEADLINE section. Walks
    # IOC_PRIMITIVES + RECONCILED; sets ATTACKER_IP_* globals.
    aggregate_attacker_ips

    build_kc_section_rows

    # Merged defense+offense timeline; entry = epoch \t kind \t payload-index.
    # Brace-group is load-bearing: `| sort` must apply to BOTH loops, else
    # bash binds the pipe to only the second loop and DEFENSE rows stay
    # unsorted.
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
        # Open box: title in top bar, plain bottom. Left bar only on
        # content lines avoids width-counting around FQDNs + combining chars.
        local W=72
        local title="CVE-2026-41940"
        # Title takes (3 left bar+space) + len(title) + 1 trailing space
        # visual columns; remainder fills with horizontal bars.
        local title_used=$(( 4 + ${#title} ))
        local right_len=$(( W - title_used ))
        (( right_len < 4 )) && right_len=4
        local right_bar="" _bi
        for (( _bi=0; _bi<right_len; _bi++ )); do right_bar+="$GLYPH_BOX_H"; done
        local full_bar="" _bi2
        for (( _bi2=0; _bi2<W; _bi2++ )); do full_bar+="$GLYPH_BOX_H"; done

        # Verdict color + display text. Compound view of the two-axis
        # verdict (root-trust + user-account); worst-of for the headline.
        local hv_root="${ENV_HOST_ROOT_VERDICT:-}"
        local hv_user="${ENV_HOST_USER_VERDICT:-}"
        local hv=""
        if [[ "$hv_root" == "COMPROMISED" || "$hv_user" == "COMPROMISED" ]]; then
            hv="COMPROMISED"
        elif [[ "$hv_root" == "SUSPICIOUS" || "$hv_user" == "SUSPICIOUS" ]]; then
            hv="SUSPICIOUS"
        elif [[ -n "$hv_root" || -n "$hv_user" ]]; then
            hv="CLEAN"
        fi
        local hv_text="$hv"
        if [[ -n "$hv" ]]; then
            hv_text="$hv (root=$hv_root, user=$hv_user)"
        fi
        local hv_color="$C_GRN"
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
        # Replay/forensic mode: prefer envelope's source host over the
        # local replay-host. Suppress IP parens when no IP is available
        # (envelope-replay typically has no primary_ip at root).
        local _kc_host="${ENV_HOST:-$HOSTNAME_FQDN}" _kc_ip="$PRIMARY_IP"
        if [[ -n "$_kc_ip" ]]; then
            printf '%s%s%s host         %s%s%s (%s)\n' "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$C_BLD" "$_kc_host" "$C_NC" "$_kc_ip"
        else
            printf '%s%s%s host         %s%s%s\n'      "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$C_BLD" "$_kc_host" "$C_NC"
        fi
        printf '%s%s%s cpanel       %s   os %s\n'    "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "${CPANEL_NORM:-unknown}" "${OS_PRETTY:-unknown}"
        printf '%s%s%s verdict      %s%s%s\n'        "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$hv_color" "$verdict_line" "$C_NC"
        local _pcount=${#KC_PERSIST_ROWS[@]}
        local _dcount=${#KC_DESTRUCT_ROWS[@]}
        if (( _pcount > 0 || _dcount > 0 )); then
            local _cta="" _ltrs _section_count=0
            # sort -u for stable order across bash versions.
            if (( _pcount > 0 )); then
                _ltrs=$(printf '%s\n' "${!KC_PERSIST_LETTERS[@]}" | LC_ALL=C sort -u | paste -sd,)
                _cta+="${_pcount} persistence (${_ltrs})"
                _section_count=$(( _section_count + 1 ))
            fi
            if (( _dcount > 0 )); then
                _ltrs=$(printf '%s\n' "${!KC_DESTRUCT_LETTERS[@]}" | LC_ALL=C sort -u | paste -sd,)
                _cta+="${_cta:+ + }${_dcount} destruction (${_ltrs})"
                _section_count=$(( _section_count + 1 ))
            fi
            local _section_plural; (( _section_count == 1 )) && _section_plural="" || _section_plural="s"
            printf '%s%s%s action       %s%s — review section%s below%s\n' \
                "$C_BLD" "$GLYPH_BOX_V" "$C_NC" \
                "${C_BLD}${C_RED}" "$_cta" "$_section_plural" "$C_NC"
        fi
        printf '%s%s%s defenses     patch %s   modsec %s   csf %s   mitigate %s\n' \
            "$C_BLD" "$GLYPH_BOX_V" "$C_NC" "$def_patch" "$def_modsec" "$def_csf" "$def_mitigate"
        printf '%s%s%s%s\n' "$C_BLD" "$GLYPH_BOX_BL" "$full_bar" "$C_NC"

        (( ${#KC_PERSIST_ROWS[@]} > 0 )) \
            && render_kc_section "PERSISTENCE" "$C_YEL" "${KC_PERSIST_ROWS[@]}"
        (( ${#KC_DESTRUCT_ROWS[@]} > 0 )) \
            && render_kc_section "DESTRUCTION" "$C_RED" "${KC_DESTRUCT_ROWS[@]}"

        # ── Chronological tree ──────────────────────────────────────────
        # Single merged stream: defense + offense events, time-sorted, with
        # zone separators when verdict-class transitions (PRE→DEF→POST).
        if [[ -z "$merged" ]]; then
            printf '\n  %s%s no events to render (no offenses, no defenses)%s\n' \
                "$C_DIM" "$GLYPH_BOX_V" "$C_NC"
        else
            # Bucket merged entries into zones (pre/def/post/undef).
            # Class transitions emit a zone header with row count.
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
                        PRE-DEFENSE)              row_zone="pre"   ;;
                        UNDEFENDED)               row_zone="undef" ;;
                        POST-DEFENSE)             row_zone="post"  ;;
                        POST-PARTIAL)             row_zone="partial" ;;
                        ADVISORY-PRE-COMPROMISE)  row_zone="adv_pre"    ;;
                        ADVISORY-ORPHAN)          row_zone="adv_orphan" ;;
                        *)                        row_zone="other" ;;
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
            local r_str r_kind r_idx

            (( ${#zones[@]} > 0 )) && for zone_rec in "${zones[@]}"; do
                IFS='|' read -r z_id z_first z_last z_count <<< "$zone_rec"
                local z_color="$C_DIM" z_label="$z_id"
                case "$z_id" in
                    pre)         z_color="$C_RED";  z_label="PRE-DEFENSE"   ;;
                    undef)       z_color="$C_RED";  z_label="UNDEFENDED"    ;;
                    def)         z_color="$C_GRN";  z_label="DEFENSES"      ;;
                    post)        z_color="$C_GRN";  z_label="POST-DEFENSE"  ;;
                    partial)     z_color="$C_YEL";  z_label="POST-PARTIAL"  ;;
                    # Advisory zones — pre-compromise context (signals
                    # before/without the CRLF anchor) and
                    # exploitation-detached (post-CRLF but no nearby
                    # successful token use).
                    adv_pre)     z_color="$C_CYN";  z_label="ADVISORY (PRE-COMPROMISE CONTEXT)" ;;
                    adv_orphan)  z_color="$C_CYN";  z_label="ADVISORY (EXPLOITATION-DETACHED)" ;;
                    *)           z_color="$C_DIM";  z_label="$z_id"         ;;
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
                    IFS='|' read -r _ r_kind r_idx _ <<< "$r_str"
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
        (( ${#OFFENSE_EVENTS[@]} > 0 )) && for _oe in "${OFFENSE_EVENTS[@]}"; do
            _ts=$(printf '%s' "$_oe" | cut -d'|' -f1)
            [[ -z "$_ts" ]] && continue
            [[ -z "$min_off" ]] || (( _ts < min_off )) && min_off="$_ts"
        done
        (( ${#DEFENSE_EVENTS[@]} > 0 )) && for _de in "${DEFENSE_EVENTS[@]}"; do
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
            (( ${#ATTACKER_IP_ANNOTATED[@]} > 0 )) && for ann in "${ATTACKER_IP_ANNOTATED[@]}"; do
                printf '  %s%s                 %s%s%s %s\n' \
                    "$C_DIM" "$GLYPH_BOX_V" "$C_DIM" "$GLYPH_ARROW" "$C_NC" "$ann"
            done
        fi

        # Counters: UNDEFENDED rolls into N_PRE; ADVISORY rows are context,
        # never increment N_PRE/N_POST. Single pass over RECONCILED.
        local n_undef=0 n_adv=0 _r _v
        (( ${#RECONCILED[@]} > 0 )) && for _r in "${RECONCILED[@]}"; do
            _v=$(printf '%s' "$_r" | cut -d'|' -f1)
            case "$_v" in
                UNDEFENDED) n_undef=$(( n_undef + 1 )) ;;
                ADVISORY-*) n_adv=$(( n_adv + 1 )) ;;
            esac
        done
        # iocs counter excludes advisory rows (reported separately).
        local n_iocs_real=$(( ${#OFFENSE_EVENTS[@]} - n_adv ))
        (( n_iocs_real < 0 )) && n_iocs_real=0
        printf '\n  %scounters%s defenses=%d  iocs=%d  pre=%d  undef=%d  post=%d  advisory=%d  attackers=%d\n' \
            "$C_BLD" "$C_NC" \
            "${#DEFENSE_EVENTS[@]}" "$n_iocs_real" \
            "$(( N_PRE - n_undef ))" "$n_undef" "$N_POST" "$n_adv" "$ATTACKER_IP_TOTAL"
    } 2>&1)

    printf '%s\n' "$buf" >&2
    KILL_CHAIN_RENDERED=$(printf '%s\n' "$buf" | ansi_strip)
}

###############################################################################
# Kill-chain primitives writer — persists renderer inputs as
# kill-chain.{tsv,jsonl,md} for offline reconstruction.
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
        printf 'kind\tts_epoch\tts_iso\tpattern\tverdict\tdelta\tdefenses_at_ioc\tkey\tnote\tarea\tip\tpath\tlog_file\tcount\thits_2xx\tstatus\tline\tcpsess_token\n'

        # Defense rows.
        local de de_epoch de_key de_note _de_line
        local sorted_def=""
        # bash 4.1 (CL6/EL6 floor) + set -u: empty-array deref inside the
        # subshell crashes; guard with the project length-check idiom.
        if (( ${#DEFENSE_EVENTS[@]} > 0 )); then
            sorted_def=$(
                local d
                for d in "${DEFENSE_EVENTS[@]}"; do printf '%s\n' "$d"; done | sort -t'|' -k1,1n
            )
        fi
        # Pipe-tolerant decode (notes may contain '|').
        while IFS= read -r _de_line; do
            [[ -z "$_de_line" ]] && continue
            IFS=$'\t' read -r de_epoch de_key de_note < <(decode_pipe_tail "$_de_line" 3)
            [[ -z "$de_epoch" ]] && continue
            printf 'DEF\t%s\t%s\t-\t-\t-\t-\t%s\t%s\t-\t\t\t\t\t\t\t\t\n' \
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

                local area ip path log_file count h2xx status line cpsess_token
                IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line cpsess_token <<< "$clean"
                # Embedded literal tabs (rare) would collide with the bundle
                # TSV column separator; flatten to spaces.
                line="${line//$'\t'/ }"
                # r_note may contain literal tabs from upstream emit - sanitize.
                local nclean="${r_note//$'\t'/ }"
                nclean="${nclean//$'\n'/ }"

                printf 'IOC\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$r_epoch" "$(epoch_to_iso "$r_epoch")" \
                    "$r_pat" "$r_verdict" "$r_delta" "$dactive" \
                    "$r_key" "$nclean" \
                    "${area:-}" "${ip:-}" "${path:-}" "${log_file:-}" \
                    "${count:-}" "${h2xx:-}" "${status:-}" "${line:-}" "${cpsess_token:-}"
            done <<< "$i_sorted"
        done
    } > "$tsv"
    chmod 0600 "$tsv" 2>/dev/null

    # JSONL: line 1 is a meta object; subsequent lines are kind=DEF/IOC.
    # Schema v3: 'stage' renamed to 'pattern' (v2); 'cpsess_token' added
    # (v3). _schema_changes in meta lets consumers auto-detect the rename.
    {
        printf '{"kind":"meta","host":"%s","primary_ip":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-forensic","tool_version":"%s","schema_version":5,"_schema_changes":[{"v":2,"since_tool":"0.10.0","renamed":{"stage":"pattern"},"note":"IOC pattern letters were emitted as stage in schema v1 (forensic <= 0.9.x)"},{"v":3,"since_tool":"2.2.0","added":["cpsess_token"],"note":"cpsess token extracted at emit-time for Pattern E + ioc_attacker_ip_2xx_on_cpsess"},{"v":4,"since_tool":"2.7.0","added":["pattern_j","quarantined_session_emit","quarantine_run_dir","original_path","reasons_ioc","low_confidence_no_sidecar","degraded_confidence_snapshot"],"note":"Pattern J (udev/systemd-unit init-facility persistence) + mitigate-quarantine secondary read (synthetic emits from .info sidecar fields)"},{"v":5,"since_tool":"2.8.0","renamed":{"host_verdict":"host_root_verdict + host_user_verdict"},"note":"Two-axis verdict: actor-privilege (root/user) and affected_user split. host_verdict removed."}],"incident_id":"%s","run_id":"%s","ioc_scan_run_id":"%s","ioc_scan_tool_version":"%s","ioc_scan_ts":"%s","host_root_verdict":"%s","host_user_verdict":"%s","code_verdict":"%s","score":"%s","effective_patch_epoch":"%s","effective_modsec_epoch":"%s"}\n' \
            "${HOSTNAME_JSON:-}" "${PRIMARY_IP_J:-}" "${LP_UID_J:-}" "${OS_J:-}" "${CPV_J:-}" "${TS_ISO:-}" \
            "$VERSION" "${INCIDENT_ID:-}" "$RUN_ID" \
            "$(json_esc "${ENV_IOC_RUN_ID:-}")" "$(json_esc "${ENV_IOC_TOOL_VERSION:-}")" "$(json_esc "${ENV_IOC_TS:-}")" \
            "$(json_esc "${ENV_HOST_ROOT_VERDICT:-${HOST_ROOT_VERDICT:-}}")" \
            "$(json_esc "${ENV_HOST_USER_VERDICT:-${HOST_USER_VERDICT:-}}")" \
            "$(json_esc "${ENV_CODE_VERDICT:-${VERDICT:-}}")" \
            "$(json_esc "${ENV_SCORE:-${SCORE:-0}}")" \
            "${eff_patch:-}" "${eff_modsec:-}"

        local de de_epoch de_key de_note _de_line
        local sorted_def=""
        # bash 4.1 (CL6/EL6 floor) + set -u: empty-array deref inside the
        # subshell crashes; guard with the project length-check idiom.
        if (( ${#DEFENSE_EVENTS[@]} > 0 )); then
            sorted_def=$(
                local d
                for d in "${DEFENSE_EVENTS[@]}"; do printf '%s\n' "$d"; done | sort -t'|' -k1,1n
            )
        fi
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
                local area ip path log_file count h2xx status line cpsess_token
                IFS="$PRIM_SEP" read -r area ip path log_file count h2xx status line cpsess_token <<< "$prims"

                # JSONL schema v3: per-IOC 'stage' was renamed to 'pattern'
                # in v2; v3 added 'cpsess_token'. Meta row carries
                # schema_version + _schema_changes so consumers can adapt.
                printf '{"kind":"IOC","epoch":%s,"ts":"%s","pattern":"%s","verdict":"%s","delta":"%s","defenses_at_ioc":"%s","key":"%s","note":"%s","area":"%s","ip":"%s","path":"%s","log_file":"%s","count":"%s","hits_2xx":"%s","status":"%s","cpsess_token":"%s","line":"%s"}\n' \
                    "$r_epoch" "$(epoch_to_iso "$r_epoch")" \
                    "$(json_esc "$r_pat")" "$(json_esc "$r_verdict")" \
                    "$(json_esc "$r_delta")" "$(json_esc "$dactive")" \
                    "$(json_esc "$r_key")" "$(json_esc "$r_note")" \
                    "$(json_esc "$area")" "$(json_esc "$ip")" \
                    "$(json_esc "$path")" "$(json_esc "$log_file")" \
                    "$(json_esc "$count")" "$(json_esc "$h2xx")" \
                    "$(json_esc "$status")" "$(json_esc "${cpsess_token:-}")" \
                    "$(json_esc "$line")"
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

# Bundle + upload pipeline. Root: $BUNDLE_DIR_ROOT/<TS>-<RUN_ID>/.
# Per-tarball cap: --max-bundle-mb. Upload PUT to $INTAKE_URL.

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

# Tar a candidate set with pre-flight size check. Args:
#   $1 dest, $2 label, $3 mode (filtered=NUL paths from $4 file; raw=$4..N).
# Skips with warning if estimated size > MAX_BUNDLE_MB (when > 0).
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

prune_old_bundles() {
    local keep="${BUNDLE_RETENTION:-$DEFAULT_BUNDLE_RETENTION}"
    local root="$BUNDLE_DIR_ROOT"
    [[ -d "$root" && "$keep" -gt 0 ]] || return 0

    # TS_ISO prefix: YYYY-MM-DDThh:mm:ssZ-...
    local prefix='^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z-'

    local bases=()
    local seen="|"
    local name base
    while IFS= read -r name; do
        base="${name%.upload.tgz}"
        [[ "$base" =~ $prefix ]] || continue
        case "$seen" in *"|${base}|"*) continue ;; esac
        seen="${seen}${base}|"
        bases+=("$base")
    done < <(find "$root" -maxdepth 1 -mindepth 1 \
              \( -type d -o -name '*.upload.tgz' \) \
              -printf '%f\n' 2>/dev/null | sort -r)

    local n=${#bases[@]}
    (( n > keep )) || return 0

    local pruned=0 freed_kb=0 i b entry sz
    for (( i = keep; i < n; i++ )); do
        b="${bases[$i]}"
        for entry in "$root/$b" "$root/${b}.upload.tgz"; do
            [[ -e "$entry" ]] || continue
            sz=$(du -sk -- "$entry" 2>/dev/null | awk '{print $1}')
            if rm -rf -- "$entry" 2>/dev/null; then
                freed_kb=$((freed_kb + ${sz:-0}))
            fi
        done
        pruned=$((pruned+1))
    done

    if (( pruned > 0 )); then
        local freed_mb=$(( freed_kb / 1024 ))
        say_info "pruned $pruned old bundle(s); freed ~${freed_mb}MiB (kept $keep newest)"
        emit_signal bundle info bundle_pruned \
            "retention=$keep pruned=$pruned freed_mib=$freed_mb" \
            retention "$keep" pruned "$pruned" freed_mib "$freed_mb"
    fi
}

phase_bundle() {
    if (( TELEMETRY_MODE )); then
        hdr_section "bundle" "lite mode (envelope + kill-chain + KB snapshots; no tarballs)"
    else
        hdr_section "bundle" "capturing raw artifacts (window=${SINCE_DAYS:-all}d, cap=${MAX_BUNDLE_MB}MB)"
    fi

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
        echo "kernel_running=$KERNEL_RUNNING"
        echo "kernel_full=$KERNEL_FULL"
        echo "kernel_latest_installed=$KERNEL_LATEST_INSTALLED"
        echo "kernel_reboot_pending=$KERNEL_REBOOT_PENDING"
        echo "kernel_tainted=$KERNEL_TAINTED"
        echo "pkgmgr_kind=$PKGMGR_KIND"
        echo "pkgmgr_health=$PKGMGR_HEALTH"
        echo "pkgmgr_health_note=$PKGMGR_HEALTH_NOTE"
        echo "pkgmgr_last_txn_epoch=$PKGMGR_LAST_TXN_EPOCH"
        echo "disk_health=$DISK_HEALTH"
        echo "disk_full_mounts=$DISK_FULL_MOUNTS"
        echo "disk_inode_full_mounts=$DISK_INODE_FULL_MOUNTS"
        echo "boot_free_mb=$BOOT_FREE_MB"
    } > "$bdir/manifest.txt"

    # Sidecar is also gzip+base64-embedded in the envelope (encoder may
    # fail on legacy distros without gzip/base64; sidecar preserved).
    local inv="$bdir/software-inventory.txt"
    local inv_kind="" inv_rc=0
    # Skip the inventory query when the pkgmgr health probe already flagged
    # the rpmdb/dpkg state as broken/locked/unknown — rpm -qa hangs forever
    # on a corrupt rpmdb and would burn the 300s cap for no payload.
    if [[ "$PKGMGR_HEALTH" != "ok" ]]; then
        : > "$inv.body"
        inv_rc=125
        if [[ "$PKGMGR_KIND" == "dnf" || "$PKGMGR_KIND" == "yum" ]]; then
            inv_kind="rpm"
        elif [[ "$PKGMGR_KIND" == "apt" ]]; then
            inv_kind="dpkg"
        fi
    elif [[ "$PKGMGR_KIND" == "dnf" || "$PKGMGR_KIND" == "yum" ]] && command -v rpm >/dev/null 2>&1; then
        inv_kind="rpm"
        timeout 300 rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' \
            > "$inv.body" 2>/dev/null
        inv_rc=$?
    elif [[ "$PKGMGR_KIND" == "apt" ]] && command -v dpkg-query >/dev/null 2>&1; then
        inv_kind="dpkg"
        timeout 300 dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' \
            > "$inv.body" 2>/dev/null
        inv_rc=$?
    fi
    # Treat timeout (124) and health-skip (125) as no-inventory so a partial
    # rpm -qa truncated mid-stream doesn't masquerade as a complete list.
    if (( inv_rc == 124 || inv_rc == 125 )); then
        : > "$inv.body"
    fi
    if [[ -s "$inv.body" ]]; then
        PKG_INVENTORY_COUNT=$(wc -l < "$inv.body" 2>/dev/null)
        PKG_INVENTORY_COUNT="${PKG_INVENTORY_COUNT//[[:space:]]/}"
    fi
    {
        echo "# software-inventory kind=$inv_kind ts=$TS_ISO count=${PKG_INVENTORY_COUNT}"
        cat "$inv.body" 2>/dev/null
    } > "$inv"
    rm -f "$inv.body"
    chmod 0600 "$inv" 2>/dev/null
    emit_signal bundle info pkg_inventory_written \
        "package inventory captured (kind=${inv_kind:-none} count=${PKG_INVENTORY_COUNT})" \
        kind "${inv_kind:-none}" count "$PKG_INVENTORY_COUNT" path "software-inventory.txt"

    # Encode the inventory for envelope embedding. Override-note carries
    # the skip reason (timeout / pkgmgr-unhealthy) so a header-only file
    # doesn't silently become `note=header_only`.
    local _enc_override=""
    case "$inv_rc" in
        124) _enc_override="query_timeout" ;;
        125) _enc_override="pkgmgr_${PKGMGR_HEALTH:-unknown}" ;;
    esac
    encode_software_inventory_b64gz "$inv" "$_enc_override"
    emit_signal bundle info pkg_inventory_b64gz \
        "inventory encoded for envelope (note=${SOFTWARE_INVENTORY_B64GZ_NOTE:-unknown} raw=${SOFTWARE_INVENTORY_RAW_BYTES} enc=${SOFTWARE_INVENTORY_ENCODED_BYTES})" \
        note "${SOFTWARE_INVENTORY_B64GZ_NOTE:-unknown}" \
        raw_bytes "$SOFTWARE_INVENTORY_RAW_BYTES" \
        encoded_bytes "$SOFTWARE_INVENTORY_ENCODED_BYTES" \
        sha256 "${SOFTWARE_INVENTORY_SHA256:-}"

    # Re-write envelope NOW so phase_telemetry_post ships the inventory in
    # the same POST; end-of-run re-write is too late. Direct-to-bundle
    # path — LEDGER_DIR is fallback only (intake must never see missing
    # ioc-scan-envelope.json or it silently CLEANs by threshold).
    local _env_dest="$bdir/ioc-scan-envelope.json"
    local _env_src="${ENVELOPE_PATH:-${SESSIONSCRIBE_IOC_JSON:-}}"
    write_json "$_env_dest" 2>/dev/null
    if [[ -s "$_env_dest" ]]; then
        chmod 0600 "$_env_dest" 2>/dev/null
        local env_size
        env_size=$(stat -c %s "$_env_dest" 2>/dev/null)
        emit_signal bundle info ioc_envelope_captured \
            "ioc-scan envelope written to bundle (${env_size:-?} bytes)" \
            dest "ioc-scan-envelope.json" bytes "${env_size:-0}"
    elif [[ -n "$_env_src" && -f "$_env_src" && -s "$_env_src" ]]; then
        # Fallback: copy from LEDGER_DIR if write_json failed.
        if cp "$_env_src" "$_env_dest" 2>/dev/null; then
            chmod 0600 "$_env_dest" 2>/dev/null
            local env_size
            env_size=$(stat -c %s "$_env_dest" 2>/dev/null)
            emit_signal bundle info ioc_envelope_captured_fallback \
                "ioc-scan envelope copied from ledger to bundle (${env_size:-?} bytes; direct write failed)" \
                src "$_env_src" dest "ioc-scan-envelope.json" bytes "${env_size:-0}"
        else
            rm -f "$_env_dest" 2>/dev/null
            emit_signal bundle fail ioc_envelope_missing \
                "ioc-scan envelope absent from bundle — both direct-write and ledger cp failed" \
                src "$_env_src"
        fi
    else
        rm -f "$_env_dest" 2>/dev/null
        emit_signal bundle fail ioc_envelope_missing \
            "ioc-scan envelope absent from bundle — direct write failed and no ledger fallback available" \
            ledger_path "${_env_src:-<unset>}"
    fi
    # Also refresh the ledger envelope (best effort; failure does not affect
    # the bundle copy, which is authoritative now).
    if [[ -n "$_env_src" ]]; then
        write_json "$_env_src" 2>/dev/null
        chmod 0600 "$_env_src" 2>/dev/null
    fi

    # Kill-chain primitives next to the manifest. These are tiny (KB-scale)
    # so they're always written - independent of any per-tarball size cap.
    write_kill_chain_primitives

    # cPanel sessions: bundle raw/+preauth/ (where the IOCs live); skip
    # cache/tmpcache (encoder noise). TELEMETRY_MODE skips entirely (PII).
    if (( ! TELEMETRY_MODE )); then
        local sess_list; sess_list=$(mktemp /tmp/forensic-sess.XXXXXX)
        {
            collect_recent /var/cpanel/sessions/raw
            collect_recent /var/cpanel/sessions/preauth
        } > "$sess_list" 2>/dev/null
        bundle_tar "sessions.tgz" "sessions (raw+preauth)" filtered "$sess_list"
        rm -f "$sess_list"
    fi

    # TELEMETRY skips sections 2-5 (MB-scale subtrees); envelope signals[]
    # already carries the derived IOC findings. Re-run sans --telemetry
    # on flagged hosts for the raw artifacts.
    if (( ! TELEMETRY_MODE )); then

    # Apache + cPanel access + cpsrvd incoming/error logs, window-filtered.
    # incoming_http_requests.log (when enabled) carries the raw CRLF carrier.
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

    # System auth/audit logs (secure, messages, audit.log) — mtime-filtered
    # to incident window. /var/log/auth.log included for Debian-family.
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

    # 4. Persistence artifacts - ssh/cron/systemd/init/profile.d/histories/passwd/sudoers (no shadow).
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
    # /etc/shadow NOT bundled (sensitive, no Pattern uses it). /etc/sudoers
    # + /etc/sudoers.d/ are bundled — attacker-planted NOPASSWD rules
    # are common post-RCE persistence; mtime/ctime brackets plant time.
    [[ -f /etc/sudoers ]] && persist+=(/etc/sudoers)
    [[ -d /etc/sudoers.d ]] && persist+=(/etc/sudoers.d)
    bundle_tar "persistence.tgz" "persistence artifacts" raw "${persist[@]}"

    # 5. Defense state. updatelogs accumulate per upcp; filter by window so
    # 5-year-old host doesn't blow the budget on historical update logs.
    local def_static=()
    [[ -d "$MITIGATE_BACKUP_ROOT" ]] && def_static+=("$MITIGATE_BACKUP_ROOT")
    [[ -f /etc/csf/csf.conf ]] && def_static+=(/etc/csf/csf.conf)
    local _csf_bak_name
    for _csf_bak_name in /etc/csf/csf.conf.cve-2026-41940.bak /etc/csf/csf.conf.ic5790.bak; do
        [[ -f "$_csf_bak_name" ]] && def_static+=("$_csf_bak_name")
    done
    [[ -f /etc/apf/conf.apf ]] && def_static+=(/etc/apf/conf.apf)
    [[ -f "$MODSEC_USER_CONF" ]] && def_static+=("$MODSEC_USER_CONF")
    local def_list; def_list=$(mktemp /tmp/forensic-def.XXXXXX)
    {
        # bash 4.1 (CL6/EL6 floor) + set -u: empty-array deref crashes;
        # def_static may be empty on a stock host with no defense files.
        local p
        if (( ${#def_static[@]} > 0 )); then
            for p in "${def_static[@]}"; do printf '%s\0' "$p"; done
        fi
        collect_recent /var/cpanel/updatelogs
    } > "$def_list" 2>/dev/null
    bundle_tar "defense-state.tgz" "defense state" filtered "$def_list"
    rm -f "$def_list"

    fi  # TELEMETRY_MODE skip — end of heavy-tarball block

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
    # 30s cap; -X skips socket xref (ss already has it). stderr→/dev/null so
    # `lsof: no pwd entry for UID NNN` warnings don't pollute the data file.
    # Emit distinct signals so renders can tell missing/timeout/empty apart.
    if have_cmd lsof; then
        local _lsof_rc=0 _lsof_bytes=0
        if have_cmd timeout; then
            timeout 30 lsof -nP -X >"$bdir/lsof.txt" 2>/dev/null
        else
            lsof -nP -X >"$bdir/lsof.txt" 2>/dev/null
        fi
        _lsof_rc=$?
        [[ -f "$bdir/lsof.txt" ]] && _lsof_bytes=$(stat -c %s "$bdir/lsof.txt" 2>/dev/null)
        _lsof_bytes="${_lsof_bytes:-0}"
        if   (( _lsof_rc == 124 )); then
            emit_signal bundle warn lsof_timeout \
                "lsof exceeded 30s SIGKILL; lsof.txt may be partial (${_lsof_bytes}B)" \
                rc "$_lsof_rc" bytes "$_lsof_bytes"
        elif (( _lsof_rc != 0 )); then
            emit_signal bundle warn lsof_failed \
                "lsof rc=$_lsof_rc (${_lsof_bytes}B)" rc "$_lsof_rc" bytes "$_lsof_bytes"
        elif (( _lsof_bytes == 0 )); then
            emit_signal bundle warn lsof_empty \
                "lsof rc=0 but produced no rows" rc "$_lsof_rc"
        else
            emit_signal bundle info lsof_captured \
                "lsof captured (${_lsof_bytes}B)" bytes "$_lsof_bytes"
        fi
    else
        emit_signal bundle info lsof_missing "lsof binary not in PATH"
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
        echo "# Pattern H seobot.php capture (CVE-2026-41940 dossier rev3)"
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
            echo "# Pattern I system-service binary capture (CVE-2026-41940 dossier rev3)"
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
    # TELEMETRY: skipped — per-account histories can be MB-scale on shared
    # hosts; the IOC engine's history-pattern findings are already in
    # signals[].
    if (( INCLUDE_HOMEDIR_HISTORY )) && (( ! TELEMETRY_MODE )); then
        mkdir -p "$bdir/user-histories"
        local found=0
        while IFS= read -r -d '' h; do
            local user
            user=$(echo "$h" | awk -F/ '{print $3}')
            cp "$h" "$bdir/user-histories/$user.history" 2>/dev/null && found=$((found+1))
        done < <(find /home -maxdepth 3 -name '.bash_history' -type f -print0 2>/dev/null)
        say_info "captured $found user bash histories"
    fi

    # Retention sweep: keep current run + DEFAULT_BUNDLE_RETENTION-1 prior
    # runs, prune the rest. Runs after capture so the just-built bundle is
    # always in the keep set. No-op if $BUNDLE_RETENTION is set to 0.
    prune_old_bundles

    # Final sweep: signal what we built.
    local total_size
    total_size=$(du -sh "$bdir" 2>/dev/null | awk '{print $1}')
    say_info "bundle complete: $bdir ($total_size)"
    emit_signal bundle info bundle_complete "dir=$bdir size=$total_size" dir "$bdir" size "$total_size"
}

phase_upload() {
    (( DO_UPLOAD )) || return 0
    if (( TELEMETRY_MODE )); then
        hdr_section "upload" "submitting LITE bundle to $INTAKE_URL (telemetry mode; no heavy tarballs)"
    else
        hdr_section "upload" "submitting bundle to $INTAKE_URL"
    fi

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

    # Outer tarball wraps the bundle dir as one upload artifact with valid
    # gzip magic. In TELEMETRY_MODE there are no inner tarballs, so the
    # outer is the primary compression layer (KB-scale upload).
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
        url "$INTAKE_URL" body "$body" outer "$outer" \
        telemetry_mode "$TELEMETRY_MODE"

    # Success: drop the outer tarball; the bundle dir itself is kept for
    # local IR review.
    rm -f "$outer"
}

# Telemetry POST — envelope.json (KB-scale) to a fleet collector.
# Transport ladder: curl > wget > bash /dev/tcp + openssl.
# Retry with 2^N expo backoff; failure warns, never changes EXIT_CODE.

phase_telemetry_post() {
    (( TELEMETRY_MODE )) || return 0
    [[ -z "$TELEMETRY_URL" ]] && return 0
    hdr_section "telemetry" "POST envelope to $TELEMETRY_URL"

    # Locate envelope. Bundle copy is preferred (it lives next to the
    # kill-chain primitives the operator may also want to ship out-of-band)
    # but ENVELOPE_PATH is the canonical ledger record and always exists
    # in --full mode (the --no-ledger gate at parse time guarantees this).
    local env_src=""
    if [[ -n "${BUNDLE_BDIR:-}" && -f "${BUNDLE_BDIR}/ioc-scan-envelope.json" ]]; then
        env_src="${BUNDLE_BDIR}/ioc-scan-envelope.json"
    elif [[ -n "${ENVELOPE_PATH:-}" && -f "$ENVELOPE_PATH" ]]; then
        env_src="$ENVELOPE_PATH"
    fi
    if [[ -z "$env_src" ]]; then
        say_warn "no envelope on disk to POST (BUNDLE_BDIR + ENVELOPE_PATH both empty)"
        # warn (not fail): telemetry-internal errors are operational, not
        # security findings. emit_signal "fail" maps to severity=strong
        # which would render as [IOC] in the section matrix and could mask
        # genuine exploit signals. warn → severity=warning is correct.
        emit_signal telemetry warn telemetry_no_envelope \
            "no envelope on disk to POST"
        return
    fi

    # Size gate: protect the endpoint from pathological envelopes.
    local env_size=0
    env_size=$(stat -c %s "$env_src" 2>/dev/null)
    env_size="${env_size:-0}"
    if (( env_size == 0 )); then
        say_warn "envelope is empty: $env_src"
        emit_signal telemetry warn telemetry_envelope_empty \
            "envelope file is zero bytes" path "$env_src"
        return
    fi
    if (( env_size > TELEMETRY_MAX_BYTES )); then
        say_warn "envelope size ${env_size} > cap ${TELEMETRY_MAX_BYTES}; skipping POST"
        emit_signal telemetry warn telemetry_envelope_too_large \
            "envelope_size=${env_size} cap=${TELEMETRY_MAX_BYTES}" \
            bytes "$env_size" cap "$TELEMETRY_MAX_BYTES" path "$env_src"
        return
    fi

    # Probe best-first, stop at first viable. HTTPS adds an SSL
    # requirement (SSL-capable curl/wget OR openssl) — surfaced as a
    # separate diagnostic when a transport is rejected.
    local _xport=""
    local _is_https=0
    [[ "$TELEMETRY_URL" =~ ^https:// ]] && _is_https=1

    if have_cmd curl; then
        _xport="curl"
    elif have_cmd wget; then
        # wget WITHOUT SSL support exists on stripped CL6 (gnu wget 1.12);
        # for HTTPS we need to verify SSL is compiled in. `wget --version`
        # lists +ssl/-ssl in the feature list.
        if (( _is_https )); then
            if wget --version 2>/dev/null | grep -qE '\+(ssl|https)'; then
                _xport="wget"
            fi
        else
            _xport="wget"
        fi
    fi
    # bash-native fallback: /dev/tcp (HTTP) / openssl s_client (HTTPS).
    # Requires bash built with --enable-net-redirections (RHEL/CL6+ does).
    if [[ -z "$_xport" ]]; then
        if (( _is_https )); then
            have_cmd openssl && _xport="bash"
        else
            _xport="bash"
        fi
    fi

    if [[ -z "$_xport" ]]; then
        local _need_msg="curl, wget, or bash + openssl"
        (( _is_https )) && _need_msg="curl, wget(+ssl), or bash + openssl s_client"
        say_warn "no HTTP transport available (need: $_need_msg)"
        emit_signal telemetry warn telemetry_no_transport \
            "need: $_need_msg" \
            url "$TELEMETRY_URL" is_https "$_is_https"
        say_info "lite bundle preserved at ${BUNDLE_BDIR:-(not created)} for out-of-band collection"
        return
    fi
    say_info "transport: $_xport (envelope=${env_size}B)"

    # Retry loop, 2^attempt backoff. TELEMETRY_RETRY hard-capped at 10
    # (attempt=10 ≈17min; attempt=20 would be 12d).
    local attempt=0 max_attempts=$((TELEMETRY_RETRY + 1))
    if (( max_attempts > 11 )); then max_attempts=11; fi
    # Hoist all per-attempt locals to the function scope (vs re-declaring
    # inside the case branches each loop iteration). The mktemp-issued
    # tempfiles are recreated per attempt; the names are reused as
    # variables.
    local rc=0 http_code="" body="" t_start t_end duration_ms last_err=""
    local _resp_file="" _hdr_file="" _err_file="" _req_file=""
    local _curl_args=() _wget_args=()
    local _scheme="" _rest="" _hp="" _path="" _host="" _port="" _host_hdr=""
    local _status_line="" backoff=0
    t_start=$(date -u +%s)
    while (( attempt < max_attempts )); do
        attempt=$((attempt + 1))
        rc=0; http_code=""; body=""; last_err=""
        case "$_xport" in
            curl)
                _resp_file=$(mktemp /tmp/telemetry-resp.XXXXXX)
                _err_file=$(mktemp /tmp/telemetry-err.XXXXXX)
                _curl_args=(
                    --silent --show-error
                    --max-time "$TELEMETRY_TIMEOUT"
                    -X POST
                    -H "Content-Type: application/json"
                    -H "User-Agent: sessionscribe-ioc-scan/${VERSION}"
                    --data-binary "@${env_src}"
                    -o "$_resp_file"
                    -w '%{http_code}'
                )
                [[ -n "$TELEMETRY_TOKEN" ]] && \
                    _curl_args+=(-H "Authorization: Bearer ${TELEMETRY_TOKEN}")
                http_code=$(curl "${_curl_args[@]}" "$TELEMETRY_URL" 2>"$_err_file") || rc=$?
                body=$(head -c 2048 "$_resp_file" 2>/dev/null)
                last_err=$(head -c 512 "$_err_file" 2>/dev/null)
                rm -f "$_resp_file" "$_err_file"
                ;;
            wget)
                # wget2 (EL9+) silences --server-response under --quiet/
                # --no-verbose, so we run with default noise and grep
                # 2>FILE for the `HTTP/1.1 NNN` line (CL6 wget 1.12 too).
                _resp_file=$(mktemp /tmp/telemetry-resp.XXXXXX)
                _hdr_file=$(mktemp /tmp/telemetry-hdr.XXXXXX)
                _wget_args=(
                    --tries=1
                    --timeout="$TELEMETRY_TIMEOUT"
                    --header="Content-Type: application/json"
                    --header="User-Agent: sessionscribe-ioc-scan/${VERSION}"
                    --post-file="$env_src"
                    --server-response
                    -O "$_resp_file"
                )
                [[ -n "$TELEMETRY_TOKEN" ]] && \
                    _wget_args+=(--header="Authorization: Bearer ${TELEMETRY_TOKEN}")
                # wget2 (EL9+) writes --server-response to stdout; classic
                # wget 1.12 (CL6) writes to stderr. -O FILE owns the body,
                # so combining stdout+stderr for the header trace is safe.
                wget "${_wget_args[@]}" "$TELEMETRY_URL" >"$_hdr_file" 2>&1 || rc=$?
                # Last "HTTP/x.x NNN" line. Both wget1 and wget2 print the
                # status line either bare or 2-space-indented; match both.
                http_code=$(grep -E '^[[:space:]]*HTTP/' "$_hdr_file" 2>/dev/null \
                    | tail -1 | awk '{print $2}')
                body=$(head -c 2048 "$_resp_file" 2>/dev/null)
                last_err=$(head -c 512 "$_hdr_file" 2>/dev/null)
                rm -f "$_resp_file" "$_hdr_file"
                ;;
            bash)
                # Bash-native HTTP. Tempfile-staged request (atomic on
                # wire), delivered via /dev/tcp or openssl s_client.
                # Wrapped in `timeout` bounded by TELEMETRY_TIMEOUT.
                _scheme="${TELEMETRY_URL%%://*}"
                _rest="${TELEMETRY_URL#*://}"
                _hp="${_rest%%/*}"
                if [[ "$_rest" == "$_hp" ]]; then
                    _path="/"
                else
                    _path="/${_rest#*/}"
                fi
                _host="${_hp%%:*}"
                _port=""
                [[ "$_hp" == *":"* ]] && _port="${_hp##*:}"
                if [[ -z "$_port" ]]; then
                    case "$_scheme" in
                        https) _port=443 ;;
                        *)     _port=80  ;;
                    esac
                fi
                # Host header includes :port only when non-default.
                _host_hdr="$_host"
                case "$_scheme" in
                    https) [[ "$_port" != "443" ]] && _host_hdr="${_host}:${_port}" ;;
                    *)     [[ "$_port" != "80"  ]] && _host_hdr="${_host}:${_port}" ;;
                esac

                _req_file=$(mktemp /tmp/telemetry-req.XXXXXX)
                _resp_file=$(mktemp /tmp/telemetry-resp.XXXXXX)
                # Build request: line-endings MUST be \r\n per RFC 7230.
                # printf '\r\n' is reliable across bash 4.1+.
                {
                    printf 'POST %s HTTP/1.1\r\n' "$_path"
                    printf 'Host: %s\r\n' "$_host_hdr"
                    printf 'User-Agent: sessionscribe-ioc-scan/%s\r\n' "$VERSION"
                    printf 'Content-Type: application/json\r\n'
                    [[ -n "$TELEMETRY_TOKEN" ]] && \
                        printf 'Authorization: Bearer %s\r\n' "$TELEMETRY_TOKEN"
                    printf 'Content-Length: %d\r\n' "$env_size"
                    printf 'Connection: close\r\n'
                    printf '\r\n'
                    cat "$env_src"
                } > "$_req_file"

                if [[ "$_scheme" == "https" ]]; then
                    # -ign_eof avoids truncated body on TLS close-notify;
                    # -servername for SNI; argv-passed args (no quote-
                    # injection surface for hostile URL values).
                    timeout "$TELEMETRY_TIMEOUT" openssl s_client \
                        -connect "${_host}:${_port}" \
                        -servername "$_host" \
                        -quiet -ign_eof \
                        < "$_req_file" \
                        > "$_resp_file" 2>/dev/null
                    rc=$?
                else
                    # SAFETY: pass _host/_port/_req_file via env (not shell
                    # interpolation) — operator-supplied URL host could
                    # contain a single-quote that breaks quote nesting and
                    # injects a command into the child shell.
                    _SS_H="$_host" _SS_P="$_port" _SS_R="$_req_file" \
                    timeout "$TELEMETRY_TIMEOUT" bash -c '
                        exec 9<>/dev/tcp/"$_SS_H"/"$_SS_P" || exit 1
                        cat "$_SS_R" >&9
                        cat <&9
                        exec 9>&-
                    ' > "$_resp_file" 2>/dev/null
                    rc=$?
                fi

                # Parse status line: first non-empty line is "HTTP/x.x NNN ...".
                # Body is whatever follows the first blank header-terminator.
                if [[ -s "$_resp_file" ]]; then
                    _status_line=$(grep -m1 -E '^HTTP/[0-9.]+[[:space:]]+[0-9]+' \
                        "$_resp_file" 2>/dev/null)
                    http_code=$(printf '%s' "$_status_line" | awk '{print $2}')
                    # awk: skip header block (everything up to first blank
                    # line, where blank = optional \r), then print body.
                    # Cap at 2048 bytes for the JSON envelope.
                    body=$(awk 'BEGIN{p=0} \
                                /^\r?$/ {if (!p) {p=1; next}} \
                                p {print}' "$_resp_file" 2>/dev/null \
                           | head -c 2048)
                    if [[ -z "$_status_line" ]]; then
                        # Response received but no recognizable HTTP/x.x
                        # status line — endpoint isn't speaking HTTP, or
                        # TLS handshake failed and we got cleartext junk.
                        # head -c 200 keeps the diagnostic short.
                        last_err="malformed response (no HTTP status line): $(head -c 200 "$_resp_file")"
                    fi
                else
                    last_err="empty response (rc=$rc)"
                fi
                rm -f "$_req_file" "$_resp_file"
                ;;
        esac

        if (( rc == 0 )) && [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            t_end=$(date -u +%s)
            duration_ms=$(( (t_end - t_start) * 1000 ))
            say_pass "POST ok: http=$http_code attempt=$attempt duration=${duration_ms}ms"
            emit_signal telemetry info telemetry_post_complete \
                "http=$http_code attempt=$attempt duration_ms=$duration_ms transport=$_xport" \
                http_code "$http_code" attempt "$attempt" \
                duration_ms "$duration_ms" transport "$_xport" \
                bytes "$env_size" url "$TELEMETRY_URL"
            return
        fi

        # Non-2xx OR transport error — record and (maybe) retry.
        say_warn "POST attempt $attempt/$max_attempts failed (rc=$rc http=${http_code:-?})"
        if (( attempt < max_attempts )); then
            backoff=$(( 1 << attempt ))
            say_info "retry in ${backoff}s"
            sleep "$backoff"
        fi
    done

    t_end=$(date -u +%s)
    duration_ms=$(( (t_end - t_start) * 1000 ))
    say_fail "POST failed after $max_attempts attempts (rc=$rc http=${http_code:-?})"
    [[ -n "$body" ]] && say_fail "  response: $(printf '%s' "$body" | head -c 256)"
    [[ -n "$last_err" ]] && say_fail "  err: $(printf '%s' "$last_err" | head -c 256)"
    emit_signal telemetry warn telemetry_post_failed \
        "attempts=$max_attempts rc=$rc http=${http_code:-?} transport=$_xport" \
        attempts "$max_attempts" rc "$rc" http_code "${http_code:-}" \
        transport "$_xport" duration_ms "$duration_ms" \
        body "$(printf '%s' "$body" | head -c 256)" \
        err "$(printf '%s' "$last_err" | head -c 256)" \
        url "$TELEMETRY_URL"
    say_info "lite bundle preserved at ${BUNDLE_BDIR:-(not created)} for retry"
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
    hdr_section "version" "cpanel -V vs published patched-build cutoffs"
    local raw=""
    if [[ -n "$VERSION_OVERRIDE" ]]; then
        raw="$VERSION_OVERRIDE"
    elif [[ -x "${CPANEL_ROOT}/cpanel" ]]; then
        # Discard stderr (perl deprecation noise) + strip CR so a
        # CRLF pipe doesn't leave \r inside build digits.
        raw=$("${CPANEL_ROOT}/cpanel" -V 2>/dev/null | head -1 | tr -d '\r')
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

    # Mirrors collect_host_meta(). WP Squared shape (11.<t>.1.<b>) dispatches
    # to its own cutoff and short-circuits the main ladder.
    local tier="" build="" _is_wpsq=0
    if [[ "$raw" =~ ^[[:space:]]*([0-9]{2,3})\.0[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        tier="${BASH_REMATCH[1]}"; build="${BASH_REMATCH[2]}"
    elif [[ "$raw" =~ ^[[:space:]]*(11\.)?([0-9]{2,3})\.0\.([0-9]+) ]]; then
        tier="${BASH_REMATCH[2]}"; build="${BASH_REMATCH[3]}"
    elif [[ "$raw" =~ ^[[:space:]]*([0-9]{2,3})\.1[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        tier="${BASH_REMATCH[1]}"; build="${BASH_REMATCH[2]}"; _is_wpsq=1
    elif [[ "$raw" =~ ^[[:space:]]*(11\.)?([0-9]{2,3})\.1\.([0-9]+) ]]; then
        tier="${BASH_REMATCH[2]}"; build="${BASH_REMATCH[3]}"; _is_wpsq=1
    fi

    if [[ -z "$tier" || -z "$build" ]]; then
        emit "version" "version_detect" "error" "unparseable" 0 \
             "raw" "$raw"
        return
    fi

    local _shape_label=0; (( _is_wpsq )) && _shape_label=1
    emit "version" "version_detect" "info" "detected" 0 \
         "version" "${tier}.${_shape_label}.${build}" "tier" "$tier" \
         "build" "$build" "raw" "$raw" "wpsquared" "$_is_wpsq"

    if (( _is_wpsq )); then
        if [[ "$tier" == "$PATCHED_WPSQUARED_TIER" ]]; then
            if (( build >= PATCHED_WPSQUARED_BUILD )); then
                emit "version" "tier_class" "info" "patched_per_build" 5 \
                     "tier" "$tier" "build" "$build" \
                     "cutoff" "$PATCHED_WPSQUARED_BUILD" "wpsquared" "1" \
                     "note" "${tier}.1.${build} ≥ WP Squared cutoff ${tier}.1.${PATCHED_WPSQUARED_BUILD}"
            else
                emit "version" "tier_class" "strong" "vulnerable_per_build" 5 \
                     "tier" "$tier" "build" "$build" \
                     "cutoff" "$PATCHED_WPSQUARED_BUILD" "wpsquared" "1" \
                     "note" "${tier}.1.${build} < WP Squared cutoff ${tier}.1.${PATCHED_WPSQUARED_BUILD}"
            fi
        else
            emit "version" "tier_class" "warning" "cutoff_unknown" 0 \
                 "tier" "$tier" "wpsquared" "1" \
                 "note" "WP Squared shape on unmapped tier $tier; verify manually."
        fi
        return
    fi

    # Classify. Patched-table lookup is authoritative for any tier in the KB,
    # so it must run BEFORE residual EOL/dev/unknown branches — otherwise a
    # patched 11.86.x / 11.94.x / 11.102.x host gets misclassified.
    local i cutoff=""
    for i in "${!PATCHED_TIERS_KEYS[@]}"; do
        if [[ "${PATCHED_TIERS_KEYS[$i]}" == "$tier" ]]; then
            cutoff="${PATCHED_TIERS_VALS[$i]}"; break
        fi
    done
    if [[ -n "$cutoff" ]]; then
        if (( build >= cutoff )); then
            emit "version" "tier_class" "info" "patched_per_build" 5 \
                 "tier" "$tier" "build" "$build" "cutoff" "$cutoff" \
                 "note" "${tier}.0.${build} ≥ vendor cutoff ${tier}.0.${cutoff}"
        else
            emit "version" "tier_class" "strong" "vulnerable_per_build" 5 \
                 "tier" "$tier" "build" "$build" "cutoff" "$cutoff" \
                 "note" "${tier}.0.${build} < vendor cutoff ${tier}.0.${cutoff}"
        fi
        return
    fi
    if [[ " $UNPATCHED_TIERS_STR " == *" $tier "* ]]; then
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
    if (( tier < 86 )); then
        emit "version" "tier_class" "strong" "vulnerable_eol" 5 \
             "tier" "$tier" "note" "Pre-LTS - no vendor patch will be issued. Migrate or decommission."
        return
    fi
    emit "version" "tier_class" "warning" "cutoff_unknown" 0 \
         "tier" "$tier" "note" "No published cutoff for this tier - verify manually."
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
# Pattern kind: 'bug' = ancillary bug (advisory); 'marker' = build-line
# patch marker (informational).
STATIC_KINDS=(marker bug marker marker marker marker marker marker)
STATIC_EXPLAINS=(
    'OpenIdConnectBase.pm operator-precedence trap (`if !length $algorithm > 2` is always false). Pre-existing OIDC bug, not the SessionScribe primitive; resolves on tier upgrade.'
    'OpenIdConnectBase.pm start_authorize() invoked inside a die() arg list mutates session-state on the error path. Pre-existing OIDC bug, not the SessionScribe primitive; resolves on tier upgrade.'
    'Patched build adds the $service_name fallback in get_display_configuration().'
    'Patched session loader has the no-ob: prefix branch.'
    'Patched encoder adds hex_decode_only / hex_encode_only methods.'
    'Patched Normalize.pm dies with UserNotFound on missing uid (defense-in-depth).'
    'Patched handler contains the Comet-state branch.'
    'CVE-2026-41940 source-level fix: session loader strips CR/LF from the pass field in addition to NUL. Absence on a sub-cutoff build means the host is vulnerable to the Authorization: Basic CRLF-injection chain.'
)

check_static() {
    hdr_section "patterns" "static config-file patterns (ancillary; not CVE-driver)"
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
    hdr_section "cpsrvd" "cpsrvd binary patch markers"
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

    # On 134+ tier, both vulnerable and patched binaries carry these
    # strings (feature evolved in pre-patch). Both counts 0 = strong vuln
    # evidence (pre-130 shape); nonzero is informational only.
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
    hdr_section "iocscan" "access_log scan over ${SINCE_DAYS:-all}d window"
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
            # 2-arg match() + substr/split for gawk 3.1.x (CL6 floor) - the
            # 3-arg match(s, /re/, arr) form is gawk 4.0+ only.
            if (match(line, /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
                _d = substr(line, RSTART+1, RLENGTH-1)
                split(_d, _p, /[\/:]/)
                ts = mktime(_p[3]" "_p[1]" "_p[2]" "_p[4]" "_p[5]" "_p[6])
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
        done < <(head -1 "$tmp")
    else
        emit "logs" "ioc_scan" "info" "no_ioc_hits" 0 \
             "note" "no IOC-pattern hits in access logs${window_note}."
    fi
    rm -f "$tmp"

    # CRLF primitive: 401 POST /login/?login_only=1 → 2xx GET /cpsess<N>/*
    # as root from same IP within 2s. Survives mitigate purging.
    # MUST run before check_attacker_ips — sets the CRLF first-epoch
    # anchor used by 2xx_on_cpsess and Pattern E pre-compromise gates.
    check_crlf_access_primitive "$logdir"
    check_attacker_ips "$logdir"
}

check_attacker_ips() {
    local logdir="$1"

    # Build IP alternation. Escape dots so 1.2.3.4 only matches that literal.
    local ip ip_re=""
    for ip in "${ATTACKER_IPS[@]}"; do
        ip_re+="${ip_re:+|}${ip//./\\.}"
    done
    # Anchored to "^IP " so we don't match an IP buried inside a URL/UA.
    ip_re="^(${ip_re}) "

    # Regexes pass via ENVIRON[]: `awk -v ip_re='...'` would interpret
    # `\.` as the escape sequence (any char) AND emit per-line warnings.
    # ${EXCLUDE_IPS[@]:-} on empty arrays is brittle on bash 4.1 (CL6).
    local excludes_env=""
    if (( ${#EXCLUDE_IPS[@]} > 0 )); then
        excludes_env=$(printf '%s\n' "${EXCLUDE_IPS[@]}")
    fi

    # Per-line src tagging (ASCII US \x1f) preserves rotated-log attribution.
    # Bash <4.4 quirks below: newline after `$(` and leading-paren case
    # patterns inside $(...) — both miscount otherwise.
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
        awk -v sep="$SEP" -v floor="${SINCE_EPOCH:-0}" '
        BEGIN {
            FS       = sep
            ip_re    = ENVIRON["IP_RE"]
            probe_re = ENVIRON["PROBE_RE"]
            n = split(ENVIRON["EXCLUDES"], ex_arr, "\n")
            for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
            total = 0; h2xx = 0; h2xx_cpsess = 0; h2xx_recon = 0
            h3xx = 0; h4xx = 0; hother = 0
            nsamp = 0; ts_first = 0
            historical_drops = 0
            cpsess_sample = ""
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

            # Extract path from Apache combined log quoted request field.
            # Format: IP - USER [DATE] "METHOD PATH PROTO" STATUS ...
            # gawk 3.1.x (CL6 floor): 2-arg match() + substr only.
            path = ""
            if (match(line, /"[A-Z]+ /)) {
                _req = substr(line, RSTART + 1)
                _qend = index(_req, "\"")
                if (_qend > 0) _req = substr(_req, 1, _qend - 1)
                _n = split(_req, _rp, " ")
                if (_n >= 2) path = _rp[2]
            }

            ts = 0
            # 2-arg match() + substr/split for gawk 3.1.x (CL6 floor).
            if (match(line, /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
                _d = substr(line, RSTART+1, RLENGTH-1)
                split(_d, _p, /[\/:]/)
                ts = mktime(_p[3]" "_p[1]" "_p[2]" "_p[4]" "_p[5]" "_p[6])
            }

            # --since gate (floor > 0) drops older hits; ts == 0 bypasses
            # so a corrupt date stamp never silently hides a real hit.
            # Historical-drop count tracked separately for operator.
            if (floor > 0 && ts > 0 && ts < floor) {
                historical_drops++
                next
            }

            if (ts > 0 && (ts_first == 0 || ts < ts_first)) ts_first = ts

            total++
            if (st ~ /^2/) {
                h2xx++
                # cpsess-split: exactly 10 digits after /cpsess followed by /.
                # gawk 3.x floor: no {10} interval - use explicit repetition.
                if (match(path, /\/cpsess[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]\//)) {
                    h2xx_cpsess++
                    if (cpsess_sample == "") cpsess_sample = line
                } else {
                    h2xx_recon++
                }
            } else if (st ~ /^3/) {
                h3xx++
            } else if (st ~ /^4/) {
                h4xx++
            } else {
                hother++
            }

            if (nsamp < 5) {
                nsamp++
                printf "S\t%s\t%s\t%s\t%d\t%s\n", src, ip, st, ts, line
            }
        }
        END {
            printf "TOTALS\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", \
                total, h2xx, h2xx_cpsess, h2xx_recon, h3xx, h4xx, hother, ts_first
            printf "DROPS\t%d\n", historical_drops
            printf "CPSESS_SAMPLE\t%s\n", cpsess_sample
        }' > "$tmp" 2>/dev/null

    local total=0 h2xx=0 h2xx_cpsess=0 h2xx_recon=0
    local h3xx=0 h4xx=0 hother=0 ts_first=0 historical_drops=0
    local cpsess_sample=""
    local totals_line; totals_line=$(grep '^TOTALS' "$tmp" 2>/dev/null | head -1)
    if [[ -n "$totals_line" ]]; then
        IFS=$'\t' read -r _ total h2xx h2xx_cpsess h2xx_recon h3xx h4xx hother ts_first \
            <<< "$totals_line"
    fi
    local drops_line; drops_line=$(grep '^DROPS' "$tmp" 2>/dev/null | head -1)
    if [[ -n "$drops_line" ]]; then
        IFS=$'\t' read -r _ historical_drops <<< "$drops_line"
    fi
    local cpsess_line; cpsess_line=$(grep '^CPSESS_SAMPLE' "$tmp" 2>/dev/null | head -1)
    if [[ -n "$cpsess_line" ]]; then
        cpsess_sample="${cpsess_line#CPSESS_SAMPLE	}"
    fi
    total="${total:-0}"; h2xx="${h2xx:-0}"
    h2xx_cpsess="${h2xx_cpsess:-0}"; h2xx_recon="${h2xx_recon:-0}"
    h3xx="${h3xx:-0}"; h4xx="${h4xx:-0}"; hother="${hother:-0}"; ts_first="${ts_first:-0}"
    historical_drops="${historical_drops:-0}"

    # Historical-only hits emit info (severity=info, weight=0) so fleet
    # aggregation records the touch without escalating host_verdict.
    if (( total == 0 && historical_drops > 0 )); then
        emit "logs" "ioc_attacker_ip_historical_only" "info" \
             "ioc_attacker_ip_outside_since_window" 0 \
             "historical_drops" "$historical_drops" \
             "since_days" "${SINCE_DAYS:-0}" \
             "note" "$historical_drops attacker-IP hit(s) found in access_log but ALL outside --since ${SINCE_DAYS:-0}d window; no in-window evidence."
    fi

    if (( total > 0 )); then
        # cpsess-split: three-way emit by 2xx landing path:
        #   h2xx_cpsess > 0 → strong (real exploitation on /cpsess<10>/)
        #   h2xx_recon  > 0 → info   (reconnaissance only)
        #   total > 0, 4xx only → warning (probing rejected)
        if (( h2xx_cpsess > 0 )); then
            # Parse structured fields from first cpsess-2xx sample line.
            local _c_ip _c_path _c_status _c_token=""
            _c_ip=$(printf '%s' "$cpsess_sample" | awk '{print $1}')
            _c_path=$(printf '%s' "$cpsess_sample" | awk -F'"' 'NF>=2{n=split($2,p," "); if(n>=2)print p[2]; else print ""}')
            _c_status=$(printf '%s' "$cpsess_sample" | awk -F'"' 'NF>=3{n=split($3,p," "); if(n>=1)print p[1]; else print ""}')
            if [[ "$_c_path" =~ /cpsess([0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])/ ]]; then
                _c_token="${BASH_REMATCH[1]}"
            fi
            # Pre-compromise gate: 2xx_on_cpsess needs the CRLF chain firing
            # at-or-before ts_first to anchor as compromise; otherwise it's
            # T1 coincidence / recycled cpsess / recon — demote to advisory.
            local _gate_sev="strong" _gate_key="ioc_attacker_ip_2xx_on_cpsess" _gate_weight=8
            local _gate_note="$h2xx_cpsess hit(s) from CVE-2026-41940 IPs returned 2xx on /cpsess<N>/ paths - real exploitation (CRITICAL)."
            if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )) \
               || ! [[ "$ts_first" =~ ^[0-9]+$ ]] \
               || (( ts_first == 0 )) \
               || (( ts_first < LOGS_CRLF_CHAIN_FIRST_EPOCH )); then
                _gate_sev="advisory"
                _gate_key="ioc_attacker_ip_2xx_on_cpsess_pre_compromise"
                _gate_weight=0
                if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )); then
                    _gate_note="$h2xx_cpsess hit(s) from CVE-2026-41940 IPs returned 2xx on /cpsess<N>/ paths but NO CVE-2026-41940 CRLF access-chain detected on this host - 2xx-on-cpsess is second-order (token consumption) and requires CRLF as compromise anchor. Likely pre-compromise / shared-infra coincidence / pre-disclosure recon (REVIEW; does not escalate host_verdict)."
                else
                    _gate_note="$h2xx_cpsess hit(s) from CVE-2026-41940 IPs returned 2xx on /cpsess<N>/ paths but ts_first ($ts_first) PREDATES first CRLF chain ($LOGS_CRLF_CHAIN_FIRST_EPOCH) - pre-compromise activity, mtime-pollution risk for cluster-onset analysis (REVIEW; does not escalate host_verdict)."
                fi
            else
                # Strong-tier emit passed the gate; record first epoch as
                # the proximity anchor for the Pattern E gate downstream.
                LOGS_2XX_CPSESS_FIRST_EPOCH="$ts_first"
            fi
            emit "logs" "ioc_attacker_ip_2xx_on_cpsess" "$_gate_sev" \
                 "$_gate_key" "$_gate_weight" \
                 "count" "$total" "hits_2xx_cpsess" "$h2xx_cpsess" \
                 "hits_2xx_recon" "$h2xx_recon" "hits_3xx" "$h3xx" \
                 "hits_4xx" "$h4xx" "hits_other" "$hother" \
                 "historical_drops" "$historical_drops" \
                 "ts_epoch_first" "$ts_first" \
                 "crlf_first_epoch" "$LOGS_CRLF_CHAIN_FIRST_EPOCH" \
                 "ip" "$_c_ip" "path" "$_c_path" "status" "$_c_status" \
                 "cpsess_token" "${_c_token:-}" \
                 "note" "$_gate_note"
        elif (( h2xx_recon > 0 )); then
            emit "logs" "ioc_attacker_ip_recon_only" "info" \
                 "ioc_attacker_ip_recon_only" 0 \
                 "count" "$total" "hits_2xx_recon" "$h2xx_recon" \
                 "hits_3xx" "$h3xx" "hits_4xx" "$h4xx" "hits_other" "$hother" \
                 "historical_drops" "$historical_drops" \
                 "ts_epoch_first" "$ts_first" \
                 "note" "$h2xx_recon hit(s) from CVE-2026-41940 IPs returned 2xx on non-cpsess paths - reconnaissance only (REVIEW)."
        elif (( total > 0 )); then
            emit "logs" "ioc_attacker_ip_probes_only" "advisory" \
                 "ioc_attacker_ip_in_access_log_probes_only" 3 \
                 "count" "$total" "hits_4xx" "$h4xx" "hits_3xx" "$h3xx" \
                 "hits_other" "$hother" \
                 "historical_drops" "$historical_drops" \
                 "ts_epoch_first" "$ts_first" \
                 "note" "$total hit(s) from CVE-2026-41940 IPs - all rejected (probing only, no successful response)."
        fi

        local tag src ip st ts line trim
        while IFS=$'\t' read -r tag src ip st ts line; do
            [[ "$tag" == "S" ]] || continue
            trim="${line:0:200}"
            emit "logs" "ioc_attacker_ip_sample" "info" "ioc_attacker_ip_sample" 0 \
                 "ip" "$ip" "status" "$st" "log_file" "$logdir/$src" \
                 "ts_epoch" "${ts:-0}" "line" "$trim" \
                 "note" "$ip $st  ($src)"
        done < "$tmp"
    fi
    rm -f "$tmp"
}

# Deterministic CRLF chain in access_log: 401 POST /login/?login_only=1
# then 2xx GET /cpsess<N>/* as root from same IP within 2s. cpsrvd 401s
# but the cpsess token has already been minted. Survives mitigate purging.
check_crlf_access_primitive() {
    local logdir="$1"
    local log="$logdir/access_log"
    [[ -f "$log" ]] || return
    local since_filter=0
    [[ -n "$SINCE_EPOCH" ]] && since_filter="$SINCE_EPOCH"
    local result
    result=$(grep -E '^[^ ]+ - (root|-) \[' "$log" 2>/dev/null \
            | grep -vE "$PROBE_UA_RE" \
            | awk -v since="$since_filter" '
        BEGIN { hits=0; sample=""; ts_first=0 }
        # gawk 3.1.x (CL6 floor) lacks 3-arg match(s, /re/, arr); use the
        # 2-arg form with RSTART/RLENGTH + substr/split to extract groups.
        function ts_of(s,    d, n, p) {
            if (match(s, /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
                d = substr(s, RSTART+1, RLENGTH-1)
                n = split(d, p, /[\/:]/)
                return mktime(p[3]" "p[1]" "p[2]" "p[4]" "p[5]" "p[6])
            }
            return 0
        }
        {
            ip = $1
            t = ts_of($0)
            if (since > 0 && t > 0 && t < since) next
            # 401 to POST /login/?login_only=1 - mints the cpsess token
            # despite the surface-level rejection.
            if (match($0, /"POST \/login\/\?login_only=1[^"]*" 401 /)) {
                last_post[ip] = t
                next
            }
            # 2xx to GET /cpsess<N>/* AS root within 2s of the matching POST.
            # Identity slot ($3) is "root" only because cpsrvd has already
            # bound the minted token to root by the time this request lands.
            if (match($0, /"GET \/cpsess[0-9]+\/[^"]*" 2[0-9][0-9] /) \
                && $3 == "root" \
                && (ip in last_post) \
                && t > 0 && last_post[ip] > 0 \
                && (t - last_post[ip]) <= 2) {
                hits++
                if (sample == "") sample = $0
                if (ts_first == 0 || t < ts_first) ts_first = t
                # Consume the matched POST; next 401 starts a fresh window.
                delete last_post[ip]
            }
        }
        END { printf "%d\t%d\t%s\n", hits, ts_first, sample }')
    local crlf_hits=0 crlf_ts_first=0 crlf_sample=""
    IFS=$'\t' read -r crlf_hits crlf_ts_first crlf_sample <<< "$result"
    crlf_hits="${crlf_hits:-0}"
    crlf_ts_first="${crlf_ts_first:-0}"
    if (( crlf_hits > 0 )); then
        # X-stack = ATTEMPT, not compromise.
        emit "logs" "ioc_cve_2026_41940_access_primitive" "warning" \
             "ioc_cve_2026_41940_crlf_access_chain" 4 \
             "count" "$crlf_hits" \
             "ts_epoch_first" "$crlf_ts_first" \
             "log_file" "$log" \
             "line" "${crlf_sample:0:240}" \
             "note" "$crlf_hits CRLF-bypass chain(s) in $log: POST /login → 401 then GET /cpsess<N>/* → 2xx as root within 2s. CVE-2026-41940 exploitation ATTEMPT — confirm compromise via Pattern A-L residue or session-file forensics (REVIEW)."
        # Record CRLF first epoch so downstream second-order signals
        # (2xx_on_cpsess, pattern_e) demote pre-compromise events.
        if [[ "$crlf_ts_first" =~ ^[0-9]+$ ]]; then
            LOGS_CRLF_CHAIN_FIRST_EPOCH="$crlf_ts_first"
        fi
    fi
}

# ---- session-store analyzer ----------------------------------------------
# Single-awk-pass per file sets SF_* globals; emit_session() wraps emit()
# with identity/provenance KPIs. login_time + file_mtime are forgeable;
# file_ctime is not.
emit_session() {
    local key="$1" sev="$2" sig="$3" weight="$4"
    shift 4
    emit "sessions" "$key" "$sev" "$sig" "$weight" \
        "user"       "${SF_USER:-}" \
        "src_ip"     "${SF_REMOTE_ADDR:-}" \
        "login_time" "${SF_LOGIN_ISO:-}" \
        "file_mtime" "${SF_FILE_MTIME_ISO:-}" \
        "file_ctime" "${SF_FILE_CTIME_ISO:-}" \
        "mtime_ctime_delta_sec" "${SF_MTIME_CTIME_DELTA:-}" \
        "$@"
}

analyze_session() {
    SF_TOKEN_DENIED=0; SF_CP_TOKEN=0; SF_BADPASS=0; SF_LEGIT_LOGIN=0
    SF_EXT_AUTH=0;     SF_INT_AUTH=0; SF_TFA=0;     SF_HASROOT=0
    SF_CANARY=0;       SF_ROOT_USER=0; SF_ACLLIST=0; SF_STRANDED=0
    SF_MALFORMED=0;    SF_MALFORMED_SAMPLE=""
    SF_PASS_COUNT=0;   SF_PASS_LEN=0; SF_PASS_PRESENT_NONEMPTY=0
    SF_TD_VAL="";      SF_CP_VAL="";   SF_ORIGIN="";  SF_AUTH_TS=""
    # Identity/provenance KPIs travel on every ioc_* emit. ctime can't be
    # backdated by user-space (touch updates mtime/atime; ctime tracks the
    # touch itself), so SF_MTIME_CTIME_DELTA detects forgery (Gap 10 IOC).
    SF_USER="";        SF_REMOTE_ADDR=""
    SF_LOGIN_TIME="";  SF_LOGIN_ISO=""
    SF_FILE_MTIME="";  SF_FILE_MTIME_ISO=""
    SF_FILE_CTIME="";  SF_FILE_CTIME_ISO=""
    SF_MTIME_CTIME_DELTA=""

    # Capture file mtime + ctime BEFORE reading the file content (stat is
    # read-only so atime is unaffected). Single stat call avoids a second
    # subprocess per session. `%Y %Z` returns "<mtime_epoch> <ctime_epoch>"
    # space-separated. Parameter-expansion split (no read needed).
    local _sf_path="$1"
    if [[ -e "$_sf_path" ]]; then
        local _times
        _times=$(stat -c '%Y %Z' "$_sf_path" 2>/dev/null)
        if [[ -n "$_times" ]]; then
            SF_FILE_MTIME="${_times%% *}"
            SF_FILE_CTIME="${_times##* }"
            if [[ "$SF_FILE_MTIME" =~ ^[0-9]+$ ]]; then
                SF_FILE_MTIME_ISO=$(date -u -d "@$SF_FILE_MTIME" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
            fi
            if [[ "$SF_FILE_CTIME" =~ ^[0-9]+$ ]]; then
                SF_FILE_CTIME_ISO=$(date -u -d "@$SF_FILE_CTIME" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
            fi
            # Compute signed delta only when both timestamps parsed cleanly.
            # Empty SF_MTIME_CTIME_DELTA means "delta unknown" (vs. "delta = 0"
            # which would falsely imply known-equal); downstream uses "" guard.
            if [[ "$SF_FILE_MTIME" =~ ^[0-9]+$ && "$SF_FILE_CTIME" =~ ^[0-9]+$ ]]; then
                SF_MTIME_CTIME_DELTA=$((SF_FILE_MTIME - SF_FILE_CTIME))
            fi
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
            pass_present_nonempty) SF_PASS_PRESENT_NONEMPTY=$_v ;;
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
        BEGIN { line_idx=0; pass_at=0; pass_count=0; pass_present_nonempty=0 }
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
            pass_count++
            # Non-empty pass= line: value length > 0.
            # /^pass=.+/ is equivalent (gawk 3.x supports .+).
            if (match($0, /^pass=.+/)) pass_present_nonempty=1
            next
        }
        pass_at > 0 && line_idx == pass_at + 1 && /./ && !/^[a-zA-Z_][a-zA-Z0-9_]*=/ { stranded=1 }
        # Malformed-line detector. cpsrvd serialization invariants exclude
        # non-key=value lines; any hit is injection footprint.
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
            print "pass_present_nonempty=" (pass_present_nonempty?1:0)
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

# Escalate "forged token" → "forged AND used" by checking access_log for
# the token with 2xx. The `" 2[0-9][0-9] ` boundary avoids matching IPs
# starting with 200 or response-byte counts of 200.
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

# Two-pass scan: (a) IOC ladder over raw/ — deterministic, no time bound.
# (b) Anomalous-shape heuristic — time-bounded by --since (lower confidence).
# Sessions with nxesec_canary_<nonce>=1 are PROBE_ARTIFACT and skipped.
check_sessions() {
    (( NO_SESSIONS )) && return
    hdr_section "sessions" "session-store IOC ladder"
    # Snapshot-aware path roots. Live mode prefix is empty.
    local _root_prefix="${ROOT_OVERRIDE:-}"
    local d="${_root_prefix}/var/cpanel/sessions"
    # On a host where mitigate already quarantined every forged session,
    # /var/cpanel/sessions may still exist but raw/ is empty. The walk
    # below produces 0 hits live - run the quarantine secondary regardless
    # so previously-compromised hosts don't scan CLEAN.
    if [[ ! -d "$d" ]]; then
        emit "sessions" "sess_dir" "info" "no_session_dir" 0 "note" "no $d"
        check_quarantined_sessions
        return
    fi
    local raw_dir="$d/raw" preauth_dir="$d/preauth"
    local scanned=0 ioc_hits=0 anomalous=0 probe_artifacts=0
    # Gap 10: count of sessions whose mtime diverges from ctime by
    # >= SESSION_MTIME_CTIME_THRESHOLD_SEC (touch-d forgery candidates,
    # cp -p / tar xp restore artifacts). Surfaced as advisory both
    # per-session and as a section-level summary.
    local mtime_anomalies=0
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

            # IOC-A: token_denied + cp_security_token co-occur.
            # Mirrors cPanel's ioc_checksessions_files.sh three-tier.
            if (( SF_TOKEN_DENIED && SF_CP_TOKEN )); then
                if (( SF_BADPASS )); then
                    if (( SF_HASROOT || SF_TFA || SF_EXT_AUTH || SF_INT_AUTH )); then
                        emit_session "ioc_token_inject_$session_name" "strong" \
                             "ioc_token_denied_with_badpass_origin" 10 \
                             "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                             "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                             "note" "Pre-auth session with attacker-injected security token + auth markers (CRITICAL)."
                        ((ioc_hits++))
                    elif (( SF_PASS_COUNT > 0 )); then
                        emit_session "ioc_token_attempt_$session_name" "evidence" \
                             "ioc_failed_exploit_attempt" 0 \
                             "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                             "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                             "pass_len" "$SF_PASS_LEN" \
                             "note" "Failed exploit attempt: badpass origin + token_denied + pass= line, but no auth markers - patch held (ATTEMPT, not compromise)."
                    else
                        emit_session "ioc_token_info_$session_name" "info" \
                             "ioc_badpass_token_denied_noauth_nopass" 0 \
                             "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                             "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                             "note" "badpass origin + token_denied with no auth markers and no pass= line - likely failed login (INFO)."
                    fi
                else
                    emit_session "ioc_token_review_$session_name" "warning" \
                         "ioc_token_denied_with_cp_security_token" 0 \
                         "path" "$f" "cp_security_token" "$SF_CP_VAL" \
                         "token_denied" "$SF_TD_VAL" "origin" "$SF_ORIGIN" \
                         "note" "token_denied + cp_security_token co-exist - review (may be expired bookmark)."
                    ((ioc_hits++))
                fi
            fi

            # IOC-B: preauth marker + auth_with_timestamp co-present.
            # cpsrvd strips preauth on promotion — both together is
            # structurally impossible in a benign flow.
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

            # IOC-C: short pass= + successful_*_auth_with_timestamp.
            # Legitimate pass= is encoder output >>PASS_FORGERY_MAX_LEN chars;
            # CRLF injection leaks single-byte cleartext (`pass=x`).
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

            # IOC-E: badpass + ANY auth marker. The badpass code path
            # cannot legitimately set ext/int auth, hasroot, or tfa_verified;
            # any combination is single-field promotion injection.
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

            # IOC-E2: canonical 4-way co-occurrence (hasroot + tfa_verified
            # + auth_timestamp + badpass-origin). Effectively zero-FP;
            # separate signal preserves ioc_cve_2026_41940_combo key.
            if (( SF_HASROOT && SF_TFA && (SF_INT_AUTH || SF_EXT_AUTH) && SF_BADPASS )); then
                emit_session "ioc_cve41940_$session_name" "strong" \
                     "ioc_cve_2026_41940_combo" 10 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "hasroot=1 + tfa_verified=1 + successful_*_auth_with_timestamp + method=badpass origin co-occur - CVE-2026-41940 forged session (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-H: standalone hasroot=1. Not in cpsrvd's session-key
            # whitelist; no caller writes it. Conclusive injection evidence.
            if (( SF_HASROOT )); then
                emit_session "ioc_hasroot_$session_name" "strong" \
                     "ioc_hasroot_in_session" 10 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "hasroot=1 present in session — not in cpsrvd session-key whitelist; conclusive injection footprint (CRITICAL)."
                ((ioc_hits++))
            fi

            # IOC-I: malformed line (any non-blank not matching `name=`).
            # cpsrvd serialization invariants exclude this shape; any hit
            # is injection footprint. Distinct from IOC-D (multiline pass=).
            if (( SF_MALFORMED )); then
                emit_session "ioc_malformed_line_$session_name" "strong" \
                     "ioc_malformed_session_line" 10 \
                     "path" "$f" "sample" "${SF_MALFORMED_SAMPLE:0:80}" \
                     "note" "Session contains a non-blank line not matching key=value - injection footprint (CRITICAL)."
                ((ioc_hits++))
            fi

            # Token-use cross-ref: token-injection IOC + cp_security_token
            # paired with 2xx in access_log → forged AND used (not just forged).
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

            # IOC-J: failed exploit attempt (cPanel IOC 5 analog). Mutually
            # exclusive with IOC-E (cp_security_token present) and IOC-E2
            # (auth markers present) — without these guards all three would
            # double-count the same session in ss-aggregate.py.
            if (( SF_BADPASS && SF_TOKEN_DENIED && SF_PASS_PRESENT_NONEMPTY \
                  && ! SF_CP_TOKEN \
                  && ! SF_INT_AUTH && ! SF_EXT_AUTH \
                  && ! SF_HASROOT && ! SF_TFA )); then
                emit_session "ioc_failed_exploit_attempt_$session_name" "warning" \
                     "ioc_failed_exploit_attempt" 3 \
                     "path" "$f" "origin" "$SF_ORIGIN" \
                     "note" "Failed CVE-2026-41940 attempt: badpass origin + token_denied + pass= line + no auth markers - injection did not promote (REVIEW)."
                ((ioc_hits++))
            fi

            # Gap 10: mtime/ctime divergence (advisory — also produced by
            # cp -p / tar xp / rsync -t restore). Section count distinguishes
            # single-forge from fleet-wide restore artifact.
            if [[ -n "$SF_MTIME_CTIME_DELTA" ]]; then
                local _abs_delta="${SF_MTIME_CTIME_DELTA#-}"
                if [[ "$_abs_delta" =~ ^[0-9]+$ ]] \
                   && (( _abs_delta >= SESSION_MTIME_CTIME_THRESHOLD_SEC )); then
                    local _direction="backdated"
                    (( SF_MTIME_CTIME_DELTA > 0 )) && _direction="future"
                    emit_session "session_mtime_anomaly_$session_name" "advisory" \
                         "session_mtime_vs_ctime_anomaly" 0 \
                         "path" "$f" \
                         "mtime_epoch" "${SF_FILE_MTIME:-}" \
                         "ctime_epoch" "${SF_FILE_CTIME:-}" \
                         "delta_sec" "$SF_MTIME_CTIME_DELTA" \
                         "abs_delta_sec" "$_abs_delta" \
                         "direction" "$_direction" \
                         "note" "Session file mtime $_direction ${_abs_delta}s vs ctime - timestamp not trustworthy for cluster-onset analysis (touch -d backdating, or cp -p / tar xp restore artifact). Hand-investigate."
                    ((mtime_anomalies++))
                fi
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
        done < <(head -1 "$atmp")
    fi
    rm -f "$atmp"

    if (( probe_artifacts > 0 )); then
        emit "sessions" "probe_artifact_summary" "info" "probe_artifact_count" 0 \
             "count" "$probe_artifacts" \
             "note" "$probe_artifacts session(s) tagged with sessionscribe-remote-probe canary - clear with: sessionscribe-remote-probe.sh --cleanup | ssh root@host"
    fi

    if (( mtime_anomalies > 0 )); then
        emit "sessions" "session_mtime_anomaly_summary" "advisory" \
             "session_mtime_vs_ctime_anomaly_count" 0 \
             "count" "$mtime_anomalies" "scanned" "$scanned" \
             "threshold_sec" "$SESSION_MTIME_CTIME_THRESHOLD_SEC" \
             "note" "$mtime_anomalies of $scanned session(s) had mtime/ctime divergence >= ${SESSION_MTIME_CTIME_THRESHOLD_SEC}s - mtime is untrustworthy for cluster-onset analysis on these sessions (could be touch-d injection or cp -p / tar xp restore artifact)."
    fi

    # ---- (b) Mitigate-quarantine secondary read --------------------------
    # Post-mitigation, forged sessions live under quarantined-sessions/raw/;
    # sidecars (`<sname>.info`) carry original mtime + IOC reasons.
    check_quarantined_sessions
    ioc_hits=$((ioc_hits + QUARANTINED_HITS))

    # The all-clear emit covers IOC-ladder + anomalous-shape + mtime-anomaly
    # cohorts. mtime_anomalies is included in the gate so a host with quietly-
    # backdated sessions but no other signals does not falsely assert no_session_iocs.
    if (( ioc_hits == 0 && anomalous == 0 && mtime_anomalies == 0 )); then
        emit "sessions" "session_scan" "info" "no_session_iocs" 0 \
             "scanned" "$scanned" "probe_artifacts" "$probe_artifacts" \
             "note" "no IOCs or anomalous-shape sessions found"
    fi
}

# Direct call (not subshell): emit() mutates SIGNALS[].
check_quarantined_sessions() {
    QUARANTINED_HITS=0
    local hits=0
    local prefix="${ROOT_OVERRIDE:-}"
    local root="${prefix}${MITIGATE_BACKUP_ROOT}"
    [[ -d "$root" ]] || return

    # Walk most-recent run-dirs first; cap total sessions analyzed.
    local _max="${PATTERN_J_MAX_QUARANTINE:-200}"
    local _seen=0
    local run_dir f
    while IFS= read -r run_dir; do
        local qraw="$run_dir/quarantined-sessions/raw"
        [[ -d "$qraw" ]] || continue
        for f in "$qraw"/*; do
            [[ -f "$f" ]] || continue
            # Skip the .info sidecars themselves.
            [[ "$f" == *.info ]] && continue
            (( _seen >= _max )) && break 2
            ((_seen++))

            local sidecar="${f}.info"
            local q_mtime="" q_reasons="" q_orig="" q_sha="" q_run_ts=""
            local _has_sidecar=0
            if [[ -f "$sidecar" ]]; then
                _has_sidecar=1
                local _k _v
                while IFS='=' read -r _k _v; do
                    case "$_k" in
                        (mtime_epoch)     q_mtime="$_v" ;;
                        (reasons_ioc)     q_reasons="$_v" ;;
                        (original_path)   q_orig="$_v" ;;
                        (sha256)          q_sha="$_v" ;;
                        (quarantine_ts)   q_run_ts="$_v" ;;
                    esac
                done < "$sidecar"
            else
                # Fallback: file mtime (the cp -a from mitigate preserves
                # the original mtime, so this is still meaningful). Flag
                # as low confidence so consumers can distinguish.
                q_mtime=$(stat -c %Y "$f" 2>/dev/null)
            fi

            local sname _key
            sname=$(basename -- "$f")
            _key="ioc_quarantined_session_${sname}"

            local _q_sev=warning _q_wt=4
            if (( _has_sidecar )) && [[ -n "$q_reasons" ]]; then
                if [[ "$q_reasons" =~ (cve_2026_41940_combo|hasroot_in_session|injected_token_used_with_2xx|token_denied_with_badpass_origin) ]] \
                   || [[ "$q_reasons" =~ (^|,)E2(,|$) ]]; then
                    _q_sev=strong; _q_wt=10
                elif [[ "$q_reasons" =~ (^|,)(B|E|F|H)(,|$) ]]; then
                    _q_sev=strong; _q_wt=5
                elif [[ "$q_reasons" =~ (^|,)(A|C|D|D2|I|2)(,|$) ]]; then
                    _q_sev=evidence; _q_wt=0
                fi
            fi

            emit "sessions" "$_key" "$_q_sev" \
                 "ioc_quarantined_session_present" "$_q_wt" \
                 "path" "$f" \
                 "original_path" "${q_orig:-}" \
                 "quarantine_run_dir" "$run_dir" \
                 "quarantine_ts" "${q_run_ts:-}" \
                 "mtime_epoch" "${q_mtime:-0}" \
                 "ts_epoch_first" "${q_mtime:-0}" \
                 "reasons_ioc" "${q_reasons:-unknown}" \
                 "sha256" "${q_sha:-}" \
                 "low_confidence_no_sidecar" "$([[ $_has_sidecar -eq 0 ]] && echo 1 || echo 0)" \
                 "tier_promoted_high_conf" "$([[ "$_q_sev" == "strong" ]] && echo 1 || echo 0)" \
                 "note" "Forged session in mitigate quarantine (reasons=${q_reasons:-unknown}); host had IOC-positive sessions before mitigation purged them — past compromise ($([[ "$_q_sev" == "strong" ]] && echo "CRITICAL: high-confidence reasons" || echo "REVIEW"))."
            ((hits++))
        done
    done < <(find "$root" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | awk '{print $2}')

    QUARANTINED_HITS="$hits"
}

# Pattern J detection — dossier paths/processes/at-jobs only. Snapshot-aware
# via ROOT_OVERRIDE (severity demoted to info+degraded_confidence_snapshot=1).
check_pattern_j_persistence() {
    PATTERN_J_HITS=0
    local hits=0
    local prefix=""
    [[ -n "${ROOT_OVERRIDE:-}" ]] && prefix="$ROOT_OVERRIDE"
    local snapshot_mode=0
    [[ -n "$prefix" ]] && snapshot_mode=1

    # Literal IOC paths + payload references + processes + at-jobs.
    local _path _full _mtime
    for _path in "${PATTERN_J_KNOWN_PATHS[@]}"; do
        _full="${prefix}${_path}"
        if [[ -e "$_full" ]]; then
            _mtime=$(stat -c %Y "$_full" 2>/dev/null)
            local _sev=strong _wt=10 _conf=""
            if (( snapshot_mode )); then
                _sev=info; _wt=2; _conf="degraded_confidence_snapshot=1; "
            fi
            emit "destruction" "ioc_pattern_j_known_path" "$_sev" \
                 "ioc_pattern_j_known_path_present" "$_wt" \
                 "path" "$_path" \
                 "mtime_epoch" "${_mtime:-0}" \
                 "note" "${_conf}Pattern J known IOC path present at $_path (dossier-documented persistence artifact; -helper suffix has no legitimate use on stock cPanel)."
            ((hits++))
        fi
    done

    # Process detection — exact-match via pgrep -x (no substring FP).
    # Skipped in snapshot mode (no live process list).
    if (( ! snapshot_mode )) && command -v pgrep >/dev/null 2>&1; then
        local _proc
        for _proc in "${PATTERN_J_PROCESS_NAMES[@]}"; do
            if pgrep -x "$_proc" >/dev/null 2>&1; then
                local _pids
                _pids=$(pgrep -x "$_proc" 2>/dev/null | head -5 | tr '\n' ',' | sed 's/,$//')
                emit "destruction" "ioc_pattern_j_process_running" "strong" \
                     "ioc_pattern_j_process_active" 10 \
                     "process" "$_proc" \
                     "pids" "$_pids" \
                     "note" "Pattern J process $_proc actively running (PIDs: $_pids) — OS-level persistence binary executing now."
                ((hits++))
            fi
        done
    fi

    # At-job enumeration — atq lists pending jobs; at -c <jobid> dumps
    # body. Catches the dossier-documented `echo /usr/lib/udev/cdrom-id-helper
    # | at now` branch even when udev rule has been removed but pending job
    # remains. Skipped in snapshot mode.
    if (( ! snapshot_mode )) && command -v atq >/dev/null 2>&1 && command -v at >/dev/null 2>&1; then
        local _atq_jobs _jobid
        _atq_jobs=$(atq 2>/dev/null)
        if [[ -n "$_atq_jobs" ]]; then
            while read -r _jobid _; do
                [[ -z "$_jobid" ]] && continue
                if at -c "$_jobid" 2>/dev/null \
                    | grep -qE 'cdrom-id-helper|dbus-broker-helper'; then
                    emit "destruction" "ioc_pattern_j_atjob_pending" "strong" \
                         "ioc_pattern_j_atjob_payload_referenced" 10 \
                         "jobid" "$_jobid" \
                         "note" "Pattern J pending at-job $_jobid references the helper binary — udev/systemd trigger has queued execution (run atq + at -c $_jobid to inspect)."
                    ((hits++))
                    break  # one emit suffices; operator inspects atq for full list
                fi
            done <<< "$_atq_jobs"
        fi
    fi

    PATTERN_J_HITS="$hits"
}

# ---- _kv_get -------------------------------------------------------------
# Pull a field value from a SIGNALS[] row's kv fragment (json-shaped).
# $1 kv-blob, $2 field-name. Empty if not present.
_kv_get() {
    local _kv="$1" _f="$2" _v=""
    if [[ "$_kv" == *"\"$_f\":\""* ]]; then
        _v="${_kv#*\"$_f\":\"}"; _v="${_v%%\"*}"
    fi
    printf '%s\n' "$_v"
}

# ---- _attribute_path / _user_is_valid ------------------------------------
# Map an absolute path to its cPanel-user owner or "_root" for system paths.
# Conservative: unknown -> _root (host-level IR queue, not tenant notify).
_attribute_path() {
    local p="${1:-}"
    case "$p" in
        /home/*)
            p="${p#/home/}"; printf '%s\n' "${p%%/*}" ;;
        /var/spool/cron/*)
            p="${p#/var/spool/cron/}"
            [[ "$p" == "root" || -z "$p" ]] && printf '_root\n' || printf '%s\n' "${p%%/*}" ;;
        /var/cpanel/users/*)
            p="${p#/var/cpanel/users/}"; printf '%s\n' "${p%%/*}" ;;
        /var/cpanel/userdata/*)
            p="${p#/var/cpanel/userdata/}"; printf '%s\n' "${p%%/*}" ;;
        *)
            printf '_root\n' ;;
    esac
}

_user_is_valid() {
    case "${1:-}" in
        ""|.|..|_root|root) return 1 ;;
        */*)                return 1 ;;
        *[!a-zA-Z0-9_-]*)   return 1 ;;
        *)                  return 0 ;;
    esac
}

# Classify a ps auxfww line's runtime context. CageFS/LVE-jailed root
# attributes to the cgroup-path user, not "root".
_rt_runtime_context() {
    local _line="${1:-}"
    _RT_CTX_USER=$(printf '%s' "$_line" | awk '{print $1}')
    _RT_CTX_PID=$(printf '%s' "$_line" | awk '{print $2}')
    _RT_CTX_JAILED=0
    _RT_CTX_OWNER="${_RT_CTX_USER:-unknown}"
    if [[ -n "$_RT_CTX_PID" && -r "/proc/$_RT_CTX_PID/cgroup" ]] \
       && grep -qE '/(cagefs|lve)/' "/proc/$_RT_CTX_PID/cgroup" 2>/dev/null; then
        _RT_CTX_JAILED=1
    fi
    if [[ "$_RT_CTX_USER" == "root" ]] && (( _RT_CTX_JAILED == 0 )); then
        _RT_CTX_OWNER="root"
    elif (( _RT_CTX_JAILED == 1 )) && [[ "$_RT_CTX_USER" == "root" ]]; then
        local _cu
        _cu=$(grep -oE '/(cagefs|lve)/[^/[:space:]]+' "/proc/$_RT_CTX_PID/cgroup" 2>/dev/null \
              | head -1 | awk -F/ '{print $NF}')
        [[ -n "$_cu" ]] && _RT_CTX_OWNER="$_cu"
    fi
}

# Diagnostic-shape classifier shared by Patterns C/F/H3.
# Args: $1 mode (regex|literal), $2 needle, $3.. files.
# Output: h=N d=N u=N fhe=EPOCH file_h=PATH.
_classify_history_match() {
    local mode="$1" needle="$2"
    shift 2
    local _hf _out _h _d _u _fhe_part
    local _h_total=0 _d_total=0 _u_total=0 _fhe="" _file_h=""
    export _CLF_MODE="$mode" _CLF_NEEDLE="$needle"
    for _hf in "$@"; do
        [[ -f "$_hf" ]] || continue
        _out=$(awk '
            BEGIN {
                mode           = ENVIRON["_CLF_MODE"]
                needle         = ENVIRON["_CLF_NEEDLE"]
                diag_re        = "^[[:space:]]*(history|cat|less|more|tail|head|grep|egrep|fgrep|zgrep|awk|find|ls|locate|file|ps|netstat|ss|stat)([[:space:]]|$)"
                download_re    = "(wget|curl|fetch|lwp-download|tftp)([[:space:]]|$)"
                pipe_shell_re  = "[|][[:space:]]*(sh|bash|ash|zsh|/bin/sh|/bin/bash)([[:space:]]|$)"
                chmod_re       = "chmod[[:space:]]+([+]x|[0-7][0-7][0-7])"
                exec_verb_re   = "(^|[[:space:]]|;|&)(source|eval|exec|bash|sh|/bin/sh|/bin/bash|/usr/bin/sh|/usr/bin/bash)[[:space:]]"
                last_epoch=""; h=0; d=0; u=0; fhe=""
            }
            /^#[0-9]+$/ { last_epoch = substr($0, 2); next }
            {
                hit = 0
                if (mode == "regex") { if ($0 ~ needle) hit = 1 }
                else                 { if (index($0, needle) > 0) hit = 1 }
                if (!hit) next
                is_hostile = 0
                if      ($0 ~ download_re)   is_hostile = 1
                else if ($0 ~ pipe_shell_re) is_hostile = 1
                else if ($0 ~ chmod_re)      is_hostile = 1
                else if ($0 ~ exec_verb_re)  is_hostile = 1
                else if (mode == "regex") {
                    # Wrap needle in (...) to scope alternation - awk ERE
                    # `|` has lowest precedence, so `^[[:space:]]*A|B`
                    # would parse as `(^[[:space:]]*A)|(B)` and FP-match
                    # B anywhere in the line.
                    if ($0 ~ ("\\./(" needle ")"))                 is_hostile = 1
                    else if ($0 ~ ("^[[:space:]]*(" needle ")"))   is_hostile = 1
                } else {
                    if (index($0, "./" needle) > 0) {
                        is_hostile = 1
                    } else {
                        line = $0
                        sub("^[[:space:]]+", "", line)
                        if (substr(line, 1, length(needle)) == needle) is_hostile = 1
                    }
                }
                if (is_hostile) {
                    h++
                    if (fhe == "" && last_epoch != "") fhe = last_epoch
                } else if ($0 ~ diag_re) {
                    d++
                } else {
                    u++
                    if (fhe == "" && last_epoch != "") fhe = last_epoch
                }
            }
            END { printf "h=%d d=%d u=%d fhe=%s\n", h, d, u, fhe }
        ' "$_hf" 2>/dev/null)
        _h=$(       printf '%s\n' "$_out" | awk -F'[ =]' '{for(i=1;i<=NF;i++)if($i=="h"){print $(i+1);exit}}')
        _d=$(       printf '%s\n' "$_out" | awk -F'[ =]' '{for(i=1;i<=NF;i++)if($i=="d"){print $(i+1);exit}}')
        _u=$(       printf '%s\n' "$_out" | awk -F'[ =]' '{for(i=1;i<=NF;i++)if($i=="u"){print $(i+1);exit}}')
        _fhe_part=$(printf '%s\n' "$_out" | awk -F'[ =]' '{for(i=1;i<=NF;i++)if($i=="fhe"){print $(i+1);exit}}')
        _h_total=$((_h_total + ${_h:-0}))
        _d_total=$((_d_total + ${_d:-0}))
        _u_total=$((_u_total + ${_u:-0}))
        if [[ -z "$_fhe" && -n "$_fhe_part" ]]; then
            _fhe="$_fhe_part"; _file_h="$_hf"
        fi
    done
    unset _CLF_MODE _CLF_NEEDLE
    printf 'h=%d d=%d u=%d fhe=%s file_h=%s\n' "$_h_total" "$_d_total" "$_u_total" "$_fhe" "$_file_h"
}

# Pull named field (h|d|u|fhe|file_h) from a classifier output line.
_classify_field() {
    awk -v k="$1" -F'[ =]' '
        { for (i = 1; i <= NF; i++) if ($i == k) { print $(i+1); exit } }
    ' <<< "$2"
}

# ---- _classify_kill_prelude_context --------------------------------------
_classify_kill_prelude_context() {
    local _kf="$1" _kre="$2" _kctx="${3:-3}"
    if [[ ! -f "$_kf" ]]; then
        printf 'h=0 d=0 u=0 fhe= file_h=\n'
        return
    fi
    export _KP_RE="$_kre" _KP_CTX="$_kctx"
    local _out
    _out=$(awk '
        BEGIN {
            kill_re      = ENVIRON["_KP_RE"]
            ctx          = ENVIRON["_KP_CTX"] + 0
            install_re   = "(wget|curl|fetch|lwp-download|tftp|base64[[:space:]]+-d|chmod[[:space:]]+([+]x|[0-7][0-7][0-7])|bash[[:space:]]*<\\(|\\./seobot)"
            verify_re    = "^[[:space:]]*(ps([[:space:]]|$)|pgrep([[:space:]]|$)|echo([[:space:]]|$)|exit([[:space:]]|$)|true([[:space:]]|$))"
            last_epoch=""; h=0; d=0; u=0; fhe=""
            n_pending=0; n_pending_lines=0; pending_epoch=""
        }
        function commit_pending(   k, cl, shape) {
            shape = "u"
            for (k = 0; k < n_pending_lines; k++) {
                cl = pending_ctx[k]
                if (cl ~ install_re) { shape = "h"; break }
            }
            if (shape != "h") {
                for (k = 0; k < n_pending_lines; k++) {
                    cl = pending_ctx[k]
                    if (cl ~ verify_re || cl == "") { shape = "d"; break }
                }
            }
            if (shape == "h") {
                h++
                if (fhe == "" && pending_epoch != "") fhe = pending_epoch
            } else if (shape == "d") {
                d++
            } else {
                u++
                if (fhe == "" && pending_epoch != "") fhe = pending_epoch
            }
            n_pending = 0
            n_pending_lines = 0
            pending_epoch = ""
            for (k = 0; k < ctx; k++) pending_ctx[k] = ""
        }
        /^#[0-9]+$/ {
            last_epoch = substr($0, 2)
            next
        }
        {
            if ($0 ~ kill_re) {
                if (n_pending > 0) commit_pending()
                pending_epoch = last_epoch
                # Same-line install primitive (`pkill ...; wget ...`)
                # short-circuits to hostile - no need to wait for ctx.
                if ($0 ~ install_re) {
                    h++
                    if (fhe == "" && pending_epoch != "") fhe = pending_epoch
                    pending_epoch = ""
                    next
                }
                n_pending = ctx
                n_pending_lines = 0
                next
            }
            if (n_pending > 0) {
                pending_ctx[n_pending_lines++] = $0
                n_pending--
                if (n_pending == 0) commit_pending()
            }
        }
        END {
            if (n_pending > 0 || n_pending_lines > 0) commit_pending()
            printf "h=%d d=%d u=%d fhe=%s\n", h, d, u, fhe
        }
    ' "$_kf" 2>/dev/null)
    unset _KP_RE _KP_CTX
    local _h _d _u _fhe_part
    _h=$(_classify_field h        "$_out")
    _d=$(_classify_field d        "$_out")
    _u=$(_classify_field u        "$_out")
    _fhe_part=$(_classify_field fhe "$_out")
    printf 'h=%d d=%d u=%d fhe=%s file_h=%s\n' "${_h:-0}" "${_d:-0}" "${_u:-0}" "${_fhe_part}" "$_kf"
}

# ---- destruction-stage IOC scan (Patterns A-J) ---------------------------

# Classifier returns via globals to avoid a fork per row.
# _CLASSIFY_KNOWN_HASH carries the published bad-hash IOC when one
# exists, empty otherwise.
_CLASSIFY_OUT=""
_CLASSIFY_KNOWN_HASH=""
_classify_external_artifact() {
    local path="$1" base
    base="${path##*/}"
    _CLASSIFY_KNOWN_HASH=""

    if [[ "$path" == "$PATTERN_A_BINARY"   ]]; then
        _CLASSIFY_OUT=A; _CLASSIFY_KNOWN_HASH="$PATTERN_A_SHA256"; return
    fi
    # PATTERN_A_README intentionally NOT classified A — live scan tiers
    # by content; off-disk we can't, so it falls to unclassified/warning.
    [[ "$path" == "$PATTERN_I_PROFILED" ]] && { _CLASSIFY_OUT=I; return; }
    [[ "$path" == "$PATTERN_I_BINARY"   ]] && { _CLASSIFY_OUT=I; return; }
    [[ "$path" == "$PATTERN_H_ZIP_PATH" ]] && { _CLASSIFY_OUT=H; return; }

    local _j
    for _j in "${PATTERN_J_KNOWN_PATHS[@]}"; do
        [[ "$path" == "$_j" ]] && { _CLASSIFY_OUT=J; return; }
    done

    if [[ "$base" == "$PATTERN_C_BIN" ]]; then
        _CLASSIFY_OUT=C; _CLASSIFY_KNOWN_HASH="$PATTERN_C_SHA256"; return
    fi
    # nuclear.* catches arch variants (nuclear.arm, .mips); rejects
    # nuclear-physics.pdf. Variants have no published hash.
    [[ "$base" == nuclear.*                 ]] && { _CLASSIFY_OUT=C; return; }
    [[ "$base" == "$PATTERN_H_DROPPER_FILE" ]] && { _CLASSIFY_OUT=H; return; }

    [[ "$base" == *.sorry              ]] && { _CLASSIFY_OUT=A; return; }
    [[ "$path" == */authorized_keys    ]] && { _CLASSIFY_OUT=G; return; }

    case "$base" in
        .bash_history|.zsh_history|.fish_history|.sh_history)
            _CLASSIFY_OUT=evidence; return ;;
    esac

    _CLASSIFY_OUT=unclassified
}

# Size-guard. Returns 0 if file is within
# MAX_EXTERNAL_QUARANTINE_FILE_BYTES, else emits a warning and returns 1.
_external_quarantine_file_ok() {
    local f="$1" qdir="$2"
    local _b _max="${MAX_EXTERNAL_QUARANTINE_FILE_BYTES:-1048576}"
    _b=$(stat -c %s "$f" 2>/dev/null || echo 0)
    (( _b <= _max )) && return 0
    local _qbase="${qdir##*/}" _fbase="${f##*/}"
    _qbase="${_qbase//[^a-zA-Z0-9]/_}"
    _fbase="${_fbase//[^a-zA-Z0-9]/_}"
    local _key="external_quarantine_file_oversized_${_qbase}_${_fbase}"
    emit "destruction" "external_quarantine_file_oversized" "warning" \
         "$_key" 4 \
         "containment_dir" "$qdir" \
         "file" "$f" \
         "size_bytes" "$_b" \
         "max_bytes" "$_max" \
         "source" "external_containment" \
         "note" "Refusing to ingest ${f##*/}: ${_b} > ${_max} bytes — review before raising the cap."
    return 1
}

check_quarantined_artifacts() {
    QUARANTINED_ARTIFACTS_HITS=0
    [[ -z "${EXTERNAL_QUARANTINE_GLOB:-}" ]] && return
    local hits=0
    local prefix="${ROOT_OVERRIDE:-}"
    local _max="${MAX_EXTERNAL_QUARANTINE_HITS:-200}"
    local _seen=0
    local qdir hashes_file pruned_log _qts _qbase_safe

    # Most-recent-first walk; cap shared across hashes.txt + prune log
    # so a flooded stream can't bypass _max.
    while IFS= read -r qdir; do
        (( _seen >= _max )) && break
        [[ -d "$qdir" ]] || continue
        hashes_file="$qdir/hashes.txt"
        pruned_log="$qdir/ssh-pruned-keys.log"
        # Skip unreadable qdirs — emitting with ts_epoch_first=0 would
        # poison cluster-onset analysis (falls back to scan-now epoch).
        _qts=$(stat -c %Y "$qdir" 2>/dev/null) || continue
        _qbase_safe="${qdir##*/}"
        _qbase_safe="${_qbase_safe//[^a-zA-Z0-9]/_}"

        if [[ -f "$hashes_file" ]]; then
            (( _seen >= _max )) && break
            if ! _external_quarantine_file_ok "$hashes_file" "$qdir"; then
                ((_seen++)); ((hits++))
            else
                local sha path _pattern _id _key _sev _wt _hi _hash_match _note _key_id
                while read -r sha path; do
                    [[ -z "$sha" || -z "$path" ]] && continue
                    [[ "$sha" =~ ^[a-fA-F0-9]{64}$ ]] || continue
                    (( _seen >= _max )) && break
                    ((_seen++))

                    _classify_external_artifact "$path"
                    _pattern="$_CLASSIFY_OUT"

                    if [[ -n "$_CLASSIFY_KNOWN_HASH" ]]; then
                        if [[ "$sha" == "$_CLASSIFY_KNOWN_HASH" ]]; then
                            _hash_match=match
                        else
                            _hash_match=mismatch
                        fi
                    else
                        _hash_match=unverified
                    fi

                    # Both id and key need ioc_pattern_<letter>_* shape —
                    # wrong shape silently downgrades contained-only hosts
                    # to SUSPICIOUS. _key carries qdir+sha[0:16] vs emit dedup.
                    _key_id="${_qbase_safe}_${sha:0:16}"
                    case "$_pattern" in
                        A|C|G|H|I|J)
                            _sev=strong;  _wt=10; _hi=1
                            _id="ioc_pattern_${_pattern,,}_contained_artifact"
                            _key="${_id}_${_key_id}" ;;
                        evidence)
                            _sev=info;    _wt=0;  _hi=0
                            _id="ioc_contained_evidence"
                            _key="${_id}_${_key_id}" ;;
                        *)
                            _sev=warning; _wt=4;  _hi=0
                            _id="ioc_contained_unclassified"
                            _key="${_id}_${_key_id}" ;;
                    esac

                    case "$_hash_match" in
                        match)
                            _note="Pattern ${_pattern} CONFIRMED: path + sha256 both match the published IOC (triple witness)." ;;
                        mismatch)
                            _note="Pattern ${_pattern} path with non-matching sha256 — possible decoy / variant / attacker substitution; investigate the binary in $qdir." ;;
                        *)
                            _note="Artifact contained off-disk into $qdir (pattern=$_pattern, sev=$_sev). sha256 validated before removal." ;;
                    esac

                    local _au_eq _ap_eq=root
                    _au_eq=$(_attribute_path "$path")
                    _user_is_valid "$_au_eq" || _au_eq="_root"
                    case "$_pattern" in
                        H) [[ "$_au_eq" != "_root" ]] && _ap_eq=user ;;
                    esac

                    emit "destruction" "$_id" "$_sev" \
                         "$_key" "$_wt" \
                         "containment_dir" "$qdir" \
                         "original_path" "$path" \
                         "sha256" "$sha" \
                         "pattern" "$_pattern" \
                         "published_hash_match" "$_hash_match" \
                         "source" "external_containment" \
                         "quarantine_ts" "$_qts" \
                         "ts_epoch_first" "$_qts" \
                         "tier_promoted_high_conf" "$_hi" \
                         "affected_user" "$_au_eq" \
                         "actor_privilege" "$_ap_eq" \
                         "note" "$_note"
                    ((hits++))
                done < "$hashes_file"
            fi
        fi

        (( _seen >= _max )) && continue

        if [[ -f "$pruned_log" ]]; then
            (( _seen >= _max )) && break
            if ! _external_quarantine_file_ok "$pruned_log" "$qdir"; then
                ((_seen++)); ((hits++))
            else
                local _l_path _l_line _l_fp _l_comment _fp_safe
                while IFS=$'\t' read -r _l_path _l_line _l_fp _l_comment; do
                    # Strip prefixes BEFORE the emptiness check — a bare
                    # `fp=` would otherwise pass and emit a colliding key.
                    _l_line="${_l_line#line=}"
                    _l_fp="${_l_fp#fp=}"
                    _l_comment="${_l_comment#comment=}"
                    [[ -z "$_l_path" || -z "$_l_fp" ]] && continue
                    (( _seen >= _max )) && break
                    ((_seen++))
                    _fp_safe="${_l_fp//[^a-zA-Z0-9]/_}"
                    local _ssh_id="ioc_pattern_g_contained_sshkey"
                    local _ssh_key="${_ssh_id}_${_qbase_safe}_${_fp_safe}"
                    local _au_ssh _ap_ssh=root
                    _au_ssh=$(_attribute_path "$_l_path")
                    _user_is_valid "$_au_ssh" || _au_ssh="_root"
                    [[ "$_au_ssh" != "_root" ]] && _ap_ssh=user
                    emit "destruction" "$_ssh_id" "strong" \
                         "$_ssh_key" 10 \
                         "containment_dir" "$qdir" \
                         "authorized_keys_path" "$_l_path" \
                         "line" "$_l_line" \
                         "fingerprint" "$_l_fp" \
                         "key_comment" "$_l_comment" \
                         "pattern" "G" \
                         "source" "external_containment" \
                         "quarantine_ts" "$_qts" \
                         "ts_epoch_first" "$_qts" \
                         "tier_promoted_high_conf" 1 \
                         "affected_user" "$_au_ssh" \
                         "actor_privilege" "$_ap_ssh" \
                         "note" "Pattern G — untrusted SSH key pruned during external containment ($qdir); rotate affected credentials."
                    ((hits++))
                done < "$pruned_log"
            fi
        fi
    done < <(
        for _q in ${prefix}${EXTERNAL_QUARANTINE_GLOB}; do
            [[ -d "$_q" ]] || continue
            printf '%s\t%s\n' "$(stat -c %Y "$_q" 2>/dev/null || echo 0)" "$_q"
        done | sort -rn | cut -f2-
    )

    QUARANTINED_ARTIFACTS_HITS="$hits"
}

check_destruction_iocs() {
    (( NO_DESTRUCTION_IOCS )) && return
    if [[ -n "$ROOT_OVERRIDE" ]]; then
        hdr_section "destruct" "destruction IOC scan (Pattern J only - snapshot mode)"
        emit "destruction" "destruction_scan" "info" "snapshot_mode_partial" 0 \
             "note" "Patterns A-I skip snapshot/--root mode (no host filesystem). Pattern J (udev/systemd persistence) walks the snapshot tree with degraded confidence (no live rpmdb)."
        # Pattern J is snapshot-aware - the trees it walks (udev rules + systemd
        # units) ARE present in a typical snapshot. Severity is auto-demoted
        # inside the function when ROOT_OVERRIDE is set. Direct call (not
        # `$( … )`) so emit()'s SIGNALS[] writes survive.
        check_pattern_j_persistence
        # Snapshot-safe: hashes.txt and ssh-pruned-keys.log are static
        # evidence files, meaningful without a live filesystem.
        check_quarantined_artifacts
        return
    fi
    hdr_section "destruct" "destruction IOC scan (Patterns A-L + runtime)"
    local hits=0

    # History files for Pattern F harvester + Pattern H markers (bash/
    # zsh/sh/fish, root + cPanel users). Hoisted once for both patterns.
    local HISTORY_FILES_GLOB=(
        /root/.bash_history /root/.zsh_history /root/.sh_history
        /root/.local/share/fish/fish_history
        /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history
        /home/*/.local/share/fish/fish_history
    )

    # ---- Pattern A: /root/sshd encryptor + .sorry + ransom README + C2 ---
    if [[ -f "$PATTERN_A_BINARY" ]]; then
        known_bad_meta "$PATTERN_A_BINARY"
        if [[ "$META_SHA256" == "$PATTERN_A_SHA256" ]]; then
            emit "destruction" "ioc_pattern_a_encryptor" "strong" \
                 "ioc_pattern_a_encryptor_match" 10 \
                 "path" "$PATTERN_A_BINARY" "${META_KV[@]}" \
                 "note" "$PATTERN_A_BINARY sha256 matches CVE-2026-41940 .sorry encryptor (CRITICAL)."
            ((hits++))
        else
            # Same path, different hash - variant or unrelated /root/sshd.
            # Warning, not strong, to avoid FPs on legitimate operator drops.
            emit "destruction" "ioc_pattern_a_unknown" "warning" \
                 "ioc_pattern_a_binary_present_unknown_hash" 4 \
                 "path" "$PATTERN_A_BINARY" "${META_KV[@]}" \
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
        first_sorry=$(timeout 300 find "$sorry_root" -maxdepth 5 \
            \( -name 'mail' -o -name '.cagefs' -o -name 'node_modules' \
               -o -name '.composer' -o -name '.npm' -o -name '.cache' \
               -o -name '.trash' -o -name 'tmp' \) -prune \
            -o -name '*.sorry' -print -quit 2>/dev/null)
        [[ -n "$first_sorry" ]] && break
    done
    if [[ -n "$first_sorry" ]]; then
        local sorry_mtime _au_sorry
        sorry_mtime=$(stat -c %Y "$first_sorry" 2>/dev/null)
        _au_sorry=$(_attribute_path "$first_sorry")
        _user_is_valid "$_au_sorry" || _au_sorry="_root"
        emit "destruction" "ioc_pattern_a_sorry" "strong" \
             "ioc_pattern_a_sorry_files_present" 10 \
             "sample_path" "$first_sorry" \
             "mtime_epoch" "${sorry_mtime:-0}" \
             "affected_user" "$_au_sorry" \
             "actor_privilege" "root" \
             "note" "found .sorry-encrypted files (Pattern A); re-run with --full for the full kill-chain + bundle (CRITICAL)."
        ((hits++))
    fi
    # qTox ransom README at /root/README.md + /home/*/README.md. Long files
    # (>200 lines) and IR-notes filename shapes demote to info-tier so
    # responder docs referencing the dossier TOX_ID hash don't FP-strong.
    local readme_hits=()
    [[ -f "$PATTERN_A_README" ]] && readme_hits+=("$PATTERN_A_README")
    while IFS= read -r rf; do
        [[ -f "$rf" ]] && readme_hits+=("$rf")
    done < <(find /home -maxdepth 2 -name 'README.md' 2>/dev/null)
    # Length-check guard: ${arr[@]} on a declared-but-empty array trips
    # `set -u` on bash 4.1 (CL6). Matches the EXCLUDE_IPS pattern above.
    local rf
    if (( ${#readme_hits[@]} > 0 )); then
        for rf in "${readme_hits[@]}"; do
            if grep -qE "qtox|TOX ID|Sorry-ID|${PATTERN_A_TOX_ID}" "$rf" 2>/dev/null; then
                local rf_mtime tox_match=0 _rf_lines=0 _rf_doc_shape=0 _au_rf
                rf_mtime=$(stat -c %Y "$rf" 2>/dev/null)
                grep -qF "$PATTERN_A_TOX_ID" "$rf" 2>/dev/null && tox_match=1
                _rf_lines=$(wc -l < "$rf" 2>/dev/null | tr -d ' ')
                _rf_lines="${_rf_lines:-0}"
                if _is_doc_shape "$rf"; then
                    _rf_doc_shape=1
                fi
                _au_rf=$(_attribute_path "$rf")
                _user_is_valid "$_au_rf" || _au_rf="_root"
                if (( _rf_doc_shape )); then
                    emit "destruction" "ioc_pattern_a_readme_documentation" "info" \
                         "ioc_pattern_a_ransom_readme_documentation" 0 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
                         "affected_user" "$_au_rf" \
                         "actor_privilege" "root" \
                         "note" "qtox/Sorry-ID/TOX_ID strings in $rf (lines=$_rf_lines) but file is in IR-notes path or too long for a ransom README - documentation-shape, not Pattern A drop."
                elif (( tox_match )); then
                    emit "destruction" "ioc_pattern_a_readme" "strong" \
                         "ioc_pattern_a_ransom_readme" 10 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
                         "affected_user" "$_au_rf" \
                         "actor_privilege" "root" \
                         "note" "qTox ransom README at $rf (tox_id_exact_match=1, lines=$_rf_lines) - Pattern A drop (CRITICAL)."
                    ((hits++))
                else
                    emit "destruction" "ioc_pattern_a_readme_review" "warning" \
                         "ioc_pattern_a_ransom_readme_review" 5 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
                         "affected_user" "$_au_rf" \
                         "actor_privilege" "root" \
                         "note" "qtox/Sorry-ID strings in $rf (lines=$_rf_lines) without exact TOX_ID hash match - manual review (may be IR documentation referencing the dossier)."
                    ((hits++))
                fi
            fi
        done
    fi
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
    # Anti-forensic: encryptor also walks /var/log + /var/cpanel encrypting
    # evidence files. ≥10 .sorry OR accounting.log encrypted = strong
    # destruction signal; survives /home restore.
    local fe_count=0 fe_acct=0 fe_sample="" _fe_list=""
    if [[ -d /var/log || -d /var/cpanel ]]; then
        _fe_list=$(timeout 300 find /var/log /var/cpanel -maxdepth 6 \
                       -name '*.sorry' -not -path '*/imunify360/cache/*' \
                       2>/dev/null)
        if [[ -n "$_fe_list" ]]; then
            fe_count=$(printf '%s\n' "$_fe_list" | wc -l)
            fe_sample=$(printf '%s\n' "$_fe_list" | head -1)
        fi
        fe_count="${fe_count:-0}"
        fe_count="${fe_count// /}"
    fi
    [[ -f /var/cpanel/accounting.log.sorry ]] && fe_acct=1
    if (( fe_count >= 10 )) || (( fe_acct == 1 )); then
        local fe_sev="strong" fe_weight=10 fe_mtime=0
        if (( fe_count < 10 && fe_acct == 1 )); then
            fe_sev="warning"; fe_weight=5
        fi
        # P1 count escalator applied at score-time.
        [[ -n "$fe_sample" ]] && fe_mtime=$(stat -c %Y "$fe_sample" 2>/dev/null)
        emit "destruction" "ioc_pattern_a_evidence_destruction" "$fe_sev" \
             "ioc_pattern_a_evidence_targeted" "$fe_weight" \
             "count" "$fe_count" "acct_log_encrypted" "$fe_acct" \
             "sample_path" "${fe_sample:-(none)}" \
             "mtime_epoch" "${fe_mtime:-0}" \
             "note" "${fe_count} .sorry-encrypted file(s) under /var/log + /var/cpanel; accounting.log encrypted=${fe_acct}. Pattern A targeted forensic evidence - upstream Pattern D/E/F detection may silently miss."
        ((hits++))
    fi

    # ---- Pattern B: mysql wipe + BTC-note index drop ---------------------
    # innodb-residue gates the wipe heuristic; wipe shape is info-tier (too many benign causes).
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
            emit "destruction" "ioc_pattern_b_mysql_wipe_diagnostic" "info" \
                 "ioc_pattern_b_mysql_dir_missing_diagnostic_only" 0 \
                 "expected" "$PATTERN_B_MYSQL_DB" \
                 "mtime_epoch" "${mysql_parent_mtime:-0}" \
                 "note" "${PATTERN_B_MYSQL_DIR}/ exists with innodb residue but mysql/ subdir is gone - informational, manual review to distinguish Pattern B wipe from operator action."
        fi
    fi
    # BTC index.html drops nested under /home/*/public_html (cohort).
    local btc_hit=""
    btc_hit=$(timeout 300 bash -c \
        'find /home/*/public_html -maxdepth 4 -name index.html -print0 2>/dev/null \
            | xargs -0 -r grep -lF -- "$1" 2>/dev/null | head -1' \
        _ "$PATTERN_B_BTC_ADDR" 2>/dev/null)
    if [[ -n "$btc_hit" ]]; then
        local btc_mtime _au_btc
        btc_mtime=$(stat -c %Y "$btc_hit" 2>/dev/null)
        _au_btc=$(_attribute_path "$btc_hit")
        _user_is_valid "$_au_btc" || _au_btc="_root"
        emit "destruction" "ioc_pattern_b_btc_note" "strong" \
             "ioc_pattern_b_btc_index_present" 10 \
             "sample_path" "$btc_hit" \
             "mtime_epoch" "${btc_mtime:-0}" \
             "affected_user" "$_au_btc" \
             "actor_privilege" "user" \
             "note" "BTC ransom note in $btc_hit - Pattern B index drop (CRITICAL)."
        ((hits++))
    fi

    # ---- Pattern C: nuclear.x86 botnet drop ------------------------------
    # Three signals: bash_history mention (shape-classified to avoid IR-grep
    # FP), on-disk binary (sha256-anchored), C2 host/IP.
    local nuke_files=()
    local _nuke_from_history=0
    local _nf
    for _nf in /root/.bash_history /home/*/.bash_history; do
        [[ -f "$_nf" ]] && grep -qF "$PATTERN_C_BIN" "$_nf" 2>/dev/null \
            && nuke_files+=("$_nf")
    done
    if (( ${#nuke_files[@]} > 0 )); then
        _nuke_from_history=1
    else
        for _nf in /tmp/*.log /var/tmp/*.log; do
            [[ -f "$_nf" ]] && grep -qF "$PATTERN_C_BIN" "$_nf" 2>/dev/null \
                && nuke_files+=("$_nf")
        done
    fi
    if (( ${#nuke_files[@]} > 0 )); then
        local _nuke_class _nh _nd _nu _nfhe _nfh_file
        _nuke_class=$(_classify_history_match regex 'nuclear\.x86' "${nuke_files[@]}")
        _nh=$(_classify_field h      "$_nuke_class")
        _nd=$(_classify_field d      "$_nuke_class")
        _nu=$(_classify_field u      "$_nuke_class")
        _nfhe=$(_classify_field fhe  "$_nuke_class")
        _nfh_file=$(_classify_field file_h "$_nuke_class")

        local _nuke_sample="${nuke_files[0]}" _nuke_mtime
        _nuke_mtime=$(stat -c %Y "$_nuke_sample" 2>/dev/null)

        if (( ${_nh:-0} > 0 )); then
            # bash_history-only hits demote to warning; /tmp/*.log hits stay strong.
            local _hf="${_nfh_file:-$_nuke_sample}"
            local _hf_mtime _c_sev _c_id _c_key _c_weight _c_note
            _hf_mtime=$(stat -c %Y "$_hf" 2>/dev/null)
            if (( _nuke_from_history )); then
                _c_sev="warning"
                _c_id="ioc_pattern_c_nuke_trace_history_review"
                _c_key="ioc_pattern_c_nuclear_x86_history_review"
                _c_weight=4
                _c_note="$PATTERN_C_BIN dropper-shape command in $_hf - bash_history-only evidence, manual review (responder paste vs real drop)."
            else
                _c_sev="strong"
                _c_id="ioc_pattern_c_nuke_trace"
                _c_key="ioc_pattern_c_nuclear_x86_referenced"
                _c_weight=10
                _c_note="$PATTERN_C_BIN dropper-shape command in $_hf (Mirai botnet drop, Abuse 46488376)."
            fi
            emit "destruction" "$_c_id" "$_c_sev" \
                 "$_c_key" "$_c_weight" \
                 "sample_path" "$_hf" \
                 "mtime_epoch" "${_hf_mtime:-${_nuke_mtime:-0}}" \
                 "ts_epoch_first" "${_nfhe:-0}" \
                 "hostile_lines" "${_nh:-0}" \
                 "diagnostic_lines" "${_nd:-0}" \
                 "unknown_lines" "${_nu:-0}" \
                 "note" "$_c_note"
            ((hits++))
        elif (( ${_nu:-0} > 0 )); then
            # Unknown-shape only - no clear dropper verb but no clear
            # diagnostic either; warning-tier so IR can review.
            emit "destruction" "ioc_pattern_c_nuke_trace_review" "warning" \
                 "ioc_pattern_c_nuclear_x86_review" 4 \
                 "sample_path" "$_nuke_sample" \
                 "mtime_epoch" "${_nuke_mtime:-0}" \
                 "diagnostic_lines" "${_nd:-0}" \
                 "unknown_lines" "${_nu:-0}" \
                 "note" "$PATTERN_C_BIN string in $_nuke_sample but no dropper shape - manual review."
            ((hits++))
        else
            # All hits diagnostic-shape - operator/IR search command
            # (history|grep, cat|grep, find -name, etc). Info-tier so
            # the audit trail records the classification but verdict is
            # not affected (severity=info, weight=0 per emit() vocabulary).
            emit "destruction" "ioc_pattern_c_nuke_trace_diagnostic" "info" \
                 "ioc_pattern_c_nuclear_x86_diagnostic_only" 0 \
                 "sample_path" "$_nuke_sample" \
                 "mtime_epoch" "${_nuke_mtime:-0}" \
                 "diagnostic_lines" "${_nd:-0}" \
                 "note" "$PATTERN_C_BIN appears only in diagnostic-shape commands (history|grep, cat|grep, find -name, etc) - operator/IR search, not an IOC."
        fi
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
                 "note" "$nx sha256 matches CVE-2026-41940 nuclear.x86 sample (CRITICAL)."
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
    flame_hit=$(grep -lE "${PATTERN_C_C2_HOST}|${PATTERN_C_C2_IP//./\\.}|${PATTERN_C_C2_IP_2//./\\.}" \
                   /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$flame_hit" ]]; then
        local flame_mtime
        flame_mtime=$(stat -c %Y "$flame_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_c_c2_ref_history_review" "warning" \
             "ioc_pattern_c_c2_referenced_history_review" 4 \
             "sample_path" "$flame_hit" \
             "mtime_epoch" "${flame_mtime:-0}" \
             "note" "Mirai C2 ($PATTERN_C_C2_HOST / $PATTERN_C_C2_IP / $PATTERN_C_C2_IP_2) referenced in $flame_hit - bash_history-only evidence, manual review."
        ((hits++))
    fi
    local persist_hit=""
    persist_hit=$(grep -rIlE "nuclear\.x86|${PATTERN_C_C2_HOST}|${PATTERN_C_C2_IP//./\\.}|${PATTERN_C_C2_IP_2//./\\.}" \
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
    # Pattern A's encryptor targets accounting.log → .sorry. If live file
    # missing but .sorry present, emit evidence-destroyed advisory and
    # skip the grep. Users/ + api-tokens.cache checks below still run.
    local acct_log=/var/cpanel/accounting.log
    local acct_log_sorry=/var/cpanel/accounting.log.sorry
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
    elif [[ -f "$acct_log_sorry" ]]; then
        local acct_sorry_mtime
        acct_sorry_mtime=$(stat -c %Y "$acct_log_sorry" 2>/dev/null)
        emit "destruction" "ioc_pattern_d_evidence_destroyed" "warning" \
             "ioc_pattern_d_acctlog_encrypted" 5 \
             "path" "$acct_log_sorry" \
             "mtime_epoch" "${acct_sorry_mtime:-0}" \
             "note" "Pattern D evidence file $acct_log_sorry encrypted by Pattern A; reseller-persistence cannot be ruled in/out from this file - rely on /var/cpanel/users/ second source."
        ((hits++))
    fi
    # Reseller presence — accounting.log may rotate or be Pattern A'd.
    # /var/cpanel/users/<name> is the canonical record (survives Pattern A);
    # getent passwd kept as fallback.
    local d_userfile="/var/cpanel/users/$PATTERN_D_RESELLER"
    if [[ -f "$d_userfile" ]]; then
        local d_userfile_mtime
        d_userfile_mtime=$(stat -c %Y "$d_userfile" 2>/dev/null)
        emit "destruction" "ioc_pattern_d_reseller" "strong" \
             "ioc_pattern_d_reseller_user_present" 10 \
             "user" "$PATTERN_D_RESELLER" "path" "$d_userfile" \
             "mtime_epoch" "${d_userfile_mtime:-0}" \
             "note" "cPanel user record '$d_userfile' present - attacker reseller (CRITICAL)."
        ((hits++))
    elif command -v getent >/dev/null 2>&1; then
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
    # Shape-classified (responder `grep __S_MARK__` lands the literal in
    # bash_history → next scan would fire strong/COMPROMISED on a clean host).
    local _f_files=()
    local _ff
    while IFS= read -r _ff; do
        [[ -n "$_ff" ]] && _f_files+=("$_ff")
    done < <(grep -lF "$PATTERN_F_S_MARK" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    if (( ${#_f_files[@]} > 0 )); then
        local _f_class _fh _fd _fu _ffhe _ffile_h
        _f_class=$(_classify_history_match literal "$PATTERN_F_S_MARK" "${_f_files[@]}")
        _fh=$(_classify_field h        "$_f_class")
        _fd=$(_classify_field d        "$_f_class")
        _fu=$(_classify_field u        "$_f_class")
        _ffhe=$(_classify_field fhe    "$_f_class")
        _ffile_h=$(_classify_field file_h "$_f_class")

        local _f_sample="${_ffile_h:-${_f_files[0]}}"
        local _f_mtime
        _f_mtime=$(stat -c %Y "$_f_sample" 2>/dev/null)

        if (( ${_fh:-0} > 0 )); then
            emit "destruction" "ioc_pattern_f_harvester_history_review" "warning" \
                 "ioc_pattern_f_smark_envelope_history_review" 5 \
                 "sample_path" "$_f_sample" \
                 "ts_epoch_first" "${_ffhe:-0}" \
                 "mtime_epoch" "${_f_mtime:-0}" \
                 "hostile_lines" "${_fh:-0}" \
                 "diagnostic_lines" "${_fd:-0}" \
                 "unknown_lines" "${_fu:-0}" \
                 "note" "$PATTERN_F_S_MARK / $PATTERN_F_E_MARK harvester envelope in $_f_sample - bash_history-only evidence, manual review."
            ((hits++))
        elif (( ${_fu:-0} > 0 )); then
            local _f_review_sample="${_f_files[0]}"
            local _f_review_mtime
            _f_review_mtime=$(stat -c %Y "$_f_review_sample" 2>/dev/null)
            emit "destruction" "ioc_pattern_f_review_undetermined" "warning" \
                 "ioc_pattern_f_smark_review" 5 \
                 "sample_path" "$_f_review_sample" \
                 "mtime_epoch" "${_f_review_mtime:-0}" \
                 "diagnostic_lines" "${_fd:-0}" \
                 "unknown_lines" "${_fu:-0}" \
                 "note" "$PATTERN_F_S_MARK in $_f_review_sample without harvester-shape verb - manual review."
            ((hits++))
        else
            local _f_diag_sample="${_f_files[0]}"
            local _f_diag_mtime
            _f_diag_mtime=$(stat -c %Y "$_f_diag_sample" 2>/dev/null)
            emit "destruction" "ioc_pattern_f_diagnostic_only" "info" \
                 "ioc_pattern_f_smark_diagnostic_only" 0 \
                 "sample_path" "$_f_diag_sample" \
                 "mtime_epoch" "${_f_diag_mtime:-0}" \
                 "diagnostic_lines" "${_fd:-0}" \
                 "note" "$PATTERN_F_S_MARK appears only in diagnostic-shape commands (history|grep, find -name, etc) in $_f_diag_sample - operator/IR search, not an IOC."
        fi
    fi

    # Pattern F additional marker: __CMD_DONE_<nanos>__.
    local _fc_files=()
    local _fcf
    while IFS= read -r _fcf; do
        [[ -n "$_fcf" ]] && _fc_files+=("$_fcf")
    done < <(grep -lE "$PATTERN_F_CMD_DONE_RE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    if (( ${#_fc_files[@]} > 0 )); then
        local _fc_class _fch _fcd _fcu _fcfhe _fcfile_h
        _fc_class=$(_classify_history_match regex "$PATTERN_F_CMD_DONE_RE" "${_fc_files[@]}")
        _fch=$(_classify_field h "$_fc_class")
        _fcd=$(_classify_field d "$_fc_class")
        _fcu=$(_classify_field u "$_fc_class")
        _fcfhe=$(_classify_field fhe "$_fc_class")
        _fcfile_h=$(_classify_field file_h "$_fc_class")
        local _fc_sample="${_fcfile_h:-${_fc_files[0]}}"
        local _fc_mtime
        _fc_mtime=$(stat -c %Y "$_fc_sample" 2>/dev/null)
        if (( ${_fch:-0} > 0 )); then
            emit "destruction" "ioc_pattern_f_cmd_done_history_review" "warning" \
                 "ioc_pattern_f_cmd_done_marker_history_review" 4 \
                 "sample_path" "$_fc_sample" \
                 "ts_epoch_first" "${_fcfhe:-0}" \
                 "mtime_epoch" "${_fc_mtime:-0}" \
                 "hostile_lines" "${_fch:-0}" \
                 "diagnostic_lines" "${_fcd:-0}" \
                 "unknown_lines" "${_fcu:-0}" \
                 "note" "Pattern F __CMD_DONE_<nanos>__ marker in $_fc_sample - bash_history-only evidence, manual review (responder paste vs harvester toolchain)."
            ((hits++))
        elif (( ${_fcu:-0} > 0 )); then
            emit "destruction" "ioc_pattern_f_cmd_done_review" "warning" \
                 "ioc_pattern_f_cmd_done_review" 3 \
                 "sample_path" "${_fc_files[0]}" \
                 "mtime_epoch" "${_fc_mtime:-0}" \
                 "diagnostic_lines" "${_fcd:-0}" \
                 "unknown_lines" "${_fcu:-0}" \
                 "note" "__CMD_DONE_<nanos>__ marker in ${_fc_files[0]} without harvester-shape verb - manual review."
            ((hits++))
        else
            emit "destruction" "ioc_pattern_f_cmd_done_diagnostic" "info" \
                 "ioc_pattern_f_cmd_done_diagnostic_only" 0 \
                 "sample_path" "${_fc_files[0]}" \
                 "mtime_epoch" "${_fc_mtime:-0}" \
                 "diagnostic_lines" "${_fcd:-0}" \
                 "note" "__CMD_DONE_<nanos>__ marker appears only in diagnostic-shape commands in ${_fc_files[0]} - operator/IR search, not an IOC."
        fi
    fi

    # ---- Pattern G: suspect SSH keys ------------------------------------
    # Fingerprint: mtime forged to 2019-12-13 + IP-shaped comment.
    # IP-label count excludes known-good provisioning labels.
    local _g_hit=0
    local key_file
    for key_file in "${SSH_KEY_FILES[@]}"; do
        [[ -f "$key_file" ]] || continue
        local key_mtime_epoch key_mtime_iso
        key_mtime_epoch=$(stat -c %Y "$key_file" 2>/dev/null)
        key_mtime_iso=$(stat -c '%y' "$key_file" 2>/dev/null | cut -d' ' -f1)
        local has_forged_mtime=0
        [[ "$key_mtime_iso" == "$PATTERN_G_FORGED_MTIME" ]] && has_forged_mtime=1
        local ip_labeled_lines
        ip_labeled_lines=$(grep -E '^(ssh-(rsa|ed25519|ecdsa|dss))[[:space:]]+[A-Za-z0-9+/=]+[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}([[:space:]]|$)' \
                              "$key_file" 2>/dev/null \
                           | grep -cvE "$SSH_KNOWN_GOOD_RE" || true)
        ip_labeled_lines="${ip_labeled_lines:-0}"
        if (( has_forged_mtime && ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ssh_key" "strong" \
                 "ioc_pattern_g_suspect_ssh_keys" 10 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "mtime" "$key_mtime_iso" \
                 "mtime_epoch" "${key_mtime_epoch:-0}" \
                 "note" "$key_file mtime forged to $key_mtime_iso + $ip_labeled_lines IP-labeled key(s) - Pattern G persistence (CRITICAL)."
            ((hits++))
            _g_hit=1
        elif (( ip_labeled_lines > 0 )); then
            emit "destruction" "ioc_pattern_g_ip_keys_review" "warning" \
                 "ioc_pattern_g_ip_labeled_keys_present" 3 \
                 "path" "$key_file" "ip_labeled_lines" "$ip_labeled_lines" \
                 "mtime_epoch" "${key_mtime_epoch:-0}" \
                 "note" "$ip_labeled_lines IP-labeled SSH key comment(s) in $key_file - review (may be legitimate provisioning)."
            ((hits++))
            _g_hit=1
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
            _odd_total=$(grep -cE '^[[:space:]]*(ssh-(rsa|ed25519|ecdsa|dss)|ecdsa-sha2-)[[:space:]]+[A-Za-z0-9+/=]+' "$_odd" 2>/dev/null)
            _odd_total="${_odd_total:-0}"
            if (( _odd_total > 0 )); then
                _odd_known=$(grep -cE "^[[:space:]]*(ssh-(rsa|ed25519|ecdsa|dss)|ecdsa-sha2-)[[:space:]]+[A-Za-z0-9+/=]+.*${SSH_KNOWN_GOOD_RE}" "$_odd" 2>/dev/null)
                _odd_known="${_odd_known:-0}"
                _odd_unknown=$(( _odd_total - _odd_known ))
                if (( _odd_unknown <= 0 )); then
                    # All keys in this file are known-good; skip.
                    continue
                fi
            fi
            oddkeys+=("$_odd")
        done < <(timeout 300 find /etc /var/spool/cron -maxdepth 5 \
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
            _g_hit=1
        fi
    fi

    # Pattern G lsyncd-amplification: master compromise → implicit replica
    # compromise via cluster replication keypair. Surfaces blast-radius for
    # remediation; doesn't escalate THIS host's verdict.
    if (( _g_hit )); then
        local _lsyncd_evidence=""
        if command -v pgrep >/dev/null 2>&1 && pgrep -x lsyncd >/dev/null 2>&1; then
            _lsyncd_evidence="process"
        elif [[ -d /etc/lsyncd ]]; then
            _lsyncd_evidence="config_dir"
        elif compgen -G '/etc/lsyncd*.conf' >/dev/null 2>&1 \
          || compgen -G '/etc/lsyncd*.lua' >/dev/null 2>&1; then
            _lsyncd_evidence="config_file"
        fi
        if [[ -n "$_lsyncd_evidence" ]]; then
            emit "destruction" "ioc_pattern_g_lsyncd_amplification" "warning" \
                 "ioc_pattern_g_lsyncd_cluster_blast_radius" 4 \
                 "evidence" "$_lsyncd_evidence" \
                 "note" "Pattern G hit on host with lsyncd present ($_lsyncd_evidence) - cluster replicas implicitly compromised via replication keypair. Revoke + reissue the cluster's keypair, not just this host's."
            ((hits++))
        fi
    fi

    # ---- Pattern H: seobot defacement / SEO spam dropper -----------------
    # H1/H2-hostile/H4 strong solo; H3 (ALLDONE) is generic English, emits
    # only when corroborated by H1, H2 (any tier), or H4. H2 uses adjacency
    # classifier (pkill is destructive both ways; C/F diag_re doesn't fit).
    local _h1_hit=0 _h2_hostile=0 _h2_review=0 _h4_hit=0
    local _h_alldone_hit=""

    # H1: seobot.php in any cPanel-managed docroot. Derive docroots from
    # /var/cpanel/userdata/<user>/<site> (canonical); fall back to
    # /home/*/public_html for hosts where userdata is sparse. Stop at first
    # hit (a single placement is enough to flag; forensic captures the rest).
    local h_seobot_hit=""
    local docroot_list; docroot_list=$(mktemp /tmp/ssioc.docroots.XXXXXX)
    {
        if [[ -d /var/cpanel/userdata ]]; then
            grep -rh '^documentroot:' /var/cpanel/userdata/*/ 2>/dev/null \
              | awk '{print $2}' | sort -u
        fi
        local _d
        for _d in /home/*/public_html; do
            [[ -d "$_d" ]] && printf '%s\n' "$_d"
        done
    } | sort -u > "$docroot_list"
    if [[ -s "$docroot_list" ]]; then
        local _dr _found
        while IFS= read -r _dr; do
            [[ -d "$_dr" ]] || continue
            _found=$(find "$_dr" -maxdepth 3 -name "$PATTERN_H_DROPPER_FILE" -print -quit 2>/dev/null)
            if [[ -n "$_found" ]]; then
                h_seobot_hit="$_found"
                break
            fi
        done < "$docroot_list"
    fi
    rm -f "$docroot_list"
    if [[ -n "$h_seobot_hit" ]]; then
        known_bad_meta "$h_seobot_hit"
        local _au_seobot
        _au_seobot=$(_attribute_path "$h_seobot_hit")
        _user_is_valid "$_au_seobot" || _au_seobot="_root"
        emit "destruction" "ioc_pattern_h_seobot_php" "strong" \
             "ioc_pattern_h_seobot_dropper_present" 10 \
             "sample_path" "$h_seobot_hit" "${META_KV[@]}" \
             "affected_user" "$_au_seobot" \
             "actor_privilege" "user" \
             "note" "$PATTERN_H_DROPPER_FILE planted in $h_seobot_hit - Pattern H SEO defacement (CRITICAL)."
        ((hits++))
        _h1_hit=1
    fi

    # H2: `pkill -9 nuclear.x86 kswapd01 xmrig` in any history file -
    # adjacency-classified via _classify_kill_prelude_context (ctx=3).
    local _h_kill_files=()
    local _hkf
    while IFS= read -r _hkf; do
        [[ -n "$_hkf" ]] && _h_kill_files+=("$_hkf")
    done < <(grep -lE "$PATTERN_H_KILL_PRELUDE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    if (( ${#_h_kill_files[@]} > 0 )); then
        local _hk_h_total=0 _hk_d_total=0 _hk_u_total=0
        local _hk_fhe="" _hk_file_h=""
        local _hk_file _hk_class _hk_h _hk_d _hk_u _hk_fhe_part _hk_file_h_part
        for _hk_file in "${_h_kill_files[@]}"; do
            _hk_class=$(_classify_kill_prelude_context "$_hk_file" "$PATTERN_H_KILL_PRELUDE" 3)
            _hk_h=$(_classify_field h         "$_hk_class")
            _hk_d=$(_classify_field d         "$_hk_class")
            _hk_u=$(_classify_field u         "$_hk_class")
            _hk_fhe_part=$(_classify_field fhe "$_hk_class")
            _hk_file_h_part=$(_classify_field file_h "$_hk_class")
            _hk_h_total=$((_hk_h_total + ${_hk_h:-0}))
            _hk_d_total=$((_hk_d_total + ${_hk_d:-0}))
            _hk_u_total=$((_hk_u_total + ${_hk_u:-0}))
            if [[ -z "$_hk_fhe" && -n "$_hk_fhe_part" && "${_hk_h:-0}" -gt 0 ]]; then
                _hk_fhe="$_hk_fhe_part"
                _hk_file_h="${_hk_file_h_part:-$_hk_file}"
            fi
        done
        local _hk_sample="${_hk_file_h:-${_h_kill_files[0]}}"
        local _hk_mtime
        _hk_mtime=$(stat -c %Y "$_hk_sample" 2>/dev/null)
        if (( _hk_h_total > 0 )); then
            emit "destruction" "ioc_pattern_h_kill_prelude_history_review" "warning" \
                 "ioc_pattern_h_competitor_kill_history_review" 4 \
                 "sample_path" "$_hk_sample" \
                 "ts_epoch_first" "${_hk_fhe:-0}" \
                 "mtime_epoch" "${_hk_mtime:-0}" \
                 "hostile_lines" "$_hk_h_total" \
                 "diagnostic_lines" "$_hk_d_total" \
                 "unknown_lines" "$_hk_u_total" \
                 "note" "Pattern H competitor-kill prelude in $_hk_sample followed by install primitive - bash_history-only evidence, manual review."
            ((hits++))
            _h2_hostile=1
        elif (( _hk_u_total > 0 )); then
            emit "destruction" "ioc_pattern_h_kill_prelude_review" "warning" \
                 "ioc_pattern_h_competitor_kill_review" 4 \
                 "sample_path" "${_h_kill_files[0]}" \
                 "mtime_epoch" "${_hk_mtime:-0}" \
                 "diagnostic_lines" "$_hk_d_total" \
                 "unknown_lines" "$_hk_u_total" \
                 "note" "Pattern H kill-prelude line in ${_h_kill_files[0]} with no adjacent install primitive and no defensive verify - manual review (attacker prep or operator cleanup)."
            ((hits++))
            _h2_review=1
        else
            emit "destruction" "ioc_pattern_h_kill_prelude_diagnostic" "info" \
                 "ioc_pattern_h_competitor_kill_diagnostic_only" 0 \
                 "sample_path" "${_h_kill_files[0]}" \
                 "mtime_epoch" "${_hk_mtime:-0}" \
                 "diagnostic_lines" "$_hk_d_total" \
                 "note" "Pattern H kill-prelude line in ${_h_kill_files[0]} adjacent to defensive verify (ps/pgrep/echo done/exit) - responder cleanup, not attacker prep."
        fi
    fi

    # H3: ALLDONE detection only - emit deferred until after H4 so the
    # corroboration gate (H1 || H2-hostile || H4) is decidable.
    _h_alldone_hit=$(grep -lF "$PATTERN_H_END_MARKER" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null | head -1)

    # H4: dropper archive on disk. Self-cleans per dossier; this catches
    # slow operators or interrupted runs. Encode first 16 bytes (raw zip
    # magic + extra-field header) as base64 and prefix-match against the
    # dossier-published H signature.
    if [[ -f "$PATTERN_H_ZIP_PATH" ]]; then
        local h_zip_b64=""
        if command -v base64 >/dev/null 2>&1; then
            h_zip_b64=$(head -c 16 "$PATTERN_H_ZIP_PATH" 2>/dev/null | base64 -w0 2>/dev/null)
        fi
        if [[ -n "$h_zip_b64" && "$h_zip_b64" == "${PATTERN_H_ZIP_MAGIC_B64}"* ]]; then
            known_bad_meta "$PATTERN_H_ZIP_PATH"
            emit "destruction" "ioc_pattern_h_zip_dropper" "strong" \
                 "ioc_pattern_h_dropper_archive" 10 \
                 "path" "$PATTERN_H_ZIP_PATH" "${META_KV[@]}" \
                 "note" "Pattern H dropper archive at $PATTERN_H_ZIP_PATH (base64 zip header matches H signature - operator did not self-clean)."
            ((hits++))
            _h4_hit=1
        fi
    fi

    # H3 deferred emit: corroboration-gated. ALLDONE alone is too generic
    # (responder grep / deploy echo / CI paste); requires H1/H2/H4. H2-review
    # (ambiguous kill-prelude adjacency) ALSO counts as corroboration.
    if [[ -n "$_h_alldone_hit" ]] \
       && (( _h1_hit || _h2_hostile || _h2_review || _h4_hit )); then
        local _h_alldone_mtime
        _h_alldone_mtime=$(stat -c %Y "$_h_alldone_hit" 2>/dev/null)
        local _h_corrob=""
        (( _h1_hit ))     && _h_corrob+="H1(seobot.php),"
        (( _h2_hostile )) && _h_corrob+="H2(hostile-shape kill prelude),"
        (( _h2_review ))  && _h_corrob+="H2(review-tier kill prelude),"
        (( _h4_hit ))     && _h_corrob+="H4(seobot.zip),"
        _h_corrob="${_h_corrob%,}"
        emit "destruction" "ioc_pattern_h_alldone_review" "warning" \
             "ioc_pattern_h_alldone_marker_review" 5 \
             "sample_path" "$_h_alldone_hit" \
             "mtime_epoch" "${_h_alldone_mtime:-0}" \
             "corroborated_by" "$_h_corrob" \
             "note" "Pattern H operator end-marker '$PATTERN_H_END_MARKER' in $_h_alldone_hit, corroborated by $_h_corrob - bash_history-only marker, manual review."
        ((hits++))
    fi

    # ---- Pattern I: system-service profile.d backdoor --------------------
    # Three strong signals (profile.d hook / binary / running process);
    # I4 (failed-chmod in /var/log/secure) is corroborating.

    # I1: profile.d hook file. Filename is unique per dossier; no benign
    # system component creates this exact filename.
    if [[ -f "$PATTERN_I_PROFILED" ]]; then
        known_bad_meta "$PATTERN_I_PROFILED"
        emit "destruction" "ioc_pattern_i_profiled_hook" "strong" \
             "ioc_pattern_i_profiled_hook_present" 10 \
             "path" "$PATTERN_I_PROFILED" "${META_KV[@]}" \
             "note" "Pattern I profile.d backdoor hook at $PATTERN_I_PROFILED - fires on every interactive login (CRITICAL)."
        ((hits++))
    fi

    # I2: binary at non-standard /root/.local/bin path.
    if [[ -f "$PATTERN_I_BINARY" ]]; then
        known_bad_meta "$PATTERN_I_BINARY"
        emit "destruction" "ioc_pattern_i_binary" "strong" \
             "ioc_pattern_i_binary_present" 10 \
             "path" "$PATTERN_I_BINARY" "${META_KV[@]}" \
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

    # I4: non-root SSH login → profile.d hook chmod hits EPERM → logged
    # to /var/log/secure. Confirms the hook is actively firing.
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

    # Pattern J: init-facility persistence (dossier-only). Direct call —
    # subshell would discard SIGNALS[] mutations from emit().
    check_pattern_j_persistence
    hits=$((hits + PATTERN_J_HITS))

    # ---- Pattern E: websocket/Shell access-log signature ---------------
    # /cpsess<id>/websocket/Shell = WHM Terminal. By (origin, status):
    # ext+2xx=strong, ext+!2xx=warn, int+2xx=info, int+!2xx=skip.
    # EXCLUDE_IPS suppresses known-good external admin IPs.
    local ws_log=/usr/local/cpanel/logs/access_log
    if [[ -f "$ws_log" ]]; then
        local excludes_env=""
        if (( ${#EXCLUDE_IPS[@]} > 0 )); then
            excludes_env=$(printf '%s\n' "${EXCLUDE_IPS[@]}")
        fi
        # Terminal dimensions (rows×cols in websocket Shell URL) act as
        # operator fingerprints; unknown dimensions flag warning-tier.
        # Handoff burst: ≥2 distinct ext IPs landing 2xx in 15m = multi-op.
        local ws_result
        ws_result=$(grep -E "$PATTERN_E_WS_RE" "$ws_log" 2>/dev/null \
                       | grep -vE "$PROBE_UA_RE" \
                       | EXCLUDES="$excludes_env" \
                         KNOWN_DIMS="$PATTERN_E_KNOWN_DIMS" \
                         awk '
            BEGIN {
                n = split(ENVIRON["EXCLUDES"], ex_arr, "\n")
                for (i = 1; i <= n; i++) if (ex_arr[i] != "") ex[ex_arr[i]] = 1
                kn = split(ENVIRON["KNOWN_DIMS"], kd_arr, ",")
                for (i = 1; i <= kn; i++) if (kd_arr[i] != "") known[kd_arr[i]] = 1
                ext_total = 0; ext_2xx = 0; int_2xx = 0; int_other = 0
                # Split ext_2xx by terminal dim: _known = CVE-2026-41940 attacker
                # fingerprint set; _unknown = legitimate WHM Terminal
                # sessions from real browsers. Without the split, wide-window
                # admin sessions (24x165 etc) trip Pattern E STRONG.
                ext_2xx_known = 0; ext_2xx_unknown = 0
                ext_sample = ""; int_sample = ""; unknown_dim_sample = ""
                # ext_known_sample = FIRST known-dim 2xx; strong-emit fields
                # parse from THIS line so a 4xx probe does not shadow the
                # actual known-dim 2xx as the surfaced sample.
                ext_known_sample = ""
                ts_first_ext = 0; burst_n = 0
            }
            # gawk 3.1.x (CL6 floor) lacks 3-arg match(s, /re/, arr); the
            # 2-arg form with substr+split extracts the captured groups.
            function dim_of(s,    seg, n, kv) {
                if (match(s, /rows=[0-9]+&cols=[0-9]+/)) {
                    seg = substr(s, RSTART, RLENGTH)
                    n = split(seg, kv, /[=&]/)
                    return kv[2] "x" kv[4]
                }
                return ""
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
                # gawk 3.1.x: 2-arg match() + substr/split (no 3-arg form).
                if (match($0, /\[[0-9][0-9]\/[0-9][0-9]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
                    _d = substr($0, RSTART+1, RLENGTH-1)
                    split(_d, _p, /[\/:]/)
                    ts = mktime(_p[3]" "_p[1]" "_p[2]" "_p[4]" "_p[5]" "_p[6])
                }
                d = dim_of($0)
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
                    if (st ~ /^2/) {
                        ext_2xx++
                        if (d != "") {
                            dim_count[d]++
                            if (d in known) {
                                # Attacker-fingerprint dim — strong-tier signal.
                                ext_2xx_known++
                                # First attacker-dim 2xx = canonical sample for
                                # strong emit; ext_sample preserved for fallback.
                                if (ext_known_sample == "") ext_known_sample = $0
                                # Handoff-burst tracking only counts attacker-
                                # dimension hits; legitimate admin teams from
                                # multiple IPs in 15min should not trip the
                                # multi-operator burst.
                                burst_n++
                                burst_ts[burst_n] = ts
                                burst_ip[burst_n] = ip
                            } else {
                                # Outside attacker fingerprint — typically a
                                # legitimate WHM Terminal admin session. Keep
                                # the unknown-dim sample for the separate
                                # ioc_pattern_e_unknown_dimension review emit.
                                ext_2xx_unknown++
                                if (unknown_dim_sample == "") unknown_dim_sample = $0
                            }
                        }
                    }
                    if (ext_sample == "") ext_sample = $0
                    if (ts > 0 && (ts_first_ext == 0 || ts < ts_first_ext)) ts_first_ext = ts
                }
            }
            END {
                # Per-dimension breakout - serialized "dim:count,dim:count,..."
                dim_csv = ""
                for (d in dim_count) {
                    dim_csv = dim_csv (dim_csv == "" ? "" : ",") d ":" dim_count[d]
                }
                # Unknown dimensions - any d not in known set.
                unknown_csv = ""
                for (d in dim_count) {
                    if (!(d in known)) {
                        unknown_csv = unknown_csv (unknown_csv == "" ? "" : ",") d
                    }
                }
                # Handoff burst: largest distinct-IP count within any 900s
                # (15-min) window over the recorded 2xx events.
                burst_max = 0
                for (i = 1; i <= burst_n; i++) {
                    delete window_ips
                    win_n = 0
                    for (j = 1; j <= burst_n; j++) {
                        if (burst_ts[j] >= burst_ts[i] && burst_ts[j] - burst_ts[i] <= 900) {
                            if (!(burst_ip[j] in window_ips)) {
                                window_ips[burst_ip[j]] = 1
                                win_n++
                            }
                        }
                    }
                    if (win_n > burst_max) burst_max = win_n
                }
                printf "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", \
                       ext_total, ext_2xx, ext_2xx_known, ext_2xx_unknown, \
                       int_2xx, int_other, \
                       ts_first_ext, burst_max, dim_csv, unknown_csv
                print ext_sample
                print int_sample
                print unknown_dim_sample
                print ext_known_sample
            }')
        local ext_total=0 ext_2xx=0 ext_2xx_known=0 ext_2xx_unknown=0
        local int_2xx=0 int_other=0 ts_first_ext=0
        local burst_max=0 dim_csv="" unknown_csv=""
        local ext_sample="" int_sample="" unknown_dim_sample="" ext_known_sample=""
        {
            IFS=$'\t' read -r ext_total ext_2xx ext_2xx_known ext_2xx_unknown int_2xx int_other ts_first_ext burst_max dim_csv unknown_csv
            IFS= read -r ext_sample
            IFS= read -r int_sample
            IFS= read -r unknown_dim_sample
            IFS= read -r ext_known_sample
        } <<< "$ws_result"
        ext_total="${ext_total:-0}"; ext_2xx="${ext_2xx:-0}"
        ext_2xx_known="${ext_2xx_known:-0}"; ext_2xx_unknown="${ext_2xx_unknown:-0}"
        int_2xx="${int_2xx:-0}"; int_other="${int_other:-0}"
        ts_first_ext="${ts_first_ext:-0}"; burst_max="${burst_max:-0}"

        # Split-by-dimension verdict gate:
        #   ext_2xx_known  > 0 → strong (attacker fingerprint matched, RCE)
        #   ext_2xx_unknown> 0 → warning (admin session most likely; review)
        #   ext_total      > 0 → warning (probes only, host repelled)
        if (( ext_2xx_known > 0 )); then
            # Parse from ext_known_sample (representative of the matching
            # known-dim 2xx). ext_sample fallback is defensive.
            # Apache combined-log: IP - USER [DATE] "METHOD PATH PROTO" STATUS SIZE
            local _e_src="${ext_known_sample:-$ext_sample}"
            local _e_ip _e_path _e_status _e_token=""
            _e_ip=$(printf '%s' "$_e_src" | awk '{print $1}')
            _e_path=$(printf '%s' "$_e_src" | awk -F'"' 'NF>=2{n=split($2,p," "); if(n>=2)print p[2]; else print ""}')
            _e_status=$(printf '%s' "$_e_src" | awk -F'"' 'NF>=3{n=split($3,p," "); if(n>=1)print p[1]; else print ""}')
            if [[ "$_e_path" =~ /cpsess([0-9]{10})/ ]]; then
                _e_token="${BASH_REMATCH[1]}"
            fi
            # Pattern E gate: requires CRLF anchor + 2xx-proximity, else demote to advisory.
            local _gate_sev="strong" _gate_key="ioc_pattern_e_websocket_shell_hits" _gate_weight=10
            local _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at CVE-2026-41940 attacker dimensions (${PATTERN_E_KNOWN_DIMS//,/ }) - Pattern E interactive RCE (CRITICAL)."
            if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )) \
               || ! [[ "$ts_first_ext" =~ ^[0-9]+$ ]] \
               || (( ts_first_ext == 0 )) \
               || (( ts_first_ext < LOGS_CRLF_CHAIN_FIRST_EPOCH )); then
                _gate_sev="advisory"
                _gate_key="ioc_pattern_e_websocket_shell_hits_pre_compromise"
                _gate_weight=0
                if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )); then
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at CVE-2026-41940 attacker dimensions but NO CVE-2026-41940 CRLF access-chain detected on this host - Pattern E is post-RCE toolchain and requires CRLF anchor as compromise evidence. Likely shared-infra coincidence or pre-disclosure noise (REVIEW; does not escalate host_verdict)."
                else
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at CVE-2026-41940 attacker dimensions but ts_first ($ts_first_ext) PREDATES first CRLF chain ($LOGS_CRLF_CHAIN_FIRST_EPOCH) - pre-compromise activity (REVIEW; does not escalate host_verdict)."
                fi
            elif (( LOGS_2XX_CPSESS_FIRST_EPOCH > 0 )); then
                # Skip proximity demotion when 2xx_on_cpsess didn't fire
                # strong (LOGS_2XX_CPSESS_FIRST_EPOCH == 0): no in-window
                # token-use means Pattern E alone still stands as RCE.
                local _e_delta=$((ts_first_ext - LOGS_2XX_CPSESS_FIRST_EPOCH))
                local _e_abs="${_e_delta#-}"
                if (( _e_abs > PATTERN_E_2XX_PROXIMITY_SEC )); then
                    _gate_sev="advisory"
                    _gate_key="ioc_pattern_e_websocket_shell_hits_orphan"
                    _gate_weight=0
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at CVE-2026-41940 attacker dimensions, post-CRLF, but ts_first ($ts_first_ext) is ${_e_abs}s away from successful token-use event ($LOGS_2XX_CPSESS_FIRST_EPOCH) - exceeds ${PATTERN_E_2XX_PROXIMITY_SEC}s operator-session window. Pattern E is exploitation-detached / orphan (REVIEW; does not escalate host_verdict)."
                fi
            fi
            emit "destruction" "ioc_pattern_e_websocket" "$_gate_sev" \
                 "$_gate_key" "$_gate_weight" \
                 "count" "$ext_2xx_known" "external_total" "$ext_total" \
                 "external_2xx_total" "$ext_2xx" \
                 "external_2xx_unknown_dim" "$ext_2xx_unknown" \
                 "internal_2xx" "$int_2xx" \
                 "dimensions" "${dim_csv:-(none)}" \
                 "ts_epoch_first" "$ts_first_ext" \
                 "crlf_first_epoch" "$LOGS_CRLF_CHAIN_FIRST_EPOCH" \
                 "twoxx_first_epoch" "$LOGS_2XX_CPSESS_FIRST_EPOCH" \
                 "proximity_sec" "$PATTERN_E_2XX_PROXIMITY_SEC" \
                 "ip" "$_e_ip" "path" "$_e_path" "status" "$_e_status" \
                 "cpsess_token" "${_e_token:-}" \
                 "sample" "${_e_src:0:200}" \
                 "note" "$_gate_note"
            ((hits++))
        elif (( ext_2xx_unknown > 0 )); then
            emit "destruction" "ioc_pattern_e_websocket" "advisory" \
                 "ioc_pattern_e_websocket_shell_unknown_dim_only" 4 \
                 "count" "$ext_2xx_unknown" "external_total" "$ext_total" \
                 "internal_2xx" "$int_2xx" \
                 "dimensions" "${dim_csv:-(none)}" \
                 "unknown_dimensions" "${unknown_csv:-(none)}" \
                 "ts_epoch_first" "$ts_first_ext" \
                 "sample" "${unknown_dim_sample:0:200}" \
                 "note" "$ext_2xx_unknown external IP(s) reached /cpsess*/websocket/Shell with 2xx, but ALL dimensions ($unknown_csv) are outside the CVE-2026-41940 attacker fingerprint - likely legitimate WHM Terminal admin sessions from non-canonical browsers. Confirm via the parallel ioc_pattern_e_unknown_dimension review (REVIEW)."
            ((hits++))
        elif (( ext_total > 0 )); then
            emit "destruction" "ioc_pattern_e_websocket" "advisory" \
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

        # Per-dimension breakout (info-level: triage context for the
        # operator; consumed by forensic kill-chain renderer for
        # annotation). Only emitted when 2xx hits exist - no signal
        # otherwise.
        if [[ -n "$dim_csv" ]]; then
            emit "destruction" "ioc_pattern_e_dimensions" "info" \
                 "ioc_pattern_e_dimension_breakout" 0 \
                 "dimensions" "$dim_csv" \
                 "note" "Pattern E websocket Shell dimensions seen: $dim_csv"
        fi
        # Unknown dimension warning - new operator fingerprint not yet in
        # PATTERN_E_KNOWN_DIMS. Triage prompt: confirm and update dossier.
        if [[ -n "$unknown_csv" ]]; then
            emit "destruction" "ioc_pattern_e_unknown_dimension" "advisory" \
                 "ioc_pattern_e_dimension_unknown" 5 \
                 "dimensions" "$unknown_csv" \
                 "sample" "${unknown_dim_sample:0:200}" \
                 "note" "Pattern E websocket Shell with dimension(s) $unknown_csv outside known operator set - possible new operator (REVIEW)."
            ((hits++))
        fi
        # Handoff burst: >=2 distinct external IPs each minted cpsess +
        # reached websocket Shell with 2xx within a 15-minute window.
        # Strong signal of multi-operator exploit chaining (toolkit
        # being shared/reused across operators on the same target).
        if (( burst_max >= 2 )); then
            emit "destruction" "ioc_pattern_e_handoff_burst" "strong" \
                 "ioc_pattern_e_handoff_burst_present" 8 \
                 "ip_count" "$burst_max" \
                 "note" "Pattern E exploit-handoff burst: $burst_max distinct external IPs each minted cpsess + reached websocket Shell within a 15-minute window (multi-operator chain)."
            ((hits++))
        fi
    fi

    # ---- Pattern K: Cloudflare-fronted /Update second-stage backdoor ----
    # K1 (host literal) shape-classified to avoid responder-grep FP.
    # K2 (tmp-path shape) emits standalone only when K1 was diagnostic-only
    # — diagnostic K1 must not silently swallow real K2 signal.
    local _k1_files=()
    local _k1f
    while IFS= read -r _k1f; do
        [[ -n "$_k1f" ]] && _k1_files+=("$_k1f")
    done < <(grep -lF "$PATTERN_K_BACKDOOR_HOST" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    local _k2_files=()
    local _k2f
    while IFS= read -r _k2f; do
        [[ -n "$_k2f" ]] && _k2_files+=("$_k2f")
    done < <(grep -lE "$PATTERN_K_TMP_RE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)

    local _k1_emit_real=0
    if (( ${#_k1_files[@]} > 0 )); then
        local _k1_class _k1h _k1d _k1u _k1fhe _k1file_h
        _k1_class=$(_classify_history_match literal "$PATTERN_K_BACKDOOR_HOST" "${_k1_files[@]}")
        _k1h=$(_classify_field h "$_k1_class")
        _k1d=$(_classify_field d "$_k1_class")
        _k1u=$(_classify_field u "$_k1_class")
        _k1fhe=$(_classify_field fhe "$_k1_class")
        _k1file_h=$(_classify_field file_h "$_k1_class")
        local _k1_sample="${_k1file_h:-${_k1_files[0]}}"
        local _k1_mtime
        _k1_mtime=$(stat -c %Y "$_k1_sample" 2>/dev/null)
        local _k1_corrob=""
        (( ${#_k2_files[@]} > 0 )) && _k1_corrob="K2(F=/tmp/.u-tempfile shape)"
        if (( ${_k1h:-0} > 0 )); then
            emit "destruction" "ioc_pattern_k_backdoor_fetch" "strong" \
                 "ioc_pattern_k_backdoor_host_referenced" 8 \
                 "sample_path" "$_k1_sample" \
                 "ts_epoch_first" "${_k1fhe:-0}" \
                 "mtime_epoch" "${_k1_mtime:-0}" \
                 "hostile_lines" "${_k1h:-0}" \
                 "diagnostic_lines" "${_k1d:-0}" \
                 "unknown_lines" "${_k1u:-0}" \
                 "corroborated_by" "${_k1_corrob:-(none)}" \
                 "note" "Pattern K backdoor host $PATTERN_K_BACKDOOR_HOST referenced in $_k1_sample (Cloudflare-fronted /Update second-stage; coordinate with Cloudflare T&S, do NOT blackhole at edge)."
            ((hits++))
            _k1_emit_real=1
        elif (( ${_k1u:-0} > 0 )); then
            emit "destruction" "ioc_pattern_k_backdoor_review" "warning" \
                 "ioc_pattern_k_backdoor_host_review" 4 \
                 "sample_path" "${_k1_files[0]}" \
                 "mtime_epoch" "${_k1_mtime:-0}" \
                 "diagnostic_lines" "${_k1d:-0}" \
                 "unknown_lines" "${_k1u:-0}" \
                 "corroborated_by" "${_k1_corrob:-(none)}" \
                 "note" "$PATTERN_K_BACKDOOR_HOST in ${_k1_files[0]} without download/exec verb - manual review."
            ((hits++))
            _k1_emit_real=1
        else
            emit "destruction" "ioc_pattern_k_backdoor_diagnostic" "info" \
                 "ioc_pattern_k_backdoor_diagnostic_only" 0 \
                 "sample_path" "${_k1_files[0]}" \
                 "mtime_epoch" "${_k1_mtime:-0}" \
                 "diagnostic_lines" "${_k1d:-0}" \
                 "note" "$PATTERN_K_BACKDOOR_HOST appears only in diagnostic-shape commands in ${_k1_files[0]} - operator/IR search, not an IOC."
        fi
    fi

    # K2 standalone emit when no real K1: F=/tmp/.u shape alone has FP
    # risk in legitimate sysadmin scripts so warning-tier only.
    if (( ${#_k2_files[@]} > 0 && _k1_emit_real == 0 )); then
        local _k2_sample="${_k2_files[0]}"
        local _k2_mtime
        _k2_mtime=$(stat -c %Y "$_k2_sample" 2>/dev/null)
        emit "destruction" "ioc_pattern_k_tmpfile_paranoid" "warning" \
             "ioc_pattern_k_pid_tempfile_shape" 3 \
             "sample_path" "$_k2_sample" \
             "mtime_epoch" "${_k2_mtime:-0}" \
             "note" "Pattern K paranoid-cleanup F=/tmp/.u<pid> tempfile shape in $_k2_sample without $PATTERN_K_BACKDOOR_HOST corroboration - manual review (low-confidence shape signal alone)."
        ((hits++))
    fi

    # K3 dropper-shape — survives C2 rotation.
    local _k3_files=()
    local _k3f
    while IFS= read -r _k3f; do
        [[ -n "$_k3f" ]] && _k3_files+=("$_k3f")
    done < <(grep -lE "$PATTERN_K_DROPPER_SHAPE_RE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    if (( ${#_k3_files[@]} > 0 && _k1_emit_real == 0 )); then
        local _k3_class _k3h _k3d _k3u _k3fhe _k3file_h
        _k3_class=$(_classify_history_match regex "$PATTERN_K_DROPPER_SHAPE_RE" "${_k3_files[@]}")
        _k3h=$(_classify_field h "$_k3_class")
        _k3d=$(_classify_field d "$_k3_class")
        _k3u=$(_classify_field u "$_k3_class")
        _k3fhe=$(_classify_field fhe "$_k3_class")
        _k3file_h=$(_classify_field file_h "$_k3_class")
        local _k3_sample="${_k3file_h:-${_k3_files[0]}}"
        local _k3_mtime
        _k3_mtime=$(stat -c %Y "$_k3_sample" 2>/dev/null)
        if (( ${_k3h:-0} > 0 )); then
            emit "destruction" "ioc_pattern_k_dropper_shape" "strong" \
                 "ioc_pattern_k_dropper_paranoid_chain" 8 \
                 "sample_path" "$_k3_sample" \
                 "ts_epoch_first" "${_k3fhe:-0}" \
                 "mtime_epoch" "${_k3_mtime:-0}" \
                 "hostile_lines" "${_k3h:-0}" \
                 "diagnostic_lines" "${_k3d:-0}" \
                 "unknown_lines" "${_k3u:-0}" \
                 "note" "Pattern K dropper paranoid-chain (wget -q -O … && chmod 755 … && … -s; rm -f) in $_k3_sample — same toolchain as cp.dene.de.com but possibly rotated C2 host (capture URL from sample for IOC update)."
            ((hits++))
        fi
    fi

    # ---- Pattern L: filesystem-nuke (rm -rf --no-preserve-root /) -------
    # L1 shape-classified for diag-shape FP. L2 (__CMD_START__/__CMD_END__)
    # emits standalone only when L1 didn't fire strong/warning.
    local _l1_files=()
    local _l1f
    while IFS= read -r _l1f; do
        [[ -n "$_l1f" ]] && _l1_files+=("$_l1f")
    done < <(grep -lE "$PATTERN_L_NUKE_RE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)

    # L2 envelope routed through classifier so responder `grep
    # __CMD_START__ /root/.bash_history` doesn't FP. Diag-only envelope
    # presence is ignored (responder pollution); hostile or unknown
    # shape counts as real corroboration.
    local _l2_files=()
    local _l2f
    while IFS= read -r _l2f; do
        [[ -n "$_l2f" ]] && _l2_files+=("$_l2f")
    done < <(grep -lE "$PATTERN_L_CMD_ENVELOPE_RE" "${HISTORY_FILES_GLOB[@]}" 2>/dev/null)
    local _l2_h=0 _l2_u=0 _l2_sample="" _l_envelope_corrob=""
    if (( ${#_l2_files[@]} > 0 )); then
        local _l2_class _l2_file_h
        _l2_class=$(_classify_history_match regex "$PATTERN_L_CMD_ENVELOPE_RE" "${_l2_files[@]}")
        _l2_h=$(_classify_field h "$_l2_class")
        _l2_u=$(_classify_field u "$_l2_class")
        _l2_file_h=$(_classify_field file_h "$_l2_class")
        _l2_sample="${_l2_file_h:-${_l2_files[0]}}"
        if (( ${_l2_h:-0} > 0 || ${_l2_u:-0} > 0 )); then
            _l_envelope_corrob="__CMD_START__/__CMD_END__ envelope present"
        fi
    fi

    local _l1_emit_real=0
    if (( ${#_l1_files[@]} > 0 )); then
        local _l1_class _l1h _l1d _l1u _l1fhe _l1file_h
        _l1_class=$(_classify_history_match regex "$PATTERN_L_NUKE_RE" "${_l1_files[@]}")
        _l1h=$(_classify_field h "$_l1_class")
        _l1d=$(_classify_field d "$_l1_class")
        _l1u=$(_classify_field u "$_l1_class")
        _l1fhe=$(_classify_field fhe "$_l1_class")
        _l1file_h=$(_classify_field file_h "$_l1_class")
        local _l1_sample="${_l1file_h:-${_l1_files[0]}}"
        local _l1_mtime
        _l1_mtime=$(stat -c %Y "$_l1_sample" 2>/dev/null)
        if (( ${_l1h:-0} > 0 )); then
            emit "destruction" "ioc_pattern_l_filesystem_nuke_history_review" "warning" \
                 "ioc_pattern_l_no_preserve_root_rm_history_review" 4 \
                 "sample_path" "$_l1_sample" \
                 "ts_epoch_first" "${_l1fhe:-0}" \
                 "mtime_epoch" "${_l1_mtime:-0}" \
                 "hostile_lines" "${_l1h:-0}" \
                 "diagnostic_lines" "${_l1d:-0}" \
                 "unknown_lines" "${_l1u:-0}" \
                 "corroborated_by" "${_l_envelope_corrob:-(none)}" \
                 "note" "Pattern L filesystem-nuke (rm -rf --no-preserve-root /) in $_l1_sample - bash_history-only evidence, manual review."
            ((hits++))
            _l1_emit_real=1
        elif (( ${_l1u:-0} > 0 )); then
            emit "destruction" "ioc_pattern_l_filesystem_nuke_review" "warning" \
                 "ioc_pattern_l_no_preserve_root_review" 4 \
                 "sample_path" "${_l1_files[0]}" \
                 "mtime_epoch" "${_l1_mtime:-0}" \
                 "diagnostic_lines" "${_l1d:-0}" \
                 "unknown_lines" "${_l1u:-0}" \
                 "corroborated_by" "${_l_envelope_corrob:-(none)}" \
                 "note" "rm -rf --no-preserve-root / in ${_l1_files[0]} without leading-token shape - manual review."
            ((hits++))
            _l1_emit_real=1
        else
            emit "destruction" "ioc_pattern_l_filesystem_nuke_diagnostic" "info" \
                 "ioc_pattern_l_no_preserve_root_diagnostic_only" 0 \
                 "sample_path" "${_l1_files[0]}" \
                 "mtime_epoch" "${_l1_mtime:-0}" \
                 "diagnostic_lines" "${_l1d:-0}" \
                 "note" "rm -rf --no-preserve-root / appears only in diagnostic-shape commands in ${_l1_files[0]} - operator/IR search, not an IOC."
        fi
    fi

    # L2 standalone emit when no real L1: destructive-class harvester
    # ran but command may have been rotated/redacted out of history.
    if [[ -n "$_l_envelope_corrob" ]] && (( _l1_emit_real == 0 )); then
        local _l_env_mtime
        _l_env_mtime=$(stat -c %Y "$_l2_sample" 2>/dev/null)
        emit "destruction" "ioc_pattern_l_cmd_envelope_review" "warning" \
             "ioc_pattern_l_destructive_cmd_envelope_review" 4 \
             "sample_path" "$_l2_sample" \
             "mtime_epoch" "${_l_env_mtime:-0}" \
             "envelope_lines" "$((_l2_h + _l2_u))" \
             "note" "Pattern L __CMD_START__/__CMD_END__ destructive-command envelope in $_l2_sample - bash_history-only evidence, manual review."
        ((hits++))
    fi

    # ---- Pattern M: rogue UID=0 user + amco_ docker botnet ---------------
    local _m1_hit=0 _m2_hit=0 _m4_hit=0 _m5_hit=0 _m7_hit=0 _m8_hit=0 _m9_hit=0
    # M1 — non-root UID=0 in /etc/passwd. Single hit = decisive.
    if [[ -f /etc/passwd ]]; then
        local _m_uid0
        while IFS= read -r _m_uid0; do
            [[ -n "$_m_uid0" ]] || continue
            emit "destruction" "ioc_pattern_m_uid0_user" "strong" \
                 "ioc_pattern_m_uid0_nonroot_user_present" 15 \
                 "username" "$_m_uid0" \
                 "passwd_line" "$(grep -E "^${_m_uid0}:" /etc/passwd 2>/dev/null | head -1)" \
                 "note" "Non-root user '$_m_uid0' has UID=0 (full root equivalent) - Pattern M backdoor user (CRITICAL)."
            ((hits++)); _m1_hit=1
        done < <(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)

        # M2 — known-bad username, corroboration-gated.
        local _m_known _m_pwline _m_uid _m_corrob _m_corrob_reason
        for _m_known in "${PATTERN_M_KNOWN_USERS[@]}"; do
            _m_pwline=$(grep -E "^${_m_known}:" /etc/passwd 2>/dev/null | head -1)
            [[ -n "$_m_pwline" ]] || continue
            _m_uid=$(awk -F: -v u="$_m_known" '$1==u {print $3; exit}' /etc/passwd 2>/dev/null)
            _m_corrob=0; _m_corrob_reason=""
            if [[ "${_m_uid:-}" == "0" ]]; then
                _m_corrob=1; _m_corrob_reason="UID=0"
            elif awk -F: -v u="$_m_known" '
                    ($1=="wheel" || $1=="sudo") {
                        n = split($4, m, ",")
                        for (i=1; i<=n; i++) if (m[i] == u) { found=1; exit }
                    }
                    END { exit found ? 0 : 1 }
                ' /etc/group 2>/dev/null; then
                _m_corrob=1; _m_corrob_reason="wheel-or-sudo-group"
            elif [[ -f "/etc/sudoers.d/${_m_known}" ]] \
                 || compgen -G "/etc/sudoers.d/*${_m_known}*" >/dev/null 2>&1; then
                _m_corrob=1; _m_corrob_reason="sudoers.d-match"
            fi
            if (( _m_corrob )); then
                emit "destruction" "ioc_pattern_m_known_bad_user" "strong" \
                     "ioc_pattern_m_known_bad_user_present" 10 \
                     "username" "$_m_known" \
                     "uid" "${_m_uid:-}" \
                     "corroboration" "$_m_corrob_reason" \
                     "passwd_line" "$_m_pwline" \
                     "note" "Known-bad backdoor username '$_m_known' present in /etc/passwd, corroborated by $_m_corrob_reason - Pattern M (amco/pakchoi botnet family) (CRITICAL)."
                ((hits++)); _m2_hit=1
            else
                emit "destruction" "ioc_pattern_m_known_bad_user_review" "warning" \
                     "ioc_pattern_m_known_bad_user_review" 4 \
                     "username" "$_m_known" \
                     "uid" "${_m_uid:-}" \
                     "passwd_line" "$_m_pwline" \
                     "note" "Username '$_m_known' (matches Pattern M known-bad list) present in /etc/passwd but UID≠0 and not in wheel/sudo group and no sudoers.d match - may be legitimate cPanel tenant; manual review."
                ((hits++))
            fi
        done
    fi

    # M3 — sudoers.d NOPASSWD:ALL post-disclosure.
    if [[ -d /etc/sudoers.d ]]; then
        local _m_sd
        while IFS= read -r _m_sd; do
            [[ -f "$_m_sd" ]] || continue
            grep -qE '^[^#]*NOPASSWD:[[:space:]]*ALL' "$_m_sd" 2>/dev/null || continue
            local _m_sd_mt _m_sd_ct
            _m_sd_mt=$(stat -c %Y "$_m_sd" 2>/dev/null)
            _m_sd_ct=$(stat -c %Z "$_m_sd" 2>/dev/null)
            _m_sd_mt="${_m_sd_mt:-0}"; _m_sd_ct="${_m_sd_ct:-0}"
            if (( _m_sd_mt < PATTERN_M_POST_DISCLOSURE_EPOCH )) \
               && (( _m_sd_ct < PATTERN_M_POST_DISCLOSURE_EPOCH )); then
                continue
            fi
            local _m_sd_base="${_m_sd##*/}"
            local _m_sd_sev=warning _m_sd_wt=4
            local _m_sd_id=ioc_pattern_m_sudoers_nopasswd_review
            local _m_sd_key=ioc_pattern_m_sudoers_nopasswd_review
            local _m_sd_note="Sudoers drop $_m_sd has NOPASSWD:ALL (post-disclosure mtime/ctime) - review (legitimate IR/devops can create these; Pattern M variants drop 99-<user>)."

            # Known-good LW/Nexcess provisioning shapes: info-tier.
            case "$_m_sd_base" in
                lwadmin|lw-admin|liquidweb|nexcess)
                    if grep -qE "^[[:space:]]*(Defaults:)?(lwadmin|lw-admin|liquidweb|nexcess)[-_[:space:]]" "$_m_sd" 2>/dev/null; then
                        _m_sd_sev=info; _m_sd_wt=0
                        _m_sd_id=ioc_pattern_m_sudoers_known_good
                        _m_sd_key=ioc_pattern_m_sudoers_known_good
                        _m_sd_note="Sudoers drop $_m_sd matches LW/Nexcess provisioning shape (NOPASSWD:ALL is standard for $_m_sd_base) - re-image+restore re-stamps mtime/ctime; not a Pattern M IOC."
                    fi
                    ;;
            esac

            # Known-bad name overrides known-good demote.
            local _m_known2
            for _m_known2 in "${PATTERN_M_KNOWN_USERS[@]}"; do
                if [[ "$_m_sd_base" == *"$_m_known2"* ]]; then
                    _m_sd_sev=strong; _m_sd_wt=10
                    _m_sd_id=ioc_pattern_m_sudoers_known_bad
                    _m_sd_key=ioc_pattern_m_sudoers_known_bad_present
                    _m_sd_note="Sudoers drop $_m_sd matches known-bad name shape ($_m_known2) with NOPASSWD:ALL (post-disclosure mtime/ctime) - Pattern M backdoor sudoers (CRITICAL)."
                    break
                fi
            done
            emit "destruction" "$_m_sd_id" "$_m_sd_sev" \
                 "$_m_sd_key" "$_m_sd_wt" \
                 "path" "$_m_sd" \
                 "mtime_epoch" "$_m_sd_mt" \
                 "ctime_epoch" "$_m_sd_ct" \
                 "note" "$_m_sd_note"
            ((hits++))
        done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
    fi

    # M7 — Monero wallet literal. Batched grep, 5min walltime cap.
    local _m_xmr_hit="" _m_xmr_from_history=0 _m_xmr_paths=(
        /root /etc /opt /tmp /var/tmp /var/spool/cron
        /usr/local/bin /usr/local/sbin
    )
    local _m_xmr_dirs_present=() _m_xmr_d
    for _m_xmr_d in "${_m_xmr_paths[@]}"; do
        [[ -d "$_m_xmr_d" ]] && _m_xmr_dirs_present+=("$_m_xmr_d")
    done
    if (( ${#_m_xmr_dirs_present[@]} > 0 )); then
        local _m_xmr_f
        while IFS= read -r _m_xmr_f; do
            [[ -n "$_m_xmr_f" ]] || continue
            # Skip toolkit self-reference.
            if grep -qE 'PATTERN_M_XMR_WALLET=|sessionscribe-ioc-scan' "$_m_xmr_f" 2>/dev/null; then
                continue
            fi
            _m_xmr_hit="$_m_xmr_f"
            break
        done < <(
            timeout 300 find "${_m_xmr_dirs_present[@]}" -maxdepth 4 \
                \( -name node_modules -o -name .cache -o -name .composer \
                   -o -name .npm -o -name .cagefs -o -name __pycache__ \
                   -o -name mail -o -name .git \) -prune \
                -o -type f -size +1c -size -10M \
                ! -name 'sessionscribe-*' ! -name 'nxesec-whmscribe-*' \
                -print0 2>/dev/null \
            | xargs -0 -r grep -lF -- "$PATTERN_M_XMR_WALLET" 2>/dev/null
        )
    fi
    if [[ -z "$_m_xmr_hit" ]]; then
        local _m_xmr_h
        for _m_xmr_h in /root/.bash_history /home/*/.bash_history; do
            [[ -f "$_m_xmr_h" ]] || continue
            if grep -qF "$PATTERN_M_XMR_WALLET" "$_m_xmr_h" 2>/dev/null; then
                _m_xmr_hit="$_m_xmr_h"
                _m_xmr_from_history=1
                break
            fi
        done
    fi
    if [[ -n "$_m_xmr_hit" ]]; then
        if _is_doc_shape "$_m_xmr_hit"; then
            emit "destruction" "ioc_pattern_m_xmr_wallet_documentation" "info" \
                 "ioc_pattern_m_xmr_wallet_documentation_reference" 0 \
                 "path" "$_m_xmr_hit" \
                 "wallet" "$PATTERN_M_XMR_WALLET" \
                 "mtime_epoch" "$(stat -c %Y "$_m_xmr_hit" 2>/dev/null)" \
                 "note" "Pattern M XMR wallet string in $_m_xmr_hit but file is in IR-notes/docs path or long-form documentation - reference, not attacker drop."
        elif (( _m_xmr_from_history )); then
            emit "destruction" "ioc_pattern_m_xmr_wallet_history_review" "warning" \
                 "ioc_pattern_m_xmr_wallet_history_review" 5 \
                 "path" "$_m_xmr_hit" \
                 "wallet" "$PATTERN_M_XMR_WALLET" \
                 "mtime_epoch" "$(stat -c %Y "$_m_xmr_hit" 2>/dev/null)" \
                 "note" "Pattern M XMR mining wallet fingerprint in $_m_xmr_hit - bash_history-only evidence, manual review (responder paste vs cryptominer C2)."
        else
            emit "destruction" "ioc_pattern_m_xmr_wallet" "strong" \
                 "ioc_pattern_m_xmr_wallet_present" 12 \
                 "path" "$_m_xmr_hit" \
                 "wallet" "$PATTERN_M_XMR_WALLET" \
                 "mtime_epoch" "$(stat -c %Y "$_m_xmr_hit" 2>/dev/null)" \
                 "note" "Pattern M XMR mining wallet fingerprint in $_m_xmr_hit - cryptominer C2 (CRITICAL; Reddit r/cpanel 27 MH/s botnet)."
            _m7_hit=1
        fi
        ((hits++))
    fi

    # M8 — C2 endpoint live socket + crontab/history references.
    local _m_c2_live="" _m_c2_file=""
    if command -v ss >/dev/null 2>&1; then
        _m_c2_live=$(ss -tn 2>/dev/null | awk -v ip="$PATTERN_M_C2_IP" '$0 ~ ip {print $0; exit}')
    elif command -v netstat >/dev/null 2>&1; then
        _m_c2_live=$(netstat -tn 2>/dev/null | awk -v ip="$PATTERN_M_C2_IP" '$0 ~ ip {print $0; exit}')
    fi
    if [[ -n "$_m_c2_live" ]]; then
        emit "destruction" "ioc_pattern_m_c2_live_socket" "strong" \
             "ioc_pattern_m_c2_live_connection" 12 \
             "c2_ip" "$PATTERN_M_C2_IP" \
             "c2_port" "$PATTERN_M_C2_PORT" \
             "socket" "$_m_c2_live" \
             "note" "Live TCP connection to Pattern M C2 $PATTERN_M_C2_IP:$PATTERN_M_C2_PORT - credential exfiltration in flight (CRITICAL)."
        ((hits++)); _m8_hit=1
    fi
    # Crontab-only scope — bash_history hits FP on operator IR-grep activity
    # (the diag-shape classifier would also work but is overkill for M8/M9).
    local _m_c2_search_files=(/var/spool/cron/root /etc/crontab)
    if [[ -d /etc/cron.d ]]; then
        local _m_cd2
        while IFS= read -r _m_cd2; do
            [[ -f "$_m_cd2" ]] && _m_c2_search_files+=("$_m_cd2")
        done < <(find /etc/cron.d -maxdepth 1 -type f 2>/dev/null)
    fi
    local _m_c2_f
    for _m_c2_f in "${_m_c2_search_files[@]}"; do
        [[ -f "$_m_c2_f" ]] || continue
        if grep -qF "$PATTERN_M_C2_IP" "$_m_c2_f" 2>/dev/null; then
            _m_c2_file="$_m_c2_f"
            break
        fi
    done
    if [[ -n "$_m_c2_file" ]]; then
        if _is_doc_shape "$_m_c2_file"; then
            emit "destruction" "ioc_pattern_m_c2_reference_documentation" "info" \
                 "ioc_pattern_m_c2_reference_documentation" 0 \
                 "path" "$_m_c2_file" \
                 "c2_ip" "$PATTERN_M_C2_IP" \
                 "mtime_epoch" "$(stat -c %Y "$_m_c2_file" 2>/dev/null)" \
                 "note" "Pattern M C2 IP referenced in $_m_c2_file but file is documentation-shape - reference, not attacker config."
        else
            emit "destruction" "ioc_pattern_m_c2_reference" "strong" \
                 "ioc_pattern_m_c2_reference_present" 10 \
                 "path" "$_m_c2_file" \
                 "c2_ip" "$PATTERN_M_C2_IP" \
                 "mtime_epoch" "$(stat -c %Y "$_m_c2_file" 2>/dev/null)" \
                 "note" "Pattern M C2 IP $PATTERN_M_C2_IP referenced in $_m_c2_file - exfil endpoint configured (CRITICAL)."
            _m8_hit=1
        fi
        ((hits++))
    fi

    # M9 — negoroo/amco docker image (distinct from amco_<UUID> in M4).
    if command -v docker >/dev/null 2>&1; then
        if docker images --format '{{.Repository}}' 2>/dev/null | grep -qFx "$PATTERN_M_DOCKER_IMAGE"; then
            emit "destruction" "ioc_pattern_m_negoroo_image_present" "strong" \
                 "ioc_pattern_m_negoroo_docker_image" 10 \
                 "image" "$PATTERN_M_DOCKER_IMAGE" \
                 "note" "Pattern M docker image '$PATTERN_M_DOCKER_IMAGE' present in docker images - cryptominer payload (CRITICAL)."
            ((hits++)); _m9_hit=1
        fi
    fi
    local _m_neg_cron=""
    for _m_c2_f in "${_m_c2_search_files[@]}"; do
        [[ -f "$_m_c2_f" ]] || continue
        if grep -qF "$PATTERN_M_DOCKER_IMAGE" "$_m_c2_f" 2>/dev/null; then
            _m_neg_cron="$_m_c2_f"
            break
        fi
    done
    if [[ -n "$_m_neg_cron" ]]; then
        if _is_doc_shape "$_m_neg_cron"; then
            emit "destruction" "ioc_pattern_m_negoroo_image_documentation" "info" \
                 "ioc_pattern_m_negoroo_image_documentation" 0 \
                 "path" "$_m_neg_cron" \
                 "image" "$PATTERN_M_DOCKER_IMAGE" \
                 "mtime_epoch" "$(stat -c %Y "$_m_neg_cron" 2>/dev/null)" \
                 "note" "Pattern M docker image referenced in $_m_neg_cron but file is documentation-shape - reference, not persistence config."
        else
            emit "destruction" "ioc_pattern_m_negoroo_image_reference" "strong" \
                 "ioc_pattern_m_negoroo_image_referenced" 10 \
                 "path" "$_m_neg_cron" \
                 "image" "$PATTERN_M_DOCKER_IMAGE" \
                 "mtime_epoch" "$(stat -c %Y "$_m_neg_cron" 2>/dev/null)" \
                 "note" "Pattern M docker image '$PATTERN_M_DOCKER_IMAGE' referenced in $_m_neg_cron - persistence anchor for cryptominer (CRITICAL)."
            _m9_hit=1
        fi
        ((hits++))
    fi

    # M6 — /root/.accesshash post-disclosure, corroboration-gated by M1-M9.
    if [[ -f "$PATTERN_M_ACCESSHASH_PATH" ]]; then
        local _m_ah_mt _m_ah_ct
        _m_ah_mt=$(stat -c %Y "$PATTERN_M_ACCESSHASH_PATH" 2>/dev/null)
        _m_ah_ct=$(stat -c %Z "$PATTERN_M_ACCESSHASH_PATH" 2>/dev/null)
        _m_ah_mt="${_m_ah_mt:-0}"; _m_ah_ct="${_m_ah_ct:-0}"
        if (( _m_ah_mt >= PATTERN_M_POST_DISCLOSURE_EPOCH )) \
           || (( _m_ah_ct >= PATTERN_M_POST_DISCLOSURE_EPOCH )); then
            local _m_ah_corrob=$(( _m1_hit || _m2_hit || _m4_hit || _m5_hit || _m7_hit || _m8_hit || _m9_hit ))
            local _m_ah_corrob_list=""
            (( _m1_hit )) && _m_ah_corrob_list+="M1(uid0),"
            (( _m2_hit )) && _m_ah_corrob_list+="M2(known-bad-user),"
            (( _m4_hit )) && _m_ah_corrob_list+="M4(amco-docker),"
            (( _m5_hit )) && _m_ah_corrob_list+="M5(cron-self-heal),"
            (( _m7_hit )) && _m_ah_corrob_list+="M7(xmr-wallet),"
            (( _m8_hit )) && _m_ah_corrob_list+="M8(c2-endpoint),"
            (( _m9_hit )) && _m_ah_corrob_list+="M9(negoroo-image),"
            _m_ah_corrob_list="${_m_ah_corrob_list%,}"
            if (( _m_ah_corrob )); then
                emit "destruction" "ioc_pattern_m_accesshash_post_disclosure" "strong" \
                     "ioc_pattern_m_accesshash_recent_drop" 10 \
                     "path" "$PATTERN_M_ACCESSHASH_PATH" \
                     "mtime_epoch" "$_m_ah_mt" \
                     "ctime_epoch" "$_m_ah_ct" \
                     "corroborated_by" "$_m_ah_corrob_list" \
                     "note" "$PATTERN_M_ACCESSHASH_PATH touched on/after 2026-04-28 (CVE-2026-41940 disclosure), corroborated by $_m_ah_corrob_list - attacker enabling WHM root API access (CRITICAL)."
            else
                emit "destruction" "ioc_pattern_m_accesshash_post_disclosure_review" "warning" \
                     "ioc_pattern_m_accesshash_recent_drop_review" 4 \
                     "path" "$PATTERN_M_ACCESSHASH_PATH" \
                     "mtime_epoch" "$_m_ah_mt" \
                     "ctime_epoch" "$_m_ah_ct" \
                     "note" "$PATTERN_M_ACCESSHASH_PATH touched on/after 2026-04-28 with no corroborating Pattern M signal - may be legitimate admin/devops WHM API enable; manual review."
            fi
            ((hits++))
        fi
    fi

    # M4 — amco_<UUID> docker container in crontab or docker ps.
    local _m_amco_hit="" _m_amco_src="" _m_cf
    for _m_cf in /var/spool/cron/root /etc/crontab /etc/cron.d/*; do
        [[ -f "$_m_cf" ]] || continue
        if grep -qE "$PATTERN_M_AMCO_RE" "$_m_cf" 2>/dev/null; then
            _m_amco_hit=$(grep -oE "$PATTERN_M_AMCO_RE" "$_m_cf" 2>/dev/null | head -1)
            _m_amco_src="$_m_cf"
            break
        fi
    done
    if [[ -n "$_m_amco_hit" ]]; then
        emit "destruction" "ioc_pattern_m_amco_docker_cron" "strong" \
             "ioc_pattern_m_amco_docker_persistence" 10 \
             "path" "$_m_amco_src" \
             "container_name" "$_m_amco_hit" \
             "mtime_epoch" "$(stat -c %Y "$_m_amco_src" 2>/dev/null)" \
             "note" "amco_<UUID> docker container '$_m_amco_hit' referenced in $_m_amco_src - Pattern M cryptominer botnet persistence (CRITICAL)."
        ((hits++)); _m4_hit=1
    fi
    if command -v docker >/dev/null 2>&1; then
        local _m_amco_live
        _m_amco_live=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E "$PATTERN_M_AMCO_RE" | head -1)
        if [[ -n "$_m_amco_live" ]]; then
            emit "destruction" "ioc_pattern_m_amco_docker_live" "strong" \
                 "ioc_pattern_m_amco_docker_live_container" 10 \
                 "container_name" "$_m_amco_live" \
                 "note" "amco_<UUID> docker container '$_m_amco_live' present in docker ps - Pattern M cryptominer live (CRITICAL)."
            ((hits++)); _m4_hit=1
        fi
    fi

    # M5 — cron self-heal shape against root crontab + /etc/cron.d/*.
    local _m_sh_files=(/var/spool/cron/root /etc/crontab)
    if [[ -d /etc/cron.d ]]; then
        local _m_cd
        while IFS= read -r _m_cd; do
            [[ -f "$_m_cd" ]] && _m_sh_files+=("$_m_cd")
        done < <(find /etc/cron.d -maxdepth 1 -type f 2>/dev/null)
    fi
    local _m_sh_hit=""
    for _m_cf in "${_m_sh_files[@]}"; do
        [[ -f "$_m_cf" ]] || continue
        if grep -qE "$PATTERN_M_CRON_SELF_HEAL_RE" "$_m_cf" 2>/dev/null; then
            _m_sh_hit="$_m_cf"
            break
        fi
    done
    if [[ -n "$_m_sh_hit" ]]; then
        local _m_sh_sample
        _m_sh_sample=$(grep -oE ".{0,40}$PATTERN_M_CRON_SELF_HEAL_RE.{0,40}" "$_m_sh_hit" 2>/dev/null | head -1)
        emit "destruction" "ioc_pattern_m_cron_self_heal" "strong" \
             "ioc_pattern_m_cron_self_heal_present" 10 \
             "path" "$_m_sh_hit" \
             "sample" "${_m_sh_sample:-<elided>}" \
             "mtime_epoch" "$(stat -c %Y "$_m_sh_hit" 2>/dev/null)" \
             "note" "Cron self-heal shape (id <U> || useradd...chpasswd...sudoers.d) in $_m_sh_hit - Pattern M backdoor user persistence (rebuilds every cron tick)."
        ((hits++)); _m5_hit=1
    fi

    # ---- Runtime-state IOCs ----
    # Live IOCs flip host_verdict=COMPROMISED only when root-attributed
    # (process UID, stat %u, /proc/<pid>/status). LPE PoC binaries stay
    # live_compromise unconditionally — kernel/setuid aims at root.
    local _rt_p _rt_owner _rt_id _rt_key _rt_sev _rt_label _rt_note_suffix
    for _rt_p in "${RUNTIME_KNOWN_BAD_PATHS[@]}"; do
        [[ -f "$_rt_p" ]] || continue
        known_bad_meta "$_rt_p"
        _rt_id="ioc_runtime_known_bad_path"
        _rt_key="ioc_runtime_known_bad_path_present"
        _rt_note_suffix=""
        case "$_rt_p" in
            /dev/shm/.gs)
                _rt_label="GSocket listener binary"
                _rt_owner=$(stat -c %u "$_rt_p" 2>/dev/null)
                if [[ "${_rt_owner:-0}" == "0" ]]; then
                    _rt_sev="live_compromise"
                else
                    _rt_sev="strong"; _rt_id="ioc_runtime_known_bad_path_userland"
                    _rt_key="ioc_runtime_known_bad_path_userland_present"
                    _rt_note_suffix=" (owner UID=${_rt_owner}; user-account compromise, review tier)"
                fi
                ;;
            /tmp/codeItems3)
                _rt_label="PHP cron-bot stage-2 payload"
                _rt_owner=$(stat -c %u "$_rt_p" 2>/dev/null)
                if [[ "${_rt_owner:-0}" == "0" ]]; then
                    _rt_sev="live_compromise"
                else
                    _rt_sev="strong"; _rt_id="ioc_runtime_known_bad_path_userland"
                    _rt_key="ioc_runtime_known_bad_path_userland_present"
                    _rt_note_suffix=" (owner UID=${_rt_owner}; user-account compromise, review tier)"
                fi
                ;;
            */c3pool/xmrig)             _rt_label="c3pool xmrig install"; _rt_sev="strong" ;;
            */c3pool/config.json)       _rt_label="c3pool xmrig config"; _rt_sev="strong" ;;
            */moneroocean/xmrig)        _rt_label="moneroocean xmrig install"; _rt_sev="strong" ;;
            */moneroocean/config.json)  _rt_label="moneroocean xmrig config"; _rt_sev="strong" ;;
            *)                          _rt_label="runtime artifact"; _rt_sev="strong" ;;
        esac
        emit "destruction" "$_rt_id" "$_rt_sev" "$_rt_key" 10 \
             "path" "$_rt_p" "${META_KV[@]}" \
             "note" "$_rt_label at $_rt_p — runtime payload artifact${_rt_note_suffix}."
        ((hits++))
    done

    local _rt_g _rt_hit
    for _rt_g in "${RUNTIME_KEYFILE_GLOBS[@]}"; do
        for _rt_hit in $_rt_g; do
            [[ -f "$_rt_hit" ]] || continue
            known_bad_meta "$_rt_hit"
            emit "destruction" "ioc_runtime_gsocket_keyfile" "strong" \
                 "ioc_runtime_gsocket_keyfile_present" 10 \
                 "path" "$_rt_hit" "${META_KV[@]}" \
                 "note" "GSocket relay-key file at $_rt_hit — interactive backdoor persistence (CRITICAL)."
            ((hits++))
        done
    done

    # /tmp dotfile webshells; cap 5.
    local _rt_drop _rt_drop_count=0
    while IFS= read -r _rt_drop; do
        [[ -z "$_rt_drop" ]] && continue
        case "$_rt_drop" in
            /tmp/.temp_mount_*|/tmp/.imunify360-*|/tmp/.s.PGSQL.*) continue ;;
        esac
        known_bad_meta "$_rt_drop"
        emit "destruction" "ioc_runtime_tmp_hex_blob" "warning" \
             "ioc_runtime_tmp_hex_blob_present" 4 \
             "path" "$_rt_drop" "${META_KV[@]}" \
             "note" "/tmp dotfile with hex32+ name at $_rt_drop — likely PHP webshell drop, manual review."
        ((hits++))
        _rt_drop_count=$((_rt_drop_count + 1))
        (( _rt_drop_count >= 5 )) && break
    done < <(find /tmp -maxdepth 1 -type f -name '.*' 2>/dev/null \
             | grep -E "$RUNTIME_TMP_HEX_RE" 2>/dev/null)

    local _rt_ps_cap; _rt_ps_cap=$(mktemp /tmp/ssioc.psrun.XXXXXX 2>/dev/null)
    if [[ -n "$_rt_ps_cap" ]] && timeout 60 ps auxfww > "$_rt_ps_cap" 2>/dev/null; then
        local _rt_line _rt_user

        _rt_line=$(grep -E "$RUNTIME_MASQ_RESPAWN_RE" "$_rt_ps_cap" 2>/dev/null | head -1)
        if [[ -n "$_rt_line" ]]; then
            # HOST-comp requires BOTH pkill target=root AND real-root context.
            _rt_runtime_context "$_rt_line"
            local _u0_target=0
            [[ "$_rt_line" =~ pkill[[:space:]]+-0[[:space:]]+-U0[[:space:]] ]] && _u0_target=1
            if (( _u0_target )) && [[ "$_RT_CTX_OWNER" == "root" ]]; then
                emit "destruction" "ioc_runtime_gsocket_respawn" "live_compromise" \
                     "ioc_runtime_gsocket_persistence_shim" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "ps_user" "$_RT_CTX_USER" "pid" "$_RT_CTX_PID" \
                     "affected_user" "_root" "actor_privilege" "root" \
                     "note" "GSocket pkill-respawn shim active under real root (USER=${_RT_CTX_USER}, not jailed) — operator persistence (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_gsocket_respawn_userland" "strong" \
                     "ioc_runtime_gsocket_persistence_shim_userland" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "ps_user" "$_RT_CTX_USER" "pid" "$_RT_CTX_PID" \
                     "jailed" "$_RT_CTX_JAILED" "u0_target" "$_u0_target" \
                     "affected_user" "$_RT_CTX_OWNER" "actor_privilege" "user" \
                     "note" "GSocket pkill-respawn shim under user-context (USER=${_RT_CTX_USER}, jailed=${_RT_CTX_JAILED}, u0_target=${_u0_target}) — user-account compromise; review tier."
            fi
            ((hits++))
        fi

        _rt_line=$(grep -E "$RUNTIME_LDLINUX_MASQ_RE" "$_rt_ps_cap" 2>/dev/null | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_xmrig_ldlinux" "live_compromise" \
                     "ioc_runtime_xmrig_masquerade" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "xmrig camouflaged as ./.ld-linux.so under root — active miner (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_xmrig_ldlinux_userland" "strong" \
                     "ioc_runtime_xmrig_masquerade_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "xmrig camouflaged as ./.ld-linux.so under user '$_rt_user' — user-account miner; review tier."
            fi
            ((hits++))
        fi

        _rt_line=$(grep -E "$RUNTIME_HTTPS_MASQ_RE" "$_rt_ps_cap" 2>/dev/null | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_xmrig_https" "live_compromise" \
                     "ioc_runtime_xmrig_masquerade" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "xmrig renamed to ./https under root with pool/randomx args — active miner (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_xmrig_https_userland" "strong" \
                     "ioc_runtime_xmrig_masquerade_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "xmrig renamed to ./https under user '$_rt_user' — user-account miner; review tier."
            fi
            ((hits++))
        fi

        _rt_line=$(grep -E "$RUNTIME_PYTHON_MASQ_RE" "$_rt_ps_cap" 2>/dev/null \
                  | grep -E "$RUNTIME_PYTHON_MASQ_ARGS_RE" | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_xmrig_python" "live_compromise" \
                     "ioc_runtime_xmrig_masquerade" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "xmrig renamed to ./python[0-9] under root with pool/donate-level args — active miner (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_xmrig_python_userland" "strong" \
                     "ioc_runtime_xmrig_masquerade_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "xmrig renamed to ./python[0-9] under user '$_rt_user' — user-account miner; review tier."
            fi
            ((hits++))
        fi

        # Two-stage gate: path AND pool/config args.
        _rt_line=$(grep -E '[ /]xmrig( |$)' "$_rt_ps_cap" 2>/dev/null \
                  | grep -E '(--config=|-o[[:space:]]+(stratum\+)?[a-z]+://|--url=.*pool\.|c3pool|moneroocean|supportxmr|nanopool|hashvault)' \
                  | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_xmrig_visible" "live_compromise" \
                     "ioc_runtime_xmrig_visible_active" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "xmrig running under root with pool/config args — active cryptominer (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_xmrig_visible_userland" "strong" \
                     "ioc_runtime_xmrig_visible_active_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "xmrig running under user '$_rt_user' with pool/config args — user-account miner; review tier."
            fi
            ((hits++))
        fi

        _rt_line=$(grep -E "$RUNTIME_LOADER_PIPE_RE" "$_rt_ps_cap" 2>/dev/null | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_loader_in_flight" "live_compromise" \
                     "ioc_runtime_known_loader_in_flight" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "Known cryptominer/PHP-loader install pipe in flight under root — operator deploying payload (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_loader_in_flight_userland" "strong" \
                     "ioc_runtime_known_loader_in_flight_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "Known loader pipe in flight under user '$_rt_user' — user-account compromise; review tier."
            fi
            ((hits++))
        fi

        local _rt_w
        for _rt_w in "${RUNTIME_WALLET_PREFIXES[@]}"; do
            _rt_line=$(grep -F "$_rt_w" "$_rt_ps_cap" 2>/dev/null | head -1)
            if [[ -n "$_rt_line" ]]; then
                _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
                if [[ "$_rt_user" == "root" ]]; then
                    emit "destruction" "ioc_runtime_wallet" "live_compromise" \
                         "ioc_runtime_wallet_in_cmdline" 10 \
                         "wallet_prefix" "$_rt_w" "sample" "${_rt_line:0:200}" \
                         "note" "XMR wallet prefix $_rt_w in root cmdline — operator-attributed miner (CRITICAL)."
                else
                    emit "destruction" "ioc_runtime_wallet_userland" "strong" \
                         "ioc_runtime_wallet_in_cmdline_userland" 10 \
                         "wallet_prefix" "$_rt_w" "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                         "note" "XMR wallet prefix $_rt_w in user '$_rt_user' cmdline — user-account miner; review tier."
                fi
                ((hits++))
            fi
        done

        local _rt_ip _rt_ip_re
        for _rt_ip in "${RUNTIME_C2_IPS[@]}"; do
            # Octet-precise (grep -F substring-matches 45.140.17.40 in 145.140.17.401).
            _rt_ip_re="(^|[^0-9])${_rt_ip//./\\.}($|[^0-9])"
            _rt_line=$(grep -E "$_rt_ip_re" "$_rt_ps_cap" 2>/dev/null | head -1)
            if [[ -n "$_rt_line" ]]; then
                _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
                if [[ "$_rt_user" == "root" ]]; then
                    emit "destruction" "ioc_runtime_c2_in_cmdline" "live_compromise" \
                         "ioc_runtime_c2_callback" 10 \
                         "c2_ip" "$_rt_ip" "sample" "${_rt_line:0:200}" \
                         "note" "Known C2 IP $_rt_ip in root cmdline — active loader/beacon (CRITICAL)."
                else
                    emit "destruction" "ioc_runtime_c2_in_cmdline_userland" "strong" \
                         "ioc_runtime_c2_callback_userland" 10 \
                         "c2_ip" "$_rt_ip" "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                         "note" "Known C2 IP $_rt_ip in user '$_rt_user' cmdline — user-account compromise; review tier."
                fi
                ((hits++))
            fi
        done

        local _rt_h
        for _rt_h in "${RUNTIME_C2_HOSTS[@]}"; do
            _rt_line=$(grep -F "$_rt_h" "$_rt_ps_cap" 2>/dev/null | head -1)
            if [[ -n "$_rt_line" ]]; then
                _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
                if [[ "$_rt_user" == "root" ]]; then
                    emit "destruction" "ioc_runtime_c2_host_in_cmdline" "live_compromise" \
                         "ioc_runtime_c2_callback" 10 \
                         "c2_host" "$_rt_h" "sample" "${_rt_line:0:200}" \
                         "note" "Known C2 host $_rt_h in root cmdline — active loader/beacon (CRITICAL)."
                else
                    emit "destruction" "ioc_runtime_c2_host_in_cmdline_userland" "strong" \
                         "ioc_runtime_c2_callback_userland" 10 \
                         "c2_host" "$_rt_h" "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                         "note" "Known C2 host $_rt_h in user '$_rt_user' cmdline — user-account compromise; review tier."
                fi
                ((hits++))
            fi
        done

        local _rt_re
        for _rt_re in "${RUNTIME_REVERSE_SHELL_RES[@]}"; do
            _rt_line=$(grep -E "$_rt_re" "$_rt_ps_cap" 2>/dev/null | head -1)
            if [[ -n "$_rt_line" ]]; then
                _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
                if [[ "$_rt_user" == "root" ]]; then
                    emit "destruction" "ioc_runtime_reverse_shell" "live_compromise" \
                         "ioc_runtime_reverse_shell_active" 10 \
                         "sample" "${_rt_line:0:200}" \
                         "note" "Reverse-shell process active under root — operator listener (CRITICAL)."
                else
                    emit "destruction" "ioc_runtime_reverse_shell_userland" "strong" \
                         "ioc_runtime_reverse_shell_active_userland" 10 \
                         "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                         "note" "Reverse-shell process active under user '$_rt_user' — user-account compromise; review tier."
                fi
                ((hits++))
            fi
        done

        # LPE binaries: stay live_compromise even under non-root user. Whole point
        # of LPE PoCs is kernel/setuid exploitation to root in seconds — threat
        # horizon is imminent privilege escalation, not steady-state account malware.
        local _rt_lpe
        for _rt_lpe in "${RUNTIME_LPE_BINARIES[@]}"; do
            _rt_line=$(awk -v b="$_rt_lpe" '{
                for (i=11; i<=NF && $i == "\\_"; i++) {}
                if ($i == b) { print; exit }
            }' "$_rt_ps_cap" 2>/dev/null)
            if [[ -n "$_rt_line" ]]; then
                emit "destruction" "ioc_runtime_lpe_binary" "live_compromise" \
                     "ioc_runtime_lpe_binary_running" 10 \
                     "binary" "$_rt_lpe" "sample" "${_rt_line:0:200}" \
                     "note" "Cwd-relative LPE PoC binary $_rt_lpe in process tree — privilege-escalation tool staged (CRITICAL)."
                ((hits++))
            fi
        done

        _rt_line=$(grep -E "$RUNTIME_XMR_WALLET_RE" "$_rt_ps_cap" 2>/dev/null | head -1)
        if [[ -n "$_rt_line" ]]; then
            _rt_user=$(printf '%s' "$_rt_line" | awk '{print $1}')
            if [[ "$_rt_user" == "root" ]]; then
                emit "destruction" "ioc_runtime_xmr_wallet_generic" "live_compromise" \
                     "ioc_runtime_xmr_wallet_in_cmdline" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "note" "95-char Monero wallet on root cmdline — active miner (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_xmr_wallet_generic_userland" "strong" \
                     "ioc_runtime_xmr_wallet_in_cmdline_userland" 10 \
                     "user" "$_rt_user" "sample" "${_rt_line:0:200}" \
                     "note" "95-char Monero wallet on user '$_rt_user' cmdline — user-account miner; review tier."
            fi
            ((hits++))
        fi

        # b64 shim: target UID hidden in base64, but ps USER + cgroup still gate.
        if grep -qF "$RUNTIME_GS_B64_PREFIX" "$_rt_ps_cap" 2>/dev/null; then
            _rt_line=$(grep -F "$RUNTIME_GS_B64_PREFIX" "$_rt_ps_cap" 2>/dev/null | head -1)
            _rt_runtime_context "$_rt_line"
            if [[ "$_RT_CTX_OWNER" == "root" ]]; then
                emit "destruction" "ioc_runtime_gsocket_b64_shim" "live_compromise" \
                     "ioc_runtime_gsocket_persistence_shim" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "ps_user" "$_RT_CTX_USER" "pid" "$_RT_CTX_PID" \
                     "affected_user" "_root" "actor_privilege" "root" \
                     "note" "GSocket pkill-respawn shim base64-wrapped under real root (USER=${_RT_CTX_USER}, not jailed) — operator persistence (CRITICAL)."
            else
                emit "destruction" "ioc_runtime_gsocket_b64_shim_userland" "strong" \
                     "ioc_runtime_gsocket_persistence_shim_userland" 10 \
                     "sample" "${_rt_line:0:200}" \
                     "ps_user" "$_RT_CTX_USER" "pid" "$_RT_CTX_PID" \
                     "jailed" "$_RT_CTX_JAILED" \
                     "affected_user" "$_RT_CTX_OWNER" "actor_privilege" "user" \
                     "note" "GSocket pkill-respawn shim base64-wrapped under user-context (USER=${_RT_CTX_USER}, jailed=${_RT_CTX_JAILED}) — user-account compromise; review tier."
            fi
            ((hits++))
        fi
    fi
    rm -f "$_rt_ps_cap" 2>/dev/null

    local _rt_conn_cap=""
    if have_cmd ss; then
        _rt_conn_cap=$(mktemp /tmp/ssioc.connrun.XXXXXX 2>/dev/null)
        [[ -n "$_rt_conn_cap" ]] && timeout 60 ss -tnp > "$_rt_conn_cap" 2>/dev/null || true
    fi
    if [[ -n "$_rt_conn_cap" && -s "$_rt_conn_cap" ]]; then
        local _rt_ip _rt_line _rt_pid _rt_uid
        for _rt_ip in "${RUNTIME_C2_IPS[@]}"; do
            _rt_line=$(grep -E "ESTAB.*[[:space:]]${_rt_ip//./\\.}:" "$_rt_conn_cap" 2>/dev/null | head -1)
            if [[ -n "$_rt_line" ]]; then
                # Resolve socket-owning pid → /proc/<pid>/status Uid (effective UID, field 2).
                # Default to root on lookup failure (process gone) — connection itself is real evidence.
                _rt_pid=$(printf '%s' "$_rt_line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
                _rt_uid=""
                [[ -n "$_rt_pid" && -r "/proc/$_rt_pid/status" ]] && \
                    _rt_uid=$(awk '/^Uid:/{print $2; exit}' "/proc/$_rt_pid/status" 2>/dev/null)
                if [[ -z "$_rt_uid" || "$_rt_uid" == "0" ]]; then
                    emit "destruction" "ioc_runtime_c2_estab" "live_compromise" \
                         "ioc_runtime_c2_callback_active" 10 \
                         "c2_ip" "$_rt_ip" "pid" "${_rt_pid:-unknown}" "sample" "${_rt_line:0:200}" \
                         "note" "Active TCP ESTAB to known C2 IP $_rt_ip (root or unknown UID) — backdoor live and connected (CRITICAL)."
                else
                    emit "destruction" "ioc_runtime_c2_estab_userland" "strong" \
                         "ioc_runtime_c2_callback_active_userland" 10 \
                         "c2_ip" "$_rt_ip" "pid" "$_rt_pid" "uid" "$_rt_uid" "sample" "${_rt_line:0:200}" \
                         "note" "Active TCP ESTAB to known C2 IP $_rt_ip (UID=$_rt_uid) — user-account compromise; review tier."
                fi
                ((hits++))
            fi
        done
    fi
    rm -f "$_rt_conn_cap" 2>/dev/null

    # External-containment ingestion. Hits feed the all-clear gate so a
    # host with no live IOCs but populated containment doesn't falsely
    # emit `no_destruction_iocs`.
    check_quarantined_artifacts
    hits=$((hits + QUARANTINED_ARTIFACTS_HITS))

    if (( hits == 0 )); then
        emit "destruction" "destruction_scan" "info" "no_destruction_iocs" 0 \
             "note" "no destruction-stage residue (Patterns A-L + runtime) found"
    fi
}

# ---- CSF firewall posture ------------------------------------------------
# Validates CSF installed AND enforcing. Findings emit `posture_*` (not
# `ioc_*`) so they surface without escalating host_verdict. --root skips
# live probes.
check_csf_posture() {
    if [[ -n "$ROOT_OVERRIDE" ]]; then
        hdr_section "posture" "CSF posture (skipped: snapshot mode)"
        emit "posture" "csf_snapshot_skip" "info" "posture_csf_snapshot_skip" 0 \
             "note" "Snapshot/--root mode: CSF posture probes live iptables/lfd state and is skipped on offline trees."
        return
    fi

    hdr_section "posture" "CSF firewall posture (chains, lfd, testing flag)"

    # ---- 1. presence ------------------------------------------------------
    local csf_bin="" csf_conf="/etc/csf/csf.conf"
    if [[ -x /usr/sbin/csf ]]; then
        csf_bin=/usr/sbin/csf
    elif [[ -x /etc/csf/csf.pl ]]; then
        csf_bin=/etc/csf/csf.pl
    fi

    if [[ -z "$csf_bin" && ! -f "$csf_conf" ]]; then
        emit "posture" "csf_not_installed" "advisory" "posture_csf_not_installed" 0 \
             "note" "CSF/lfd not installed (no /usr/sbin/csf, no /etc/csf/csf.conf). cPanel/WHM fleet hosts are expected to run ConfigServer Firewall."
        return
    fi

    # ---- 2. administratively disabled ------------------------------------
    if [[ -f /etc/csf/csf.disable ]]; then
        local _dis_mtime=0
        _dis_mtime=$(stat -c %Y /etc/csf/csf.disable 2>/dev/null)
        emit "posture" "csf_disabled" "advisory" "posture_csf_administratively_disabled" 0 \
             "path" "/etc/csf/csf.disable" \
             "mtime_epoch" "${_dis_mtime:-0}" \
             "note" "/etc/csf/csf.disable present - CSF is administratively disabled. lfd will not start, chains stay flushed. Remove the file and 'csf -r' to re-enable."
        return
    fi

    # ---- 3. csf.conf missing while binary present -----------------------
    if [[ -n "$csf_bin" && ! -f "$csf_conf" ]]; then
        emit "posture" "csf_conf_missing" "warning" "posture_csf_conf_missing" 4 \
             "path" "$csf_conf" \
             "note" "CSF binary at $csf_bin but $csf_conf is missing - broken install; reinstall the csf rpm/tarball."
        # Continue — chains/lfd may still be probable.
    fi

    # ---- 4. TESTING flag --------------------------------------------------
    local testing=0 testing_interval=""
    if [[ -r "$csf_conf" ]]; then
        if grep -Eq '^[[:space:]]*TESTING[[:space:]]*=[[:space:]]*"1"' \
            "$csf_conf" 2>/dev/null; then
            testing=1
        fi
        testing_interval=$(grep -E '^[[:space:]]*TESTING_INTERVAL[[:space:]]*=' \
            "$csf_conf" 2>/dev/null | head -1 \
            | sed -n 's/.*"\([0-9]\{1,\}\)".*/\1/p')
    fi
    if (( testing )); then
        emit "posture" "csf_testing_mode" "warning" "posture_csf_testing_mode" 4 \
             "path" "$csf_conf" \
             "testing_interval_min" "${testing_interval:-5}" \
             "note" "TESTING=\"1\" in csf.conf - lfd cron auto-flushes iptables every ${testing_interval:-5} min. Production posture requires TESTING=\"0\" + 'csf -r'."
    fi

    # ---- 5. lfd daemon liveness -----------------------------------------
    # Robust 3-stage probe: pidfile + /proc/<pid>/comm verification, then
    # pidof, then pgrep. The /proc check defends against stale-pid reuse
    # (a different process inheriting the lfd PID after lfd crashed).
    local lfd_pid=0 lfd_alive=0 _lfd_comm=""
    local lfd_pidfile="/var/run/lfd.pid"
    if [[ -r "$lfd_pidfile" ]]; then
        lfd_pid=$(head -1 "$lfd_pidfile" 2>/dev/null | tr -dc '0-9')
        lfd_pid="${lfd_pid:-0}"
    fi
    if (( lfd_pid > 0 )) && [[ -d "/proc/${lfd_pid}" ]]; then
        if [[ -r "/proc/${lfd_pid}/comm" ]]; then
            _lfd_comm=$(head -1 "/proc/${lfd_pid}/comm" 2>/dev/null)
        fi
        # lfd's `comm` is "lfd" on EL7+, "perl" on EL6 (lfd.pl exec'd via
        # perl interpreter). Accept both.
        if [[ "$_lfd_comm" == lfd* ]] || [[ "$_lfd_comm" == perl* ]]; then
            lfd_alive=1
        fi
    fi
    if (( ! lfd_alive )) && command -v pidof >/dev/null 2>&1; then
        local _p
        _p=$(pidof lfd 2>/dev/null | awk '{print $1}')
        if [[ -n "$_p" && -d "/proc/${_p}" ]]; then
            lfd_pid="$_p"; lfd_alive=1
        fi
    fi
    if (( ! lfd_alive )) && command -v pgrep >/dev/null 2>&1; then
        local _p
        _p=$(pgrep -f 'lfd \(' 2>/dev/null | head -1)
        [[ -z "$_p" ]] && _p=$(pgrep -f '/etc/csf/lfd\.pl|/usr/sbin/lfd' 2>/dev/null | head -1)
        if [[ -n "$_p" && -d "/proc/${_p}" ]]; then
            lfd_pid="$_p"; lfd_alive=1
        fi
    fi

    if (( ! lfd_alive )); then
        local _stale=0
        [[ -f "$lfd_pidfile" ]] && _stale=1
        emit "posture" "csf_lfd_dead" "warning" "posture_csf_lfd_not_running" 4 \
             "lfd_pidfile_present" "$_stale" \
             "lfd_pid_recorded" "$lfd_pid" \
             "note" "lfd daemon not running. Login-failure scanning + dynamic blocks inactive. Start with 'service lfd start' (CL6) or 'systemctl start lfd' (EL7+)."
    fi

    # ---- 6. iptables availability ---------------------------------------
    local ipt_bin=""
    if command -v iptables >/dev/null 2>&1; then
        ipt_bin="iptables"
    elif [[ -x /sbin/iptables ]]; then
        ipt_bin="/sbin/iptables"
    elif [[ -x /usr/sbin/iptables ]]; then
        ipt_bin="/usr/sbin/iptables"
    fi
    if [[ -z "$ipt_bin" ]]; then
        emit "posture" "csf_iptables_missing" "warning" "posture_csf_iptables_missing" 4 \
             "note" "iptables binary not found in PATH or /sbin or /usr/sbin. CSF cannot enforce rules without iptables."
        return
    fi

    # ---- 7. csf -v self-test --------------------------------------------
    local csf_version=""
    if [[ -n "$csf_bin" ]]; then
        local _v_out _v_rc=0
        _v_out=$("$csf_bin" -v 2>&1) || _v_rc=$?
        if (( _v_rc != 0 )); then
            emit "posture" "csf_binary_broken" "warning" "posture_csf_binary_self_test_fail" 4 \
                 "rc" "$_v_rc" \
                 "sample" "$(printf '%s' "$_v_out" | head -1 | tr -d '\n' | cut -c1-160)" \
                 "note" "'$csf_bin -v' returned rc=$_v_rc - csf binary cannot self-report version. Likely Perl module gap or corrupt install."
        else
            # Extract the "vNN.NN" token for the healthy roll-up note.
            csf_version=$(printf '%s' "$_v_out" | head -1 \
                | sed -n 's/.*\bv\([0-9][0-9.]*\).*/\1/p')
        fi
    fi

    # ---- 8. chain enumeration -------------------------------------------
    # iptables -n (no DNS) is critical: -L without -n hangs 30+s on hosts
    # whose nameservers are firewalled by the very rules we're inspecting.
    local ipt_nl="" ipt_nl_rc=0
    ipt_nl=$("$ipt_bin" -n -L 2>/dev/null) || ipt_nl_rc=$?
    if (( ipt_nl_rc != 0 )) || [[ -z "$ipt_nl" ]]; then
        emit "posture" "csf_iptables_unreadable" "warning" "posture_csf_iptables_list_failed" 4 \
             "rc" "$ipt_nl_rc" \
             "note" "'$ipt_bin -n -L' returned rc=$ipt_nl_rc / empty - cannot enumerate chains. Run as root; check kernel iptables modules."
        return
    fi

    local has_localin=0 has_localout=0 has_logdropin=0 has_invdrop=0
    grep -q '^Chain LOCALINPUT' <<<"$ipt_nl"  && has_localin=1
    grep -q '^Chain LOCALOUTPUT' <<<"$ipt_nl" && has_localout=1
    grep -q '^Chain LOGDROPIN' <<<"$ipt_nl"   && has_logdropin=1
    grep -q '^Chain INVDROP' <<<"$ipt_nl"     && has_invdrop=1

    # INPUT default policy. iptables -n -L emits a single "Chain INPUT
    # (policy DROP|ACCEPT)" header line; sed -n '1p' on the matched lines
    # is enough.
    local input_policy=""
    input_policy=$(printf '%s\n' "$ipt_nl" \
        | sed -n 's/^Chain INPUT (policy \([A-Z]\{1,\}\).*/\1/p' | head -1)
    [[ -z "$input_policy" ]] && input_policy="UNKNOWN"

    # ---- 9. INPUT -> LOCALINPUT jump ------------------------------------
    local input_jumps_to_csf=0
    if (( has_localin )); then
        if "$ipt_bin" -S INPUT 2>/dev/null \
            | grep -qE '^-A INPUT( |[[:space:]].* )-j LOCALINPUT( |$)'; then
            input_jumps_to_csf=1
        fi
    fi

    # ---- 10. LOCALINPUT rule count --------------------------------------
    local localin_rule_count=0
    if (( has_localin )); then
        localin_rule_count=$("$ipt_bin" -S LOCALINPUT 2>/dev/null \
            | grep -c '^-A LOCALINPUT ')
        localin_rule_count="${localin_rule_count:-0}"
    fi

    # Aggregate chain-state finding (one emit per break-mode, in priority
    # order — chains absent dominates orphaned, which dominates empty).
    if (( ! has_localin && ! has_localout && ! has_logdropin )); then
        # CSF chains entirely absent. If INPUT policy is also ACCEPT the
        # firewall is effectively off — bump severity to evidence.
        local _sev="warning" _wt=4 _key="posture_csf_chains_absent"
        if [[ "$input_policy" == "ACCEPT" ]]; then
            _sev="evidence"; _wt=6; _key="posture_csf_firewall_open"
        fi
        emit "posture" "csf_chains_absent" "$_sev" "$_key" "$_wt" \
             "input_policy" "$input_policy" \
             "has_localinput" "$has_localin" \
             "has_logdropin" "$has_logdropin" \
             "note" "CSF terminal chains (LOCALINPUT/LOCALOUTPUT/LOGDROPIN) not loaded; INPUT policy=${input_policy}. CSF installed but rules are not hydrated - run 'csf -r'."
    elif (( has_localin && ! input_jumps_to_csf )); then
        emit "posture" "csf_chains_orphaned" "warning" "posture_csf_chains_orphaned" 4 \
             "input_policy" "$input_policy" \
             "localin_rules" "$localin_rule_count" \
             "note" "LOCALINPUT chain exists with $localin_rule_count rules but INPUT does not jump to it - chain orphaned, no traffic enforced. Likely partial iptables flush; run 'csf -r'."
    elif (( has_localin && localin_rule_count == 0 )); then
        emit "posture" "csf_chains_empty" "warning" "posture_csf_chains_empty" 4 \
             "input_policy" "$input_policy" \
             "note" "LOCALINPUT chain exists and INPUT jumps to it, but the chain is empty - no allow/deny rules. Likely interrupted 'csf -r' or kill -9 mid-load."
    fi

    # ---- 11. LF_IPSET drift ---------------------------------------------
    local lf_ipset=0 ipset_set_count=0
    if [[ -r "$csf_conf" ]] \
       && grep -Eq '^[[:space:]]*LF_IPSET[[:space:]]*=[[:space:]]*"1"' \
            "$csf_conf" 2>/dev/null; then
        lf_ipset=1
    fi
    if (( lf_ipset )); then
        if ! command -v ipset >/dev/null 2>&1; then
            emit "posture" "csf_ipset_missing" "warning" "posture_csf_ipset_binary_missing" 4 \
                 "note" "csf.conf has LF_IPSET=\"1\" but the 'ipset' binary is not installed - CSF can't materialize set-based blocklists. Install 'ipset' rpm and 'csf -r'."
        else
            ipset_set_count=$(ipset -L -n 2>/dev/null | grep -c '^[A-Za-z0-9_]')
            ipset_set_count="${ipset_set_count:-0}"
            if (( ipset_set_count == 0 )); then
                emit "posture" "csf_ipset_empty" "warning" "posture_csf_ipset_no_sets" 4 \
                     "note" "LF_IPSET=\"1\" and ipset binary present, but no sets are loaded. Run 'csf -r' to rehydrate."
            fi
        fi
    fi

    # ---- 12. healthy roll-up --------------------------------------------
    # All hard-fail probes passed: emit an info-tier signal so fleet
    # aggregators can confirm green-status per host. This row is suppressed
    # in print_signal_human's no-detail clean-info bucket via key match.
    if (( has_localin && has_localout && has_logdropin \
          && input_jumps_to_csf && lfd_alive && ! testing \
          && localin_rule_count > 0 )); then
        emit "posture" "csf_active" "info" "posture_csf_active" 0 \
             "input_policy" "$input_policy" \
             "localin_rules" "$localin_rule_count" \
             "has_invdrop" "$has_invdrop" \
             "lfd_pid" "$lfd_pid" \
             "csf_version" "${csf_version:-unknown}" \
             "lf_ipset" "$lf_ipset" \
             "ipset_sets" "$ipset_set_count" \
             "note" "CSF active: LOCALINPUT/LOCALOUTPUT/LOGDROPIN loaded, INPUT->LOCALINPUT jump present (${localin_rule_count} rules), lfd pid=${lfd_pid}, csf=${csf_version:-?}, INPUT policy=${input_policy}."
    fi
}

# ---- localhost marker probe ----------------------------------------------
check_localhost_probe() {
    (( PROBE )) || return
    hdr_section "probe" "localhost marker probe"
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
    local compromise_critical=0 compromise_critical_quarantine=0 compromise_critical_live=0
    local version_says_vuln=0 version_says_patched=0
    local row area id sev key weight kv
    # Per-axis counters mirror the global counters but split by attribution.
    # Computed inline so we don't re-walk SIGNALS[] in aggregate_per_user_verdict.
    local root_compromise_critical=0 root_ioc_critical=0 root_ioc_review=0
    local root_compromise_critical_live=0
    local user_compromise_critical=0 user_ioc_critical=0 user_ioc_review=0
    # Top-level globals (see declarations near SIGNALS=()); reset contents
    # rather than redeclare to stay on the bash 4.1.2 (EL6) floor.
    USER_SEVERITY=()
    USER_PATTERNS=()
    USER_KEYS=()
    USER_PRIV_MAX=()
    USER_FIRST_EPOCH=()
    USER_LAST_EPOCH=()
    USER_COUNT=()
    # Persistence cluster tracking. Dedupes by pattern letter (G/J/I/F/D/H);
    # multiplier rewards distinct patterns, not key count.
    local -A PERSIST_PATTERNS=()
    local -A PERSIST_PATTERNS_LIVE_ROOT=()
    local persist_weight_sum=0
    # P1b/P1c/P5 aggregators.
    local -A PATTERN_A_SUBTYPES=()
    local -A COMPROMISE_LETTERS=()
    local attempt_evidence_count=0
    # P3 pre-pass: any strong-tier on-disk compromise letter (A/B/C/D/F/G/H/I/J/K/L,
    # excluding E + soft variants) gates Pattern E websocket re-credit.
    local pre_compromise_present=0
    if (( ${#SIGNALS[@]} > 0 )); then
        local _row _area _id _sev _key _wt _kv
        for _row in "${SIGNALS[@]}"; do
            IFS=$'\t' read -r _area _id _sev _key _wt _kv <<< "$_row"
            [[ "$_sev" == "strong" ]] || continue
            ioc_key_is_soft_variant "$_key" && continue
            if [[ "$_id" =~ ^ioc_pattern_([abcdfghijklm])_ ]]; then
                pre_compromise_present=1
                break
            fi
        done
    fi
    # Per-session score dedup. Live and quarantined emits credit ONE base
    # contribution per session_id; reason count drives the confidence tier.
    local -A SESSION_REASONS=()
    # Reset (don't redeclare) - the arrays are top-level globals; using
    # `declare -ga` here would require bash 4.2. Reassigning to () clears
    # the array contents while preserving the global binding.
    REASONS=()
    IOC_KEYS=()
    ADVISORIES=()
    # Reset per-area verdict tracking. Worst-wins ladder:
    #   [IOC] > [VULN] > [WARN] > [ADVISORY] > [OK] > [..] (skipped/empty)
    SECTION_VERDICT=()
    SECTION_COUNTS=()
    SECTION_KEYS=()
    # Length-check guard: SIGNALS may be empty (e.g. snapshot mode skipping
    # the destruction scan with no upstream IOC emits). Bash 4.1 (CL6) trips
    # `set -u` on ${arr[@]} of an empty declared array.
    if (( ${#SIGNALS[@]} > 0 )); then
        for row in "${SIGNALS[@]}"; do
            IFS=$'\t' read -r area id sev key weight kv <<< "$row"
            weight="${weight:-0}"
            # Per-axis attribution captured up-front so the rest of the loop
            # can branch on it without re-parsing kv.
            local _au _ap
            _au=$(_kv_get "$kv" affected_user)
            _ap=$(_kv_get "$kv" actor_privilege)
            [[ -z "$_au" ]] && _au="_root"
            [[ -z "$_ap" ]] && _ap="root"
            # P3 Pattern E pre-compromise re-credit when on-disk letter present.
            if [[ "$id" == "ioc_pattern_e_websocket" ]] && (( pre_compromise_present )) \
               && [[ "$weight" == "0" ]]; then
                sev="strong"; weight=10
            fi
            # P4 CRLF chain warning→evidence with capped per-chain bonus.
            local _crlf_bonus=0
            if [[ "$id" == "ioc_cve_2026_41940_access_primitive" ]] && [[ "$sev" == "warning" ]]; then
                local _cnt=0
                if [[ "$kv" == *'"count":"'* ]]; then
                    _cnt="${kv#*\"count\":\"}"; _cnt="${_cnt%%\"*}"
                fi
                [[ "$_cnt" =~ ^[0-9]+$ ]] || _cnt=0
                sev="evidence"
                if (( _cnt > 0 )); then
                    _crlf_bonus=$(( _cnt * 2 ))
                    (( _crlf_bonus > 20 )) && _crlf_bonus=20
                else
                    _crlf_bonus=2
                fi
            fi
            # P2 quarantine reasons-aware promotion.
            if [[ "$id" == ioc_quarantined_session_* ]] && [[ "$sev" == "warning" ]] \
               && [[ "$kv" == *'"reasons_ioc":"'* ]]; then
                local _ri="${kv#*\"reasons_ioc\":\"}"; _ri="${_ri%%\"*}"
                if [[ "$_ri" =~ (cve_2026_41940_combo|hasroot_in_session|injected_token_used_with_2xx|token_denied_with_badpass_origin) ]] \
                   || [[ "$_ri" =~ (^|,)E2(,|$) ]]; then
                    sev="strong"; weight=10
                elif [[ "$_ri" =~ (^|,)(B|E|F|H)(,|$) ]]; then
                    sev="strong"; weight=5
                elif [[ "$_ri" =~ (^|,)(A|C|D|D2|I|2)(,|$) ]]; then
                    sev="evidence"; weight=0
                fi
            fi
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
            # Per-section worst-wins tag: [LIVE] > [IOC] > [VULN] > [WARN] > [ADVISORY] > [OK].
            local _tag=""
            case "$sev" in
                live_compromise)  _tag="[LIVE]" ;;
                strong)
                    if [[ "$key" == ioc_* ]]; then _tag="[IOC]"; else _tag="[VULN]"; fi ;;
                evidence|warning) _tag="[WARN]" ;;
                advisory)         _tag="[ADVISORY]" ;;
                info)
                    case "$key" in
                        patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs|no_destruction_iocs|request_complete|marker_logged|posture_csf_active)
                            _tag="[OK]" ;;
                    esac
                    ;;
            esac
            if [[ -n "$_tag" ]]; then
                local _cur="${SECTION_VERDICT[$area]:-}"
                if [[ -z "$_cur" ]] \
                   || [[ "$_cur" == "[OK]" ]] \
                   || [[ "$_cur" == "[ADVISORY]" && "$_tag" =~ ^\[(WARN|VULN|IOC|LIVE)\]$ ]] \
                   || [[ "$_cur" == "[WARN]" && "$_tag" =~ ^\[(VULN|IOC|LIVE)\]$ ]] \
                   || [[ "$_cur" == "[VULN]" && "$_tag" =~ ^\[(IOC|LIVE)\]$ ]] \
                   || [[ "$_cur" == "[IOC]" && "$_tag" == "[LIVE]" ]]; then
                    SECTION_VERDICT[$area]="$_tag"
                fi
            fi
            # Per-area roll-up counts (used in matrix detail column).
            case "$sev" in
                live_compromise) SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} live" ;;
                strong)   SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} ioc" ;;
                warning|evidence) SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} warn" ;;
                advisory) SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} advisory" ;;
                info)
                    case "$key" in
                        patched_per_build|ancillary_bug_fixed|patch_marker_present|acl_machinery_present_informational|no_ioc_hits|no_session_iocs|no_destruction_iocs|request_complete|marker_logged|posture_csf_active)
                            SECTION_COUNTS[$area]="${SECTION_COUNTS[$area]:-} ok" ;;
                    esac
                    ;;
            esac
            # Per-area unique key list (used by --verbose matrix expansion).
            # Append to a space-joined string; print_section_matrix dedupes via sort -u.
            if [[ "$sev" == "live_compromise" || "$sev" == "strong" || "$sev" == "warning" || "$sev" == "evidence" || "$sev" == "advisory" ]]; then
                SECTION_KEYS[$area]="${SECTION_KEYS[$area]:-} $key"
            fi
            # Persistence-class accumulation: strong/warning only
            # (info/advisory/evidence excluded). Dedup by pattern letter
            # so multiple keys per pattern fold to one cluster slot.
            case "$sev" in
                live_compromise|strong|warning)
                    local _pp
                    _pp=$(ioc_key_to_persist_pattern "$key")
                    if [[ -n "$_pp" ]]; then
                        PERSIST_PATTERNS["$_pp"]=1
                        if ! _is_quarantine_signal "$id" && ! _is_quarantine_signal "$key" \
                           && [[ "$_ap" == "root" ]]; then
                            PERSIST_PATTERNS_LIVE_ROOT["$_pp"]=1
                        fi
                        local _pw
                        case "$sev" in
                            live_compromise) _pw=$((weight > 0 ? weight : 10)) ;;
                            strong)  _pw=$((weight > 0 ? weight : 5)) ;;
                            warning) _pw=$((weight > 0 ? weight : 4)) ;;
                        esac
                        persist_weight_sum=$((persist_weight_sum + _pw))
                    fi
                    ;;
            esac
            case "$sev" in
                strong)
                    # P1 Pattern A evidence_destruction count escalator.
                    if [[ "$id" == "ioc_pattern_a_evidence_destruction" ]]; then
                        local _fe_cnt=0
                        if [[ "$kv" == *'"count":"'* ]]; then
                            _fe_cnt="${kv#*\"count\":\"}"; _fe_cnt="${_fe_cnt%%\"*}"
                        fi
                        [[ "$_fe_cnt" =~ ^[0-9]+$ ]] || _fe_cnt=0
                        if   (( _fe_cnt >= 10000 )); then weight=80
                        elif (( _fe_cnt >= 1000 ));  then weight=50
                        elif (( _fe_cnt >= 100 ));   then weight=30
                        elif (( _fe_cnt >= 10 ));    then weight=15
                        fi
                    fi
                    # P1b/P1c subtype + compromise-letter tracking.
                    if ! ioc_key_is_soft_variant "$key"; then
                        case "$id" in
                            ioc_pattern_a_sorry|ioc_pattern_a_readme|ioc_pattern_a_evidence_destruction|ioc_pattern_a_c2_live|ioc_pattern_a_encryptor)
                                PATTERN_A_SUBTYPES["${id#ioc_pattern_a_}"]=1
                                ;;
                        esac
                        if [[ "$id" =~ ^ioc_pattern_([abcdfghijklm])_ ]]; then
                            COMPROMISE_LETTERS["${BASH_REMATCH[1]}"]=1
                        fi
                    fi
                    # Per-session score dedup. First strong emit per session_id
                    # credits base score; subsequent emits bump reason count
                    # only. Quarantined emit's reasons_ioc kv (one-shot) sets
                    # the count from the .info sidecar's comma list.
                    local _sid="" _rcnt_pre=0
                    if [[ "$id" =~ ^ioc_(token_used|token_inject|preauth_extauth|short_pass|multiline_pass|badpass_authmarkers|cve41940|hasroot|malformed_line|forged_timestamp|quarantined_session)_(.+)$ ]]; then
                        _sid="${BASH_REMATCH[2]}"
                    fi
                    if [[ -n "$_sid" ]]; then
                        _rcnt_pre="${SESSION_REASONS[$_sid]:-0}"
                        if [[ "$id" == ioc_quarantined_session_* ]] && [[ "$kv" == *'"reasons_ioc":"'* ]]; then
                            local _ri="${kv#*\"reasons_ioc\":\"}"
                            _ri="${_ri%%\"*}"
                            local _ri_n=1 _c
                            for (( _c=0; _c<${#_ri}; _c++ )); do
                                [[ "${_ri:$_c:1}" == "," ]] && ((_ri_n++))
                            done
                            SESSION_REASONS["$_sid"]=$_ri_n
                        else
                            SESSION_REASONS["$_sid"]=$((_rcnt_pre + 1))
                        fi
                    fi
                    if [[ -z "$_sid" ]] || (( _rcnt_pre == 0 )); then
                        score=$((score + (weight > 0 ? weight : 5)))
                    fi
                    ((strong_count++))
                    REASONS+=("$key")
                    if [[ "$key" == ioc_* ]]; then
                        ((ioc_critical++))
                        IOC_KEYS+=("$key")
                        local _cc
                        _cc=$(ioc_compromise_class "$key")
                        if [[ -n "$_cc" ]]; then
                            ((compromise_critical++))
                            if _is_quarantine_signal "$id" || _is_quarantine_signal "$key"; then
                                ((compromise_critical_quarantine++))
                            else
                                ((compromise_critical_live++))
                            fi
                        fi
                    fi
                    ;;
                live_compromise)
                    # Single-hit COMPROMISED (bypasses v3 ladder).
                    score=$((score + (weight > 0 ? weight : 10)))
                    ((strong_count++))
                    REASONS+=("$key")
                    if [[ "$key" == ioc_* ]]; then
                        ((ioc_critical++))
                        IOC_KEYS+=("$key")
                        ((compromise_critical++))
                        if _is_quarantine_signal "$id" || _is_quarantine_signal "$key"; then
                            ((compromise_critical_quarantine++))
                        else
                            ((compromise_critical_live++))
                        fi
                    fi
                    ;;
                evidence)
                    # P5 attempt-class aggregator.
                    if [[ "$id" == ioc_token_attempt_* ]] || [[ "$id" == ioc_quarantined_session_* ]]; then
                        ((attempt_evidence_count++))
                    elif (( _crlf_bonus > 0 )); then
                        score=$((score + _crlf_bonus))
                    else
                        score=$((score + 2))
                    fi
                    REASONS+=("$key")
                    ;;
                warning)
                    ((inconclusive_count++))
                    if [[ "$key" == ioc_* ]]; then
                        ((ioc_review++))
                        IOC_KEYS+=("$key")
                        # Surface review-tier IOCs in the verdict reasons line
                        # so operators see e.g. "ioc_attacker_ip_in_access_log_probes_only"
                        # even when host_root_verdict/user_verdict resolves to SUSPICIOUS not COMPROMISED.
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

            # Per-axis + per-user bookkeeping. Counters mirror the global
            # ioc_critical / ioc_review / compromise_critical but split by
            # actor_privilege (root vs user). When affected_user != _root,
            # also accumulate into the per-user severity/pattern bucket.
            case "$sev" in
                strong|live_compromise)
                    if [[ "$key" == ioc_* ]]; then
                        if [[ "$_ap" == "user" ]]; then
                            ((user_ioc_critical++))
                        else
                            ((root_ioc_critical++))
                        fi
                        local _cc2
                        _cc2=$(ioc_compromise_class "$key")
                        if [[ -n "$_cc2" ]] || [[ "$sev" == "live_compromise" ]]; then
                            if [[ "$_ap" == "user" ]]; then
                                ((user_compromise_critical++))
                            else
                                ((root_compromise_critical++))
                                if ! _is_quarantine_signal "$id" && ! _is_quarantine_signal "$key"; then
                                    ((root_compromise_critical_live++))
                                fi
                            fi
                        fi
                    fi
                    ;;
                warning)
                    if [[ "$key" == ioc_* ]]; then
                        if [[ "$_ap" == "user" ]]; then
                            ((user_ioc_review++))
                        else
                            ((root_ioc_review++))
                        fi
                    fi
                    ;;
            esac

            if [[ "$_au" != "_root" ]] && _user_is_valid "$_au"; then
                local _u_sev_cur="${USER_SEVERITY[$_au]:-clean}"
                local _u_sev_new="$_u_sev_cur"
                case "$sev" in
                    live_compromise|strong)
                        [[ "$key" == ioc_* ]] && _u_sev_new="strong" ;;
                    warning|evidence)
                        [[ "$_u_sev_cur" != "strong" && "$key" == ioc_* ]] && _u_sev_new="warning" ;;
                esac
                if [[ "$_u_sev_new" != "$_u_sev_cur" ]]; then
                    USER_SEVERITY[$_au]="$_u_sev_new"
                fi
                if [[ "$key" == ioc_* ]] && [[ "$sev" == "strong" || "$sev" == "live_compromise" || "$sev" == "warning" ]]; then
                    USER_COUNT[$_au]=$(( ${USER_COUNT[$_au]:-0} + 1 ))
                    USER_KEYS[$_au]="${USER_KEYS[$_au]:-} $key"
                    if [[ "$id" =~ ^ioc_pattern_([abcdefghijklm])_ ]]; then
                        USER_PATTERNS[$_au]="${USER_PATTERNS[$_au]:-} ${BASH_REMATCH[1]^^}"
                    fi
                    local _cur_priv="${USER_PRIV_MAX[$_au]:-user}"
                    if [[ "$_ap" == "root" ]] || [[ "$_cur_priv" == "root" ]]; then
                        USER_PRIV_MAX[$_au]="root"
                    else
                        USER_PRIV_MAX[$_au]="user"
                    fi
                    local _ep
                    _ep=$(_kv_get "$kv" mtime_epoch)
                    [[ -z "$_ep" || ! "$_ep" =~ ^[0-9]+$ ]] && _ep=$(_kv_get "$kv" ts_epoch_first)
                    [[ -z "$_ep" || ! "$_ep" =~ ^[0-9]+$ ]] && _ep=""
                    if [[ -n "$_ep" ]]; then
                        local _fe="${USER_FIRST_EPOCH[$_au]:-}"
                        local _le="${USER_LAST_EPOCH[$_au]:-}"
                        [[ -z "$_fe" || "$_ep" -lt "$_fe" ]] && USER_FIRST_EPOCH[$_au]="$_ep"
                        [[ -z "$_le" || "$_ep" -gt "$_le" ]] && USER_LAST_EPOCH[$_au]="$_ep"
                    fi
                fi
            fi
        done
    fi

    # Per-session confidence tier: sessions with multi-reason co-occurrence
    # (canonical CVE-2026-41940 shape) score above single-trace sessions.
    # Bounded bonus tiers; same math for live (per-reason emit count) and
    # quarantined (reasons_ioc comma count).
    local _sid _rcnt _bonus
    local session_tiered_count=0 session_max_reasons=0
    if (( ${#SESSION_REASONS[@]} > 0 )); then
        for _sid in "${!SESSION_REASONS[@]}"; do
            _rcnt="${SESSION_REASONS[$_sid]}"
            ((session_tiered_count++))
            (( _rcnt > session_max_reasons )) && session_max_reasons=$_rcnt
            _bonus=0
            if   (( _rcnt >= 6 )); then _bonus=10
            elif (( _rcnt >= 4 )); then _bonus=5
            elif (( _rcnt >= 2 )); then _bonus=2
            fi
            score=$((score + _bonus))
        done
    fi

    # P1b Pattern A on-disk subtype cluster bonus.
    local _pa_subs=${#PATTERN_A_SUBTYPES[@]}
    if   (( _pa_subs >= 4 )); then score=$((score + 100))
    elif (( _pa_subs >= 3 )); then score=$((score + 50))
    elif (( _pa_subs >= 2 )); then score=$((score + 25))
    fi

    # P1c cross-pattern compromise-letter cluster bonus, excludes E.
    local _comp_letters=${#COMPROMISE_LETTERS[@]}
    if   (( _comp_letters >= 5 )); then score=$((score + 250))
    elif (( _comp_letters >= 4 )); then score=$((score + 150))
    elif (( _comp_letters >= 3 )); then score=$((score + 75))
    elif (( _comp_letters >= 2 )); then score=$((score + 30))
    fi

    # P5 attempt-class evidence cap +20.
    if (( attempt_evidence_count > 0 )); then
        local _att=$(( attempt_evidence_count * 2 ))
        (( _att > 20 )) && _att=20
        score=$((score + _att))
    fi

    # P6 persistence cluster multipliers.
    local persist_count=${#PERSIST_PATTERNS[@]}
    local persist_count_live_root=${#PERSIST_PATTERNS_LIVE_ROOT[@]}
    local persist_mult=1
    (( persist_count >= 2 )) && persist_mult=3
    (( persist_count >= 3 )) && persist_mult=5
    (( persist_count >= 4 )) && persist_mult=8
    if (( persist_count >= 1 )); then
        score=$((score + persist_weight_sum * (persist_mult - 1)))
    fi

    # P7 compromise floor.
    local _comp_floor=0
    if (( _pa_subs > 0 )) || (( _comp_letters > 0 )) || (( persist_count >= 1 )); then
        _comp_floor=100
    fi
    if (( persist_count >= 2 )) || (( _comp_letters >= 2 )); then
        _comp_floor=200
    fi
    (( score < _comp_floor )) && score=$_comp_floor

    SCORE="$score"
    STRONG_COUNT="$strong_count"
    FIXED_COUNT="$fixed_count"
    INCONCLUSIVE_COUNT="$inconclusive_count"
    ADVISORY_COUNT="$advisory_count"
    IOC_CRITICAL="$ioc_critical"
    IOC_REVIEW="$ioc_review"
    COMPROMISE_CRITICAL="$compromise_critical"
    PROBE_ARTIFACT_COUNT="$probe_artifact_count"
    PERSIST_COUNT="$persist_count"
    PERSIST_WEIGHT_SUM="$persist_weight_sum"
    PERSIST_MULTIPLIER="$persist_mult"
    PERSIST_PATTERNS_LIST=$(printf '%s,' "${!PERSIST_PATTERNS[@]}" | sed 's/,$//')
    SESSION_TIERED_COUNT="$session_tiered_count"
    SESSION_MAX_REASONS="$session_max_reasons"

    # Code-state axis: pure cpanel -V driven. IOC evidence informs
    # host_root/user verdicts only — runtime hits never imply binary patch level.
    if (( IOC_ONLY )); then
        VERDICT="SKIPPED"
        EXIT_CODE=0
    elif (( version_says_vuln )); then
        VERDICT="VULNERABLE"
        EXIT_CODE=1
    elif (( version_says_patched )); then
        VERDICT="PATCHED"
        EXIT_CODE=0
    else
        VERDICT="INCONCLUSIVE"
        EXIT_CODE=2
    fi

    # Quarantine still credits score but loses verdict trigger;
    # user-attributed signals route to host_user_verdict only.
    local _quarantine_only=0
    if (( root_compromise_critical_live == 0 )) && (( persist_count_live_root == 0 )) \
       && ( (( root_compromise_critical > 0 )) || (( persist_count > 0 )) ); then
        _quarantine_only=1
    fi
    if (( _quarantine_only )); then
        HOST_ROOT_VERDICT="SUSPICIOUS"
    elif (( root_compromise_critical_live > 0 )) || (( persist_count_live_root >= 1 )); then
        HOST_ROOT_VERDICT="COMPROMISED"
    elif (( root_ioc_critical > 0 )) || (( root_ioc_review > 0 )); then
        HOST_ROOT_VERDICT="SUSPICIOUS"
    else
        HOST_ROOT_VERDICT="CLEAN"
    fi
    if (( user_compromise_critical > 0 )); then
        HOST_USER_VERDICT="COMPROMISED"
    elif (( user_ioc_critical > 0 )) || (( user_ioc_review > 0 )); then
        HOST_USER_VERDICT="SUSPICIOUS"
    else
        HOST_USER_VERDICT="CLEAN"
    fi
    if [[ "$HOST_ROOT_VERDICT" == "COMPROMISED" || "$HOST_USER_VERDICT" == "COMPROMISED" ]]; then
        EXIT_CODE=4
    elif [[ "$HOST_ROOT_VERDICT" == "SUSPICIOUS" || "$HOST_USER_VERDICT" == "SUSPICIOUS" ]]; then
        EXIT_CODE=3
    fi

    # Cluster advisory: surface multi-pattern persistence as a distinct
    # advisory entry so fleet aggregators / CSV consumers can rank these
    # above single-pattern hosts. Emit only at count >= 3 to keep the
    # advisory channel high-signal.
    if (( persist_count >= 3 )); then
        local _plist="$PERSIST_PATTERNS_LIST"
        emit advisory ioc_persistence_cluster_critical advisory \
            ioc_persistence_cluster_critical 0 \
            note "$persist_count distinct persistence patterns detected (${_plist}) — cluster_score=$persist_weight_sum, multiplier=${persist_mult}x" \
            persist_count "$persist_count" persist_score "$persist_weight_sum" \
            multiplier "$persist_mult" patterns "$_plist"
        ADVISORIES+=("ioc_persistence_cluster_critical|ioc_persistence_cluster_critical|$persist_count distinct persistence patterns detected (${_plist}) - cluster_score=$persist_weight_sum, multiplier=${persist_mult}x")
        ((advisory_count++))
        ADVISORY_COUNT="$advisory_count"
    fi

    # Surface quarantine-only demotion so consumers see WHY host_root_verdict
    # is SUSPICIOUS. Fires only when quarantine was the sole compromise input.
    if (( _quarantine_only )); then
        emit advisory ioc_quarantine_only_no_live_corroboration advisory \
            ioc_quarantine_only_no_live_corroboration 0 \
            note "$compromise_critical_quarantine quarantined_session strong-tier signal(s) with no live corroboration (no on-disk Pattern A-M, no token_used_2xx, no persistence cluster); demoted to SUSPICIOUS — mitigate.sh remediated past compromise, host is operationally clean." \
            quarantine_count "$compromise_critical_quarantine"
        ADVISORIES+=("ioc_quarantine_only_no_live_corroboration|ioc_quarantine_only_no_live_corroboration|$compromise_critical_quarantine quarantined_session strong-tier signal(s) with no live corroboration; demoted to SUSPICIOUS.")
        ((advisory_count++))
        ADVISORY_COUNT="$advisory_count"
    fi
    COMPROMISE_CRITICAL_LIVE="$compromise_critical_live"
    COMPROMISE_CRITICAL_QUARANTINE="$compromise_critical_quarantine"
}

# Materialise per-user verdict block. Caps at USERS_BLOCK_CAP (50) by
# severity-then-count. Sets USERS_JSON + AFFECTED_USER_* + total_users.
USERS_BLOCK_CAP=50
aggregate_per_user_verdict() {
    AFFECTED_USER_COUNT=0
    AFFECTED_USER_COMPROMISED=0
    AFFECTED_USER_SUSPECT=0
    USERS_TRUNCATED=0
    USERS_TRUNCATED_COUNT=0
    USERS_JSON=""
    HOST_USER_TOTAL=0

    if [[ -d /var/cpanel/users ]]; then
        HOST_USER_TOTAL=$(find /var/cpanel/users -mindepth 1 -maxdepth 1 -type f 2>/dev/null | wc -l)
        HOST_USER_TOTAL="${HOST_USER_TOTAL//[^0-9]/}"
        HOST_USER_TOTAL="${HOST_USER_TOTAL:-0}"
    fi

    if (( ${#USER_SEVERITY[@]} == 0 )); then
        return
    fi

    local _u _sev _cnt
    local -a _rows=()
    for _u in "${!USER_SEVERITY[@]}"; do
        _sev="${USER_SEVERITY[$_u]:-clean}"
        _cnt="${USER_COUNT[$_u]:-0}"
        case "$_sev" in
            strong)  ((AFFECTED_USER_COMPROMISED++)) ;;
            warning) ((AFFECTED_USER_SUSPECT++)) ;;
            *)       continue ;;
        esac
        ((AFFECTED_USER_COUNT++))
        local _rank
        case "$_sev" in
            strong)  _rank=2 ;;
            warning) _rank=1 ;;
            *)       _rank=0 ;;
        esac
        _rows+=("${_rank}|${_cnt}|${_u}")
    done

    if (( ${#_rows[@]} == 0 )); then
        return
    fi

    local -a _sorted
    mapfile -t _sorted < <(printf '%s\n' "${_rows[@]}" | sort -t'|' -k1,1nr -k2,2nr)
    local _total=${#_sorted[@]}
    if (( _total > USERS_BLOCK_CAP )); then
        USERS_TRUNCATED=1
        USERS_TRUNCATED_COUNT=$(( _total - USERS_BLOCK_CAP ))
    fi

    local _json="" _i=0
    local _row _r_rank _r_cnt _r_user _verdict _patterns _keys _priv _fe _le
    for _row in "${_sorted[@]}"; do
        (( _i >= USERS_BLOCK_CAP )) && break
        IFS='|' read -r _r_rank _r_cnt _r_user <<< "$_row"
        case "$_r_rank" in
            2) _verdict="USER_COMPROMISED" ;;
            1) _verdict="USER_SUSPECT" ;;
            *) continue ;;
        esac
        _patterns=$(printf '%s\n' ${USER_PATTERNS[$_r_user]:-} | sort -u | tr '\n' ',' | sed 's/,$//; s/^,//')
        _keys=$(printf '%s\n' ${USER_KEYS[$_r_user]:-} | sort -u | tr '\n' ',' | sed 's/,$//; s/^,//')
        _priv="${USER_PRIV_MAX[$_r_user]:-user}"
        _fe="${USER_FIRST_EPOCH[$_r_user]:-0}"
        _le="${USER_LAST_EPOCH[$_r_user]:-0}"
        local _pat_json="" _key_json=""
        local _t
        local IFS=','
        for _t in $_patterns; do
            [[ -z "$_t" ]] && continue
            [[ -n "$_pat_json" ]] && _pat_json+=,
            _pat_json+="\"$(json_esc "$_t")\""
        done
        for _t in $_keys; do
            [[ -z "$_t" ]] && continue
            [[ -n "$_key_json" ]] && _key_json+=,
            _key_json+="\"$(json_esc "$_t")\""
        done
        unset IFS

        (( _i > 0 )) && _json+=","
        _json+=$'\n    '
        _json+=$(printf '{"user":"%s","verdict":"%s","evidence_count":%d,"actor_privilege_max":"%s","patterns":[%s],"ioc_keys":[%s],"first_evidence_epoch":%d,"last_evidence_epoch":%d}' \
                 "$(json_esc "$_r_user")" "$_verdict" "$_r_cnt" "$_priv" \
                 "$_pat_json" "$_key_json" "${_fe:-0}" "${_le:-0}")

        if (( JSONL )); then
            printf '{"host":"%s","run_id":"%s","kind":"user_summary","user":"%s","verdict":"%s","evidence_count":%d,"actor_privilege_max":"%s","patterns":[%s],"ioc_keys":[%s],"first_evidence_epoch":%d,"last_evidence_epoch":%d}\n' \
                "$HOSTNAME_JSON" "$RUN_ID" \
                "$(json_esc "$_r_user")" "$_verdict" "$_r_cnt" "$_priv" \
                "$_pat_json" "$_key_json" "${_fe:-0}" "${_le:-0}"
        fi

        ((_i++))
    done
    USERS_JSON="$_json"
}

# Per-section verdict matrix - mitigate-style 7-row table rendered at the
# top of print_verdict. Reads SECTION_VERDICT[] + SECTION_COUNTS[] populated
# by aggregate_verdict(). Each row: <tag> <section_label> <count_summary>.
# Areas with no signals render as [..] / "skipped".
print_section_matrix() {
    (( QUIET )) && return
    local area label tag counts color tok
    local n_live n_ioc n_warn n_adv n_ok detail
    for area in "${SECTION_ORDER[@]}"; do
        label="${SECTION_LABEL[$area]:-$area}"
        tag="${SECTION_VERDICT[$area]:-[..]}"
        counts="${SECTION_COUNTS[$area]:-}"
        n_live=0; n_ioc=0; n_warn=0; n_adv=0; n_ok=0
        for tok in $counts; do
            case "$tok" in
                live)     ((n_live++)) ;;
                ioc)      ((n_ioc++)) ;;
                warn)     ((n_warn++)) ;;
                advisory) ((n_adv++)) ;;
                ok)       ((n_ok++)) ;;
            esac
        done
        if [[ -z "$counts" ]]; then
            detail="skipped"
        else
            detail=""
            (( n_live > 0 )) && detail+="${detail:+, }${n_live} live"
            (( n_ioc  > 0 )) && detail+="${detail:+, }${n_ioc} ioc"
            (( n_warn > 0 )) && detail+="${detail:+, }${n_warn} warn"
            (( n_adv  > 0 )) && detail+="${detail:+, }${n_adv} advisory"
            (( n_ok   > 0 )) && detail+="${detail:+, }${n_ok} ok"
        fi
        color="$DIM"
        case "$tag" in
            "[LIVE]")                  color="${BOLD}${RED}" ;;
            "[IOC]"|"[VULN]"|"[ERR]") color="$RED"    ;;
            "[WARN]")                  color="$YELLOW" ;;
            "[ADVISORY]")              color="$CYAN"   ;;
            "[OK]")                    color="$GREEN"  ;;
            "[..]")                    color="$DIM"    ;;
        esac
        printf '  %s%-10s%s %-10s %s%s%s\n' \
            "$color" "$tag" "$NC" "$label" "$DIM" "$detail" "$NC" >&2
        # --verbose: list unique IOC keys for this area, indented under the row.
        # Restores per-section signal vocabulary that the count-only form summarizes.
        if (( VERBOSE )) && [[ -n "${SECTION_KEYS[$area]:-}" ]]; then
            local k
            for k in $(printf '%s\n' ${SECTION_KEYS[$area]} | sort -u); do
                printf '             %s%s%s\n' "$DIM" "$k" "$NC" >&2
            done
        fi
    done
    printf '\n' >&2
}

print_verdict() {
    (( QUIET )) && return
    hdr_section "summary" "code state + host posture"
    sayf '  host: %s   os: %s   cpanel: %s\n\n' \
        "$HOSTNAME_FQDN" "${OS_PRETTY:-unknown}" "${CPANEL_NORM:-unknown}"
    print_section_matrix
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
    local _root_color="" _user_color=""
    case "$HOST_ROOT_VERDICT" in
        COMPROMISED) _root_color="$RED" ;;
        SUSPICIOUS)  _root_color="$YELLOW" ;;
        CLEAN)       _root_color="$GREEN" ;;
        *)           _root_color="$DIM" ;;
    esac
    case "$HOST_USER_VERDICT" in
        COMPROMISED) _user_color="$RED" ;;
        SUSPICIOUS)  _user_color="$YELLOW" ;;
        CLEAN)       _user_color="$GREEN" ;;
        *)           _user_color="$DIM" ;;
    esac

    say ""
    sayf ' %sCode verdict:%s %s%s%s    score=%+d\n' "$BOLD" "$NC" "$code_color" "$VERDICT" "$NC" "$SCORE"
    sayf ' %sHost root verdict:%s %s%s%s\n' "$BOLD" "$NC" "$_root_color" "$HOST_ROOT_VERDICT" "$NC"
    sayf ' %sHost user verdict:%s %s%s%s   (affected_users=%d, total=%d)\n' \
        "$BOLD" "$NC" "$_user_color" "$HOST_USER_VERDICT" "$NC" \
        "${AFFECTED_USER_COUNT:-0}" "${HOST_USER_TOTAL:-0}"

    if (( ${AFFECTED_USER_COUNT:-0} > 0 )); then
        local _u _u_sev _u_cnt _u_pat _shown=0
        for _u in "${!USER_SEVERITY[@]}"; do
            (( _shown >= 10 )) && break
            _u_sev="${USER_SEVERITY[$_u]:-clean}"
            [[ "$_u_sev" == "clean" ]] && continue
            _u_cnt="${USER_COUNT[$_u]:-0}"
            _u_pat=$(printf '%s\n' ${USER_PATTERNS[$_u]:-} | sort -u | tr '\n' ',' | sed 's/,$//; s/^,//')
            local _u_color="$YELLOW"
            [[ "$_u_sev" == "strong" ]] && _u_color="$RED"
            sayf '   %suser%s %-20s %s%-10s%s patterns=%s (events=%d)\n' \
                "$DIM" "$NC" "$_u" "$_u_color" \
                "${_u_sev/strong/COMPROMISED}" "$NC" "${_u_pat:-?}" "$_u_cnt"
            ((_shown++))
        done
        if (( USERS_TRUNCATED )); then
            sayf '   %s...and %d more (users[] capped at %d)%s\n' \
                "$DIM" "$USERS_TRUNCATED_COUNT" "$USERS_BLOCK_CAP" "$NC"
        fi
    fi

    if (( ${PERSIST_COUNT:-0} >= 1 )); then
        sayf '   persistence: %s%d distinct pattern(s) (%s) — cluster_score=%d ×%d%s\n' \
            "$YELLOW" "${PERSIST_COUNT:-0}" "${PERSIST_PATTERNS_LIST:-}" \
            "${PERSIST_WEIGHT_SUM:-0}" "${PERSIST_MULTIPLIER:-1}" "$NC"
    fi

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
            sayf '  %s%-10s%s %s (%s)\n' "$CYAN" "[ADVISORY]" "$NC" "$adv_id" "$adv_key"
            [[ -n "$adv_note" ]] && sayf '       %s%s%s\n' "$DIM" "$adv_note" "$NC"
        done
    fi

    if [[ "$HOST_ROOT_VERDICT" == "COMPROMISED" || "$HOST_USER_VERDICT" == "COMPROMISED" ]]; then
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
            # ${BASH_SOURCE[0]} is the file path when run as a script. $0 can
            # be the literal "bash" (cat | bash, bash -c "$(...)", bash <(...))
            # which prints "bash bash" — fall back to the script's own
            # filename so the recommendation is always actionable.
            local _self="${BASH_SOURCE[0]:-}"
            case "${_self##*/}" in
                ""|bash|main|sh) _self="sessionscribe-ioc-scan.sh" ;;
            esac
            say ""
            say "   Recommended action:"
            say "     /usr/local/cpanel/scripts/upcp --force"
            say "     /usr/local/cpanel/scripts/restartsrv_cpsrvd"
            say "     bash $_self                                # confirm verdict flips to PATCHED"
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
        printf '  "host_root_verdict": "%s",\n' "$HOST_ROOT_VERDICT"
        printf '  "host_user_verdict": "%s",\n' "$HOST_USER_VERDICT"
        printf '  "host_user_summary": {"total_users":%d,"compromised":%d,"suspect":%d,"clean_or_unknown":%d},\n' \
            "${HOST_USER_TOTAL:-0}" "${AFFECTED_USER_COMPROMISED:-0}" \
            "${AFFECTED_USER_SUSPECT:-0}" \
            "$(( ${HOST_USER_TOTAL:-0} - ${AFFECTED_USER_COMPROMISED:-0} - ${AFFECTED_USER_SUSPECT:-0} ))"
        printf '  "users": [%s%s],\n' "${USERS_JSON}" "$([[ -n "$USERS_JSON" ]] && printf '\n  ')"
        printf '  "users_truncated": %s,\n' "$([[ ${USERS_TRUNCATED:-0} -eq 1 ]] && echo true || echo false)"
        printf '  "users_truncated_count": %d,\n' "${USERS_TRUNCATED_COUNT:-0}"
        printf '  "score": %d,\n' "$SCORE"
        printf '  "exit_code": %d,\n' "$EXIT_CODE"
        printf '  "summary": {"strong":%d,"fixed":%d,"inconclusive":%d,"ioc_critical":%d,"ioc_review":%d,"compromise_critical":%d,"compromise_critical_live":%d,"compromise_critical_quarantine":%d,"advisories":%d,"probe_artifacts":%d,"persist_count":%d,"persist_score":%d,"persist_multiplier":%d,"persist_patterns":"%s","session_tiered_count":%d,"session_max_reasons":%d},\n' \
            "$STRONG_COUNT" "$FIXED_COUNT" "$INCONCLUSIVE_COUNT" "$IOC_CRITICAL" "$IOC_REVIEW" "${COMPROMISE_CRITICAL:-0}" \
            "${COMPROMISE_CRITICAL_LIVE:-0}" "${COMPROMISE_CRITICAL_QUARANTINE:-0}" \
            "${ADVISORY_COUNT:-0}" "${PROBE_ARTIFACT_COUNT:-0}" \
            "${PERSIST_COUNT:-0}" "${PERSIST_WEIGHT_SUM:-0}" "${PERSIST_MULTIPLIER:-1}" "$(json_esc "${PERSIST_PATTERNS_LIST:-}")" \
            "${SESSION_TIERED_COUNT:-0}" "${SESSION_MAX_REASONS:-0}"
        printf '  "advisories": [\n'
        first=1
        local entry adv_id adv_key adv_note
        # Length-check guards: empty advisories[]/signals[] are valid JSON
        # output, but ${arr[@]} on an empty array trips `set -u` on bash 4.1.
        if (( ${#ADVISORIES[@]} > 0 )); then
            for entry in "${ADVISORIES[@]}"; do
                IFS='|' read -r adv_id adv_key adv_note <<< "$entry"
                (( first )) || printf ',\n'
                first=0
                printf '    {"id":"%s","key":"%s","note":"%s"}' \
                    "$(json_esc "$adv_id")" "$(json_esc "$adv_key")" "$(json_esc "$adv_note")"
            done
        fi
        printf '\n  ],\n'
        printf '  "signals": [\n'
        first=1
        if (( ${#SIGNALS[@]} > 0 )); then
            for row in "${SIGNALS[@]}"; do
                IFS=$'\t' read -r area id sev key weight kv <<< "$row"
                (( first )) || printf ',\n'
                first=0
                # Per-signal host prefix mirrors the JSONL stream so each row is
                # self-attributing when the signals[] array is flattened across hosts.
                printf '    {"host":"%s","area":"%s","id":"%s","severity":"%s","key":"%s","weight":%s%s}' \
                    "$HOSTNAME_JSON" "$area" "$id" "$sev" "$key" "${weight:-0}" "${kv:+,$kv}"
            done
        fi
        printf '\n  ],\n'
        printf '  "software_digest": {"kernel_running":"%s","kernel_full":"%s","kernel_latest_installed":"%s","kernel_reboot_pending":%d,"kernel_tainted":"%s","pkgmgr_kind":"%s","pkgmgr_health":"%s","pkgmgr_health_note":"%s","pkgmgr_last_txn_epoch":"%s","disk_health":"%s","disk_full_mounts":"%s","disk_inode_full_mounts":"%s","boot_free_mb":"%s"},\n' \
            "$(json_esc "$KERNEL_RUNNING")" \
            "$(json_esc "$KERNEL_FULL")" \
            "$(json_esc "$KERNEL_LATEST_INSTALLED")" \
            "${KERNEL_REBOOT_PENDING:-0}" \
            "$(json_esc "$KERNEL_TAINTED")" \
            "$(json_esc "$PKGMGR_KIND")" \
            "$(json_esc "$PKGMGR_HEALTH")" \
            "$(json_esc "$PKGMGR_HEALTH_NOTE")" \
            "$(json_esc "$PKGMGR_LAST_TXN_EPOCH")" \
            "$(json_esc "$DISK_HEALTH")" \
            "$(json_esc "$DISK_FULL_MOUNTS")" \
            "$(json_esc "$DISK_INODE_FULL_MOUNTS")" \
            "$(json_esc "$BOOT_FREE_MB")"
        printf '  "software_inventory_b64gz": "%s",\n' "$SOFTWARE_INVENTORY_B64GZ"
        printf '  "software_inventory_meta": {"sha256":"%s","raw_bytes":%d,"encoded_bytes":%d,"encoding":"gzip+base64","note":"%s"},\n' \
            "$(json_esc "${SOFTWARE_INVENTORY_SHA256:-}")" \
            "${SOFTWARE_INVENTORY_RAW_BYTES:-0}" \
            "${SOFTWARE_INVENTORY_ENCODED_BYTES:-0}" \
            "$(json_esc "${SOFTWARE_INVENTORY_B64GZ_NOTE:-}")"
        printf '  "lmd_hits_b64gz": "%s",\n' "${LMD_HITS_B64GZ:-}"
        printf '  "lmd_hits_meta": {"installed":%s,"active":%s,"version":"%s","window_days":%d,"max_rows":%d,"row_count":%d,"raw_bytes":%d,"encoded_bytes":%d,"encoding":"gzip+base64","note":"%s"}\n' \
            "$([[ ${LMD_INSTALLED:-0} -eq 1 ]] && echo true || echo false)" \
            "$([[ ${LMD_ACTIVE:-0} -eq 1 ]] && echo true || echo false)" \
            "$(json_esc "${LMD_VERSION:-}")" \
            "${LMD_HITS_WINDOW_DAYS:-30}" \
            "${LMD_HITS_MAX_ROWS:-2000}" \
            "${LMD_HITS_ROW_COUNT:-0}" \
            "${LMD_HITS_RAW_BYTES:-0}" \
            "${LMD_HITS_ENCODED_BYTES:-0}" \
            "$(json_esc "${LMD_HITS_B64GZ_NOTE:-not_collected}")"
        printf '}\n'
    } > "$out"
}

###############################################################################
# CSV output — one summary row per host. Multi-value columns (reasons,
# advisory_ids) use ';' to keep the ',' shape stable for fleet roll-up.
###############################################################################

# RFC 4180: wrap in double quotes, double any embedded quotes.
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
        # Column order: two-axis verdicts (host_root + host_user) +
        # affected_user_count + users_truncated. Positional consumers map col 6.
        printf 'host,run_id,ts,tool_version,code_verdict,host_root_verdict,host_user_verdict,affected_user_count,users_truncated,score,exit_code,strong,fixed,inconclusive,ioc_critical,ioc_review,advisories,probe_artifacts,reasons,advisory_ids,persist_count,persist_score,persist_multiplier,persist_patterns,compromise_critical,session_tiered_count,session_max_reasons\n'
        printf '%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s,%s,%d,%d,%d,%s,%d,%d,%d\n' \
            "$(csv_field "$HOSTNAME_FQDN")" \
            "$(csv_field "$RUN_ID")" \
            "$(csv_field "$TS_ISO")" \
            "$(csv_field "$VERSION")" \
            "$(csv_field "$VERDICT")" \
            "$(csv_field "$HOST_ROOT_VERDICT")" \
            "$(csv_field "$HOST_USER_VERDICT")" \
            "${AFFECTED_USER_COUNT:-0}" \
            "${USERS_TRUNCATED:-0}" \
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
            "$(csv_field "$adv_ids")" \
            "${PERSIST_COUNT:-0}" \
            "${PERSIST_WEIGHT_SUM:-0}" \
            "${PERSIST_MULTIPLIER:-1}" \
            "$(csv_field "${PERSIST_PATTERNS_LIST:-}")" \
            "${COMPROMISE_CRITICAL:-0}" \
            "${SESSION_TIERED_COUNT:-0}" \
            "${SESSION_MAX_REASONS:-0}"
    } > "$out"
}

###############################################################################
# Run ledger — append-only JSONL at $LEDGER_DIR/runs.jsonl + per-run
# envelope (skipped when -o supplied). --no-ledger opts out. Soft-fails.
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
    line=$(printf '{"ts":"%s","run_id":"%s","host":"%s","tool_version":"%s","code_verdict":"%s","host_root_verdict":"%s","host_user_verdict":"%s","affected_user_count":%d,"score":%d,"exit_code":%d,"duration_s":%d,"ioc_critical":%d,"ioc_review":%d}' \
        "$TS_ISO" "$RUN_ID" "$HOSTNAME_JSON" "$VERSION" \
        "$VERDICT" "$HOST_ROOT_VERDICT" "$HOST_USER_VERDICT" "${AFFECTED_USER_COUNT:-0}" "$SCORE" "$EXIT_CODE" "$duration" \
        "$IOC_CRITICAL" "$IOC_REVIEW")
    # Append - flock would be ideal but introduces a util-linux dependency
    # we don't want for fleet portability. The single-line atomic write
    # is good enough for this access pattern (one writer per host per run).
    printf '%s\n' "$line" >> "$LEDGER_DIR/runs.jsonl" 2>/dev/null || true
    chmod 0600 "$LEDGER_DIR/runs.jsonl" 2>/dev/null || true
    # Per-run envelope. Skip if -o was given (operator captured their own).
    # Path is exported on the global ENVELOPE_PATH for forensic phases and
    # replay mode.
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
    msg=$(printf 'run_id=%s host=%s code=%s host_root=%s host_user=%s aff_users=%d exit=%d ioc_critical=%d ioc_review=%d' \
        "$RUN_ID" "$HOSTNAME_FQDN" "$VERDICT" "$HOST_ROOT_VERDICT" "$HOST_USER_VERDICT" \
        "${AFFECTED_USER_COUNT:-0}" "$EXIT_CODE" "$IOC_CRITICAL" "$IOC_REVIEW")
    logger -t sessionscribe-ioc -p auth.notice -- "$msg" 2>/dev/null || true
}

# Resolve --replay PATH (.json | dir/ | .tgz | .tar.gz) → envelope path.
# Sets RESOLVED_ENVELOPE_PATH; exits 2 on ambiguity/unreadability.
RESOLVED_ENVELOPE_PATH=""
REPLAY_TMPDIR=""
resolve_replay_envelope() {
    local p="$1"
    if [[ -z "$p" ]]; then
        echo "Error: resolve_replay_envelope called with empty path" >&2
        exit 2
    fi
    if [[ -f "$p" ]]; then
        case "$p" in
            (*.json)
                RESOLVED_ENVELOPE_PATH="$p"
                return 0
                ;;
            (*.tgz|*.tar.gz)
                REPLAY_TMPDIR=$(mktemp -d "/tmp/sessionscribe-replay-${RUN_ID}.XXXXXX") || {
                    echo "Error: mktemp failed for replay extraction" >&2
                    exit 2
                }
                if ! tar -xzf "$p" -C "$REPLAY_TMPDIR" 2>/dev/null; then
                    echo "Error: failed to extract $p (not a valid gzip tarball?)" >&2
                    exit 2
                fi
                # Bundle layout: <tmp>/<bundle-dir-name>/<run_id>.json (forensic
                # bundle convention) OR <tmp>/envelope.json (legacy). Multi-match
                # is an error — same rule as the directory case so an operator
                # can't accidentally replay against a non-envelope JSON file.
                local cand n_cand
                n_cand=$(find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' 2>/dev/null | wc -l)
                if (( n_cand == 0 )); then
                    echo "Error: no .json envelope found inside $p" >&2
                    exit 2
                elif (( n_cand > 1 )); then
                    echo "Error: $n_cand .json files found inside $p — ambiguous; extract manually and pass the envelope file directly with --replay" >&2
                    find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' >&2
                    exit 2
                fi
                cand=$(find "$REPLAY_TMPDIR" -maxdepth 3 -type f -name '*.json' 2>/dev/null | head -1)
                RESOLVED_ENVELOPE_PATH="$cand"
                return 0
                ;;
            (*)
                echo "Error: --replay file must be .json, .tgz, or .tar.gz (got $p)" >&2
                exit 2
                ;;
        esac
    elif [[ -d "$p" ]]; then
        # Directory — find the first envelope.json or numeric-prefixed .json
        local cand
        cand=$(find "$p" -maxdepth 1 -type f -name '*.json' 2>/dev/null | head -1)
        if [[ -z "$cand" ]]; then
            echo "Error: no .json envelope found in directory $p" >&2
            exit 2
        fi
        RESOLVED_ENVELOPE_PATH="$cand"
        return 0
    else
        echo "Error: --replay PATH does not exist: $p" >&2
        exit 2
    fi
}

###############################################################################
# Main
###############################################################################

HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname || echo unknown)
HOSTNAME_JSON=$(json_esc "$HOSTNAME_FQDN")    # pre-escaped, used by emit/write_json
TS_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

###############################################################################
# Detection phase (skipped in --replay mode)
###############################################################################
if (( ! REPLAY_MODE )); then
    banner

    local_init
    collect_host_meta
    collect_software_digest
    collect_lmd_meta
    if (( IOC_ONLY )); then
        hdr_section "ioc-only" "code-state checks skipped"
    else
        check_version
        check_static
        check_binary
    fi
    check_logs
    check_sessions
    check_destruction_iocs
    check_csf_posture
    check_localhost_probe

    aggregate_verdict
    aggregate_per_user_verdict

    # Write the envelope to disk BEFORE forensic phases run so the forensic
    # path can read it from disk via the same code path used by --replay.
    # This makes the envelope contract a same-script invariant rather than
    # a cross-script handshake.
    if [[ -z "$NO_LEDGER" || "$NO_LEDGER" -eq 0 ]]; then
        mkdir -p "$LEDGER_DIR" 2>/dev/null
        ENVELOPE_PATH="$LEDGER_DIR/${RUN_ID}.json"
        write_json "$ENVELOPE_PATH" 2>/dev/null
        [[ -f "$ENVELOPE_PATH" ]] && chmod 0600 "$ENVELOPE_PATH" 2>/dev/null
    fi
else
    # --replay PATH: skip detection, set ENVELOPE_PATH from resolved input.
    resolve_replay_envelope "$REPLAY_PATH"
    ENVELOPE_PATH="$RESOLVED_ENVELOPE_PATH"
    # Read host verdicts / score / tool_version from the envelope so the
    # forensic phases see consistent context.
    read_envelope_meta "$ENVELOPE_PATH"
    HOST_ROOT_VERDICT="${ENV_HOST_ROOT_VERDICT:-UNKNOWN}"
    HOST_USER_VERDICT="${ENV_HOST_USER_VERDICT:-UNKNOWN}"
    SCORE="${ENV_SCORE:-0}"
    hdr_section "replay" "forensic phases on $ENVELOPE_PATH"
fi

###############################################################################
# Forensic phases (--full or --replay)
###############################################################################
RUN_FORENSIC=0
if (( REPLAY_MODE )); then
    RUN_FORENSIC=1
elif (( FULL_MODE )); then
    _root_compromised=0; _user_compromised=0
    [[ "$HOST_ROOT_VERDICT" == "COMPROMISED" ]] && _root_compromised=1
    [[ "$HOST_USER_VERDICT" == "COMPROMISED" ]] && _user_compromised=1
    _any_compromised=$(( _root_compromised || _user_compromised ))
    if (( CHAIN_ON_ALL )); then
        emit "summary" "forensic_run" "info" "forensic_chain_on_all" 0 \
             "host_root_verdict" "$HOST_ROOT_VERDICT" \
             "host_user_verdict" "$HOST_USER_VERDICT" \
             "note" "host_root=$HOST_ROOT_VERDICT host_user=$HOST_USER_VERDICT; --chain-on-all forces forensic phases regardless of verdict."
        RUN_FORENSIC=1
    elif (( CHAIN_ON_ROOT_ONLY )) && (( ! _root_compromised )); then
        emit "summary" "forensic_skip" "info" "forensic_skipped_user_only" 0 \
             "host_root_verdict" "$HOST_ROOT_VERDICT" \
             "host_user_verdict" "$HOST_USER_VERDICT" \
             "note" "host_root=$HOST_ROOT_VERDICT host_user=$HOST_USER_VERDICT; --chain-on-root-only requires host_root_verdict=COMPROMISED."
    elif (( CHAIN_ON_CRITICAL )) && (( ! _any_compromised )); then
        emit "summary" "forensic_skip" "info" "forensic_skipped_below_critical" 0 \
             "host_root_verdict" "$HOST_ROOT_VERDICT" \
             "host_user_verdict" "$HOST_USER_VERDICT" \
             "note" "host_root=$HOST_ROOT_VERDICT host_user=$HOST_USER_VERDICT; --chain-on-critical limits forensic to COMPROMISED on either axis."
    elif [[ "$HOST_ROOT_VERDICT" == "CLEAN" && "$HOST_USER_VERDICT" == "CLEAN" ]]; then
        emit "summary" "forensic_skip" "info" "forensic_skipped_clean" 0 \
             "note" "both verdicts CLEAN; not running forensic phases (use --chain-on-all to override)."
    else
        RUN_FORENSIC=1
    fi
fi

if (( RUN_FORENSIC )); then
    phase_defense
    phase_offense
    phase_reconcile
    render_kill_chain
    if (( DO_BUNDLE )); then
        phase_bundle
        # Telemetry POST runs after the bundle so it can read the in-bundle
        # envelope copy. Independent of --upload (which ships the outer
        # tarball to intake); both can fire in the same run.
        (( TELEMETRY_MODE )) && [[ -n "$TELEMETRY_URL" ]] && phase_telemetry_post
        (( DO_UPLOAD )) && phase_upload
    fi

    # Forensic summary signal. NO `local` keyword — this runs at top level;
    # `local` would be a parse error. Names become globals (read once below).
    n_off="${#OFFENSE_EVENTS[@]}"; n_def="${#DEFENSE_EVENTS[@]}"
    f_verdict="CLEAN"; f_exit=0
    if (( n_off > 0 )); then
        if (( N_PRE > 0 )); then f_verdict="COMPROMISED_PRE_DEFENSE"; f_exit=2
        else                     f_verdict="COMPROMISED_POST_DEFENSE"; f_exit=1
        fi
    fi
    emit "summary" "forensic_summary" "info" "forensic_reconstruction" 0 \
         "verdict" "$f_verdict" "iocs_total" "$n_off" \
         "pre_defense" "$N_PRE" "post_defense" "$N_POST" \
         "defenses_extracted" "$n_def" \
         "note" "forensic reconstruction: $f_verdict (exit=$f_exit; does not override host_verdict exit code)"
fi

print_verdict

# Streaming: --csv to stdout (--jsonl is already streamed line-by-line during
# emit() so no end-of-run write is needed for that mode).
(( CSV )) && write_csv /dev/stdout

# File output (-o FILE).
if [[ -n "$OUTPUT_FILE" ]]; then
    if (( CSV )); then
        write_csv "$OUTPUT_FILE"
    else
        write_json "$OUTPUT_FILE"
    fi
fi

# Re-write the envelope at end-of-run so forensic-phase signals and the
# forensic_summary land in the on-disk artifact (the early write above
# had only the detection signals).
if (( ! REPLAY_MODE )) && [[ -n "$ENVELOPE_PATH" && -f "$ENVELOPE_PATH" ]]; then
    write_json "$ENVELOPE_PATH" 2>/dev/null
    chmod 0600 "$ENVELOPE_PATH" 2>/dev/null
fi

ledger_write
syslog_emit

# Replay mode: clean up the tmpdir from tgz extraction.
if (( REPLAY_MODE )) && [[ -n "$REPLAY_TMPDIR" && -d "$REPLAY_TMPDIR" ]]; then
    rm -rf "$REPLAY_TMPDIR" 2>/dev/null
fi

exit "$EXIT_CODE"
