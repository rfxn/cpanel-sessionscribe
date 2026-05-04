#!/bin/bash
#
##
# sessionscribe-ioc-scan.sh v2.7.25
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
# Modes (v2.0.0+ - forensic phases live inline; --replay supersedes the
# v1.x two-script chain):
#   --triage      detection only (default); writes envelope to run-ledger
#   --full        detection + forensic (defense, offense, reconcile,
#                 kill-chain, bundle, upload). Bundle on by default.
#   --replay PATH replay forensic against a saved envelope (.json), bundle
#                 directory, or .tgz - re-render or re-submit without rescan.
#
# Output streams (any mode):
#   default       ANSI sectioned report on stderr
#   -o, --output  structured output to FILE (JSON, or CSV with --csv)
#   --jsonl       one JSON signal per line on stdout (suppresses sectioned)
#   --csv         one per-host summary row on stdout (suppresses sectioned)
#   --quiet       suppress sectioned report
#   --verbose     expand matrix detail
#
# Verdict axes (independent):
#   code_verdict  PATCHED / VULNERABLE / INCONCLUSIVE - from version, Perl
#                 patterns, cpsrvd binary fingerprint
#   host_verdict  CLEAN / SUSPICIOUS / COMPROMISED - from session IOC scan
#                 (vendor + CVE-2026-41940 ladder) and access-log scan.
#                 Sessions tagged with the companion probe's canary attribute
#                 bucket as PROBE_ARTIFACT (do NOT escalate).
#
# Exit codes (highest priority wins):
#   0  PATCHED+CLEAN
#   1  VULNERABLE      code-state: cpsrvd binary unpatched
#   2  INCONCLUSIVE    code-state ambiguous; also tool error (bad args/deps)
#   3  SUSPICIOUS      host-state: ioc_review > 0 (warning-tier IOC hits)
#   4  COMPROMISED     host-state: ioc_critical > 0 (overrides 0/1/2/3 -
#                      a patched host can still be compromised from prior
#                      exploitation)
#
# Usage:
#   bash sessionscribe-ioc-scan.sh                       # triage (default)
#   bash sessionscribe-ioc-scan.sh --full                # + forensic + bundle
#   bash sessionscribe-ioc-scan.sh --full --upload       # + ship to intake
#   bash sessionscribe-ioc-scan.sh --replay PATH         # re-render saved bundle
#   bash sessionscribe-ioc-scan.sh --since 90 --jsonl    # 90d window, JSONL stream
#
# Fleet (Ansible/Salt/SSH wrap of local mode):
#   ansible -i hosts all -m script -a 'sessionscribe-ioc-scan.sh --full --jsonl --quiet'
#   pdsh -w cpanel-fleet 'bash -s' < sessionscribe-ioc-scan.sh

set -u

###############################################################################
# Constants - vendor patch cutoffs and signal definitions
###############################################################################

VERSION="2.7.25"

# Vendor patched-build cutoff per tier (cPanel KB 40073787579671). Per the
# vendor advisory: tier 86 (EL6 path) and tier 124 added; tier 130 cutoff
# bumped from .18 to .19. WP Squared product line: separate patch at build
# 136.1.7 (tracked in mitigate/forensic, not in this tier-keyed map).
PATCHED_TIERS_KEYS=(86 110 118 124 126 130 132 134 136)
PATCHED_TIERS_VALS=(41 97  63  35  54  19  29  20  5)

# Tiers explicitly excluded from the vendor patch list. In-place patch
# unavailable; hosts must be upgraded to a patched tier. Tier 124 was
# in this list pre-advisory but was given an in-place patch (.35), so
# is now moved into PATCHED_TIERS_KEYS above.
# Maintained as an array (UNPATCHED_TIERS) so adding/removing tiers stays a
# one-token edit; the derived UNPATCHED_TIERS_STR is what both call sites
# (phase_defense and check_version) actually consume via the same substring-
# match idiom (` $UNPATCHED_TIERS_STR ` == *" $tier "*).
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

###############################################################################
# Destruction-stage IOCs (Patterns A-I). Cheap host-state probes - bounded
# stat / hash / grep checks suitable for fleet triage. The heavyweight
# kill-chain reconstruction now runs inline under --full / --replay (same
# script); this set just answers "does this host carry visible compromise
# residue?"
#
# Last updated from incident dossier: 2026-05-01.
###############################################################################

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
# in shell history. C2 host/IP catch the drop even after rename. _IP_2
# is the rev5 second binary host (same /24, same actor scaling infra).
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
# wraps recon; __CMD_DONE_<nanos>__ is an additional same-actor marker
# (rev5: Vishnu's host, imagicktest).
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

# Pattern J - persistence via Linux init facilities (udev rule + systemd
# unit). Shape-based detection (filenames vary per host); both observed
# attacker shapes pull a payload binary. Two sub-detectors:
#   J1: udev rule with `RUN+=...sh -c '...'` body that backgrounds via
#       `at now` (the dossier-observed shape). Strong tier requires the
#       pipe-to-`at now` form; nohup/setsid/disown demote to warning.
#   J2: systemd unit with ExecStart pointing OUTSIDE legit binary roots
#       (allowlist below) + unit not RPM-owned + Description shadows
#       a known systemd/cPanel service name. /usr/share/<x>/<y> ExecStart
#       is the strongest discriminator: legit systemd units never live in
#       /usr/share/ per FHS (data, not executables).
PATTERN_J_UDEV_DIRS=(/etc/udev/rules.d /run/udev/rules.d)
PATTERN_J_SYSTEMD_UNIT_DIRS=(/etc/systemd/system)
# ExecStart-allowed binary roots. Legit cPanel/LSWS/Plesk extras included
# so a stock control-panel host doesn't FP. /usr/lib/systemd/ covers
# upstream systemd's own service binaries. /usr/local/lp/ covers Liquid
# Web management infra (Prometheus exporters under
# /usr/local/lp/opt/exporters/, etc.) - LW-managed binaries are
# RPM-unowned by design but operator-deployed and not attacker-planted.
PATTERN_J_EXECSTART_ALLOWED_RE='^(/usr/(bin|sbin|lib/systemd|lib(64)?/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|local/(bin|sbin|cpanel|lsws|directadmin|lp))|/opt/|/var/(cpanel|lib/dovecot|lib/mysql)|/bin/|/sbin/)'
# Description shadow list - legit systemd/cPanel service names an attacker
# might mimic with a `<name>-helper` / `<name>-cleanup` / `<name>2` suffix.
PATTERN_J_DESC_SHADOW_RE='\b(dbus-broker|systemd-(resolved|networkd|timesyncd|logind|udevd)|cpsrvd|cphulkd|queueprocd|exim-altport|chkservd|tailwatchd|cpanel-dovecot)\b'
# Pattern J incident-window cutoff (90 days) for promoting from warning to
# strong on the soft-shape branch. Files older than this are still emitted
# at warning weight=4 but don't reach strong unless an extra signal hits.
PATTERN_J_RECENT_DAYS=90
# Cap on systemd units walked per scan (perf bound). EL7+ stock fleet has
# ~30-50 units in /etc/systemd/system/ - 200 is a generous cap.
PATTERN_J_MAX_UNITS=200
# Pattern J known-IOC paths (v2.7.20 — direct dossier strings). The
# `-helper` suffix is the discriminator vs legitimate counterparts:
# - real cpanel/upstream uses `cdrom_id` (underscore), not `cdrom-id-helper`
# - real dbus-broker is `dbus-broker.service`, not `dbus-broker-helper.service`
# - /usr/share/dbus-1/ never contains a `-helper` binary on a stock system
# Direct existence check is zero-FP — these strings have no legitimate use.
PATTERN_J_KNOWN_PATHS=(
    "/etc/udev/rules.d/89-cdrom-id-helper.rules"
    "/usr/lib/udev/cdrom-id-helper"
    "/etc/systemd/system/dbus-broker-helper.service"
    "/usr/lib/systemd/system/dbus-broker-helper.service"
    "/usr/share/dbus-1/dbus-broker-helper"
)
# Pattern J process names — exact matches via pgrep -x (no substring FP).
# (Note: payload-fetch URL/hostname is NOT an IOC — the OVH bucket is
# legitimate IR sharing infra; payload-file presence is captured by J3a
# literal-path check below. See INTERNAL-NOTES.md "v2.7.20/v2.7.21".)
PATTERN_J_PROCESS_NAMES=(cdrom-id-helper dbus-broker-helper)

# Pattern K - Cloudflare-fronted /Update second-stage backdoor. Hostname
# is Cloudflare shared anycast - do NOT blocklist at edge (coordinate
# Cloudflare T&S for zone takedown). _TMP_RE [$][$] char-class matches
# both literal `$$` (as-typed) and `[0-9]+` (echo-expanded) forms.
PATTERN_K_BACKDOOR_HOST="cp.dene.de.com"
PATTERN_K_TMP_RE='F=/tmp/\.u([$][$]|[0-9]+)'
# Pattern K dropper paranoid-cleanup shape (v2.7.20 — survives C2 rotation).
# Per dossier: "Combination of `wget -q -O ... && chmod 755 ... && ... -s; rm -f`
# on a single line — paranoid-cleanup pattern that rarely appears in legitimate
# sysadmin work." Catches Pattern K from a renamed/rotated C2 host where the
# cp.dene.de.com literal no longer applies.
PATTERN_K_DROPPER_SHAPE_RE='wget[[:space:]]+-q[[:space:]]+-O[[:space:]].*&&[[:space:]]*chmod[[:space:]]+755.*&&.*-s[[:space:]]*;[[:space:]]*rm[[:space:]]+-f'

# Pattern L - filesystem-nuke (rm -rf --no-preserve-root /). The
# --no-preserve-root flag is the load-bearing IOC; GNU coreutils
# defaults to --preserve-root specifically to block accidental nukes.
# Trailing-`/`-as-target anchor (followed by whitespace, special char,
# or EOL) avoids FP on `--no-preserve-root /tmp/foo` (operator just
# disabled the safety on a non-root target). __CMD_START__/__CMD_END__
# wraps destructive commands (Pattern F-family marker; distinct from
# __S_MARK__/__E_MARK__ recon envelope).
PATTERN_L_NUKE_RE="rm[[:space:]]+-rf[[:space:]]+--no-preserve-root[[:space:]]+/([[:space:]&;\"']|\$)"
PATTERN_L_CMD_START="__CMD_START__"
PATTERN_L_CMD_END="__CMD_END__"
PATTERN_L_CMD_ENVELOPE_RE="${PATTERN_L_CMD_START}|${PATTERN_L_CMD_END}"

# Attacker-planted jumphost-mimic SSH key labels (per IC-5790 dossier).
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

# Attacker IPs from IC-5790 dossier rev3 (2026-05-01). Some blackholed —
# still count hits in case rotation didn't take. --exclude-ip suppresses
# operator scan boxes. 183.82.160.147 has DEC 2025 websocket/Shell hits,
# four months pre-disclosure — --since 90 misses these.
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
    # Pattern Unknown (rev3 cohort entry, not yet classified A or B)
    89.34.18.59
    # rev4 expansion (2026-05-02): four DigitalOcean operators chained
    # the CRLF exploit over 8h on a single target then handed off to a
    # destruction operator running 24x200 websocket Shell. 80.75.212.14
    # is the early scout (mixed-UA recon hours before the exploit wave).
    80.75.212.14     206.189.227.202  159.223.155.255  67.205.134.215
    136.244.66.225
    # rev5 (2026-05-03): Pattern J operator - drops udev/systemd-unit
    # persistence that fetches an out-of-band payload binary. Detection
    # is by the Pattern J shape gates (J1/J2) plus this operator IP; no
    # payload-binary fingerprint shipped yet (sha256 will land in the
    # dossier when the binary is fully analyzed).
    45.92.1.188
    # rev5 (2026-05-03): second nuclear.x86 binary host (Pattern C
    # variant - same /24 as 87.121.84.78, same actor scaling
    # infrastructure). Surfaced on host.eworksinc.com (Rahul Krishnan
    # case 46501374) with multiple active nuclear.x86 processes still
    # running as root; binary persisted and beaconing - confirms
    # Pattern C can run in active-process mode in addition to the
    # originally-documented hit-and-run.
    87.121.84.243
    # rev5 (2026-05-03): badpass exploit IP null-routed by Jamie 8:02
    # CDT. Source host: cloudvpstemplate.1g9j3u-lwsites.com.
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

# Run ledger. /var/cpanel/sessionscribe-ioc/ holds an append-only JSONL
# of every run plus a per-run JSON envelope. Default ON so operators get
# local history without an aggregator; --no-ledger opts out for paranoid
# runs that must leave no host residue. Sibling to sessionscribe-mitigate's
# /var/cpanel/sessionscribe-mitigation/ - both stay under /var/cpanel/
# so cpanel-tool state is co-located.
NO_LEDGER=0
LEDGER_DIR_DEFAULT="/var/cpanel/sessionscribe-ioc"
LEDGER_DIR=""            # resolved at run time; --ledger-dir overrides

# Forensic phase defaults — used when --full or --replay
# is supplied; no-op in default --triage mode.
DEFAULT_BUNDLE_DIR_ROOT="/root/.ic5790-forensic"
DEFAULT_MAX_BUNDLE_MB=2048      # per-tarball cap (NOT bundle-wide)
DEFAULT_FORENSIC_SINCE_DAYS=90  # forensic-mode default --since when unspecified
# Bundle retention: keep the N newest bundles in $BUNDLE_DIR_ROOT (current
# run + the N-1 most-recent prior runs); older bundle dirs and any sibling
# .upload.tgz are pruned at the end of phase_bundle. Bundle uploads ride
# off-host to intake, so the local copy is operator-recovery scratch -
# 3 is enough to keep "this run + last two" without unbounded growth on
# busy fleet hosts. Override via $BUNDLE_RETENTION env var; set 0 to
# disable pruning entirely.
DEFAULT_BUNDLE_RETENTION=3
INTAKE_DEFAULT_URL="https://intake.rfxn.com/"
# Convenience token for ad-hoc intake submissions; server enforces 1000-PUT
# cap per token. For fleet use, supply --upload-token or RFXN_INTAKE_TOKEN.
INTAKE_DEFAULT_TOKEN="cd88c9970c3176997c9671a2566fadc84904be0b73edd5e3b071452eade796e1"

# Sentinel file whose mtime phase_defense uses to estimate when a host
# adopted the vendor cPanel patch (Load.pm is the file the patch rewrites).
# Empty/missing canary => host has never been patched in-place.
PATCH_CANARY_FILE="/usr/local/cpanel/Cpanel/Session/Load.pm"
MITIGATE_BACKUP_ROOT="/var/cpanel/sessionscribe-mitigation"
MODSEC_USER_CONFS=(
    "/etc/apache2/conf.d/modsec/modsec2.user.conf"   # EA4 (cPanel default)
    "/etc/httpd/conf.d/modsec/modsec2.user.conf"     # non-EA4 fallback
    "/etc/httpd/conf.d/modsec2.user.conf"            # legacy non-EA4
)
MODSEC_USER_CONF="${MODSEC_USER_CONFS[0]}"
CPSRVD_PORTS=(2082 2083 2086 2087 2095 2096)

# Optional syslog one-liner for SIEM ingestion. Off by default.
SYSLOG=0

# --chain-forensic: v1.x back-compat alias — equivalent to --full (no
# host-verdict gate). The forensic phases are now inline; the alias
# remains so deployed v1.x curl one-liners keep working.
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

# --chain-on-critical: only run forensic when ioc_critical > 0
# (skips SUSPICIOUS hosts). Implies --chain-forensic.
CHAIN_ON_CRITICAL=0

# --chain-on-all: always run forensic regardless of host_verdict.
# Wins over --chain-on-critical. Implies --chain-forensic.
CHAIN_ON_ALL=0

# Forensic / merged-mode defaults.
FULL_MODE=0                             # 1 if --full set (or back-compat chain flag)
REPLAY_PATH=""                          # set by --replay PATH
REPLAY_MODE=0                           # 1 if --replay PATH set (skip detection)
DO_BUNDLE=1                             # default ON when --full active; --no-bundle disables
BUNDLE_DIR_ROOT="$DEFAULT_BUNDLE_DIR_ROOT"
MAX_BUNDLE_MB="$DEFAULT_MAX_BUNDLE_MB"
EXTRA_LOGS_DIR=""
INCLUDE_HOMEDIR_HISTORY=1
DO_UPLOAD=0
INTAKE_URL="$INTAKE_DEFAULT_URL"
INTAKE_TOKEN=""

# Telemetry mode — lite bundle (no heavy tarballs) + optional envelope POST.
# Designed for high-frequency fleet polling: ~50-100 KB on-disk per host vs
# ~50 MB for full bundles. Lite bundle keeps envelope.json + kill-chain.{tsv,
# jsonl,md} + manifest.txt + KB-scale forensic snapshots (ps/connections/
# iptables + Pattern A/H/I attacker-binary metadata). Skips heavy tarballs
# (sessions, access-logs, system-logs, cpanel-state, cpanel-users,
# persistence, defense-state) and per-user bash histories.
#
# Transport ladder for --telemetry-url POST: curl > wget > bash native.
# bash native uses /dev/tcp for HTTP and openssl s_client for HTTPS;
# bash on RHEL/CL6+ is built --enable-net-redirections so the /dev/tcp
# pseudo-path works without any external HTTP client. openssl is
# universally present on cPanel hosts (cpsrvd uses libssl), so HTTPS
# stays covered even on minimal installs that strip curl/wget.
TELEMETRY_MODE=0
TELEMETRY_URL=""
TELEMETRY_TOKEN=""
TELEMETRY_TIMEOUT=15
TELEMETRY_RETRY=2
# 5 MB cap. Envelopes rarely exceed 50 KB on a clean host, but a destruction-
# heavy host with hundreds of A/B/C/H pattern hits can grow into double-digit
# KB; the cap is a defense-in-depth ceiling against pathological cases.
TELEMETRY_MAX_BYTES=$((5 * 1024 * 1024))

# --telemetry-cron <add|remove> [1h|2h|6h|12h|24h]: install or remove a system
# cron entry under /etc/cron.d/ that runs the telemetry path on a fixed
# interval (default 6h). The generated cron self-fetches the script with a
# canonical→fallback source order at each tick (GitHub raw primary, rfxn
# CDN fallback), atomically installs it to a stable path, runs syntax
# validation (bash -n) before exec, then runs the scan under timeout 300.
# This makes the cron entry portable (curl-pipe install needs no on-disk
# script) and keeps fleet hosts on the latest released version with no
# operator-side push. Splay 5-300s spreads fleet load across the minute mark.
TELEMETRY_CRON_ACTION=""
TELEMETRY_CRON_INTERVAL="6h"
TELEMETRY_CRON_FILE="/etc/cron.d/sessionscribe-telemetry"
# Cron self-fetch sources (GitHub canonical, CDN fallback) + install dest.
# See INTERNAL-NOTES.md "v2.7.17/v2.7.18" for failover + drift-window detail.
TELEMETRY_CRON_GITHUB_URL="https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh"
TELEMETRY_CRON_CDN_URL="https://sh.rfxn.com/sessionscribe-ioc-scan.sh"
TELEMETRY_CRON_INSTALL_PATH="/usr/local/bin/sessionscribe-ioc-scan.sh"

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
                             (default: /root/.ic5790-forensic)
      --max-bundle-mb N      Per-tarball size cap in MB (0 = no cap;
                             default: 2048)
      --extra-logs DIR       Additional access-log directory to scan (e.g.
                             an expanded archive of rotated logs)
      --no-history           Skip /home/*/.bash_history bundle capture

Upload (off by default):
      --upload               Submit bundle to $INTAKE_URL after capture.
                             Intake URL and token can be overridden via the
                             upload-url / upload-token flags documented in
                             the Misc section below. Token resolution order:
                             flag > $RFXN_INTAKE_TOKEN env > built-in token
                             (1000-PUT cap; proj@rfxn.com for fleet token).

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
      --chain-on-critical    full mode only if host_verdict == COMPROMISED
                             (CLEAN/SUSPICIOUS skip forensic phases)
      --chain-on-all         full mode for EVERY host_verdict, including
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

###############################################################################
# Telemetry cron management — install / remove /etc/cron.d/<name> entry that
# runs the telemetry path on a fixed interval (1h/2h/6h/12h/24h). Generated
# cron is self-bootstrapping: each tick curl-fetches the latest script —
# canonical source is GitHub raw (raw.githubusercontent.com/rfxn/cpanel-
# sessionscribe), fallback is the rfxn CDN (sh.rfxn.com) — atomic-installs
# to /usr/local/bin/ after a size guard + `bash -n` syntax check, then
# runs under `timeout 300`. Splay 5-300s spreads fleet load. Curl-pipe
# install works (no on-disk script required at --telemetry-cron add time)
# since the cron line embeds the source URLs, not $0.
#
# Cron file format chosen: /etc/cron.d/<name>. Reasons:
#   - System cron (works under cronie / vixie-cron / EL9 systemd-cron-shim);
#     no per-user crontab dependency
#   - SHELL=/bin/bash declared in-file so $((RANDOM % N)) works at run time
#     (cron's default /bin/sh on Debian-derivatives is dash, no $RANDOM)
#   - Easy to inspect / disable (cat / rm); no `crontab -l | { …; } | crontab`
#     race window when re-running 'add'
#   - install(1) preserves perms; restorecon(1) best-effort fixes SELinux
#     context if the binary is present (cPanel hosts typically permissive
#     selinux but the call is harmless either way)
#
# Defined here (early in the script, immediately after usage()) so the
# dispatch site at the end of arg parsing can call it before any scan-mode
# validation runs. Cron management is its own operational mode and exits
# cleanly without attempting detection.
###############################################################################

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

    # The cron line is self-bootstrapping: it embeds source URL constants
    # (GitHub canonical + CDN fallback) and the install path constant, not
    # $0. So `--telemetry-cron add` works correctly when invoked via
    # curl-pipe (where $0 is bash, not a real script path) — the cron entry
    # is generated and installed regardless of how this script was launched.
    # Validate that none of the embedded constants contain single-quotes
    # (we single-quote all of them inside the heredoc; an embedded quote
    # would close the outer quoting). Also validate the install path's
    # parent exists so the per-tick mktemp doesn't fail on missing dir.
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

    # Pass through --upload-url and --upload-token if the operator set them
    # on this command line — embed in the generated cron so the scheduled
    # run ships to their custom intake without manual file edits. Single-
    # quoted in the cron line so values containing spaces or special chars
    # don't break shell parsing at run time. Operators can rotate the
    # token by re-running '--telemetry-cron add ... --upload-token NEW'.
    local extra_args=""
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
    fi

    # Heredoc preserves \$((…)) for cron-shell evaluation per tick.
    # See INTERNAL-NOTES.md "v2.7.16/v2.7.17" for timeout + splay rationale.
    local tmp
    tmp=$(mktemp /tmp/telemetry-cron.XXXXXX) || {
        echo "Error: mktemp failed" >&2; exit 2; }
    cat > "$tmp" <<CRONEOF
# /etc/cron.d/sessionscribe-telemetry
# Managed by sessionscribe-ioc-scan.sh --telemetry-cron
# Generated $(date -u +%FT%TZ) at interval=${TELEMETRY_CRON_INTERVAL}
#
# DO NOT EDIT DIRECTLY — re-running '--telemetry-cron add' overwrites this
# file. Use '--telemetry-cron remove' to uninstall, or re-run 'add' with
# different flags to update.
#
# Perms: 0600 root:root. The cron line below embeds an --upload-token
# value; world-readability would expose the credential to any local user.
# crond reads /etc/cron.d/* as root, so 0600 doesn't break execution.
#
# Self-fetch shape: each cron tick downloads the latest script with a
# canonical -> fallback source order: (1) GitHub raw (canonical, updated
# within ~5min of every git push), (2) sh.rfxn.com CDN (fallback, updated
# by the freedom-syncs publish workflow). The (curl GH || curl CDN)
# subshell tries primary first and falls back on any curl failure. After
# fetch the script is size-guarded, syntax-validated with bash -n, atomic-
# installed at mode 0755, then run under timeout 300. Always-current; no
# operator-side push for routine updates. Splay 5-300s spreads fleet
# intake load across the minute mark (~5 min for a 1000-host fleet).
#
# Failure modes (each gated by &&-chain so a failure short-circuits cleanly):
#   mktemp fails  -> chain bails before curl, prior install runs unchanged
#   GH unreachable-> CDN fallback fires (the || curl) and runs second
#   both fail     -> chain bails after the (||) group fails, prior install
#                    runs unchanged ([ -x "\$_D" ] still true on second tick)
#   0-byte body   -> [ -s "\$_T" ] catches it (Caddy serves 200+0 for missing
#                    on the CDN tree; GH raw returns 404 caught by curl -f)
#   bad bash      -> bash -n catches truncation/HTML-error-page corruption
#   install fails -> destination keeps prior version; rm -f cleans temp
#   cold start    -> [ -x "\$_D" ] short-circuits exec, no error spam
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
${schedule} root { sleep \$((5 + RANDOM % 296)); _D='${TELEMETRY_CRON_INSTALL_PATH}'; _T=\$(mktemp "\$_D.XXXXXX" 2>/dev/null) && (curl -fsS --max-time 60 -o "\$_T" '${TELEMETRY_CRON_GITHUB_URL}' || curl -fsS --max-time 60 -o "\$_T" '${TELEMETRY_CRON_CDN_URL}') && [ -s "\$_T" ] && bash -n "\$_T" && install -m 0755 -o root -g root "\$_T" "\$_D"; rm -f "\$_T" 2>/dev/null; [ -x "\$_D" ] && timeout 300 "\$_D" --telemetry --chain-on-all --chain-upload --quiet --jsonl${extra_args}; } >/dev/null 2>&1
CRONEOF

    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        echo "Error: cron file build failed (tempfile empty)" >&2
        exit 2
    fi

    # install(1) atomically replaces the target with correct perms/owner.
    # Mode 0600 (root-only) instead of the cron.d-standard 0644 because the
    # generated cron line embeds --upload-token values verbatim — leaving
    # the file world-readable would expose the intake credential to any
    # local user via `cat /etc/cron.d/sessionscribe-telemetry`. cronie /
    # vixie-cron read /etc/cron.d/* as root and don't require world-
    # readability; verified locally that 0600 entries are picked up
    # normally with no journal rejection. We use 0600 unconditionally
    # (even without an embedded token) for consistency — the file's
    # contents aren't otherwise sensitive but mode-uniformity makes
    # operator audit trivial.
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
    echo "Command:   timeout 300 '$TELEMETRY_CRON_INSTALL_PATH' --telemetry --chain-on-all --chain-upload --quiet --jsonl${extra_args}"
    echo
    echo "Inspect:   cat $TELEMETRY_CRON_FILE"
    echo "Test now:  curl -fsS --max-time 60 -o '$TELEMETRY_CRON_INSTALL_PATH' '$TELEMETRY_CRON_GITHUB_URL' && timeout 300 '$TELEMETRY_CRON_INSTALL_PATH' --telemetry --chain-on-all --chain-upload --quiet --jsonl${extra_args}"
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
        --bundle-dir)         BUNDLE_DIR_ROOT="$2"; shift 2 ;;
        --max-bundle-mb)      MAX_BUNDLE_MB="$2"; shift 2 ;;
        --extra-logs)         EXTRA_LOGS_DIR="$2"; shift 2 ;;
        --no-history)         INCLUDE_HOMEDIR_HISTORY=0; shift ;;
        --upload)             DO_UPLOAD=1; shift ;;
        # Telemetry mode — lite bundle (no heavy tarballs) for high-frequency
        # fleet polling. Implies --full --chain-on-all --bundle so the
        # forensic phases run on every host and the bundle dir gets the
        # envelope + kill-chain primitives written. The lite-mode skip
        # logic lives inside phase_bundle (gated on TELEMETRY_MODE).
        --telemetry)
            TELEMETRY_MODE=1; FULL_MODE=1; CHAIN_ON_ALL=1
            CHAIN_FORENSIC=1; DO_BUNDLE=1; shift ;;
        --telemetry-url)
            TELEMETRY_URL="$2"
            TELEMETRY_MODE=1; FULL_MODE=1; CHAIN_ON_ALL=1
            CHAIN_FORENSIC=1; DO_BUNDLE=1; shift 2 ;;
        --telemetry-token)    TELEMETRY_TOKEN="$2"; shift 2 ;;
        --telemetry-timeout)  TELEMETRY_TIMEOUT="$2"; shift 2 ;;
        --telemetry-retry)    TELEMETRY_RETRY="$2"; shift 2 ;;
        --telemetry-max-bytes) TELEMETRY_MAX_BYTES="$2"; shift 2 ;;
        # --telemetry-cron <add|remove> [INTERVAL]: action arg is required;
        # for 'add', the optional positional INTERVAL is consumed if it
        # doesn't look like another flag (i.e., doesn't start with '--').
        # The function validates the interval value at run time so a bad
        # value like '99h' produces a clear "invalid interval" error
        # instead of falling through to the parser's "Unknown option"
        # branch. For 'remove', no interval is meaningful — leave the
        # next token alone so it can be parsed normally.
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
        # Back-compat aliases -- set --full + the legacy gate flags so the
        # main-flow gating logic (Phase 5) honors the original semantics.
        --chain-forensic)     FULL_MODE=1; CHAIN_FORENSIC=1; shift ;;
        --chain-upload)       FULL_MODE=1; DO_UPLOAD=1; CHAIN_UPLOAD=1; CHAIN_FORENSIC=1; shift ;;
        --upload-url)         CHAIN_UPLOAD_URL="$2"; shift 2 ;;
        --upload-token)       CHAIN_UPLOAD_TOKEN="$2"; shift 2 ;;
        --chain-on-critical)  FULL_MODE=1; CHAIN_ON_CRITICAL=1; CHAIN_FORENSIC=1; shift ;;
        # chain-on-all override — runs forensic phases for EVERY
        # host (including CLEAN). Pair with --upload for unconditional
        # bundle submission across the fleet. Implies --full.
        --chain-on-all|--chain-always) FULL_MODE=1; CHAIN_ON_ALL=1; CHAIN_FORENSIC=1; shift ;;
        --root)               ROOT_OVERRIDE="$2"; shift 2 ;;
        --version-string)     VERSION_OVERRIDE="$2"; shift 2 ;;
        --cpsrvd-path)        CPSRVD_OVERRIDE="$2"; shift 2 ;;
        --timeout)            TIMEOUT="$2"; shift 2 ;;
        -h|--help)            usage ;;
        *) echo "Unknown option: $1" >&2; echo "Try --help" >&2; exit 2 ;;
    esac
done

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
# Resolve upload token at parse time. Order: --upload-token > env > built-in.
if (( DO_UPLOAD )); then
    INTAKE_TOKEN="${CHAIN_UPLOAD_TOKEN:-${RFXN_INTAKE_TOKEN:-$INTAKE_DEFAULT_TOKEN}}"
    [[ -n "$CHAIN_UPLOAD_URL" ]] && INTAKE_URL="$CHAIN_UPLOAD_URL"
fi
# Validate --max-bundle-mb is a non-negative integer.
if ! [[ "$MAX_BUNDLE_MB" =~ ^[0-9]+$ ]]; then
    echo "Error: --max-bundle-mb requires a non-negative integer (MB)" >&2
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
    # --telemetry is incompatible with --no-ledger for the same reason --full
    # is — phase_telemetry_post and the kill-chain primitives both need the
    # envelope on disk. The earlier --full + --no-ledger gate covers this
    # transitively (TELEMETRY_MODE implies FULL_MODE) but we restate it for
    # clarity in the error message.
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

###############################################################################
# Forensic state
###############################################################################
# When the operator runs --full or --replay, the forensic phases populate
# these arrays. They stay empty in default --triage mode. All forensic
# findings flow through emit() into the unified SIGNALS[] stream.
DEFENSE_EVENTS=()       # "epoch|kind|note" strings, sorted at render time
OFFENSE_EVENTS=()       # "epoch|pattern|key|note|defenses_required" strings
IOC_PRIMITIVES=()       # parallel-indexed with OFFENSE_EVENTS; TSV row per IOC
IOC_ANNOTATIONS=()      # parallel-indexed; renderer-side annotations (Pattern E dim)
RECONCILED_EVENTS=()    # "epoch|pattern|key|verdict|delta|note" strings

# PRIM_SEP: ASCII Unit Separator (0x1f) used to join ioc_primitive_row fields.
# Non-whitespace so consecutive empty fields survive IFS-based read.
# Columns: area | ip | path | log_file | count | hits_2xx | status | line
PRIM_SEP=$'\x1f'

# ENV_* globals populated by read_envelope_meta() when --full or --replay
# is in effect. They mirror the envelope's root-level fields so the kill-
# chain renderer can show host_verdict/score/tool_version without re-
# parsing the envelope on every render call.
ENV_HOST_VERDICT=""
ENV_CODE_VERDICT=""
ENV_SCORE=""
ENV_IOC_TOOL_VERSION=""
ENV_IOC_RUN_ID=""
ENV_IOC_TS=""
N_PRE=0                 # PRE-DEFENSE event count (set in phase_reconcile)
N_POST=0                # POST-DEFENSE event count (set in phase_reconcile)
N_DEF=0                 # defense-event count (informational, set at render time)
N_OFF=0                 # offense-event count (informational, set at render time)
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
HOST_VERDICT="UNKNOWN"
CODE_VERDICT="UNKNOWN"
VERDICT="UNKNOWN"
EXIT_CODE=0

# Pre-compromise gate state populated during check_logs. CRLF first-epoch
# is the compromise anchor; signals before it are pre-compromise noise.
# 2XX_CPSESS first-epoch is the proximity anchor for Pattern E.
LOGS_CRLF_CHAIN_FIRST_EPOCH=0
LOGS_2XX_CPSESS_FIRST_EPOCH=0

# Host-meta globals consumed by phase_defense (CPANEL_NORM patch matching),
# print_verdict (host/cpanel/os summary), phase_bundle (manifest.txt), and
# write_kill_chain_primitives (meta record). Values are assigned by
# collect_host_meta() in the main flow; declared empty here so any reference
# before that assignment yields "" instead of "unbound" under set -u.
# Earlier revisions documented these as `set by banner()` but banner() only
# printed - manifest/meta fields rendered empty in every bundle until the
# host-meta phase was added.
#
# LP_UID is the exception: declared with `:=` so an inherited environment
# variable (`LP_UID=nx-prod-12 ./sessionscribe-ioc-scan ...`) survives this
# initialization. A plain `LP_UID=""` would clobber the env-var before any
# function had a chance to read it.
PATCHED_BUILDS_CPANEL=()   # populated from PATCHED_TIERS_KEYS/VALS just below
for _i in "${!PATCHED_TIERS_KEYS[@]}"; do
    PATCHED_BUILDS_CPANEL+=("11.${PATCHED_TIERS_KEYS[$_i]}.0.${PATCHED_TIERS_VALS[$_i]}")
done
unset _i
PATCHED_BUILD_WPSQUARED="11.136.1.7"  # WP Squared product line (separate
                            # patch lineage; see comment at PATCHED_TIERS_KEYS)
CPANEL_NORM=""             # normalised cPanel version "11.<tier>.0.<build>"
PRIMARY_IP=""              # primary outbound IPv4 (ip-route-get probe)
OS_PRETTY=""               # /etc/os-release PRETTY_NAME or redhat-release line
: "${LP_UID:=}"            # hosting-provider UID; env-overridable, default ""
INCIDENT_ID="IC-5790"      # dossier identifier baked into all forensic output
PRIMARY_IP_J=""            # json_esc'd PRIMARY_IP
LP_UID_J=""                # json_esc'd LP_UID
OS_J=""                    # json_esc'd OS_PRETTY
CPV_J=""                   # json_esc'd CPANEL_NORM

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
BUNDLE_BDIR=""          # absolute path to /root/.ic5790-forensic/<TS>-<RUN_ID>

###############################################################################
# Per-section verdict tracking
# SECTION_ORDER drives the summary matrix row sequence + section ID display.
# SECTION_LABEL maps the emit() area to the human-facing matrix row label.
# SECTION_VERDICT[area] is filled by aggregate_verdict() (worst-wins) and
# consumed by print_verdict() to render the 7-row matrix at the top of
# the summary block.
###############################################################################
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

# High-level host gate: /var/cpanel is the canonical cPanel state directory.
# Its absence means we're not on a cPanel/WHM host. Bail before doing anything
# that would emit confusing "no log dir / no cpsrvd / no sessions" boilerplate.
# Snapshot/offline forensic runs use --root / --version-string / --cpsrvd-path
# to override; in that case, skip the gate (the operator opted in explicitly).
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
GLYPH_BOX_TL='┌'; GLYPH_BOX_TR='┐'; GLYPH_BOX_BL='└'; GLYPH_BOX_BR='┘'
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
GLYPH_BOX_TL='+'; GLYPH_BOX_TR='+'; GLYPH_BOX_BL='+'; GLYPH_BOX_BR='+'
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

# Populate host-meta globals (CPANEL_NORM / PRIMARY_IP / OS_PRETTY / LP_UID
# and their *_J twins) read by phase_defense, print_verdict, phase_bundle's
# manifest, and write_json's meta record. Called once from the main flow
# after local_init() (so $CPANEL_ROOT is set) and before any phase that
# consumes these globals or any envelope/manifest write.
#
# Resolution order for CPANEL_NORM mirrors check_version() so both yield
# the same value from the same source. LP_UID has no canonical filesystem
# source today; honor an `LP_UID` env-var override at fleet dispatch and
# default to empty (envelope/manifest field stays empty when not applicable,
# but is now operator-configurable, not silently never-assigned).
collect_host_meta() {
    # OS_PRETTY: /etc/os-release preferred; /etc/redhat-release fallback for
    # EL6 hosts that predate os-release. Read with a data-only key=value
    # parser (no eval, no `.` sourcing) so the file is treated as data even
    # when it contains shell metachars like `$(...)` or backticks. /etc/os-
    # release is root-owned so adversarial content shouldn't be reachable,
    # but a snapshot/offline run may consume an attacker-influenced copy and
    # we'd rather be safe by construction.
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

    # CPANEL_NORM: same four-source resolution chain check_version() walks.
    # Two raw shapes accepted:
    #   "110.0 (build 97)"   -> 11.110.0.97
    #   "11.110.0.97"        -> 11.110.0.97 (already normalized)
    # Bash `=~` uses libc POSIX ERE - `{2,3}` interval expressions are safe
    # (only awk regexes need the gawk-3.x-safe rewrite per project floor).
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

    # LP_UID is the hosting-provider tag. No filesystem source defined today;
    # operators set it via the LP_UID env-var at fleet dispatch time. The
    # top-level `: "${LP_UID:=}"` declaration preserves an inherited env-var
    # so we don't reassign it here - if the env was set, it's already in
    # LP_UID; if unset, top-level defaulted it to "".

    # JSON-escaped variants used by the meta record at write_kill_chain_primitives.
    PRIMARY_IP_J=$(json_esc "$PRIMARY_IP")
    OS_J=$(json_esc "$OS_PRETTY")
    CPV_J=$(json_esc "$CPANEL_NORM")
    LP_UID_J=$(json_esc "$LP_UID")
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
    local tag color
    case "$severity" in
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
# Forensic output primitives
# say_* / hdr() mirror ioc-scan's section style with status-prefixed tags so
# the forensic phase output stays visually distinct from detection sections.
# All output goes to stderr (never contaminates --jsonl/--json on stdout).
###############################################################################

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
        (pass|info)  ioc_sev="info";    weight=0  ;;
        (warn)       ioc_sev="warning"; weight=4  ;;
        (fail)       ioc_sev="strong";  weight=10 ;;
        (*)          ioc_sev="info";    weight=0  ;;
    esac
    emit "$area" "$key" "$ioc_sev" "$key" "$weight" "note" "$note" "$@"
}

###############################################################################
# Forensic helpers — used by phase_defense / phase_offense
# / phase_reconcile / render_kill_chain / phase_bundle / phase_upload.
# No-op in default --triage mode (the phase functions aren't called).
###############################################################################

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Package-ownership probe for Pattern J FP gating. Prefer rpm; fall back
# to dpkg for debian-ish hosts; if neither tool exists, return 2 ("no
# probe available") so callers can downgrade severity rather than guess.
# Returns: 0 = file is owned by an installed package
#          1 = file is NOT owned by any installed package
#          2 = no ownership probe available (rpm AND dpkg both missing)
# Always returns text on stdout for diagnostic logging:
#   "owned:<pkg>" | "not_owned" | "no_probe"
# Set -u safe: every branch initializes _own and uses `|| true` to swallow
# rpm/dpkg non-zero exit codes (rpm -qf rc=1 on not-owned is normal).
is_rpm_owned() {
    local _file="$1" _own=""
    if have_cmd rpm; then
        _own=$(rpm -qf -- "$_file" 2>/dev/null || true)
        if [[ -z "$_own" || "$_own" == *"not owned by any package"* \
              || "$_own" == *"No such file"* ]]; then
            printf 'not_owned'
            return 1
        fi
        printf 'owned:%s' "$_own"
        return 0
    fi
    if have_cmd dpkg; then
        # dpkg -S returns "<pkg>: <path>" on owned, exit non-zero on not-owned.
        _own=$(dpkg -S -- "$_file" 2>/dev/null || true)
        if [[ -z "$_own" ]]; then
            printf 'not_owned'
            return 1
        fi
        printf 'owned:%s' "${_own%%:*}"
        return 0
    fi
    printf 'no_probe'
    return 2
}

# Bulk variant: pass an array of paths, get back tab-separated lines
# of "<rc>\t<path>" where rc is 0/1/2 per is_rpm_owned semantics. Uses
# one rpm process for all paths (rpmdb opens once instead of N times).
# Performance: ~200ms once vs ~50-80ms × N for the per-path form.
bulk_rpm_owned_filter() {
    (( $# > 0 )) || return 0
    local _f
    if have_cmd rpm; then
        # rpm -qf <p1> <p2> ... emits one line per input, in input order.
        # Owned lines: "<package-NVR>". Not-owned: "file <p> is not owned...".
        # Pair input order with output via paste-style awk.
        local _out
        _out=$(rpm -qf -- "$@" 2>&1 || true)
        local _i=0
        while IFS= read -r _line; do
            _f="${@:$((_i+1)):1}"
            if [[ "$_line" == *"not owned by any package"* \
                  || "$_line" == *"No such file"* ]]; then
                printf '1\t%s\n' "$_f"
            else
                printf '0\t%s\n' "$_f"
            fi
            _i=$((_i+1))
        done <<< "$_out"
        return
    fi
    # dpkg has no bulk equivalent; loop. Set -u safe.
    if have_cmd dpkg; then
        for _f in "$@"; do
            if dpkg -S -- "$_f" >/dev/null 2>&1; then
                printf '0\t%s\n' "$_f"
            else
                printf '1\t%s\n' "$_f"
            fi
        done
        return
    fi
    for _f in "$@"; do
        printf '2\t%s\n' "$_f"
    done
}

mtime_of() {
    local f="$1"
    [[ -e "$f" ]] || { echo ""; return; }
    stat -c %Y "$f" 2>/dev/null
}

cat_log() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    case "$f" in
        (*.gz)  have_cmd zcat  && zcat  "$f" 2>/dev/null ;;
        (*.xz)  have_cmd xzcat && xzcat "$f" 2>/dev/null ;;
        (*.bz2) have_cmd bzcat && bzcat "$f" 2>/dev/null ;;
        (*)     cat "$f" 2>/dev/null ;;
    esac
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

    # Pattern-aware fallback: pattern=X events MUST have a real timestamp;
    # synthesizing TS_EPOCH for them pollutes cluster-onset analysis
    # (q5/q8 in summary.json - patient-zero anchor shifts to scan time).
    # File-on-disk patterns (A/B/C/D/F/G/H/I) retain the TS_EPOCH fallback
    # because they are authentic on-disk evidence even when the emit omits ts.
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
    ENV_HOST_VERDICT=$(envelope_root_field "$env" host_verdict)
    ENV_CODE_VERDICT=$(envelope_root_field "$env" code_verdict)
    ENV_SCORE=$(envelope_root_field "$env" score)
    ENV_IOC_TOOL_VERSION=$(envelope_root_field "$env" tool_version)
    ENV_IOC_RUN_ID=$(envelope_root_field "$env" run_id)
    ENV_IOC_TS=$(envelope_root_field "$env" ts)
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

# Modified from forensic: takes envelope path as $1 with
# $SESSIONSCRIBE_IOC_JSON as fallback. Otherwise verbatim. Reads the
# envelope from disk, populates OFFENSE_EVENTS[], IOC_PRIMITIVES[],
# IOC_ANNOTATIONS[]. Returns 1 with a non-fatal say_warn if envelope is
# absent — preserves forensic's standalone-mode tolerance.
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
            (strong|warning) ;;
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
        # Pattern X events with no resolvable timestamp are refused:
        # ioc_signal_epoch() returns 0 for pattern=X when no real ts is found.
        # Using TS_EPOCH for pattern=X would synthesize a scan-time anchor and
        # corrupt cluster-onset (q8_patient_zero_x) analysis.
        # The warning emitted here is a pattern=meta informational row
        # recording the refused event for post-hoc review.
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

###############################################################################
# Forensic phases — defense / offense / reconcile.
# Run only when --full or --replay is set. Inputs: envelope (read from disk
# via read_iocs_from_envelope). Outputs: DEFENSE_EVENTS[], OFFENSE_EVENTS[],
# IOC_PRIMITIVES[], IOC_ANNOTATIONS[], RECONCILED[], N_PRE, N_POST,
# plus signals via emit() under areas defense/offense/reconcile.
###############################################################################

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

    # Drop RFC1918 + loopback (WHM admin); mirrors Pattern E is_internal at line ~7084.
    local suspect_ips
    suspect_ips=$(
        for lg in "${cp_logs[@]}"; do cat_log "$lg"; done \
            | grep -E '"GET /cpsess[0-9]+/(websocket/Shell|json-api/(createacct|setupreseller|setacls))' 2>/dev/null \
            | awk '$1 !~ /^10\./ && $1 !~ /^127\./ && $1 !~ /^192\.168\./ && $1 !~ /^172\.(1[6-9]|2[0-9]|3[01])\./ {print $1}' \
            | sort -u | head -50
    )
    if [[ -n "$suspect_ips" ]]; then
        local ip_list
        ip_list=$(echo "$suspect_ips" | tr '\n' ',' | sed 's/,$//')
        say_ioc "suspect attacker IPs (websocket/createacct hits): $ip_list"
        emit_signal offense info suspect_ips "$ip_list" ips "$ip_list"
    fi
}

phase_defense() {
    hdr_section "defense" "extracting timestamps for every mitigation layer"

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
            # Prefer the .ic5790.bak file mtime if it exists (operator
            # pre-mutation backup) since that records the original CSF
            # mutation time.
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
        # guard with project length-check idiom (see v2.7.3 Pattern J fix).
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

# Order patterns canonically for the offense timeline. init is the recon
# pre-cursor; A-I map to the IC-5790 dossier Pattern letters; X is forged-
# session evidence that doesn't fit a destruction pattern; ? is anything
# unmapped (a runtime ioc_key_to_pattern gap).
PATTERN_ORDER=(init A B C D E F G H I J X "?")
declare -A PATTERN_LABEL=(
    [init]="recon / harvest"
    [A]="ransom / encryptor"
    [B]="data destruction"
    [C]="malware deploy"
    [D]="persistence (reseller token)"
    [E]="websocket / fileman harvest"
    [F]="harvester shell"
    [G]="persistence (ssh key)"
    [H]="seobot defacement / SEO spam"
    [I]="persistence (profile.d backdoor)"
    [J]="persistence (udev / systemd unit)"
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
            local r_str r_ts r_kind r_idx r_zone
            local row_i=0

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

        # ── Counters ────────────────────────────────────────────────────
        # Surface UNDEFENDED + ADVISORY breakouts separately. UNDEFENDED is
        # rolled into N_PRE during reconcile; advisory rows live in
        # OFFENSE_EVENTS but never increment N_PRE / N_POST (they're
        # context, not attack chain). One pass over RECONCILED computes
        # both breakouts.
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
        printf '{"kind":"meta","host":"%s","primary_ip":"%s","uid":"%s","os":"%s","cpanel_version":"%s","ts":"%s","tool":"sessionscribe-forensic","tool_version":"%s","schema_version":4,"_schema_changes":[{"v":2,"since_tool":"0.10.0","renamed":{"stage":"pattern"},"note":"IOC pattern letters were emitted as stage in schema v1 (forensic <= 0.9.x)"},{"v":3,"since_tool":"2.2.0","added":["cpsess_token"],"note":"cpsess token extracted at emit-time for Pattern E + ioc_attacker_ip_2xx_on_cpsess"},{"v":4,"since_tool":"2.7.0","added":["pattern_j","quarantined_session_emit","quarantine_run_dir","original_path","reasons_ioc","low_confidence_no_sidecar","degraded_confidence_snapshot"],"note":"Pattern J (udev/systemd-unit init-facility persistence) + mitigate-quarantine secondary read (synthetic emits from .info sidecar fields)"}],"incident_id":"%s","run_id":"%s","ioc_scan_run_id":"%s","ioc_scan_tool_version":"%s","ioc_scan_ts":"%s","host_verdict":"%s","code_verdict":"%s","score":"%s","effective_patch_epoch":"%s","effective_modsec_epoch":"%s"}\n' \
            "${HOSTNAME_JSON:-}" "${PRIMARY_IP_J:-}" "${LP_UID_J:-}" "${OS_J:-}" "${CPV_J:-}" "${TS_ISO:-}" \
            "$VERSION" "${INCIDENT_ID:-}" "$RUN_ID" \
            "$(json_esc "${ENV_IOC_RUN_ID:-}")" "$(json_esc "${ENV_IOC_TOOL_VERSION:-}")" "$(json_esc "${ENV_IOC_TS:-}")" \
            "$(json_esc "${ENV_HOST_VERDICT:-}")" "$(json_esc "${ENV_CODE_VERDICT:-}")" "$(json_esc "${ENV_SCORE:-}")" \
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

###############################################################################
# Bundle + upload pipeline.
# Bundle root: $BUNDLE_DIR_ROOT/<TS>-<RUN_ID>/ (set in Phase 4 CLI parsing).
# Tarball cap: --max-bundle-mb (per-tarball). Upload: --upload (PUT to
# $INTAKE_URL with $INTAKE_TOKEN).
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

# Bundle retention sweep. Keeps the $keep newest bundles in $BUNDLE_DIR_ROOT
# (sorted lexically by name; TS_ISO prefix is sortable) and removes older
# ones plus any sibling .upload.tgz. Operator-renamed entries that don't
# match the TS_ISO-Z- prefix are left alone so a manually-staged bundle is
# never silently deleted.
#
# bash 4.1 floor: char-class repetition only (no {n} quantifiers); case-
# pattern dedupe instead of associative arrays; C-style for over an array
# index range so set -u + empty-array iteration doesn't trip the floor.
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
    } > "$bdir/manifest.txt"

    # Stash the upstream ioc-scan JSON envelope. Only the canonical structured
    # record is preserved (operator-facing stdout is not captured); without
    # this, an offline analyst can see the kill-chain reconciliation but not
    # the source per-signal evidence ioc-scan emitted. KB-sized, always safe
    # to bundle. In --full mode ENVELOPE_PATH is the authoritative source;
    # SESSIONSCRIBE_IOC_JSON is the legacy shim path (kept for back-compat).
    local _env_src="${ENVELOPE_PATH:-${SESSIONSCRIBE_IOC_JSON:-}}"
    if [[ -n "$_env_src" && -f "$_env_src" ]]; then
        if cp "$_env_src" "$bdir/ioc-scan-envelope.json" 2>/dev/null; then
            chmod 0600 "$bdir/ioc-scan-envelope.json" 2>/dev/null
            local env_size
            env_size=$(stat -c %s "$bdir/ioc-scan-envelope.json" 2>/dev/null)
            emit_signal bundle info ioc_envelope_captured \
                "ioc-scan envelope copied to bundle (${env_size:-?} bytes)" \
                src "$_env_src" dest "ioc-scan-envelope.json" bytes "${env_size:-0}"
        else
            emit_signal bundle warn ioc_envelope_copy_failed \
                "could not copy ioc-scan envelope into bundle" src "$_env_src"
        fi
    fi

    # Kill-chain primitives next to the manifest. These are tiny (KB-scale)
    # so they're always written - independent of any per-tarball size cap.
    write_kill_chain_primitives

    # 1. cPanel sessions - forensically-relevant subtrees only. /var/cpanel/
    # sessions/cache + tmpcache are the bulk of session-dir size on busy
    # hosts and carry no forensic value (encoder cache, not forged-session
    # artifacts). raw/ + preauth/ are where the IOCs live.
    # TELEMETRY: skipped — sessions are MB-scale and per-host PII; the
    # envelope + kill-chain already carry the IOC summary.
    if (( ! TELEMETRY_MODE )); then
        local sess_list; sess_list=$(mktemp /tmp/forensic-sess.XXXXXX)
        {
            collect_recent /var/cpanel/sessions/raw
            collect_recent /var/cpanel/sessions/preauth
        } > "$sess_list" 2>/dev/null
        bundle_tar "sessions.tgz" "sessions (raw+preauth)" filtered "$sess_list"
        rm -f "$sess_list"
    fi

    # TELEMETRY: skip sections 2-5 (heavy tarballs). The access-log /
    # system-log / cpanel-state / persistence / defense-state subtrees
    # are MB-scale per host; the envelope's signals[] already carries
    # the IOC findings derived from these sources. Operators who need
    # the raw artifacts can re-run on flagged hosts without --telemetry.
    if (( ! TELEMETRY_MODE )); then

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

    # Re-archive the bundle directory into a single outer tarball. The
    # individual tarballs inside are already gzipped; tar -cz over them
    # yields very little extra compression but produces one upload artifact
    # per host with valid gzip magic on the outer wrapper. In TELEMETRY_MODE
    # there are NO inner tarballs — just the envelope/kill-chain/manifest/
    # snapshot files — so the outer tarball is itself the primary
    # compression layer (and the upload is KB-scale, not MB-scale).
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

###############################################################################
# Telemetry POST — ships envelope JSON to a fleet collector.
#
# Distinct from phase_upload (which PUTs the outer tarball to intake): this
# only sends the envelope.json (KB-scale), gated on --telemetry-url. Designed
# for high-frequency fleet polling where you want every host's signals[]
# stream into a central database without the per-host tarball overhead.
#
# Transport ladder (best-first):
#   1. curl   — preferred; --data-binary @file avoids ARG_MAX, -w embeds
#               http_code in stdout, --max-time per attempt
#   2. wget   — --post-file=, --server-response captures HTTP/x.x line for
#               status extraction; --tries=1 because we manage retry here
#   3. bash   — bash-native fallback. /dev/tcp socket for HTTP; openssl
#               s_client wraps the same request payload for HTTPS. No
#               external HTTP client required — relies only on bash
#               (built --enable-net-redirections, the RHEL/CL6+ default)
#               and openssl (universally present on cPanel hosts; cpsrvd
#               itself uses it). The whole transaction is wrapped in
#               `timeout` so a hung connect or stalled read can't outlive
#               TELEMETRY_TIMEOUT.
#
# Retry: up to (1 + TELEMETRY_RETRY) attempts with exponential backoff
# (2^attempt seconds: 2, 4, 8, ...). Each attempt has its own timeout via
# TELEMETRY_TIMEOUT — the cumulative wall is bounded but generous enough
# that a slow link doesn't fail spuriously.
#
# Failure mode: emits a warning signal (`telemetry_post_failed`) but does
# NOT change EXIT_CODE — telemetry shipping is operationally reportable
# but should not fail the scan; the lite bundle on disk is the durable
# artifact.
###############################################################################

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

    # Probe transport ladder. bash-native is the floor: /dev/tcp covers
    # HTTP, openssl s_client covers HTTPS. We probe in best-first order
    # and stop at the first viable transport. HTTPS adds an SSL
    # requirement (curl/wget compiled with SSL OR openssl binary); we
    # surface that as a separate diagnostic so the operator knows why a
    # transport was rejected.
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
    # bash-native fallback: /dev/tcp for HTTP, openssl s_client for HTTPS.
    # bash on RHEL/CL6+ is built with --enable-net-redirections; the
    # /dev/tcp/<host>/<port> pseudo-path opens a TCP socket via the
    # built-in. For HTTPS we require an openssl binary — cPanel hosts
    # always have one (cpsrvd uses libssl) but verify before declaring
    # the transport viable.
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

    # Retry loop. Backoff is 2^attempt seconds (2, 4, 8, …). Each attempt
    # uses TELEMETRY_TIMEOUT as the per-call ceiling. TELEMETRY_RETRY is
    # capped at 10 here as a defense-in-depth bound — the parse-time
    # validator allows any non-negative int, but at attempt=10 the
    # backoff is 1024s (~17min) and at attempt=20 it would be 12 days.
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
                # NOTE: --quiet AND --no-verbose both silence --server-
                # response in wget2 (Fedora/EL9+) — we need the HTTP/x.x
                # status line to extract the response code. Default-noise
                # wget without quiet flags is the only portable way; the
                # 2>FILE redirect captures everything to a scratch file we
                # then grep. Classic CL6 wget 1.12 prints the same
                # `HTTP/1.1 NNN` line shape, so the regex matches both.
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
                # Capture stdout + stderr both — wget2 (Fedora/EL9+) writes
                # --server-response output to stdout; classic wget 1.12
                # (CL6) writes it to stderr. -O FILE has already taken
                # ownership of the response body, so combining stdout+
                # stderr into the header trace is safe.
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
                # Bash-native HTTP. Parse URL into host/port/path, build the
                # full request to a tempfile (so request body and headers
                # are atomic on the wire), then deliver via /dev/tcp (HTTP)
                # or openssl s_client (HTTPS). The whole operation is
                # wrapped in `timeout` so a hung connect or stalled read
                # is bounded by TELEMETRY_TIMEOUT.
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
                    # openssl s_client: -quiet suppresses cert dump; -ign_eof
                    # keeps reading after the server's TLS close-notify so
                    # we don't truncate the response body. -servername sends
                    # SNI for vhost-routed endpoints. Args are passed via
                    # the argv (not interpolated into a shell string), so
                    # no quote-injection surface for hostile URL values.
                    timeout "$TELEMETRY_TIMEOUT" openssl s_client \
                        -connect "${_host}:${_port}" \
                        -servername "$_host" \
                        -quiet -ign_eof \
                        < "$_req_file" \
                        > "$_resp_file" 2>/dev/null
                    rc=$?
                else
                    # Plain HTTP via bash /dev/tcp. We spawn a child bash
                    # with `timeout` wrapping it — this gives us a bound
                    # on both connect-time AND read-time without bash
                    # builtin gymnastics. The child opens FD 9 (avoiding
                    # 3-collision with our own redirection space if any),
                    # writes the request, then `cat <&9` reads everything
                    # the server sends until close.
                    #
                    # SAFETY: pass _host/_port/_req_file via the env, NOT
                    # via shell-string interpolation. URL host/port come
                    # from the operator's --telemetry-url; if the value
                    # contained a single-quote (e.g. "x';rm -rf /'") the
                    # interpolated form ('...'"$_host"'...') would break
                    # quote nesting and execute the injected command in
                    # the child shell. Env passthrough makes the values
                    # data, not code.
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
        # Discard stderr (perl deprecation noise can precede the version line
        # on some cpanel builds) and strip CR so a CRLF-translated pipe
        # doesn't leave \r inside the captured build digits. Matches the
        # read form in collect_host_meta() so both paths produce identical
        # raw strings on the same host.
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

    # Anchored to start-of-string (skipping leading whitespace) so a stray
    # 4+ digit prefix doesn't match its trailing 2-3 digits via leftmost-not-
    # anchored bash regex behavior. Mirrors collect_host_meta() so both
    # functions yield the same value from the same source.
    local tier="" build=""
    if [[ "$raw" =~ ^[[:space:]]*([0-9]{2,3})\.0[[:space:]]*\(build[[:space:]]*([0-9]+)\) ]]; then
        tier="${BASH_REMATCH[1]}"; build="${BASH_REMATCH[2]}"
    elif [[ "$raw" =~ ^[[:space:]]*(11\.)?([0-9]{2,3})\.0\.([0-9]+) ]]; then
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
#
# alg_length_optrec_bug demoted from 'bug' to 'marker' in v2.7.13 — fleet
# observation showed it as the single most-firing signal (one row per host
# on tiers 110/118/126/132, which is most of the fleet) with zero
# SessionScribe verdict impact. The pre-existing OIDC operator-precedence
# bug is real but unrelated to CVE-2026-41940; demoting silences the
# advisory while preserving the per-host detection (queryable via
# severity=info / key=patch_marker_absent in records.jsonl). The twin
# start_authorize_in_die (index 1) remains 'bug'-class for now — flip it
# too if fleet data shows the same noise profile.
STATIC_KINDS=(marker bug marker marker marker marker marker marker)
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

            # --since gate: when SINCE_EPOCH is set (floor > 0), drop hits
            # whose log timestamp is older than the cutoff. Lines with
            # unparseable timestamps (ts == 0) bypass the gate so a corrupt
            # date stamp never silently hides a real hit. The historical
            # count is tracked separately so the operator can see how
            # many in-history hits were filtered.
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

    # If --since pruned all in-window hits but historical hits exist,
    # emit a low-noise informational so fleet aggregation still records
    # that the host was historically touched - just not within the
    # window the operator asked about. Does not contribute to
    # ioc_critical / ioc_review (severity=info, weight=0), so cannot
    # escalate host_verdict to COMPROMISED or SUSPICIOUS.
    if (( total == 0 && historical_drops > 0 )); then
        emit "logs" "ioc_attacker_ip_historical_only" "info" \
             "ioc_attacker_ip_outside_since_window" 0 \
             "historical_drops" "$historical_drops" \
             "since_days" "${SINCE_DAYS:-0}" \
             "note" "$historical_drops attacker-IP hit(s) found in access_log but ALL outside --since ${SINCE_DAYS:-0}d window; no in-window evidence."
    fi

    if (( total > 0 )); then
        # cpsess-split: three-way emit depending on where the 2xx hits landed.
        #   h2xx_cpsess > 0 → strong  (2xx on /cpsess<10digits>/ = real exploitation)
        #   h2xx_recon  > 0 → info    (2xx on other paths = reconnaissance only)
        #   total > 0, 4xx only → warning (probing, all rejected)
        # The legacy ioc_attacker_ip_in_access_log strong emit is REPLACED by
        # this chain; it no longer fires at strong severity for any path.
        if (( h2xx_cpsess > 0 )); then
            # Parse structured fields from first cpsess-2xx sample line.
            local _c_ip _c_path _c_status _c_token=""
            _c_ip=$(printf '%s' "$cpsess_sample" | awk '{print $1}')
            _c_path=$(printf '%s' "$cpsess_sample" | awk -F'"' 'NF>=2{n=split($2,p," "); if(n>=2)print p[2]; else print ""}')
            _c_status=$(printf '%s' "$cpsess_sample" | awk -F'"' 'NF>=3{n=split($3,p," "); if(n>=1)print p[1]; else print ""}')
            if [[ "$_c_path" =~ /cpsess([0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])/ ]]; then
                _c_token="${BASH_REMATCH[1]}"
            fi
            # Pre-compromise gate. 2xx_on_cpsess (token consumption) is
            # second-order — it needs the deterministic CRLF chain firing
            # AT OR BEFORE ts_first to anchor as compromise. Otherwise the
            # hit is most likely shared-infra T1-IP coincidence, a recycled
            # cpsess from a prior legitimate session, or pre-disclosure recon.
            # Demote to advisory; surfaces in signals[] for fleet aggregator.
            local _gate_sev="strong" _gate_key="ioc_attacker_ip_2xx_on_cpsess" _gate_weight=8
            local _gate_note="$h2xx_cpsess hit(s) from IC-5790 IPs returned 2xx on /cpsess<N>/ paths - real exploitation (CRITICAL)."
            if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )) \
               || ! [[ "$ts_first" =~ ^[0-9]+$ ]] \
               || (( ts_first == 0 )) \
               || (( ts_first < LOGS_CRLF_CHAIN_FIRST_EPOCH )); then
                _gate_sev="advisory"
                _gate_key="ioc_attacker_ip_2xx_on_cpsess_pre_compromise"
                _gate_weight=0
                if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )); then
                    _gate_note="$h2xx_cpsess hit(s) from IC-5790 IPs returned 2xx on /cpsess<N>/ paths but NO CVE-2026-41940 CRLF access-chain detected on this host - 2xx-on-cpsess is second-order (token consumption) and requires CRLF as compromise anchor. Likely pre-compromise / shared-infra coincidence / pre-disclosure recon (REVIEW; does not escalate host_verdict)."
                else
                    _gate_note="$h2xx_cpsess hit(s) from IC-5790 IPs returned 2xx on /cpsess<N>/ paths but ts_first ($ts_first) PREDATES first CRLF chain ($LOGS_CRLF_CHAIN_FIRST_EPOCH) - pre-compromise activity, mtime-pollution risk for cluster-onset analysis (REVIEW; does not escalate host_verdict)."
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
                 "note" "$h2xx_recon hit(s) from IC-5790 IPs returned 2xx on non-cpsess paths - reconnaissance only (REVIEW)."
        elif (( total > 0 )); then
            emit "logs" "ioc_attacker_ip_probes_only" "advisory" \
                 "ioc_attacker_ip_in_access_log_probes_only" 3 \
                 "count" "$total" "hits_4xx" "$h4xx" "hits_3xx" "$h3xx" \
                 "hits_other" "$hother" \
                 "historical_drops" "$historical_drops" \
                 "ts_epoch_first" "$ts_first" \
                 "note" "$total hit(s) from IC-5790 IPs - all rejected (probing only, no successful response)."
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

# Deterministic CRLF chain at the access-log layer: 401 POST
# /login/?login_only=1 then 2xx GET /cpsess<N>/* as root from the same
# IP within 2s. cpsrvd 401s the POST but saveSession() has already minted
# the cpsess token. Survives mitigate purging (only needs access_log).
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
        # X-stack = ATTEMPT, not compromise; see INTERNAL-NOTES.md "v2.7.15".
        emit "logs" "ioc_cve_2026_41940_access_primitive" "warning" \
             "ioc_cve_2026_41940_crlf_access_chain" 4 \
             "count" "$crlf_hits" \
             "ts_epoch_first" "$crlf_ts_first" \
             "log_file" "$log" \
             "line" "${crlf_sample:0:240}" \
             "note" "$crlf_hits CRLF-bypass chain(s) in $log: POST /login → 401 then GET /cpsess<N>/* → 2xx as root within 2s. CVE-2026-41940 exploitation ATTEMPT — confirm compromise via Pattern A-L residue or session-file forensics (REVIEW)."
        # Record CRLF first epoch globally so downstream second-order
        # signals (ioc_attacker_ip_2xx_on_cpsess,
        # ioc_pattern_e_websocket_shell_hits) can demote pre-compromise
        # events to advisory tier instead of polluting host_verdict +
        # cluster-onset timeline.
        if [[ "$crlf_ts_first" =~ ^[0-9]+$ ]]; then
            LOGS_CRLF_CHAIN_FIRST_EPOCH="$crlf_ts_first"
        fi
    fi
}

# ---- session-store analyzer ----------------------------------------------
# Single awk pass per session file sets SF_* globals; emit_session() is the
# wrapper around emit() that attaches identity/provenance KPIs from the
# most recent analyze_session() call so every fleet record carries
# {user, src_ip, login_time, file_mtime, file_ctime, mtime_ctime_delta_sec}.
# login_time and file_mtime are forgeable; file_ctime is not.
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

            # IOC-A: token_denied + cp_security_token co-occur. Three-tier
            # mirrors cPanel's ioc_checksessions_files.sh. badpass call
            # site (Cpanel/Server.pm:1244-1252) cannot legitimately set
            # auth markers; saveSession (Cpanel/Session.pm:181) only
            # writes pass= when length>0.
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

            # IOC-H: standalone hasroot=1. Not in cpsrvd's _SESSION_PARTS
            # whitelist (Cpanel/Server.pm:2216-2247); no caller writes it.
            # Conclusive injection evidence regardless of other markers.
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

            # Gap 10: mtime/ctime divergence on a session file. cpsrvd
            # writes both atomically; divergence is `touch -d` backdating.
            # Advisory only — cp -p / tar xp / rsync -t restores also
            # produce divergence. Section-level count distinguishes
            # single-session forgery from fleet-wide restore artifacts.
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

    # Gap 10: section-level mtime-anomaly summary. Surfaced even when no
    # other IOCs fired so a host with quietly-backdated sessions doesn't
    # get a "no_session_iocs" all-clear. The count lets fleet aggregators
    # distinguish single-session forgery (likely real) from fleet-wide
    # restore artifacts (mass cp -p / tar xp - many sessions affected).
    if (( mtime_anomalies > 0 )); then
        emit "sessions" "session_mtime_anomaly_summary" "advisory" \
             "session_mtime_vs_ctime_anomaly_count" 0 \
             "count" "$mtime_anomalies" "scanned" "$scanned" \
             "threshold_sec" "$SESSION_MTIME_CTIME_THRESHOLD_SEC" \
             "note" "$mtime_anomalies of $scanned session(s) had mtime/ctime divergence >= ${SESSION_MTIME_CTIME_THRESHOLD_SEC}s - mtime is untrustworthy for cluster-onset analysis on these sessions (could be touch-d injection or cp -p / tar xp restore artifact)."
    fi

    # ---- (b) Mitigate-quarantine secondary read --------------------------
    # On hosts where sessionscribe-mitigate.sh ran, forged sessions have
    # been moved out of /var/cpanel/sessions/raw/ and into the quarantine
    # tree at $MITIGATE_BACKUP_ROOT/<RUN>/quarantined-sessions/raw/. The
    # live walk above sees an empty raw/ on those hosts, so without this
    # secondary path a previously-compromised host scans CLEAN. Sidecars
    # next to each quarantined file (`<sname>.info`) carry the original
    # mtime + IOC pattern letters that fired the quarantine - emit
    # synthetic signals from those fields so the kill-chain timeline
    # reflects when the attacker forged the session, not when we
    # quarantined it. Direct call (not `$( … )`) - subshell would discard
    # SIGNALS[] mutations from emit().
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

# Walk $MITIGATE_BACKUP_ROOT/*/quarantined-sessions/raw/ and emit one
# synthetic signal per quarantined session, derived from the .info sidecar
# (no re-run of the live IOC ladder, which is coupled to current host
# state). Writes hit count to global QUARANTINED_HITS - emit() mutates
# SIGNALS[] which would be lost in a `$( … )` subshell. Honors snapshot
# mode by reading from $ROOT_OVERRIDE when set. Capped at
# PATTERN_J_MAX_QUARANTINE total sessions to bound runtime on hosts with
# bulk-quarantine history.
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

            # High-confidence reasons → strong; see INTERNAL-NOTES.md "v2.7.20".
            local _q_sev=warning _q_wt=4
            if (( _has_sidecar )) && [[ -n "$q_reasons" ]] \
                && [[ "$q_reasons" =~ (cve_2026_41940_combo|hasroot_in_session|injected_token_used_with_2xx|token_denied_with_badpass_origin) ]]; then
                _q_sev=strong; _q_wt=10
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

# Pattern J detection - init-facility persistence (udev + systemd unit).
# Writes hit count to global PATTERN_J_HITS (not stdout) - emit() mutates
# the SIGNALS[] array, which would be lost in a `$( … )` subshell.
# Snapshot-aware: when ROOT_OVERRIDE is set, walks $ROOT_OVERRIDE-prefixed
# paths and demotes severity to info+degraded_confidence_snapshot=1 (no
# live rpmdb to cross-check). FP gates documented inline.
check_pattern_j_persistence() {
    PATTERN_J_HITS=0
    local hits=0
    local prefix=""
    [[ -n "${ROOT_OVERRIDE:-}" ]] && prefix="$ROOT_OVERRIDE"
    local snapshot_mode=0
    [[ -n "$prefix" ]] && snapshot_mode=1

    # ---- J1: udev rules with backgrounded RUN ----------------------------
    # Strong tier requires the pipe-to-`at now` shape (dossier-observed,
    # vanishingly rare in benign automation). nohup/setsid/disown forms
    # demote to warning - those are common in legit ad-hoc tooling.
    local d _udev_files=()
    for d in "${PATTERN_J_UDEV_DIRS[@]}"; do
        local _d="${prefix}${d}"
        [[ -d "$_d" ]] || continue
        # Find rule files modified in the last PATTERN_J_RECENT_DAYS days OR
        # all rule files (we want full coverage here - the FP gate is the
        # shape match below, not file age).
        while IFS= read -r f; do
            _udev_files+=("$f")
        done < <(find "$_d" -maxdepth 1 -type f -name '*.rules' 2>/dev/null)
    done

    if (( ${#_udev_files[@]} > 0 )); then
        # Shape probe: scan bodies once with grep, then RPM-filter only the hits.
        local _hit_shape_strong=()  _hit_shape_warn=()
        local f
        for f in "${_udev_files[@]}"; do
            # Strong: `| at now` (or `| at[[:space:]]+now`) inside a RUN value.
            if grep -qE 'RUN[+=]+=.*sh -c.*\|[[:space:]]*at[[:space:]]+now\b' "$f" 2>/dev/null; then
                _hit_shape_strong+=("$f")
            elif grep -qE 'RUN[+=]+=.*sh -c.*\b(nohup|setsid|disown)\b' "$f" 2>/dev/null; then
                _hit_shape_warn+=("$f")
            fi
        done

        # FP gate: not RPM-owned. In snapshot mode skip ownership check
        # (no rpmdb) and always demote tier by one notch.
        # bash 4.1 (CL6/EL6) + set -u trips 'unbound variable' on
        # ${arr[@]} for any declared-but-empty array; guard each
        # dereference with a length check.
        local _strong_unowned=() _warn_unowned=()
        if (( snapshot_mode )); then
            (( ${#_hit_shape_strong[@]} > 0 )) && _strong_unowned=("${_hit_shape_strong[@]}")
            (( ${#_hit_shape_warn[@]}   > 0 )) && _warn_unowned=("${_hit_shape_warn[@]}")
        else
            local _all=()
            (( ${#_hit_shape_strong[@]} > 0 )) && _all+=("${_hit_shape_strong[@]}")
            (( ${#_hit_shape_warn[@]}   > 0 )) && _all+=("${_hit_shape_warn[@]}")
            local _own_lines=""
            if (( ${#_all[@]} > 0 )); then
                _own_lines=$(bulk_rpm_owned_filter "${_all[@]}")
            fi
            local _rc _path
            while IFS=$'\t' read -r _rc _path; do
                [[ -z "$_path" ]] && continue
                # rc=0 owned, rc=1 not_owned, rc=2 no_probe (treat as warn)
                if [[ "$_rc" == "1" || "$_rc" == "2" ]]; then
                    local _is_strong=0
                    if (( ${#_hit_shape_strong[@]} > 0 )) \
                       && printf '%s\n' "${_hit_shape_strong[@]}" | grep -qxF "$_path"; then
                        _is_strong=1
                    fi
                    if (( _is_strong )); then
                        _strong_unowned+=("$_path")
                    else
                        _warn_unowned+=("$_path")
                    fi
                fi
            done <<< "$_own_lines"
        fi

        if (( ${#_strong_unowned[@]} > 0 )); then
            for f in "${_strong_unowned[@]}"; do
                local _mtime _run_line
                _mtime=$(stat -c %Y "$f" 2>/dev/null)
                _run_line=$(grep -m1 -E 'RUN[+=]+=.*sh -c.*\|[[:space:]]*at[[:space:]]+now\b' "$f" 2>/dev/null)
                local _sev=strong _wt=10 _conf=""
                if (( snapshot_mode )); then
                    _sev=info; _wt=2; _conf="degraded_confidence_snapshot=1; "
                fi
                emit "destruction" "ioc_pattern_j_udev_run" "$_sev" \
                     "ioc_pattern_j_udev_run_at_now" "$_wt" \
                     "path" "$f" "mtime_epoch" "${_mtime:-0}" \
                     "sample" "${_run_line:0:300}" \
                     "note" "${_conf}Pattern J1 udev rule at $f backgrounds shell via 'at now' and is not package-owned (CRITICAL)."
                ((hits++))
            done
        fi
        if (( ${#_warn_unowned[@]} > 0 )); then
            for f in "${_warn_unowned[@]}"; do
                local _mtime
                _mtime=$(stat -c %Y "$f" 2>/dev/null)
                emit "destruction" "ioc_pattern_j_udev_async" "warning" \
                     "ioc_pattern_j_udev_async_run" 4 \
                     "path" "$f" "mtime_epoch" "${_mtime:-0}" \
                     "note" "Pattern J1 candidate: udev rule at $f backgrounds shell (nohup/setsid/disown) and is not package-owned (REVIEW)."
                ((hits++))
            done
        fi
    fi

    # ---- J2: systemd units with non-allowlisted ExecStart ----------------
    # Walk /etc/systemd/system only (operator-customizable tree). Cap at
    # PATTERN_J_MAX_UNITS to bound walk-time on hosts with many units.
    local _unit_files=()
    for d in "${PATTERN_J_SYSTEMD_UNIT_DIRS[@]}"; do
        local _d="${prefix}${d}"
        [[ -d "$_d" ]] || continue
        while IFS= read -r f; do
            _unit_files+=("$f")
            (( ${#_unit_files[@]} >= PATTERN_J_MAX_UNITS )) && break
        done < <(find "$_d" -maxdepth 1 -type f -name '*.service' 2>/dev/null)
    done

    if (( ${#_unit_files[@]} > 0 )); then
        # Shape probe: extract ExecStart and Description per unit.
        local _suspicious_units=()
        local f
        for f in "${_unit_files[@]}"; do
            local _exec _desc _exec_path
            _exec=$(grep -m1 -E '^[[:space:]]*ExecStart[[:space:]]*=' "$f" 2>/dev/null \
                | sed -E 's/^[[:space:]]*ExecStart[[:space:]]*=[+!@-]*//' \
                | awk '{print $1}')
            [[ -z "$_exec" ]] && continue
            _exec_path="$_exec"
            # ExecStart shape: outside allowlist OR /usr/share/ root.
            if [[ "$_exec_path" =~ ^/usr/share/ ]] \
               || ! [[ "$_exec_path" =~ $PATTERN_J_EXECSTART_ALLOWED_RE ]]; then
                _suspicious_units+=("$f")
            fi
        done

        # RPM-filter both unit files AND their ExecStart binaries; both
        # must be not-RPM-owned to qualify as Pattern J (an unowned unit
        # pointing at an RPM-owned binary is a sysadmin custom unit;
        # an owned unit with an unowned binary is broken-but-benign).
        if (( ${#_suspicious_units[@]} > 0 )); then
            local _unit_unowned=()
            if (( snapshot_mode )); then
                _unit_unowned=("${_suspicious_units[@]}")
            else
                local _own_lines _rc _path
                _own_lines=$(bulk_rpm_owned_filter "${_suspicious_units[@]}")
                while IFS=$'\t' read -r _rc _path; do
                    [[ -z "$_path" ]] && continue
                    if [[ "$_rc" == "1" || "$_rc" == "2" ]]; then
                        _unit_unowned+=("$_path")
                    fi
                done <<< "$_own_lines"
            fi

            local f
            if (( ${#_unit_unowned[@]} > 0 )); then
                for f in "${_unit_unowned[@]}"; do
                    local _mtime _exec_path _desc _now _age _is_recent=0
                    _mtime=$(stat -c %Y "$f" 2>/dev/null)
                    _now=$(date -u +%s 2>/dev/null || echo 0)
                    _age=$(( _now - ${_mtime:-0} ))
                    (( _age < PATTERN_J_RECENT_DAYS * 86400 )) && _is_recent=1
                    _exec_path=$(grep -m1 -E '^[[:space:]]*ExecStart[[:space:]]*=' "$f" 2>/dev/null \
                        | sed -E 's/^[[:space:]]*ExecStart[[:space:]]*=[+!@-]*//' \
                        | awk '{print $1}')
                    _desc=$(grep -m1 -E '^[[:space:]]*Description[[:space:]]*=' "$f" 2>/dev/null \
                        | sed -E 's/^[[:space:]]*Description[[:space:]]*=//')

                    # Strong-tier conjunction: /usr/share/ ExecStart AND Description
                    # shadows known service AND mtime recent. Otherwise warning/4.
                    local _strong_match=0
                    if [[ "$_exec_path" =~ ^/usr/share/ ]] \
                       && [[ "$_desc" =~ $PATTERN_J_DESC_SHADOW_RE ]] \
                       && (( _is_recent )); then
                        _strong_match=1
                    fi

                    local _sev _wt _key
                    if (( snapshot_mode )); then
                        _sev=info; _wt=2
                        _key="ioc_pattern_j_systemd_unit_snapshot"
                    elif (( _strong_match )); then
                        _sev=strong; _wt=10
                        _key="ioc_pattern_j_systemd_unit_present"
                    else
                        # _candidate is too FP-prone alone; see INTERNAL-NOTES.md "v2.7.20".
                        _sev=advisory; _wt=2
                        _key="ioc_pattern_j_systemd_unit_candidate"
                    fi
                    emit "destruction" "ioc_pattern_j_systemd_unit" "$_sev" \
                         "$_key" "$_wt" \
                         "path" "$f" "mtime_epoch" "${_mtime:-0}" \
                         "exec_start" "${_exec_path:-}" \
                         "description" "${_desc:0:120}" \
                         "shadow_match" "$([[ "$_desc" =~ $PATTERN_J_DESC_SHADOW_RE ]] && echo 1 || echo 0)" \
                         "is_recent" "$_is_recent" \
                         "snapshot" "$snapshot_mode" \
                         "note" "Pattern J2 systemd unit at $f - non-allowlist ExecStart=$_exec_path and not package-owned."
                    ((hits++))
                done
            fi
        fi
    fi

    # ---- J3: literal IOC paths + payload references + processes + at-jobs --
    # Dossier-string checks (zero-FP); see INTERNAL-NOTES.md "v2.7.20".
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

# ---- _classify_history_match ---------------------------------------------
# Diagnostic-shape classifier hoisted from v2.7.5 Pattern C inline awk so
# Patterns C, F, H3 share one source of truth.
#   $1 mode  : "regex"   - <needle> is awk ERE (e.g. nuclear\.x86)
#              "literal" - <needle> is literal substring (e.g. __S_MARK__)
#   $2 needle: matcher per mode
#   $3.. files
# Output (one line): h=N d=N u=N fhe=EPOCH file_h=PATH
# Counts are AGGREGATE across all matched files (matches v2.7.5 Pattern C
# precedent); file_h is the file containing the first hostile-or-unknown
# match. fhe = embedded `#<epoch>` marker before that match - diagnostic-
# only matches do not pollute the kill-chain epoch.
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
# Pattern H2 adjacency classifier. `pkill -9 nuclear.x86 kswapd01 xmrig`
# is destructive on both attacker (prelude before drop) and responder
# (cleanup) paths, so diag_re shape doesn't apply - classify by what
# FOLLOWS within ctx command lines (epoch markers don't count).
#   hostile  : same line OR any next-ctx line matches install primitive
#              (wget|curl|fetch|tftp|base64 -d|chmod +x|<octal>|bash <(|./seobot)
#   diagnostic: next-ctx line matches ps|pgrep|echo|exit|true at line start
#              or is empty
#   unknown  : kill matched but neither condition - review tier
#   $1 file  $2 ERE (PATTERN_H_KILL_PRELUDE)  $3 ctx (default 3)
# Output: h=N d=N u=N fhe=EPOCH file_h=PATH
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
# Cheap, bounded host-state probes for late-stage compromise residue.
# Scoped to /home, /var/www, /root, /etc, /var/spool/cron, /tmp, /var/tmp -
# operator-overrideable via $CPANEL_ROOT? No: these paths are filesystem
# constants, not cpanel-prefixed. Snapshot mode (--root) skips most patterns
# but Pattern J does honor --root with degraded confidence (the udev/systemd
# trees ARE present in a snapshot).
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
        return
    fi
    hdr_section "destruct" "destruction IOC scan (Patterns A-J)"
    local hits=0

    # History files swept by Pattern F harvester and Pattern H markers
    # (kill-prelude, ALLDONE). Bash + zsh + sh + fish, root + every cPanel
    # user. Empty globs expand to literal pattern; grep handles missing
    # paths via 2>/dev/null. Hoisted once so both pattern blocks share
    # a single source of truth.
    local HISTORY_FILES_GLOB=(
        /root/.bash_history /root/.zsh_history /root/.sh_history
        /root/.local/share/fish/fish_history
        /home/*/.bash_history /home/*/.zsh_history /home/*/.sh_history
        /home/*/.local/share/fish/fish_history
    )

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
             "note" "found .sorry-encrypted files (Pattern A); re-run with --full for the full kill-chain + bundle (CRITICAL)."
        ((hits++))
    fi
    # qTox ransom README at /root/README.md (canonical) + /home/*/README.md
    # (per-user). Content/path-shape filter (added 2.7.6) demotes long files
    # (>200 lines = documentation, real ransom notes are <50 lines) and
    # IR-notes filename shapes to info-tier so responder docs that
    # reference the dossier TOX_ID hash don't FP-strong. Path-prefix
    # branches (^/root/(IR|notes|runbooks|.claude|.cache)/) are
    # future-proofing - the current candidate-file walk only reaches
    # /root/README.md + /home/*/README.md, none of which match those
    # subtrees; the filename-substring branches (IR-notes, runbook,
    # notes-<digit>) are the active filter for /home/*/README.md
    # operator-notes drops.
    local readme_hits=()
    [[ -f "$PATTERN_A_README" ]] && readme_hits+=("$PATTERN_A_README")
    while IFS= read -r rf; do
        [[ -f "$rf" ]] && readme_hits+=("$rf")
    done < <(find /home -maxdepth 2 -name 'README.md' 2>/dev/null)
    local _ir_paths_re='^/root/(IR|notes|runbooks|\.claude|\.cache)/|IR-notes|runbook|notes-[0-9]'
    # Length-check guard: ${arr[@]} on a declared-but-empty array trips
    # `set -u` on bash 4.1 (CL6). Matches the EXCLUDE_IPS pattern above.
    local rf
    if (( ${#readme_hits[@]} > 0 )); then
        for rf in "${readme_hits[@]}"; do
            if grep -qE "qtox|TOX ID|Sorry-ID|${PATTERN_A_TOX_ID}" "$rf" 2>/dev/null; then
                local rf_mtime tox_match=0 _rf_lines=0 _rf_doc_shape=0
                rf_mtime=$(stat -c %Y "$rf" 2>/dev/null)
                grep -qF "$PATTERN_A_TOX_ID" "$rf" 2>/dev/null && tox_match=1
                _rf_lines=$(wc -l < "$rf" 2>/dev/null | tr -d ' ')
                _rf_lines="${_rf_lines:-0}"
                if [[ "$rf" =~ $_ir_paths_re ]] || (( _rf_lines > 200 )); then
                    _rf_doc_shape=1
                fi
                if (( _rf_doc_shape )); then
                    emit "destruction" "ioc_pattern_a_readme_documentation" "info" \
                         "ioc_pattern_a_ransom_readme_documentation" 0 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
                         "note" "qtox/Sorry-ID/TOX_ID strings in $rf (lines=$_rf_lines) but file is in IR-notes path or too long for a ransom README - documentation-shape, not Pattern A drop."
                elif (( tox_match )); then
                    emit "destruction" "ioc_pattern_a_readme" "strong" \
                         "ioc_pattern_a_ransom_readme" 10 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
                         "note" "qTox ransom README at $rf (tox_id_exact_match=1, lines=$_rf_lines) - Pattern A drop (CRITICAL)."
                    ((hits++))
                else
                    emit "destruction" "ioc_pattern_a_readme_review" "warning" \
                         "ioc_pattern_a_ransom_readme_review" 5 \
                         "path" "$rf" "tox_id_match" "$tox_match" \
                         "line_count" "$_rf_lines" \
                         "mtime_epoch" "${rf_mtime:-0}" \
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
    local fe_count=0 fe_acct=0 fe_sample=""
    if [[ -d /var/log || -d /var/cpanel ]]; then
        fe_count=$(find /var/log /var/cpanel -maxdepth 6 -name '*.sorry' \
                       -not -path '*/imunify360/cache/*' 2>/dev/null | wc -l)
        fe_count="${fe_count:-0}"
        fe_count="${fe_count// /}"
        fe_sample=$(find /var/log /var/cpanel -maxdepth 6 -name '*.sorry' \
                        -not -path '*/imunify360/cache/*' 2>/dev/null | head -1)
    fi
    [[ -f /var/cpanel/accounting.log.sorry ]] && fe_acct=1
    if (( fe_count >= 10 )) || (( fe_acct == 1 )); then
        local fe_sev="strong" fe_weight=10 fe_mtime=0
        if (( fe_count < 10 && fe_acct == 1 )); then
            fe_sev="warning"; fe_weight=5
        fi
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
    # BTC index.html drops across /home users. Cohort observation:
    # nested drops appear at /home/<user>/public_html/<subdir>/index.html
    # (multiple sibling subdirs per user). -maxdepth 4 bounds the walk;
    # -name index.html filters before reading. -print0 + xargs -0
    # keeps a malicious user
    # dir name from breaking the pipeline. find errors quiet via 2>/dev/null
    # when /home/*/public_html glob is empty.
    local btc_hit=""
    btc_hit=$(find /home/*/public_html -maxdepth 4 -name index.html -print0 2>/dev/null \
                | xargs -0 grep -lF "$PATTERN_B_BTC_ADDR" 2>/dev/null | head -1)
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
    #
    # bash_history hits are classified hostile-shape vs diagnostic-shape
    # before emit. LW responders routinely run `history | grep -F
    # "nuclear.x86"` or `cat /root/.bash_history | grep nuclear.x86` post-
    # patch as part of an IR/QA check; without classification, every
    # checked host emits strong/COMPROMISED. Field-reported by V.Narayanan
    # + R.Poulose on 2026-05-03 against patched-clean cPanel hosts.
    # Hostile shape = download (wget/curl/fetch/tftp) / pipe-to-shell /
    # chmod +x / ./<bin> / source-eval-exec verb / bin-as-leading-token.
    # Diagnostic shape = read-only verb (history/cat/grep/find/ls/...) at
    # line start with no hostile verb anywhere.
    local nuke_files=()
    local _nf
    for _nf in /root/.bash_history /home/*/.bash_history; do
        [[ -f "$_nf" ]] && grep -qF "$PATTERN_C_BIN" "$_nf" 2>/dev/null \
            && nuke_files+=("$_nf")
    done
    if (( ${#nuke_files[@]} == 0 )); then
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
            # Hostile-shape line(s) present - real dropper trace; emit
            # strong as before, with classifier counts for IR triage.
            # mtime_epoch tracks the actual hostile-file (which may
            # differ from _nuke_sample when multiple history files match).
            local _hf="${_nfh_file:-$_nuke_sample}"
            local _hf_mtime
            _hf_mtime=$(stat -c %Y "$_hf" 2>/dev/null)
            emit "destruction" "ioc_pattern_c_nuke_trace" "strong" \
                 "ioc_pattern_c_nuclear_x86_referenced" 10 \
                 "sample_path" "$_hf" \
                 "mtime_epoch" "${_hf_mtime:-${_nuke_mtime:-0}}" \
                 "ts_epoch_first" "${_nfhe:-0}" \
                 "hostile_lines" "${_nh:-0}" \
                 "diagnostic_lines" "${_nd:-0}" \
                 "unknown_lines" "${_nu:-0}" \
                 "note" "$PATTERN_C_BIN dropper-shape command in $_hf (Mirai botnet drop, Abuse 46488376)."
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
    flame_hit=$(grep -lE "${PATTERN_C_C2_HOST}|${PATTERN_C_C2_IP//./\\.}|${PATTERN_C_C2_IP_2//./\\.}" \
                   /root/.bash_history /home/*/.bash_history 2>/dev/null | head -1)
    if [[ -n "$flame_hit" ]]; then
        local flame_mtime
        flame_mtime=$(stat -c %Y "$flame_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_c_c2_ref" "strong" \
             "ioc_pattern_c_c2_referenced" 8 \
             "sample_path" "$flame_hit" \
             "mtime_epoch" "${flame_mtime:-0}" \
             "note" "Mirai C2 ($PATTERN_C_C2_HOST / $PATTERN_C_C2_IP / $PATTERN_C_C2_IP_2) referenced in $flame_hit."
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
    # Reseller account presence - the accounting.log row may have rotated
    # OR been encrypted by Pattern A. /var/cpanel/users/<name> is cpanel's
    # canonical user record (written by createacct before any /etc/passwd
    # row materializes; survives Pattern A which only walks logs). getent
    # passwd is kept as a fallback for completeness.
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
    # Diagnostic-shape filter via shared _classify_history_match (same
    # primitive as v2.7.5 Pattern C). Without it `grep __S_MARK__
    # /root/.bash_history` (responder check) lands the literal in history
    # and the next scan fires strong/COMPROMISED on a clean host.
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
            emit "destruction" "ioc_pattern_f_harvester" "strong" \
                 "ioc_pattern_f_smark_envelope" 10 \
                 "sample_path" "$_f_sample" \
                 "ts_epoch_first" "${_ffhe:-0}" \
                 "mtime_epoch" "${_f_mtime:-0}" \
                 "hostile_lines" "${_fh:-0}" \
                 "diagnostic_lines" "${_fd:-0}" \
                 "unknown_lines" "${_fu:-0}" \
                 "note" "$PATTERN_F_S_MARK / $PATTERN_F_E_MARK harvester envelope in $_f_sample - automated post-exploit recon (CRITICAL)."
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

    # Pattern F additional marker: __CMD_DONE_<nanos>__ (rev5 dossier).
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
            emit "destruction" "ioc_pattern_f_cmd_done" "strong" \
                 "ioc_pattern_f_cmd_done_marker" 8 \
                 "sample_path" "$_fc_sample" \
                 "ts_epoch_first" "${_fcfhe:-0}" \
                 "mtime_epoch" "${_fc_mtime:-0}" \
                 "hostile_lines" "${_fch:-0}" \
                 "diagnostic_lines" "${_fcd:-0}" \
                 "unknown_lines" "${_fcu:-0}" \
                 "note" "Pattern F additional marker __CMD_DONE_<nanos>__ in $_fc_sample - same harvester actor toolchain as __S_MARK__/__E_MARK__."
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
    # IC-5790 fingerprint: mtime forged to 2019-12-13 + IP-shaped key
    # comment. Both required (LW provisioning legitimately uses IP-labeled
    # keys) so we don't FP on real ops. _g_hit feeds the lsyncd-
    # amplification check at end of this block.
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
            _g_hit=1
        fi
    fi

    # Pattern G lsyncd-amplification: master compromise = implicit
    # replica compromise via the cluster's replication keypair (Norman
    # Dumond, 5/3 dossier). Doesn't escalate THIS host's verdict but
    # surfaces blast-radius for remediation (revoke + reissue cluster
    # keypair, not just master's key).
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
    # Four signals: H1/H2-hostile/H4 each strong on their own; H3 (ALLDONE)
    # generic English so emits only when corroborated by H1, H2 (any tier
    # incl. review - kill-prelude line existing at all is corroboration
    # for the operator end-marker), or H4. H2 uses adjacency classifier
    # (pkill is destructive on both sides; diag_re shape check from C/F
    # doesn't apply).
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
        local h_mtime
        h_mtime=$(stat -c %Y "$h_seobot_hit" 2>/dev/null)
        emit "destruction" "ioc_pattern_h_seobot_php" "strong" \
             "ioc_pattern_h_seobot_dropper_present" 10 \
             "sample_path" "$h_seobot_hit" "mtime_epoch" "${h_mtime:-0}" \
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
            emit "destruction" "ioc_pattern_h_kill_prelude" "strong" \
                 "ioc_pattern_h_competitor_kill" 8 \
                 "sample_path" "$_hk_sample" \
                 "ts_epoch_first" "${_hk_fhe:-0}" \
                 "mtime_epoch" "${_hk_mtime:-0}" \
                 "hostile_lines" "$_hk_h_total" \
                 "diagnostic_lines" "$_hk_d_total" \
                 "unknown_lines" "$_hk_u_total" \
                 "note" "Pattern H competitor-kill prelude in $_hk_sample followed by install primitive (kills nuclear.x86/kswapd01/xmrig before drop)."
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
            local h_zip_mtime
            h_zip_mtime=$(stat -c %Y "$PATTERN_H_ZIP_PATH" 2>/dev/null)
            emit "destruction" "ioc_pattern_h_zip_dropper" "strong" \
                 "ioc_pattern_h_dropper_archive" 10 \
                 "path" "$PATTERN_H_ZIP_PATH" "mtime_epoch" "${h_zip_mtime:-0}" \
                 "note" "Pattern H dropper archive at $PATTERN_H_ZIP_PATH (base64 zip header matches H signature - operator did not self-clean)."
            ((hits++))
            _h4_hit=1
        fi
    fi

    # H3 deferred emit: corroboration-gated. ALLDONE alone is too generic
    # (responder `grep ALLDONE`, deployment `echo "ALLDONE"`, copy-pasted
    # CI output) to justify IR queue capacity. H2-review (kill prelude
    # with ambiguous adjacency: id/whoami/cd in ctx window) ALSO
    # corroborates - the kill-prelude line existing at all alongside an
    # ALLDONE marker is enough signal to surface for IR (sentinel finding).
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
        emit "destruction" "ioc_pattern_h_alldone" "warning" \
             "ioc_pattern_h_alldone_marker" 5 \
             "sample_path" "$_h_alldone_hit" \
             "mtime_epoch" "${_h_alldone_mtime:-0}" \
             "corroborated_by" "$_h_corrob" \
             "note" "Pattern H operator end-marker '$PATTERN_H_END_MARKER' in $_h_alldone_hit, corroborated by $_h_corrob."
        ((hits++))
    fi

    # ---- Pattern I: system-service profile.d backdoor --------------------
    # Three primary signals - profile.d hook, binary present, process
    # running. Any one is strong. I4 (failed-chmod log signature) is
    # corroborating evidence that confirms the hook actually fired for
    # non-root logins.

    # I1: profile.d hook file. Filename is unique per dossier; no benign
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

    # I2: binary at non-standard /root/.local/bin path. Capture mtime only;
    # forensic v0.10.1+ hashes the binary into bundle metadata.
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

    # I4: failed-chmod log signature in /var/log/secure (or rotation).
    # Discovery path: when a non-root user logs in via SSH, the profile.d
    # hook tries to chmod the binary, hits permission-denied, and logs
    # the failure to /var/log/secure. Confirms the hook is actively
    # firing in the wild.
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

    # ---- Pattern J: init-facility persistence (udev + systemd) ----------
    # Co-stage with Patterns G/I (post-RCE persistence). Walks udev rules
    # and /etc/systemd/system/ (operator-customizable tree only - skip
    # /usr/lib/systemd/ which is RPM territory). FP gates: (1) RPM ownership
    # via bulk_rpm_owned_filter (one rpmdb open per scan), (2) attacker-
    # specific shape match (`| at now` for J1; /usr/share/ ExecStart +
    # description-shadow for J2), (3) mtime within incident window for the
    # soft-shape branch. Direct call (not `$( … )`) - subshell would discard
    # SIGNALS[] mutations from emit().
    check_pattern_j_persistence
    hits=$((hits + PATTERN_J_HITS))

    # ---- Pattern E: websocket/Shell access-log signature ---------------
    # /cpsess<id>/websocket/Shell is WHM Terminal. Categorize per
    # (origin, status): external+2xx → strong (RCE landed); external+non-2xx
    # → warning; internal+2xx → info (admin Terminal); internal+non-2xx
    # → ignore. EXCLUDE_IPS suppresses known-good external admin IPs.
    local ws_log=/usr/local/cpanel/logs/access_log
    if [[ -f "$ws_log" ]]; then
        local excludes_env=""
        if (( ${#EXCLUDE_IPS[@]} > 0 )); then
            excludes_env=$(printf '%s\n' "${EXCLUDE_IPS[@]}")
        fi
        # Per-dimension breakout + handoff-burst detection: terminal
        # dimensions (rows×cols in the websocket Shell URL) function as
        # operator fingerprints across the dossier - distinct dimensions
        # imply distinct toolchains. The known-good set is maintained in
        # sync with PATTERNS.md; new dimensions are flagged warning-tier.
        # Handoff burst: >=2 distinct external IPs each landing a 2xx in
        # any 15-minute window indicates multi-operator exploit chaining.
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
                # Split ext_2xx by terminal dim: _known = IC-5790 attacker
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
                                # Capture the FIRST attacker-dim 2xx line as
                                # the canonical sample for the strong-emit
                                # structured fields. ext_sample (any external
                                # line) is preserved for fallback / lower-tier
                                # emits.
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
            # Pre-compromise gate. Pattern E is post-RCE toolchain, so
            # only count it as compromise evidence when (1) CRLF anchor
            # fired (ioc_cve_2026_41940_crlf_access_chain), AND (2) Pattern E
            # first epoch is within PATTERN_E_2XX_PROXIMITY_SEC of a
            # successful 2xx_on_cpsess. Otherwise demote to advisory: an
            # orphan Pattern E is most likely shared-infra coincidence or
            # pre-disclosure recon. Advisory still surfaces in signals[]
            # so ss-aggregate.py can discount it from cluster-onset.
            local _gate_sev="strong" _gate_key="ioc_pattern_e_websocket_shell_hits" _gate_weight=10
            local _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at IC-5790 attacker dimensions (${PATTERN_E_KNOWN_DIMS//,/ }) - Pattern E interactive RCE (CRITICAL)."
            if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )) \
               || ! [[ "$ts_first_ext" =~ ^[0-9]+$ ]] \
               || (( ts_first_ext == 0 )) \
               || (( ts_first_ext < LOGS_CRLF_CHAIN_FIRST_EPOCH )); then
                _gate_sev="advisory"
                _gate_key="ioc_pattern_e_websocket_shell_hits_pre_compromise"
                _gate_weight=0
                if (( LOGS_CRLF_CHAIN_FIRST_EPOCH == 0 )); then
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at IC-5790 attacker dimensions but NO CVE-2026-41940 CRLF access-chain detected on this host - Pattern E is post-RCE toolchain and requires CRLF anchor as compromise evidence. Likely shared-infra coincidence or pre-disclosure noise (REVIEW; does not escalate host_verdict)."
                else
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at IC-5790 attacker dimensions but ts_first ($ts_first_ext) PREDATES first CRLF chain ($LOGS_CRLF_CHAIN_FIRST_EPOCH) - pre-compromise activity (REVIEW; does not escalate host_verdict)."
                fi
            elif (( LOGS_2XX_CPSESS_FIRST_EPOCH > 0 )); then
                # Co-temporal proximity check vs. successful token-consumption
                # event. Compute |delta| via arithmetic + parameter-strip of
                # the leading sign. Skip the proximity demotion when 2xx_on_cpsess
                # did not fire at strong tier (LOGS_2XX_CPSESS_FIRST_EPOCH == 0):
                # in that case, the host has CRLF-anchored compromise but no
                # in-window token-use evidence, and Pattern E by itself is
                # still real RCE evidence (operator opened shell, didn't
                # subsequently re-use token). Strong stands.
                local _e_delta=$((ts_first_ext - LOGS_2XX_CPSESS_FIRST_EPOCH))
                local _e_abs="${_e_delta#-}"
                if (( _e_abs > PATTERN_E_2XX_PROXIMITY_SEC )); then
                    _gate_sev="advisory"
                    _gate_key="ioc_pattern_e_websocket_shell_hits_orphan"
                    _gate_weight=0
                    _gate_note="$ext_2xx_known external IP(s) reached /cpsess*/websocket/Shell with 2xx at IC-5790 attacker dimensions, post-CRLF, but ts_first ($ts_first_ext) is ${_e_abs}s away from successful token-use event ($LOGS_2XX_CPSESS_FIRST_EPOCH) - exceeds ${PATTERN_E_2XX_PROXIMITY_SEC}s operator-session window. Pattern E is exploitation-detached / orphan (REVIEW; does not escalate host_verdict)."
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
                 "note" "$ext_2xx_unknown external IP(s) reached /cpsess*/websocket/Shell with 2xx, but ALL dimensions ($unknown_csv) are outside the IC-5790 attacker fingerprint - likely legitimate WHM Terminal admin sessions from non-canonical browsers. Confirm via the parallel ioc_pattern_e_unknown_dimension review (REVIEW)."
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
    # K1 (PATTERN_K_BACKDOOR_HOST literal) routed through
    # _classify_history_match so responder `grep cp.dene` doesn't FP.
    # K2 (PATTERN_K_TMP_RE shape) corroborates K1; standalone emit only
    # when K1 didn't fire strong-or-warning (sentinel-driven gate -
    # diagnostic-only K1 must not silently swallow a real K2 signal).
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

    # K3 dropper-shape — survives C2 rotation; see INTERNAL-NOTES.md "v2.7.20".
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
    # L1 (PATTERN_L_NUKE_RE) routed through _classify_history_match for
    # diag-shape FP filtering. L2 (__CMD_START__/__CMD_END__ envelope)
    # corroborates L1; standalone emit only when L1 didn't fire strong-
    # or-warning (sentinel-driven gate parallel to K1/K2).
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
            emit "destruction" "ioc_pattern_l_filesystem_nuke" "strong" \
                 "ioc_pattern_l_no_preserve_root_rm" 10 \
                 "sample_path" "$_l1_sample" \
                 "ts_epoch_first" "${_l1fhe:-0}" \
                 "mtime_epoch" "${_l1_mtime:-0}" \
                 "hostile_lines" "${_l1h:-0}" \
                 "diagnostic_lines" "${_l1d:-0}" \
                 "unknown_lines" "${_l1u:-0}" \
                 "corroborated_by" "${_l_envelope_corrob:-(none)}" \
                 "note" "Pattern L filesystem-nuke (rm -rf --no-preserve-root /) in $_l1_sample - scorched-earth destruction, REIMAGE only (CRITICAL)."
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
        emit "destruction" "ioc_pattern_l_cmd_envelope" "warning" \
             "ioc_pattern_l_destructive_cmd_envelope" 4 \
             "sample_path" "$_l2_sample" \
             "mtime_epoch" "${_l_env_mtime:-0}" \
             "envelope_lines" "$((_l2_h + _l2_u))" \
             "note" "Pattern L __CMD_START__/__CMD_END__ destructive-command envelope in $_l2_sample without the rm -rf --no-preserve-root command itself - destructive-class harvester ran, manual review (command may have been rotated/redacted)."
        ((hits++))
    fi

    if (( hits == 0 )); then
        emit "destruction" "destruction_scan" "info" "no_destruction_iocs" 0 \
             "note" "no destruction-stage residue (Patterns A-L) found"
    fi
}

# ---- CSF firewall posture ------------------------------------------------
# Validates that ConfigServer Firewall is installed AND actually enforcing on
# the host. Fleet hosts are expected to run CSF; "installed but not loaded"
# (chains absent, lfd dead, TESTING=1, csf.disable, ipset gap) is a common
# silent-failure mode — the binary lives in PATH and the operator assumes
# protection while iptables is wide open.
#
# Severity discipline: posture findings are DEFENSIVE-degradation signals,
# not exploit IOCs. Keys use the `posture_` prefix (never `ioc_`) so they
# surface in the section matrix and JSON envelope without flipping
# host_verdict to SUSPICIOUS/COMPROMISED. The IOC engine is reserved for
# attacker-evidence rows.
#
# Probe ladder (each phase is independent; later phases run even when an
# earlier phase finds a fault, so a single run surfaces every break-mode):
#   1. presence              — csf binary + /etc/csf/csf.conf
#   2. csf.disable           — administrative kill-switch (advisory + return)
#   3. csf.conf missing      — broken install (binary without config)
#   4. TESTING=1             — production posture requires TESTING=0
#   5. lfd liveness          — pidfile → /proc/<pid>/comm → pidof/pgrep
#   6. iptables availability — binary on PATH or /sbin or /usr/sbin
#   7. csf -v self-test      — binary cannot self-report version
#   8. chain enumeration     — LOCALINPUT/LOCALOUTPUT/LOGDROPIN in iptables -nL
#   9. INPUT->LOCALINPUT     — orphaned-chain detection
#  10. LOCALINPUT rule count — chain hydrated (kill -9 mid-load FP)
#  11. LF_IPSET=1 promised   — ipset binary present, set list non-empty
#  12. healthy roll-up       — info-tier emit with rule_count, lfd_pid, version
#
# Snapshot mode (--root): all live probes skipped; emits a single info row.
# Bash 4.1 / set -u safe: every local initialized; no [[ -v ]]; no namerefs.
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
            # Per-section verdict: track worst tag observed per area.
            # Worst-wins ladder: [IOC] > [VULN] > [WARN] > [ADVISORY] > [OK].
            # local _tag="" re-initializes on each loop iteration (local is
            # function-scoped in bash, not loop-scoped; the declaration is
            # idempotent after the first pass). The per-iteration reset
            # prevents a high-tier tag from bleeding into the next SIGNALS[]
            # row when a later row's severity has no tag mapping.
            local _tag=""
            case "$sev" in
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
                   || [[ "$_cur" == "[ADVISORY]" && "$_tag" =~ ^\[(WARN|VULN|IOC)\]$ ]] \
                   || [[ "$_cur" == "[WARN]" && "$_tag" =~ ^\[(VULN|IOC)\]$ ]] \
                   || [[ "$_cur" == "[VULN]" && "$_tag" == "[IOC]" ]]; then
                    SECTION_VERDICT[$area]="$_tag"
                fi
            fi
            # Per-area roll-up counts (used in matrix detail column).
            case "$sev" in
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
            if [[ "$sev" == "strong" || "$sev" == "warning" || "$sev" == "evidence" || "$sev" == "advisory" ]]; then
                SECTION_KEYS[$area]="${SECTION_KEYS[$area]:-} $key"
            fi
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
                        # so operators see e.g. "ioc_attacker_ip_in_access_log_probes_only"
                        # even when host_verdict is SUSPICIOUS not COMPROMISED.
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
    fi

    SCORE="$score"
    STRONG_COUNT="$strong_count"
    FIXED_COUNT="$fixed_count"
    INCONCLUSIVE_COUNT="$inconclusive_count"
    ADVISORY_COUNT="$advisory_count"
    IOC_CRITICAL="$ioc_critical"
    IOC_REVIEW="$ioc_review"
    PROBE_ARTIFACT_COUNT="$probe_artifact_count"

    # Code-state axis. Version is authoritative: on 134+ tier, vulnerable
    # and patched cpsrvd binaries share ACL/token-reader strings, so the
    # binary fingerprint cannot discriminate.
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
    # SUSPICIOUS now exits 3 unconditionally (in all modes, including --ioc-only).
    # This disambiguates from code-state INCONCLUSIVE which keeps exit 2.
    if (( ioc_critical > 0 )); then
        HOST_VERDICT="COMPROMISED"
        EXIT_CODE=4
    elif (( ioc_review > 0 )); then
        HOST_VERDICT="SUSPICIOUS"
        EXIT_CODE=3
    else
        HOST_VERDICT="CLEAN"
    fi
}

# Per-section verdict matrix - mitigate-style 7-row table rendered at the
# top of print_verdict. Reads SECTION_VERDICT[] + SECTION_COUNTS[] populated
# by aggregate_verdict(). Each row: <tag> <section_label> <count_summary>.
# Areas with no signals render as [..] / "skipped".
print_section_matrix() {
    (( QUIET )) && return
    local area label tag counts color tok
    local n_ioc n_warn n_adv n_ok detail
    for area in "${SECTION_ORDER[@]}"; do
        label="${SECTION_LABEL[$area]:-$area}"
        tag="${SECTION_VERDICT[$area]:-[..]}"
        counts="${SECTION_COUNTS[$area]:-}"
        n_ioc=0; n_warn=0; n_adv=0; n_ok=0
        for tok in $counts; do
            case "$tok" in
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
            (( n_ioc  > 0 )) && detail+="${detail:+, }${n_ioc} ioc"
            (( n_warn > 0 )) && detail+="${detail:+, }${n_warn} warn"
            (( n_adv  > 0 )) && detail+="${detail:+, }${n_adv} advisory"
            (( n_ok   > 0 )) && detail+="${detail:+, }${n_ok} ok"
        fi
        color="$DIM"
        case "$tag" in
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
            sayf '  %s%-10s%s %s (%s)\n' "$CYAN" "[ADVISORY]" "$NC" "$adv_id" "$adv_key"
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
        printf '\n  ]\n'
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
    msg=$(printf 'run_id=%s host=%s code=%s host_verdict=%s exit=%d ioc_critical=%d ioc_review=%d' \
        "$RUN_ID" "$HOSTNAME_FQDN" "$VERDICT" "$HOST_VERDICT" \
        "$EXIT_CODE" "$IOC_CRITICAL" "$IOC_REVIEW")
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
    # Read host_verdict / score / tool_version from the envelope so the
    # forensic phases see consistent context.
    read_envelope_meta "$ENVELOPE_PATH"
    HOST_VERDICT="${ENV_HOST_VERDICT:-UNKNOWN}"
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
    # Gate priority (highest first):
    #   --chain-on-all       run forensic for EVERY host_verdict (overrides
    #                        --chain-on-critical AND the default CLEAN-skip).
    #                        Operator's explicit "I want everything" override.
    #   --chain-on-critical  run forensic only for COMPROMISED.
    #   (default --full)     run forensic for SUSPICIOUS / COMPROMISED;
    #                        skip CLEAN (we don't ship empty bundles by default).
    if (( CHAIN_ON_ALL )); then
        emit "summary" "forensic_run" "info" "forensic_chain_on_all" 0 \
             "host_verdict" "$HOST_VERDICT" \
             "note" "host_verdict=$HOST_VERDICT; --chain-on-all forces forensic phases regardless of verdict."
        RUN_FORENSIC=1
    elif (( CHAIN_ON_CRITICAL )) && [[ "$HOST_VERDICT" != "COMPROMISED" ]]; then
        emit "summary" "forensic_skip" "info" "forensic_skipped_below_critical" 0 \
             "host_verdict" "$HOST_VERDICT" \
             "note" "host_verdict=$HOST_VERDICT; --chain-on-critical limits forensic to COMPROMISED."
    elif [[ "$HOST_VERDICT" == "CLEAN" ]]; then
        emit "summary" "forensic_skip" "info" "forensic_skipped_clean" 0 \
             "note" "host_verdict=CLEAN; not running forensic phases (use --chain-on-all to override)."
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

    # Forensic summary signal (mirrors the old standalone forensic exit
    # logic, but now folded into the unified envelope + verdict). NO `local`
    # keyword — this code runs at top level (outside any function); local
    # would be a parse error. The names become globals; they're only read
    # in the emit() call below so the namespace pollution is harmless.
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
