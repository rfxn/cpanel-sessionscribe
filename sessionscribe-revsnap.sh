#!/bin/bash
#
##
# sessionscribe-revsnap.sh v1.4.0
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
# Per-tier reverse-engineering snapshot for cPanel/WHM upgrades.
#
# cPanel upgrades are non-reversible and a "minor" bump can rewrite both
# Perl modules and the cpsrvd binary. Run this once before each upgrade
# step to freeze a self-contained RE bundle for that exact version, so
# later you can diff binaries, strings, and Perl source across tiers.
#
# Usage:
#   ./sessionscribe-revsnap.sh              # writes to /var/tmp/cpanel-snapshots/
#   SNAPDIR=/path ./sessionscribe-revsnap.sh
#
# Workflow:
#   1. Snapshot current state (e.g. 124.0.30)
#   2. Upgrade one tier (124 -> 126)
#   3. Snapshot again (e.g. 126.x.y)
#   4. Repeat for each step you want to diff
#
# Each run produces one tarball + sha256, keyed off `/usr/local/cpanel/cpanel -V`.
# RPM packages are not included (use yumdownloader / dnf download separately).

set -u
SNAPDIR="${SNAPDIR:-/var/tmp/cpanel-snapshots}"
HOST=$(hostname -s)
TS=$(date -u +%Y%m%dT%H%M%SZ)

# --- Version detection ---
# `cpanel -V` returns "X.Y (build Z)" which isn't filename-safe; normalize to X.Y.Z.
RAW_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null | head -1 | tr -d '\r')
VER=$(echo "$RAW_VER" | sed -E 's/^([0-9.]+)[[:space:]]+\(build[[:space:]]+([0-9]+)\).*/\1.\2/')
if [ -z "$VER" ] || [ "$VER" = "$RAW_VER" ]; then
  VER="unknown-$(date +%s)"
  echo "[!] WARNING: could not parse version from: $RAW_VER" >&2
fi

WORK="${SNAPDIR}/cpanel-${VER}-${HOST}-${TS}"
mkdir -p "$WORK"/{binaries,symbols,modules,meta,runtime}

echo "[+] snapshot: cpanel ${VER} on ${HOST}"
echo "[+] working : ${WORK}"

# --- Meta: version + RPM inventory ---
echo "$RAW_VER" > "$WORK/meta/cpanel-version-raw.txt"
echo "$VER"     > "$WORK/meta/cpanel-version-normalized.txt"
cp /usr/local/cpanel/version "$WORK/meta/usrlocal-version" 2>/dev/null
cp /var/cpanel/version       "$WORK/meta/varcpanel-version" 2>/dev/null
rpm -qa | grep -iE 'cpanel|whm' | sort > "$WORK/meta/rpms-cpanel.txt"
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{INSTALLTIME:date}\n' 2>/dev/null \
  | grep -iE 'cpanel|whm' | sort > "$WORK/meta/rpms-cpanel-detailed.txt"
{ cat /etc/redhat-release 2>/dev/null; cat /etc/os-release 2>/dev/null; } \
  > "$WORK/meta/os-release.txt"
uname -a > "$WORK/meta/uname.txt"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$WORK/meta/captured-at-utc.txt"

# --- Core service binaries ---
# cpsrvd ships as a launcher + .so payload pair; either half can carry a fix.
# whostmgr / whostmgr2 are the WHM dispatch binaries.
for bin in \
  /usr/local/cpanel/cpsrvd \
  /usr/local/cpanel/cpsrvd.so \
  /usr/local/cpanel/cpsrvd-ssl \
  /usr/local/cpanel/cpanel \
  /usr/local/cpanel/whostmgr/bin/whostmgr \
  /usr/local/cpanel/whostmgr/bin/whostmgr2 \
  /usr/local/cpanel/bin/cpsrvd-init \
  /usr/local/cpanel/bin/cpwrap \
  /usr/local/cpanel/bin/cpkeyclt \
  /usr/local/cpanel/bin/cpses_tool \
  /usr/local/cpanel/bin/checkallsslcerts
do
  [ -e "$bin" ] || continue
  cp -a "$bin" "$WORK/binaries/" 2>/dev/null
done

# --- Fallback ELF sweep ---
# Layout shifts between tiers; this catches binaries we didn't list explicitly.
for searchdir in \
  /usr/local/cpanel \
  /usr/local/cpanel/bin \
  /usr/local/cpanel/whostmgr/bin \
  /usr/local/cpanel/cgi-sys
do
  [ -d "$searchdir" ] || continue
  find "$searchdir" -maxdepth 1 -type f \( -executable -o -name '*.so' \) 2>/dev/null | \
  while read -r bin; do
    name=$(basename "$bin")
    [ -e "$WORK/binaries/$name" ] && continue
    if file "$bin" 2>/dev/null | grep -q ELF; then
      cp -a "$bin" "$WORK/binaries/" 2>/dev/null
    fi
  done
done

# --- Symbol/metadata extraction per binary ---
for bin in "$WORK/binaries/"*; do
  [ -f "$bin" ] || continue
  name=$(basename "$bin")
  file "$bin" > "$WORK/symbols/${name}.file" 2>/dev/null
  if file "$bin" 2>/dev/null | grep -q ELF; then
    nm -D       "$bin" > "$WORK/symbols/${name}.dynsym"     2>/dev/null
    objdump -T  "$bin" > "$WORK/symbols/${name}.objdump-T"  2>/dev/null
    readelf -a  "$bin" > "$WORK/symbols/${name}.readelf"    2>/dev/null
    ldd         "$bin" > "$WORK/symbols/${name}.ldd"        2>/dev/null
  fi
  strings -a -n 8 "$bin" > "$WORK/symbols/${name}.strings"  2>/dev/null
done

# --- Pre-filtered string sets for cross-version diff ---
# Full strings dumps are noisy; auth/session/token strings + route-dispatch
# regexes are the high-leverage subset for spotting handler changes between tiers.
mkdir -p "$WORK/symbols/auth-strings"
for bin in "$WORK/binaries/"*; do
  [ -f "$bin" ] || continue
  file "$bin" 2>/dev/null | grep -q ELF || continue
  name=$(basename "$bin")
  strings -a -n 8 "$bin" 2>/dev/null | \
    grep -iE 'auth|login|session|password|token|xauth|cookie|csrf|2fa|otp|hmac|secret|nonce' \
    > "$WORK/symbols/auth-strings/${name}.auth-strings.txt"
  strings -a -n 8 "$bin" 2>/dev/null | \
    grep -E '\^|\\\.|\(\?:' | grep -iE 'auth|login|session|cpanel|whm|webmail|cgi' \
    > "$WORK/symbols/auth-strings/${name}.regex-candidates.txt"
done

# --- Perl module subtrees ---
# Skip /usr/local/cpanel/3rdparty/ (upstream CPAN; rarely involved in cPanel-side bugs).
#
# For every captured subtree, also grab the sibling parent .pm one level up.
# A recursive copy of Cpanel/Session/ alone misses Cpanel/Session.pm - the
# package file that holds the namespace's public API (saveSession, write_*,
# filter_*, etc.). The parent .pm is almost always the entry point.
for path in \
  /usr/local/cpanel/Cpanel/Auth \
  /usr/local/cpanel/Cpanel/Session \
  /usr/local/cpanel/Cpanel/Server \
  /usr/local/cpanel/Cpanel/Security \
  /usr/local/cpanel/Cpanel/AccessIds \
  /usr/local/cpanel/Cpanel/PwCache \
  /usr/local/cpanel/Cpanel/LoadModule \
  /usr/local/cpanel/Cpanel/Login \
  /usr/local/cpanel/Cpanel/Validate \
  /usr/local/cpanel/Cpanel/Exception \
  /usr/local/cpanel/Cpanel/Config \
  /usr/local/cpanel/Cpanel/HTTP \
  /usr/local/cpanel/Cpanel/AdminBin \
  /usr/local/cpanel/Cpanel/FileUtils \
  /usr/local/cpanel/Cpanel/Encoder \
  /usr/local/cpanel/Cpanel/Rand \
  /usr/local/cpanel/Whostmgr/Auth \
  /usr/local/cpanel/Whostmgr/Session \
  /usr/local/cpanel/Whostmgr/Login
do
  [ -d "$path" ] || continue
  rel=$(echo "$path" | sed 's|^/usr/local/cpanel/||')
  mkdir -p "$WORK/modules/$rel"
  cp -a "$path/." "$WORK/modules/$rel/" 2>/dev/null

  parent_pm="${path}.pm"
  if [ -f "$parent_pm" ]; then
    parent_rel="$(dirname "$rel")"
    mkdir -p "$WORK/modules/$parent_rel"
    cp -a "$parent_pm" "$WORK/modules/$parent_rel/" 2>/dev/null
  fi
done

# --- Individually-named .pm files ---
# These carry session/cookie/file-IO/serializer primitives that are routinely
# load-bearing for auth analysis but don't always live under one of the
# subtrees above. Explicit capture survives upstream tree reorganization.
for srcfile in \
  /usr/local/cpanel/Cpanel/Session.pm \
  /usr/local/cpanel/Cpanel/Server.pm \
  /usr/local/cpanel/Cpanel/Cookies.pm \
  /usr/local/cpanel/Cpanel/Auth.pm \
  /usr/local/cpanel/Cpanel/SafeFile.pm \
  /usr/local/cpanel/Cpanel/SV.pm \
  /usr/local/cpanel/Cpanel/Config/LoadConfig.pm \
  /usr/local/cpanel/Cpanel/Config/FlushConfig.pm \
  /usr/local/cpanel/Cpanel/Config/Session.pm \
  /usr/local/cpanel/Cpanel/AdminBin/Serializer.pm \
  /usr/local/cpanel/Cpanel/HTTP/QueryString.pm \
  /usr/local/cpanel/Cpanel/FileUtils/Write.pm \
  /usr/local/cpanel/Cpanel/Encoder/URI.pm \
  /usr/local/cpanel/Cpanel/Rand/Get.pm \
  /usr/local/cpanel/Cpanel/JSON.pm \
  /usr/local/cpanel/Cpanel/App.pm \
  /usr/local/cpanel/Cpanel/Logger.pm
do
  [ -f "$srcfile" ] || continue
  rel=$(echo "$srcfile" | sed 's|^/usr/local/cpanel/||')
  mkdir -p "$WORK/modules/$(dirname "$rel")"
  cp -a "$srcfile" "$WORK/modules/$rel" 2>/dev/null
done

# --- WHM ACL gate + exception/validation primitives ---
# Whostmgr/ACLS{,.pm} resolves hasroot()/checkacl()/init_acls(). Cpanel/Exception
# carries cpsrvd's Forbidden/AccessDenied response bodies. Username validation
# is a common gate target - captured both as a subtree (above) and explicitly.
for srcfile in \
  /usr/local/cpanel/Whostmgr/ACLS.pm \
  /usr/local/cpanel/Whostmgr/ACLS \
  /usr/local/cpanel/Cpanel/Exception.pm \
  /usr/local/cpanel/Cpanel/Validate/Username/Core.pm
do
  [ -e "$srcfile" ] || continue
  rel=$(echo "$srcfile" | sed 's|^/usr/local/cpanel/||')
  mkdir -p "$WORK/modules/$(dirname "$rel")"
  if [ -d "$srcfile" ]; then
    cp -a "$srcfile/." "$WORK/modules/$rel/" 2>/dev/null
  else
    cp -a "$srcfile" "$WORK/modules/$rel" 2>/dev/null
  fi
done

# --- All cPanel-owned shared objects (excludes 3rdparty CPAN) ---
mkdir -p "$WORK/modules/_so_files"
find /usr/local/cpanel -name '*.so' -type f \
  -not -path '*/3rdparty/*' \
  -not -path '*/cache/*' \
  -not -path '*/var/*' \
  2>/dev/null | while read -r so; do
    rel=$(echo "$so" | sed 's|^/usr/local/cpanel/||' | tr '/' '_')
    cp -a "$so" "$WORK/modules/_so_files/$rel" 2>/dev/null
done

# --- Web frontend auth/login route templates ---
for path in \
  /usr/local/cpanel/base/unprotected \
  /usr/local/cpanel/base/webmail \
  /usr/local/cpanel/base/frontend
do
  [ -d "$path" ] || continue
  rel=$(echo "$path" | sed 's|^/usr/local/cpanel/||')
  destbase="$WORK/modules/$rel"
  mkdir -p "$destbase"
  ( cd "$path" && find . -maxdepth 4 -type f \
      \( -name '*login*' -o -name '*auth*' -o -name '*session*' \) \
      -exec cp --parents {} "$destbase/" \; ) 2>/dev/null
done

# --- Full-tree hash inventory ---
# Lets you identify what changed between snapshots without bundling the whole tree.
find /usr/local/cpanel \
  \( -name '*.pm' -o -name '*.so' -o -name '*.pl' -o -name '*.cgi' -o -perm -u+x \) \
  -type f \
  -not -path '*/3rdparty/*' \
  -not -path '*/logs/*' \
  -not -path '*/tmp/*' \
  -not -path '*/cache/*' \
  -not -path '*/var/*' \
  2>/dev/null | xargs -r sha256sum 2>/dev/null | sort -k2 \
  > "$WORK/meta/full-tree-hashes.txt"

# --- Function-level disassembly ---
# Same-tier security patches frequently land with zero string deltas - only
# function logic differs. Disasm dumps unblock BinDiff / Diaphora workflows
# when string-level diff comes up empty. ~30-150 MB per binary; gzipped.
mkdir -p "$WORK/symbols/disasm"
for name in cpsrvd cpsrvd.so cpanel whostmgr whostmgr2; do
  bin="$WORK/binaries/$name"
  [ -f "$bin" ] || continue
  file "$bin" 2>/dev/null | grep -q ELF || continue
  objdump -d --no-show-raw-insn "$bin" 2>/dev/null | gzip -c \
    > "$WORK/symbols/disasm/${name}.objdump-d.gz"
done

# --- Runtime artifacts (anonymized) ---
# One redacted preauth session file as a schema reference. Knowing the
# baseline shape of a normal session - which fields exist, which don't -
# is the cleanest way to spot anomalies in later forensic review.
{
  echo "# Anonymized sample from /var/cpanel/sessions/raw/ at snapshot time."
  echo "# Token-bearing values redacted to <REDACTED>."
  echo "# Use as a baseline schema for what a normal preauth session contains."
  echo "# ---"
  sample=$(ls /var/cpanel/sessions/raw/ 2>/dev/null | head -1)
  if [ -n "$sample" ] && [ -f "/var/cpanel/sessions/raw/$sample" ]; then
    sed -E '
      s/(token=)[A-Za-z0-9_/.-]+/\1<REDACTED>/g;
      s/(cp_security_token=)[^[:space:]]+/\1<REDACTED>/g;
      s/(external_validation_token=)[^[:space:]]+/\1<REDACTED>/g;
      s/(pass=).*/\1<REDACTED>/;
    ' "/var/cpanel/sessions/raw/$sample"
  else
    echo "# (no session file present at snapshot time)"
  fi
} > "$WORK/runtime/preauth-session-schema-sample.txt"

# Session-dir listing only - no per-session bodies.
{
  echo "# /var/cpanel/sessions/{raw,preauth,cache} layout. Filenames only."
  for sub in raw preauth cache; do
    echo "## /var/cpanel/sessions/$sub/"
    if [ -d "/var/cpanel/sessions/$sub" ]; then
      ls -la "/var/cpanel/sessions/$sub/" 2>/dev/null | head -50
    fi
    echo ""
  done
} > "$WORK/runtime/session-dir-layout.txt"

# cpsrvd PID + start time - anchor for "was the daemon restarted post-upgrade?"
{
  pgrep -fa '^/usr/local/cpanel/cpsrvd' 2>/dev/null | head -5
  echo ""
  ps -eo pid,etime,cmd 2>/dev/null | grep -E 'cpsrvd|whostmgrd' | grep -v grep | head -10
} > "$WORK/runtime/cpsrvd-process-state.txt"

# --- Captured-collateral rationale ---
# Self-documenting note inside the tarball so a later analyst can orient
# without context from this script.
cat > "$WORK/meta/captured-collateral-rationale.txt" <<'RATIONALE'
What this snapshot contains and why
====================================

PURPOSE
  Per-tier RE collateral for cPanel/WHM upgrades. One tarball = one version.
  Diff across tarballs to identify code changes between tiers.

binaries/
  cpsrvd, cpsrvd.so, cpsrvd-ssl, cpanel, whostmgr, whostmgr2, and any other
  ELF objects under /usr/local/cpanel{,/bin,/whostmgr/bin,/cgi-sys}.
  cpsrvd is split launcher (cpsrvd) + payload (.so); fixes can land in
  either half, so capture both.

symbols/
  Per-binary `nm -D`, `objdump -T`, `readelf -a`, `ldd`, `strings` dumps,
  plus `file` output. Used for ABI-level diff and library-graph review.

symbols/auth-strings/
  Pre-filtered strings: auth/login/session/token/cookie/csrf/2fa/otp/hmac
  plus regex-shaped strings (route dispatchers). Highest-signal subset for
  cross-version diff - far less noise than the full strings dump.

symbols/disasm/
  gzipped `objdump -d` for cpsrvd, cpsrvd.so, cpanel, whostmgr, whostmgr2.
  Required when string-level diff is empty (same-tier patches frequently
  ship without string deltas). Feeds BinDiff / Diaphora.

modules/
  cPanel-owned Perl source under /usr/local/cpanel/{Cpanel,Whostmgr}/...
  3rdparty/ deliberately omitted (upstream CPAN, low signal).
  For each captured subtree, the sibling parent .pm one level up is also
  captured (e.g. Cpanel/Session.pm next to Cpanel/Session/). Parent .pm
  files hold the namespace's public API and are the typical entry point;
  a recursive directory copy alone misses them.

modules/_so_files/
  Flat copy of every cPanel-owned .so under /usr/local/cpanel (excludes
  3rdparty/, cache/, var/). Path separators rewritten to underscores so
  the flat directory is unambiguous.

modules/base/
  Login/auth/session frontend assets from base/{unprotected,webmail,frontend}.

meta/
  Version strings (raw + normalized), RPM inventory, OS release, uname,
  capture timestamp, and full-tree sha256 hash inventory. The hash file
  is the cheap diff: compare two snapshots' full-tree-hashes.txt to
  enumerate every changed file without unpacking the tarball.

runtime/
  preauth-session-schema-sample.txt - one anonymized session file from
    /var/cpanel/sessions/raw/. Establishes the baseline field set for a
    normal preauth session at this version.
  session-dir-layout.txt - directory listings of the raw/preauth/cache
    split (filenames only, no bodies).
  cpsrvd-process-state.txt - running PID + etime. Anchors questions like
    "was cpsrvd restarted after the upgrade?".

INTENTIONAL OMISSIONS
  - 3rdparty/ (upstream Perl/CPAN; high volume, low signal)
  - logs/, tmp/, cache/, session bodies (privacy + size; one redacted
    sample only, in runtime/)
  - RPM packages (download separately with yumdownloader / dnf download)
RATIONALE

# --- Bundle, hash, cleanup ---
TARBALL="${SNAPDIR}/cpanel-${VER}-${HOST}-${TS}.tar.gz"
cd "$SNAPDIR" || { echo "[!] cd $SNAPDIR failed" >&2; exit 1; }
tar -czf "$TARBALL" "$(basename "$WORK")"
sha256sum "$TARBALL" > "${TARBALL}.sha256"
SIZE=$(du -h "$TARBALL" | cut -f1)
rm -rf "$WORK"

echo
echo "[+] DONE"
echo "    tarball : ${TARBALL}"
echo "    size    : ${SIZE}"
echo "    sha256  : $(cut -d' ' -f1 "${TARBALL}.sha256")"
echo
echo "[+] snapshots in ${SNAPDIR}:"
ls -lh "${SNAPDIR}/"cpanel-*.tar.gz 2>/dev/null | awk '{print "    "$NF" ("$5")"}'
