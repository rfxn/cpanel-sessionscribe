#!/bin/bash
# sessionscribe-forensic.sh v0.99.0 (deprecation shim)
# (C) 2026, R-fx Networks <proj@rfxn.com> — GNU GPL v2
# DEPRECATED: forensic phases merged into sessionscribe-ioc-scan.sh v2.0.0.
# This shim delegates to ioc-scan --replay so existing one-liners still work.
# Switch to: sessionscribe-ioc-scan.sh --full | --replay PATH
# This shim will be removed in a future release. See PLAN.md and STATE.md.
VERSION="0.99.0"
case " $* " in
    (*\ --quiet\ *|*\ --jsonl\ *)
        : ;;
    (*)
        echo "DEPRECATED: sessionscribe-forensic.sh has been merged into sessionscribe-ioc-scan.sh (v2.0.0+)." >&2
        echo "  See https://github.com/rfxn/cpanel-sessionscribe for the new --full / --replay flags." >&2
        ;;
esac
# Resolve envelope: $SESSIONSCRIBE_IOC_JSON env > first .json/.tgz/.tar.gz arg.
ENVELOPE_PATH="${SESSIONSCRIBE_IOC_JSON:-}"
if [[ -z "$ENVELOPE_PATH" ]]; then
    for arg in "$@"; do
        case "$arg" in
            (*.json|*.tgz|*.tar.gz)
                ENVELOPE_PATH="$arg"
                break
                ;;
        esac
    done
fi
if [[ -z "$ENVELOPE_PATH" ]]; then
    echo "Error: sessionscribe-forensic.sh shim requires an envelope path." >&2
    echo "       Set SESSIONSCRIBE_IOC_JSON=<path> or run:" >&2
    echo "         sessionscribe-ioc-scan.sh --replay <envelope.json|bundle.tgz|bundle-dir>" >&2
    exit 3
fi
# Locate ioc-scan: sibling (version-checked) > CDN fetch > PATH > current dir.
# SELF_DIR resolution: BASH_SOURCE[0] is /dev/stdin or /dev/fd/N when run via
# curl | bash, so the sibling check falls through to the CDN fetch path.
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
IOC_PATH=""
# Check sibling — only accept it if it understands --replay (v2.0.0+).
if [[ -n "$SELF_DIR" && -f "$SELF_DIR/sessionscribe-ioc-scan.sh" ]]; then
    if grep -q -- '--replay' "$SELF_DIR/sessionscribe-ioc-scan.sh" 2>/dev/null; then
        IOC_PATH="$SELF_DIR/sessionscribe-ioc-scan.sh"
    fi
fi
# Check current dir (same version guard).
if [[ -z "$IOC_PATH" && -f "./sessionscribe-ioc-scan.sh" ]]; then
    if grep -q -- '--replay' "./sessionscribe-ioc-scan.sh" 2>/dev/null; then
        IOC_PATH="./sessionscribe-ioc-scan.sh"
    fi
fi
# Check PATH.
if [[ -z "$IOC_PATH" ]] && command -v sessionscribe-ioc-scan.sh >/dev/null 2>&1; then
    _p=$(command -v sessionscribe-ioc-scan.sh)
    if grep -q -- '--replay' "$_p" 2>/dev/null; then
        IOC_PATH="$_p"
    fi
fi
# CDN fetch fallback: when no local v2.0.0+ copy is available (e.g. curl | bash
# deploy of the shim where only the shim was fetched).
# SESSIONSCRIBE_IOC_SCAN_URL overrides the CDN URL (useful for pre-release testing).
if [[ -z "$IOC_PATH" ]]; then
    _tmpdir=$(mktemp -d 2>/dev/null || { echo "Error: mktemp failed" >&2; exit 3; })
    _fetched="$_tmpdir/sessionscribe-ioc-scan.sh"
    _cdn_url="${SESSIONSCRIBE_IOC_SCAN_URL:-https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh}"
    if curl -fsSL "$_cdn_url" -o "$_fetched" 2>/dev/null && [[ -s "$_fetched" ]]; then
        IOC_PATH="$_fetched"
    else
        rm -rf "$_tmpdir" 2>/dev/null
        echo "Error: sessionscribe-ioc-scan.sh not found (sibling, PATH, ., CDN)." >&2
        echo "       Fetch from https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh" >&2
        exit 3
    fi
fi
exec bash "$IOC_PATH" "$@" --replay "$ENVELOPE_PATH"  # delegates to sessionscribe-ioc-scan.sh
