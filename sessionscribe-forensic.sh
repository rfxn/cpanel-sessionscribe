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
# Locate ioc-scan: sibling > PATH > current dir.
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)
IOC_PATH=""
if [[ -n "$SELF_DIR" && -f "$SELF_DIR/sessionscribe-ioc-scan.sh" ]]; then
    IOC_PATH="$SELF_DIR/sessionscribe-ioc-scan.sh"
elif command -v sessionscribe-ioc-scan.sh >/dev/null 2>&1; then
    IOC_PATH=$(command -v sessionscribe-ioc-scan.sh)
elif [[ -f "./sessionscribe-ioc-scan.sh" ]]; then
    IOC_PATH="./sessionscribe-ioc-scan.sh"
else
    echo "Error: sessionscribe-ioc-scan.sh not found (sibling, PATH, or .)." >&2
    echo "       Fetch from https://raw.githubusercontent.com/rfxn/cpanel-sessionscribe/main/sessionscribe-ioc-scan.sh" >&2
    exit 3
fi
exec bash "$IOC_PATH" "$@" --replay "$ENVELOPE_PATH"  # delegates to sessionscribe-ioc-scan.sh
