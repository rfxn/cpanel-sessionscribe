#!/bin/bash
#
# tests/run-session-tests.sh - phase_sessions IOC-ladder fixture driver.
#
# Extracts the awk block from sessionscribe-mitigate.sh phase_sessions and
# runs it standalone against fixtures in tests/sessions/. Asserts each
# fixture's reasons CSV against the expected (must-include) and forbidden
# (must-not-include) lists declared below. No mutation of host state.
#
# Usage:
#   bash tests/run-session-tests.sh                      # runs from repo root
#   bash tests/run-session-tests.sh --script PATH        # override script
#   bash tests/run-session-tests.sh --fixtures DIR       # override fixtures
#
# Exit codes:
#   0  all assertions passed
#   1  one or more assertions failed
#   2  test infrastructure error (awk extraction failed, fixtures missing)
#
# Floor: bash 4.1 / gawk 3.1 / coreutils 8.4 (CL6 EL6) - matches the
# production script.

set -u

SCRIPT="${SCRIPT:-$(dirname "$0")/../sessionscribe-mitigate.sh}"
FIXTURES="${FIXTURES:-$(dirname "$0")/sessions}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --script)    SCRIPT="$2"; shift 2 ;;
        --fixtures)  FIXTURES="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ -r "$SCRIPT" ]]    || { echo "ERROR: cannot read $SCRIPT" >&2; exit 2; }
[[ -d "$FIXTURES" ]]  || { echo "ERROR: fixtures dir missing: $FIXTURES" >&2; exit 2; }

# Extract the awk literal from the production script. The awk pipeline
# begins on a line ending in `... -v floor=...\` and the literal opens on
# the next line ending in `... -v canary_re="..." '`. The literal closes
# on a line beginning `' "$f" 2>/dev/null)`. Bash 4.1 / gawk 3.1 safe.
AWK_TMP=$(mktemp /tmp/ioc-ladder.XXXXXX.awk) || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$AWK_TMP"' EXIT
awk '
    /awk -v now=.*-v floor=/                       { in_block=1; next }
    in_block && /-v canary_re=.*[[:space:]]\x27[[:space:]]*$/ { in_awk=1; next }
    in_awk && /^[[:space:]]*\x27[[:space:]]*"\$f"[[:space:]]*2>\/dev\/null/ { exit }
    in_awk
' "$SCRIPT" > "$AWK_TMP"

if ! [[ -s "$AWK_TMP" ]]; then
    echo "ERROR: awk extraction returned empty - script structure changed?" >&2
    exit 2
fi

# Per-fixture assertions. Format: "fixture-name|expect-include|expect-exclude"
# Tokens are space-separated. Lookup is by IOC letter (A,B,C,D,D2,E,E2,F,H,I,2)
# matched as comma-bracketed substrings of the reasons CSV.
CASES=(
    "pos-d2-single-pass-on-badpass|D2|D E"
    "pos-2-tfa-fabricated-origin|2|E"
    "neg-benign-badpass||D2"
    "neg-benign-tfa-known-good||2 D2 E"
    "neg-d-supersedes-d2|D|D2"
    "neg-bp-tfa-stays-on-e|E|2"
)

NOW=$(date -u +%s)
PASS=0; FAIL=0
for c in "${CASES[@]}"; do
    name="${c%%|*}"; rest="${c#*|}"
    expect="${rest%%|*}"; not_expect="${rest#*|}"
    fix="$FIXTURES/$name"

    if [[ ! -f "$fix" ]]; then
        echo "  MISSING  $name (no fixture file at $fix)"
        FAIL=$((FAIL+1)); continue
    fi

    out=$(awk -v now="$NOW" -v floor=12 \
              -v canary_re='^nxesec_canary_[A-Za-z0-9]+=' \
              -f "$AWK_TMP" "$fix" 2>/dev/null) || {
        echo "  AWK_ERR  $name"; FAIL=$((FAIL+1)); continue
    }

    if [[ "$out" == FORGED:* ]]; then
        reasons="${out#FORGED:}"
    else
        reasons="$out"
    fi

    ok=1
    if [[ -n "$expect" ]]; then
        for tok in $expect; do
            if ! [[ ",$reasons," == *",$tok,"* ]]; then
                ok=0
                echo "  FAIL  $name: expected $tok in reasons (got: $reasons)"
            fi
        done
    fi
    if [[ -n "$not_expect" ]]; then
        for tok in $not_expect; do
            if [[ ",$reasons," == *",$tok,"* ]]; then
                ok=0
                echo "  FAIL  $name: forbidden $tok in reasons (got: $reasons)"
            fi
        done
    fi

    if (( ok )); then
        printf '  %sPASS%s  %-40s -> %s\n' $'\033[0;32m' $'\033[0m' "$name" "${reasons:-<clean>}"
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
done

echo
echo "Summary: $PASS pass / $FAIL fail"
exit $(( FAIL > 0 ? 1 : 0 ))
