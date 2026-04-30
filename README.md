<div align="center">

# SessionScribe - CVE-2026-41940

**Critical unauthenticated RCE in cPanel & WHM.**
Four HTTP requests forge a root session via CRLF injection into the
password field of a preauth session.
No auth, no preconditions, every supported tier affected.
Disclosed 2026-04-28 by Sina Kheirkhah / [watchTowr Labs](https://labs.watchtowr.com/).

<a href="https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940"><img src="https://img.shields.io/badge/%F0%9F%93%96%20full%20research-rfxn.com-22d3ee?style=for-the-badge&labelColor=09090b" alt="rfxn.com research article"></a>

[![CVE](https://img.shields.io/badge/CVE-2026--41940-d97757?labelColor=09090b)](https://support.cpanel.net/hc/en-us/articles/40073787579671)
[![Severity](https://img.shields.io/badge/severity-CRITICAL%20RCE-d44d4d?labelColor=09090b)](#priority-order)
[![Disclosed](https://img.shields.io/badge/disclosed-2026--04--28-22d3ee?labelColor=09090b)](https://support.cpanel.net/hc/en-us/articles/40073787579671)
[![License](https://img.shields.io/badge/license-GPL--2.0-22d3ee?labelColor=09090b)](LICENSE)
[![Hosted](https://img.shields.io/badge/hosted-sh.rfxn.com-4ade80?labelColor=09090b)](https://sh.rfxn.com/)

[Tools](#tools) · [Each tool](#each-tool) · [Affected builds](#affected-builds) · [Priority order](#priority-order) · [References](#references)

</div>

---

This repo is the operator-side toolkit: one-command active mitigation that
holds across patched and unpatched tiers, ModSec rules that work today, a
non-destructive remote probe for fleet sweeps, an on-host IOC scanner, and
the patch-diff snapshot collector behind the
[research article](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940).

```bash
# audit a single host (read-only)
curl -fsSLO https://sh.rfxn.com/sessionscribe-mitigate.sh
bash sessionscribe-mitigate.sh

# full remediation
bash sessionscribe-mitigate.sh --apply

# fleet roll-up - one CSV row per host (host, os, cpanel_version, ...)
bash sessionscribe-mitigate.sh --csv
```

> **The primitive in one paragraph.** CRLF injected into the `pass=` line
> of a preauth session splits the single line into multiple `key=value`
> lines on disk. Set `user=root`, `hasroot=1`, and
> `successful_internal_auth_with_timestamp`, and you've forged a
> root-authenticated session plus a working `cpsess` token. The
> [research article](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940)
> covers the patch dissection, the two composing asymmetries
> (`filter_sessiondata` not on every write path; encoder short-circuits
> on missing `ob_part`), and the architectural argument for proxy-endpoint
> enforcement.

---

## Tools

Filename links go to the canonical hosted copy on
[sh.rfxn.com](https://sh.rfxn.com/) (`curl`-ready); the per-tool docs
sections below have full usage detail.

| Artifact | Role | Where it runs |
|---|---|---|
| [`sessionscribe-mitigate.sh`](https://sh.rfxn.com/sessionscribe-mitigate.sh) | Active mitigation shim. One phased pass with fleet-friendly JSONL/CSV per host. [Docs](#sessionscribe-mitigatesh---defense-in-depth-shim) | On the cPanel host |
| [`modsec-sessionscribe.conf`](https://sh.rfxn.com/modsec-sessionscribe.conf) | ModSecurity rule pack. Phase-1 deny on the CVE primitive + adjacent WHM-token rules. [Docs](#modsec-sessionscribeconf---the-modsecurity-rule-pack) | Apache + mod_security2, in front of cpsrvd |
| [`sessionscribe-remote-probe.sh`](https://sh.rfxn.com/sessionscribe-remote-probe.sh) | Non-destructive remote probe. Verdict by HTTP code; canary-tagged sessions. [Docs](#sessionscribe-remote-probesh---non-destructive-verdict-per-host) | Anywhere with curl |
| [`sessionscribe-ioc-scan.sh`](https://sh.rfxn.com/sessionscribe-ioc-scan.sh) | Read-only on-host IOC scanner. Vendor IOCs + co-occurrence detector. [Docs](#sessionscribe-ioc-scansh---on-host-ioc-ladder) | On the cPanel host |
| [`sessionscribe-revsnap.sh`](https://sh.rfxn.com/sessionscribe-revsnap.sh) | Per-tier RE snapshot (binaries, strings, dynsym, disasm, Perl modules). [Docs](#sessionscribe-revsnapsh---re-snapshot-collector) | On the cPanel host, around `upcp` |

All shell scripts are GPL v2.

---

## How we got here

The first useful question after a security release is *what changed*. With
cPanel that is harder than it sounds. `cpsrvd` is a launcher/payload pair of
stripped ELF binaries with URL routing, login form parsing, and token
validation split across them; the Perl tree under `/usr/local/cpanel/Cpanel/`
and `Whostmgr/` carries the high-level handlers, but for this class of bug
the actual fix surface is compiled. There is no source release. To work the
diff, you have to capture the binaries pre and post upgrade and reason from
strings, dynsym, and disassembly outward.

That collector is `sessionscribe-revsnap.sh`. It produces a self-contained
tarball per tier so you can diff binaries, strings, and Perl source across
versions. From there the primitive falls out cleanly.

The primitive is **two asymmetries that compose**:

1. **`filter_sessiondata` is not on every write path.** `Cpanel::Session::create()`
   (the `/login/` form path) calls `filter_sessiondata()`, which strips CR/LF
   from string values before they hit disk. `Cpanel::Session::saveSession()`
   (the path used when an `Authorization: Basic` request lands on an
   existing session) does not. Anything written via `saveSession()` lands on
   disk verbatim.

2. **The encoder short-circuits on a missing `ob_part`.** The `whostmgrsession`
   cookie's canonical shape is `:NAME,OBHEX`. The OBHEX tail seeds the
   encoder for the `pass` field. `get_ob_part()` extracts it via the regex
   `s/,([0-9a-f]{1,64})$//`. Five cookie shapes fail this regex (no comma,
   trailing comma, non-hex tail, uppercase hex, hex tail >64 chars). When it
   fails, `$ob` stays undefined and `my $encoder = $ob && Encoder->new(...)`
   short-circuits - `$encoder` is false, the next-line `$encoder->encode_data`
   never runs, and `pass` is written through verbatim.

Compose them: with the encoder skipped *and* `saveSession()` not filtering, a
password supplied via `Authorization: Basic` is written to the on-disk
session file character for character. CR/LF inside the password splits the
single `pass=` line into multiple `key=value` lines. cpsrvd reads them back
as canonical session attributes. Set `successful_internal_auth_with_timestamp`,
`user=root`, and `hasroot=1`, and you have forged a logged-in root session.
The vendor advisory and watchTowr writeup document the request chain that
lands the resulting `cpsess` token.

The patch hex-encodes the whole `pass` value when ob_part is missing
(`pass=no-ob:<hex>`) and adds a companion `no-ob:` decode branch on the read
side. CR and LF become ASCII hex, the value can no longer split into
standalone `key=value` lines, and the invariant is encoded in the data
rather than in a single function call.

The full reverse-engineering walkthrough - including the auth-strings diff,
the 134-tier byte-identical-strings problem, and what we learned about the
adjacent identity-injection issue - is in the
[research article](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940).

---

## Each tool

### `sessionscribe-mitigate.sh` - defense-in-depth shim

One phased pass that walks a cPanel host into the documented mitigation
posture. Idempotent (re-run on a healthy host is a no-op), defaults to
`--check` (read-only), fleet-friendly output with `host`/`os`/
`cpanel_version` on every JSONL/CSV/JSON record.

| Phase | What it does |
|---|---|
| `patch` | `cpanel -V` vs the published patched-build list (incl. EL6 11.86.0.41 and WP Squared 136.1.7) |
| `preflight` | Removes `/etc/yum.repos.d/threatdown.repo`; ensures `epel-release`; disables broken non-base repos so `upcp` doesn't die mid-flight |
| `upcp` | If unpatched, kicks off `/scripts/upcp --force --bg` |
| `proxysub` | Enables `proxysubdomains` + new-account variant; rebuilds httpd conf |
| `csf` / `apf` / `runfw` | Strips cpsrvd ports (2082/2083/2086/2087/2095/2096) from `TCP_IN`/`TCP6_IN`/`IG_TCP_CPORTS`; verifies live iptables INPUT chain |
| `apache` | `httpd` running + `security2_module` loaded |
| `modsec` | `modsec2.user.conf` contains rules `1500030` + `1500031`; deploy if missing (timestamped backup, `httpd -t` validation, graceful reload) |
| `probe` (opt-in) | Run `sessionscribe-remote-probe.sh` against `127.0.0.1` to confirm denials in practice |

CentOS / Alma / Rocky base/appstream/extras/updates/powertools are *never*
disabled by the preflight sweep, even if currently unreachable. Mutations
write timestamped backups under `/var/cpanel/sessionscribe-mitigation/`
before touching any file.

```bash
# audit (read-only)
bash sessionscribe-mitigate.sh

# full remediation
bash sessionscribe-mitigate.sh --apply

# fleet aggregation
bash sessionscribe-mitigate.sh --jsonl > host.jsonl
bash sessionscribe-mitigate.sh --csv   > host.csv

# narrow scope
bash sessionscribe-mitigate.sh --apply --only modsec --probe
bash sessionscribe-mitigate.sh --only patch,preflight     # pre-upcp gate
```

<details>
<summary><b>Full <code>--help</code> reference</b> (click to expand)</summary>

```
sessionscribe-mitigate.sh v0.2.1
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
                           Phases: patch,preflight,upcp,proxysub,csf,apf,runfw,apache,modsec,probe
    --no-PHASE             Skip a phase. Per-phase opt-outs:
                             --no-patch     --no-preflight   --no-upcp
                             --no-proxysub  --no-csf         --no-apf
                             --no-runfw     --no-apache      --no-modsec
    --no-fw                Shorthand for --no-csf --no-apf --no-runfw.
    --probe                Enable the optional probe phase (opt-in).
                           Runs sessionscribe-remote-probe.sh against
                           127.0.0.1:2087; expects SAFE/blocked verdict.
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
                           (default: /var/cpanel/sessionscribe-mitigation).
    --yes, -y              Non-interactive; assume yes (no prompts).
    -h, --help             Show this help.

EXIT CODES
    0    clean - patched + posture ok, no action needed
    1    remediation applied successfully (--apply made changes)
    2    manual intervention required (warns in --check, or fail in --apply)
    3    tool error (bad args, missing dependencies, not root for --apply)
```

</details>

### `modsec-sessionscribe.conf` - the ModSecurity rule pack

One file, two surfaces: the CVE primitive and an adjacent `Authorization: WHM`
log-injection issue we surfaced during the analysis. ID range reserved is
`1500000–1500099`. Every deny runs in phase 1 - the request never reaches
the body inspector or the application.

| Rule | Surface | Action |
|---|---|---|
| `1500030` | CRLF inside `Authorization: Basic` decoded payload | deny, all sources, all paths |
| `1500031` | `whostmgrsession` cookie missing valid `,OBHEX` suffix | deny (defense-in-depth) |
| `1500010` | `Authorization: WHM` on `/json-api/`, `/execute/`, `/acctxfer*/` | deny when source not in trust list |
| `1500020` | `Authorization: WHM` on WebSocket dispatch family | deny when source not in trust list |
| `1500021` | `Authorization: WHM` on SSE dispatch path | deny when source not in trust list |

Rule 1500030 base64-decodes the `Authorization: Basic` payload in phase 1
and rejects on CR/LF in the decoded bytes. No legitimate Basic-auth value
decodes to bytes with newlines, so the rule has no trust-list bypass: it
applies to every source on every path. The WHM-token rules use
`@ipMatch` against an operator-defined trust list - edit the CIDRs at the
top of the file before deploying.

Caveat: these rules run inside Apache. The `cpsrvd` daemon listens directly
on its own ports (2082/2083/2086/2087/2095/2096) and is reachable
independent of Apache. **The rule pack only fires on traffic that traverses
Apache.** Pair it with cpsrvd-port firewalling to management CIDRs - the
"proxy-endpoint enforcement" section of the [research article](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940#going-forward)
is the canonical writeup of that posture.

```bash
curl -fsSLO https://sh.rfxn.com/modsec-sessionscribe.conf

# new install (modsec2.user.conf is empty by default)
cp modsec-sessionscribe.conf /etc/apache2/conf.d/modsec/modsec2.user.conf

# or append to an existing user.conf
sed -n '/^# === RULES ===/,$p' modsec-sessionscribe.conf \
    >> /etc/apache2/conf.d/modsec/modsec2.user.conf

# edit @ipMatch trust list, then
apachectl -t
/usr/local/cpanel/scripts/restartsrv_httpd
```

### `sessionscribe-remote-probe.sh` - non-destructive verdict per host

We did not want live exploit code on customer hosts even for verification.
The probe approximates the chain (mint preauth → inject CRLF → propagate
raw→cache → verify via `/json-api/version`) and then actively logs out.
Verdict-determining signal is the HTTP code at stage 4: `200`, or `5xx` with
a license body, is **VULNERABLE**; `401` or `403` is **SAFE**.

Every test session is tagged with an `nxesec_canary_<nonce>` attribute so
cleanup is wildcard-safe, and **no state-mutating API calls are made**.

```bash
# single host
bash sessionscribe-remote-probe.sh --target 1.2.3.4

# fleet - quiet, exit 2 on any VULN
bash sessionscribe-remote-probe.sh --target 1.2.3.4 --quiet --no-color
echo "exit=$?"

# CSV aggregation
bash sessionscribe-remote-probe.sh --csv \
    $(awk '{print "--target "$1}' fleet.txt) > fleet.csv

# JSON for parsing
bash sessionscribe-remote-probe.sh --target 1.2.3.4 --all --json | jq .

# clean canary sessions on a target after a run
bash sessionscribe-remote-probe.sh --cleanup
```

### `sessionscribe-ioc-scan.sh` - on-host IOC ladder

Patched build numbers are not enough. A patched host can still be carrying
forensic artifacts of prior exploitation. This script is the read-only
counterpart to the probe: it walks `/var/cpanel/sessions/raw/`, the access
logs, and the `cpsrvd` binary fingerprint, then returns two independent
verdict axes:

- **`code_verdict`** (`PATCHED` / `VULNERABLE` / `INCONCLUSIVE`) - from
  version, Perl source patterns, and binary fingerprint.
- **`host_verdict`** (`CLEAN` / `SUSPICIOUS` / `COMPROMISED`) - from the
  session-file IOC ladder and access-log scan.

The IOC set is the vendor pattern (token-injection, preauth-with-extauth,
tfa-with-bad-origin, multi-line `pass`) plus a four-way co-occurrence
detector and a forged-timestamp heuristic.

Exit codes (highest priority wins): `0` = PATCHED + CLEAN, `1` = VULNERABLE,
`2` = INCONCLUSIVE, `4` = COMPROMISED. A patched host can still exit `4` if
prior exploitation left IOCs on disk. Sessions tagged with the remote
probe's canary are bucketed as `PROBE_ARTIFACT` and do not escalate to
COMPROMISED.

```bash
# default sectioned report
bash sessionscribe-ioc-scan.sh

# JSONL for SIEM ingest
bash sessionscribe-ioc-scan.sh --jsonl --quiet > sessionscribe-host.jsonl

# fleet
ansible -i hosts all -m script -a 'sessionscribe-ioc-scan.sh --jsonl --quiet'
pdsh -w cpanel-fleet 'bash -s' < sessionscribe-ioc-scan.sh
```

### `sessionscribe-revsnap.sh` - RE snapshot collector

The same collector used for the patch dissection in the writeup. Run it
before each step of an upgrade, run `/scripts/upcp --force`, run it again.
Each invocation produces one tarball keyed off `cpanel -V`, host, and
timestamp. The captured collateral is built for BinDiff, Diaphora, and
plain text-diff workflows side by side.

```
cpanel-<ver>-<host>-<ts>/
├── binaries/                 cpsrvd, cpsrvd.so, cpanel, whostmgr, …
├── symbols/
│   ├── <bin>.strings         full strings dump
│   ├── <bin>.dynsym          nm -D
│   ├── <bin>.objdump-T       dynamic symbol table
│   ├── <bin>.readelf         full ELF metadata
│   ├── auth-strings/
│   │   ├── *.auth-strings.txt    auth|login|session|token|…
│   │   └── *.regex-candidates.txt PCRE-shaped strings
│   └── disasm/
│       └── *.objdump-d.gz    function-level disassembly
├── modules/
│   ├── Cpanel/{Auth,Session,Server,Cookies,…}
│   ├── Whostmgr/{Auth,Session,ACLS,…}
│   └── _so_files/            cpanel-only .so flattened
├── runtime/
│   ├── preauth-session-schema-sample.txt   anonymized baseline
│   ├── session-dir-layout.txt
│   └── cpsrvd-process-state.txt
└── meta/
    ├── full-tree-hashes.txt  sha256 of every .pm/.so/.pl/exec
    ├── rpms-cpanel-detailed.txt
    └── captured-collateral-rationale.txt
```

```bash
bash sessionscribe-revsnap.sh        # capture current tier
/scripts/upcp --force                # step upgrade
bash sessionscribe-revsnap.sh        # capture next tier
```

We're publishing this beyond just SessionScribe because it generalizes:
every future cpsrvd CVE will land in roughly the same surface, and having
a tarball pair for the pre-patch and patched build is the difference
between hours and days of analysis.

---

## Indicators of compromise

Forged session-file shape (contents of `/var/cpanel/sessions/raw/<sessname>`
after exploitation):

```
local_port=2087
hasroot=1
hulk_registered=1
pass=x
origin_as_string=address=127.0.0.1,app=whostmgrd,method=badpass
token_denied=1
local_ip_address=127.0.0.1
external_validation_token=cS9C19OfV0hCA4uD
cp_security_token=/cpsess6844364556
ip_address=127.0.0.1
user=root
tfa_verified=1
successful_internal_auth_with_timestamp=9999999999
port=39040
login_theme=cpanel
```

A normal preauth session never contains `pass=`, `hasroot=1`, `user=root`,
`tfa_verified=1`, or `successful_internal_auth_with_timestamp=`. Any of
those combined with `origin_as_string=…method=badpass` is diagnostic. A
forged-timestamp value beyond `now+365d` (e.g. `9999999999`) is
independently diagnostic.

```bash
for f in /var/cpanel/sessions/raw/*; do
  [ -f "$f" ] || continue
  if grep -q '^token_denied=' "$f" \
     && grep -q '^cp_security_token=' "$f" \
     && grep -q '^origin_as_string=.*method=badpass' "$f"; then
    echo "IOC0 hit: $f"
  fi
done
```

Access-log signal: successful `200`/`302`/`307` responses on `/json-api/`,
`/execute/`, or `/scripts2/` paths from non-baseline source IPs without a
preceding `/login/` 200 in the same session window.

---

## Affected builds

```
11.86.0.41 (EL6)   11.110.0.97   11.118.0.63   11.126.0.54
11.130.0.19        11.132.0.29   11.134.0.20   11.136.0.5

WP Squared:        136.1.7
```

Tiers excluded from the vendor patch list have **no in-place fix**: 112,
114, 116, 120, 122, 124, 128. Hosts on those tiers must be upgraded to a
patched major series, migrated, or have their cpsrvd listeners firewalled
until they are.

The 11.86.0.41 build for EL6 was added in the 04/29 advisory revision; 11.130
was bumped from `.18` to `.19` in the same revision.

---

## Priority order

**Immediate**
- Patch to the build for your tier (above).
- If the tier has no patch, firewall TCP/2082, 2083, 2086, 2087, 2095, 2096
  to management CIDRs immediately. Plan an upgrade or migration.
- Run `sessionscribe-ioc-scan.sh` fleet-wide. A patched host can still be
  compromised.

**Forward**
- Enable proxy subdomains so cPanel/WHM/Webmail are reachable through
  Apache on 80/443.
- Deploy `modsec-sessionscribe.conf` into `modsec2.user.conf` with the
  `@ipMatch` trust list set.
- Firewall TCP/2082, 2083, 2086, 2087, 2095, 2096 to management CIDRs only.
  Apache + ModSecurity becomes the sole public ingress.
- Standardize this proxy-endpoint posture as the default. The next cpsrvd
  advisory will land on the same six ports.

The architectural case for proxy-endpoint enforcement - why we're treating
SessionScribe as the moment to stop shipping cpsrvd to the open internet,
and how to do it without breaking customer ingress - is the closing third
of the [research article](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940#going-forward).

---

## References

- **Research article (full writeup):** [rfxn.com/research/cpanel-sessionscribe-cve-2026-41940](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940)
- **Vendor advisory:** [cPanel KB 40073787579671](https://support.cpanel.net/hc/en-us/articles/40073787579671)
- **Researcher writeup:** [watchTowr Labs](https://labs.watchtowr.com/)
- **Public PoC:** [watchtowrlabs/watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py](https://github.com/watchtowrlabs/watchTowr-vs-cPanel-WHM-AuthBypass-to-RCE.py)
- **Hosted scripts:** [sh.rfxn.com](https://sh.rfxn.com/)

## License

GPL v2 - see individual file headers. Additional IOCs or variant samples
welcome via [Keybase](https://keybase.io/rfxn) or
[email](mailto:ryan@rfxn.com).
