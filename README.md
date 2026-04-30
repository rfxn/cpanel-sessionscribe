# SessionScribe - CVE-2026-41940

Detection, mitigation, and reverse-engineering tooling for **CVE-2026-41940**,
the unauthenticated session-forgery vulnerability in cPanel & WHM disclosed
on 2026-04-28 ([cPanel KB 40073787579671](https://support.cpanel.net/hc/en-us/articles/40073787579671)).

> **The bug.** CRLF injection into the password field of a preauth session
> promotes attacker input into canonical session attributes. Outcome is a
> logged-in root session and a root-equivalent `cpsess` token. Severity is
> the maximum the rubric allows: remote code execution as root, no
> authentication, no preconditions, every supported tier affected.

**Researcher credit:** Sina Kheirkhah ([@SinSinology](https://twitter.com/SinSinology)) of
[watchTowr Labs](https://labs.watchtowr.com/).

**Full writeup:** [rfxn.com/research/cpanel-sessionscribe-cve-2026-41940](https://rfxn.com/research/cpanel-sessionscribe-cve-2026-41940).
Covers the patch dissection, primitive walk-through, and the architectural
argument for proxy-endpoint enforcement.

---

## The easy button: `sessionscribe-mitigate.sh`

If you operate cPanel at scale and want a single command that walks a host
into the full SessionScribe mitigation posture, that's what
[`sessionscribe-mitigate.sh`](./sessionscribe-mitigate.sh) is for. One
phased pass, idempotent, fleet-friendly output, drop-in for any
config-management or SSH-loop pipeline.

What it actually does, in order:

- **patch** - reads `cpanel -V`, compares to the published patched-build list
  (incl. EL6 11.86.0.41 and WP Squared 136.1.7); if behind, kicks off
  `/scripts/upcp --force --bg` in the background.
- **preflight** - removes `/etc/yum.repos.d/threatdown.repo` if present,
  installs `epel-release` if missing, probes every enabled repo and
  disables the broken non-base ones so `upcp` doesn't die mid-flight.
  CentOS / Alma / Rocky base/appstream/extras/updates/powertools are
  *never* touched, even if they happen to be unreachable.
- **proxysub** - turns on `proxysubdomains` and the new-account variant via
  `whmapi1`, then rebuilds the Apache vhost config so customer ingress
  flows through Apache (where ModSec can intercept) instead of straight
  to cpsrvd.
- **csf / apf / runfw** - scrubs the six cpsrvd ports
  (2082/2083/2086/2087/2095/2096) out of `TCP_IN`, `TCP6_IN`,
  `IG_TCP_CPORTS`; reloads csf/apf; walks the running iptables INPUT
  chain (and every chain it references) to confirm no `ACCEPT` rule
  still matches those ports from `0.0.0.0/0`.
- **apache / modsec** - verifies `httpd` is up and `security2_module` is
  loaded; checks `modsec2.user.conf` for rules `1500030` + `1500031` and,
  if missing, fetches the source (local downloads, then `sh.rfxn.com`),
  appends from the `# === RULES ===` anchor with a timestamped backup,
  validates `httpd -t`, and graceful-reloads.
- **probe (opt-in via `--probe`)** - runs `sessionscribe-remote-probe.sh`
  against `127.0.0.1` to confirm the rules deny in practice, not just
  on paper.

Built for fleet roll-outs:

- Defaults to `--check` (read-only); `--apply` is required to mutate state.
- Idempotent - re-running on a healthy host is a no-op, no backup churn.
- `--only PHASES` lets you pin scope, e.g. `--only modsec,csf` for a daily
  drift check, or `--only patch,preflight` as the front of an upcp wave.
- `--no-PHASE` opt-outs (`--no-upcp`, `--no-modsec`, `--no-fw`) for the
  inverse.
- Every JSONL/CSV/JSON record carries `host`, `os`, `cpanel_version`,
  `ts`, `tool_version`, `mode`, `phase`, `severity`, `key`, `note` so
  fleet aggregators can attribute every signal to its source without
  joining tables.
- Timestamped backups written to `/var/cpanel/sessionscribe-mitigation/`
  before any mutation; `httpd -t` validation gates the modsec deploy.

```bash
# audit a single host
bash sessionscribe-mitigate.sh

# full remediation
bash sessionscribe-mitigate.sh --apply

# fleet collection
bash sessionscribe-mitigate.sh --jsonl > host.jsonl
bash sessionscribe-mitigate.sh --csv   > host.csv

# narrow scope
bash sessionscribe-mitigate.sh --apply --only modsec --probe
bash sessionscribe-mitigate.sh --only patch,preflight     # pre-upcp gate
```

Exit codes are designed for fleet aggregation: `0` clean, `1` remediation
applied, `2` manual intervention required, `3` tool error.

---

## What's in the repo

| Artifact | Role | Where it runs |
|---|---|---|
| [`sessionscribe-mitigate.sh`](./sessionscribe-mitigate.sh) | Defense-in-depth active mitigation. One phased pass: patch / preflight / upcp / proxysub / csf / apf / runfw / apache / modsec / probe. Fleet-friendly JSONL+CSV with host/os/cpanel-version per record | On the cPanel host |
| [`modsec-sessionscribe.conf`](./modsec-sessionscribe.conf) | ModSecurity rule pack - phase-1 deny on the CVE primitive, plus three rules for an adjacent WHM-token log-injection issue | Apache + mod_security2, in front of cpsrvd |
| [`sessionscribe-remote-probe.sh`](./sessionscribe-remote-probe.sh) | Non-destructive remote probe. Verdict by HTTP code; canary-tagged sessions for safe cleanup | Anywhere with curl |
| [`sessionscribe-ioc-scan.sh`](./sessionscribe-ioc-scan.sh) | Read-only on-host scanner. Vendor IOCs + four-way co-occurrence + forged-timestamp heuristics | On the cPanel host |
| [`sessionscribe-revsnap.sh`](./sessionscribe-revsnap.sh) | Per-tier RE snapshot collector (binaries, strings, dynsym, disasm, Perl modules) | On the cPanel host, around `upcp` |

All shell scripts are GPL v2.

The canonical hosted versions are at `https://sh.rfxn.com/<filename>` if
you'd rather `curl`-pipe than clone.

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
