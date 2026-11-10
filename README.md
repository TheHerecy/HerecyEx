# HerecyEx
Blackbox Intelligence Group LLC

External recon and enumeration workflow for authorized penetration tests.

One Python 3 entry point, `external_recon_workflow.py`, takes a mixed target list (FQDNs, IPs, and CIDRs), runs a phased recon/enum pipeline, and writes a consolidated JSON, Markdown, and HTML report. The console keeps the Rich CLI: a banner, a stage panel per phase, status spinners while tools run, and a summary table at the end.

HerecyEx performs reconnaissance and read-only enumeration only. It does **not** exploit, does **not** password-spray or credential-brute, and does **not** run denial-of-service checks.

## Requirements

- Python 3.10+ (3.11/3.13 fine)
- Written authorization for every target in the list

Python packages are optional but recommended. `rich` draws the CLI; without it the same workflow still runs with plain text.

```bash
python3 -m pip install --user -r requirements.txt
```

`--help` and `--check-tools` work with the standard library alone. Missing OS or GitHub tools are detected at startup, warned about, and skipped. A missing tool does not crash the run.

### Install bootstrap (Kali)

```bash
# 1. Python extras
python3 -m pip install --user -r requirements.txt

# 2. Apt toolset + SecLists wordlists
sudo apt update
sudo apt install -y \
  whois dnsutils curl nmap ncat \
  theharvester dnsrecon amass massdns \
  fping masscan rustscan \
  whatweb wafw00f nikto \
  gobuster feroxbuster ffuf \
  eyewitness sslscan testssl.sh \
  enum4linux enum4linux-ng smbmap smbclient \
  onesixtyone snmp ldap-utils ssh-audit \
  seclists golang-go git chromium

# 3. ProjectDiscovery suite (subfinder, dnsx, httpx, naabu, nuclei, katana, tlsx)
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin:$HOME/.pdtm/go/bin"
go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -ia subfinder,dnsx,httpx,naabu,nuclei,katana,tlsx
nuclei -update-templates

# 4. Additional GitHub tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/sensepost/gowitness@latest

# 5. Confirm what the workflow can see
python3 external_recon_workflow.py --check-tools
```

Exact commands for every optional tool, including git and pipx fallbacks, live in the commented section of `requirements.txt`.

### httpx name collision

Many systems have the Python `httpx` CLI, which does **not** support `-l` or `-tech-detect`. HerecyEx looks in `~/go/bin`, `~/.pdtm/go/bin`, and `~/.local/bin` before PATH and only accepts ProjectDiscovery httpx. If the Python CLI is the only `httpx` it finds, HTTP probing is skipped with a warning.

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
export PATH="$HOME/go/bin:$PATH"
```

## Usage

```bash
# Inventory the box (no targets, no scans)
python3 external_recon_workflow.py --check-tools

# Standard authorized run
python3 external_recon_workflow.py -t targets.txt --authorized

# Faster first pass
python3 external_recon_workflow.py -t targets.txt --quick --authorized

# Thorough pass (content discovery on, deeper web checks)
python3 external_recon_workflow.py -t targets.txt --full --udp --authorized

# Passive OSINT + DNS only (no ping, no port scan, no HTTP)
python3 external_recon_workflow.py -t targets.txt --no-active --authorized

# Selected phases
python3 external_recon_workflow.py -t targets.txt --phases passive,resolve,report --authorized

# Drop anything not in an allowlist of CIDRs, IPs, or domain suffixes
python3 external_recon_workflow.py -t targets.txt --scope-check scope.txt --authorized

# Resume a previous output directory (skip existing tool output)
python3 external_recon_workflow.py --resume results/20261110-090000 --phases web,services,report --authorized
```

Without `--authorized`, HerecyEx prints the authorization banner and requires you to type `YES` in a TTY before it continues. A non-interactive run without `--authorized` exits and does not touch the targets.

### Target file format

One token per line. Blank lines, `#` comments, accidental commas, and duplicate entries are tolerated. Mix FQDNs, IPv4/IPv6 addresses, CIDRs, and URLs (scheme and path are stripped). See `targets.example.txt`.

```
# Client example — authorized scope
example.com
www.example.com
api.example.com
203.0.113.10
203.0.113.0/29
https://staging.example.com/login
```

CIDRs larger than `--max-cidr-hosts` (default 4096) are not expanded. Raise the limit only when that entire range is in scope.

Domains and IP addresses are split automatically. Subdomain enumeration runs for names. Pure IP targets skip that phase and go to resolution, HTTP probing, and port scanning.

### Flags

| Flag | Purpose |
|------|---------|
| `-t / --targets FILE` | Mixed target list |
| `-o / --output DIR` | Base output dir (a timestamped subdir is created). Default: `./results` |
| `--threads N` | Worker count (default 8) |
| `--rate SEC` | Minimum interval between tool launches |
| `--http-rate N` | httpx and nuclei rate (default 50). Content discovery is capped at 30 |
| `--naabu-rate N` | naabu packets per second (default 1000) |
| `--timeout SEC` | Default per-tool timeout (default 300) |
| `--phases LIST` | `passive,resolve,ports,web,services,report` or `all` |
| `--quick` / `--full` | Speed vs thoroughness profiles |
| `--no-active` | Passive OSINT + DNS only |
| `--scope-check FILE` | Allowlist; drop out-of-scope tokens |
| `--full-ports` | After top-ports, run `nmap -p-` (slow) |
| `--udp` | Opt-in UDP top-ports (needs root or passwordless sudo) |
| `--nuclei-severity` | e.g. `medium,high,critical` |
| `--no-nuclei` | Disable nuclei |
| `--direnum` / `--no-direnum` | Web content discovery (on by default with `--full`) |
| `--wordlist FILE` | Override the SecLists/dirb default |
| `--nikto` | Optional, off by default (noisy) |
| `--testssl` | Also run Kali `testssl` or upstream `testssl.sh` alongside sslscan |
| `--allow-intrusive-checks` | Opt in to open-relay, one VRFY probe, and empty-password DB scripts. Needs `--authorized`. Off by default. Per-engagement approval. |
| `--force` | Re-run even when output files already exist |
| `--resume DIR` | Continue a previous run |
| `--alive-only` | Drop ICMP non-responders (**not** recommended externally) |
| `--authorized` | Skip the interactive YES prompt |
| `--check-tools` | Print the tool inventory and exit |
| `--max-cidr-hosts N` | Refuse to expand a CIDR larger than this (default 4096) |
| `--nmap-timing N` | nmap `-T` value (default 4, or 3 with `--full-ports`) |

Nmap uses `-sS` (and `-sU` when `--udp` is set) if you are root or have passwordless `sudo -n`. Otherwise it falls back to TCP connect (`-sT`) and skips UDP. Service confirmation is `nmap -sV` only. `-sC` (`--script=default`) is not used: that category is whatever the installed Nmap calls default, and a script can override the HTTP library's redirect check. HerecyEx does not treat the category name as a scope boundary.

External hosts often drop ICMP. By default, **every in-scope IP is port-scanned** regardless of ping results. `--alive-only` changes that and is usually the wrong call for an external test.

## Phases

The CLI prints each phase as a stage panel. Inside a phase, work runs with a small worker pool. A missing binary is a warning and a skip.

### 1. `passive` — OSINT / subdomain discovery (domains only)

For each apex domain: `whois`, `dig` (A/AAAA/MX/NS/TXT/SOA/CAA), `subfinder`, `amass enum -passive`, `assetfinder`, a crt.sh JSON query, `theHarvester` (free sources), plus `gau` and `waybackurls` for historical URLs. `dnsrecon -t std` is not run, because it attempts a zone transfer. Discovered hostnames are de-duplicated and kept. They are not actively probed until resolution shows every address is in scope.

### 2. `resolve` — DNS resolution and liveness

`dnsx` (then massdns, then threaded `dig`) resolves names to A/AAAA. A name is eligible for later active probes only when every address is in scope. Otherwise it stays a candidate. Liveness is informational (`fping` or `nmap -sn`) and only for allowed addresses. The first `httpx` pass does not follow redirects. `--no-active` still resolves DNS but skips ping and httpx.

### 3. `ports` — Port discovery + service confirmation

A fast front-end is used when present, in this order: **naabu → rustscan → masscan**. masscan runs only with raw-socket privilege, at a conservative `--rate 500`. naabu uses `--naabu-rate` (default 1000) and `-exclude-cdn`. Open ports are then confirmed with `nmap -sV` (no `-sC`). If no front-end is available, nmap does discovery itself (`--top-ports 100` in `--quick`, `1000` otherwise). `--full-ports` adds a later `-p-` sweep. `--udp` adds a UDP top-ports pass.

### 4. `web` — Web and TLS enumeration

`httpx` (title, tech, status, server, TLS, Location header) on in-scope hosts only. It is not passed `-follow-redirects`. A Location pointing at another host is recorded and not requested. Then per-URL `whatweb` (`--follow-redirect=never`), `wafw00f -r`, `sslscan`, and `testssl` / `testssl.sh` with `--testssl` (or as a fallback when sslscan is absent). Kali's package installs the binary as `testssl`. Optional `tlsx`. Nuclei is rate-limited, always passed `-disable-redirects`, `-no-interactsh`, and `-exclude-tags dos,fuzz,intrusive,brute`, and writes JSONL (`-jsonl -o`). The parser also accepts a JSON array so an older export is not dropped. Content discovery (`feroxbuster`, then `gobuster`, then `ffuf`) does not pass a follow-redirect flag. It is modest, non-recursive, rate-capped, and off unless `--full` or `--direnum`.

Katana, gowitness, EyeWitness, and Nikto are not started. Their clients follow redirects onto other hosts and cannot be given a scope pin. That is a limit of those tools.

### 5. `services` — Service-specific enum from open ports

Only services that were actually observed get this pass. Script names containing brute, dos, flood, exploit, auth-bypass, or fuzz are refused.

| Service | Ports | What runs |
|---------|-------|-----------|
| FTP | 21 | nmap `ftp-anon,ftp-syst,ftp-feat` |
| SSH | 22 | nmap `ssh-auth-methods,ssh2-enum-algos,ssh-hostkey` + `ssh-audit` |
| SMTP | 25, 465, 587 | `smtp-commands` only. `smtp-vrfy` is not an NSE script. `smtp-enum-users` (one VRFY of `herecyex-probe`) and `smtp-open-relay` require `--allow-intrusive-checks` and `--authorized` |
| DNS | 53 | `dig AXFR` only at an in-scope server address, never at a third-party NS hostname |
| SMB | 139, 445 | nmap smb scripts (no `smb-brute`), `enum4linux-ng`, `smbmap` null session |
| SNMP | 161/udp | `onesixtyone` + `snmpwalk` with community **public** only |
| LDAP | 389, 636, 3268/9 | nmap ldap scripts, anonymous `ldapsearch` rootDSE |
| RDP | 3389 | `rdp-enum-encryption`, `rdp-ntlm-info` |
| VNC | 5900/5901 | `vnc-info`, `vnc-title` |
| MSSQL / MySQL | 1433, 3306 | info scripts only. `ms-sql-empty-password` and `mysql-empty-password` require `--allow-intrusive-checks` and `--authorized` |
| Other | 6379, 27017, 2375/6, 6443, 10250 | light nmap info/title probes |

### 6. `report` — Consolidated output

Always written at the end, including after an interrupt. Aggregates per-host ports and services, subdomains, web tech, notable nmap/nuclei/TLS items, and a **Findings of Interest** section. Those findings are leads to verify. The report states that they are **not confirmed exploits**. `confirmed_exploit` is always false.

## Output layout

```
results/<YYYYMMDD-HHMMSS>/
  herecyex.log
  run-meta.json
  state.json
  targets/          original + parsed domains, IPs, CIDRs, scope-drops
  passive/<apex>/   whois, dig, subfinder, amass, crt.sh, ...
  resolve/          dnsx/massdns/dig, ping, first httpx pass
  ports/            front-end output, nmap -oA (xml/nmap/gnmap)
  web/              httpx, nuclei, tlsx, per-URL tool output, screenshots
  services/<host>/  service-specific tool output
  reports/
    summary.json
    summary.md
    summary.html
    findings-of-interest.md
```

Re-running with `--resume` against the same directory skips existing non-empty output files unless you pass `--force`. Ctrl-C asks the run to stop after in-flight work and still writes the report. A second Ctrl-C exits immediately.

## Profiles

| | `--quick` | default (standard) | `--full` |
|--|-----------|--------------------|----------|
| TCP ports | top 100 | top 1000 | top 1000 (optional `-p-`) |
| Nuclei severity | high,critical | all | all |
| Content discovery | off | off | on (rate-limited, no recursion) |
| Katana crawl | off | off | off (cannot pin redirects) |

## Safety model

- Authorization is a gate. `--authorized` records that the operator already has written permission. Otherwise a TTY must answer `YES`. A non-interactive run without `--authorized` exits 3 and does not create an output directory. Piping the process (`python3 ... | tail`) masks that code: `$?` is then the pipe's last command, not HerecyEx. Check the Python process itself.
- `--scope-check` is fail-closed. A discovered name is actively probed only when it resolved and **every** address is inside the allowlist. A mixed or unresolved answer stays a candidate. Out-of-scope addresses are not port-scanned, passed to httpx, nuclei, or service enum, and are not AXFR targets. An allowlist with only domain suffixes cannot prove an address, so active probes of those names are not started.
- Without `--scope-check`, a domain-only list is the operator's responsibility and those names are probed. If the list contains any IP or CIDR, a name is probed only when every resolved address is inside that set. Unresolved names are not probed.
- Zone transfer is sent only to an in-scope address. `dnsrecon -t std` is not run, because it attempts AXFR before that check.
- Passive mode (`--no-active`) does not ping, port-scan, or send HTTP probes.
- Nuclei always excludes the `dos`, `fuzz`, `intrusive`, and `brute` tags, and is passed `-disable-redirects` and `-no-interactsh`. Exclude-tags are not treated as a scope boundary.
- No password wordlists, no community-string lists beyond `public`, no `smb-brute` / `ftp-brute` / `ssh-brute`, and no exploit or auth-bypass NSE scripts.
- `smtp-open-relay`, `smtp-enum-users`, `ms-sql-empty-password`, and `mysql-empty-password` do not run unless `--allow-intrusive-checks` and authorization are both set. The VRFY probe, when enabled, is the single name `herecyex-probe` with `unpwdb.userlimit=1` and `methods={VRFY}`.
- httpx is not told to follow redirects. whatweb is `--follow-redirect=never`. wafw00f is `-r`. Directory tools are not passed their follow-redirect flags. A Location to another host is not enqueued.
- Content discovery does not recurse and is capped at 30 requests/second.
- masscan, when used at all, is limited to 500 packets/second.
- Findings of interest are recon leads. The JSON, Markdown, and HTML reports say so in the disclaimer and on every finding.

### What the child tools still cannot promise

- DNS can change between the scope check and the probe. HerecyEx does not pin httpx or nuclei to the address it just resolved. A name that was entirely in-scope can later point somewhere else.
- A nuclei template can still request a URL it writes itself. `-disable-redirects` stops the HTTP client from following 3xx, including a template that sets `redirects: true`. It does not stop a template from naming another host.
- Nmap's HTTP library refuses a different host unless a script replaces `redirect_ok`. `-sC` is omitted because that set is not reviewed script by script. The explicit service scripts that remain do not include `http-title` or `http-methods`.
- enum4linux-ng, smbmap, ssh-audit, snmpwalk, and ldapsearch are given an in-scope address and do not follow HTTP redirects. They are not a redirect hop. They also are not a proof that every future flag of those tools stays on-box.
- Katana, gowitness, EyeWitness, and Nikto are skipped because they follow redirects onto other hosts and cannot be pinned.

### Bounded smoke after install

Replace the two TEST-NET-3 addresses with the two hosts that are actually in scope before running this. Do not add `--allow-intrusive-checks` or `--nikto`. This command is not run by the workflow itself.

```bash
printf '%s\n' '203.0.113.10' '203.0.113.11' > /tmp/herecy-two-hosts.txt
printf '%s\n' '203.0.113.10' '203.0.113.11' > /tmp/herecy-two-hosts.scope
python3 external_recon_workflow.py \
  -t /tmp/herecy-two-hosts.txt \
  --scope-check /tmp/herecy-two-hosts.scope \
  --authorized \
  --quick \
  --timeout 60 \
  -o ./results
```

## Legal

Only use this against systems you have written authorization to test. You are responsible for the contents of `--targets` and `--scope-check`. Findings of interest are recon leads, not proof of a vulnerability and not proof of exploitability.
