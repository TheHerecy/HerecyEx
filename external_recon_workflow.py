#!/usr/bin/env python3
"""
HerecyEx — External recon and enumeration workflow.

Blackbox Intelligence Group LLC
Authorized external assessments only. Recon and read-only enumeration.
No exploitation, no credential brute force, no denial of service.

Usage:
    python3 external_recon_workflow.py --check-tools
    python3 external_recon_workflow.py -t targets.txt --authorized
    python3 external_recon_workflow.py -t targets.txt --quick --authorized
    python3 external_recon_workflow.py -t targets.txt --no-active --authorized
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

__version__ = "2.1.0"
__author__ = "Blackbox Intelligence Group LLC"
__tool__ = "HerecyEx"

# Nuclei must never run these template tags. Enforced in run_nuclei().
NUCLEI_EXCLUDED_TAGS = "dos,fuzz,intrusive,brute"

# nmap script names containing any of these tokens are refused.
_UNSAFE_NMAP_SCRIPT = re.compile(r"brute|dos|flood|exploit|auth-bypass|fuzz", re.I)

# ---------------------------------------------------------------------------
# Optional third-party imports — the script must still run --help and
# --check-tools with the standard library only.
# ---------------------------------------------------------------------------
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.theme import Theme

    HAS_RICH = True
except ImportError:  # pragma: no cover - optional dependency
    HAS_RICH = False
    box = Console = Panel = Table = Theme = None  # type: ignore

try:
    import requests as _requests

    HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    HAS_REQUESTS = False
    _requests = None

try:
    from jinja2 import Template as _JinjaTemplate

    HAS_JINJA2 = True
except ImportError:  # pragma: no cover
    HAS_JINJA2 = False
    _JinjaTemplate = None

try:
    import dns.resolver as _dns_resolver  # noqa: F401

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PHASES = ("passive", "resolve", "ports", "web", "services", "report")

WEB_PORTS = {80, 443, 81, 300, 591, 593, 832, 981, 1010, 1311, 2082, 2083,
             2086, 2087, 2095, 2096, 2480, 3000, 3128, 3333, 4243, 4443,
             4567, 4711, 4712, 4993, 5000, 5104, 5108, 5280, 5281, 5601,
             5800, 6543, 7000, 7001, 7396, 7474, 8000, 8001, 8008, 8014,
             8042, 8069, 8080, 8081, 8083, 8088, 8090, 8091, 8118, 8123,
             8172, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8530,
             8531, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080,
             9090, 9091, 9200, 9443, 9800, 9981, 10000, 10250, 10443,
             11371, 12443, 15672, 16080, 18091, 18092, 20720, 28017}

SERVICE_PORT_MAP = {
    "ftp": {21},
    "ssh": {22},
    "smtp": {25, 465, 587, 2525},
    "dns": {53},
    "http": WEB_PORTS,
    "kerberos": {88},
    "pop3": {110, 995},
    "rpc": {111, 135},
    "imap": {143, 993},
    "snmp": {161, 162},
    "ldap": {389, 636, 3268, 3269},
    "smb": {139, 445},
    "mssql": {1433, 1434},
    "oracle": {1521},
    "nfs": {2049},
    "mysql": {3306},
    "rdp": {3389},
    "sip": {5060, 5061},
    "vnc": {5900, 5901},
    "postgres": {5432},
    "winrm": {5985, 5986},
    "redis": {6379},
    "k8s": {6443, 10250},
    "docker": {2375, 2376},
    "mongodb": {27017},
    "elasticsearch": {9200, 9300},
}

# Conservative default TCP discovery sets
QUICK_TOP_PORTS = 100
FULL_TOP_PORTS = 1000
UDP_TOP_PORTS_QUICK = 20
UDP_TOP_PORTS_FULL = 50

# Directory-enumeration wordlists, first match wins
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

SNMP_COMMUNITIES = ["public"]  # default community only — not a community brute

ADMIN_TITLE_HINTS = (
    "phpmyadmin", "wp-admin", "wordpress", "jenkins", "grafana", "kibana",
    "vcenter", "vsphere", "esxi", "horizon", "tomcat", "weblogic", "jira",
    "confluence", "gitlab", "gitea", "portainer", "cockpit", "webmin",
    "cpanel", "plesk", "sonarqube", "nexus", "harbor", "rancher", "vault",
    "keycloak", "authentik", "prometheus", "alertmanager", "traefik",
    "nodered", "n8n", "roundcube", "zabbix", "nagios", "prtg", "solarwinds",
    "fortigate", "fortinet", "palo alto", "cisco", "sonicwall", "watchguard",
    "ubiquiti", "unifi", "proxmox", "synology", "qnap", "idrac", "ilo ",
    "ipmi", "imm ", "xclarity", "dell openmanage", "hp system management",
    "outlook web", "owa ", "exchange", "adfs", "okta", "citrix", "netscaler",
    "vpn", "anyconnect", "pulse secure", "globalprotect", "admin login",
    "administrator login", "router", "firewall", "nas login", "camera",
)

LEGAL_BANNER = """
================================================================
  HerecyEx  v{version}  —  Blackbox Intelligence Group LLC
  External recon & enumeration workflow
================================================================

  This tool is for AUTHORIZED external penetration tests only.
  Running it against systems you do not have written permission
  to assess may be illegal.

  The workflow performs reconnaissance and read-only enumeration.
  It does not exploit, does not password-brute or spray, and
  does not conduct denial-of-service testing.

  You are responsible for ensuring the target list is in scope
  and that you have authorization before continuing.
================================================================
""".strip()

# Extra PATH locations commonly used by Go / pdtm installs on Kali
EXTRA_PATH_DIRS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    os.path.expanduser("~/.pdtm/go/bin"),
    "/usr/local/go/bin",
    "/usr/local/bin",
    "/opt/testssl.sh",
]


# ---------------------------------------------------------------------------
# Console / logging
# ---------------------------------------------------------------------------

_IS_TTY = sys.stdout.isatty()
_LOG_LOCK = threading.Lock()
_LOG_FH = None  # type: Optional[Any]
_SHUTDOWN = threading.Event()

if HAS_RICH:
    console = Console(
        theme=Theme({
            "info": "cyan",
            "success": "bold green",
            "warning": "bold yellow",
            "error": "bold red",
            "stage": "bold magenta",
            "tool": "dim cyan",
        }),
        highlight=False,
        soft_wrap=True,
    )
else:
    console = None


class Colors:
    """ANSI colors that degrade when stdout is not a TTY."""

    if _IS_TTY:
        RED = "\033[31m"
        GRN = "\033[32m"
        YEL = "\033[33m"
        BLU = "\033[34m"
        MAG = "\033[35m"
        CYN = "\033[36m"
        WHT = "\033[37m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RST = "\033[0m"
    else:
        RED = GRN = YEL = BLU = MAG = CYN = WHT = BOLD = DIM = RST = ""


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _emit(level: str, msg: str, style: str = "") -> None:
    line = f"[{_ts()}] [{level}] {msg}"
    with _LOG_LOCK:
        if _LOG_FH is not None:
            try:
                _LOG_FH.write(line + "\n")
                _LOG_FH.flush()
            except Exception:
                pass
        if console is not None:
            color = {
                "INFO": "cyan",
                "OK": "green",
                "WARN": "yellow",
                "ERROR": "red",
                "DEBUG": "dim",
                "PHASE": "magenta bold",
            }.get(level, "white")
            console.print(f"[dim]{_ts()}[/dim] [{color}]{level:<5}[/{color}] {msg}")
        else:
            prefix = {
                "INFO": Colors.CYN,
                "OK": Colors.GRN,
                "WARN": Colors.YEL,
                "ERROR": Colors.RED,
                "DEBUG": Colors.DIM,
                "PHASE": Colors.MAG + Colors.BOLD,
            }.get(level, "")
            print(f"{prefix}{line}{Colors.RST}", flush=True)


def log_info(msg: str) -> None:
    _emit("INFO", msg)


def log_ok(msg: str) -> None:
    _emit("OK", msg)


def log_warn(msg: str) -> None:
    _emit("WARN", msg)


def log_error(msg: str) -> None:
    _emit("ERROR", msg)


def log_debug(msg: str) -> None:
    _emit("DEBUG", msg)


def log_phase(msg: str) -> None:
    """Stage panel on screen, plain line in the log file."""
    line = f"[{_ts()}] [PHASE] {msg}"
    with _LOG_LOCK:
        if _LOG_FH is not None:
            try:
                _LOG_FH.write(line + "\n")
                _LOG_FH.flush()
            except Exception:
                pass
    if console is not None:
        console.print()
        console.print(Panel(
            f"[stage]{msg}[/]",
            border_style="magenta",
            box=box.ROUNDED,
            expand=False,
        ))
    else:
        print(f"{Colors.MAG}{Colors.BOLD}{line}{Colors.RST}", flush=True)


def banner() -> None:
    """Opening banner. Rich panel when available, plain legal text otherwise."""
    if console is not None:
        console.print(Panel.fit(
            "[bold white]BLACKBOX INTELLIGENCE GROUP LLC[/]\n"
            "[dim]HerecyEx — External Recon & Enumeration[/]\n"
            "[dim]No exploitation • No credential brute force • No denial of service[/]",
            border_style="blue",
            box=box.DOUBLE,
            padding=(1, 4),
        ))
        return
    print(LEGAL_BANNER.format(version=__version__))
    print()


def print_targets_table(domains: int, ips: int, cidrs: int, dropped: int) -> None:
    if console is None:
        log_info(f"Domains {domains} | IPs {ips} | CIDRs {cidrs} | Dropped {dropped}")
        return
    table = Table(title="Targets Loaded", box=box.SIMPLE)
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right", style="green")
    table.add_row("Domains", str(domains))
    table.add_row("IPs", str(ips))
    table.add_row("CIDRs", str(cidrs))
    table.add_row("Dropped by scope", str(dropped))
    table.add_row("Total in pipeline", str(domains + ips))
    console.print(table)


def print_results_summary(state: "RunState", targets: "TargetSet", outdir: Path, elapsed: float) -> None:
    reports = outdir / "reports"
    findings = len(state.findings)
    open_ports = sum(len(h.open_tcp) + len(h.open_udp) for h in state.hosts.values())
    if console is None:
        log_ok(f"Findings of interest: {findings}. Output: {outdir}")
        return
    console.print()
    console.print(Panel(
        "[success]Workflow complete[/]\n"
        f"Results: [bold]{outdir}[/]\n"
        f"JSON: [bold]{reports / 'summary.json'}[/]\n"
        f"Markdown: [bold]{reports / 'summary.md'}[/]\n"
        f"HTML: [bold]{reports / 'summary.html'}[/]\n"
        "Findings of interest are leads to verify — not confirmed exploits.",
        title="Done",
        border_style="green",
    ))
    table = Table(title="Results Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right", style="green")
    table.add_row("Domains in pipeline", str(len(targets.domains)))
    table.add_row("IPs in pipeline", str(len(targets.ips)))
    table.add_row("Subdomains", str(len(state.subdomains)))
    table.add_row("Host records", str(len(state.hosts)))
    table.add_row("Open port records", str(open_ports))
    table.add_row("Findings of interest", str(findings))
    table.add_row("Elapsed", f"{elapsed / 60:.1f} min")
    table.add_row("Output directory", outdir.name)
    console.print(table)


def init_log(path: Path) -> None:
    global _LOG_FH
    path.parent.mkdir(parents=True, exist_ok=True)
    _LOG_FH = open(path, "a", encoding="utf-8")
    log_info(f"Log file: {path}")


def close_log() -> None:
    global _LOG_FH
    if _LOG_FH is not None:
        try:
            _LOG_FH.close()
        except Exception:
            pass
        _LOG_FH = None


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    name: str
    binary: str
    hint: str
    phases: tuple[str, ...]
    optional: bool = True
    alt_binaries: tuple[str, ...] = ()


# Install hints are short; the README and requirements.txt have full commands.
TOOLS: list[Tool] = [
    Tool("whois", "whois", "sudo apt install whois", ("passive",), optional=False),
    Tool("dig", "dig", "sudo apt install dnsutils", ("passive", "resolve", "services"), optional=False),
    Tool("curl", "curl", "sudo apt install curl", ("passive", "web"), optional=False),
    Tool("nmap", "nmap", "sudo apt install nmap", ("resolve", "ports", "web", "services"), optional=False),
    Tool("subfinder", "subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", ("passive",)),
    Tool("amass", "amass", "sudo apt install amass  # or go install github.com/owasp-amass/amass/v4/...@master", ("passive",)),
    Tool("assetfinder", "assetfinder", "go install github.com/tomnomnom/assetfinder@latest", ("passive",)),
    Tool("theHarvester", "theHarvester", "sudo apt install theharvester", ("passive",)),
    Tool("dnsrecon", "dnsrecon", "sudo apt install dnsrecon", ("passive", "services")),
    Tool("dnsx", "dnsx", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", ("passive", "resolve")),
    Tool("massdns", "massdns", "sudo apt install massdns", ("resolve",)),
    Tool("httpx", "httpx", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", ("resolve", "web")),
    Tool("fping", "fping", "sudo apt install fping", ("resolve",)),
    Tool("naabu", "naabu", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", ("ports",)),
    Tool("rustscan", "rustscan", "sudo apt install rustscan  # or cargo / GitHub release", ("ports",)),
    Tool("masscan", "masscan", "sudo apt install masscan", ("ports",)),
    Tool("whatweb", "whatweb", "sudo apt install whatweb", ("web",)),
    Tool("wafw00f", "wafw00f", "sudo apt install wafw00f", ("web",)),
    Tool("nuclei", "nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", ("web",)),
    Tool("feroxbuster", "feroxbuster", "sudo apt install feroxbuster", ("web",)),
    Tool("gobuster", "gobuster", "sudo apt install gobuster", ("web",)),
    Tool("ffuf", "ffuf", "sudo apt install ffuf", ("web",)),
    Tool("nikto", "nikto", "sudo apt install nikto", ("web",)),
    Tool("gowitness", "gowitness", "go install github.com/sensepost/gowitness@latest", ("web",)),
    Tool("eyewitness", "eyewitness", "sudo apt install eyewitness", ("web",)),
    Tool("sslscan", "sslscan", "sudo apt install sslscan", ("web",)),
    Tool(
        "testssl",
        "testssl.sh",
        "sudo apt install testssl.sh  # Kali installs the binary as testssl, not testssl.sh",
        ("web",),
        alt_binaries=("testssl",),
    ),
    Tool("tlsx", "tlsx", "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest", ("web",)),
    Tool("gau", "gau", "go install github.com/lc/gau/v2/cmd/gau@latest", ("passive",)),
    Tool("waybackurls", "waybackurls", "go install github.com/tomnomnom/waybackurls@latest", ("passive",)),
    Tool("katana", "katana", "go install github.com/projectdiscovery/katana/cmd/katana@latest", ("web",)),
    Tool("enum4linux-ng", "enum4linux-ng", "sudo apt install enum4linux-ng", ("services",)),
    Tool("enum4linux", "enum4linux", "sudo apt install enum4linux", ("services",)),
    Tool("smbmap", "smbmap", "sudo apt install smbmap", ("services",)),
    Tool("smbclient", "smbclient", "sudo apt install smbclient", ("services",)),
    Tool("onesixtyone", "onesixtyone", "sudo apt install onesixtyone", ("services",)),
    Tool("snmpwalk", "snmpwalk", "sudo apt install snmp", ("services",)),
    Tool("ssh-audit", "ssh-audit", "sudo apt install ssh-audit", ("services",)),
    Tool("ldapsearch", "ldapsearch", "sudo apt install ldap-utils", ("services",)),
]


def _bootstrap_path() -> None:
    """Prepend common Go / pipx / pdtm install dirs so tool detection finds them."""
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for d in EXTRA_PATH_DIRS:
        if d and os.path.isdir(d) and d not in parts:
            parts.insert(0, d)
    os.environ["PATH"] = os.pathsep.join(parts)


def which(binary: str) -> Optional[str]:
    """Locate a binary, including testssl.sh odd paths."""
    if not binary:
        return None
    found = shutil.which(binary)
    if found:
        return found
    extras = [
        os.path.expanduser(f"~/go/bin/{binary}"),
        os.path.expanduser(f"~/.pdtm/go/bin/{binary}"),
        os.path.expanduser(f"~/.local/bin/{binary}"),
        f"/usr/local/bin/{binary}",
        f"/opt/{binary}/{binary}",
    ]
    if binary in {"testssl.sh", "testssl"}:
        # Kali's testssl.sh package installs /usr/bin/testssl (no .sh).
        # Upstream git checkouts keep the testssl.sh name. Either is accepted.
        extras.extend(
            [
                "/usr/bin/testssl",
                "/usr/local/bin/testssl",
                "/usr/bin/testssl.sh",
                "/usr/local/bin/testssl.sh",
                os.path.expanduser("~/testssl.sh/testssl.sh"),
                "/opt/testssl.sh/testssl.sh",
                "/usr/share/testssl.sh/testssl.sh",
            ]
        )
    if binary == "enum4linux-ng":
        extras.extend(
            [
                "/usr/bin/enum4linux-ng",
                os.path.expanduser("~/.local/bin/enum4linux-ng"),
            ]
        )
    for p in extras:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _is_projectdiscovery_httpx(path: str) -> bool:
    """True only for ProjectDiscovery httpx, not the Python httpx CLI."""
    try:
        r = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
        out = (r.stdout + r.stderr).lower()
        if "projectdiscovery" in out:
            return True
        r2 = subprocess.run([path, "-h"], capture_output=True, text=True, timeout=5)
        help_text = (r2.stdout + r2.stderr).lower()
        has_list = "-list" in help_text or "-l string" in help_text
        return has_list and "tech-detect" in help_text
    except Exception:
        return False


def find_pd_httpx() -> Optional[str]:
    """Locate ProjectDiscovery httpx, preferring Go/pdtm install dirs over PATH."""
    candidates: list[str] = []
    for base in EXTRA_PATH_DIRS:
        candidates.append(os.path.join(base, "httpx"))
    found = shutil.which("httpx")
    if found:
        candidates.append(found)
    seen: set[str] = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if os.path.isfile(cand) and os.access(cand, os.X_OK) and _is_projectdiscovery_httpx(cand):
            return cand
    return None


@dataclass
class ToolStatus:
    name: str
    binary: str
    path: Optional[str]
    present: bool
    hint: str
    phases: tuple[str, ...]
    optional: bool


class Toolset:
    """Detected tool inventory for the current machine."""

    def __init__(self) -> None:
        self.status: dict[str, ToolStatus] = {}
        self._detect()

    def _detect(self) -> None:
        for t in TOOLS:
            if t.name == "httpx":
                path = find_pd_httpx()
            else:
                path = which(t.binary)
                if not path:
                    for alt in t.alt_binaries:
                        path = which(alt)
                        if path:
                            break
            hint = t.hint
            if t.name == "httpx" and not path and shutil.which("httpx"):
                hint = (
                    "The httpx on PATH looks like the Python CLI (no -l / -tech-detect). "
                    "Install ProjectDiscovery httpx: "
                    "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
                )
            self.status[t.name] = ToolStatus(
                name=t.name,
                binary=t.binary,
                path=path,
                present=bool(path),
                hint=hint,
                phases=t.phases,
                optional=t.optional,
            )

    def has(self, name: str) -> bool:
        st = self.status.get(name)
        return bool(st and st.present)

    def path(self, name: str) -> Optional[str]:
        st = self.status.get(name)
        return st.path if st else None

    def require(self, name: str) -> Optional[str]:
        """Return binary path or log a skip hint and return None."""
        st = self.status.get(name)
        if st and st.present and st.path:
            return st.path
        hint = st.hint if st else f"install {name}"
        log_warn(f"Skipping {name}: not installed. Hint: {hint}")
        return None

    def present_names(self) -> list[str]:
        return [n for n, s in self.status.items() if s.present]

    def missing(self, optional: Optional[bool] = None) -> list[ToolStatus]:
        out = [s for s in self.status.values() if not s.present]
        if optional is not None:
            out = [s for s in out if s.optional is optional]
        return out

    def print_report(self) -> None:
        present = [s for s in self.status.values() if s.present]
        missing = [s for s in self.status.values() if not s.present]
        log_info(f"Tool detection: {len(present)} present, {len(missing)} missing")
        if console is not None:
            table = Table(title="Tool Inventory", box=box.SIMPLE, show_lines=False)
            table.add_column("Tool", style="cyan")
            table.add_column("Status")
            table.add_column("Path / install hint", overflow="fold")
            table.add_column("Phases", style="dim")
            for s in self.status.values():
                status = "[success]OK[/]" if s.present else "[warning]MISSING[/]"
                loc = s.path or s.hint
                table.add_row(s.name, status, loc, ",".join(s.phases))
            console.print(table)
        else:
            width = max((len(s.name) for s in self.status.values()), default=10)
            for s in self.status.values():
                flag = "OK     " if s.present else "MISSING"
                loc = s.path or s.hint
                print(f"  {s.name:<{width}}  {flag}  {loc}")
        if missing:
            log_warn("Missing tools will be skipped. See requirements.txt for install commands.")
            req = [s for s in missing if not s.optional]
            if req:
                log_warn("Recommended core tools missing: " + ", ".join(s.name for s in req))


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def sudo_n_available() -> bool:
    if not which("sudo"):
        return False
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def nmap_scan_flag(udp: bool = False) -> tuple[list[str], str]:
    """
    Return (command_prefix_including_nmap, scan_flag).
    Prefer SYN/UDP when root or passwordless sudo is available; otherwise TCP connect.
    """
    nmap = which("nmap") or "nmap"
    if udp:
        if is_root():
            return [nmap], "-sU"
        if sudo_n_available():
            return ["sudo", "-n", nmap], "-sU"
        return [nmap], "-sT"  # caller should avoid UDP without privs
    if is_root():
        return [nmap], "-sS"
    if sudo_n_available():
        return ["sudo", "-n", nmap], "-sS"
    return [nmap], "-sT"


def can_raw_scan() -> bool:
    return is_root() or sudo_n_available()


# ---------------------------------------------------------------------------
# Subprocess wrapper
# ---------------------------------------------------------------------------

@dataclass
class CmdResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False
    timed_out: bool = False
    outfile: Optional[str] = None
    duration: float = 0.0


class RateLimiter:
    """Simple minimum-interval limiter shared across threads."""

    def __init__(self, min_interval: float = 0.0) -> None:
        self.min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            gap = self.min_interval - (now - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()


def run_cmd(
    cmd: list[str],
    *,
    outfile: Optional[Path] = None,
    timeout: int = 600,
    cwd: Optional[Path] = None,
    stdin_data: Optional[str] = None,
    skip_if_exists: bool = True,
    env: Optional[dict[str, str]] = None,
    quiet: bool = False,
) -> CmdResult:
    """Run a command, optionally tee stdout/stderr to a file. Never raises on tool failure."""
    if _SHUTDOWN.is_set():
        return CmdResult(cmd, -1, "", "shutdown", skipped=True)

    if outfile is not None and skip_if_exists and outfile.exists() and outfile.stat().st_size > 0:
        if not quiet:
            log_info(f"Skip (exists): {outfile.name}")
        try:
            existing = outfile.read_text(encoding="utf-8", errors="replace")
        except Exception:
            existing = ""
        return CmdResult(cmd, 0, existing, "", skipped=True, outfile=str(outfile))

    display = " ".join(cmd)
    if len(display) > 240:
        display = display[:237] + "..."
    if not quiet:
        log_info(f"$ {display}")

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    # Avoid interactive prompts hanging the orchestrator
    merged_env.setdefault("DEBIAN_FRONTEND", "noninteractive")
    merged_env.setdefault("NUCLEI_HIDE_UPDATE", "true")

    if outfile is not None:
        outfile.parent.mkdir(parents=True, exist_ok=True)

    def _invoke() -> CmdResult:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                text=True,
                errors="replace",
                check=False,
            )
            duration = time.monotonic() - start
            stdout, stderr = proc.stdout or "", proc.stderr or ""
            if outfile is not None:
                try:
                    with open(outfile, "w", encoding="utf-8") as fh:
                        fh.write(stdout)
                        if stderr and stderr.strip():
                            fh.write("\n\n----- stderr -----\n")
                            fh.write(stderr)
                except Exception as exc:
                    log_warn(f"Failed writing {outfile}: {exc}")
            return CmdResult(
                cmd,
                proc.returncode,
                stdout,
                stderr,
                outfile=str(outfile) if outfile else None,
                duration=duration,
            )
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            log_warn(f"Timeout after {timeout}s: {display}")
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
            if outfile is not None:
                try:
                    with open(outfile, "w", encoding="utf-8") as fh:
                        fh.write(stdout)
                        fh.write(f"\n\n----- TIMEOUT after {timeout}s -----\n")
                        fh.write(stderr)
                except Exception:
                    pass
            return CmdResult(
                cmd, -1, stdout, stderr, timed_out=True,
                outfile=str(outfile) if outfile else None, duration=duration,
            )
        except FileNotFoundError:
            log_warn(f"Binary not found: {cmd[0]}")
            return CmdResult(cmd, 127, "", f"not found: {cmd[0]}")
        except Exception as exc:
            log_error(f"Command failed ({display}): {exc}")
            return CmdResult(cmd, -1, "", str(exc))

    # Spinners only on the main thread. Worker pools paint their own status,
    # and a nested status from a pool thread fights the console.
    tool_name = Path(cmd[0]).name if cmd else "tool"
    use_spinner = (
        console is not None
        and console.is_terminal
        and threading.current_thread() is threading.main_thread()
        and not quiet
    )
    if use_spinner:
        with console.status(f"[tool]Running {tool_name}...[/]", spinner="dots"):
            return _invoke()
    return _invoke()


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_lines(path: Path, lines: Iterable[str]) -> None:
    uniq = []
    seen = set()
    for line in lines:
        s = line.strip()
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    write_text(path, "\n".join(uniq) + ("\n" if uniq else ""))


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s:
            out.append(s)
    return out


def unique(seq: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in seq:
        s = item.strip()
        if not s:
            continue
        key = s.lower()
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", value.strip())
    cleaned = cleaned.strip("._") or "target"
    return cleaned[:180]


# ---------------------------------------------------------------------------
# Target parsing / scope
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False


def is_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except Exception:
        return False


def is_ip(value: str) -> bool:
    return is_ipv4(value) or is_ipv6(value)


def parse_network(value: str) -> Optional[ipaddress._BaseNetwork]:
    """Broad recon loader. Host bits are masked on purpose (strict=False).

    ``203.0.113.10/0`` becomes ``0.0.0.0/0`` here. Narrow checks do not use
    this function. Their scope loader rejects that line instead of widening it.
    """
    try:
        return ipaddress.ip_network(value, strict=False)
    except Exception:
        return None


def is_domain(value: str) -> bool:
    v = value.rstrip(".").lower()
    if is_ip(v) or "/" in v:
        return False
    if v in {"localhost"}:
        return True
    return bool(_DOMAIN_RE.match(v))


def registrable_domain(fqdn: str) -> str:
    """Cheap eTLD+1 approximation (not a full PSL). Good enough to group subdomains."""
    parts = fqdn.rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_part_slds = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "com.au", "net.au",
        "com.br", "co.nz", "co.in", "com.mx", "com.cn", "co.za",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_part_slds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


@dataclass
class TargetSet:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)
    # Seeds are the operator's original list. Passive discovery must not widen them.
    seed_domains: list[str] = field(default_factory=list)
    seed_ips: list[str] = field(default_factory=list)
    seed_networks: list = field(default_factory=list)
    active_names: list[str] = field(default_factory=list)
    candidates: list[str] = field(default_factory=list)
    scope_decisions: list = field(default_factory=list)

    def all_hosts(self) -> list[str]:
        return unique(list(self.domains) + list(self.ips))

    def add_domain(self, name: str) -> None:
        name = name.rstrip(".").lower()
        if name and name not in {d.lower() for d in self.domains}:
            self.domains.append(name)

    def add_ip(self, ip: str) -> None:
        if ip and ip not in self.ips:
            self.ips.append(ip)


def expand_cidr(cidr: str, max_hosts: int) -> list[str]:
    net = parse_network(cidr)
    if net is None:
        return []
    # Exclude network/broadcast for IPv4 when they are not usable hosts
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    if len(hosts) > max_hosts:
        log_warn(
            f"CIDR {cidr} expands to {len(hosts)} hosts, exceeding --max-cidr-hosts {max_hosts}. "
            "Skipping expansion. Raise the limit if this range is in scope."
        )
        return []
    return [str(h) for h in hosts]


def load_scope(path: Path) -> tuple[list[ipaddress._BaseNetwork], list[str]]:
    """Allowlist of CIDRs/IPs and domain suffixes."""
    nets: list[ipaddress._BaseNetwork] = []
    domains: list[str] = []
    for raw in read_lines(path):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        net = parse_network(line) if (line.count(":") >= 2 or line.replace(".", "").replace("/", "").isdigit() or "/" in line or is_ip(line)) else None
        if net is not None:
            nets.append(net)
            continue
        if is_ip(line):
            nets.append(ipaddress.ip_network(line, strict=False))
            continue
        domains.append(line.rstrip(".").lower().lstrip("."))
    return nets, unique(domains)


def in_scope(value: str, nets: list[ipaddress._BaseNetwork], domain_suffixes: list[str]) -> bool:
    if is_ip(value):
        addr = ipaddress.ip_address(value)
        return any(addr in n for n in nets) if nets or not domain_suffixes else False
    # Domain: allow if it matches a suffix (example.com matches a.example.com)
    v = value.rstrip(".").lower()
    if not domain_suffixes and nets:
        # IPs-only allowlist cannot confirm a domain until it resolves; keep it
        # and let the resolve phase drop out-of-scope IPs later.
        return True
    if not domain_suffixes and not nets:
        return True
    for sfx in domain_suffixes:
        if v == sfx or v.endswith("." + sfx):
            return True
    return False


def capture_seeds(ts: TargetSet) -> None:
    """Remember the operator's original names, addresses, and ranges."""
    ts.seed_domains = list(ts.domains)
    ts.seed_ips = list(ts.ips)
    nets: list[ipaddress._BaseNetwork] = []
    for cidr in ts.cidrs:
        net = parse_network(cidr)
        if net is not None:
            nets.append(net)
    for ip in ts.seed_ips:
        if is_ip(ip):
            nets.append(ipaddress.ip_network(ip, strict=False))
    ts.seed_networks = nets


def ip_in_seed_networks(ip: str, targets: TargetSet) -> bool:
    if not is_ip(ip):
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in targets.seed_networks)


def ip_allowed(ip: str, cfg: "Config", targets: TargetSet) -> bool:
    """True only when this address may be actively probed."""
    if not is_ip(ip):
        return False
    if getattr(cfg, "scope_enforced", False):
        # An allowlist with only domain suffixes cannot prove an address.
        if not cfg.scope_nets:
            return False
        return bool(in_scope(ip, cfg.scope_nets, []))
    if targets.seed_networks:
        # Any IP/CIDR in the original list becomes the ceiling when no allowlist was given.
        return ip_in_seed_networks(ip, targets)
    # Domain-only list and no --scope-check: the operator named the names.
    return bool(targets.seed_domains)


def nuclei_enabled(cfg: "Config") -> bool:
    """Nuclei stays off under --scope-check. Templates can request other hosts."""
    if getattr(cfg, "no_nuclei", False):
        return False
    if getattr(cfg, "scope_enforced", False):
        return False
    return True


_SCOPED_IP_ONLY_WARNED = False


def warn_scoped_ip_only(cfg: "Config") -> None:
    """One clear warning. Hostname coverage is off; DNS scope is not claimed fixed."""
    global _SCOPED_IP_ONLY_WARNED
    if not getattr(cfg, "scope_enforced", False) or _SCOPED_IP_ONLY_WARNED:
        return
    _SCOPED_IP_ONLY_WARNED = True
    log_warn(
        "Scoped active workflow is IP-only. Hostname active coverage is disabled. "
        "Discovered names stay candidates. DNS is not pinned, so this is not DNS-scope enforcement. "
        "Nuclei, katana, gowitness, EyeWitness, and nikto are not started, "
        "even if --full, --nikto, or the default nuclei run was requested."
    )


def name_may_be_probed(name: str, ips: Iterable[str], cfg: "Config", targets: TargetSet) -> tuple[bool, str]:
    """Whether an active probe may use this hostname.

    With --scope-check the answer is always no. Address pinning is not implemented,
    so a name is not treated as in scope just because it resolved inside the allowlist.
    Without --scope-check, IP/CIDR lists still fail closed on unresolved or out-of-range answers.
    """
    resolved = [ip for ip in ips if is_ip(ip)]
    if getattr(cfg, "scope_enforced", False):
        warn_scoped_ip_only(cfg)
        return False, (
            "hostname active probing is disabled under --scope-check; "
            "DNS is not pinned to the resolved addresses"
        )
    if targets.seed_networks:
        if not resolved:
            return False, "unresolved; IP/CIDR targets fail closed without --scope-check"
        outside = [ip for ip in resolved if not ip_in_seed_networks(ip, targets)]
        if outside:
            return False, "resolved outside the initial target IP/CIDR set: " + ", ".join(outside)
        return True, "every resolved IP is inside the initial target IP/CIDR set"
    if targets.seed_domains:
        return True, "no --scope-check and the target list is domain-only; the operator owns that list"
    return False, "no seed names, no seed ranges, and no --scope-check"


def apply_resolution_scope(
    cfg: "Config",
    targets: TargetSet,
    resolved: dict[str, list[str]],
    state: Optional["RunState"] = None,
) -> None:
    """Split names into active vs candidate and drop addresses that must not be probed."""
    names = unique(list(targets.domains) + list(resolved.keys()))
    decisions = []
    active: list[str] = []
    candidates: list[str] = []
    allowed_from_dns: list[str] = []
    for name in names:
        if not is_domain(name):
            continue
        ips = list(resolved.get(name) or resolved.get(name.lower()) or [])
        ok, reason = name_may_be_probed(name, ips, cfg, targets)
        decisions.append({"name": name, "ips": ips, "active": ok, "reason": reason})
        if ok:
            active.append(name)
        else:
            candidates.append(name)
        for ip in ips:
            if ip_allowed(ip, cfg, targets):
                allowed_from_dns.append(ip)
        if state is not None and is_domain(name):
            hr = state.host(name, kind="domain")
            hr.ips = [ip for ip in ips if ip_allowed(ip, cfg, targets)]
            for ip in hr.ips:
                ip_rec = state.host(ip, kind="ip")
                if name not in ip_rec.names:
                    ip_rec.names.append(name)
    kept_ips: list[str] = []
    for ip in list(targets.seed_ips) + list(targets.ips) + allowed_from_dns:
        if ip_allowed(ip, cfg, targets) and ip not in kept_ips:
            kept_ips.append(ip)
    targets.ips = kept_ips
    targets.active_names = active
    targets.candidates = candidates
    targets.scope_decisions = decisions
    try:
        base = cfg.outdir / "resolve"
        base.mkdir(parents=True, exist_ok=True)
        write_text(base / "scope-decisions.json", json.dumps(decisions, indent=2))
        write_lines(cfg.outdir / "targets" / "candidates.txt", candidates)
        write_lines(cfg.outdir / "targets" / "active-names.txt", active)
    except Exception as exc:
        log_warn(f"Could not write scope decisions: {exc}")
    log_info(
        f"Scope: {len(active)} name(s) eligible for active probes, "
        f"{len(candidates)} kept as candidates only"
    )


def split_host_token(token: str) -> str:
    """Hostname or address from a URL, host, or host:port token."""
    text = token.strip()
    text = re.sub(r"^https?://", "", text, flags=re.I)
    text = text.split("/")[0].strip()
    if text.startswith("["):
        return text[1:].split("]")[0]
    if text.count(":") == 1 and not is_ipv6(text):
        return text.split(":")[0]
    return text


def url_host_allowed(token: str, cfg: "Config", targets: TargetSet) -> bool:
    host = split_host_token(token).rstrip(".").lower()
    if not host:
        return False
    if is_ip(host):
        return ip_allowed(host, cfg, targets)
    return host in {n.lower() for n in targets.active_names}


def filter_probe_tokens(tokens: Iterable[str], cfg: "Config", targets: TargetSet) -> list[str]:
    """Drop every token whose host is not eligible for an active probe."""
    return [tok for tok in unique(tokens) if url_host_allowed(tok, cfg, targets)]


def portscan_targets(cfg: "Config", targets: TargetSet) -> list[str]:
    """IP addresses only. Names are never handed to a port scanner."""
    return [ip for ip in unique(targets.ips) if ip_allowed(ip, cfg, targets)]


def axfr_server_ips(ns_label: str, resolved_ips: Iterable[str], cfg: "Config", targets: TargetSet) -> list[str]:
    """Addresses that may receive AXFR. A hostname is never returned.

    Third-party name servers are skipped even when the zone name is in scope.
    """
    ips: list[str] = []
    if is_ip(ns_label):
        ips.append(ns_label)
    for ip in resolved_ips:
        if is_ip(ip):
            ips.append(ip)
    return [ip for ip in unique(ips) if ip_allowed(ip, cfg, targets)]


def axfr_commands(zone: str, ns_label: str, ns_ips: Iterable[str], cfg: "Config", targets: TargetSet) -> list[list[str]]:
    """dig AXFR argv list. Empty when the server is not in scope."""
    dig = "dig"
    cmds = []
    for ip in axfr_server_ips(ns_label, ns_ips, cfg, targets):
        cmds.append([dig, f"@{ip}", zone, "AXFR", "+time=8", "+tries=1"])
    return cmds


def consider_redirect(location: str, cfg: "Config", targets: TargetSet) -> bool:
    """Whether a Location/final URL may itself be probed. Off-scope hosts never may."""
    if not location or not str(location).strip():
        return False
    return url_host_allowed(str(location), cfg, targets)


# Child tools that follow redirects onto other hosts and cannot be given a scope pin.
# They are not started. This is a limit of those tools, not something HerecyEx can patch inside them.
REDIRECT_UNSCOPED_TOOLS = {
    "katana": (
        "Katana follows HTTP redirects in its client before crawl-scope filtering. "
        "A 3xx to another host is requested. Katana is not started."
    ),
    "gowitness": (
        "gowitness drives a browser, and the browser follows redirects to any host. "
        "Screenshots are not taken."
    ),
    "eyewitness": (
        "EyeWitness drives a browser that follows redirects off-host. Screenshots are not taken."
    ),
    "nikto": (
        "Nikto follows 3xx responses and has no switch that pins the next request to the scoped host. "
        "Nikto is not started, including when --nikto was passed."
    ),
}


def httpx_probe_args(binary: str, infile: Path, json_out: Path, cfg: "Config") -> list[str]:
    """httpx argv. Redirects are not followed; -location only records the header."""
    return [
        binary, "-l", str(infile), "-silent", "-json",
        "-title", "-tech-detect", "-status-code", "-web-server",
        "-content-type", "-location", "-no-color",
        "-timeout", "8", "-rate-limit", str(cfg.http_rate),
        "-threads", str(min(50, max(10, cfg.threads * 2))),
        "-o", str(json_out),
    ]


def nuclei_probe_args(binary: str, urlfile: Path, json_out: Path, cfg: "Config") -> list[str]:
    """nuclei argv. JSONL output, redirects forced off, interactsh off.

    Per-template `redirects: true` is overridden by -disable-redirects in current
    nuclei. Templates can still issue their own requests to other URLs; that
    cannot be prevented from the CLI. See README.
    """
    severity = cfg.nuclei_severity or (
        "high,critical" if cfg.profile == "quick" else "info,low,medium,high,critical"
    )
    return [
        binary,
        "-l", str(urlfile),
        "-severity", severity,
        "-exclude-tags", NUCLEI_EXCLUDED_TAGS,
        "-disable-redirects",
        "-no-interactsh",
        "-rl", str(cfg.http_rate),
        "-c", str(min(25, max(5, cfg.threads))),
        "-timeout", "10",
        "-retries", "1",
        "-jsonl",
        "-o", str(json_out),
        "-silent",
        "-no-color",
    ]


def whatweb_args(binary: str, url: str, cfg: "Config") -> list[str]:
    aggression = "3" if cfg.profile == "full" else "1"
    return [binary, "--color=never", "--follow-redirect=never", "-a", aggression, url]


def wafw00f_args(binary: str, url: str) -> list[str]:
    # -r / --noredirect: do not request the Location target.
    return [binary, "-a", "-r", url]


def ferox_args(binary: str, url: str, wordlist: Path, outfile: Path, cfg: "Config") -> list[str]:
    threads = 10 if cfg.profile == "full" else 8
    return [
        binary, "-u", url, "-w", str(wordlist),
        "-t", str(threads), "-n", "--quiet", "--no-state",
        "-C", "404,400,429,501",
        "--rate-limit", str(min(30, cfg.http_rate)),
        "-d", "0",
        "-o", str(outfile),
    ]


def gobuster_args(binary: str, url: str, wordlist: Path, outfile: Path, cfg: "Config") -> list[str]:
    threads = 10 if cfg.profile == "full" else 8
    return [
        binary, "dir", "-u", url, "-w", str(wordlist),
        "-t", str(threads), "-q", "-k",
        "--timeout", "8s",
        "-o", str(outfile),
    ]


def ffuf_args(binary: str, url: str, wordlist: Path, outfile: Path, cfg: "Config") -> list[str]:
    threads = 10 if cfg.profile == "full" else 8
    return [
        binary,
        "-u", url.rstrip("/") + "/FUZZ",
        "-w", str(wordlist),
        "-t", str(threads),
        "-rate", str(min(30, cfg.http_rate)),
        "-mc", "200,204,301,302,307,401,403",
        "-of", "json",
        "-o", str(outfile),
        "-s",
    ]


def nmap_service_cmd(
    cfg: "Config",
    prefix: list[str],
    sflag: str,
    dest: Path,
    hostfile: Path,
    *,
    ports: Optional[str] = None,
    top_ports: Optional[int] = None,
) -> list[str]:
    """Version detection only. No -sC.

    ``-sC`` is ``--script=default``. That set is whatever the installed nmap
    calls default, and individual scripts can override the HTTP library's
    redirect check. HerecyEx does not treat the category name as a scope boundary.
    """
    cmd = list(prefix) + [sflag, "-Pn", "-n", f"-T{cfg.nmap_timing}"]
    if ports:
        cmd += ["-p", ports]
    elif top_ports:
        cmd += ["--top-ports", str(top_ports)]
    cmd += ["-sV", "--version-intensity", "5", "-oA", str(dest), "-iL", str(hostfile)]
    return cmd + list(cfg.extra_nmap)


def intrusive_checks_enabled(cfg: "Config") -> bool:
    """Open-relay and empty-password NSE run only with both switches."""
    return bool(getattr(cfg, "allow_intrusive_checks", False) and getattr(cfg, "authorized", False))


SMTP_SINGLE_PROBE = "herecyex-probe"


def smtp_scripts(cfg: "Config") -> str:
    """Default is smtp-commands only.

    ``smtp-vrfy`` is not an Nmap NSE script (the nsedoc page is 404). Requesting
    it makes nmap abort the whole SMTP script set. ``smtp-enum-users`` is in the
    intrusive category and walks a username database unless it is pinned; it is
    not used unless the operator opted in.
    """
    parts = ["smtp-commands"]
    if intrusive_checks_enabled(cfg):
        parts.extend(["smtp-enum-users", "smtp-open-relay"])
    return ",".join(parts)


def smtp_script_args(probe_file: Path) -> str:
    """One VRFY of a single dummy name. No RCPT, no EXPN, no user list."""
    return (
        "smtp-enum-users.methods={VRFY},"
        f"userdb={probe_file},"
        "unpwdb.userlimit=1"
    )


def mssql_scripts(cfg: "Config") -> str:
    base = "ms-sql-info,ms-sql-ntlm-info"
    if intrusive_checks_enabled(cfg):
        return base + ",ms-sql-empty-password"
    return base


def mysql_scripts(cfg: "Config") -> str:
    base = "mysql-info"
    if intrusive_checks_enabled(cfg):
        return base + ",mysql-empty-password"
    return base


def parse_nuclei_records(path: Path) -> list[dict[str, Any]]:
    """Read nuclei JSONL or a JSON array. Empty and missing files yield nothing."""
    if not path.exists() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line in {"[", "]"}:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
        elif isinstance(row, list):
            records.extend(item for item in row if isinstance(item, dict))
    return records


def parse_targets(
    path: Path,
    max_cidr_hosts: int = 4096,
    scope_file: Optional[Path] = None,
) -> TargetSet:
    ts = TargetSet()
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")

    nets: list[ipaddress._BaseNetwork] = []
    suffixes: list[str] = []
    if scope_file:
        nets, suffixes = load_scope(scope_file)
        log_info(f"Scope allowlist: {len(nets)} networks, {len(suffixes)} domain suffixes")

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Tolerate accidental commas / whitespace-separated tokens
        tokens = re.split(r"[\s,;]+", line)
        for tok in tokens:
            tok = tok.strip().lower() if not (":" in tok and tok.count(":") >= 2) else tok.strip()
            # IPv6 should not be lowercased in a harmful way; lowercasing is fine
            tok = tok.strip().strip("[]")
            if not tok:
                continue
            ts.raw.append(tok)

            net = parse_network(tok) if "/" in tok else None
            if net is not None and "/" in tok:
                if scope_file and nets and not any(
                    net.subnet_of(s) or net.supernet_of(s) or net == s or (net.num_addresses == 1 and next(net.hosts(), ipaddress.ip_address(tok.split("/")[0])) in s)  # type: ignore
                    for s in nets
                ):
                    # If the CIDR itself isn't covered, still expand and filter hosts
                    pass
                ts.cidrs.append(tok)
                for ip in expand_cidr(tok, max_cidr_hosts):
                    if scope_file and not in_scope(ip, nets, suffixes):
                        ts.dropped.append(ip)
                        continue
                    ts.add_ip(ip)
                continue

            if is_ip(tok):
                if scope_file and not in_scope(tok, nets, suffixes):
                    ts.dropped.append(tok)
                    continue
                ts.add_ip(tok)
                continue

            # Strip scheme and path if a URL snuck in
            tok2 = re.sub(r"^https?://", "", tok, flags=re.I)
            tok2 = tok2.split("/")[0].split(":")[0].strip().rstrip(".")
            if not tok2:
                continue
            if is_ip(tok2):
                if scope_file and not in_scope(tok2, nets, suffixes):
                    ts.dropped.append(tok2)
                    continue
                ts.add_ip(tok2)
                continue
            if is_domain(tok2):
                if scope_file and not in_scope(tok2, nets, suffixes):
                    ts.dropped.append(tok2)
                    continue
                ts.add_domain(tok2)
                continue
            log_warn(f"Unrecognized target token, skipping: {tok}")

    ts.domains = unique(ts.domains)
    ts.ips = unique(ts.ips)
    ts.dropped = unique(ts.dropped)
    capture_seeds(ts)
    return ts


# ---------------------------------------------------------------------------
# Findings / run state
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str  # info, low, medium, high, critical
    host: str
    source: str
    evidence: str = ""
    detail: str = ""
    confirmed_exploit: bool = False  # always False — we never claim exploitation

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Never publish a finding as a confirmed exploit, even if a caller set the flag.
        d["confirmed_exploit"] = False
        d["note"] = (
            "Flagged as a finding of interest from reconnaissance output. "
            "This is not a confirmed exploitable vulnerability."
        )
        return d


@dataclass
class HostRecord:
    target: str
    kind: str  # ip or domain
    ips: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    alive: bool = False
    open_tcp: list[dict[str, Any]] = field(default_factory=list)
    open_udp: list[dict[str, Any]] = field(default_factory=list)
    web: list[dict[str, Any]] = field(default_factory=list)
    tls: list[dict[str, Any]] = field(default_factory=list)
    nuclei: list[dict[str, Any]] = field(default_factory=list)
    services: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RunState:
    """In-memory aggregation written out incrementally as JSON."""

    def __init__(self, outdir: Path) -> None:
        self.outdir = outdir
        self.lock = threading.Lock()
        self.hosts: dict[str, HostRecord] = {}
        self.subdomains: list[str] = []
        self.findings: list[Finding] = []
        self.meta: dict[str, Any] = {}
        self.errors: list[str] = []

    def host(self, target: str, kind: str = "") -> HostRecord:
        key = target.strip().lower()
        with self.lock:
            if key not in self.hosts:
                inferred = "ip" if is_ip(target) else "domain"
                self.hosts[key] = HostRecord(target=target, kind=kind or inferred)
            return self.hosts[key]

    def add_subdomains(self, names: Iterable[str]) -> list[str]:
        added = []
        with self.lock:
            have = {s.lower() for s in self.subdomains}
            for n in names:
                n2 = n.rstrip(".").lower()
                if n2 and is_domain(n2) and n2 not in have:
                    have.add(n2)
                    self.subdomains.append(n2)
                    added.append(n2)
        return added

    def add_finding(self, finding: Finding) -> None:
        with self.lock:
            # De-dupe on title+host+source
            sig = (finding.title.lower(), finding.host.lower(), finding.source.lower())
            for existing in self.findings:
                if (existing.title.lower(), existing.host.lower(), existing.source.lower()) == sig:
                    return
            self.findings.append(finding)

    def add_error(self, msg: str) -> None:
        with self.lock:
            self.errors.append(msg)
        log_error(msg)

    def save(self) -> None:
        payload = {
            "meta": self.meta,
            "subdomains": self.subdomains,
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
        path = self.outdir / "state.json"
        tmp = path.with_suffix(".json.tmp")
        write_text(tmp, json.dumps(payload, indent=2, default=str))
        tmp.replace(path)

    def load(self) -> None:
        path = self.outdir / "state.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log_warn(f"Could not reload state.json: {exc}")
            return
        self.meta = data.get("meta") or {}
        self.subdomains = list(data.get("subdomains") or [])
        self.errors = list(data.get("errors") or [])
        for k, v in (data.get("hosts") or {}).items():
            rec = HostRecord(
                target=v.get("target", k),
                kind=v.get("kind", ""),
                ips=list(v.get("ips") or []),
                names=list(v.get("names") or []),
                alive=bool(v.get("alive")),
                open_tcp=list(v.get("open_tcp") or []),
                open_udp=list(v.get("open_udp") or []),
                web=list(v.get("web") or []),
                tls=list(v.get("tls") or []),
                nuclei=list(v.get("nuclei") or []),
                services=dict(v.get("services") or {}),
                notes=list(v.get("notes") or []),
            )
            self.hosts[k] = rec
        for f in data.get("findings") or []:
            self.findings.append(
                Finding(
                    title=f.get("title", ""),
                    severity=f.get("severity", "info"),
                    host=f.get("host", ""),
                    source=f.get("source", ""),
                    evidence=f.get("evidence", ""),
                    detail=f.get("detail", ""),
                    confirmed_exploit=False,
                )
            )
        log_info(f"Resumed state: {len(self.hosts)} hosts, {len(self.subdomains)} subdomains, {len(self.findings)} findings")


# ---------------------------------------------------------------------------
# HTTP helper (crt.sh etc.) — stdlib fallback
# ---------------------------------------------------------------------------

def http_get_json(url: str, timeout: int = 30, headers: Optional[dict[str, str]] = None) -> Any:
    hdrs = {"User-Agent": f"HerecyEx/{__version__} (authorized-security-assessment)"}
    if headers:
        hdrs.update(headers)
    if HAS_REQUESTS:
        try:
            r = _requests.get(url, headers=hdrs, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            log_warn(f"HTTP GET failed {url}: {exc}")
            return None
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8", "replace"))
    except (URLError, TimeoutError, json.JSONDecodeError, Exception) as exc:
        log_warn(f"HTTP GET failed {url}: {exc}")
        return None


def http_get_text(url: str, timeout: int = 30) -> Optional[str]:
    hdrs = {"User-Agent": f"HerecyEx/{__version__} (authorized-security-assessment)"}
    if HAS_REQUESTS:
        try:
            r = _requests.get(url, headers=hdrs, timeout=timeout)
            r.raise_for_status()
            return r.text
        except Exception as exc:
            log_warn(f"HTTP GET failed {url}: {exc}")
            return None
    try:
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception as exc:
        log_warn(f"HTTP GET failed {url}: {exc}")
        return None


def find_wordlist(explicit: Optional[str] = None) -> Optional[Path]:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
        log_warn(f"Wordlist not found: {explicit}")
    for c in WORDLIST_CANDIDATES:
        p = Path(c)
        if p.is_file():
            return p
    return None




# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    outdir: Path
    threads: int
    timeout: int
    skip_if_exists: bool
    profile: str
    no_active: bool
    full_ports: bool
    udp: bool
    nuclei_severity: str
    no_nuclei: bool
    direnum: bool
    nikto: bool
    wordlist: Optional[Path]
    rate_interval: float
    max_cidr_hosts: int
    phases: list[str]
    tools: Toolset
    limiter: RateLimiter
    nmap_timing: str
    testssl: bool
    alive_only: bool
    http_rate: int = 50
    naabu_rate: int = 1000
    allow_intrusive_checks: bool = False
    authorized: bool = False
    scope_enforced: bool = False
    scope_nets: list = field(default_factory=list)
    scope_suffixes: list = field(default_factory=list)
    extra_nmap: list[str] = field(default_factory=list)

    @property
    def top_ports(self) -> int:
        return QUICK_TOP_PORTS if self.profile == "quick" else FULL_TOP_PORTS

    @property
    def udp_top_ports(self) -> int:
        return UDP_TOP_PORTS_QUICK if self.profile == "quick" else UDP_TOP_PORTS_FULL

    @property
    def port_timeout(self) -> int:
        if self.full_ports:
            return max(self.timeout, 3600)
        return max(self.timeout, 900 if self.profile == "full" else 600)


def maybe_wait(cfg: Config) -> None:
    cfg.limiter.wait()


def should_stop() -> bool:
    return _SHUTDOWN.is_set()


def run_pool(fn, items: list, threads: int, desc: str) -> None:
    """Run fn(item) over items with a thread pool, honoring shutdown."""
    if not items or should_stop():
        return
    workers = max(1, min(threads, len(items)))
    log_info(f"{desc}: {len(items)} item(s), {workers} worker(s)")

    def _drain(futs: dict) -> None:
        try:
            for fut in concurrent.futures.as_completed(futs):
                if should_stop():
                    for f in futs:
                        f.cancel()
                    break
                try:
                    fut.result()
                except Exception as exc:
                    log_error(f"{desc} worker error on {futs[fut]}: {exc}")
        except KeyboardInterrupt:
            _SHUTDOWN.set()
            log_warn("Ctrl-C received — finishing in-flight work…")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="herecyex") as ex:
        futs = {ex.submit(fn, item): item for item in items}
        use_spinner = (
            console is not None
            and console.is_terminal
            and threading.current_thread() is threading.main_thread()
        )
        if use_spinner:
            with console.status(f"[tool]{desc}...[/]", spinner="dots"):
                _drain(futs)
        else:
            _drain(futs)


# ---------------------------------------------------------------------------
# Nmap XML parsing
# ---------------------------------------------------------------------------

def parse_nmap_xml(path: Path) -> list[dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception as exc:
        log_warn(f"Failed to parse nmap XML {path}: {exc}")
        return []

    hosts = []
    for h in root.findall("host"):
        rec: dict[str, Any] = {"addresses": [], "hostnames": [], "ports": [], "os": [], "scripts": []}
        status = h.find("status")
        rec["status"] = status.get("state") if status is not None else "unknown"
        for addr in h.findall("address"):
            rec["addresses"].append(
                {"addr": addr.get("addr", ""), "type": addr.get("addrtype", "")}
            )
        for hn in h.findall("hostnames/hostname"):
            rec["hostnames"].append(hn.get("name", ""))
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            state = state_el.get("state") if state_el is not None else ""
            if state not in {"open", "open|filtered"}:
                continue
            svc = p.find("service")
            scripts = []
            for sc in p.findall("script"):
                scripts.append({"id": sc.get("id", ""), "output": sc.get("output", "")})
            rec["ports"].append(
                {
                    "port": int(p.get("portid", 0)),
                    "protocol": p.get("protocol", "tcp"),
                    "state": state,
                    "service": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
                    "tunnel": (svc.get("tunnel") if svc is not None else "") or "",
                    "scripts": scripts,
                }
            )
        for osmatch in h.findall("os/osmatch"):
            rec["os"].append(
                {"name": osmatch.get("name", ""), "accuracy": osmatch.get("accuracy", "")}
            )
        for sc in h.findall("hostscript/script"):
            rec["scripts"].append({"id": sc.get("id", ""), "output": sc.get("output", "")})
        hosts.append(rec)
    return hosts


def ingest_nmap(state: RunState, xml_path: Path) -> None:
    for rec in parse_nmap_xml(xml_path):
        addrs = [a["addr"] for a in rec.get("addresses", []) if a.get("addr")]
        names = [n for n in rec.get("hostnames", []) if n]
        keys = addrs + names
        if not keys:
            continue
        primary = addrs[0] if addrs else names[0]
        hr = state.host(primary)
        if rec.get("status") == "up" or rec.get("ports"):
            hr.alive = True
        for a in addrs:
            if a not in hr.ips:
                hr.ips.append(a)
        for n in names:
            n2 = n.rstrip(".").lower()
            if n2 not in hr.names:
                hr.names.append(n2)
            other = state.host(n2, kind="domain")
            for a in addrs:
                if a not in other.ips:
                    other.ips.append(a)
        for p in rec.get("ports", []):
            bucket = hr.open_udp if p.get("protocol") == "udp" else hr.open_tcp
            if not any(x.get("port") == p["port"] and x.get("protocol") == p.get("protocol") for x in bucket):
                bucket.append(p)
            # Mirror onto other keys
            for k in keys[1:]:
                alt = state.host(k)
                b2 = alt.open_udp if p.get("protocol") == "udp" else alt.open_tcp
                if not any(x.get("port") == p["port"] and x.get("protocol") == p.get("protocol") for x in b2):
                    b2.append(p)
        harvest_nmap_scripts(state, primary, rec)


def harvest_nmap_scripts(state: RunState, host: str, rec: dict[str, Any]) -> None:
    """Turn high-signal nmap script output into findings-of-interest (not confirmed vulns)."""
    items = list(rec.get("scripts") or [])
    for p in rec.get("ports") or []:
        for sc in p.get("scripts") or []:
            items.append({**sc, "port": p.get("port"), "service": p.get("service")})

    for sc in items:
        sid = (sc.get("id") or "").lower()
        out = sc.get("output") or ""
        low = out.lower()
        port = sc.get("port", "")
        if sid in {"ftp-anon", "ftp-syst"} and ("anonymous ftp login allowed" in low or "anonymous login allowed" in low):
            state.add_finding(Finding(
                title="Anonymous FTP login allowed",
                severity="high",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
                detail="The FTP service appears to allow anonymous authentication. This is a finding of interest, not a confirmed exploit.",
            ))
        if sid in {"vnc-info"} and (
            "does not require authentication" in low or "security type: none" in low or "auth-none" in low
        ):
            state.add_finding(Finding(
                title="VNC advertises no authentication",
                severity="high",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
                detail="VNC appears to advertise Security Type None. This indicates unauthenticated screen access, not command execution.",
            ))
        if "smb" in sid and ("message signing is disabled" in low or "message signing enabled but not required" in low or "signing enabled: false" in low or "signing required: false" in low):
            state.add_finding(Finding(
                title="SMB signing not required",
                severity="medium",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
                detail="SMB signing appears disabled or not required. This is relevant for relay risk, not direct RCE.",
            ))
        if "smb" in sid and ("guest" in low and ("allowed" in low or "account" in low)):
            state.add_finding(Finding(
                title="SMB guest access hinted",
                severity="medium",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
            ))
        if sid in {"smtp-open-relay"} and ("open relay" in low and "not an open relay" not in low):
            state.add_finding(Finding(
                title="Possible SMTP open relay",
                severity="high",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
            ))
        if sid in {"ssl-cert", "ssl-date"} and ("expired" in low or "not yet valid" in low):
            state.add_finding(Finding(
                title="TLS certificate expired or not yet valid",
                severity="medium",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
            ))
        if sid.startswith("ssl-") and ("sslv2" in low or "sslv3" in low or "tlsv1.0" in low or "tls 1.0" in low):
            state.add_finding(Finding(
                title="Legacy SSL/TLS protocol advertised",
                severity="medium",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
            ))
        if sid in {"http-title"}:
            title = out.strip()
            if any(h in title.lower() for h in ADMIN_TITLE_HINTS):
                state.add_finding(Finding(
                    title=f"Possible admin or infrastructure panel: {title[:80]}",
                    severity="info",
                    host=f"{host}:{port}" if port else host,
                    source="nmap:http-title",
                    evidence=title[:800],
                    detail="Title matched a common administrative or infrastructure product string.",
                ))
        if sid in {"ms-sql-empty-password", "mysql-empty-password"} and "account" in low:
            state.add_finding(Finding(
                title="Database empty-password check flagged",
                severity="high",
                host=host,
                source=f"nmap:{sid}",
                evidence=out[:800],
                detail="Nmap reported a possible empty database password. Verify manually; this is not a confirmed exploit.",
            ))


# ---------------------------------------------------------------------------
# PHASE 1 — Passive recon / OSINT
# ---------------------------------------------------------------------------

def apex_domains(domains: Iterable[str]) -> list[str]:
    return unique(registrable_domain(d) for d in domains if is_domain(d))


def _collect_hostnames_from_text(text: str, apex: str) -> list[str]:
    apex = apex.lower().rstrip(".")
    found = set()
    # FQDN-looking tokens ending with the apex
    for m in re.findall(r"\b([A-Za-z0-9._-]+\." + re.escape(apex) + r")\b", text, flags=re.I):
        name = m.rstrip(".").lower()
        if is_domain(name):
            found.add(name)
    found.add(apex)
    return sorted(found)


def phase_passive(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 1 — Passive recon / OSINT")
    if not targets.domains:
        log_info("No domain names in the target list; skipping passive OSINT.")
        return

    apexes = apex_domains(targets.domains)
    log_info(f"Passive recon across {len(apexes)} apex domain(s): {', '.join(apexes)}")
    base = cfg.outdir / "passive"
    base.mkdir(parents=True, exist_ok=True)

    def work(apex: str) -> None:
        if should_stop():
            return
        maybe_wait(cfg)
        ddir = base / safe_name(apex)
        ddir.mkdir(parents=True, exist_ok=True)
        discovered: list[str] = [apex]

        # whois
        bin_whois = cfg.tools.path("whois")
        if bin_whois:
            run_cmd([bin_whois, apex], outfile=ddir / "whois.txt", timeout=min(cfg.timeout, 60),
                    skip_if_exists=cfg.skip_if_exists)

        # dig record grab
        bin_dig = cfg.tools.path("dig")
        if bin_dig:
            chunks = []
            for rr in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
                r = run_cmd(
                    [bin_dig, "+short", apex, rr],
                    outfile=None,
                    timeout=30,
                    skip_if_exists=False,
                    quiet=True,
                )
                if r.stdout.strip():
                    chunks.append(f";; {rr}\n{r.stdout.strip()}\n")
            # also NS hosts
            rns = run_cmd([bin_dig, "+short", apex, "NS"], timeout=30, quiet=True, skip_if_exists=False)
            if rns.stdout.strip():
                chunks.append(f";; NS servers\n{rns.stdout.strip()}\n")
            write_text(ddir / "dig.txt", "\n".join(chunks) if chunks else "")
            discovered.extend(_collect_hostnames_from_text("\n".join(chunks), apex))

        # subfinder
        bin_sf = cfg.tools.path("subfinder")
        if bin_sf:
            r = run_cmd(
                [bin_sf, "-d", apex, "-silent", "-o", str(ddir / "subfinder.txt")],
                outfile=ddir / "subfinder.log",
                timeout=max(cfg.timeout, 300),
                skip_if_exists=cfg.skip_if_exists,
            )
            discovered.extend(read_lines(ddir / "subfinder.txt"))
            if not (ddir / "subfinder.txt").exists() and r.stdout:
                write_lines(ddir / "subfinder.txt", r.stdout.splitlines())
                discovered.extend(r.stdout.splitlines())

        # amass passive
        bin_am = cfg.tools.path("amass")
        if bin_am:
            amass_out = ddir / "amass.txt"
            run_cmd(
                [bin_am, "enum", "-passive", "-norecursive", "-noalts", "-d", apex, "-o", str(amass_out)],
                outfile=ddir / "amass.log",
                timeout=max(cfg.timeout, 600 if cfg.profile != "quick" else 180),
                skip_if_exists=cfg.skip_if_exists,
            )
            discovered.extend(read_lines(amass_out))

        # assetfinder
        bin_af = cfg.tools.path("assetfinder")
        if bin_af:
            r = run_cmd(
                [bin_af, "--subs-only", apex],
                outfile=ddir / "assetfinder.txt",
                timeout=max(cfg.timeout, 180),
                skip_if_exists=cfg.skip_if_exists,
            )
            discovered.extend(r.stdout.splitlines())

        # crt.sh
        crt_names = query_crtsh(apex, ddir / "crtsh.json")
        discovered.extend(crt_names)

        # theHarvester — stick to free/public sources
        bin_th = cfg.tools.path("theHarvester")
        if bin_th:
            sources = "crtsh,hackertarget,dnsdumpster,urlscan,otx"
            th_out = ddir / "theharvester"
            run_cmd(
                [bin_th, "-d", apex, "-b", sources, "-l", "200", "-f", str(th_out)],
                outfile=ddir / "theharvester.log",
                timeout=max(cfg.timeout, 300),
                skip_if_exists=cfg.skip_if_exists,
            )
            for cand in (ddir / "theharvester.json", Path(str(th_out) + ".json"), ddir / "theharvester.xml"):
                if cand.exists():
                    discovered.extend(_collect_hostnames_from_text(cand.read_text(encoding="utf-8", errors="replace"), apex))
            discovered.extend(_collect_hostnames_from_text((ddir / "theharvester.log").read_text(encoding="utf-8", errors="replace") if (ddir / "theharvester.log").exists() else "", apex))

        # dnsrecon -t std also attempts AXFR against the zone's NS hosts.
        # Those servers are often a third-party DNS provider. AXFR is done
        # later, and only to name-server addresses that are in scope.
        if cfg.tools.path("dnsrecon"):
            log_info(f"{apex}: not running dnsrecon -t std (it attempts AXFR before the NS address is scope-checked)")

        # gau / waybackurls (passive URL discovery)
        for tool, args in (
            ("gau", lambda: [cfg.tools.path("gau"), "--subs", apex]),
            ("waybackurls", lambda: [cfg.tools.path("waybackurls"), apex]),
        ):
            binv = cfg.tools.path(tool)
            if not binv:
                continue
            cmd = args()
            cmd[0] = binv
            r = run_cmd(cmd, outfile=ddir / f"{tool}.txt", timeout=max(cfg.timeout, 180), skip_if_exists=cfg.skip_if_exists)
            if r.stdout:
                discovered.extend(_collect_hostnames_from_text(r.stdout, apex))
                # keep a sample of discovered URLs for later web phase
            if (ddir / f"{tool}.txt").exists():
                discovered.extend(_collect_hostnames_from_text((ddir / f"{tool}.txt").read_text(encoding="utf-8", errors="replace"), apex))

        # dnsx or dig already handled; also collect from any leftover files
        names = []
        for n in discovered:
            n2 = n.strip().rstrip(".").lower()
            n2 = n2.replace("*.", "")
            if not n2 or not is_domain(n2):
                continue
            # stay under this apex
            if n2 == apex or n2.endswith("." + apex):
                if cfg.scope_suffixes and not in_scope(n2, cfg.scope_nets, cfg.scope_suffixes):
                    continue
                names.append(n2)
        names = unique(names)
        write_lines(ddir / "subdomains.txt", names)
        added = state.add_subdomains(names)
        log_ok(f"{apex}: {len(names)} unique hostname(s), {len(added)} new")

    run_pool(work, apexes, cfg.threads, "passive recon")

    # Merge into the live-host pipeline
    for name in state.subdomains:
        targets.add_domain(name)
    targets.domains = unique(targets.domains)
    write_lines(base / "subdomains-all.txt", state.subdomains)
    write_lines(cfg.outdir / "targets" / "domains-after-passive.txt", targets.domains)
    log_ok(f"Passive phase complete — {len(state.subdomains)} unique subdomain(s) in pipeline")
    state.save()


def query_crtsh(apex: str, outfile: Path) -> list[str]:
    names: list[str] = []
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    data = http_get_json(url, timeout=45)
    if data is None:
        # curl fallback
        curl = which("curl")
        if curl:
            r = run_cmd(
                [curl, "-sS", "-A", f"HerecyEx/{__version__}", "--max-time", "45", url],
                outfile=outfile.with_suffix(".raw"),
                timeout=60,
                skip_if_exists=True,
                quiet=True,
            )
            try:
                data = json.loads(r.stdout) if r.stdout else None
            except json.JSONDecodeError:
                data = None
    if data is None:
        log_warn(f"crt.sh returned no data for {apex}")
        return []
    try:
        write_text(outfile, json.dumps(data, indent=2)[:2_000_000])
    except Exception:
        pass
    if not isinstance(data, list):
        return []
    seen = set()
    for row in data:
        for field_name in ("name_value", "common_name"):
            val = row.get(field_name) if isinstance(row, dict) else None
            if not val:
                continue
            for part in str(val).splitlines():
                n = part.strip().lower().rstrip(".").replace("*.", "")
                if n and is_domain(n) and n not in seen:
                    seen.add(n)
                    names.append(n)
    return names


# ---------------------------------------------------------------------------
# PHASE 2 — DNS resolution & liveness
# ---------------------------------------------------------------------------

def phase_resolve(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 2 — DNS resolution & host liveness")
    base = cfg.outdir / "resolve"
    base.mkdir(parents=True, exist_ok=True)

    domains = unique(list(targets.domains) + list(state.subdomains))
    write_lines(base / "domains-to-resolve.txt", domains)

    resolved: dict[str, list[str]] = {}  # name -> ips
    if domains:
        resolved = resolve_domains(cfg, base, domains)

    apply_resolution_scope(cfg, targets, resolved, state)
    write_lines(base / "resolved-ips.txt", targets.ips)
    write_text(base / "resolved.json", json.dumps(resolved, indent=2))
    log_ok(f"Resolved {sum(1 for v in resolved.values() if v)} name(s) to {len(targets.ips)} in-scope IP(s)")

    # Liveness — ICMP/TCP ping is informational. External hosts often drop ICMP,
    # so we still carry every in-scope IP into the port-scan phase unless
    # the operator explicitly passed --alive-only.
    if not cfg.no_active and targets.ips:
        alive = probe_liveness(cfg, base, targets.ips)
        for ip in alive:
            state.host(ip, kind="ip").alive = True
        write_lines(base / "icmp-tcp-alive.txt", alive)
        log_ok(f"Liveness probe: {len(alive)}/{len(targets.ips)} responded to ICMP/TCP ping")
        if cfg.alive_only:
            dropped = [i for i in targets.ips if i not in set(alive)]
            log_warn(f"--alive-only set; dropping {len(dropped)} non-responding IP(s) from later phases")
            targets.ips = [i for i in targets.ips if i in set(alive)]
    elif cfg.no_active:
        log_info("--no-active: skipping ICMP/TCP liveness and httpx")

    # httpx only sees names whose every address was allowed, plus those addresses.
    if not cfg.no_active:
        probe_hosts = filter_probe_tokens(list(targets.active_names) + list(targets.ips), cfg, targets)
        if probe_hosts:
            probe_httpx(cfg, state, targets, base / "httpx-live", probe_hosts)
        else:
            log_info("No in-scope hosts for httpx")

    write_lines(cfg.outdir / "targets" / "ips-after-resolve.txt", targets.ips)
    state.save()


def resolve_domains(cfg: Config, base: Path, domains: list[str]) -> dict[str, list[str]]:
    resolved: dict[str, list[str]] = defaultdict(list)
    bin_dnsx = cfg.tools.path("dnsx")
    if bin_dnsx:
        json_out = base / "dnsx.json"
        txt_out = base / "dnsx.txt"
        run_cmd(
            [bin_dnsx, "-l", str(base / "domains-to-resolve.txt"),
             "-a", "-aaaa", "-cname", "-resp", "-silent", "-json", "-o", str(json_out)],
            outfile=base / "dnsx.log",
            timeout=max(cfg.timeout, 300),
            skip_if_exists=cfg.skip_if_exists,
        )
        # dnsx also supports a simple text map
        if json_out.exists():
            for line in json_out.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = (rec.get("host") or rec.get("hostname") or "").rstrip(".").lower()
                ips = rec.get("a") or rec.get("A") or []
                aaaa = rec.get("aaaa") or rec.get("AAAA") or []
                if isinstance(ips, str):
                    ips = [ips]
                if isinstance(aaaa, str):
                    aaaa = [aaaa]
                # Some dnsx versions put addresses under "all" or "a" as list of {type,value}
                for key in ("all", "records"):
                    extra = rec.get(key) or []
                    if isinstance(extra, list):
                        for item in extra:
                            if isinstance(item, str) and is_ip(item):
                                ips.append(item)
                if host:
                    for ip in list(ips) + list(aaaa):
                        if isinstance(ip, str) and is_ip(ip) and ip not in resolved[host]:
                            resolved[host].append(ip)
        if resolved:
            return dict(resolved)

    # massdns fallback if a resolver list exists
    bin_md = cfg.tools.path("massdns")
    resolvers = Path("/etc/resolv.conf")
    # massdns wants a simple IP list of resolvers
    if bin_md and not resolved:
        resolver_file = base / "resolvers.txt"
        write_lines(resolver_file, ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        r = run_cmd(
            [bin_md, "-r", str(resolver_file), "-t", "A", "-o", "S", "-w", str(base / "massdns.txt"),
             str(base / "domains-to-resolve.txt")],
            outfile=base / "massdns.log",
            timeout=max(cfg.timeout, 300),
            skip_if_exists=cfg.skip_if_exists,
        )
        text = (base / "massdns.txt").read_text(encoding="utf-8", errors="replace") if (base / "massdns.txt").exists() else r.stdout
        for line in text.splitlines():
            # name. A IP
            m = re.match(r"^(\S+)\s+A\s+(\S+)$", line.strip(), re.I)
            if m and is_ip(m.group(2)):
                resolved[m.group(1).rstrip(".").lower()].append(m.group(2))
        if resolved:
            return dict(resolved)

    # dig fallback (threaded)
    bin_dig = cfg.tools.path("dig")
    if not bin_dig:
        log_warn("No dnsx, massdns, or dig available — cannot resolve names")
        return {}

    def one(name: str) -> None:
        if should_stop():
            return
        ips: list[str] = []
        for rr in ("A", "AAAA"):
            r = run_cmd([bin_dig, "+short", name, rr], timeout=20, quiet=True, skip_if_exists=False)
            for line in r.stdout.splitlines():
                cand = line.strip().split()[-1] if line.strip() else ""
                if is_ip(cand):
                    ips.append(cand)
        if ips:
            resolved[name] = unique(ips)

    run_pool(one, domains, min(cfg.threads, 16), "dig resolve")
    return dict(resolved)


def probe_liveness(cfg: Config, base: Path, ips: list[str]) -> list[str]:
    alive: list[str] = []
    ipfile = base / "ips-for-ping.txt"
    write_lines(ipfile, ips)

    bin_fping = cfg.tools.path("fping")
    if bin_fping:
        r = run_cmd(
            [bin_fping, "-a", "-C", "1", "-t", "500", "-f", str(ipfile)],
            outfile=base / "fping.txt",
            timeout=max(cfg.timeout, 180),
            skip_if_exists=cfg.skip_if_exists,
        )
        text = (base / "fping.txt").read_text(encoding="utf-8", errors="replace") if (base / "fping.txt").exists() else r.stdout
        for line in text.splitlines():
            tok = line.split()[0] if line.strip() else ""
            if is_ip(tok):
                alive.append(tok)
        return unique(alive)

    prefix, _flag = nmap_scan_flag(udp=False)
    # -sn ping scan: ICMP + TCP 80/443. -n no DNS.
    r = run_cmd(
        prefix + ["-sn", "-n", "-T4", "-oA", str(base / "nmap-ping"), "-iL", str(ipfile)],
        outfile=base / "nmap-ping.log",
        timeout=max(cfg.timeout, 300),
        skip_if_exists=cfg.skip_if_exists,
    )
    xml = base / "nmap-ping.xml"
    if xml.exists():
        for rec in parse_nmap_xml(xml):
            if rec.get("status") == "up":
                for a in rec.get("addresses", []):
                    if a.get("addr") and is_ip(a["addr"]):
                        alive.append(a["addr"])
    return unique(alive)


def probe_httpx(cfg: Config, state: RunState, targets: TargetSet, dest: Path, hosts: list[str]) -> list[dict[str, Any]]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    infile = dest.with_suffix(".in.txt")
    write_lines(infile, hosts)
    records: list[dict[str, Any]] = []
    bin_httpx = cfg.tools.path("httpx")
    if not bin_httpx:
        log_warn("httpx not installed — web liveness will rely on open web ports later")
        return records

    json_out = dest.with_suffix(".json")
    cmd = httpx_probe_args(bin_httpx, infile, json_out, cfg)
    run_cmd(cmd, outfile=dest.with_suffix(".log"), timeout=max(cfg.timeout, 600), skip_if_exists=cfg.skip_if_exists)
    if not json_out.exists():
        return records
    for line in json_out.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        records.append(rec)
        url = rec.get("url") or rec.get("input") or ""
        location = rec.get("location") or rec.get("final_url") or ""
        if location and not consider_redirect(str(location), cfg, targets):
            # The header is evidence. It is not a new probe target.
            targets.scope_decisions.append({
                "name": split_host_token(str(location)).lower(),
                "ips": [],
                "active": False,
                "reason": f"redirect Location from {url or rec.get('input')} was not probed: {location}",
            })
            log_info(f"Not following redirect from {url or rec.get('input')} to {location}")
        if not url_host_allowed(str(url or rec.get("input") or ""), cfg, targets):
            continue
        host = rec.get("host") or rec.get("input") or ""
        # strip scheme/port for the host key
        key = host
        if not key and url:
            key = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        if not key:
            continue
        hr = state.host(key)
        hr.alive = True
        entry = {
            "url": url,
            "status": rec.get("status_code") or rec.get("status-code") or rec.get("status"),
            "title": rec.get("title") or "",
            "tech": rec.get("tech") or rec.get("technologies") or [],
            "webserver": rec.get("webserver") or rec.get("server") or "",
            "content_type": rec.get("content_type") or rec.get("content-type") or "",
            "tls": rec.get("tls") or rec.get("tls-grab") or {},
            "final_url": rec.get("final_url") or rec.get("location") or url,
        }
        if not any(w.get("url") == url for w in hr.web):
            hr.web.append(entry)
        title = (entry.get("title") or "").lower()
        if any(h in title for h in ADMIN_TITLE_HINTS):
            state.add_finding(Finding(
                title=f"Possible admin or infrastructure panel: {entry.get('title','')[:80]}",
                severity="info",
                host=url or key,
                source="httpx",
                evidence=str(entry.get("title") or "")[:800],
            ))
    log_ok(f"httpx: {len(records)} live web endpoint(s)")
    return records


# ---------------------------------------------------------------------------
# PHASE 3 — Port scanning
# ---------------------------------------------------------------------------

def phase_ports(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 3 — Port scanning")
    if cfg.no_active:
        log_info("--no-active: skipping port scans")
        return
    ips = portscan_targets(cfg, targets)
    if not ips:
        log_warn(
            "No in-scope IP addresses to port-scan. "
            "Hostnames are not sent to naabu, rustscan, masscan, or nmap."
        )
        state.save()
        return

    base = cfg.outdir / "ports"
    base.mkdir(parents=True, exist_ok=True)
    write_lines(base / "scan-targets.txt", ips)

    discovered: dict[str, set[int]] = defaultdict(set)  # host -> tcp ports

    # Fast front-end
    frontend_ports = run_port_frontend(cfg, base, ips)
    for host, ports in frontend_ports.items():
        discovered[host].update(ports)

    # Confirm with nmap -sV only. -sC is not used; see nmap_service_cmd.
    confirm_nmap(cfg, state, base, ips, discovered)

    if cfg.full_ports and not should_stop():
        log_info("Full TCP port sweep (-p-) requested — this can take a long time")
        full_nmap(cfg, state, base, ips)

    if cfg.udp and not should_stop():
        if not can_raw_scan() and nmap_scan_flag(udp=True)[1] != "-sU":
            log_warn("UDP scan requested but raw sockets are unavailable (not root / no passwordless sudo). Skipping UDP.")
        else:
            udp_nmap(cfg, state, base, ips)

    # Summarize
    total_open = 0
    for h in state.hosts.values():
        total_open += len(h.open_tcp) + len(h.open_udp)
    log_ok(f"Port scan complete — ingested open-port records across {len(state.hosts)} host key(s)")
    state.save()


def run_port_frontend(cfg: Config, base: Path, ips: list[str]) -> dict[str, set[int]]:
    found: dict[str, set[int]] = defaultdict(set)
    infile = base / "scan-targets.txt"

    bin_naabu = cfg.tools.path("naabu")
    if bin_naabu:
        out = base / "naabu.txt"
        cmd = [
            bin_naabu, "-l", str(infile), "-top-ports", str(cfg.top_ports),
            "-silent", "-rate", str(cfg.naabu_rate), "-exclude-cdn",
            "-c", str(min(25, cfg.threads * 2)),
            "-o", str(out),
        ]
        if can_raw_scan() and not is_root() and sudo_n_available():
            # naabu may need cap or root for SYN; try without first, it falls back
            pass
        run_cmd(cmd, outfile=base / "naabu.log", timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        for line in read_lines(out):
            # host:port
            if ":" in line:
                host, _, port = line.rpartition(":")
                host = host.strip().strip("[]")
                try:
                    found[host].add(int(port))
                except ValueError:
                    continue
        if found:
            log_ok(f"naabu discovered ports on {len(found)} host(s)")
            return found

    bin_rs = cfg.tools.path("rustscan")
    if bin_rs:
        out = base / "rustscan.txt"
        # rustscan greppable: host -> [ports]
        # Batch via -a address list. rustscan accepts comma-separated or file depending on version.
        cmd = [bin_rs, "-a", str(infile), "--ulimit", "5000", "-g", "--", "-Pn"]
        r = run_cmd(cmd, outfile=out, timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else r.stdout
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+|\[?[A-Fa-f0-9:]+\]?)\s*->\s*\[([0-9, ]+)\]", text):
            host = m.group(1).strip("[]")
            for p in m.group(2).split(","):
                p = p.strip()
                if p.isdigit():
                    found[host].add(int(p))
        if found:
            log_ok(f"rustscan discovered ports on {len(found)} host(s)")
            return found

    bin_mc = cfg.tools.path("masscan")
    if bin_mc and can_raw_scan():
        out = base / "masscan.json"
        prefix = ["sudo", "-n", bin_mc] if not is_root() and sudo_n_available() else [bin_mc]
        # Conservative rate for external assessments
        cmd = prefix + [
            "-iL", str(infile), f"--top-ports", str(cfg.top_ports),
            "--rate", "500", "-oJ", str(out), "--wait", "3",
        ]
        # masscan --top-ports may not exist on all versions; fall back to a common set
        r = run_cmd(cmd, outfile=base / "masscan.log", timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        if r.returncode != 0:
            cmd = prefix + [
                "-iL", str(infile), "-p1-1024,1433,1521,2049,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017",
                "--rate", "500", "-oJ", str(out), "--wait", "3",
            ]
            run_cmd(cmd, outfile=base / "masscan.log", timeout=cfg.port_timeout, skip_if_exists=False)
        if out.exists():
            raw = out.read_text(encoding="utf-8", errors="replace").strip().rstrip(",")
            # masscan JSON is often concatenated objects
            try:
                data = json.loads(raw) if raw.startswith("[") else None
            except json.JSONDecodeError:
                data = None
            if data is None:
                for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in {"[", "]"}:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ip = rec.get("ip")
                    for p in rec.get("ports") or []:
                        if ip and p.get("port"):
                            found[ip].add(int(p["port"]))
            else:
                for rec in data:
                    ip = rec.get("ip")
                    for p in rec.get("ports") or []:
                        if ip and p.get("port"):
                            found[ip].add(int(p["port"]))
        if found:
            log_ok(f"masscan discovered ports on {len(found)} host(s)")
            return found
    elif bin_mc and not can_raw_scan():
        log_warn("masscan present but raw sockets unavailable; skipping masscan")

    log_info("No successful fast front-end — nmap will perform discovery")
    return found


def confirm_nmap(cfg: Config, state: RunState, base: Path, ips: list[str], discovered: dict[str, set[int]]) -> None:
    prefix, sflag = nmap_scan_flag(udp=False)
    outdir = base / "nmap-confirm"
    outdir.mkdir(parents=True, exist_ok=True)

    # If the frontend found ports, confirm those per host (batched when the set is shared).
    # Otherwise a single top-ports version/script scan.
    if not any(discovered.values()):
        out = outdir / "top-ports"
        cmd = nmap_service_cmd(
            cfg, prefix, sflag, out, base / "scan-targets.txt", top_ports=cfg.top_ports,
        )
        run_cmd(cmd, outfile=outdir / "top-ports.log", timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        ingest_nmap(state, Path(str(out) + ".xml"))
        return

    # Group hosts by identical port sets to reduce nmap invocations
    groups: dict[tuple[int, ...], list[str]] = defaultdict(list)
    unscanned = []
    for ip in ips:
        ports = discovered.get(ip) or discovered.get(ip.lower())
        if ports:
            groups[tuple(sorted(ports))].append(ip)
        else:
            unscanned.append(ip)

    def scan_group(item: tuple[tuple[int, ...], list[str]]) -> None:
        if should_stop():
            return
        maybe_wait(cfg)
        ports, hosts = item
        tag = "p" + "-".join(str(p) for p in ports[:8]) + (f"-plus{len(ports)-8}" if len(ports) > 8 else "")
        tag = f"{tag}-{len(hosts)}h"
        dest = outdir / safe_name(tag)
        hostfile = Path(str(dest) + ".hosts")
        write_lines(hostfile, hosts)
        port_str = ",".join(str(p) for p in ports)
        cmd = nmap_service_cmd(cfg, prefix, sflag, dest, hostfile, ports=port_str)
        run_cmd(cmd, outfile=Path(str(dest) + ".log"), timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        ingest_nmap(state, Path(str(dest) + ".xml"))

    run_pool(scan_group, list(groups.items()), min(cfg.threads, 6), "nmap service confirm")

    if unscanned and not should_stop():
        dest = outdir / "no-frontend-ports"
        hostfile = Path(str(dest) + ".hosts")
        write_lines(hostfile, unscanned)
        cmd = nmap_service_cmd(
            cfg, prefix, sflag, dest, hostfile, top_ports=cfg.top_ports,
        )
        run_cmd(cmd, outfile=Path(str(dest) + ".log"), timeout=cfg.port_timeout, skip_if_exists=cfg.skip_if_exists)
        ingest_nmap(state, Path(str(dest) + ".xml"))


def full_nmap(cfg: Config, state: RunState, base: Path, ips: list[str]) -> None:
    prefix, sflag = nmap_scan_flag(udp=False)
    dest = base / "nmap-full"
    # Moderate min-rate — thorough but not a flood
    cmd = prefix + [
        sflag, "-Pn", "-n", "-T3", "-p-", "--min-rate", "200", "--max-retries", "2",
        "-oA", str(dest),
        "-iL", str(base / "scan-targets.txt"),
    ] + cfg.extra_nmap
    run_cmd(cmd, outfile=base / "nmap-full.log", timeout=max(cfg.port_timeout, 7200), skip_if_exists=cfg.skip_if_exists)
    ingest_nmap(state, Path(str(dest) + ".xml"))
    # Service-scan any newly discovered ports that lack version info
    new_ports: dict[str, set[int]] = defaultdict(set)
    for key, hr in list(state.hosts.items()):
        if not is_ip(hr.target) and hr.ips:
            continue
        for p in hr.open_tcp:
            if not p.get("product") and not p.get("service"):
                new_ports[hr.ips[0] if hr.ips else hr.target].add(p["port"])
    # Optional second confirm skipped to keep runtime bounded; XML already ingested.


def udp_nmap(cfg: Config, state: RunState, base: Path, ips: list[str]) -> None:
    prefix, sflag = nmap_scan_flag(udp=True)
    if sflag != "-sU":
        log_warn("Could not select UDP scan mode; skipping")
        return
    dest = base / "nmap-udp"
    cmd = prefix + [
        "-sU", "-Pn", "-n", f"-T{cfg.nmap_timing}",
        "--top-ports", str(cfg.udp_top_ports),
        "-sV", "--version-intensity", "2",
        "-oA", str(dest),
        "-iL", str(base / "scan-targets.txt"),
    ] + cfg.extra_nmap
    run_cmd(cmd, outfile=base / "nmap-udp.log", timeout=max(cfg.port_timeout, 1800), skip_if_exists=cfg.skip_if_exists)
    ingest_nmap(state, Path(str(dest) + ".xml"))




# ---------------------------------------------------------------------------
# PHASE 4 — Web enumeration
# ---------------------------------------------------------------------------

def open_ports_for(hr: HostRecord, proto: str = "tcp") -> set[int]:
    bucket = hr.open_udp if proto == "udp" else hr.open_tcp
    return {int(p["port"]) for p in bucket if p.get("port") is not None}


def web_endpoints(state: RunState, targets: TargetSet, cfg: Optional[Config] = None) -> list[str]:
    """Build a de-duplicated list of URLs / hosts to feed web tools."""
    urls: list[str] = []
    seen = set()

    def add(u: str) -> None:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            urls.append(u)

    for hr in state.hosts.values():
        for w in hr.web:
            if w.get("url"):
                add(w["url"])
        ports = open_ports_for(hr)
        web_p = ports & WEB_PORTS
        keys = [hr.target] + hr.ips + hr.names
        if web_p:
            for key in unique(keys):
                if not key:
                    continue
                host = f"[{key}]" if is_ipv6(key) else key
                for p in sorted(web_p):
                    scheme = "https" if p in {443, 8443, 9443, 10443, 12443, 8531, 2083, 2087} or p == 443 else "http"
                    if p in {80, 443}:
                        add(f"{scheme}://{host}")
                    else:
                        # Prefer https on common TLS ports, http otherwise — httpx will fix up
                        if p in {8443, 9443, 10443, 12443, 8531, 2083, 2087, 8834}:
                            add(f"https://{host}:{p}")
                        else:
                            add(f"http://{host}:{p}")
                            if p not in {80}:
                                add(f"https://{host}:{p}")
        elif not ports and hr.web:
            pass
        elif not ports and (is_domain(hr.target) or hr.names):
            # No port data yet — still try 80/443 via httpx if we didn't already
            pass

    for name in unique(list(targets.active_names) + list(targets.ips)):
        add(name)
    if cfg is None:
        return urls
    return filter_probe_tokens(urls, cfg, targets)


def phase_web(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 4 — Web enumeration")
    if cfg.no_active:
        log_info("--no-active: skipping active web enumeration")
        return

    base = cfg.outdir / "web"
    base.mkdir(parents=True, exist_ok=True)

    if not targets.scope_decisions:
        resolved: dict[str, list[str]] = {}
        resolved_path = cfg.outdir / "resolve" / "resolved.json"
        if resolved_path.exists():
            try:
                loaded = json.loads(resolved_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    resolved = {str(k): list(v or []) for k, v in loaded.items()}
            except Exception as exc:
                log_warn(f"Could not reload resolved.json: {exc}")
        apply_resolution_scope(cfg, targets, resolved, state)

    hosts_for_httpx = list(targets.active_names) + list(targets.ips)
    for hr in state.hosts.values():
        ports = open_ports_for(hr)
        for p in sorted(ports & WEB_PORTS):
            if p in {80, 443}:
                continue
            for key in unique(hr.ips + ([hr.target] if is_ip(hr.target) else [])):
                hosts_for_httpx.append(f"{key}:{p}")
    hosts_for_httpx = filter_probe_tokens(hosts_for_httpx, cfg, targets)
    write_lines(base / "httpx-input.txt", hosts_for_httpx)
    if hosts_for_httpx:
        probe_httpx(cfg, state, targets, base / "httpx", hosts_for_httpx)

    live_urls = filter_probe_tokens(
        (
            w.get("url")
            for hr in state.hosts.values()
            for w in hr.web
            if w.get("url")
        ),
        cfg,
        targets,
    )
    write_lines(base / "live-urls.txt", live_urls)
    if cfg.scope_enforced:
        warn_scoped_ip_only(cfg)
        if cfg.nikto:
            log_warn("nikto was requested and is refused under --scope-check. " + REDIRECT_UNSCOPED_TOOLS["nikto"])
        if cfg.profile == "full":
            log_warn("katana is refused under --scope-check. " + REDIRECT_UNSCOPED_TOOLS["katana"])
    else:
        for tool, reason in REDIRECT_UNSCOPED_TOOLS.items():
            if tool == "nikto" and not cfg.nikto:
                continue
            if tool == "katana" and cfg.profile != "full":
                continue
            if cfg.tools.path(tool) or (tool == "nikto" and cfg.nikto):
                log_warn(reason)
    if not live_urls:
        log_info("No live web endpoints discovered")
        state.save()
        return
    log_info(f"Enumerating {len(live_urls)} live web endpoint(s)")

    # Per-URL light tools
    def per_url(url: str) -> None:
        if should_stop():
            return
        maybe_wait(cfg)
        udir = base / "hosts" / safe_name(re.sub(r"^https?://", "", url))
        udir.mkdir(parents=True, exist_ok=True)

        if not url_host_allowed(url, cfg, targets):
            return
        if cfg.tools.path("whatweb"):
            run_cmd(
                whatweb_args(cfg.tools.path("whatweb"), url, cfg),
                outfile=udir / "whatweb.txt",
                timeout=min(cfg.timeout, 120),
                skip_if_exists=cfg.skip_if_exists,
            )
        if cfg.tools.path("wafw00f"):
            run_cmd(
                wafw00f_args(cfg.tools.path("wafw00f"), url),
                outfile=udir / "wafw00f.txt",
                timeout=min(cfg.timeout, 90),
                skip_if_exists=cfg.skip_if_exists,
            )
            harvest_waf(state, url, udir / "wafw00f.txt")

        is_https = url.lower().startswith("https://")
        if is_https:
            tls_enum(cfg, state, url, udir)

        if cfg.direnum:
            dir_enum(cfg, state, url, udir)

    # Bound per-URL parallelism; dir enum / sslscan can be heavy
    url_threads = min(cfg.threads, 8 if cfg.profile == "full" else 12)
    run_pool(per_url, live_urls, url_threads, "web per-URL enum")

    # Nuclei can request hosts other than the URL it was given. Under
    # --scope-check it is not started, including when the operator did not pass --no-nuclei.
    if nuclei_enabled(cfg):
        run_nuclei(cfg, state, base, base / "live-urls.txt")
    elif cfg.scope_enforced:
        warn_scoped_ip_only(cfg)
        log_warn("Nuclei disabled: --scope-check is set. Template requests cannot be limited to the input host.")
    else:
        log_info("Nuclei disabled (--no-nuclei)")

    # Screenshots are not taken. Browsers follow redirects off-host. See REDIRECT_UNSCOPED_TOOLS.

    # tlsx batched if present
    if cfg.tools.path("tlsx"):
        https_urls = [u for u in live_urls if u.lower().startswith("https://")]
        if https_urls:
            write_lines(base / "https-urls.txt", https_urls)
            run_cmd(
                [cfg.tools.path("tlsx"), "-l", str(base / "https-urls.txt"), "-silent", "-json",
                 "-san", "-cn", "-so", "-expired", "-self-signed", "-mismatched",
                 "-o", str(base / "tlsx.json")],
                outfile=base / "tlsx.log",
                timeout=max(cfg.timeout, 300),
                skip_if_exists=cfg.skip_if_exists,
            )
            harvest_tlsx(state, base / "tlsx.json")

    state.save()


def harvest_waf(state: RunState, url: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"is behind\s+\S+", text, re.I) or "is protected by" in text.lower():
        state.add_finding(Finding(
            title="Web application firewall detected",
            severity="info",
            host=url,
            source="wafw00f",
            evidence=text[:800],
        ))


def tls_enum(cfg: Config, state: RunState, url: str, udir: Path) -> None:
    hostport = re.sub(r"^https?://", "", url).split("/")[0]
    ran = False
    if cfg.tools.path("sslscan"):
        run_cmd(
            [cfg.tools.path("sslscan"), "--no-colour", hostport],
            outfile=udir / "sslscan.txt",
            timeout=min(cfg.timeout, 180),
            skip_if_exists=cfg.skip_if_exists,
        )
        harvest_sslscan(state, url, udir / "sslscan.txt")
        ran = True
    # --testssl adds testssl.sh alongside sslscan. If sslscan is missing,
    # testssl.sh is the fallback so TLS enum is not silently skipped.
    if cfg.tools.path("testssl") and (cfg.testssl or not ran):
        run_cmd(
            [cfg.tools.path("testssl"), "--fast", "--color", "0", "--quiet", url],
            outfile=udir / "testssl.txt",
            timeout=max(cfg.timeout, 400),
            skip_if_exists=cfg.skip_if_exists,
        )
        harvest_testssl(state, url, udir / "testssl.txt")


def harvest_sslscan(state: RunState, host: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    if "sslv2" in low and "enabled" in low:
        state.add_finding(Finding(title="SSLv2 enabled", severity="high", host=host, source="sslscan", evidence=_extract_line(text, "SSLv2")))
    if re.search(r"sslv3.*enabled", low) or ("sslv3" in low and "enabled" in low):
        if re.search(r"SSLv3\s+enabled", text, re.I):
            state.add_finding(Finding(title="SSLv3 enabled", severity="high", host=host, source="sslscan", evidence=_extract_line(text, "SSLv3")))
    if re.search(r"TLSv1\.0\s+enabled", text, re.I):
        state.add_finding(Finding(title="TLS 1.0 enabled", severity="medium", host=host, source="sslscan", evidence=_extract_line(text, "TLSv1.0")))
    if re.search(r"TLSv1\.1\s+enabled", text, re.I):
        state.add_finding(Finding(title="TLS 1.1 enabled", severity="low", host=host, source="sslscan", evidence=_extract_line(text, "TLSv1.1")))
    if "expired" in low:
        state.add_finding(Finding(title="TLS certificate may be expired", severity="medium", host=host, source="sslscan", evidence=text[:800]))
    if "self signed" in low or "self-signed" in low:
        state.add_finding(Finding(title="Self-signed TLS certificate", severity="low", host=host, source="sslscan", evidence=_extract_line(text, "self")))
    if re.search(r"\b(RC4|DES|MD5|NULL|EXPORT|anon)\b", text):
        # Only flag if those appear in a cipher line that isn't "disabled"
        for line in text.splitlines():
            if re.search(r"\b(RC4|DES-CBC|MD5|NULL-SHA|EXP-|ADH-|AECDH-)", line) and "rejected" not in line.lower() and "disabled" not in line.lower():
                state.add_finding(Finding(
                    title="Weak TLS cipher advertised",
                    severity="medium",
                    host=host,
                    source="sslscan",
                    evidence=line.strip()[:800],
                ))
                break


def harvest_testssl(state: RunState, host: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    for label, sev, pat in (
        ("SSLv3 enabled", "high", r"SSLv3\s+.*(?:offered|vulnerable|YES)"),
        ("TLS 1.0 enabled", "medium", r"TLS 1\.0\s+.*(?:offered|YES)"),
        ("Expired certificate", "medium", r"expired"),
        ("Heartbleed indication", "high", r"Heartbleed"),
    ):
        if re.search(pat, text, re.I) and not re.search(pat + r".*(not vulnerable|no\b|OK\b)", text, re.I):
            # Heartbleed especially needs care — only flag if not clearly negative
            if "Heartbleed" in label and re.search(r"Heartbleed\s+.*(not vulnerable|no\b)", text, re.I):
                continue
            state.add_finding(Finding(title=label, severity=sev, host=host, source="testssl.sh", evidence=text[:800]))


def harvest_tlsx(state: RunState, path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = rec.get("host") or rec.get("ip") or rec.get("input") or ""
        if rec.get("expired"):
            state.add_finding(Finding(title="TLS certificate expired", severity="medium", host=str(host), source="tlsx", evidence=json.dumps(rec)[:800]))
        if rec.get("self_signed") or rec.get("self-signed"):
            state.add_finding(Finding(title="Self-signed TLS certificate", severity="low", host=str(host), source="tlsx", evidence=json.dumps(rec)[:800]))
        if rec.get("mismatched") or rec.get("mismatch"):
            state.add_finding(Finding(title="TLS name mismatch", severity="low", host=str(host), source="tlsx", evidence=json.dumps(rec)[:800]))


def _extract_line(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle.lower() in line.lower():
            return line.strip()[:800]
    return text[:400]


def dir_enum(cfg: Config, state: RunState, url: str, udir: Path) -> None:
    """
    Content discovery only (not credential brute force). Rate-limited, modest wordlist.
    Disabled in --quick unless --direnum is set; skip with --no-direnum.
    """
    wordlist = cfg.wordlist or find_wordlist()
    if not wordlist:
        log_warn("No directory wordlist found (install seclists). Skipping content discovery.")
        return
    out = udir / "direnum.txt"

    # None of these argv lists pass a follow-redirect flag. A 3xx is recorded, not fetched.
    if cfg.tools.path("feroxbuster"):
        run_cmd(
            ferox_args(cfg.tools.path("feroxbuster"), url, wordlist, out, cfg),
            outfile=udir / "direnum.log",
            timeout=min(max(cfg.timeout, 300), 600),
            skip_if_exists=cfg.skip_if_exists,
        )
    elif cfg.tools.path("gobuster"):
        run_cmd(
            gobuster_args(cfg.tools.path("gobuster"), url, wordlist, out, cfg),
            outfile=udir / "direnum.log",
            timeout=min(max(cfg.timeout, 300), 600),
            skip_if_exists=cfg.skip_if_exists,
        )
    elif cfg.tools.path("ffuf"):
        run_cmd(
            ffuf_args(cfg.tools.path("ffuf"), url, wordlist, udir / "direnum.json", cfg),
            outfile=udir / "direnum.log",
            timeout=min(max(cfg.timeout, 300), 600),
            skip_if_exists=cfg.skip_if_exists,
        )
        # flatten json into text
        jpath = udir / "direnum.json"
        if jpath.exists() and not out.exists():
            try:
                data = json.loads(jpath.read_text(encoding="utf-8", errors="replace"))
                rows = data.get("results") or []
                write_lines(out, [f"{r.get('status')} {r.get('url') or r.get('input')}" for r in rows])
            except Exception:
                pass
    else:
        return

    harvest_direnum(state, url, out)


def harvest_direnum(state: RunState, url: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    interesting = (
        "admin", "login", "phpmyadmin", "wp-admin", "wp-login", "cgi-bin",
        "manager", "console", "actuator", "swagger", "graphql", "server-status",
        "server-info", ".git", ".env", "backup", "config", "jenkins", "grafana",
        "horizon", "vcenter", "owa", "ecp", "exchange", "remote", "vpn",
        "openapi", "api-docs", "robots.txt", "security.txt",
    )
    hits = []
    for line in text.splitlines():
        low = line.lower()
        if any(tok in low for tok in interesting):
            hits.append(line.strip())
    if hits:
        state.add_finding(Finding(
            title="Interesting web path(s) discovered",
            severity="info",
            host=url,
            source="direnum",
            evidence="\n".join(hits[:25])[:1200],
            detail="Content discovery hit names commonly associated with admin, backup, or debug endpoints. Not a confirmed vulnerability.",
        ))


def run_nuclei(cfg: Config, state: RunState, base: Path, urlfile: Path) -> None:
    bin_n = cfg.tools.path("nuclei")
    if not bin_n:
        cfg.tools.require("nuclei")
        return
    json_out = base / "nuclei.jsonl"
    cmd = nuclei_probe_args(bin_n, urlfile, json_out, cfg)
    r = run_cmd(cmd, outfile=base / "nuclei.log", timeout=max(cfg.timeout, 1200), skip_if_exists=cfg.skip_if_exists)
    if r.returncode != 0 and (not json_out.exists() or json_out.stat().st_size == 0):
        # Do not retry without -disable-redirects. A nuclei that rejects the
        # flag would otherwise follow per-template redirects off-scope.
        log_warn("nuclei produced no JSONL. Not retrying without -disable-redirects.")
    count = harvest_nuclei(state, json_out)
    log_ok(f"Nuclei: ingested {count} result(s) (findings of interest, not confirmed exploits)")


def harvest_nuclei(state: RunState, path: Path) -> int:
    records = parse_nuclei_records(path)
    count = 0
    for rec in records:
        count += 1
        info = rec.get("info") or {}
        host = rec.get("host") or rec.get("matched-at") or rec.get("matched_at") or rec.get("url") or rec.get("ip") or ""
        template = rec.get("template-id") or rec.get("templateID") or rec.get("template-path") or ""
        name = info.get("name") or template
        sev = str(info.get("severity") or "info").lower()
        tags = info.get("tags") or rec.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        entry = {
            "template": template,
            "name": name,
            "severity": sev,
            "host": host,
            "matched": rec.get("matched-at") or rec.get("matched_at") or "",
            "tags": tags,
        }
        # attach to host record when possible
        key = re.sub(r"^https?://", "", str(host)).split("/")[0].split(":")[0]
        if key:
            hr = state.host(key)
            hr.nuclei.append(entry)

        interesting = any(
            t in {str(x).lower() for x in tags}
            for t in ("default-login", "exposure", "exposed-panel", "misconfig", "cve", "rce", "sqli", "lfi", "xss", "takeover")
        ) or sev in {"medium", "high", "critical"}
        if interesting or sev in {"low", "info"} and any(
            k in (template + " " + name).lower()
            for k in ("default-login", "exposed-panel", "anonymous", "unauth", "takeover", "expired", "weak")
        ):
            # Cap info-level noise: only keep high-signal info
            if sev in {"info"} and not any(
                k in (template + " " + " ".join(map(str, tags)) + " " + name).lower()
                for k in ("exposed-panel", "default-login", "exposure", "misconfig", "takeover", "expired")
            ):
                continue
            state.add_finding(Finding(
                title=str(name)[:160],
                severity=sev if sev in {"info", "low", "medium", "high", "critical"} else "info",
                host=str(host),
                source=f"nuclei:{template}",
                evidence=(rec.get("matcher-name") or rec.get("extracted-results") or rec.get("matched-at") or "")[:800]
                         if not isinstance(rec.get("extracted-results"), list)
                         else ", ".join(map(str, rec.get("extracted-results") or []))[:800],
                detail="Nuclei template match. Treat as a lead to verify — not a confirmed exploit.",
            ))
    return count


def screenshot(cfg: Config, base: Path, urlfile: Path) -> None:
    shotdir = base / "screenshots"
    shotdir.mkdir(parents=True, exist_ok=True)
    if cfg.tools.path("gowitness"):
        run_cmd(
            [cfg.tools.path("gowitness"), "scan", "file", "-f", str(urlfile),
             "--screenshot-path", str(shotdir)],
            outfile=base / "gowitness.log",
            timeout=max(cfg.timeout, 600),
            skip_if_exists=cfg.skip_if_exists,
        )
        # gowitness CLI has changed across versions; try a second syntax if needed
        if not any(shotdir.iterdir()) and not cfg.skip_if_exists:
            run_cmd(
                [cfg.tools.path("gowitness"), "file", "-f", str(urlfile), "-P", str(shotdir)],
                outfile=base / "gowitness.log",
                timeout=max(cfg.timeout, 600),
                skip_if_exists=False,
            )
        return
    if cfg.tools.path("eyewitness"):
        run_cmd(
            [cfg.tools.path("eyewitness"), "-f", str(urlfile), "-d", str(shotdir), "--no-prompt", "--web"],
            outfile=base / "eyewitness.log",
            timeout=max(cfg.timeout, 900),
            skip_if_exists=cfg.skip_if_exists,
        )


# ---------------------------------------------------------------------------
# PHASE 5 — Service-specific enumeration
# ---------------------------------------------------------------------------

def hosts_with_port(
    state: RunState,
    ports: set[int],
    proto: str = "tcp",
    allowed_ips: Optional[set[str]] = None,
) -> list[tuple[HostRecord, int]]:
    """Open-port jobs keyed by an allowed IP. Hostnames are not substituted."""
    out = []
    seen = set()
    for hr in state.hosts.values():
        openp = open_ports_for(hr, proto)
        hit = openp & ports
        if not hit:
            continue
        candidates = [ip for ip in hr.ips if is_ip(ip)]
        if is_ip(hr.target):
            candidates.insert(0, hr.target)
        target = None
        for ip in candidates:
            if allowed_ips is None or ip in allowed_ips:
                target = ip
                break
        if target is None:
            continue
        for p in sorted(hit):
            sig = (target, p, proto)
            if sig in seen:
                continue
            seen.add(sig)
            pinned = state.host(target, kind="ip")
            out.append((pinned, p))
    return out


def phase_services(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 5 — Service-specific enumeration")
    if cfg.no_active:
        log_info("--no-active: skipping service enumeration")
        return
    base = cfg.outdir / "services"
    base.mkdir(parents=True, exist_ok=True)

    jobs = []
    allowed_ips = set(portscan_targets(cfg, targets))

    def add_job(kind: str, hr: HostRecord, port: int, fn) -> None:
        jobs.append((kind, hr, port, fn))

    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["ftp"], allowed_ips=allowed_ips):
        add_job("ftp", hr, port, enum_ftp)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["ssh"], allowed_ips=allowed_ips):
        add_job("ssh", hr, port, enum_ssh)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["smtp"], allowed_ips=allowed_ips):
        add_job("smtp", hr, port, enum_smtp)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["dns"], allowed_ips=allowed_ips):
        add_job("dns", hr, port, enum_dns)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["smb"], allowed_ips=allowed_ips):
        add_job("smb", hr, port, enum_smb)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["snmp"], proto="udp", allowed_ips=allowed_ips):
        add_job("snmp", hr, port, enum_snmp)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["ldap"], allowed_ips=allowed_ips):
        add_job("ldap", hr, port, enum_ldap)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["rdp"], allowed_ips=allowed_ips):
        add_job("rdp", hr, port, enum_rdp)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["vnc"], allowed_ips=allowed_ips):
        add_job("vnc", hr, port, enum_vnc)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["mssql"], allowed_ips=allowed_ips):
        add_job("mssql", hr, port, enum_mssql)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["mysql"], allowed_ips=allowed_ips):
        add_job("mysql", hr, port, enum_mysql)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["redis"], allowed_ips=allowed_ips):
        add_job("redis", hr, port, enum_banner_script)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["mongodb"], allowed_ips=allowed_ips):
        add_job("mongodb", hr, port, enum_banner_script)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["docker"], allowed_ips=allowed_ips):
        add_job("docker", hr, port, enum_banner_script)
    for hr, port in hosts_with_port(state, SERVICE_PORT_MAP["k8s"], allowed_ips=allowed_ips):
        add_job("k8s", hr, port, enum_banner_script)

    # Zone transfers against discovered NS even if port 53 wasn't in the nmap top-ports set
    if targets.domains and cfg.tools.path("dig"):
        jobs.append(("axfr-apex", None, 53, None))

    log_info(f"Service enum jobs: {len(jobs)}")

    def run_job(job) -> None:
        if should_stop():
            return
        maybe_wait(cfg)
        kind, hr, port, fn = job
        if kind == "axfr-apex":
            enum_zone_transfers(cfg, state, targets, base / "axfr")
            return
        target = hr.target if is_ip(hr.target) else (hr.ips[0] if hr.ips else "")
        if not target or not ip_allowed(target, cfg, targets):
            log_info(f"Skipping {kind} enum: {target or hr.target} is not an in-scope address")
            return
        sdir = base / safe_name(target)
        sdir.mkdir(parents=True, exist_ok=True)
        try:
            fn(cfg, state, hr, target, port, sdir)
        except Exception as exc:
            log_error(f"{kind} enum failed for {target}:{port}: {exc}")

    run_pool(run_job, jobs, min(cfg.threads, 8), "service enum")
    state.save()


def nmap_script_enum(
    cfg: Config,
    state: RunState,
    target: str,
    port: int,
    scripts: str,
    outfile_base: Path,
    udp: bool = False,
    script_args: Optional[str] = None,
) -> None:
    """Run a fixed, non-brute nmap script set. Refuses anything that looks intrusive."""
    unsafe = [tok for tok in re.split(r"[, ]+", scripts) if tok and _UNSAFE_NMAP_SCRIPT.search(tok)]
    if unsafe:
        log_warn(f"Refusing nmap scripts with intrusive names ({', '.join(unsafe)}); skipping {target}:{port}")
        return
    prefix, sflag = nmap_scan_flag(udp=udp)
    if udp:
        sflag = "-sU"
    cmd = prefix + [
        sflag, "-Pn", "-n", f"-T{cfg.nmap_timing}",
        "-p", str(port),
        "--script", scripts,
    ]
    if script_args:
        cmd.extend(["--script-args", script_args])
    cmd += ["-oA", str(outfile_base), target]
    run_cmd(cmd, outfile=Path(str(outfile_base) + ".log"), timeout=min(max(cfg.timeout, 180), 400), skip_if_exists=cfg.skip_if_exists)
    ingest_nmap(state, Path(str(outfile_base) + ".xml"))


def enum_ftp(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, "ftp-anon,ftp-syst,ftp-feat", sdir / f"ftp-{port}")
    hr.services.setdefault("ftp", []).append({"port": port, "file": str(sdir / f"ftp-{port}.xml")})


def enum_ssh(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey", sdir / f"ssh-{port}")
    bin_sa = cfg.tools.path("ssh-audit")
    if bin_sa:
        run_cmd(
            [bin_sa, "-p", str(port), target],
            outfile=sdir / f"ssh-audit-{port}.txt",
            timeout=min(cfg.timeout, 90),
            skip_if_exists=cfg.skip_if_exists,
        )
        harvest_ssh_audit(state, target, sdir / f"ssh-audit-{port}.txt")
    hr.services.setdefault("ssh", []).append({"port": port})


def harvest_ssh_audit(state: RunState, host: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    # ssh-audit marks weak algos; look for [fail] or (cvss) warnings without over-claiming
    fails = [ln.strip() for ln in text.splitlines() if re.search(r"\[fail\]|# fail|warn \(cvss", ln, re.I)]
    if fails:
        state.add_finding(Finding(
            title="SSH algorithm issues reported by ssh-audit",
            severity="low",
            host=host,
            source="ssh-audit",
            evidence="\n".join(fails[:20])[:1200],
            detail="ssh-audit flagged weak or legacy algorithms. Verify against the client's baseline; this is not an exploit.",
        ))


def enum_smtp(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    scripts = smtp_scripts(cfg)
    args = None
    if "smtp-enum-users" in scripts:
        probe = sdir / "smtp-single-probe.txt"
        write_text(probe, SMTP_SINGLE_PROBE + "\n")
        args = smtp_script_args(probe)
    else:
        log_info(
            f"SMTP {target}:{port}: smtp-commands only. "
            "smtp-vrfy is not an NSE script. smtp-enum-users and smtp-open-relay "
            "stay off without --allow-intrusive-checks and --authorized."
        )
    nmap_script_enum(cfg, state, target, port, scripts, sdir / f"smtp-{port}", script_args=args)
    hr.services.setdefault("smtp", []).append({"port": port})


def enum_dns(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    """AXFR only at the in-scope address that had port 53 open. Never at a hostname."""
    bin_dig = cfg.tools.path("dig")
    if not bin_dig:
        return
    if not is_ip(target):
        log_warn(f"Skipping AXFR against {target}: not an address")
        return
    zones = unique(
        registrable_domain(n)
        for n in list(hr.names) + list(state.subdomains)
        if is_domain(n)
    )
    for name in zones:
        outfile = sdir / f"axfr-{safe_name(name)}-{port}.txt"
        r = run_cmd(
            [bin_dig, f"@{target}", name, "AXFR", "+time=8", "+tries=1"],
            outfile=outfile,
            timeout=30,
            skip_if_exists=cfg.skip_if_exists,
        )
        harvest_axfr(state, target, name, outfile, r.stdout)
    hr.services.setdefault("dns", []).append({"port": port})


def enum_zone_transfers(cfg: Config, state: RunState, targets: TargetSet, dest: Path) -> None:
    bin_dig = cfg.tools.path("dig")
    if not bin_dig:
        return
    dest.mkdir(parents=True, exist_ok=True)
    apexes = apex_domains(targets.domains)
    for apex in apexes:
        if should_stop():
            return
        rns = run_cmd([bin_dig, "+short", apex, "NS"], timeout=20, quiet=True, skip_if_exists=False)
        nss = [ln.strip().rstrip(".") for ln in rns.stdout.splitlines() if ln.strip()]
        for ns in nss:
            ips: list[str] = [ns] if is_ip(ns) else []
            if not is_ip(ns):
                for rr in ("A", "AAAA"):
                    ra = run_cmd(
                        [bin_dig, "+short", ns, rr],
                        timeout=15,
                        quiet=True,
                        skip_if_exists=False,
                    )
                    for line in ra.stdout.splitlines():
                        cand = line.strip().split()[-1] if line.strip() else ""
                        if is_ip(cand):
                            ips.append(cand)
            chosen = axfr_server_ips(ns, ips, cfg, targets)
            if not chosen:
                log_warn(f"Skipping AXFR via {ns}: name server is not an in-scope address")
                targets.scope_decisions.append({
                    "name": ns.rstrip(".").lower(),
                    "ips": ips,
                    "active": False,
                    "reason": "AXFR not sent; name server is outside the allowlist or the target IP/CIDR set",
                })
                continue
            for ip in chosen:
                outfile = dest / f"axfr-{safe_name(apex)}-via-{safe_name(ip)}.txt"
                r = run_cmd(
                    [bin_dig, f"@{ip}", apex, "AXFR", "+time=8", "+tries=1"],
                    outfile=outfile,
                    timeout=30,
                    skip_if_exists=cfg.skip_if_exists,
                )
                harvest_axfr(state, ip, apex, outfile, r.stdout)


def harvest_axfr(state: RunState, server: str, zone: str, path: Path, stdout: str = "") -> None:
    text = stdout or ""
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    if "transfer failed" in low or "refused" in low or "timeout" in low or "not implemented" in low:
        return
    # Success heuristic: multiple resource records and no failure banner
    rr_lines = [ln for ln in text.splitlines() if re.search(r"\s+(IN|in)\s+(A|AAAA|NS|MX|TXT|CNAME|SOA)\s+", ln)]
    if len(rr_lines) >= 3 and "failed" not in low:
        state.add_finding(Finding(
            title=f"DNS zone transfer (AXFR) succeeded for {zone}",
            severity="high",
            host=server,
            source="dig-axfr",
            evidence="\n".join(rr_lines[:30])[:1200],
            detail="The name server permitted a full zone transfer. This is an information-disclosure finding, not an exploit.",
        ))


def enum_smb(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(
        cfg, state, target, port,
        "smb-protocols,smb-security-mode,smb2-security-mode,smb-os-discovery,smb2-time",
        sdir / f"smb-{port}",
    )
    e4 = cfg.tools.path("enum4linux-ng") or cfg.tools.path("enum4linux")
    if e4:
        args = [e4, "-A", target] if "enum4linux-ng" in e4 or Path(e4).name == "enum4linux-ng" else [e4, "-a", target]
        # enum4linux-ng default -A is safe-ish enumeration (no brute). Keep a tight timeout.
        run_cmd(args, outfile=sdir / f"enum4linux-{port}.txt", timeout=min(max(cfg.timeout, 180), 400), skip_if_exists=cfg.skip_if_exists)
        harvest_smb_text(state, target, sdir / f"enum4linux-{port}.txt")
    if cfg.tools.path("smbmap"):
        run_cmd(
            [cfg.tools.path("smbmap"), "-H", target],
            outfile=sdir / f"smbmap-{port}.txt",
            timeout=min(cfg.timeout, 180),
            skip_if_exists=cfg.skip_if_exists,
        )
        harvest_smb_text(state, target, sdir / f"smbmap-{port}.txt")
    hr.services.setdefault("smb", []).append({"port": port})


def harvest_smb_text(state: RunState, host: str, path: Path) -> None:
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    low = text.lower()
    if "signing" in low and ("not required" in low or "disabled" in low or "signing enabled: false" in low):
        state.add_finding(Finding(title="SMB signing not required", severity="medium", host=host, source=path.name, evidence=text[:800]))
    if re.search(r"guest.*(access|login|allowed|ok)|null session", low):
        state.add_finding(Finding(title="SMB guest / null session hinted", severity="medium", host=host, source=path.name, evidence=text[:800]))
    if re.search(r"(Sharename|Disk|IPC)", text, re.I):
        # Don't over-claim; note share listing succeeded
        state.add_finding(Finding(
            title="SMB share listing obtained",
            severity="info",
            host=host,
            source=path.name,
            evidence=text[:800],
            detail="A share inventory was returned. Review permissions manually; this is not proof of write access.",
        ))


def enum_snmp(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    # Default community "public" only — not a community-string brute force
    comm_file = sdir / "snmp-communities.txt"
    write_lines(comm_file, SNMP_COMMUNITIES)
    bin_161 = cfg.tools.path("onesixtyone")
    if bin_161:
        r = run_cmd(
            [bin_161, "-c", str(comm_file), target],
            outfile=sdir / "onesixtyone.txt",
            timeout=min(cfg.timeout, 60),
            skip_if_exists=cfg.skip_if_exists,
        )
        text = (sdir / "onesixtyone.txt").read_text(encoding="utf-8", errors="replace") if (sdir / "onesixtyone.txt").exists() else r.stdout
        if re.search(r"\bpublic\b", text, re.I) and target in text or (text.strip() and "public" in text.lower() and "timeout" not in text.lower()):
            if text.strip() and not re.search(r"did not respond|0 of|no results", text, re.I):
                # onesixtyone prints 'ip [community] description' on success
                if re.search(rf"{re.escape(target)}\s+\[?public\]?", text, re.I) or re.search(r"\[public\]", text, re.I):
                    state.add_finding(Finding(
                        title="SNMP responds to the default 'public' community",
                        severity="high",
                        host=target,
                        source="onesixtyone",
                        evidence=text[:800],
                        detail="A default community string appears valid. Treat as information disclosure; not a confirmed exploit.",
                    ))
                    if cfg.tools.path("snmpwalk"):
                        run_cmd(
                            [cfg.tools.path("snmpwalk"), "-v2c", "-c", "public", target, "system"],
                            outfile=sdir / "snmpwalk-system.txt",
                            timeout=min(cfg.timeout, 60),
                            skip_if_exists=cfg.skip_if_exists,
                        )
    nmap_script_enum(cfg, state, target, port, "snmp-info,snmp-sysdescr", sdir / f"snmp-{port}", udp=True)
    hr.services.setdefault("snmp", []).append({"port": port})


def enum_ldap(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, "ldap-rootdse,ldap-search", sdir / f"ldap-{port}")
    bin_ls = cfg.tools.path("ldapsearch")
    if bin_ls:
        uri = f"ldap{'s' if port in {636, 3269} else ''}://{target}:{port}"
        run_cmd(
            [bin_ls, "-x", "-H", uri, "-s", "base", "(objectclass=*)"],
            outfile=sdir / f"ldapsearch-rootdse-{port}.txt",
            timeout=min(cfg.timeout, 45),
            skip_if_exists=cfg.skip_if_exists,
        )
        p = sdir / f"ldapsearch-rootdse-{port}.txt"
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            if "namingContexts" in text or "defaultNamingContext" in text or "rootDomainNamingContext" in text:
                state.add_finding(Finding(
                    title="Anonymous LDAP rootDSE readable",
                    severity="low",
                    host=f"{target}:{port}",
                    source="ldapsearch",
                    evidence=text[:800],
                    detail="Unauthenticated LDAP bind returned directory metadata. Not a confirmed exploit.",
                ))
    hr.services.setdefault("ldap", []).append({"port": port})


def enum_rdp(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, "rdp-enum-encryption,rdp-ntlm-info", sdir / f"rdp-{port}")
    hr.services.setdefault("rdp", []).append({"port": port})


def enum_vnc(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, "vnc-info,vnc-title", sdir / f"vnc-{port}")
    hr.services.setdefault("vnc", []).append({"port": port})


def enum_mssql(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    # Empty-password login is off unless --allow-intrusive-checks and --authorized.
    nmap_script_enum(cfg, state, target, port, mssql_scripts(cfg), sdir / f"mssql-{port}")
    hr.services.setdefault("mssql", []).append({"port": port})


def enum_mysql(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    nmap_script_enum(cfg, state, target, port, mysql_scripts(cfg), sdir / f"mysql-{port}")
    hr.services.setdefault("mysql", []).append({"port": port})


def enum_banner_script(cfg: Config, state: RunState, hr: HostRecord, target: str, port: int, sdir: Path) -> None:
    """Light, safe nmap version/script probes for less common management services."""
    # http-title and http-methods use the NSE HTTP library, and a script can
    # override its redirect check. Banner and ssl-cert stay on this connection.
    scripts = {
        6379: "redis-info",
        27017: "mongodb-info,mongodb-databases",
        2375: "banner",
        2376: "ssl-cert",
        6443: "ssl-cert",
        10250: "ssl-cert",
    }.get(port, "banner")
    nmap_script_enum(cfg, state, target, port, scripts, sdir / f"svc-{port}")
    # Flag obviously exposed management APIs from titles / scripts already harvested
    hr.services.setdefault(f"port-{port}", []).append({"port": port})


# ---------------------------------------------------------------------------
# PHASE 6 — Reporting
# ---------------------------------------------------------------------------

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def phase_report(cfg: Config, state: RunState, targets: TargetSet) -> None:
    log_phase("Phase 6 — Reporting")
    harvest_leftover_signals(state, cfg)
    reports = cfg.outdir / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    # Dedup hosts that are aliases of each other for the summary tables
    summary = build_summary(cfg, state, targets)
    json_path = reports / "summary.json"
    write_text(json_path, json.dumps(summary, indent=2, default=str))

    md = render_markdown(summary)
    write_text(reports / "summary.md", md)
    write_text(reports / "findings-of-interest.md", render_findings_md(summary))
    write_text(reports / "summary.html", render_html(summary))
    state.meta["reports"] = {
        "json": str(json_path),
        "markdown": str(reports / "summary.md"),
        "html": str(reports / "summary.html"),
        "findings": str(reports / "findings-of-interest.md"),
    }
    state.save()
    log_ok(f"Reports written to {reports}")
    log_ok(f"  JSON      {json_path}")
    log_ok(f"  Markdown  {reports / 'summary.md'}")
    log_ok(f"  HTML      {reports / 'summary.html'}")
    nfind = len(summary.get("findings") or [])
    log_ok(f"Findings of interest: {nfind} (not confirmed exploits)")


def harvest_leftover_signals(state: RunState, cfg: Config) -> None:
    """Catch high-signal items that may not have been converted to findings yet."""
    for hr in state.hosts.values():
        for p in hr.open_tcp + hr.open_udp:
            svc = (p.get("service") or "").lower()
            prod = (p.get("product") or "")
            ver = (p.get("version") or "")
            # Exposed common management ports
            if p.get("port") in {2375} or (p.get("port") == 2376 and svc):
                state.add_finding(Finding(
                    title="Docker API port open",
                    severity="high",
                    host=f"{hr.target}:{p['port']}",
                    source="ports",
                    evidence=f"{svc} {prod} {ver}".strip(),
                    detail="Docker API ports on an external interface are high-signal. Confirm exposure and auth; this is not a confirmed exploit.",
                ))
            if p.get("port") in {10250, 6443} and ("kubernetes" in svc or "https" in svc or "ssl" in (p.get("tunnel") or "") or p.get("port") in {10250, 6443}):
                if p.get("port") == 10250:
                    state.add_finding(Finding(
                        title="Kubernetes kubelet port (10250) open",
                        severity="medium",
                        host=f"{hr.target}:10250",
                        source="ports",
                        evidence=f"{svc} {prod} {ver}".strip(),
                    ))
        for w in hr.web:
            title = (w.get("title") or "").lower()
            tech = w.get("tech") or []
            if isinstance(tech, str):
                tech = [tech]
            blob = " ".join([title] + [str(t).lower() for t in tech])
            if any(h in blob for h in ("phpmyadmin", "wp-login", "jenkins", "grafana", "vcenter", "esxi")):
                # may already be filed from httpx
                pass


def build_summary(cfg: Config, state: RunState, targets: TargetSet) -> dict[str, Any]:
    findings = sorted(
        [f.to_dict() for f in state.findings],
        key=lambda f: (SEV_ORDER.get(str(f.get("severity", "info")).lower(), 9), f.get("host") or ""),
    )
    hosts = []
    for key in sorted(state.hosts.keys()):
        hr = state.hosts[key]
        # Skip empty alias shells
        if not (hr.open_tcp or hr.open_udp or hr.web or hr.ips or hr.alive or hr.nuclei or hr.services):
            continue
        hosts.append(hr.to_dict())

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[str(f.get("severity", "info")).lower()] += 1

    return {
        "generated": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "tool": __tool__,
        "version": __version__,
        "disclaimer": (
            "This report aggregates reconnaissance and enumeration output. "
            "Items under Findings of Interest are leads to verify. "
            "HerecyEx does not exploit targets and does not claim confirmed exploitation."
        ),
        "meta": {
            **state.meta,
            "profile": cfg.profile,
            "phases": cfg.phases,
            "no_active": cfg.no_active,
            "threads": cfg.threads,
            "full_ports": cfg.full_ports,
            "udp": cfg.udp,
        },
        "counts": {
            "input_domains": len(targets.domains),
            "input_ips": len(targets.ips),
            "subdomains": len(state.subdomains),
            "hosts_recorded": len(hosts),
            "findings": len(findings),
            "findings_by_severity": dict(sev_counts),
            "errors": len(state.errors),
        },
        "subdomains": state.subdomains,
        "hosts": hosts,
        "findings": findings,
        "errors": state.errors,
        "dropped_out_of_scope": targets.dropped,
    }


def render_findings_md(summary: dict[str, Any]) -> str:
    lines = [
        "# Findings of Interest",
        "",
        "> These items are high-signal leads extracted from recon/enum output. "
        "They are **not** confirmed exploitable vulnerabilities.",
        "",
    ]
    findings = summary.get("findings") or []
    if not findings:
        lines.append("No findings of interest were automatically flagged.")
        return "\n".join(lines) + "\n"
    current = None
    for f in findings:
        sev = str(f.get("severity", "info")).upper()
        if sev != current:
            current = sev
            lines += [f"## {sev}", ""]
        lines.append(f"### {f.get('title')}")
        lines.append("")
        lines.append(f"- **Host:** `{f.get('host')}`")
        lines.append(f"- **Source:** `{f.get('source')}`")
        lines.append(f"- **Severity:** {f.get('severity')}")
        if f.get("detail"):
            lines.append(f"- **Detail:** {f.get('detail')}")
        if f.get("evidence"):
            lines.append("")
            lines.append("```")
            lines.append(str(f.get("evidence"))[:1500])
            lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def render_markdown(summary: dict[str, Any]) -> str:
    c = summary.get("counts") or {}
    meta = summary.get("meta") or {}
    lines = [
        "# HerecyEx External Recon Report",
        "",
        f"_Generated {summary.get('generated')} by HerecyEx v{summary.get('version')}_",
        "",
        f"> {summary.get('disclaimer')}",
        "",
        "## Summary",
        "",
        f"- Profile: `{meta.get('profile')}`",
        f"- Phases: {', '.join(meta.get('phases') or [])}",
        f"- Passive / no-active: `{meta.get('no_active')}`",
        f"- Input domains (after discovery): {c.get('input_domains')}",
        f"- IPs in pipeline: {c.get('input_ips')}",
        f"- Subdomains discovered: {c.get('subdomains')}",
        f"- Host records: {c.get('hosts_recorded')}",
        f"- Findings of interest: {c.get('findings')} {c.get('findings_by_severity')}",
        "",
        "## Findings of Interest",
        "",
    ]
    findings = summary.get("findings") or []
    if not findings:
        lines.append("None automatically flagged.")
        lines.append("")
    else:
        lines += [
            "| Severity | Host | Title | Source |",
            "|----------|------|-------|--------|",
        ]
        for f in findings:
            title = str(f.get("title", "")).replace("|", "/")
            lines.append(f"| {f.get('severity')} | `{f.get('host')}` | {title} | `{f.get('source')}` |")
        lines.append("")

    lines += ["## Discovered Subdomains", ""]
    subs = summary.get("subdomains") or []
    if subs:
        for s in subs:
            lines.append(f"- `{s}`")
    else:
        lines.append("_None._")
    lines.append("")

    lines += ["## Hosts", ""]
    for h in summary.get("hosts") or []:
        target = h.get("target")
        ips = ", ".join(f"`{i}`" for i in (h.get("ips") or [])[:12]) or "_"
        names = ", ".join(f"`{n}`" for n in (h.get("names") or [])[:12]) or "_"
        lines.append(f"### `{target}`")
        lines.append("")
        lines.append(f"- Kind: {h.get('kind')}  |  Alive: {h.get('alive')}")
        lines.append(f"- IPs: {ips}")
        lines.append(f"- Names: {names}")
        tcp = h.get("open_tcp") or []
        udp = h.get("open_udp") or []
        if tcp:
            lines.append("- Open TCP:")
            for p in tcp:
                svc = " ".join(filter(None, [p.get("service"), p.get("product"), p.get("version")]))
                lines.append(f"  - `{p.get('port')}/tcp` {svc}".rstrip())
        if udp:
            lines.append("- Open UDP:")
            for p in udp:
                svc = " ".join(filter(None, [p.get("service"), p.get("product"), p.get("version")]))
                lines.append(f"  - `{p.get('port')}/udp` {svc}".rstrip())
        web = h.get("web") or []
        if web:
            lines.append("- Web:")
            for w in web:
                tech = w.get("tech") or []
                if isinstance(tech, list):
                    tech_s = ", ".join(map(str, tech[:8]))
                else:
                    tech_s = str(tech)
                lines.append(f"  - {w.get('url')}  status={w.get('status')}  title={w.get('title')!r}  tech={tech_s}")
        lines.append("")

    errs = summary.get("errors") or []
    if errs:
        lines += ["## Errors", ""]
        for e in errs:
            lines.append(f"- {e}")
        lines.append("")
    return "\n".join(lines) + "\n"


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HerecyEx report — {{ generated }}</title>
<style>
  :root {
    --red: #E04832;
    --black: #000000;
    --slate: #2E363E;
    --gray: #D9D9D9;
    --white: #FAFAFA;
    --card: #1A1F24;
    --crit: #8E1B12;
    --high: #E04832;
    --med: #F29A2E;
    --low: #3A7CA5;
    --info: #6B7480;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: Inter, system-ui, Segoe UI, sans-serif;
    background: var(--black); color: var(--gray); line-height: 1.5;
  }
  header {
    background: linear-gradient(180deg, #111 0%, #000 100%);
    border-bottom: 3px solid var(--red);
    padding: 2rem 2.5rem 1.5rem;
  }
  header h1 { margin: 0; color: var(--white); font-weight: 650; letter-spacing: .02em; }
  header .sub { color: #9aa0a6; margin-top: .4rem; font-size: .95rem; }
  header .brand { color: var(--red); font-weight: 700; letter-spacing: .12em; font-size: .75rem; text-transform: uppercase; }
  main { padding: 1.5rem 2.5rem 3rem; max-width: 1200px; }
  .disclaimer {
    background: #1a1210; border-left: 3px solid var(--red);
    padding: .8rem 1rem; margin: 1rem 0 1.5rem; color: #d0c6c4; font-size: .92rem;
  }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.8rem; margin-bottom: 1.5rem; }
  .card { background: var(--card); border: 1px solid #2a3138; padding: 1rem; }
  .card .n { font-size: 1.8rem; color: var(--white); font-weight: 650; }
  .card .l { font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; color: #8b949e; }
  h2 { color: var(--white); border-bottom: 1px solid #2a3138; padding-bottom: .4rem; margin-top: 2rem; }
  table { width: 100%; border-collapse: collapse; font-size: .9rem; }
  th, td { text-align: left; padding: .45rem .55rem; border-bottom: 1px solid #2a3138; vertical-align: top; }
  th { color: #9aa0a6; font-weight: 600; font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; }
  tr:hover td { background: #151a1e; }
  .sev { display: inline-block; padding: .1rem .45rem; font-size: .7rem; font-weight: 700; letter-spacing: .06em; color: #fff; text-transform: uppercase; }
  .sev-critical { background: var(--crit); }
  .sev-high { background: var(--high); }
  .sev-medium { background: var(--med); color: #1a1a1a; }
  .sev-low { background: var(--low); }
  .sev-info { background: var(--info); }
  .host { background: var(--card); border: 1px solid #2a3138; margin: 0.7rem 0; padding: 1rem 1.1rem; }
  .host h3 { margin: 0 0 .4rem; color: var(--white); font-size: 1.05rem; }
  .meta { color: #8b949e; font-size: .85rem; }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .86em; }
  ul.subs { columns: 2; gap: 1.5rem; }
  pre { background: #111; padding: .6rem .8rem; overflow: auto; color: #d0d4d8; font-size: .8rem; }
  footer { padding: 1.2rem 2.5rem; color: #6b7480; font-size: .8rem; border-top: 1px solid #2a3138; }
</style>
</head>
<body>
<header>
  <div class="brand">Blackbox Intelligence Group LLC</div>
  <h1>HerecyEx External Recon Report</h1>
  <div class="sub">Generated {{ generated }} · HerecyEx v{{ version }}</div>
</header>
<main>
  <div class="disclaimer">{{ disclaimer }}</div>
  <div class="cards">
    <div class="card"><div class="n">{{ counts.subdomains }}</div><div class="l">Subdomains</div></div>
    <div class="card"><div class="n">{{ counts.input_ips }}</div><div class="l">IPs in pipeline</div></div>
    <div class="card"><div class="n">{{ counts.hosts_recorded }}</div><div class="l">Host records</div></div>
    <div class="card"><div class="n">{{ counts.findings }}</div><div class="l">Findings of interest</div></div>
  </div>

  <h2>Findings of Interest</h2>
  {% if findings %}
  <table>
    <thead><tr><th>Severity</th><th>Host</th><th>Title</th><th>Source</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
        <td class="mono">{{ f.host }}</td>
        <td>{{ f.title }}</td>
        <td class="mono">{{ f.source }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>None automatically flagged.</p>
  {% endif %}

  <h2>Discovered Subdomains</h2>
  {% if subdomains %}
  <ul class="subs">
    {% for s in subdomains %}<li class="mono">{{ s }}</li>{% endfor %}
  </ul>
  {% else %}
  <p>None.</p>
  {% endif %}

  <h2>Hosts</h2>
  {% for h in hosts %}
  <div class="host">
    <h3 class="mono">{{ h.target }}</h3>
    <div class="meta">kind={{ h.kind }} · alive={{ h.alive }}
      {% if h.ips %} · ips={{ h.ips | join(', ') }}{% endif %}
      {% if h.names %} · names={{ h.names | join(', ') }}{% endif %}
    </div>
    {% if h.open_tcp %}
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Product / version</th></tr></thead>
      <tbody>
      {% for p in h.open_tcp %}
        <tr>
          <td class="mono">{{ p.port }}/{{ p.protocol or 'tcp' }}</td>
          <td>{{ p.service }}</td>
          <td>{{ p.product }} {{ p.version }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% endif %}
    {% if h.open_udp %}
    <table>
      <thead><tr><th>UDP Port</th><th>Service</th><th>Product / version</th></tr></thead>
      <tbody>
      {% for p in h.open_udp %}
        <tr>
          <td class="mono">{{ p.port }}/udp</td>
          <td>{{ p.service }}</td>
          <td>{{ p.product }} {{ p.version }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% endif %}
    {% if h.web %}
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
      <tbody>
      {% for w in h.web %}
        <tr>
          <td class="mono">{{ w.url }}</td>
          <td>{{ w.status }}</td>
          <td>{{ w.title }}</td>
          <td>{{ w.tech if w.tech is string else (w.tech or []) | join(', ') }}</td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% endif %}
  </div>
  {% endfor %}
</main>
<footer>HerecyEx does not perform exploitation. Verify every finding of interest before reporting it as a vulnerability.</footer>
</body>
</html>
"""


def _html_escape(s: Any) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(summary: dict[str, Any]) -> str:
    if HAS_JINJA2 and _JinjaTemplate is not None:
        try:
            return _JinjaTemplate(HTML_TEMPLATE).render(**summary)
        except Exception as exc:
            log_warn(f"Jinja2 render failed ({exc}); using stdlib fallback")
    # Minimal stdlib fallback — still self-contained
    c = summary.get("counts") or {}
    rows = []
    for f in summary.get("findings") or []:
        rows.append(
            "<tr><td><span class='sev sev-{sev}'>{sev}</span></td>"
            "<td class='mono'>{host}</td><td>{title}</td><td class='mono'>{src}</td></tr>".format(
                sev=_html_escape(f.get("severity")),
                host=_html_escape(f.get("host")),
                title=_html_escape(f.get("title")),
                src=_html_escape(f.get("source")),
            )
        )
    subs = "".join(f"<li class='mono'>{_html_escape(s)}</li>" for s in (summary.get("subdomains") or []))
    host_html = []
    for h in summary.get("hosts") or []:
        ports = "".join(
            f"<tr><td class='mono'>{_html_escape(p.get('port'))}/tcp</td>"
            f"<td>{_html_escape(p.get('service'))}</td>"
            f"<td>{_html_escape(p.get('product'))} {_html_escape(p.get('version'))}</td></tr>"
            for p in (h.get("open_tcp") or [])
        )
        host_html.append(
            f"<div class='host'><h3 class='mono'>{_html_escape(h.get('target'))}</h3>"
            f"<div class='meta'>alive={_html_escape(h.get('alive'))}</div>"
            f"<table><tbody>{ports}</tbody></table></div>"
        )
    # Reuse CSS from the template head
    css_start = HTML_TEMPLATE.find("<style>")
    css_end = HTML_TEMPLATE.find("</style>") + len("</style>")
    css = HTML_TEMPLATE[css_start:css_end]
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>HerecyEx report</title>{css}</head><body>
<header><div class="brand">Blackbox Intelligence Group LLC</div>
<h1>HerecyEx External Recon Report</h1>
<div class="sub">{_html_escape(summary.get('generated'))} · v{_html_escape(summary.get('version'))}</div></header>
<main>
<div class="disclaimer">{_html_escape(summary.get('disclaimer'))}</div>
<div class="cards">
<div class="card"><div class="n">{_html_escape(c.get('subdomains'))}</div><div class="l">Subdomains</div></div>
<div class="card"><div class="n">{_html_escape(c.get('input_ips'))}</div><div class="l">IPs in pipeline</div></div>
<div class="card"><div class="n">{_html_escape(c.get('hosts_recorded'))}</div><div class="l">Host records</div></div>
<div class="card"><div class="n">{_html_escape(c.get('findings'))}</div><div class="l">Findings of interest</div></div>
</div>
<h2>Findings of Interest</h2>
<table><thead><tr><th>Severity</th><th>Host</th><th>Title</th><th>Source</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=4>None automatically flagged.</td></tr>'}</tbody></table>
<h2>Discovered Subdomains</h2><ul class="subs">{subs or '<li>None.</li>'}</ul>
<h2>Hosts</h2>{''.join(host_html) or '<p>None.</p>'}
</main>
<footer>HerecyEx does not perform exploitation. Verify every finding of interest before reporting it as a vulnerability.</footer>
</body></html>"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="external_recon_workflow.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HerecyEx — external recon and enumeration workflow.\n"
            "Accepts a mixed list of FQDNs, IPs, and CIDRs and runs a phased\n"
            "recon/enum pipeline. No exploitation, no credential brute force,\n"
            "and no denial-of-service checks."
        ),
        epilog=(
            "examples:\n"
            "  python3 external_recon_workflow.py --check-tools\n"
            "  python3 external_recon_workflow.py -t scope.txt --authorized\n"
            "  python3 external_recon_workflow.py -t scope.txt --quick --authorized\n"
            "  python3 external_recon_workflow.py -t scope.txt --full --udp --authorized\n"
            "  python3 external_recon_workflow.py -t scope.txt --no-active --authorized\n"
            "  python3 external_recon_workflow.py -t scope.txt --phases passive,resolve,report --authorized\n"
            "  python3 external_recon_workflow.py -t scope.txt --scope-check allowlist.txt --authorized\n"
            "  python3 external_recon_workflow.py --resume results/20261110-090000 --phases web,services,report --authorized\n"
            "  python3 external_recon_workflow.py --narrow-checks --manifest ssh.txt --scope-check scope.txt --admit admit.txt --authorized -o out\n"
        ),
    )
    p.add_argument("--targets", "-t", metavar="FILE", help="Target file (FQDNs, IPs, and/or CIDRs, one per line)")
    p.add_argument("--output", "-o", metavar="DIR", default="results",
                   help="Base output directory (a timestamped subdirectory is created). Default: ./results")
    p.add_argument("--resume", metavar="DIR", help="Resume a previous run directory (skip-if-exists, reload state)")
    p.add_argument("--threads", type=int, default=8, help="Worker thread count (default: 8)")
    p.add_argument("--rate", type=float, default=0.0,
                   help="Minimum seconds between tool launches (rate limiting). Default: 0")
    p.add_argument("--timeout", type=int, default=300, help="Default per-tool timeout in seconds (default: 300)")
    p.add_argument("--phases", default="all",
                   help="Comma-separated phases to run: " + ",".join(PHASES) + " (or 'all'). Default: all")
    prof = p.add_mutually_exclusive_group()
    prof.add_argument("--quick", action="store_true", help="Faster profile: top 100 ports, nuclei high+critical, no dir enum")
    prof.add_argument("--full", action="store_true", help="Thorough profile: top 1000 ports, dir enum, deeper web checks")
    p.add_argument("--no-active", action="store_true",
                   help="Passive-only: OSINT + DNS resolution, no ping/port/web/service probing")
    p.add_argument("--authorized", action="store_true",
                   help="Skip the interactive authorization prompt (you confirm you are authorized)")
    p.add_argument("--scope-check", metavar="FILE",
                   help="Allowlist file of CIDRs, IPs, and domain suffixes; drop anything not in scope")
    p.add_argument("--full-ports", action="store_true", help="After the top-ports pass, run nmap -p- (slow)")
    p.add_argument("--udp", action="store_true", help="Opt-in UDP top-ports nmap (requires root or passwordless sudo)")
    p.add_argument("--nuclei-severity", default=None,
                   help="Nuclei severity filter, e.g. 'medium,high,critical'. Defaults depend on --quick/--full")
    p.add_argument("--no-nuclei", action="store_true", help="Disable nuclei")
    p.add_argument("--direnum", action="store_true", help="Enable web content discovery (on by default with --full)")
    p.add_argument("--no-direnum", action="store_true", help="Disable web content discovery")
    p.add_argument("--wordlist", metavar="FILE", help="Wordlist for content discovery (defaults to SecLists/dirb common lists)")
    p.add_argument("--nikto", action="store_true", help="Enable optional nikto scans (off by default; can be noisy)")
    p.add_argument("--testssl", action="store_true",
                   help="Also run testssl (Kali binary) or testssl.sh alongside sslscan")
    p.add_argument("--allow-intrusive-checks", action="store_true",
                   help="Per-engagement opt-in for smtp-open-relay, one-name smtp-enum-users VRFY, "
                        "and empty-password database scripts. Requires --authorized (or the YES prompt). Off by default.")
    p.add_argument("--force", action="store_true", help="Do not skip existing tool output (re-run everything)")
    p.add_argument("--check-tools", action="store_true", help="Detect installed tools, print a report, and exit")
    p.add_argument("--max-cidr-hosts", type=int, default=4096, help="Refuse to expand CIDRs larger than this (default: 4096)")
    p.add_argument("--alive-only", action="store_true",
                   help="Drop IPs that do not respond to ICMP/TCP ping (NOT recommended for external tests)")
    p.add_argument("--nmap-timing", default=None, help="nmap -T value (default: 4, or 3 with --full-ports)")
    p.add_argument("--http-rate", type=int, default=50,
                   help="httpx / nuclei request rate (default: 50). Content discovery is capped at 30.")
    p.add_argument("--naabu-rate", type=int, default=1000,
                   help="naabu packets per second (default: 1000)")
    p.add_argument("--narrow-checks", action="store_true",
                   help="Run only admitted tls/ssh/smb checks from --manifest. Off by default. "
                        "Not enabled by --quick. The only other flags accepted are --manifest, "
                        "--scope-check, --admit, --authorized, and -o/--output. Any other flag, "
                        "including one typed at its usual default, is refused before any tool "
                        "or output directory.")
    p.add_argument("--manifest", metavar="FILE",
                   help="Narrow-check rows: tls|ssh|smb IP PORT. Used only with --narrow-checks.")
    p.add_argument("--admit", metavar="FILE",
                   help="Exact ip:port admissions. Used only with --narrow-checks. A bare IP is not enough.")
    p.add_argument("--version", action="version", version=f"HerecyEx {__version__}")
    return p


def parse_phases(raw: str) -> list[str]:
    if not raw or raw.strip().lower() == "all":
        return list(PHASES)
    parts = [p.strip().lower() for p in raw.split(",") if p.strip()]
    bad = [p for p in parts if p not in PHASES]
    if bad:
        raise SystemExit(f"Unknown phase(s): {', '.join(bad)}. Valid: {', '.join(PHASES)} or all")
    # report always implied if anything ran and user didn't exclude it? Only if requested or 'all'.
    return parts


def confirm_authorized(skip: bool) -> bool:
    """Authorization gate. --authorized skips the interactive YES prompt."""
    if console is not None:
        console.print(Panel(
            "[warning]Authorized assessments only.[/]\n"
            "HerecyEx performs reconnaissance and read-only enumeration.\n"
            "It does not exploit, password-spray, or run denial-of-service checks.\n"
            "You are responsible for every target in the list.",
            title="Authorization",
            border_style="yellow",
        ))
    else:
        print("Authorized assessments only. Type YES to continue, or pass --authorized.")
    if skip:
        log_ok("Authorization confirmed via --authorized.")
        return True
    if not sys.stdin.isatty():
        log_error("No TTY for the authorization prompt. Re-run with --authorized if you have written permission.")
        return False
    try:
        ans = input("Type YES if you are authorized to test every target in the list: ").strip()
    except EOFError:
        return False
    if ans == "YES":
        log_ok("Authorization acknowledged.")
        return True
    log_error("Authorization not confirmed.")
    return False


def install_signal_handlers() -> None:
    def _handler(signum, _frame):
        if _SHUTDOWN.is_set():
            log_warn("Second interrupt — exiting immediately")
            raise SystemExit(130)
        _SHUTDOWN.set()
        log_warn("Interrupt received — will stop after in-flight work (Ctrl-C again to force quit)")

    signal.signal(signal.SIGINT, _handler)
    try:
        signal.signal(signal.SIGTERM, _handler)
    except Exception:
        pass


def prepare_outdir(args: argparse.Namespace) -> Path:
    if args.resume:
        out = Path(args.resume).expanduser().resolve()
        if not out.exists():
            raise SystemExit(f"--resume directory does not exist: {out}")
        return out
    base = Path(args.output).expanduser().resolve()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = base / ts
    out.mkdir(parents=True, exist_ok=True)
    return out


def build_config(args: argparse.Namespace, tools: Toolset, outdir: Path) -> Config:
    if args.quick:
        profile = "quick"
    elif args.full:
        profile = "full"
    else:
        profile = "standard"

    direnum = False
    if args.full:
        direnum = True
    if args.direnum:
        direnum = True
    if args.no_direnum:
        direnum = False

    timing = args.nmap_timing or ("3" if args.full_ports else "4")
    try:
        tval = int(timing)
        if tval < 0 or tval > 5:
            raise ValueError
        timing = str(tval)
    except ValueError:
        raise SystemExit("--nmap-timing must be an integer 0-5")

    wl = Path(args.wordlist).expanduser() if args.wordlist else find_wordlist()
    phases = parse_phases(args.phases)
    if args.no_active:
        # Keep only passive + resolve + report if the user asked for all
        allowed = {"passive", "resolve", "report"}
        if set(phases) == set(PHASES):
            phases = ["passive", "resolve", "report"]
        else:
            phases = [p for p in phases if p in allowed or p == "report"]

    return Config(
        outdir=outdir,
        threads=max(1, args.threads),
        timeout=max(30, args.timeout),
        skip_if_exists=not args.force,
        profile=profile,
        no_active=bool(args.no_active),
        full_ports=bool(args.full_ports),
        udp=bool(args.udp),
        nuclei_severity=args.nuclei_severity or "",
        no_nuclei=bool(args.no_nuclei),
        direnum=direnum,
        nikto=bool(args.nikto),
        wordlist=wl if wl and Path(wl).exists() else (Path(args.wordlist).expanduser() if args.wordlist else None),
        rate_interval=max(0.0, float(args.rate)),
        max_cidr_hosts=max(1, args.max_cidr_hosts),
        phases=phases,
        tools=tools,
        limiter=RateLimiter(max(0.0, float(args.rate))),
        nmap_timing=timing,
        testssl=bool(args.testssl),
        alive_only=bool(args.alive_only),
        http_rate=max(1, int(args.http_rate)),
        naabu_rate=max(1, int(args.naabu_rate)),
        allow_intrusive_checks=bool(args.allow_intrusive_checks),
        authorized=bool(args.authorized),
        scope_enforced=bool(args.scope_check),
    )


def write_run_meta(outdir: Path, args: argparse.Namespace, cfg: Config, tools: Toolset) -> None:
    meta = {
        "tool": __tool__,
        "version": __version__,
        "started": datetime.now().astimezone().isoformat(),
        "argv": sys.argv,
        "profile": cfg.profile,
        "phases": cfg.phases,
        "threads": cfg.threads,
        "no_active": cfg.no_active,
        "cwd": os.getcwd(),
        "tools_present": tools.present_names(),
        "tools_missing": [s.name for s in tools.missing()],
        "root": is_root(),
        "sudo_n": sudo_n_available(),
    }
    write_text(outdir / "run-meta.json", json.dumps(meta, indent=2))


# Tests inject these. Production leaves them unset so the real runner is used.
# A script run does not see injections made on an imported copy of this module.
_NARROW_RUNNER = None
_NARROW_WHICH = None
_NARROW_NOW = None

# Anything else on the argv, even when the value equals the usual default, is a
# recon option and is refused. --phases all and --threads 8 are not exempt.
_NARROW_BARE_OPTIONS = {"--narrow-checks", "--authorized"}
_NARROW_VALUE_OPTIONS = {"--manifest", "--scope-check", "--admit", "--output", "-o"}


def narrow_mode_conflicts(argv: list[str]) -> list[str]:
    """Flags that must not appear on a --narrow-checks command."""
    conflicts: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        name = token
        attached = False
        if token.startswith("--") and "=" in token:
            name = token.split("=", 1)[0]
            attached = True
        elif token.startswith("-o") and not token.startswith("--") and token != "-o":
            name = "-o"
            attached = True
        if name in _NARROW_BARE_OPTIONS or (attached and name in _NARROW_VALUE_OPTIONS):
            index += 1
            continue
        if name in _NARROW_VALUE_OPTIONS:
            index += 2 if index + 1 < len(argv) else 1
            continue
        if token.startswith("-"):
            conflicts.append(name)
            if not attached and index + 1 < len(argv) and not str(argv[index + 1]).startswith("-"):
                index += 2
            else:
                index += 1
            continue
        conflicts.append(token)
        index += 1
    return conflicts


def run_admitted_narrow_checks(args: argparse.Namespace) -> int:
    """Opt-in path. Imports narrow_checks only after this module has finished loading."""
    import narrow_checks as narrow_checks

    manifest = Path(args.manifest)
    scope = Path(args.scope_check)
    admit = Path(args.admit)
    for path in (manifest, scope, admit):
        if not path.is_file():
            print(f"error: missing file: {path}", file=sys.stderr)
            return 2
    rows = narrow_checks.parse_manifest(manifest)
    outdir = Path(args.output).expanduser()
    report = narrow_checks.run_manifest(
        rows,
        scope_file=scope,
        admit_file=admit,
        outdir=outdir,
        runner=_NARROW_RUNNER,
        which=_NARROW_WHICH or shutil.which,
        now=_NARROW_NOW,
    )
    if report.get("refused"):
        if report.get("error"):
            print(f"refused: {report['error']}", file=sys.stderr)
        else:
            for row in report["results"]:
                target = row.get("target") or {}
                print(
                    f"refused: {row.get('check_id')} {target.get('ip')}:{target.get('port')} "
                    f"{row['provenance']['error']}",
                    file=sys.stderr,
                )
        return 2
    counts: dict[str, int] = {}
    for row in report["results"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    # Exit 0 means the manifest was admitted and the checks ran.
    # observed_weakness, lead, error, and not_tested also exit 0.
    print(json.dumps({
        "mode": "narrow-checks",
        "output": str(outdir / "narrow-checks.json"),
        "counts": counts,
        "confirmed_exploit": False,
    }))
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.narrow_checks:
        raw = list(sys.argv[1:] if argv is None else argv)
        conflicts = narrow_mode_conflicts(raw)
        if conflicts:
            print(
                "error: --narrow-checks accepts only --manifest, --scope-check, "
                "--admit, --authorized, and -o/--output. Refusing "
                + ", ".join(conflicts)
                + ".",
                file=sys.stderr,
            )
            return 2
        if not args.manifest or not args.scope_check or not args.admit:
            print(
                "error: --narrow-checks requires --manifest, --scope-check, and --admit.",
                file=sys.stderr,
            )
            return 2
        for label, value in (("--manifest", args.manifest), ("--scope-check", args.scope_check), ("--admit", args.admit)):
            if not Path(value).is_file():
                print(f"error: missing file for {label}: {value}", file=sys.stderr)
                return 2
        if not confirm_authorized(args.authorized):
            print("Aborted — authorization not confirmed.", file=sys.stderr)
            return 3
        return run_admitted_narrow_checks(args)

    _bootstrap_path()
    banner()
    tools = Toolset()

    if args.check_tools:
        tools.print_report()
        log_info("Missing tools are skipped at runtime. Nothing was scanned.")
        return 0

    if not args.targets and not args.resume:
        parser.print_help()
        print("\nerror: --targets is required unless --check-tools or --resume is used", file=sys.stderr)
        return 2

    if not confirm_authorized(args.authorized):
        print("Aborted — authorization not confirmed.", file=sys.stderr)
        return 3
    # A typed YES is authorization. The intrusive-check gate treats it the same as --authorized.
    args.authorized = True

    try:
        outdir = prepare_outdir(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    init_log(outdir / "herecyex.log")
    install_signal_handlers()

    cfg = build_config(args, tools, outdir)
    tools.print_report()
    if not tools.has("httpx"):
        note = (
            "ProjectDiscovery httpx was not found, so live HTTP probing will be skipped."
        )
        if shutil.which("httpx"):
            note += (
                " The httpx on PATH looks like the Python CLI (no -l / -tech-detect). "
                "Install the Go binary and put ~/go/bin ahead of it on PATH."
            )
        if console is not None:
            console.print(Panel(f"[warning]{note}[/]", title="httpx", border_style="yellow"))
        else:
            log_warn(note)
    write_run_meta(outdir, args, cfg, tools)

    if cfg.allow_intrusive_checks and cfg.authorized:
        log_warn(
            "Intrusive NSE checks are ON (smtp-open-relay, one VRFY probe, empty-password DB scripts). "
            "That switch needs per-engagement approval."
        )
    elif cfg.allow_intrusive_checks:
        log_warn("--allow-intrusive-checks ignored: authorization was not confirmed.")
    if cfg.scope_enforced:
        warn_scoped_ip_only(cfg)
    else:
        log_warn(
            "No --scope-check file. Domain-only lists are probed as named. "
            "If the list has any IP or CIDR, a name is probed only when every resolved address is inside that set. "
            "Unresolved names are not probed."
        )
    log_info(f"HerecyEx v{__version__}  profile={cfg.profile}  phases={','.join(cfg.phases)}  threads={cfg.threads}")
    log_info(f"Output: {outdir}")
    if not is_root():
        if sudo_n_available():
            log_info("Passwordless sudo detected — nmap SYN/UDP will use sudo -n")
        else:
            log_warn("Not running as root and no passwordless sudo — nmap will use TCP connect scans (-sT). UDP will be skipped.")

    state = RunState(outdir)
    if args.resume:
        state.load()

    tdir = outdir / "targets"
    tdir.mkdir(parents=True, exist_ok=True)

    try:
        if args.targets:
            scope = Path(args.scope_check).expanduser() if args.scope_check else None
            if scope and not scope.exists():
                log_error(f"Scope file not found: {scope}")
                close_log()
                return 2
            targets = parse_targets(Path(args.targets).expanduser(), cfg.max_cidr_hosts, scope)
        elif args.resume:
            # Reconstruct a minimal target set from saved files / state
            targets = TargetSet()
            for d in read_lines(tdir / "domains-after-passive.txt") or read_lines(tdir / "domains.txt"):
                targets.add_domain(d)
            for i in read_lines(tdir / "ips-after-resolve.txt") or read_lines(tdir / "ips.txt"):
                targets.add_ip(i)
            if not targets.domains and not targets.ips:
                for name in state.subdomains:
                    targets.add_domain(name)
                for hr in state.hosts.values():
                    if is_ip(hr.target):
                        targets.add_ip(hr.target)
                    elif is_domain(hr.target):
                        targets.add_domain(hr.target)
                    for ip in hr.ips:
                        targets.add_ip(ip)
        else:
            log_error("No targets")
            close_log()
            return 2
    except FileNotFoundError as exc:
        log_error(str(exc))
        close_log()
        return 2

    if args.scope_check:
        cfg.scope_nets, cfg.scope_suffixes = load_scope(Path(args.scope_check).expanduser())

    write_lines(tdir / "domains.txt", targets.domains)
    write_lines(tdir / "ips.txt", targets.ips)
    write_lines(tdir / "cidrs.txt", targets.cidrs)
    write_lines(tdir / "dropped-out-of-scope.txt", targets.dropped)
    write_lines(tdir / "raw.txt", targets.raw)

    log_info(
        f"Loaded targets: {len(targets.domains)} domain(s), {len(targets.ips)} IP(s), "
        f"{len(targets.cidrs)} CIDR(s), {len(targets.dropped)} dropped by scope"
    )
    print_targets_table(len(targets.domains), len(targets.ips), len(targets.cidrs), len(targets.dropped))
    if not targets.domains and not targets.ips:
        log_error("No usable targets after parsing / scope-check")
        close_log()
        return 2

    state.meta.update({
        "outdir": str(outdir),
        "profile": cfg.profile,
        "phases": cfg.phases,
        "started": datetime.now().astimezone().isoformat(),
    })
    state.save()

    phase_fns = {
        "passive": lambda: phase_passive(cfg, state, targets),
        "resolve": lambda: phase_resolve(cfg, state, targets),
        "ports": lambda: phase_ports(cfg, state, targets),
        "web": lambda: phase_web(cfg, state, targets),
        "services": lambda: phase_services(cfg, state, targets),
        "report": lambda: phase_report(cfg, state, targets),
    }

    started = time.monotonic()
    try:
        for name in [p for p in PHASES if p in cfg.phases]:
            if should_stop():
                log_warn(f"Stopping before phase '{name}' due to shutdown request")
                break
            phase_fns[name]()
            state.save()
        # Always try to write a report if we didn't already and we have any data
        if "report" not in cfg.phases and not should_stop():
            log_info("Generating a report even though 'report' was not in --phases")
            phase_report(cfg, state, targets)
    except KeyboardInterrupt:
        _SHUTDOWN.set()
        log_warn("Interrupted — writing partial report")
        try:
            phase_report(cfg, state, targets)
        except Exception as exc:
            log_error(f"Partial report failed: {exc}")
    except Exception as exc:
        log_error(f"Uncaught error: {exc}")
        try:
            phase_report(cfg, state, targets)
        except Exception:
            pass
        raise
    finally:
        elapsed = time.monotonic() - started
        state.meta["finished"] = datetime.now().astimezone().isoformat()
        state.meta["elapsed_seconds"] = round(elapsed, 1)
        state.save()
        log_info(f"Finished in {elapsed/60:.1f} minute(s). Output: {outdir}")
        print_results_summary(state, targets, outdir, elapsed)
        close_log()

    return 0 if not should_stop() else 130


if __name__ == "__main__":
    sys.exit(main())
