#!/usr/bin/env python3
"""
Blackbox Intelligence Group LLC
External Penetration Test — Recon & Enumeration Workflow
Polished CLI | No exploitation | Stage results properly chain

Usage:
  python3 external_recon_workflow.py -t targets.txt
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme
from rich import box

custom_theme = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "stage": "bold magenta",
    "tool": "dim cyan",
})

console = Console(theme=custom_theme)

DEFAULT_HTTP_RATE = 50
DEFAULT_NAABU_RATE = 1000
TIMEOUT = 3600

# Core tools — script continues with warnings if some are missing
CORE_TOOLS = ["subfinder", "naabu"]  # httpx checked separately for PD binary
OPTIONAL_TOOLS = ["amass", "nuclei", "katana", "ffuf", "theHarvester", "nmap", "nikto", "dnsx"]

def banner():
    console.print(Panel.fit(
        "[bold white]BLACKBOX INTELLIGENCE GROUP[/]\n"
        "[dim]External Recon & Enumeration Workflow[/]\n"
        "[dim]No exploitation • Results chain stage-to-stage[/]",
        border_style="blue",
        box=box.DOUBLE,
        padding=(1, 4)
    ))

def log(msg, style="info"):
    console.print(f"[{style}]{msg}[/]")

def find_pd_httpx():
    """Return path to ProjectDiscovery httpx, or None if only the Python httpx CLI is present."""
    candidates = []
    # Common locations
    for base in [Path.home() / "go" / "bin", Path("/usr/local/bin"), Path("/usr/bin"), Path.home() / ".local" / "bin"]:
        candidates.append(base / "httpx")
    # PATH search
    which = shutil.which("httpx")
    if which:
        candidates.append(Path(which))
    seen = set()
    for cand in candidates:
        if not cand or not cand.is_file():
            continue
        try:
            r = subprocess.run([str(cand), "-version"], capture_output=True, text=True, timeout=5)
            out = (r.stdout + r.stderr).lower()
            if "projectdiscovery" in out or "httpx version" in out and "go" in out:
                return str(cand)
            # Fallback: check help for PD-specific flag
            r2 = subprocess.run([str(cand), "-h"], capture_output=True, text=True, timeout=5)
            help_text = (r2.stdout + r2.stderr).lower()
            if "-list" in help_text or "-l string" in help_text or "rate-limit" in help_text and "tech-detect" in help_text:
                return str(cand)
        except Exception:
            continue
    return None

def check_tools():
    missing_core = [t for t in CORE_TOOLS if shutil.which(t) is None]
    if missing_core:
        console.print(Panel(
            f"[error]Missing core tools (required for useful results):[/]\n" +
            "\n".join(f"  • {t}" for t in missing_core) +
            "\n\n[dim]Install ProjectDiscovery tools or run from Kali/Parrot.[/]",
            title="Tool Check",
            border_style="red"
        ))
        sys.exit(1)

    present = [t for t in OPTIONAL_TOOLS if shutil.which(t)]
    missing = [t for t in OPTIONAL_TOOLS if shutil.which(t) is None]
    if present:
        log(f"Optional tools available: {', '.join(present)}", "success")
    if missing:
        log(f"Optional tools not found (stages skipped): {', '.join(missing)}", "warning")

def run_cmd(cmd, outfile=None, timeout=TIMEOUT, quiet=False):
    """Run a command. Returns True on success (rc==0 or tool produced output)."""
    tool = cmd[0]
    status_msg = f"[tool]Running {tool}...[/]"
    with console.status(status_msg, spinner="dots"):
        try:
            if outfile:
                with open(outfile, "w") as f:
                    result = subprocess.run(
                        cmd, stdout=f, stderr=subprocess.PIPE, text=True, timeout=timeout
                    )
            else:
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout
                )
            if result.returncode != 0 and not quiet:
                err = (result.stderr or "").strip()[:400]
                if err:
                    log(f"{tool} exited {result.returncode}: {err}", "warning")
            return True  # Continue even on non-zero; many tools return non-zero with useful output
        except subprocess.TimeoutExpired:
            log(f"{tool} timed out after {timeout}s", "error")
            return False
        except FileNotFoundError:
            log(f"Tool not found: {tool}", "error")
            return False

def load_targets(path: Path):
    targets = []
    with open(path) as f:
        for line in f:
            t = line.strip()
            if t and not t.startswith("#"):
                targets.append(t)
    return targets

def is_domain(t: str) -> bool:
    # Simple heuristic: contains a dot and is not pure IPv4/IPv6
    if not "." in t:
        return False
    # Strip port if present
    host = t.split(":")[0] if ":" in t and not t.count(":") > 1 else t
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        return False
    if ":" in host and not re.match(r"^[0-9a-fA-F:]+$", host.replace(".", "")):  # rough IPv6 skip
        pass
    return True

def stage_header(num, title):
    console.print(Panel(
        f"[stage]Stage {num}[/]  {title}",
        border_style="magenta",
        box=box.ROUNDED,
        expand=False
    ))

def extract_urls_from_httpx(outfile: Path) -> list[str]:
    """Extract clean URLs from httpx output (handles both plain and -json)."""
    urls = []
    if not outfile.exists():
        return urls
    text = outfile.read_text(errors="ignore")
    # Prefer JSON if present
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and '"url"' in line:
            try:
                obj = json.loads(line)
                if url := obj.get("url"):
                    urls.append(url)
                continue
            except json.JSONDecodeError:
                pass
        # Fallback: first token that looks like a URL
        token = line.split()[0]
        if token.startswith(("http://", "https://")):
            urls.append(token)
    return sorted(set(urls))

def main():
    parser = argparse.ArgumentParser(
        description="External recon & enumeration workflow (no exploitation)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--targets", required=True, help="Path to targets.txt (domains and/or IPs)")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("--http-rate", type=int, default=DEFAULT_HTTP_RATE, help="httpx/nuclei rate limit")
    parser.add_argument("--naabu-rate", type=int, default=DEFAULT_NAABU_RATE, help="naabu packets per second")
    parser.add_argument("--skip-ffuf", action="store_true", help="Skip content discovery")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip nmap -A")
    args = parser.parse_args()

    banner()

    targets_path = Path(args.targets)
    if not targets_path.exists():
        log(f"Targets file not found: {targets_path}", "error")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output or f"recon_{timestamp}")
    outdir.mkdir(parents=True, exist_ok=True)
    log(f"Output directory: [bold]{outdir.absolute()}[/]")

    check_tools()

    httpx_bin = find_pd_httpx()
    if not httpx_bin:
        console.print(Panel(
            "[error]ProjectDiscovery httpx not found.[/]\n"
            "The 'httpx' in your PATH appears to be the Python httpx CLI (no -l / -list support).\n\n"
            "Install the correct one:\n"
            "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "Then ensure ~/go/bin is before the Python httpx in PATH, or use the full path.",
            title="httpx Mismatch",
            border_style="red"
        ))
        sys.exit(1)
    log(f"Using ProjectDiscovery httpx: [bold]{httpx_bin}[/]", "success")

    targets = load_targets(targets_path)
    domains = [t for t in targets if is_domain(t)]
    ips = [t for t in targets if not is_domain(t)]

    table = Table(title="Targets Loaded", box=box.SIMPLE)
    table.add_column("Type", style="cyan")
    table.add_column("Count", justify="right", style="green")
    table.add_row("Domains", str(len(domains)))
    table.add_row("IPs", str(len(ips)))
    table.add_row("Total", str(len(targets)))
    console.print(table)

    all_subs = set(domains)  # always include root domains

    # ---------- Stage 1: Subdomain Enumeration ----------
    stage_header(1, "Subdomain Enumeration")
    if domains and shutil.which("subfinder"):
        domains_file = outdir / "01_domains.txt"
        domains_file.write_text("\n".join(domains) + "\n")
        subfinder_out = outdir / "01_subfinder.txt"
        run_cmd(["subfinder", "-dL", str(domains_file), "-silent", "-all", "-o", str(subfinder_out)])
        if subfinder_out.exists():
            all_subs.update(line.strip() for line in subfinder_out.read_text().splitlines() if line.strip())

    if domains and shutil.which("amass"):
        amass_out = outdir / "01_amass.txt"
        for d in domains:
            tmp = outdir / f"01_amass_{d.replace('.', '_')}.txt"
            run_cmd(["amass", "enum", "-passive", "-d", d, "-o", str(tmp), "-silent"], timeout=1800, quiet=True)
            if tmp.exists():
                all_subs.update(line.strip() for line in tmp.read_text().splitlines() if line.strip())
        # Merge for convenience
        (outdir / "01_amass_merged.txt").write_text("\n".join(sorted(all_subs)) + "\n")

    subs_file = outdir / "01_all_subdomains.txt"
    subs_file.write_text("\n".join(sorted(all_subs)) + "\n")
    log(f"Unique subdomains (+ roots): [bold green]{len(all_subs)}[/]", "success")

    # ---------- Stage 2: DNS Resolution (dnsx) ----------
    resolved_hosts = set(all_subs)
    resolved_ips = set(ips)
    if shutil.which("dnsx") and (all_subs or domains):
        stage_header(2, "DNS Resolution (dnsx)")
        dnsx_out = outdir / "02_dnsx.txt"
        run_cmd(["dnsx", "-l", str(subs_file), "-silent", "-a", "-resp", "-o", str(dnsx_out)])
        if dnsx_out.exists():
            for line in dnsx_out.read_text().splitlines():
                # e.g. "sub.example.com [1.2.3.4]"
                if "[" in line and "]" in line:
                    host = line.split("[")[0].strip()
                    ip_part = line.split("[")[1].split("]")[0].strip()
                    if host:
                        resolved_hosts.add(host)
                    if ip_part and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip_part):
                        resolved_ips.add(ip_part)
        log(f"Resolved hosts: {len(resolved_hosts)} | Unique IPs: {len(resolved_ips)}", "success")
    else:
        if not shutil.which("dnsx"):
            log("dnsx not in PATH — skipping explicit resolution (naabu/httpx will resolve).", "warning")
        else:
            log("No hostnames to resolve with dnsx.", "warning")

    # ---------- Stage 3: Live HTTP Discovery (httpx) ----------
    stage_header(3, "Live HTTP Host Discovery")
    probe_targets = sorted(resolved_hosts | resolved_ips)
    probe_file = outdir / "03_probe_targets.txt"
    probe_file.write_text("\n".join(probe_targets) + "\n")

    httpx_out = outdir / "03_httpx.jsonl"
    run_cmd([
        httpx_bin, "-l", str(probe_file),
        "-silent", "-json",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-follow-redirects", "-rate-limit", str(args.http_rate),
        "-o", str(httpx_out)
    ])
    live_urls = extract_urls_from_httpx(httpx_out)
    # Also write clean list
    (outdir / "03_live_urls.txt").write_text("\n".join(live_urls) + "\n")
    log(f"Live HTTP endpoints: [bold green]{len(live_urls)}[/]", "success")

    # ---------- Stage 4: Port Scanning (naabu) ----------
    stage_header(4, "Port Scanning (naabu)")
    portscan_targets = sorted(resolved_hosts | resolved_ips)
    ports_file = outdir / "04_portscan_targets.txt"
    ports_file.write_text("\n".join(portscan_targets) + "\n")

    naabu_out = outdir / "04_naabu.txt"
    naabu_cmd = [
        "naabu", "-list", str(ports_file),
        "-top-ports", "1000",
        "-rate", str(args.naabu_rate),
        "-exclude-cdn",
        "-silent", "-o", str(naabu_out)
    ]
    run_cmd(naabu_cmd, timeout=7200)

    open_ports = []  # list of "host:port"
    hosts_with_ports = set()
    if naabu_out.exists():
        for line in naabu_out.read_text().splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                open_ports.append(line)
                hosts_with_ports.add(line.split(":")[0])
    log(f"Open ports found: [bold green]{len(open_ports)}[/] across {len(hosts_with_ports)} hosts", "success")

    # ---------- Stage 4b: Probe discovered non-standard ports with httpx ----------
    extra_urls = []
    if open_ports and httpx_bin:
        stage_header("4b", "HTTP Probe on Discovered Ports")
        # Build host:port list for non-80/443 (and always include originals)
        extra_targets = [p for p in open_ports if not p.endswith(":80") and not p.endswith(":443")]
        if extra_targets:
            extra_file = outdir / "04b_extra_ports.txt"
            extra_file.write_text("\n".join(extra_targets) + "\n")
            extra_httpx = outdir / "04b_httpx_extra.jsonl"
            run_cmd([
                httpx_bin, "-l", str(extra_file),
                "-silent", "-json",
                "-status-code", "-title", "-tech-detect",
                "-follow-redirects", "-rate-limit", str(args.http_rate),
                "-o", str(extra_httpx)
            ])
            extra_urls = extract_urls_from_httpx(extra_httpx)
            live_urls = sorted(set(live_urls + extra_urls))
            (outdir / "03_live_urls.txt").write_text("\n".join(live_urls) + "\n")
            log(f"Additional live endpoints from open ports: {len(extra_urls)}", "success")

    # ---------- Stage 5: nmap -A on hosts with open ports ----------
    if not args.skip_nmap and shutil.which("nmap") and hosts_with_ports:
        stage_header(5, "Nmap Aggressive Scan (-A)")
        nmap_targets = outdir / "05_nmap_targets.txt"
        nmap_targets.write_text("\n".join(sorted(hosts_with_ports)) + "\n")
        nmap_out = outdir / "05_nmap_A.txt"
        # -A = -O -sV -sC --traceroute (version, OS, scripts, traceroute)
        run_cmd([
            "nmap", "-iL", str(nmap_targets),
            "-A", "--open",
            "-oN", str(nmap_out)
        ], timeout=10800)
        log("nmap -A complete. Review 05_nmap_A.txt for service/OS details.", "success")
    elif args.skip_nmap:
        log("Skipping nmap (--skip-nmap).", "warning")

    # ---------- Stage 6: Web Crawling (katana) ----------
    if live_urls and shutil.which("katana"):
        stage_header(6, "Web Crawling (katana)")
        katana_in = outdir / "06_katana_targets.txt"
        katana_in.write_text("\n".join(live_urls) + "\n")
        katana_out = outdir / "06_katana_endpoints.txt"
        run_cmd([
            "katana", "-list", str(katana_in),
            "-silent", "-jc", "-d", "3",
            "-rate-limit", str(args.http_rate),
            "-o", str(katana_out)
        ])
    else:
        log("Skipping katana (no live URLs or tool missing).", "warning")

    # ---------- Stage 7: Nuclei ----------
    if live_urls and shutil.which("nuclei"):
        stage_header(7, "Nuclei Template Scanning")
        nuclei_in = outdir / "07_nuclei_targets.txt"
        nuclei_in.write_text("\n".join(live_urls) + "\n")
        nuclei_out = outdir / "07_nuclei_findings.txt"
        run_cmd([
            "nuclei", "-l", str(nuclei_in),
            "-severity", "low,medium,high,critical",
            "-rate-limit", str(args.http_rate),
            "-silent", "-o", str(nuclei_out)
        ])
    else:
        log("Skipping nuclei (no live URLs or tool missing).", "warning")

    # ---------- Stage 8: Content Discovery (ffuf) ----------
    if not args.skip_ffuf and live_urls and shutil.which("ffuf"):
        stage_header(8, "Content Discovery (ffuf)")
        ffuf_targets = live_urls[:15]  # limit to avoid very long runs
        ffuf_dir = outdir / "08_ffuf"
        ffuf_dir.mkdir(exist_ok=True)
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if Path(wordlist).exists():
            for url in ffuf_targets:
                safe = re.sub(r"[^a-zA-Z0-9._-]", "_", url)[:70]
                outf = ffuf_dir / f"{safe}.json"
                run_cmd([
                    "ffuf", "-u", f"{url}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,301,302,403",
                    "-rate", str(args.http_rate),
                    "-o", str(outf), "-of", "json",
                    "-s"
                ], timeout=1800, quiet=True)
        else:
            log("No common wordlist found; skipping ffuf.", "warning")
    elif args.skip_ffuf:
        log("Skipping content discovery (--skip-ffuf).", "warning")

    # ---------- Stage 9: OSINT (theHarvester) ----------
    if domains and shutil.which("theHarvester"):
        stage_header(9, "OSINT Email Harvest (theHarvester)")
        harvest_out = outdir / "09_theHarvester.txt"
        for d in domains[:3]:
            run_cmd(["theHarvester", "-d", d, "-b", "all", "-f", str(harvest_out)], timeout=900, quiet=True)

    # ---------- Stage 10: Nikto ----------
    if not args.skip_nikto and live_urls and shutil.which("nikto"):
        stage_header(10, "Nikto Web Server Scan")
        nikto_dir = outdir / "10_nikto"
        nikto_dir.mkdir(exist_ok=True)
        for url in live_urls[:8]:
            safe = re.sub(r"[^a-zA-Z0-9._-]", "_", url)[:50]
            outf = nikto_dir / f"{safe}.txt"
            run_cmd(["nikto", "-h", url, "-o", str(outf)], timeout=900, quiet=True)
    elif args.skip_nikto:
        log("Skipping Nikto (--skip-nikto).", "warning")

    # ---------- Summary ----------
    summary = {
        "timestamp": timestamp,
        "targets_file": str(targets_path),
        "output_dir": str(outdir.absolute()),
        "domains": len(domains),
        "ips_input": len(ips),
        "subdomains_discovered": len(all_subs),
        "live_http_endpoints": len(live_urls),
        "open_ports_found": len(open_ports),
        "hosts_with_open_ports": len(hosts_with_ports),
    }
    summary_file = outdir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))

    console.print()
    console.print(Panel(
        f"[success]Workflow complete[/]\n"
        f"Results: [bold]{outdir.absolute()}[/]\n"
        f"Summary: [bold]{summary_file.name}[/]\n"
        f"Key files: 01_all_subdomains.txt, 03_live_urls.txt, 04_naabu.txt, 05_nmap_A.txt",
        title="Done",
        border_style="green"
    ))

    final_table = Table(title="Results Summary", box=box.ROUNDED)
    final_table.add_column("Metric", style="cyan")
    final_table.add_column("Value", justify="right", style="green")
    final_table.add_row("Subdomains", str(len(all_subs)))
    final_table.add_row("Live HTTP endpoints", str(len(live_urls)))
    final_table.add_row("Open ports (naabu)", str(len(open_ports)))
    final_table.add_row("Hosts with ports", str(len(hosts_with_ports)))
    final_table.add_row("Output directory", str(outdir.name))
    console.print(final_table)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[error]Interrupted by user.[/]")
        sys.exit(130)
