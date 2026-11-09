#!/usr/bin/env python3
"""
Blackbox Intelligence Group LLC
External Penetration Test — Recon & Enumeration Workflow
Polished CLI | No exploitation | Stage results feed the next

Usage:
  python3 external_recon_workflow.py -t targets.txt
"""

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

# ---------- Theme ----------
custom_theme = Theme({
    "info": "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "stage": "bold magenta",
    "tool": "dim cyan",
    "banner": "bold white on blue",
})

console = Console(theme=custom_theme)

DEFAULT_RATE = 50
TIMEOUT = 3600

REQUIRED_TOOLS = [
    "subfinder", "amass", "httpx", "naabu", "nuclei", "katana", "ffuf", "theHarvester"
]
OPTIONAL_TOOLS = ["nmap", "nikto", "dnsx"]

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

def check_tools():
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        console.print(Panel(
            f"[error]Missing required tools:[/]\n" + "\n".join(f"  • {t}" for t in missing) +
            "\n\n[dim]Install ProjectDiscovery suite via Go or use a Kali/Parrot environment.[/]",
            title="Tool Check Failed",
            border_style="red"
        ))
        sys.exit(1)

    present_optional = [t for t in OPTIONAL_TOOLS if shutil.which(t)]
    missing_optional = [t for t in OPTIONAL_TOOLS if shutil.which(t) is None]
    if present_optional:
        log(f"Optional tools available: {', '.join(present_optional)}", "success")
    if missing_optional:
        log(f"Optional tools not found (skipped): {', '.join(missing_optional)}", "warning")
    log("All required tools present.", "success")

def run_cmd(cmd, outfile=None, timeout=TIMEOUT):
    """Run a command with a spinner. Returns True on success."""
    tool = cmd[0]
    with console.status(f"[tool]Running {tool}...[/]", spinner="dots"):
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
            if result.returncode != 0:
                err = (result.stderr or "").strip()[:300]
                if err:
                    log(f"{tool} exited {result.returncode}: {err}", "warning")
            return result.returncode == 0
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

def is_domain(t):
    return "." in t and not t.replace(".", "").replace(":", "").isdigit()

def stage_header(num, title):
    console.print(Panel(
        f"[stage]Stage {num}[/]  {title}",
        border_style="magenta",
        box=box.ROUNDED,
        expand=False
    ))

def main():
    parser = argparse.ArgumentParser(
        description="External recon & enumeration workflow (no exploitation)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--targets", required=True, help="Path to targets.txt")
    parser.add_argument("-o", "--output", default=None, help="Output directory")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE, help="Request/packet rate limit")
    parser.add_argument("--skip-ffuf", action="store_true", help="Skip content discovery")
    parser.add_argument("--skip-nikto", action="store_true", help="Skip Nikto")
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

    # ---------- Stage 1 ----------
    stage_header(1, "Subdomain Enumeration")
    all_subs = set()
    if domains:
        subfinder_out = outdir / "01_subfinder.txt"
        run_cmd(["subfinder", "-dL", str(targets_path), "-silent", "-all"], subfinder_out)
        if subfinder_out.exists():
            all_subs.update(line.strip() for line in subfinder_out.read_text().splitlines() if line.strip())

        amass_out = outdir / "01_amass.txt"
        for d in domains:
            run_cmd(["amass", "enum", "-passive", "-d", d, "-o", str(amass_out), "-silent"], timeout=1800)
        if amass_out.exists():
            all_subs.update(line.strip() for line in amass_out.read_text().splitlines() if line.strip())

    subs_file = outdir / "01_all_subdomains.txt"
    subs_file.write_text("\n".join(sorted(all_subs)) + "\n")
    log(f"Unique subdomains: [bold green]{len(all_subs)}[/]", "success")

    # ---------- Stage 2 ----------
    stage_header(2, "Live HTTP Host Discovery")
    probe_targets = list(all_subs) + domains + ips
    probe_file = outdir / "02_probe_targets.txt"
    probe_file.write_text("\n".join(probe_targets) + "\n")

    httpx_out = outdir / "02_httpx_live.txt"
    run_cmd([
        "httpx", "-l", str(probe_file),
        "-silent", "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-rate-limit", str(args.rate),
        "-o", str(httpx_out)
    ])
    live_urls = []
    if httpx_out.exists():
        live_urls = [line.strip() for line in httpx_out.read_text().splitlines() if line.strip()]
    log(f"Live HTTP endpoints: [bold green]{len(live_urls)}[/]", "success")

    # ---------- Stage 3 ----------
    stage_header(3, "Port Scanning")
    portscan_targets = list(all_subs) + domains + ips
    ports_file = outdir / "03_portscan_targets.txt"
    ports_file.write_text("\n".join(portscan_targets) + "\n")

    naabu_out = outdir / "03_naabu_ports.txt"
    run_cmd([
        "naabu", "-list", str(ports_file),
        "-top-ports", "1000", "-rate", str(args.rate),
        "-silent", "-o", str(naabu_out)
    ])

    if shutil.which("nmap") and naabu_out.exists():
        hosts_with_ports = set()
        for line in naabu_out.read_text().splitlines():
            if ":" in line:
                hosts_with_ports.add(line.split(":")[0])
        if hosts_with_ports:
            nmap_targets = outdir / "03_nmap_targets.txt"
            nmap_targets.write_text("\n".join(hosts_with_ports) + "\n")
            nmap_out = outdir / "03_nmap_services.txt"
            run_cmd([
                "nmap", "-iL", str(nmap_targets),
                "-sV", "-sC", "--top-ports", "100",
                "-oN", str(nmap_out), "--open"
            ], timeout=7200)

    # ---------- Stage 4 ----------
    stage_header(4, "Web Crawling")
    if live_urls:
        katana_in = outdir / "04_katana_targets.txt"
        katana_in.write_text("\n".join(live_urls) + "\n")
        katana_out = outdir / "04_katana_endpoints.txt"
        run_cmd([
            "katana", "-list", str(katana_in),
            "-silent", "-jc", "-d", "3",
            "-rate-limit", str(args.rate),
            "-o", str(katana_out)
        ])
    else:
        log("No live URLs for crawling.", "warning")

    # ---------- Stage 5 ----------
    stage_header(5, "Nuclei Template Scanning")
    if live_urls:
        nuclei_in = outdir / "05_nuclei_targets.txt"
        nuclei_in.write_text("\n".join(live_urls) + "\n")
        nuclei_out = outdir / "05_nuclei_findings.txt"
        run_cmd([
            "nuclei", "-l", str(nuclei_in),
            "-severity", "low,medium,high,critical",
            "-rate-limit", str(args.rate),
            "-silent", "-o", str(nuclei_out)
        ])
    else:
        log("No live URLs for Nuclei.", "warning")

    # ---------- Stage 6 ----------
    if not args.skip_ffuf and live_urls:
        stage_header(6, "Content Discovery (ffuf)")
        ffuf_targets = live_urls[:20]
        ffuf_dir = outdir / "06_ffuf"
        ffuf_dir.mkdir(exist_ok=True)
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if Path(wordlist).exists():
            for url in ffuf_targets:
                safe_name = url.replace("://", "_").replace("/", "_").replace(":", "_")[:60]
                outf = ffuf_dir / f"{safe_name}.json"
                run_cmd([
                    "ffuf", "-u", f"{url}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,301,302,403",
                    "-rate", str(args.rate),
                    "-o", str(outf), "-of", "json",
                    "-s"
                ], timeout=1800)
        else:
            log("No common wordlist found; skipping ffuf.", "warning")
    elif args.skip_ffuf:
        log("Skipping content discovery (--skip-ffuf).", "warning")

    # ---------- Stage 7 ----------
    stage_header(7, "OSINT Email Harvest")
    if domains:
        harvest_out = outdir / "07_theHarvester.txt"
        for d in domains[:5]:
            run_cmd(["theHarvester", "-d", d, "-b", "all", "-f", str(harvest_out)], timeout=1200)

    # ---------- Stage 8 ----------
    if not args.skip_nikto and shutil.which("nikto") and live_urls:
        stage_header(8, "Nikto Web Server Scan")
        nikto_dir = outdir / "08_nikto"
        nikto_dir.mkdir(exist_ok=True)
        for url in live_urls[:10]:
            safe = url.replace("://", "_").replace("/", "_")[:50]
            outf = nikto_dir / f"{safe}.txt"
            run_cmd(["nikto", "-h", url, "-o", str(outf)], timeout=900)
    elif args.skip_nikto:
        log("Skipping Nikto (--skip-nikto).", "warning")

    # ---------- Summary ----------
    summary = {
        "timestamp": timestamp,
        "targets_file": str(targets_path),
        "output_dir": str(outdir.absolute()),
        "domains": len(domains),
        "ips": len(ips),
        "subdomains_discovered": len(all_subs),
        "live_http_endpoints": len(live_urls),
    }
    summary_file = outdir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))

    console.print()
    console.print(Panel(
        f"[success]Workflow complete[/]\n"
        f"Results: [bold]{outdir.absolute()}[/]\n"
        f"Summary: [bold]{summary_file.name}[/]",
        title="Done",
        border_style="green"
    ))

    final_table = Table(title="Results Summary", box=box.ROUNDED)
    final_table.add_column("Metric", style="cyan")
    final_table.add_column("Value", justify="right", style="green")
    final_table.add_row("Subdomains", str(len(all_subs)))
    final_table.add_row("Live HTTP endpoints", str(len(live_urls)))
    final_table.add_row("Output directory", str(outdir.name))
    console.print(final_table)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[error]Interrupted by user.[/]")
        sys.exit(130)
