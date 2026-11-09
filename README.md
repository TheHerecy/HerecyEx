# External Recon & Enumeration Workflow
Blackbox Intelligence Group LLC

Polished CLI orchestrator that chains external recon tools. No exploitation. Each stage feeds the next.

## Requirements
**Python packages:**
```bash
pip install rich
```

**Tools in PATH** (Kali/Parrot recommended or Go-installed ProjectDiscovery suite):

**Core (required):**
- subfinder
- httpx
- naabu

**Optional (used if present):**
- amass
- dnsx
- nuclei
- katana
- ffuf
- theHarvester
- nmap
- nikto

### Quick install (Go)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

Wordlists expected for ffuf (Kali defaults):
- /usr/share/wordlists/dirb/common.txt
- or /usr/share/seclists/Discovery/Web-Content/common.txt

## Usage
```bash
# Basic run
python3 external_recon_workflow.py -t targets.txt

# Custom rates and output
python3 external_recon_workflow.py -t targets.txt -o /path/to/results --http-rate 30 --naabu-rate 1500

# Skip slower stages
python3 external_recon_workflow.py -t targets.txt --skip-ffuf --skip-nikto --skip-nmap
```

## Stages
1. Subdomain enumeration (subfinder + amass, domains only)
2. DNS resolution (dnsx if available)
3. Live HTTP discovery (httpx with JSON output, clean URL extraction)
4. Port scanning (naabu top-1000, configurable rate, exclude-CDN)
4b. HTTP probe on discovered non-standard ports
5. Nmap aggressive scan (`-A`) on hosts with open ports
6. Endpoint crawling (katana)
7. Template scanning (nuclei)
8. Content discovery (ffuf)
9. OSINT email harvest (theHarvester)
10. Quick web server scan (nikto)

All raw output lands in a timestamped directory. Final `summary.json` plus a rich summary table.

## Notes
- Rate limits applied where supported. Naabu default is 1000 pps; httpx/nuclei default 50.
- Nmap uses `-A` (OS detection, version detection, default scripts, traceroute) on hosts that had open ports.
- No exploitation, no credential attacks, no Metasploit.
- Review findings manually. Scanner output is a starting point, not a final report.
- Run only against authorized targets under written rules of engagement.
- Ctrl+C cleanly exits.
