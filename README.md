# External Recon & Enumeration Workflow
Blackbox Intelligence Group LLC

Polished CLI orchestrator that chains external recon tools. No exploitation. Each stage feeds the next.

## Requirements
**Python packages:**
```bash
pip install rich
```

**Tools in PATH** (Kali/Parrot recommended or Go-installed ProjectDiscovery suite):

**Required:**
- subfinder
- amass
- httpx
- naabu
- nuclei
- katana
- ffuf
- theHarvester

**Optional (used if present):**
- nmap
- nikto
- dnsx

### Quick install (Go)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
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

# Custom output and rate
python3 external_recon_workflow.py -t targets.txt -o /path/to/results --rate 30

# Skip slower stages
python3 external_recon_workflow.py -t targets.txt --skip-ffuf --skip-nikto
```

## Stages
1. Subdomain enumeration (subfinder + amass)
2. Live HTTP discovery (httpx with tech-detect)
3. Port scanning (naabu top-1000 + optional nmap -sV)
4. Endpoint crawling (katana)
5. Template scanning (nuclei, low+)
6. Content discovery (ffuf on first 20 live hosts)
7. OSINT email harvest (theHarvester)
8. Quick web server scan (nikto, first 10)

All raw output lands in a timestamped directory. Final `summary.json` plus a rich summary table.

## Notes
- Rate limits applied where supported.
- No exploitation, no credential attacks, no Metasploit.
- Review findings manually. Scanner output is a starting point, not a final report.
- Run only against authorized targets under written rules of engagement.
- Ctrl+C cleanly exits.
