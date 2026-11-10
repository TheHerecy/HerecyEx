#!/usr/bin/env python3
"""Offline regression checks for HerecyEx scope, redirects, and tool detection.

No network. No scans. The unauthorized case checks the Python process
return code directly. A shell pipeline (`python3 ... | tail; echo $?`)
reports the last command in the pipe, which is why an earlier run looked
like exit 0.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import external_recon_workflow as hx  # noqa: E402


class Cfg:
    def __init__(self, outdir: Path, **kw):
        self.outdir = outdir
        self.scope_enforced = kw.get("scope_enforced", True)
        self.scope_nets = kw.get("scope_nets", [])
        self.scope_suffixes = kw.get("scope_suffixes", [])
        self.allow_intrusive_checks = kw.get("allow_intrusive_checks", False)
        self.authorized = kw.get("authorized", False)
        self.http_rate = 50
        self.threads = 2
        self.profile = "standard"
        self.nuclei_severity = ""
        self.extra_nmap = []
        self.nmap_timing = "4"


def _scoped(tmp: Path):
    net = __import__("ipaddress").ip_network("203.0.113.0/24")
    cfg = Cfg(tmp, scope_nets=[net], scope_suffixes=["example.com"])
    ts = hx.TargetSet()
    for name in ("example.com", "www.example.com", "cdn.example.com", "mixed.example.com", "dangling.example.com"):
        ts.add_domain(name)
    ts.add_ip("203.0.113.10")
    ts.cidrs = ["203.0.113.0/24"]
    hx.capture_seeds(ts)
    resolved = {
        "www.example.com": ["203.0.113.10"],
        "cdn.example.com": ["198.51.100.50"],
        "mixed.example.com": ["203.0.113.10", "198.51.100.8"],
        "dangling.example.com": [],
        "example.com": ["203.0.113.10"],
    }
    hx.apply_resolution_scope(cfg, ts, resolved, state=None)
    return cfg, ts


def row_active_is_false(ts: hx.TargetSet, name: str) -> bool:
    return any(row["name"] == name and row["active"] is False for row in ts.scope_decisions)


def test_out_of_scope_dns_is_candidate_only():
    with tempfile.TemporaryDirectory() as raw:
        cfg, ts = _scoped(Path(raw))
        assert ts.active_names == []
        for name in ("www.example.com", "cdn.example.com", "mixed.example.com", "dangling.example.com", "example.com"):
            assert name in ts.candidates or name in ts.domains
            assert name not in ts.active_names
        assert "cdn.example.com" in ts.domains
        probes = hx.filter_probe_tokens(
            [
                "https://www.example.com",
                "https://cdn.example.com",
                "https://mixed.example.com",
                "https://dangling.example.com",
                "198.51.100.50",
                "203.0.113.10",
                "https://203.0.113.10",
            ],
            cfg,
            ts,
        )
        assert probes == ["203.0.113.10", "https://203.0.113.10"], probes
        assert hx.portscan_targets(cfg, ts) == ["203.0.113.10"]
        assert "198.51.100.50" not in ts.ips
        assert hx.nuclei_enabled(cfg) is False
        reasons = {row["name"]: row["reason"] for row in ts.scope_decisions}
        assert "not pinned" in reasons["www.example.com"]
        assert reasons["www.example.com"] and row_active_is_false(ts, "www.example.com")


def test_redirect_is_not_a_probe_target():
    with tempfile.TemporaryDirectory() as raw:
        cfg, ts = _scoped(Path(raw))
        off = "https://evil.example/landing"
        assert hx.consider_redirect(off, cfg, ts) is False
        # The name resolved in-scope, and it is still not probed. DNS is not pinned.
        assert hx.consider_redirect("https://www.example.com/app", cfg, ts) is False
        assert hx.consider_redirect("https://203.0.113.10/", cfg, ts) is True
        assert hx.filter_probe_tokens(["https://www.example.com", off, "https://203.0.113.10"], cfg, ts) == [
            "https://203.0.113.10"
        ]


def test_child_commands_do_not_follow_off_host_redirects():
    with tempfile.TemporaryDirectory() as raw:
        cfg, ts = _scoped(Path(raw))
        url = "https://203.0.113.10"
        assert hx.url_host_allowed(url, cfg, ts)
        assert hx.url_host_allowed("https://www.example.com", cfg, ts) is False
        assert hx.nuclei_enabled(cfg) is False
        httpx = hx.httpx_probe_args("httpx", Path("in.txt"), Path("out.json"), cfg)
        nuclei = hx.nuclei_probe_args("nuclei", Path("urls.txt"), Path("nuclei.jsonl"), cfg)
        whatweb = hx.whatweb_args("whatweb", url, cfg)
        waf = hx.wafw00f_args("wafw00f", url)
        word = Path("words.txt")
        ferox = hx.ferox_args("feroxbuster", url, word, Path("out.txt"), cfg)
        gob = hx.gobuster_args("gobuster", url, word, Path("out.txt"), cfg)
        ffuf = hx.ffuf_args("ffuf", url, word, Path("out.json"), cfg)
        nmap = hx.nmap_service_cmd(cfg, ["nmap"], "-sT", Path("out"), Path("hosts"), top_ports=100)
        for cmd in (httpx, nuclei, whatweb, waf, ferox, gob, ffuf, nmap):
            assert "-follow-redirects" not in cmd
            assert "-follow-host-redirects" not in cmd
            assert "-sC" not in cmd
            assert "katana" not in cmd
            assert "nikto" not in cmd
            assert "gowitness" not in cmd
        assert "--follow-redirect=never" in whatweb
        assert "-r" in waf
        assert "-disable-redirects" in nuclei
        assert "-no-interactsh" in nuclei
        assert hx.NUCLEI_EXCLUDED_TAGS in nuclei
        assert "-jsonl" in nuclei and "-je" not in nuclei
        assert "--redirects" not in ferox
        assert "-r" not in gob  # gobuster -r follows redirects
        assert "-r" not in ffuf
        # Out-of-scope URL must not be planned as an httpx/nuclei input.
        assert hx.filter_probe_tokens(["https://cdn.example.com"], cfg, ts) == []
        for name in hx.REDIRECT_UNSCOPED_TOOLS:
            assert name in {"katana", "gowitness", "eyewitness", "nikto"}


def test_intrusive_nse_off_by_default():
    cfg = Cfg(Path("."), allow_intrusive_checks=False, authorized=True, scope_enforced=False)
    assert hx.smtp_scripts(cfg) == "smtp-commands"
    assert "smtp-vrfy" not in hx.smtp_scripts(cfg)
    assert "smtp-open-relay" not in hx.smtp_scripts(cfg)
    assert "empty-password" not in hx.mssql_scripts(cfg)
    assert "empty-password" not in hx.mysql_scripts(cfg)
    opted = Cfg(Path("."), allow_intrusive_checks=True, authorized=False, scope_enforced=False)
    assert hx.smtp_scripts(opted) == "smtp-commands"
    both = Cfg(Path("."), allow_intrusive_checks=True, authorized=True, scope_enforced=False)
    assert "smtp-enum-users" in hx.smtp_scripts(both)
    assert "smtp-open-relay" in hx.smtp_scripts(both)
    args = hx.smtp_script_args(Path("/tmp/probe.txt"))
    assert "methods={VRFY}" in args
    assert "userlimit=1" in args
    assert "RCPT" not in args
    assert "ms-sql-empty-password" in hx.mssql_scripts(both)
    assert "mysql-empty-password" in hx.mysql_scripts(both)


def test_axfr_skips_third_party_nameserver():
    with tempfile.TemporaryDirectory() as raw:
        cfg, ts = _scoped(Path(raw))
        third = hx.axfr_commands("example.com", "ns.cloudflare.example", ["198.51.100.53"], cfg, ts)
        assert third == []
        local = hx.axfr_commands("example.com", "ns1.example.com", ["203.0.113.53"], cfg, ts)
        assert local and local[0][1] == "@203.0.113.53"
        assert all(not part.startswith("@ns") for cmd in local for part in cmd)


def test_nuclei_parser_accepts_array_and_jsonl():
    with tempfile.TemporaryDirectory() as raw:
        base = Path(raw)
        array = base / "array.json"
        array.write_text('[{"template-id":"a","info":{"name":"A","severity":"info"}}]')
        pretty = base / "pretty.json"
        pretty.write_text('[\n  {"template-id": "b", "info": {"name": "B", "severity": "low"}}\n]\n')
        jsonl = base / "lines.jsonl"
        jsonl.write_text('{"template-id":"c","info":{"name":"C","severity":"high"}}\n\n')
        empty = base / "empty.jsonl"
        empty.write_text("")
        missing = base / "missing.jsonl"
        assert len(hx.parse_nuclei_records(array)) == 1
        assert len(hx.parse_nuclei_records(pretty)) == 1
        assert hx.parse_nuclei_records(jsonl)[0]["template-id"] == "c"
        assert hx.parse_nuclei_records(empty) == []
        assert hx.parse_nuclei_records(missing) == []


def test_kali_testssl_binary_name():
    """Kali's testssl.sh package installs /usr/bin/testssl, not testssl.sh."""
    tool = next(t for t in hx.TOOLS if t.name == "testssl")
    assert tool.binary == "testssl.sh"
    assert "testssl" in tool.alt_binaries
    with tempfile.TemporaryDirectory() as raw:
        exe = Path(raw) / "testssl"
        exe.write_text("#!/bin/sh\nexit 0\n")
        exe.chmod(0o755)
        real_which = hx.which

        def only_kali_name(binary: str):
            if binary == "testssl.sh":
                return None
            if binary == "testssl":
                return str(exe)
            return real_which(binary)

        hx.which = only_kali_name
        try:
            tools = hx.Toolset()
        finally:
            hx.which = real_which
        status = tools.status["testssl"]
        assert status.present, status
        assert status.path == str(exe)
        assert Path(status.path).name == "testssl"


def test_unauthorized_exit_is_3_and_creates_no_directory():
    """The app's own return code. Do not pipe this through tail."""
    with tempfile.TemporaryDirectory() as raw:
        out = Path(raw) / "should-not-exist"
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "external_recon_workflow.py"),
                "-t",
                str(ROOT / "targets.example.txt"),
                "-o",
                str(out),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 3, (proc.returncode, proc.stdout[-400:], proc.stderr[-400:])
        assert not out.exists()


def main() -> int:
    tests = [
        test_out_of_scope_dns_is_candidate_only,
        test_redirect_is_not_a_probe_target,
        test_child_commands_do_not_follow_off_host_redirects,
        test_intrusive_nse_off_by_default,
        test_axfr_skips_third_party_nameserver,
        test_nuclei_parser_accepts_array_and_jsonl,
        test_kali_testssl_binary_name,
        test_unauthorized_exit_is_3_and_creates_no_directory,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
        except Exception as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
        else:
            print(f"ok   {fn.__name__}")
    if failed:
        print(f"{failed} failed")
        return 1
    print(f"{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
