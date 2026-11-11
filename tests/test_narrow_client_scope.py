#!/usr/bin/env python3
"""Offline scope, DNS, concurrency, and crypto tests for narrow checks.

No live resolver and no socket to a real host. DNS is a fake function.
Tool output is a string. Documentation addresses only (RFC 5737 / RFC 3849).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import external_recon_workflow as hx  # noqa: E402
import narrow_checks as nc  # noqa: E402

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
IP = "203.0.113.10"
OTHER = "203.0.113.11"
OUTSIDE = "198.51.100.5"
HARD = "\n".join([
    "(kex) curve25519-sha256 -- [info] available",
    "(mac) hmac-sha2-256 -- [info] available",
])


class Boom:
    def __init__(self):
        self.calls = []

    def run(self, argv, timeout):
        self.calls.append(list(argv))
        raise AssertionError(argv)

    def __call__(self, name):
        raise AssertionError(name)


def write_files(tmp: Path, manifest: str, scope: str, admit: str):
    manifest_path = tmp / "m.txt"
    scope_path = tmp / "s.txt"
    admit_path = tmp / "a.txt"
    manifest_path.write_text(manifest)
    scope_path.write_text(scope)
    admit_path.write_text(admit)
    return manifest_path, scope_path, admit_path


def run(tmp, manifest, scope, admit, **kwargs):
    manifest_path, scope_path, admit_path = write_files(tmp, manifest, scope, admit)
    rows = nc.parse_manifest(manifest_path)
    return nc.run_manifest(
        rows,
        scope_file=scope_path,
        admit_file=admit_path,
        outdir=tmp / "out",
        now=NOW,
        which=lambda name: f"/usr/bin/{name}",
        sleeper=kwargs.pop("sleeper", lambda _seconds: None),
        clock=kwargs.pop("clock", lambda: 0.0),
        **kwargs,
    )


class ScriptRunner:
    def __init__(self, stdout=HARD, code=0, raise_for=None, unreachable=""):
        self.stdout = stdout
        self.code = code
        self.raise_for = raise_for
        self.unreachable = unreachable
        self.calls = []
        self.lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0

    def run(self, argv, timeout):
        with self.lock:
            self.calls.append((list(argv), timeout))
        if "-V" in argv or "--version" in argv:
            return nc.Completed(list(argv), 0, "tool 1", "", False, "t0", "t1")
        ip = argv[-1]
        with self.lock:
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            if self.raise_for and ip == self.raise_for:
                raise RuntimeError(f"boom {ip}")
            text = self.unreachable or self.stdout
            code = 255 if self.unreachable and ip == OUTSIDE else self.code
            return nc.Completed(list(argv), code, text, "", False, "t0", "t1")
        finally:
            with self.lock:
                self.inflight -= 1

    def probes(self):
        return [argv for argv, _timeout in self.calls if "-V" not in argv and "--version" not in argv]


def test_load_narrow_scope_still_accepts_documentation_prefix_without_caps():
    with tempfile.TemporaryDirectory() as raw:
        scope = Path(raw) / "scope.txt"
        scope.write_text("203.0.113.0/24\n203.0.113.10\n2001:db8::/32\n")
        loaded = nc.load_narrow_scope(scope)
        assert {str(net) for net in loaded} == {"203.0.113.0/24", "203.0.113.10/32", "2001:db8::/32"}


def test_slash_zero_and_broad_cidrs_fail_closed():
    cases = [
        ("0.0.0.0/0\n", "0.0.0.0/0", False),
        ("::/0\n", "::/0", False),
        ("0.0.0.0/0\n", "0.0.0.0/0", True),
        ("::/0\n", "::/0", True),
        ("203.0.0.0/16\n", "prefix floor", False),
        ("2001:db8::/119\n", "prefix floor", False),
    ]
    for text, needle, broad in cases:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            runner = Boom()
            resolver = Boom()
            limits = nc.NarrowLimits(allow_broad_cidr=broad, rate_interval=0)
            try:
                report = run(
                    tmp, f"ssh {IP} 22\n", text, f"{IP}:22\n",
                    runner=runner, resolver=resolver, limits=limits,
                )
            except AssertionError:
                raise AssertionError(text)
            assert report["refused"] is True
            assert needle in report["error"]
            assert runner.calls == []
            assert not (tmp / "out").exists()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        limits = nc.NarrowLimits(allow_broad_cidr=True, rate_interval=0, max_addresses=1024)
        report = run(
            tmp, f"ssh {IP} 22\n", "203.0.0.0/16\n", f"{IP}:22\n",
            runner=Boom(), resolver=Boom(), limits=limits,
        )
        assert report["refused"] is True
        assert "1024" in report["error"]
        assert not (tmp / "out").exists()
    with tempfile.TemporaryDirectory() as raw:
        scope = Path(raw) / "s.txt"
        scope.write_text("203.0.113.10/0\n")
        try:
            nc.load_narrow_scope(scope)
        except nc.NarrowInputError as exc:
            assert "203.0.113.10/0" in exc.message
            assert "0.0.0.0/0" not in exc.message
        else:
            raise AssertionError("non-canonical /0 was rewritten")


def test_address_cap_counts_prefix_legal_networks():
    lines = [f"203.0.11{i}.0/24" for i in range(5)]
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        report = run(
            tmp, f"ssh {IP} 22\n", "\n".join(lines) + "\n", f"{IP}:22\n",
            runner=Boom(), resolver=Boom(), limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["refused"] is True
        assert "1024" in report["error"]
        assert not (tmp / "out").exists()
    four = "\n".join(f"203.0.11{i}.0/24" for i in range(4)) + "\n"
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        report = run(
            tmp, f"ssh 203.0.110.10 22\n", four, "203.0.110.10:22\n",
            runner=Boom(), limits=nc.NarrowLimits(rate_interval=0), dry_run=True,
        )
        assert report["refused"] is False
        assert report["expanded_count"] == 1024
        assert "203.0.110.10" in report["targets"]
        assert not (tmp / "out").exists()


def test_malformed_scope_fails_before_resolver_or_directory():
    bad = [
        "http://example.com\n",
        "example\n",
        "*.example.com\n",
        "+203.0.113.10\n",
        "!\n",
        "203.0.113.010\n",
        "not a host\n",
        "example.com\nexample.com\n",
        "+vpn.example.com\n!vpn.example.com\n",
    ]
    for text in bad:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            runner = Boom()
            resolver = Boom()
            report = run(
                tmp, f"ssh {IP} 22\n", text, f"{IP}:22\n",
                runner=runner, resolver=resolver, limits=nc.NarrowLimits(rate_interval=0),
            )
            assert report["refused"] is True, text
            assert report["error"]
            assert "scope file rejected" in report["error"]
            assert runner.calls == []
            assert not (tmp / "out").exists()


def test_exclusion_and_plain_fqdn_do_not_authorize_outside_addresses():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp,
            f"ssh {IP} 22\nssh 203.0.113.5 22\n",
            "203.0.113.0/28\n!203.0.113.5\n",
            f"{IP}:22\n203.0.113.5:22\n",
            runner=runner, resolver=Boom(), limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["refused"] is True
        assert any("outside --scope-check" in row["provenance"]["error"] for row in report["results"])
        assert runner.calls == []
        assert not (tmp / "out").exists()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        called = []

        def resolver(name):
            called.append(name)
            return {"a": [OUTSIDE], "aaaa": [], "cnames": [], "queried_at": "2026-11-11T00:00:00Z"}

        report = run(
            tmp, f"ssh {OUTSIDE} 22\n", f"vpn.client.example\n{IP}\n", f"{OUTSIDE}:22\n",
            runner=Boom(), resolver=resolver, limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["refused"] is True
        assert "outside --scope-check" in report["results"][0]["provenance"]["error"]
        assert called == []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        seen = []

        def resolver(name):
            seen.append((name, "2026-11-11T00:00:00Z"))
            return {
                "a": [IP],
                "aaaa": ["2001:db8::10"],
                "cnames": ["cdn.client.example"],
                "queried_at": "2026-11-11T00:00:00Z",
            }

        runner = ScriptRunner()
        report = run(
            tmp, f"ssh {IP} 22\n", f"203.0.113.0/28\nvpn.client.example\n", f"{IP}:22\n",
            runner=runner, resolver=resolver, limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["refused"] is False, report.get("error")
        assert report["results"][0]["status"] == "observed_no_weakness"
        saved = report["dns"]["resolutions"][0]
        assert saved["queried_at"] == "2026-11-11T00:00:00Z"
        assert saved["a"] == [IP]
        assert saved["aaaa"] == ["2001:db8::10"]
        assert saved["authorizes"] is False
        assert len(runner.probes()) == 1


def test_plus_authorizes_and_third_party_cname_does_not():
    def answer(name, cnames, addresses, when):
        assert name == "vpn.client.example"
        return {"a": addresses, "aaaa": [], "cnames": cnames, "queried_at": when}

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp, f"ssh {IP} 22\n", "+vpn.client.example\n", f"{IP}:22\n",
            runner=runner,
            resolver=lambda name: answer(name, [], [IP], "2026-11-11T00:00:01Z"),
            limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["results"][0]["status"] == "observed_no_weakness", report
        assert report["dns"]["resolutions"][0]["authorizes"] is True
        assert report["dns"]["resolutions"][0]["queried_at"] == "2026-11-11T00:00:01Z"
        assert len(runner.probes()) == 1
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp, f"ssh {OUTSIDE} 22\n", "+vpn.client.example\n", f"{OUTSIDE}:22\n",
            runner=runner,
            resolver=lambda name: answer(name, ["d111.cloudfront.net"], [OUTSIDE], "2026-11-11T00:00:02Z"),
            limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["refused"] is True
        assert report["dns"]["resolutions"][0]["flagged"] == "third_party_cname"
        assert report["dns"]["resolutions"][0]["authorizes"] is False
        assert runner.calls == []
        assert not (tmp / "out").exists()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp, f"ssh {OUTSIDE} 22\n", "++vpn.client.example\n", f"{OUTSIDE}:22\n",
            runner=runner,
            resolver=lambda name: answer(name, ["d111.cloudfront.net"], [OUTSIDE], "2026-11-11T00:00:03Z"),
            limits=nc.NarrowLimits(rate_interval=0),
        )
        assert report["results"][0]["status"] == "observed_no_weakness"
        assert report["dns"]["resolutions"][0]["flagged"] == "third_party_override"
        assert report["dns"]["resolutions"][0]["authorizes"] is True
        assert len(runner.probes()) == 1


def test_dns_change_blocks_hostname_authorization_only():
    calls = {"n": 0}

    def resolver(_name):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"a": [IP], "aaaa": [], "cnames": [], "queried_at": "2026-11-11T00:00:00Z"}
        return {"a": [OUTSIDE], "aaaa": [], "cnames": [], "queried_at": "2026-11-11T00:00:05Z"}

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp, f"ssh {IP} 22\n", "+vpn.client.example\n", f"{IP}:22\n",
            runner=runner, resolver=resolver, limits=nc.NarrowLimits(rate_interval=0),
        )
        row = report["results"][0]
        assert row["status"] == "error"
        assert row["status"] != "observed_no_weakness"
        assert "dns_changed" in row["provenance"]["error"]
        assert runner.probes() == []
        recheck = row["provenance"]["dns_recheck"][0]
        assert recheck["queried_at"] == "2026-11-11T00:00:05Z"
        assert recheck["still_present"] is False
        assert (tmp / "out" / "narrow-checks.json").is_file()


def test_getaddrinfo_fallback_cannot_authorize_and_cname_walk_is_offline():
    def fake_getaddrinfo(host, _port, *_args):
        assert host == "vpn.client.example"
        return [(__import__("socket").AF_INET, 1, 6, "", ("203.0.113.10", 0))]

    raw = nc._resolve_getaddrinfo("vpn.client.example", fake_getaddrinfo)
    assert raw["cname_unknown"] is True
    assert raw["a"] == [IP]
    scope = nc.NarrowScope(names=[nc.ScopeName("vpn.client.example", "authorize")])
    classified = nc.classify_resolution(scope.names[0], raw, scope)
    assert classified["authorizes"] is False
    assert classified["flagged"] == "cname_chain_unknown"

    def query(name, rtype):
        if rtype == "CNAME" and name == "www.client.example":
            return ["cdn.client.example"]
        if rtype == "CNAME" and name == "cdn.client.example":
            return ["d111.cloudfront.net"]
        if rtype == "CNAME":
            return []
        if rtype == "A" and name == "www.client.example":
            return [OUTSIDE]
        if rtype == "AAAA":
            return []
        raise LookupError("nxdomain")

    walked = nc._resolve_with_query("www.client.example", query)
    assert walked["cnames"] == ["cdn.client.example", "d111.cloudfront.net"]
    assert walked["a"] == [OUTSIDE]
    assert nc.cname_is_third_party("www.client.example", walked["cnames"]) is True
    assert nc.cname_is_third_party("www.client.example", ["cdn.client.example"]) is False


def test_dry_run_expands_without_network_or_directory():
    names = "\n".join(f"host{i}.client.example" for i in range(19))
    bare = "\n".join(f"203.0.113.{i}" for i in range(1, 11))
    scope = "\n".join([
        bare,
        "203.0.113.16/28",
        "203.0.113.32/29",
        "!203.0.113.16",
        "!203.0.113.17",
        names,
    ]) + "\n"
    assert len([line for line in scope.splitlines() if line.strip()]) == 33
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        report = run(
            tmp, "ssh 203.0.113.1 22\n", scope, "203.0.113.1:22\n",
            runner=Boom(), resolver=Boom(), limits=nc.NarrowLimits(rate_interval=0), dry_run=True,
        )
        assert report["dry_run"] is True
        assert report["refused"] is False
        assert report["expanded_count"] == 32
        assert "203.0.113.1" in report["targets"]
        assert "203.0.113.16" not in report["targets"]
        assert "203.0.113.18" in report["targets"]
        assert "203.0.113.32" in report["targets"]
        assert len(report["hostnames"]) == 19
        assert all(item["resolved"] is False for item in report["hostnames"])
        assert not (tmp / "out").exists()


def test_main_dry_run_and_rejects_recon_flags():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_files(tmp, f"ssh {IP} 22\n", "203.0.113.0/28\n", f"{IP}:22\n")
        out = tmp / "out"
        runner = Boom()
        hx._NARROW_RUNNER = runner
        hx._NARROW_RESOLVER = Boom()
        try:
            code = hx.main([
                "--narrow-checks", "--manifest", str(manifest), "--scope-check", str(scope),
                "--admit", str(admit), "--authorized", "-o", str(out), "--dry-run",
                "--narrow-rate", "0",
            ])
        finally:
            hx._NARROW_RUNNER = hx._NARROW_RESOLVER = None
        assert code == 0
        assert runner.calls == []
        assert not out.exists()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_files(tmp, f"ssh {IP} 22\n", f"{IP}\n", f"{IP}:22\n")
        out = tmp / "out"
        runner = Boom()
        hx._NARROW_RUNNER = runner
        try:
            code = hx.main([
                "--narrow-checks", "--manifest", str(manifest), "--scope-check", str(scope),
                "--admit", str(admit), "--authorized", "-o", str(out), "--threads", "4",
            ])
        finally:
            hx._NARROW_RUNNER = None
        assert code == 2
        assert runner.calls == []
        assert not out.exists()


def test_probe_count_is_bounded_per_host_and_in_total():
    hosts = [f"203.0.113.{i}" for i in range(1, 9)]
    manifest = "".join(f"ssh {ip} 22\n" for ip in hosts)
    scope = "".join(f"{ip}\n" for ip in hosts)
    admit = "".join(f"{ip}:22\n" for ip in hosts)
    limits = nc.NarrowLimits(workers=3, rate_interval=0)
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(tmp, manifest, scope, admit, runner=runner, limits=limits)
        probes = runner.probes()
        assert len(probes) == len(hosts)
        assert report["probe_accounting"]["probes_started"] == len(hosts)
        assert report["probe_accounting"]["per_host_probe_cap"] == 1
        assert runner.max_inflight <= 3
        by_ip = {}
        for argv in probes:
            by_ip.setdefault(argv[-1], 0)
            by_ip[argv[-1]] += 1
            assert argv[1:] == ["-n", "-p", "22", "-t", "10", "--skip-rate-test", argv[-1]]
        assert by_ip == {ip: 1 for ip in hosts}
        versions = [argv for argv, _timeout in runner.calls if "-V" in argv]
        assert len(versions) == len(hosts)


def test_stop_does_not_start_past_the_in_flight_set():
    hosts = [f"203.0.113.{i}" for i in range(1, 9)]
    manifest = "".join(f"ssh {ip} 22\n" for ip in hosts)
    scope = "".join(f"{ip}\n" for ip in hosts)
    admit = "".join(f"{ip}:22\n" for ip in hosts)
    stop = threading.Event()
    workers = 3

    class Blocking:
        def __init__(self):
            self.lock = threading.Lock()
            self.probes = []
            self.entered = threading.Event()
            self.release = threading.Event()
            self.max_inflight = 0
            self.inflight = 0

        def run(self, argv, timeout):
            if "-V" in argv or "--version" in argv:
                return nc.Completed(list(argv), 0, "ssh-audit 3.3.0", "", False, "t0", "t1")
            with self.lock:
                self.inflight += 1
                self.max_inflight = max(self.max_inflight, self.inflight)
                self.probes.append(argv[-1])
                if len(self.probes) >= workers:
                    self.entered.set()
            self.release.wait(5)
            with self.lock:
                self.inflight -= 1
            return nc.Completed(list(argv), 0, HARD, "", False, "t0", "t1")

    runner = Blocking()

    def watch():
        assert runner.entered.wait(5)
        stop.set()
        runner.release.set()

    threading.Thread(target=watch, daemon=True).start()
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        report = run(
            tmp, manifest, scope, admit,
            runner=runner,
            limits=nc.NarrowLimits(workers=workers, rate_interval=0),
            stop_event=stop,
        )
        assert len(runner.probes) == workers
        assert runner.max_inflight <= workers
        assert report["interrupted"] is True
        assert report["probe_accounting"]["probes_started"] == workers
        interrupted = [row for row in report["results"] if row["provenance"]["error"] == "interrupted before probe"]
        assert len(interrupted) == len(hosts) - workers
        assert all(row["status"] == "not_tested" for row in interrupted)
        assert all(row["status"] != "observed_no_weakness" for row in interrupted)
        assert (tmp / "out" / "narrow-checks.json").is_file()


def test_rate_gap_does_not_overshoot_and_partial_failure_keeps_other_rows():
    hosts = [f"203.0.113.{i}" for i in range(1, 5)]
    manifest = "".join(f"ssh {ip} 22\n" for ip in hosts)
    scope = "".join(f"{ip}\n" for ip in hosts)
    admit = "".join(f"{ip}:22\n" for ip in hosts)
    now = [0.0]
    slept = []

    def clock():
        return now[0]

    def sleeper(seconds):
        slept.append(seconds)
        now[0] += seconds

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner()
        report = run(
            tmp, manifest, scope, admit, runner=runner,
            limits=nc.NarrowLimits(workers=1, rate_interval=0.2),
            sleeper=sleeper, clock=clock,
        )
        assert len(runner.probes()) == 4
        assert abs(sum(slept) - 0.6) < 0.02
        assert len(slept) < 80
        assert report["probe_accounting"]["probes_started"] == 4
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner(raise_for=hosts[1])
        report = run(
            tmp, manifest, scope, admit, runner=runner,
            limits=nc.NarrowLimits(workers=2, rate_interval=0),
        )
        by_ip = {row["target"]["ip"]: row for row in report["results"]}
        assert len(by_ip) == 4
        assert "check failed" in by_ip[hosts[1]]["provenance"]["error"]
        assert by_ip[hosts[1]]["status"] == "error"
        assert by_ip[hosts[0]]["status"] == "observed_no_weakness"
        assert by_ip[hosts[2]]["status"] == "observed_no_weakness"


def test_unreachable_is_not_a_negative_and_timeouts_are_configurable():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = ScriptRunner(unreachable="Connection refused\n")
        report = run(
            tmp, f"ssh {IP} 22\n", f"{IP}\n", f"{IP}:22\n",
            runner=runner, limits=nc.NarrowLimits(rate_interval=0),
        )
        row = report["results"][0]
        assert row["status"] == "unreachable"
        assert row["status"] != "observed_no_weakness"
        assert row["remediation"]
    text = "\n".join([
        "(kex) curve25519-sha256 -- [info] available",
        "(mac) hmac-sha2-256 -- [info] available",
        "(enc) aes128-cbc -- [warn] using broken CBC mode",
        "(key) ssh-ed25519 -- [info] available",
    ])
    status, observations, _snippet, err = nc.parse_ssh_audit(text, 0, False)
    assert status == "lead", err
    assert status != "observed_no_weakness"
    warn = next(item for item in observations if item["id"] == "ssh-cipher-warn")
    assert warn["severity"] == "medium"
    assert "CBC" in warn["remediation"]

    class TimeoutRunner:
        def __init__(self):
            self.calls = []

        def run(self, argv, timeout):
            self.calls.append((list(argv), timeout))
            if "-V" in argv:
                return nc.Completed(list(argv), 0, "ssh-audit 3", "", False, "t0", "t1")
            return nc.Completed(list(argv), 0, HARD, "", False, "t0", "t1")

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        runner = TimeoutRunner()
        run(
            tmp, f"ssh {IP} 22\n", f"{IP}\n", f"{IP}:22\n",
            runner=runner,
            limits=nc.NarrowLimits(rate_interval=0, connect_timeout=7, host_timeout=15),
        )
        probe = next(item for item in runner.calls if "-V" not in item[0])
        assert probe[0][probe[0].index("-t") + 1] == "7"
        assert probe[1] == 15
        version = next(item for item in runner.calls if "-V" in item[0])
        assert version[1] == 10


def test_ssh_cipher_and_hostkey_and_tls_certificate_findings():
    text = "\n".join([
        "(kex) curve25519-sha256 -- [info] available",
        "(mac) hmac-sha2-256 -- [info] available",
        "(enc) 3des-cbc -- [fail] using broken 3DES cipher",
        "(enc) aes128-cbc -- [fail] using broken CBC mode",
        "(enc) arcfour -- [fail] using broken RC4 cipher",
        "(key) ssh-rsa -- [fail] using broken SHA-1 hash",
        "(key) ssh-dss -- [fail] using small 1024-bit modulus",
    ])
    status, observations, _snippet, err = nc.parse_ssh_audit(text, 3, False)
    assert status == "observed_weakness", err
    by_id = {item["id"]: item for item in observations if item["status"] == "observed_weakness"}
    assert "ssh-cipher" in by_id and "ssh-hostkey" in by_id
    assert by_id["ssh-cipher"]["severity"] == "high"
    assert "3DES-CBC" in by_id["ssh-cipher"]["remediation"]
    assert "arcfour" in by_id["ssh-cipher"]["remediation"]
    assert "ssh-ed25519" in by_id["ssh-hostkey"]["remediation"]
    covered = "\n".join([
        "(kex) curve25519-sha256 -- [info] available",
        "(mac) hmac-sha2-256 -- [info] available",
        "(enc) chacha20-poly1305@openssh.com -- [info] available",
        "(key) ssh-ed25519 -- [info] available",
    ])
    status, observations, _snippet, err = nc.parse_ssh_audit(covered, 0, False)
    assert status == "observed_no_weakness", err
    assert "enc line" in observations[0]["evidence"]

    def xml(extra):
        return f"""<document><ssltest>
<protocol type="ssl" version="2" enabled="0"/>
<protocol type="ssl" version="3" enabled="0"/>
<protocol type="tls" version="1.0" enabled="0"/>
<protocol type="tls" version="1.1" enabled="0"/>
<protocol type="tls" version="1.2" enabled="1"/>
<cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256"/>
<certificate>
<not-valid-after>Jan  1 00:00:00 2035 GMT</not-valid-after>
{extra}
</certificate>
</ssltest></document>"""

    status, observations, _snippet, err = nc.parse_tls_output(xml("<self-signed>true</self-signed>"), NOW)
    assert status == "observed_weakness", err
    finding = next(item for item in observations if item["id"] == "tls-cert-self-signed")
    assert finding["severity"] == "medium" and finding["remediation"]
    status, observations, _snippet, err = nc.parse_tls_output(
        xml('<pk type="rsaEncryption" bits="1024"/><signature-algorithm>md5WithRSAEncryption</signature-algorithm>'),
        NOW,
    )
    assert status == "observed_weakness"
    ids = {item["id"] for item in observations if item["status"] == "observed_weakness"}
    assert "tls-cert-key" in ids and "tls-cert-signature" in ids
    status, observations, _snippet, err = nc.parse_tls_output(
        xml("<signature-algorithm>sha1WithRSAEncryption</signature-algorithm>"), NOW,
    )
    sig = next(item for item in observations if item["id"] == "tls-cert-signature")
    assert sig["severity"] == "medium"
    status, _observations, _snippet, err = nc.parse_tls_output(
        xml('<pk type="rsaEncryption" bits="2048"/><signature-algorithm>sha256WithRSAEncryption</signature-algorithm>'),
        NOW,
    )
    assert status == "observed_no_weakness", err
    triple = xml("").replace("ECDHE-RSA-AES128-GCM-SHA256", "DES-CBC3-SHA")
    status, _observations, _snippet, err = nc.parse_tls_output(triple, NOW)
    assert status == "observed_no_weakness", err
    tls11 = xml("").replace('version="1.1" enabled="0"', 'version="1.1" enabled="1"')
    status, observations, _snippet, err = nc.parse_tls_output(tls11, NOW)
    assert status == "lead", err
    assert any(item["id"] == "tls-1.1" and item["severity"] == "low" for item in observations)


def test_signal_handler_and_subprocess_sigterm_drains_one_probe():
    stop = threading.Event()
    previous = nc._install_stop(stop)
    try:
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        assert stop.is_set()
    finally:
        nc._restore_stop(previous)

    guard = r"""
import os, socket
def _blocked(kind):
    def inner(*_a, **_k):
        raise OSError("network blocked: " + kind)
    return inner
socket.getaddrinfo = _blocked("getaddrinfo")
socket.create_connection = _blocked("create_connection")
socket.socket.connect = _blocked("connect")
"""
    mock = r"""#!/usr/bin/env python3
import os, sys, time
with open(os.environ["NARROW_TOOL_LOG"], "a", encoding="utf-8") as handle:
    handle.write("\t".join(sys.argv) + "\n")
    handle.flush()
if "-V" in sys.argv or "--version" in sys.argv:
    sys.stdout.write("ssh-audit 3.3.0\n")
    raise SystemExit(0)
time.sleep(1.2)
sys.stdout.write("(kex) curve25519-sha256 -- [info] available\n(mac) hmac-sha2-256 -- [info] available\n")
raise SystemExit(0)
"""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        guard_dir = tmp / "guard"
        guard_dir.mkdir()
        (guard_dir / "sitecustomize.py").write_text(guard)
        bindir = tmp / "bin"
        bindir.mkdir()
        tool = bindir / "ssh-audit"
        tool.write_text(mock)
        tool.chmod(0o755)
        hosts = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
        (tmp / "m.txt").write_text("".join(f"ssh {ip} 22\n" for ip in hosts))
        (tmp / "s.txt").write_text("".join(f"{ip}\n" for ip in hosts))
        (tmp / "a.txt").write_text("".join(f"{ip}:22\n" for ip in hosts))
        (tmp / "tool.log").write_text("")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(guard_dir) + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONNOUSERSITE"] = "1"
        env["PATH"] = str(bindir) + os.pathsep + "/usr/bin:/bin"
        env["NARROW_TOOL_LOG"] = str(tmp / "tool.log")
        out = tmp / "out"
        proc = subprocess.Popen(
            [
                sys.executable, str(ROOT / "external_recon_workflow.py"),
                "--narrow-checks", "--manifest", str(tmp / "m.txt"),
                "--scope-check", str(tmp / "s.txt"), "--admit", str(tmp / "a.txt"),
                "--authorized", "-o", str(out), "--narrow-workers", "1", "--narrow-rate", "0",
            ],
            cwd=str(tmp), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            text = (tmp / "tool.log").read_text(encoding="utf-8")
            if any("--skip-rate-test" in line for line in text.splitlines()):
                break
            time.sleep(0.05)
        else:
            proc.kill()
            raise AssertionError((tmp / "tool.log").read_text())
        os.kill(proc.pid, signal.SIGTERM)
        stdout, stderr = proc.communicate(timeout=15)
        assert proc.returncode == 130, (proc.returncode, stderr[-400:], stdout[-400:])
        log = (tmp / "tool.log").read_text(encoding="utf-8")
        assert log.count("--skip-rate-test") == 1
        report = json.loads((out / "narrow-checks.json").read_text())
        assert report["interrupted"] is True
        assert report["probe_accounting"]["probes_started"] == 1
        assert report["confirmed_exploit"] is False
        done = [row for row in report["results"] if row["status"] != "not_tested"]
        assert len(done) == 1
        assert done[0]["status"] == "observed_no_weakness"


def test_dry_run_subprocess_makes_no_socket():
    guard = r"""
import os, socket, subprocess, shutil
_log = os.environ.get("NARROW_GUARD_LOG", "")
def _note(kind, detail):
    if not _log:
        return
    with open(_log, "a", encoding="utf-8") as handle:
        handle.write(kind + "\t" + detail + "\n")
def _blocked(kind):
    def inner(*_a, **_k):
        _note("socket", kind)
        raise OSError("network blocked")
    return inner
socket.getaddrinfo = _blocked("getaddrinfo")
socket.create_connection = _blocked("create_connection")
socket.socket.connect = _blocked("connect")
_run = subprocess.run
def run(argv, *args, **kwargs):
    name = os.path.basename(str(argv[0])) if isinstance(argv, (list, tuple)) and argv else ""
    _note("run", name)
    raise OSError("refused " + name)
subprocess.run = run
"""
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        guard_dir = tmp / "guard"
        guard_dir.mkdir()
        (guard_dir / "sitecustomize.py").write_text(guard)
        (tmp / "guard.log").write_text("")
        (tmp / "m.txt").write_text("ssh 203.0.113.10 22\n")
        (tmp / "s.txt").write_text("203.0.113.0/28\nvpn.client.example\n")
        (tmp / "a.txt").write_text("203.0.113.10:22\n")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(guard_dir) + os.pathsep + env.get("PYTHONPATH", "")
        env["PYTHONNOUSERSITE"] = "1"
        env["NARROW_GUARD_LOG"] = str(tmp / "guard.log")
        out = tmp / "out"
        proc = subprocess.run(
            [
                "unshare", "-n", "-r", sys.executable, str(ROOT / "narrow_checks.py"),
                "--manifest", str(tmp / "m.txt"), "--scope-check", str(tmp / "s.txt"),
                "--admit", str(tmp / "a.txt"), "--authorized", "-o", str(out), "--dry-run",
                "--narrow-rate", "0",
            ],
            cwd=str(tmp), env=env, capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:], proc.stdout[-400:])
        payload = json.loads([line for line in proc.stdout.splitlines() if line.strip()][-1])
        assert payload["dry_run"] is True
        assert payload["expanded_count"] == 16
        assert "203.0.113.10" in payload["targets"]
        assert not out.exists()
        log = (tmp / "guard.log").read_text(encoding="utf-8")
        assert "socket\t" not in log
        assert "run\t" not in log


def main() -> int:
    tests = [
        test_load_narrow_scope_still_accepts_documentation_prefix_without_caps,
        test_slash_zero_and_broad_cidrs_fail_closed,
        test_address_cap_counts_prefix_legal_networks,
        test_malformed_scope_fails_before_resolver_or_directory,
        test_exclusion_and_plain_fqdn_do_not_authorize_outside_addresses,
        test_plus_authorizes_and_third_party_cname_does_not,
        test_dns_change_blocks_hostname_authorization_only,
        test_getaddrinfo_fallback_cannot_authorize_and_cname_walk_is_offline,
        test_dry_run_expands_without_network_or_directory,
        test_main_dry_run_and_rejects_recon_flags,
        test_probe_count_is_bounded_per_host_and_in_total,
        test_stop_does_not_start_past_the_in_flight_set,
        test_rate_gap_does_not_overshoot_and_partial_failure_keeps_other_rows,
        test_unreachable_is_not_a_negative_and_timeouts_are_configurable,
        test_ssh_cipher_and_hostkey_and_tls_certificate_findings,
        test_signal_handler_and_subprocess_sigterm_drains_one_probe,
        test_dry_run_subprocess_makes_no_socket,
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
    print(f"{len(tests) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
