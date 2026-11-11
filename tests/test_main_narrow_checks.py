#!/usr/bin/env python3
"""Main-command forwarding tests for admitted narrow checks. No sockets."""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import external_recon_workflow as hx  # noqa: E402
import narrow_checks as nc  # noqa: E402

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
WEAK = "203.0.113.10"
HARD = "203.0.113.11"

WEAK_SSH = "\n".join([
    "(kex) diffie-hellman-group1-sha1 -- [fail] using small 1024-bit modulus",
    "(kex) curve25519-sha256 -- [info] available",
    "(mac) hmac-sha1 -- [fail] using broken SHA-1",
    "(mac) hmac-sha2-256 -- [info] available",
])
HARD_SSH = "\n".join([
    "(kex) curve25519-sha256 -- [info] available",
    "(mac) hmac-sha2-256 -- [info] available",
])
LEAD_SSH = "\n".join([
    "(kex) diffie-hellman-group14-sha1 -- [warn] using weak hashing algorithm SHA-1",
    "(mac) hmac-sha2-256 -- [info] available",
])


class MapRunner:
    def __init__(self, by_ip, default_code=0, default_stdout="", timed_out=False):
        self.by_ip = by_ip
        self.default_code = default_code
        self.default_stdout = default_stdout
        self.timed_out = timed_out
        self.calls = []

    def run(self, argv, timeout):
        self.calls.append(list(argv))
        if "-V" in argv or "--version" in argv:
            return nc.Completed(list(argv), 0, "ssh-audit 3.3.0", "", False, "t0", "t1")
        spec = self.by_ip.get(argv[-1], {"stdout": self.default_stdout, "code": self.default_code, "timeout": self.timed_out})
        return nc.Completed(
            list(argv), spec["code"], spec["stdout"], "", spec.get("timeout", False), "t0", "t1",
        )


def write_pair(tmp: Path):
    manifest = tmp / "ssh-manifest.txt"
    scope = tmp / "ssh-scope.txt"
    admit = tmp / "ssh-admit.txt"
    manifest.write_text(f"ssh {WEAK} 22\nssh {HARD} 22\n")
    scope.write_text(f"{WEAK}\n{HARD}\n")
    admit.write_text(f"{WEAK}:22\n{HARD}:22\n")
    return manifest, scope, admit


def argv_for(out: Path, manifest, scope, admit, extra=None):
    base = [
        "--narrow-checks",
        "--manifest", str(manifest),
        "--scope-check", str(scope),
        "--admit", str(admit),
        "--authorized",
        "-o", str(out),
    ]
    if extra:
        base.extend(extra)
    return base


def test_main_forwards_two_ssh_rows_and_exit_3_is_a_finding():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_pair(tmp)
        out = tmp / "ssh-out"
        runner = MapRunner({
            WEAK: {"stdout": WEAK_SSH, "code": 3},
            HARD: {"stdout": HARD_SSH, "code": 0},
        })
        hx._NARROW_RUNNER = runner
        hx._NARROW_WHICH = lambda name: f"/usr/bin/{name}" if name == "ssh-audit" else None
        hx._NARROW_NOW = NOW
        try:
            code = hx.main(argv_for(out, manifest, scope, admit))
        finally:
            hx._NARROW_RUNNER = hx._NARROW_WHICH = hx._NARROW_NOW = None
        assert code == 0, code
        report = json.loads((out / "narrow-checks.json").read_text())
        assert report["confirmed_exploit"] is False
        assert report["refused"] is False
        by_ip = {row["target"]["ip"]: row for row in report["results"]}
        assert by_ip[WEAK]["status"] == "observed_weakness"
        assert by_ip[WEAK]["provenance"]["exit_code"] == 3
        assert by_ip[WEAK]["check_id"] == "ssh"
        assert by_ip[HARD]["status"] == "observed_no_weakness"
        assert by_ip[HARD]["provenance"]["exit_code"] == 0
        assert all(row["confirmed_exploit"] is False for row in report["results"])
        probes = [call for call in runner.calls if "-V" not in call]
        assert len(probes) == 2
        for call in probes:
            assert call[0].endswith("ssh-audit") or call[0] == "ssh-audit"
            assert "--dheat" not in call and "-c" not in call and "-T" not in call
            assert "ssh-auth-methods" not in call
        tools = {Path(call[0]).name for call in runner.calls}
        assert tools == {"ssh-audit"}


def test_lead_and_error_are_not_negatives():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest = tmp / "m.txt"
        scope = tmp / "s.txt"
        admit = tmp / "a.txt"
        manifest.write_text(f"ssh {WEAK} 22\n")
        scope.write_text(WEAK + "\n")
        admit.write_text(f"{WEAK}:22\n")
        out = tmp / "out"
        runner = MapRunner({WEAK: {"stdout": LEAD_SSH, "code": 0}})
        hx._NARROW_RUNNER = runner
        hx._NARROW_WHICH = lambda name: "/usr/bin/ssh-audit" if name == "ssh-audit" else None
        hx._NARROW_NOW = NOW
        try:
            code = hx.main(argv_for(out, manifest, scope, admit))
        finally:
            hx._NARROW_RUNNER = hx._NARROW_WHICH = hx._NARROW_NOW = None
        row = json.loads((out / "narrow-checks.json").read_text())["results"][0]
        assert code == 0
        assert row["status"] == "lead"
        assert row["status"] != "observed_no_weakness"

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest = tmp / "m.txt"
        scope = tmp / "s.txt"
        admit = tmp / "a.txt"
        manifest.write_text(f"ssh {WEAK} 22\n")
        scope.write_text(WEAK + "\n")
        admit.write_text(f"{WEAK}:22\n")
        out = tmp / "out"
        runner = MapRunner({}, default_stdout="(kex) curve25519-sha256 -- [info] only\n", default_code=3)
        hx._NARROW_RUNNER = runner
        hx._NARROW_WHICH = lambda name: "/usr/bin/ssh-audit" if name == "ssh-audit" else None
        hx._NARROW_NOW = NOW
        try:
            hx.main(argv_for(out, manifest, scope, admit))
        finally:
            hx._NARROW_RUNNER = hx._NARROW_WHICH = hx._NARROW_NOW = None
        row = json.loads((out / "narrow-checks.json").read_text())["results"][0]
        assert row["status"] == "error"
        assert row["status"] != "observed_no_weakness"
        assert row["status"] != "observed_weakness"


def test_quick_does_not_enable_narrow_and_combination_is_refused():
    args = hx.build_parser().parse_args(["-t", "targets.txt", "--quick", "--authorized"])
    assert args.narrow_checks is False
    assert args.quick is True
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_pair(tmp)
        out = tmp / "out"
        runner = MapRunner({})
        hx._NARROW_RUNNER = runner
        try:
            code = hx.main(argv_for(out, manifest, scope, admit, extra=["--quick"]))
        finally:
            hx._NARROW_RUNNER = None
        assert code == 2
        assert runner.calls == []
        assert not out.exists()


def test_refusals_create_no_directory_and_no_tool():
    cases = [
        ("ssh cdn.example 22\n", "203.0.113.10\n", "203.0.113.10:22\n"),
        ("ssh 198.51.100.5 22\n", "203.0.113.10\n", "203.0.113.10:22\n198.51.100.5:22\n"),
        ("ssh 203.0.113.10 2222\n", "203.0.113.10\n", "203.0.113.10:22\n"),
        ("ssh 203.0.113.10 22\nssh cdn.example 22\n", "203.0.113.10\n", "203.0.113.10:22\n"),
    ]
    for manifest_text, scope_text, admit_text in cases:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            manifest, scope, admit = tmp / "m.txt", tmp / "s.txt", tmp / "a.txt"
            manifest.write_text(manifest_text)
            scope.write_text(scope_text)
            admit.write_text(admit_text)
            out = tmp / "out"
            runner = MapRunner({})
            hx._NARROW_RUNNER = runner
            hx._NARROW_WHICH = lambda name: "/usr/bin/ssh-audit"
            try:
                code = hx.main(["--narrow-checks", "--manifest", str(manifest), "--scope-check", str(scope),
                                "--admit", str(admit), "--authorized", "-o", str(out)])
            finally:
                hx._NARROW_RUNNER = hx._NARROW_WHICH = None
            assert code == 2, (code, manifest_text)
            assert runner.calls == []
            assert not out.exists()


def test_explicit_defaults_noncanonical_scope_and_bad_admit():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_pair(tmp)
        out = tmp / "out"
        (out).mkdir()
        (out / "sentinel.txt").write_text("keep")
        runner = MapRunner({})
        hx._NARROW_RUNNER = runner
        hx._NARROW_WHICH = lambda name: "/usr/bin/ssh-audit"
        cases = [
            ["--phases", "all"],
            ["--threads", "8"],
            ["--timeout", "300"],
            ["--rate", "0"],
            ["--http-rate", "50"],
            ["--naabu-rate", "1000"],
            ["--max-cidr-hosts", "4096"],
            ["--alive-only"],
            ["--nmap-timing", "9"],
            ["--nuclei-severity", "high"],
            ["--wordlist", "missing-list"],
            ["--force"],
            ["--no-nuclei"],
            ["--no-direnum"],
            ["--phases=all"],
            ["--threads=8"],
        ]
        try:
            for extra in cases:
                code = hx.main(argv_for(out, manifest, scope, admit, extra=extra))
                assert code == 2, (extra, code)
                assert runner.calls == []
                assert (out / "sentinel.txt").read_text() == "keep"
                assert not (out / "narrow-checks.json").exists()
        finally:
            hx._NARROW_RUNNER = hx._NARROW_WHICH = None

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest = tmp / "m.txt"
        scope = tmp / "s.txt"
        admit = tmp / "a.txt"
        manifest.write_text(f"ssh {WEAK} 22\nssh 198.51.100.5 22\n")
        scope.write_text("203.0.113.10/0\n")
        admit.write_text(f"{WEAK}:22\n198.51.100.5:22\n")
        out = tmp / "out"
        runner = MapRunner({})
        hx._NARROW_RUNNER = runner
        try:
            code = hx.main(argv_for(out, manifest, scope, admit))
        finally:
            hx._NARROW_RUNNER = None
        assert code == 2
        assert runner.calls == []
        assert not out.exists()
        widened = hx.parse_network("203.0.113.10/0")
        assert str(widened) == "0.0.0.0/0"
        try:
            nc.load_narrow_scope(scope)
        except nc.NarrowInputError as exc:
            assert "203.0.113.10/0" in exc.message
        else:
            raise AssertionError("non-canonical scope was accepted")

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, _admit = write_pair(tmp)
        bad = tmp / "bad-admit.txt"
        bad.write_text(f"{WEAK}\n")
        out = tmp / "out"
        runner = MapRunner({})
        hx._NARROW_RUNNER = runner
        try:
            code = hx.main(argv_for(out, manifest, scope, bad))
        finally:
            hx._NARROW_RUNNER = None
        assert code == 2
        assert runner.calls == []
        assert not out.exists()


def test_unauthorized_main_exits_3():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest, scope, admit = write_pair(tmp)
        out = tmp / "out"
        code = hx.main(["--narrow-checks", "--manifest", str(manifest), "--scope-check", str(scope),
                        "--admit", str(admit), "-o", str(out)])
        assert code == 3
        assert not out.exists()


def main() -> int:
    tests = [
        test_main_forwards_two_ssh_rows_and_exit_3_is_a_finding,
        test_lead_and_error_are_not_negatives,
        test_quick_does_not_enable_narrow_and_combination_is_refused,
        test_refusals_create_no_directory_and_no_tool,
        test_explicit_defaults_noncanonical_scope_and_bad_admit,
        test_unauthorized_main_exits_3,
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
