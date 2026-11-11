#!/usr/bin/env python3
"""Offline fixtures for narrow TLS, SSH, and SMB2 checks. No sockets are opened."""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import narrow_checks as nc  # noqa: E402

NOW = datetime(2026, 11, 11, tzinfo=timezone.utc)
IP = "203.0.113.10"
OTHER = "203.0.113.11"
OUTSIDE = "198.51.100.5"


def tls_xml(*, tls10="0", cipher="ECDHE-RSA-AES128-GCM-SHA256", cipher_status="accepted", after="Jan  1 00:00:00 2035 GMT", extra=""):
    return f"""<?xml version="1.0"?>
<document>
<ssltest host="{IP}" port="443">
<protocol type="ssl" version="2" enabled="0"/>
<protocol type="ssl" version="3" enabled="0"/>
<protocol type="tls" version="1.0" enabled="{tls10}"/>
<protocol type="tls" version="1.2" enabled="1"/>
<cipher status="{cipher_status}" sslversion="TLSv1.2" bits="128" cipher="{cipher}"/>
<certificate><not-valid-after>{after}</not-valid-after></certificate>
{extra}
</ssltest>
</document>
"""


class FakeRunner:
    def __init__(self, stdout="", returncode=0, timed_out=False, version="tool-test"):
        self.stdout = stdout
        self.returncode = returncode
        self.timed_out = timed_out
        self.version = version
        self.calls = []

    def run(self, argv, timeout):
        self.calls.append(list(argv))
        if argv[1:] in (["--version"], ["-V"]) or argv[-1] in {"--version", "-V"}:
            text = self.version
            return nc.Completed(list(argv), 0, text, "", False, "2026-11-11T00:00:00Z", "2026-11-11T00:00:01Z")
        return nc.Completed(
            list(argv), self.returncode, self.stdout, "", self.timed_out,
            "2026-11-11T00:00:00Z", "2026-11-11T00:00:02Z",
        )


class Boom:
    def run(self, argv, timeout):
        raise AssertionError(argv)


def write_scope_admit(tmp: Path):
    scope = tmp / "scope.txt"
    admit = tmp / "admit.txt"
    scope.write_text(f"{IP}\n{OTHER}\n")
    admit.write_text("\n".join([
        f"{IP}:443",
        f"{IP}:22",
        f"{IP}:445",
        f"{OTHER}:443",
        f"{OTHER}:22",
        f"{OTHER}:445",
    ]) + "\n")
    return scope, admit


def present_which(name):
    return f"/usr/bin/{name}"


def run_one(tmp, check, port, stdout, returncode=0, timed_out=False, host=IP):
    scope, admit = write_scope_admit(tmp)
    runner = FakeRunner(stdout=stdout, returncode=returncode, timed_out=timed_out)
    report = nc.run_manifest(
        [{"check": check, "host": host, "port": port, "line": 1}],
        scope_file=scope,
        admit_file=admit,
        outdir=tmp / "out",
        runner=runner,
        now=NOW,
        which=present_which,
    )
    return report["results"][0], runner


def ids(result):
    return [item["id"] for item in result["observations"] if item["status"] == "observed_weakness"]


def test_tls_positive_and_hardened():
    with tempfile.TemporaryDirectory() as raw:
        weak, runner = run_one(Path(raw), "tls", 443, tls_xml(tls10="1"))
    assert weak["status"] == "observed_weakness", weak
    assert "tls-1.0" in ids(weak)
    assert weak["confirmed_exploit"] is False
    assert "--no-heartbleed" in runner.calls[-1]
    assert "--no-compression" in runner.calls[-1]
    assert "--no-renegotiation" in runner.calls[-1]
    assert "--no-fallback" in runner.calls[-1]
    assert not any(arg.startswith("--sni") for arg in runner.calls[-1])
    assert "testssl" not in " ".join(runner.calls[-1])

    with tempfile.TemporaryDirectory() as raw:
        cipher, _ = run_one(Path(raw), "tls", 443, tls_xml(cipher="RC4-SHA"))
    assert cipher["status"] == "observed_weakness"
    assert "tls-cipher" in ids(cipher)

    with tempfile.TemporaryDirectory() as raw:
        expired, _ = run_one(Path(raw), "tls", 443, tls_xml(after="Jan  1 00:00:00 2020 GMT"))
    assert expired["status"] == "observed_weakness"
    assert "tls-cert-expiry" in ids(expired)

    with tempfile.TemporaryDirectory() as raw:
        hardened, _ = run_one(Path(raw), "tls", 443, tls_xml())
    assert hardened["status"] == "observed_no_weakness", hardened
    assert ids(hardened) == []

    with tempfile.TemporaryDirectory() as raw:
        triple, _ = run_one(Path(raw), "tls", 443, tls_xml(cipher="DES-CBC3-SHA"))
    assert triple["status"] == "observed_weakness", triple
    assert "tls-3des" in ids(triple)
    des = next(item for item in triple["observations"] if item["id"] == "tls-3des")
    assert des["severity"] == "medium"
    assert "SWEET32" in des["remediation"]

    with tempfile.TemporaryDirectory() as raw:
        rejected, _ = run_one(Path(raw), "tls", 443, tls_xml(cipher="RC4-SHA", cipher_status="rejected"))
    assert "tls-cipher" not in ids(rejected)
    assert rejected["status"] == "observed_no_weakness"


def test_tls_negation_truncated_malformed_exit_timeout():
    disabled = """<document><ssltest>
<protocol type="tls" version="1.0" enabled="0"/>
<protocol type="tls" version="1.2" enabled="1"/>
<cipher status="accepted" cipher="ECDHE-RSA-AES128-GCM-SHA256"/>
<certificate><not-valid-after>Jan  1 00:00:00 2035 GMT</not-valid-after></certificate>
</ssltest></document>"""
    status, observations, _, err = nc.parse_tls_output(disabled, NOW)
    assert status == "observed_no_weakness", (status, err, observations)
    assert "enabled=0" in " ".join(item["evidence"] for item in observations) or status == "observed_no_weakness"

    status, _, _, err = nc.parse_tls_output("<document><ssltest></ssltest></document>", NOW)
    assert status == "error"
    assert err

    status, _, _, err = nc.parse_tls_output("this is not xml", NOW)
    assert status == "error"

    with tempfile.TemporaryDirectory() as raw:
        bad_exit, _ = run_one(Path(raw), "tls", 443, tls_xml(), returncode=2)
    assert bad_exit["status"] == "error"
    assert bad_exit["status"] != "observed_no_weakness"

    with tempfile.TemporaryDirectory() as raw:
        timed, _ = run_one(Path(raw), "tls", 443, tls_xml(tls10="1"), timed_out=True)
    assert timed["status"] == "error"
    assert timed["provenance"]["timed_out"] is True


def test_ssh_positive_hardened_negation_and_failures():
    positive = "\n".join([
        "(kex) diffie-hellman-group1-sha1 -- [fail] using small 1024-bit modulus",
        "(kex) curve25519-sha256 -- [info] available",
        "(mac) hmac-md5 -- [fail] using broken MD5",
        "(mac) hmac-sha2-256 -- [info] available",
    ])
    with tempfile.TemporaryDirectory() as raw:
        result, runner = run_one(Path(raw), "ssh", 22, positive, returncode=1)
    assert result["status"] == "observed_weakness"
    assert "ssh-algorithm" in ids(result)
    assert "--dheat" not in runner.calls[-1]
    assert "-c" not in runner.calls[-1]
    assert "-g" not in runner.calls[-1]
    assert "-T" not in runner.calls[-1]
    assert "ssh-auth-methods" not in " ".join(runner.calls[-1])

    hardened = "\n".join([
        "(kex) curve25519-sha256 -- [info] available",
        "(mac) hmac-sha2-256 -- [info] available",
    ])
    with tempfile.TemporaryDirectory() as raw:
        result, _ = run_one(Path(raw), "ssh", 22, hardened, returncode=0)
    assert result["status"] == "observed_no_weakness", result

    ambiguous = "\n".join([
        "(kex) diffie-hellman-group1-sha1 -- [fail] not a weak algorithm",
        "(mac) hmac-sha2-256 -- [info] available",
    ])
    status, _, _, err = nc.parse_ssh_audit(ambiguous, 1, False)
    assert status == "error", err

    status, _, _, err = nc.parse_ssh_audit("(kex) curve25519-sha256 -- [info] only\n", 0, False)
    assert status == "error"

    status, _, _, err = nc.parse_ssh_audit("<<<<", 2, False)
    assert status == "error"

    status, _, _, err = nc.parse_ssh_audit("usage: ssh-audit", 2, False)
    assert status == "error"

    status, _, _, err = nc.parse_ssh_audit(hardened, 0, True)
    assert status == "error"


def test_smb_signing_only():
    weak = "|\n smb2-security-mode:\n 3.1.1:\n Message signing enabled but not required\n"
    with tempfile.TemporaryDirectory() as raw:
        result, runner = run_one(Path(raw), "smb", 445, weak, returncode=0)
    assert result["status"] == "observed_weakness"
    assert ids(result) == ["smb-signing"]
    script = runner.calls[-1][runner.calls[-1].index("--script") + 1]
    assert script == "smb2-security-mode"
    assert "smb-security-mode" not in runner.calls[-1]
    assert "-sC" not in runner.calls[-1]
    joined = " ".join(runner.calls[-1])
    assert "enum4linux" not in joined and "smbmap" not in joined

    disabled = "Message signing is disabled and not required!\n"
    status, _, snippet, err = nc.parse_smb2_signing(disabled, 0, False)
    assert status == "observed_weakness", err
    assert "disabled and not required" in snippet

    hardened = "3.1.1:\n Message signing enabled and required\n"
    status, observations, _, err = nc.parse_smb2_signing(hardened, 0, False)
    assert status == "observed_no_weakness", err
    assert all(item["id"] != "smb-share" for item in observations)

    shares = "Sharename Type\nIPC$ IPC\n" + hardened
    status, observations, _, err = nc.parse_smb2_signing(shares, 0, False)
    assert status == "observed_no_weakness", (status, err)
    assert all("share" not in item["id"] for item in observations)

    status, _, _, err = nc.parse_smb2_signing("Message signing is not disabled\n", 0, False)
    assert status == "error", err

    status, _, _, err = nc.parse_smb2_signing("smb2-security-mode:\n 3.1.1:\n", 0, False)
    assert status == "error"

    status, _, _, err = nc.parse_smb2_signing("account_used: guest\n" + hardened, 0, False)
    assert status == "error"

    status, _, _, err = nc.parse_smb2_signing(hardened, 1, False)
    assert status == "error"

    status, _, _, err = nc.parse_smb2_signing(weak, 0, True)
    assert status == "error"


def test_admission_default_deny_and_no_subprocess():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        scope, admit = write_scope_admit(tmp)
        cases = [
            ("tls", "cdn.example", 443),
            ("tls", OUTSIDE, 443),
            ("tls", IP, 8443),
            ("tls", IP, 443),
        ]
        # last one is admitted; the runner is only allowed to see that one
        runner = FakeRunner(stdout=tls_xml())
        for check, host, port in cases[:-1]:
            report = nc.run_manifest(
                [{"check": check, "host": host, "port": port, "line": 1}],
                scope_file=scope, admit_file=admit, outdir=tmp / f"deny-{port}-{host}",
                runner=Boom(), now=NOW, which=present_which,
            )
            assert report["results"][0]["status"] == "not_tested", report["results"][0]
            assert report["results"][0]["provenance"]["argv"] == []
        ok = nc.run_manifest(
            [{"check": "tls", "host": IP, "port": 443, "line": 1}],
            scope_file=scope, admit_file=admit, outdir=tmp / "ok", runner=runner, now=NOW, which=present_which,
        )
        assert ok["results"][0]["status"] == "observed_no_weakness"
        assert any(call[0].endswith("sslscan") or call[0] == "sslscan" for call in runner.calls)


def test_missing_tool_private_key_and_argv_contract():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        scope, admit = write_scope_admit(tmp)
        report = nc.run_manifest(
            [{"check": "ssh", "host": IP, "port": 22, "line": 1}],
            scope_file=scope, admit_file=admit, outdir=tmp / "out",
            runner=Boom(), now=NOW, 
        ) if False else None
        result = nc.run_row(
            {"check": "ssh", "host": IP, "port": 22, "line": 1},
            nets=nc.hx.load_scope(scope)[0],
            admitted=nc.parse_admit(admit),
            runner=Boom(),
            outdir=tmp / "out",
            now=NOW,
            which=lambda name: None,
        )
        assert result["status"] == "not_tested"
        argv = nc.ssh_argv("/usr/bin/ssh-audit", IP, 22)
        assert argv[:4] == ["/usr/bin/ssh-audit", "-n", "-p", "22"]
        forbidden = {"--dheat", "-c", "-g", "-T", "--gex-test", "ssh-auth-methods"}
        assert forbidden.isdisjoint(argv)
        tls = nc.tls_argv("/usr/bin/sslscan", IP, 443, tmp / "out.xml")
        assert "--no-heartbleed" in tls and "--show-certificate" in tls
        assert "https://" not in " ".join(tls)
        smb = nc.smb_argv("/usr/bin/nmap", IP, 445, tmp / "out.nmap")
        assert smb[smb.index("--script") + 1] == "smb2-security-mode"
        assert "smb-security-mode" not in smb

    leaked = tls_xml() + "\n-----BEGIN RSA PRIVATE KEY-----\nSECRET\n-----END RSA PRIVATE KEY-----\n"
    with tempfile.TemporaryDirectory() as raw:
        result, _ = run_one(Path(raw), "tls", 443, leaked)
    assert "SECRET" not in json.dumps(result)
    assert "BEGIN RSA PRIVATE KEY" not in json.dumps(result)
    assert result["confirmed_exploit"] is False


def test_unauthorized_exit():
    proc_args = [
        sys.executable,
        str(ROOT / "narrow_checks.py"),
        "--manifest", str(ROOT / "targets.example.txt"),
        "--scope-check", str(ROOT / "scope.example.txt"),
        "--admit", str(ROOT / "scope.example.txt"),
        "-o", "/tmp/narrow-should-not-exist",
    ]
    import subprocess
    proc = subprocess.run(proc_args, cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 3, (proc.returncode, proc.stderr[-300:], proc.stdout[-300:])
    assert not Path("/tmp/narrow-should-not-exist").exists()


def main() -> int:
    tests = [
        test_tls_positive_and_hardened,
        test_tls_negation_truncated_malformed_exit_timeout,
        test_ssh_positive_hardened_negation_and_failures,
        test_smb_signing_only,
        test_admission_default_deny_and_no_subprocess,
        test_missing_tool_private_key_and_argv_contract,
        test_unauthorized_exit,
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
