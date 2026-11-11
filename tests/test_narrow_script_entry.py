#!/usr/bin/env python3
"""Script-entry tests for --narrow-checks.

These start ``python3 external_recon_workflow.py`` and ``narrow_checks.py``.
They do not call ``main()`` with an injected runner. The child uses
``SubprocessRunner`` against a mock ``ssh-audit`` on PATH. ``unshare -n``
removes the network namespace, and a sitecustomize guard records socket and
tool calls. Documentation addresses only. No lab host is contacted.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import external_recon_workflow as hx  # noqa: E402
import narrow_checks as nc  # noqa: E402

WEAK = "203.0.113.10"
HARD = "203.0.113.11"
LEAD = "203.0.113.12"
ERR = "203.0.113.13"
OUTSIDE = "198.51.100.5"

ALLOWED = {
    "--narrow-checks",
    "--manifest",
    "--scope-check",
    "--admit",
    "--authorized",
    "--output",
    "-o",
    "--help",
    "-h",
    "--version",
    # Narrow-only controls. Recon flags such as --threads and --rate stay refused.
    "--dry-run",
    "--narrow-workers",
    "--narrow-rate",
    "--narrow-connect-timeout",
    "--narrow-host-timeout",
    "--narrow-min-prefix-v4",
    "--narrow-min-prefix-v6",
    "--narrow-max-addresses",
    "--narrow-allow-broad-cidr",
}

GUARD = r"""
import os, socket, subprocess, shutil, threading, urllib.request
_log_path = os.environ.get("NARROW_GUARD_LOG", "")
_log_lock = threading.Lock()

def _log(kind, detail):
    if not _log_path:
        return
    # Narrow runs are concurrent. One locked append keeps each record on its own line.
    with _log_lock:
        with open(_log_path, "a", encoding="utf-8") as handle:
            handle.write(kind + "\t" + detail.replace("\n", " ") + "\n")

def _blocked(kind):
    def inner(*_args, **_kwargs):
        _log("socket", kind)
        raise OSError("network blocked: " + kind)
    return inner

socket.getaddrinfo = _blocked("getaddrinfo")
socket.create_connection = _blocked("create_connection")
socket.socket.connect = _blocked("connect")
socket.socket.connect_ex = _blocked("connect_ex")
socket.socket.sendto = _blocked("sendto")
urllib.request.urlopen = _blocked("urlopen")

_run = subprocess.run
_popen = subprocess.Popen
_which = shutil.which

def _name(argv):
    if isinstance(argv, (list, tuple)) and argv:
        return os.path.basename(str(argv[0]))
    if isinstance(argv, str):
        return os.path.basename(argv)
    return ""

def run(argv, *args, **kwargs):
    name = _name(argv)
    _log("run", "%s\t%s\t%s" % (name, kwargs.get("timeout"), list(argv)))
    if name != "ssh-audit":
        _log("refused-tool", name)
        raise OSError("guard refused tool: " + name)
    return _run(argv, *args, **kwargs)

def popen(argv, *args, **kwargs):
    name = _name(argv)
    _log("popen", name)
    if name != "ssh-audit":
        _log("refused-tool", name)
        raise OSError("guard refused tool: " + name)
    return _popen(argv, *args, **kwargs)

def which(cmd, *args, **kwargs):
    _log("which", str(cmd))
    return _which(cmd, *args, **kwargs)

subprocess.run = run
subprocess.Popen = popen
shutil.which = which
"""

MOCK = r"""#!/usr/bin/env python3
import json, os, sys
ip = sys.argv[-1]
with open(os.environ["NARROW_TOOL_LOG"], "a", encoding="utf-8") as handle:
    handle.write("\t".join(sys.argv) + "\n")
if "-V" in sys.argv or "--version" in sys.argv:
    sys.stdout.write("ssh-audit 3.3.0\n")
    raise SystemExit(0)
table = json.loads(os.environ["NARROW_SSH_TABLE"])
spec = table[ip]
sys.stdout.write(spec["stdout"])
raise SystemExit(int(spec["code"]))
"""

WEAK_OUT = "\n".join([
    "# MOCK-SSH-AUDIT",
    "(kex) diffie-hellman-group1-sha1 -- [fail] using small 1024-bit modulus",
    "(kex) curve25519-sha256 -- [info] available",
    "(mac) hmac-sha1 -- [fail] using broken SHA-1",
    "(mac) hmac-sha2-256 -- [info] available",
    "",
])
HARD_OUT = "\n".join([
    "# MOCK-SSH-AUDIT",
    "(kex) curve25519-sha256 -- [info] available",
    "(mac) hmac-sha2-256 -- [info] available",
    "",
])
LEAD_OUT = "\n".join([
    "# MOCK-SSH-AUDIT",
    "(kex) diffie-hellman-group14-sha1 -- [warn] using weak hashing algorithm SHA-1",
    "(mac) hmac-sha2-256 -- [info] available",
    "",
])
INFO_OUT = HARD_OUT


def write_guard(tmp: Path) -> Path:
    guard = tmp / "guard"
    guard.mkdir(exist_ok=True)
    (guard / "sitecustomize.py").write_text(GUARD)
    return guard


def write_mock(tmp: Path) -> Path:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    tool = bindir / "ssh-audit"
    tool.write_text(MOCK)
    tool.chmod(0o755)
    return bindir


def table_for(mapping: dict[str, tuple[str, int]]) -> str:
    return json.dumps({ip: {"stdout": text, "code": code} for ip, (text, code) in mapping.items()})


def child_env(tmp: Path, table: str) -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if "proxy" in key.lower():
            env.pop(key)
    guard = write_guard(tmp)
    bindir = write_mock(tmp)
    env["PYTHONPATH"] = str(guard) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONNOUSERSITE"] = "1"
    env["PATH"] = str(bindir) + os.pathsep + "/usr/bin:/bin"
    env["NARROW_GUARD_LOG"] = str(tmp / "guard.log")
    env["NARROW_TOOL_LOG"] = str(tmp / "tool.log")
    env["NARROW_SSH_TABLE"] = table
    env["HOME"] = str(tmp / "home")
    (tmp / "home").mkdir(exist_ok=True)
    (tmp / "guard.log").write_text("")
    (tmp / "tool.log").write_text("")
    return env


def run_entry(script: Path, args: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    cmd = ["unshare", "-n", "-r", sys.executable, str(script), *args]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        timeout=40,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def log_text(tmp: Path) -> str:
    return (tmp / "guard.log").read_text(encoding="utf-8")


def assert_quiet(tmp: Path, proc: subprocess.CompletedProcess) -> None:
    text = log_text(tmp)
    assert "socket\t" not in text, text
    assert "refused-tool" not in text, text
    assert proc.stderr.find("Traceback") < 0, proc.stderr[-500:]


def base_files(tmp: Path, manifest: str, scope: str, admit: str):
    (tmp / "m.txt").write_text(manifest)
    (tmp / "s.txt").write_text(scope)
    (tmp / "a.txt").write_text(admit)
    return tmp / "m.txt", tmp / "s.txt", tmp / "a.txt"


def narrow_args(tmp: Path, out: Path, extra: Optional[list[str]] = None) -> list[str]:
    args = [
        "--narrow-checks",
        "--manifest", str(tmp / "m.txt"),
        "--scope-check", str(tmp / "s.txt"),
        "--admit", str(tmp / "a.txt"),
        "--authorized",
        "-o", str(out),
    ]
    if extra:
        args.extend(extra)
    return args


def test_broad_loader_still_widens_and_narrow_loader_rejects():
    assert str(hx.parse_network("203.0.113.10/0")) == "0.0.0.0/0"
    assert str(hx.parse_network("203.0.113.10/24")) == "203.0.113.0/24"
    with tempfile.TemporaryDirectory() as raw:
        scope = Path(raw) / "scope.txt"
        scope.write_text("203.0.113.10/0\n203.0.113.10\n")
        nets, _domains = hx.load_scope(scope)
        assert any(str(net) == "0.0.0.0/0" for net in nets)
        try:
            nc.load_narrow_scope(scope)
        except nc.NarrowInputError as exc:
            assert "203.0.113.10/0" in exc.message
            assert "0.0.0.0/0" not in exc.message
        else:
            raise AssertionError("narrow loader accepted a non-canonical CIDR")
        canonical = Path(raw) / "canonical.txt"
        canonical.write_text("203.0.113.0/24\n203.0.113.10\n2001:db8::/32\n")
        loaded = nc.load_narrow_scope(canonical)
        assert {str(net) for net in loaded} == {"203.0.113.0/24", "203.0.113.10/32", "2001:db8::/32"}
        hostbits = Path(raw) / "hostbits.txt"
        hostbits.write_text("2001:db8::1/32\n")
        try:
            nc.load_narrow_scope(hostbits)
        except nc.NarrowInputError as exc:
            assert "2001:db8::1/32" in exc.message
        else:
            raise AssertionError("IPv6 host bits were widened")


def test_script_two_status_classes_use_real_runner():
    mapping = {
        WEAK: (WEAK_OUT, 3),
        HARD: (HARD_OUT, 0),
        LEAD: (LEAD_OUT, 3),
        ERR: (INFO_OUT, 3),
    }
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        manifest = "\n".join([
            f"ssh {WEAK} 22",
            f"ssh {HARD} 22",
            f"ssh {LEAD} 22",
            f"ssh {ERR} 22",
            "",
        ])
        scope = "\n".join([WEAK, HARD, LEAD, ERR, ""])
        admit = "\n".join(f"{ip}:22" for ip in (WEAK, HARD, LEAD, ERR)) + "\n"
        base_files(tmp, manifest, scope, admit)
        out = tmp / "ssh-out"
        env = child_env(tmp, table_for(mapping))
        proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out), tmp, env)
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, (proc.returncode, proc.stderr[-800:], proc.stdout[-800:])
        report = json.loads((out / "narrow-checks.json").read_text())
        assert report["refused"] is False
        assert report["confirmed_exploit"] is False
        assert report["budgets"]["ssh"] == {"process_timeout": 30, "tool_timeout": 10}
        by_ip = {row["target"]["ip"]: row for row in report["results"]}
        assert by_ip[WEAK]["status"] == "observed_weakness"
        assert by_ip[WEAK]["provenance"]["exit_code"] == 3
        assert by_ip[HARD]["status"] == "observed_no_weakness"
        assert by_ip[HARD]["provenance"]["exit_code"] == 0
        assert by_ip[LEAD]["status"] == "lead"
        assert by_ip[LEAD]["status"] != "observed_no_weakness"
        assert by_ip[ERR]["status"] == "error"
        assert "without a [fail] line" in by_ip[ERR]["provenance"]["error"]
        assert by_ip[ERR]["status"] != "observed_no_weakness"
        assert all(row["confirmed_exploit"] is False for row in report["results"])
        for ip, row in by_ip.items():
            argv = row["provenance"]["argv"]
            assert argv[1:] == ["-n", "-p", "22", "-t", "10", "--skip-rate-test", ip], argv
            assert Path(argv[0]).name == "ssh-audit"
            artifact = out / "artifacts" / f"ssh-{ip}-22.txt"
            assert "MOCK-SSH-AUDIT" in artifact.read_text(encoding="utf-8")
        assert not (out / "run-meta.json").exists()
        guard = log_text(tmp)
        which_names = [line.split("\t", 1)[1] for line in guard.splitlines() if line.startswith("which\t")]
        assert which_names == ["ssh-audit"] * 4, which_names
        runs = [line for line in guard.splitlines() if line.startswith("run\t")]
        assert len(runs) == 8, runs
        timeouts = sorted({int(line.split("\t")[2]) for line in runs})
        assert timeouts == [10, 30], runs
        assert all(line.split("\t")[1] == "ssh-audit" for line in runs)
        tool_log = (tmp / "tool.log").read_text(encoding="utf-8")
        assert tool_log.count("ssh-audit") == 8
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        payload = json.loads(lines[-1])
        assert payload["mode"] == "narrow-checks"
        assert payload["confirmed_exploit"] is False
        assert payload["counts"]["observed_weakness"] == 1
        assert payload["counts"]["observed_no_weakness"] == 1
        assert payload["counts"]["lead"] == 1
        assert payload["counts"]["error"] == 1
        assert "Authorization confirmed" in proc.stdout or "Authorized assessments only" in proc.stdout


def test_canonical_cidr_is_kept_and_noncanonical_is_refused():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", "203.0.113.0/24\n", f"{WEAK}:22\n")
        out = tmp / "out"
        env = child_env(tmp, table_for({WEAK: (HARD_OUT, 0)}))
        proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out), tmp, env)
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, proc.stderr[-400:]
        row = json.loads((out / "narrow-checks.json").read_text())["results"][0]
        assert row["status"] == "observed_no_weakness"
        assert row["target"]["ip"] == WEAK

    for bad_scope in ("203.0.113.10/0\n", "203.0.113.10/24\n"):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            base_files(
                tmp,
                f"ssh {WEAK} 22\nssh {OUTSIDE} 22\n",
                bad_scope,
                f"{WEAK}:22\n{OUTSIDE}:22\n",
            )
            out = tmp / "out"
            out.mkdir()
            (out / "sentinel.txt").write_text("keep")
            env = child_env(tmp, table_for({WEAK: (HARD_OUT, 0), OUTSIDE: (HARD_OUT, 0)}))
            proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out), tmp, env)
            assert_quiet(tmp, proc)
            assert proc.returncode == 2, (bad_scope, proc.returncode, proc.stderr[-400:])
            assert "non-canonical" in proc.stderr
            assert bad_scope.strip() in proc.stderr
            assert "which\t" not in log_text(tmp)
            assert "run\t" not in log_text(tmp)
            assert (out / "sentinel.txt").read_text() == "keep"
            assert not (out / "narrow-checks.json").exists()
            assert not (tmp / "tool.log").read_text()


def test_whole_manifest_and_bad_admit_exit_2():
    cases = {
        "hostname": ("ssh 203.0.113.10 22\nssh cdn.example 22\n", "203.0.113.10\n", "203.0.113.10:22\n", "hostname"),
        "domain-scope": ("ssh 203.0.113.10 22\n", "example.com\n", "203.0.113.10:22\n", "outside --scope-check"),
        "bare-admit": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.10\n", "admit line must be ip:port"),
        "host-admit": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.10:22\ncdn.example:443\n", "cdn.example:443"),
        "port-0": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.10:0\n", "203.0.113.10:0"),
        "port-high": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.10:65536\n", "65536"),
        "port-neg": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.10:-1\n", "-1"),
        "leading-zero": ("ssh 203.0.113.10 22\n", "203.0.113.10\n", "203.0.113.010:22\n", "203.0.113.010:22"),
    }
    for name, (manifest, scope, admit, needle) in cases.items():
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            base_files(tmp, manifest, scope, admit)
            out = tmp / "out"
            out.mkdir()
            (out / "sentinel.txt").write_text("keep")
            env = child_env(tmp, table_for({WEAK: (HARD_OUT, 0)}))
            proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out), tmp, env)
            assert_quiet(tmp, proc)
            assert proc.returncode == 2, (name, proc.returncode, proc.stderr[-400:])
            assert "refused:" in proc.stderr
            assert needle in proc.stderr, (name, proc.stderr[-400:])
            assert "which\t" not in log_text(tmp)
            assert "run\t" not in log_text(tmp)
            assert (out / "sentinel.txt").read_text() == "keep"
            assert not (out / "narrow-checks.json").exists()


def option_invocation(option: str, action: argparse.Action) -> list[str]:
    if action.nargs == 0 or isinstance(action, argparse._StoreTrueAction):
        return [option]
    if action.dest == "nmap_timing":
        value = "9"
    elif action.dest == "nuclei_severity":
        value = "high"
    elif action.dest in {"wordlist", "resume", "targets"}:
        value = "missing-file"
    elif action.default not in (None, argparse.SUPPRESS):
        value = str(action.default)
    else:
        value = "explicit"
    return [option, value]


def test_every_other_flag_including_explicit_defaults_is_refused():
    parser = hx.build_parser()
    seen = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\nssh {HARD} 22\n", f"{WEAK}\n{HARD}\n", f"{WEAK}:22\n{HARD}:22\n")
        out = tmp / "out"
        out.mkdir()
        (out / "sentinel.txt").write_text("keep")
        for action in parser._actions:
            for option in action.option_strings:
                if option in ALLOWED:
                    continue
                extra = option_invocation(option, action)
                env = child_env(tmp, table_for({WEAK: (WEAK_OUT, 3), HARD: (HARD_OUT, 0)}))
                proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out, extra), tmp, env)
                assert proc.returncode == 2, (extra, proc.returncode, proc.stderr[-500:], proc.stdout[-300:])
                assert "Refusing" in proc.stderr, (extra, proc.stderr[-400:])
                assert option in proc.stderr, (extra, proc.stderr[-400:])
                assert "Authorization confirmed" not in proc.stdout
                assert "Authorized assessments only" not in proc.stdout
                assert "which\t" not in log_text(tmp), (extra, log_text(tmp))
                assert "run\t" not in log_text(tmp), extra
                assert "socket\t" not in log_text(tmp), extra
                assert (out / "sentinel.txt").read_text() == "keep"
                assert not (out / "narrow-checks.json").exists()
                seen.append(option)
        equals = [
            "--phases=all",
            "--threads=8",
            "--timeout=300",
            "--rate=0",
            "--http-rate=50",
            "--naabu-rate=1000",
            "--max-cidr-hosts=4096",
            "--nmap-timing=9",
        ]
        for extra_flag in equals:
            env = child_env(tmp, table_for({WEAK: (WEAK_OUT, 3), HARD: (HARD_OUT, 0)}))
            proc = run_entry(
                ROOT / "external_recon_workflow.py",
                narrow_args(tmp, out, [extra_flag]),
                tmp,
                env,
            )
            assert proc.returncode == 2, (extra_flag, proc.returncode, proc.stderr[-300:])
            assert "Refusing" in proc.stderr
            assert "which\t" not in log_text(tmp)
            assert "run\t" not in log_text(tmp)
        # One command carrying the recon flags the previous gate missed, at explicit defaults.
        combined = [
            "--alive-only",
            "--nmap-timing", "9",
            "--http-rate", "50",
            "--naabu-rate", "1000",
            "--nuclei-severity", "high",
            "--wordlist", "missing-list",
            "--force",
            "--no-nuclei",
            "--no-direnum",
            "--threads", "8",
            "--rate", "0",
            "--timeout", "300",
            "--max-cidr-hosts", "4096",
            "--phases", "all",
        ]
        env = child_env(tmp, table_for({WEAK: (WEAK_OUT, 3), HARD: (HARD_OUT, 0)}))
        proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out, combined), tmp, env)
        assert proc.returncode == 2, proc.stderr[-400:]
        assert "Refusing" in proc.stderr
        for flag in ("--alive-only", "--nmap-timing", "--http-rate", "--naabu-rate", "--nuclei-severity",
                     "--wordlist", "--force", "--threads", "--phases"):
            assert flag in proc.stderr
        assert "which\t" not in log_text(tmp)
        assert "run\t" not in log_text(tmp)
        assert (out / "sentinel.txt").read_text() == "keep"
    assert "--alive-only" in seen
    assert "--nmap-timing" in seen
    assert "--http-rate" in seen
    assert "--naabu-rate" in seen
    assert "--nuclei-severity" in seen
    assert "--wordlist" in seen
    assert "--force" in seen
    assert "--threads" in seen
    assert "--phases" in seen
    assert "--quick" in seen
    assert "--full" in seen


def test_default_output_tilde_and_missing_tool():
    mapping = table_for({WEAK: (HARD_OUT, 0)})
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", f"{WEAK}\n", f"{WEAK}:22\n")
        env = child_env(tmp, mapping)
        args = [
            "--narrow-checks",
            "--manifest", str(tmp / "m.txt"),
            "--scope-check", str(tmp / "s.txt"),
            "--admit", str(tmp / "a.txt"),
            "--authorized",
        ]
        proc = run_entry(ROOT / "external_recon_workflow.py", args, tmp, env)
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, proc.stderr[-400:]
        assert (tmp / "results" / "narrow-checks.json").is_file()
        children = sorted(path.name for path in (tmp / "results").iterdir())
        assert children == ["artifacts", "narrow-checks.json"], children
        payload = json.loads([line for line in proc.stdout.splitlines() if line.strip()][-1])
        assert payload["output"] == "results/narrow-checks.json"
        assert not (tmp / "run-meta.json").exists()

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", f"{WEAK}\n", f"{WEAK}:22\n")
        env = child_env(tmp, mapping)
        proc = run_entry(
            ROOT / "external_recon_workflow.py",
            narrow_args(tmp, Path("~/ssh-out")),
            tmp,
            env,
        )
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, proc.stderr[-400:]
        assert (tmp / "home" / "ssh-out" / "narrow-checks.json").is_file()
        assert not (tmp / "~").exists()

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", f"{WEAK}\n", f"{WEAK}:22\n")
        out = tmp / "out"
        env = child_env(tmp, mapping)
        env["PATH"] = "/usr/bin:/bin"
        proc = run_entry(ROOT / "external_recon_workflow.py", narrow_args(tmp, out), tmp, env)
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:], proc.stdout[-400:])
        row = json.loads((out / "narrow-checks.json").read_text())["results"][0]
        assert row["status"] == "not_tested"
        assert row["status"] != "observed_no_weakness"
        assert "which\tssh-audit" in log_text(tmp)
        assert "run\t" not in log_text(tmp)


def test_standalone_script_matches_and_bad_admit_is_exit_2():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\nssh {HARD} 22\n", f"{WEAK}\n{HARD}\n", f"{WEAK}:22\n{HARD}:22\n")
        out = tmp / "standalone-out"
        env = child_env(tmp, table_for({WEAK: (WEAK_OUT, 3), HARD: (HARD_OUT, 0)}))
        proc = run_entry(
            ROOT / "narrow_checks.py",
            ["--manifest", str(tmp / "m.txt"), "--scope-check", str(tmp / "s.txt"),
             "--admit", str(tmp / "a.txt"), "--authorized", "-o", str(out)],
            tmp,
            env,
        )
        assert_quiet(tmp, proc)
        assert proc.returncode == 0, proc.stderr[-400:]
        report = json.loads((out / "narrow-checks.json").read_text())
        by_ip = {row["target"]["ip"]: row for row in report["results"]}
        assert by_ip[WEAK]["status"] == "observed_weakness"
        assert by_ip[HARD]["status"] == "observed_no_weakness"
        assert by_ip[WEAK]["provenance"]["argv"][1:] == ["-n", "-p", "22", "-t", "10", "--skip-rate-test", WEAK]
        payload = json.loads([line for line in proc.stdout.splitlines() if line.strip()][-1])
        assert "mode" not in payload
        assert payload["counts"]["observed_weakness"] == 1
        assert "MOCK-SSH-AUDIT" in (out / "artifacts" / f"ssh-{WEAK}-22.txt").read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", f"{WEAK}\n", f"{WEAK}\n")
        out = tmp / "out"
        env = child_env(tmp, table_for({WEAK: (HARD_OUT, 0)}))
        proc = run_entry(
            ROOT / "narrow_checks.py",
            ["--manifest", str(tmp / "m.txt"), "--scope-check", str(tmp / "s.txt"),
             "--admit", str(tmp / "a.txt"), "--authorized", "-o", str(out)],
            tmp,
            env,
        )
        assert proc.returncode == 2, (proc.returncode, proc.stderr[-400:])
        assert "refused:" in proc.stderr
        assert "admit line must be ip:port" in proc.stderr
        assert "Traceback" not in proc.stderr
        assert not out.exists()
        assert "which\t" not in log_text(tmp)
        assert "run\t" not in log_text(tmp)


def test_unauthorized_script_exits_3():
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_files(tmp, f"ssh {WEAK} 22\n", f"{WEAK}\n", f"{WEAK}:22\n")
        out = tmp / "out"
        env = child_env(tmp, table_for({WEAK: (HARD_OUT, 0)}))
        args = [
            "--narrow-checks",
            "--manifest", str(tmp / "m.txt"),
            "--scope-check", str(tmp / "s.txt"),
            "--admit", str(tmp / "a.txt"),
            "-o", str(out),
        ]
        proc = run_entry(ROOT / "external_recon_workflow.py", args, tmp, env)
        assert proc.returncode == 3, (proc.returncode, proc.stderr[-300:], proc.stdout[-300:])
        assert not out.exists()
        assert "which\t" not in log_text(tmp)
        assert "run\t" not in log_text(tmp)
        assert "socket\t" not in log_text(tmp)


def main() -> int:
    tests = [
        test_broad_loader_still_widens_and_narrow_loader_rejects,
        test_script_two_status_classes_use_real_runner,
        test_canonical_cidr_is_kept_and_noncanonical_is_refused,
        test_whole_manifest_and_bad_admit_exit_2,
        test_every_other_flag_including_explicit_defaults_is_refused,
        test_default_output_tilde_and_missing_tool,
        test_standalone_script_matches_and_bad_admit_is_exit_2,
        test_unauthorized_script_exits_3,
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
