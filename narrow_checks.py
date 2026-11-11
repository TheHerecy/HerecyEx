#!/usr/bin/env python3
"""IP-and-port checks for TLS config, SSH algorithms, and SMB2 signing.

This is not the all-phase recon workflow. It does not discover hosts, does not
follow redirects, and does not run nuclei, nikto, testssl, enum4linux, or smbmap.

A row runs only when the manifest names that check, that IP, and that port, and
the same IP is inside --scope-check and the same IP:port is in --admit.
Anything else is not_tested and no probe process is started.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from xml.etree import ElementTree

import external_recon_workflow as hx

CHECKS_VERSION = "1.0.1"
SCHEMA_VERSION = "1"

# Process budgets. sslscan's own --timeout and --connect-timeout are inside the process budget.
BUDGETS = {
    "tls": {"process_timeout": 90, "connect_timeout": 10, "socket_timeout": 5},
    "ssh": {"process_timeout": 30, "tool_timeout": 10},
    "smb": {"process_timeout": 45, "script_timeout": "20s"},
}

STATUSES = (
    "observed_weakness",
    "observed_no_weakness",
    "lead",
    "not_tested",
    "error",
)

# Exact smb2-security-mode sentences from nmap's script (negotiate response).
SMB_WEAK_SENTENCES = (
    "Message signing enabled but not required",
    "Message signing is disabled and not required",
    "Message signing is disabled",
)
SMB_REQUIRED_SENTENCE = "Message signing enabled and required"

WEAK_CIPHER = re.compile(
    r"(^NULL|NULL-|EXP-|EXPORT|RC4|^AECDH-|^ADH-|anon|-anon|DES-CBC-(?!3))",
    re.I,
)

PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.S,
)
SECRET_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|secret|community|smbpass|smbuser)\b\s*[:=]\s*\S+"
)


@dataclass
class Completed:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    started: str
    finished: str


class SubprocessRunner:
    """Real process runner. Tests inject a fake and never use this."""

    def run(self, argv: list[str], timeout: int) -> Completed:
        started = _now_iso()
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                errors="replace",
                check=False,
            )
            return Completed(
                argv=list(argv),
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                timed_out=False,
                started=started,
                finished=_now_iso(),
            )
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            return Completed(
                argv=list(argv),
                returncode=-1,
                stdout=out,
                stderr=err,
                timed_out=True,
                started=started,
                finished=_now_iso(),
            )
        except FileNotFoundError:
            return Completed(
                argv=list(argv),
                returncode=127,
                stdout="",
                stderr=f"not found: {argv[0]}",
                timed_out=False,
                started=started,
                finished=_now_iso(),
            )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(text: str) -> str:
    text = PRIVATE_KEY.sub("[redacted-private-key]", text)
    text = SECRET_ASSIGN.sub(lambda m: f"{m.group(1)}=[redacted]", text)
    return text


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class NarrowInputError(Exception):
    """Malformed scope or admit input. Callers turn this into exit 2."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def load_narrow_scope(path: Path) -> list:
    """Bare IPs and canonical CIDRs. Host bits are not masked.

    A bare IP is that host (/32 or /128). A CIDR is accepted only when
    ``ipaddress.ip_network(line, strict=True)`` accepts it, so the written
    address is already the network address. ``203.0.113.10/0`` and
    ``203.0.113.10/24`` are rejected. They are not rewritten to
    ``0.0.0.0/0`` or ``203.0.113.0/24``.

    The broad recon loader still uses strict=False. This function is only
    for narrow checks. A domain suffix is not a network and does not admit
    an address.
    """
    nets = []
    errors = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "/" in line:
            try:
                nets.append(ipaddress.ip_network(line, strict=True))
            except ValueError:
                errors.append(
                    f"line {lineno}: scope CIDR must be canonical (network address and prefix), not {line!r}"
                )
            continue
        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            continue
        nets.append(ipaddress.ip_network(ip))
    if errors:
        raise NarrowInputError(
            "scope file rejected; non-canonical CIDRs are not widened. " + "; ".join(errors)
        )
    return nets


def parse_admit(path: Path) -> set[tuple[str, int]]:
    """Exact ip:port admissions. A bare IP or a hostname is rejected."""
    admitted: set[tuple[str, int]] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        ip, port = _split_ip_port(line)
        if ip is None or port is None:
            raise NarrowInputError(f"admit line must be ip:port, not {line!r}")
        admitted.add((ip, port))
    return admitted


def _split_ip_port(text: str) -> tuple[Optional[str], Optional[int]]:
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if not rest.startswith(":"):
            return None, None
        port_s = rest[1:]
        ip = host
    else:
        if text.count(":") != 1:
            return None, None
        ip, port_s = text.rsplit(":", 1)
    if not hx.is_ip(ip):
        return None, None
    try:
        port = int(port_s)
    except ValueError:
        return None, None
    if port < 1 or port > 65535:
        return None, None
    return str(ipaddress.ip_address(ip)), port


def parse_manifest(path: Path) -> list[dict[str, Any]]:
    rows = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 3:
            rows.append({"line": lineno, "raw": line, "error": "manifest row must be: CHECK IP PORT"})
            continue
        check, host, port_s = parts
        try:
            port = int(port_s)
        except ValueError:
            port = None
        rows.append({
            "line": lineno,
            "check": check.strip().lower(),
            "host": host.strip(),
            "port": port,
            "raw": line,
        })
    return rows


def admission_block(host: str, port: Optional[int], nets: list, admitted: set[tuple[str, int]]) -> Optional[str]:
    """Return a reason to refuse, or None if this exact IP and port may be probed."""
    if port is None or not isinstance(port, int) or port < 1 or port > 65535:
        return "port is missing or not an integer 1-65535"
    if not hx.is_ip(host):
        return "hostname and non-IP targets are not admitted"
    ip = str(ipaddress.ip_address(host))
    if not nets or not hx.in_scope(ip, nets, []):
        return "IP is outside --scope-check"
    if (ip, port) not in admitted:
        return "IP:port is not in --admit (default deny)"
    return None


def tls_argv(binary: str, ip: str, port: int, xml_path: Path) -> list[str]:
    budget = BUDGETS["tls"]
    # Config handshakes only. Heartbleed, CRIME, renegotiation, and fallback checks are off.
    # No --sni-name, no --targets, no --pk, no STARTTLS, no --bugs.
    return [
        binary,
        "--no-colour",
        "--no-heartbleed",
        "--no-compression",
        "--no-renegotiation",
        "--no-fallback",
        "--no-groups",
        "--show-certificate",
        f"--connect-timeout={budget['connect_timeout']}",
        f"--timeout={budget['socket_timeout']}",
        f"--xml={xml_path}",
        f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}",
    ]


def ssh_argv(binary: str, ip: str, port: int) -> list[str]:
    # Algorithm audit only. No client listener, no DHEat, no GEX sweep, no target file.
    return [
        binary,
        "-n",
        "-p", str(port),
        "-t", str(BUDGETS["ssh"]["tool_timeout"]),
        "--skip-rate-test",
        ip,
    ]


def smb_argv(binary: str, ip: str, port: int, normal_path: Path) -> list[str]:
    # smb2-security-mode sends SMB2 negotiate and reads SecurityMode.
    # smb-security-mode is not used: it records account_used.
    return [
        binary,
        "-Pn",
        "-n",
        "-p", str(port),
        "--script", "smb2-security-mode",
        "--script-timeout", BUDGETS["smb"]["script_timeout"],
        "-oN", str(normal_path),
        ip,
    ]


def version_argv(check: str, binary: str) -> list[str]:
    if check == "tls":
        return [binary, "--version"]
    if check == "ssh":
        return [binary, "-V"]
    return [binary, "--version"]


def _result(
    check: str,
    ip: str,
    port: Optional[int],
    status: str,
    *,
    observations: Optional[list[dict[str, Any]]] = None,
    tool: str = "",
    tool_version: str = "",
    source_file: str = "",
    source_sha256: str = "",
    snippet: str = "",
    argv: Optional[list[str]] = None,
    started: str = "",
    finished: str = "",
    exit_code: Optional[int] = None,
    timed_out: bool = False,
    error: str = "",
    remediation: str = "",
    limitations: str = "",
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(status)
    return {
        "schema_version": SCHEMA_VERSION,
        "checks_version": CHECKS_VERSION,
        "check_id": check,
        "status": status,
        "confirmed_exploit": False,
        "target": {"ip": ip, "port": port, "transport": "tcp"},
        "observations": observations or [],
        "provenance": {
            "tool": tool,
            "tool_version": tool_version,
            "source_file": source_file,
            "source_sha256": source_sha256,
            "snippet": snippet[:1200],
            "argv": argv or [],
            "started": started,
            "finished": finished,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "error": error,
        },
        "remediation": remediation,
        "limitations": limitations,
    }


def _tls_overall(observations: list[dict[str, Any]]) -> str:
    """A real weakness is reported even if another subcheck is incomplete.

    Missing evidence never becomes observed_no_weakness.
    """
    statuses = [item["status"] for item in observations]
    if "observed_weakness" in statuses:
        return "observed_weakness"
    if "error" in statuses or not statuses:
        return "error"
    if "lead" in statuses:
        return "lead"
    if all(item == "observed_no_weakness" for item in statuses):
        return "observed_no_weakness"
    return "error"


def _worst(statuses: Iterable[str]) -> str:
    order = ["error", "not_tested", "observed_weakness", "lead", "observed_no_weakness"]
    present = set(statuses)
    for item in order:
        if item in present:
            return item
    return "error"


def parse_tls_output(xml_text: str, now: datetime) -> tuple[str, list[dict[str, Any]], str, str]:
    """Return status, observations, snippet, error. Incomplete XML is error, not a pass."""
    if not xml_text or not xml_text.strip():
        return "error", [], "", "sslscan XML is empty"
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError as exc:
        return "error", [], "", f"sslscan XML did not parse: {exc}"
    protocols = list(root.iter("protocol"))
    ciphers = list(root.iter("cipher"))
    expiries = list(root.iter("not-valid-after"))
    if not protocols:
        return "error", [], "", "sslscan XML has no protocol elements"
    observations: list[dict[str, Any]] = []
    snippet_lines: list[str] = []

    for proto in protocols:
        version = (proto.get("version") or "").strip()
        ptype = (proto.get("type") or "").strip().lower()
        enabled = (proto.get("enabled") or "").strip()
        line = f'{ptype} {version} enabled={enabled}'
        snippet_lines.append(line)
        if enabled not in {"0", "1"}:
            observations.append({
                "id": f"tls-protocol-{ptype}-{version}",
                "status": "error",
                "evidence": line,
                "remediation": "",
            })
            continue
        weak_version = (
            (ptype == "tls" and version == "1.0")
            or (ptype == "ssl" and version in {"2", "3"})
        )
        if enabled == "1" and weak_version:
            observations.append({
                "id": "tls-1.0" if version == "1.0" else f"tls-{ptype}{version}",
                "status": "observed_weakness",
                "evidence": line,
                "remediation": "Disable SSLv2, SSLv3, and TLS 1.0 on this listener.",
            })
        elif enabled == "1" and ptype == "tls" and version == "1.1":
            observations.append({
                "id": "tls-1.1",
                "status": "lead",
                "evidence": line,
                "remediation": "TLS 1.1 is deprecated. Prefer TLS 1.2 or 1.3.",
            })

    weak_ciphers = []
    for cipher in ciphers:
        status = (cipher.get("status") or "").lower()
        name = cipher.get("cipher") or ""
        if status not in {"accepted", "preferred"}:
            continue
        if WEAK_CIPHER.search(name):
            evidence = f'{status} {cipher.get("sslversion") or ""} {name}'.strip()
            weak_ciphers.append(evidence)
    if weak_ciphers:
        observations.append({
            "id": "tls-cipher",
            "status": "observed_weakness",
            "evidence": "; ".join(weak_ciphers[:8]),
            "remediation": "Disable NULL, anonymous, export, RC4, and single-DES cipher suites.",
        })
        snippet_lines.extend(weak_ciphers[:8])

    if not ciphers:
        observations.append({
            "id": "tls-cipher",
            "status": "error",
            "evidence": "",
            "remediation": "",
        })
    if not expiries or not (expiries[0].text or "").strip():
        observations.append({
            "id": "tls-cert-expiry",
            "status": "error",
            "evidence": "",
            "remediation": "",
        })
        return _tls_overall(observations), observations, "\n".join(snippet_lines), "certificate not-valid-after is missing"
    expiry_raw = expiries[0].text.strip()
    snippet_lines.append(f"not-valid-after {expiry_raw}")
    expiry = _parse_cert_date(expiry_raw)
    if expiry is None:
        observations.append({
            "id": "tls-cert-expiry",
            "status": "error",
            "evidence": expiry_raw,
            "remediation": "",
        })
        return _tls_overall(observations), observations, "\n".join(snippet_lines), f"unparsed certificate date: {expiry_raw}"
    if expiry <= now:
        observations.append({
            "id": "tls-cert-expiry",
            "status": "observed_weakness",
            "evidence": expiry_raw,
            "remediation": "Replace the expired certificate.",
        })
    else:
        observations.append({
            "id": "tls-cert-expiry",
            "status": "observed_no_weakness",
            "evidence": expiry_raw,
            "remediation": "",
        })

    if not any(item["id"] == "tls-cipher" for item in observations):
        observations.append({
            "id": "tls-cipher",
            "status": "observed_no_weakness",
            "evidence": f"{len(ciphers)} cipher element(s), no NULL/anonymous/export/RC4/single-DES accepted",
            "remediation": "",
        })
    if not any(item["status"] == "observed_weakness" and item["id"].startswith("tls-") and "cipher" not in item["id"] and "expiry" not in item["id"] for item in observations):
        if not any(item["status"] == "error" and item["id"].startswith("tls-protocol") for item in observations):
            observations.append({
                "id": "tls-protocol",
                "status": "observed_no_weakness",
                "evidence": "SSLv2, SSLv3, and TLS 1.0 are not enabled in the XML",
                "remediation": "",
            })
    return _tls_overall(observations), observations, "\n".join(snippet_lines)[:1200], ""


def _parse_cert_date(value: str) -> Optional[datetime]:
    text = re.sub(r"\s+", " ", value.strip())
    text = text.replace(" GMT", "").replace(" UTC", "")
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc)
    return None


def parse_ssh_audit(text: str, returncode: int, timed_out: bool) -> tuple[str, list[dict[str, Any]], str, str]:
    if timed_out:
        return "error", [], "", "ssh-audit timed out"
    if not text.strip():
        return "error" if returncode not in {None, 127} else "error", [], "", "ssh-audit produced no output"
    fails = []
    warns = []
    ambiguous = []
    kex_lines = 0
    mac_lines = 0
    for raw in text.splitlines():
        line = raw.strip()
        kind = None
        if "(kex)" in line:
            kind = "kex"
            kex_lines += 1
        elif "(mac)" in line:
            kind = "mac"
            mac_lines += 1
        if kind is None or "[fail]" not in line and "[warn]" not in line:
            continue
        note = line.split("[fail]", 1)[-1] if "[fail]" in line else line.split("[warn]", 1)[-1]
        if re.search(r"\bnot\b", note, re.I):
            ambiguous.append(line)
            continue
        if "[fail]" in line:
            fails.append(line)
        elif "[warn]" in line:
            warns.append(line)
    if ambiguous and not fails:
        return "error", [{
            "id": "ssh-ambiguous",
            "status": "error",
            "evidence": ambiguous[0][:400],
            "remediation": "",
        }], ambiguous[0][:400], "a [fail] or [warn] note contains 'not' and was not accepted as a weakness"
    if kex_lines < 1 or mac_lines < 1:
        return "error", [], "", "ssh-audit output has no complete (kex) and (mac) algorithm lines"
    observations = []
    if fails:
        observations.append({
            "id": "ssh-algorithm",
            "status": "observed_weakness",
            "evidence": "\n".join(fails[:12]),
            "remediation": "Remove the listed SSH key-exchange and MAC algorithms.",
        })
        status = "observed_weakness"
    elif warns:
        observations.append({
            "id": "ssh-algorithm-warn",
            "status": "lead",
            "evidence": "\n".join(warns[:12]),
            "remediation": "Review the warned SSH algorithms against the approved baseline.",
        })
        status = "lead"
    elif returncode not in {0, None}:
        return "error", [], "", f"ssh-audit exit {returncode} without a [fail] line is not a negative result"
    else:
        observations.append({
            "id": "ssh-algorithm",
            "status": "observed_no_weakness",
            "evidence": f"{kex_lines} kex line(s), {mac_lines} mac line(s), no [fail] or [warn]",
            "remediation": "",
        })
        status = "observed_no_weakness"
    snippet = "\n".join((fails or warns)[:12])
    return status, observations, snippet[:1200], ""


def parse_smb2_signing(text: str, returncode: int, timed_out: bool) -> tuple[str, list[dict[str, Any]], str, str]:
    if timed_out:
        return "error", [], "", "nmap smb2-security-mode timed out"
    if re.search(r"account_used\s*:", text, re.I):
        return "error", [{
            "id": "smb-session-identity",
            "status": "error",
            "evidence": "account_used appeared in the output",
            "remediation": "",
        }], "account_used", (
            "SMB output included account_used. smb-security-mode does that after smb.get_account. "
            "This check does not treat that as a signing result."
        )
    if re.search(r"\b(Sharename|IPC\$|guest)\b", text) and not any(s in text for s in SMB_WEAK_SENTENCES + (SMB_REQUIRED_SENTENCE,)):
        return "error", [], text[:200], "share, guest, or IPC text is not SMB signing evidence"
    weak = [sentence for sentence in SMB_WEAK_SENTENCES if sentence in text]
    required = SMB_REQUIRED_SENTENCE in text
    # "disabled and not required" also contains "disabled" as its own sentence prefix.
    if "Message signing is disabled and not required" in weak and "Message signing is disabled" in weak:
        weak = [s for s in weak if s != "Message signing is disabled"]
    if weak and required:
        return "error", [], "\n".join(weak + [SMB_REQUIRED_SENTENCE]), "contradictory SMB signing sentences"
    if weak:
        return "observed_weakness", [{
            "id": "smb-signing",
            "status": "observed_weakness",
            "evidence": weak[0],
            "remediation": "Require SMB2 signing on this listener.",
        }], weak[0], ""
    if required:
        if returncode not in {0, None}:
            return "error", [], SMB_REQUIRED_SENTENCE, f"nmap exit {returncode} with a signing sentence is not a negative result"
        return "observed_no_weakness", [{
            "id": "smb-signing",
            "status": "observed_no_weakness",
            "evidence": SMB_REQUIRED_SENTENCE,
            "remediation": "",
        }], SMB_REQUIRED_SENTENCE, ""
    if "not disabled" in text.lower() or "signing is not" in text.lower():
        return "error", [], text[:300], "negated signing wording is not a positive or a negative result"
    return "error", [], text[:300], "no exact smb2-security-mode signing sentence in the output"


SMB_LIMITATION = (
    "Only nmap --script smb2-security-mode is invoked, never with smb-brute, smb-os-discovery, "
    "smb-security-mode, enum4linux, or smbmap. smb.start calls smbauth.init_account, which only "
    "fills an in-memory anonymous/guest table, and may query NetBIOS. smb2.negotiate_v2 then "
    "sends SMB2_COM_NEGOTIATE only and stores SecurityMode. The script does not call "
    "start_session, tree_connect, or get_account. smb-security-mode is excluded because it "
    "calls get_account and prints account_used. smb-os-discovery is excluded because it "
    "opens an anonymous session. This was not run against Samba 4.25.0. Output that contains "
    "account_used is status error, not a signing result."
)

SSH_LIMITATION = (
    "ssh-audit is invoked as an algorithm audit: -n -p PORT -t SECONDS --skip-rate-test IP. "
    "It is not passed -c, --dheat, -g/--gex-test, -T, or any credential. "
    "ssh-auth-methods is not run. ssh-audit completes the SSH key exchange to read the "
    "algorithm lists; that is not a user login. [fail] on a (kex) or (mac) line is the weakness. "
    "A note containing the word 'not' is rejected."
)

TLS_LIMITATION = (
    "sslscan 2.1.5 flags used: --no-colour --no-heartbleed --no-compression --no-renegotiation "
    "--no-fallback --no-groups --show-certificate --connect-timeout=10 --timeout=5 --xml=FILE IP:PORT. "
    "Those --no-* switches are present in the rbsec sslscan 2.1.5 source. testssl is not invoked. "
    "No --sni-name is set. TLS 1.0, SSLv2, and SSLv3 enabled=1 in XML are weaknesses. TLS 1.1 is only a lead. "
    "Accepted NULL, anonymous, export, RC4, and single-DES suites are weaknesses; 3DES (DES-CBC3) is not. "
    "Certificate expiry uses not-valid-after against the checker clock. A missing or unparsed date is error. "
    "The terrifier OpenSSL is 3.6.5 with MinProtocol TLSv1.2, SECLEVEL 2, and SSL3 compiled out. "
    "This sslscan build may be unable to offer TLS 1.0 or SSLv3, so an offline XML fixture is not a live TLS 1.0 result."
)


def _tool_missing(check: str, binary: Optional[str], ip: str, port: int) -> dict[str, Any]:
    return _result(
        check, ip, port, "not_tested",
        error=f"{check} tool is not installed",
        limitations={"tls": TLS_LIMITATION, "ssh": SSH_LIMITATION, "smb": SMB_LIMITATION}[check],
        remediation="",
    )


def _finish_from_parse(
    check: str,
    ip: str,
    port: int,
    status: str,
    observations: list[dict[str, Any]],
    snippet: str,
    parse_error: str,
    completed: Completed,
    tool: str,
    tool_version: str,
    source: Path,
    limitations: str,
    remediation: str,
) -> dict[str, Any]:
    redacted = redact(completed.stdout)
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(redacted, encoding="utf-8")
    digest = sha256_text(redacted)
    if completed.timed_out:
        status = "error"
        parse_error = parse_error or "timed out"
    elif completed.returncode not in {0, None} and status == "observed_no_weakness":
        status = "error"
        parse_error = parse_error or f"exit {completed.returncode} is not a negative result"
    elif status == "error" and not parse_error:
        parse_error = "parse failed"
    if status == "observed_weakness":
        remediation = remediation or next(
            (item.get("remediation") or "" for item in observations if item.get("status") == "observed_weakness"),
            "",
        )
    else:
        remediation = "" if status != "lead" else remediation
    return _result(
        check, ip, port, status,
        observations=observations,
        tool=tool,
        tool_version=tool_version,
        source_file=str(source),
        source_sha256=digest,
        snippet=snippet,
        argv=completed.argv,
        started=completed.started,
        finished=completed.finished,
        exit_code=completed.returncode,
        timed_out=completed.timed_out,
        error=parse_error,
        remediation=remediation,
        limitations=limitations,
    )


def run_row(
    row: dict[str, Any],
    *,
    nets: list,
    admitted: set[tuple[str, int]],
    runner: Any,
    outdir: Path,
    now: datetime,
    which=shutil.which,
) -> dict[str, Any]:
    host = str(row.get("host") or "")
    port = row.get("port")
    check = str(row.get("check") or "")
    if row.get("error"):
        return _result(check or "unknown", host, port if isinstance(port, int) else None, "not_tested", error=row["error"])
    reason = admission_block(host, port if isinstance(port, int) else None, nets, admitted)
    if reason:
        return _result(check or "unknown", host, port if isinstance(port, int) else None, "not_tested", error=reason)
    if check not in {"tls", "ssh", "smb"}:
        return _result(check or "unknown", host, port, "not_tested", error=f"unsupported check {check}")
    ip = str(ipaddress.ip_address(host))
    port_i = int(port)
    binary_name = {"tls": "sslscan", "ssh": "ssh-audit", "smb": "nmap"}[check]
    binary = which(binary_name)
    if not binary:
        return _tool_missing(check, None, ip, port_i)
    art = outdir / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    safe_ip = ip.replace(":", "_")
    version_run = runner.run(version_argv(check, binary), 10)
    tool_version = redact((version_run.stdout or version_run.stderr or "").strip().splitlines()[0] if (version_run.stdout or version_run.stderr) else "")
    if version_run.timed_out:
        return _result(check, ip, port_i, "error", tool=binary_name, tool_version=tool_version, error="version command timed out", timed_out=True, argv=version_run.argv, exit_code=version_run.returncode, started=version_run.started, finished=version_run.finished)
    if check == "tls":
        xml_path = art / f"tls-{safe_ip}-{port_i}.xml"
        argv = tls_argv(binary, ip, port_i, xml_path)
        completed = runner.run(argv, BUDGETS["tls"]["process_timeout"])
        if xml_path.exists():
            xml_text = redact(xml_path.read_text(encoding="utf-8", errors="replace"))
        else:
            xml_text = redact(completed.stdout)
        status, observations, snippet, err = parse_tls_output(xml_text, now)
        if completed.timed_out:
            status, err = "error", "sslscan timed out"
        completed = Completed(
            completed.argv, completed.returncode, xml_text, completed.stderr,
            completed.timed_out, completed.started, completed.finished,
        )
        return _finish_from_parse(
            check, ip, port_i, status, observations, snippet, err, completed,
            "sslscan", tool_version or "unknown", art / f"tls-{safe_ip}-{port_i}.txt",
            TLS_LIMITATION, "",
        )
    if check == "ssh":
        argv = ssh_argv(binary, ip, port_i)
        completed = runner.run(argv, BUDGETS["ssh"]["process_timeout"])
        status, observations, snippet, err = parse_ssh_audit(redact(completed.stdout), completed.returncode, completed.timed_out)
        return _finish_from_parse(
            check, ip, port_i, status, observations, snippet, err, completed,
            "ssh-audit", tool_version or "unknown", art / f"ssh-{safe_ip}-{port_i}.txt",
            SSH_LIMITATION, "",
        )
    normal = art / f"smb-{safe_ip}-{port_i}.nmap"
    argv = smb_argv(binary, ip, port_i, normal)
    completed = runner.run(argv, BUDGETS["smb"]["process_timeout"])
    text = redact(completed.stdout)
    if normal.exists():
        file_text = redact(normal.read_text(encoding="utf-8", errors="replace"))
        if len(file_text) > len(text):
            text = file_text
    status, observations, snippet, err = parse_smb2_signing(text, completed.returncode, completed.timed_out)
    finished = _finish_from_parse(
        check, ip, port_i, status, observations, snippet, err,
        Completed(completed.argv, completed.returncode, text, completed.stderr, completed.timed_out, completed.started, completed.finished),
        "nmap", tool_version or "unknown", art / f"smb-{safe_ip}-{port_i}.txt",
        SMB_LIMITATION, "",
    )
    return finished


def refusal_reason(row: dict[str, Any], nets: list, admitted: set[tuple[str, int]]) -> Optional[str]:
    """None when this row may be probed. Any other string is a hard refusal."""
    if row.get("error"):
        return str(row["error"])
    host = str(row.get("host") or "")
    port = row.get("port")
    check = str(row.get("check") or "")
    reason = admission_block(host, port if isinstance(port, int) else None, nets, admitted)
    if reason:
        return reason
    if check not in {"tls", "ssh", "smb"}:
        return f"unsupported check {check}"
    return None


def run_manifest(
    rows: list[dict[str, Any]],
    *,
    scope_file: Path,
    admit_file: Path,
    outdir: Path,
    runner: Any = None,
    now: Optional[datetime] = None,
    which=shutil.which,
) -> dict[str, Any]:
    try:
        nets = load_narrow_scope(scope_file)
        admitted = parse_admit(admit_file)
    except NarrowInputError as exc:
        # No output directory and no tool. Bad admit used to raise SystemExit.
        return _refused_report([
            _result("unknown", "", None, "not_tested", error=exc.message),
        ], error=exc.message)
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    refusals = []
    if not rows:
        refusals.append(_result("unknown", "", None, "not_tested", error="manifest has no checks"))
    for row in rows:
        reason = refusal_reason(row, nets, admitted)
        if reason:
            host = str(row.get("host") or "")
            port = row.get("port") if isinstance(row.get("port"), int) else None
            refusals.append(_result(str(row.get("check") or "unknown"), host, port, "not_tested", error=reason))
    if refusals:
        # No output directory and no tool process. One bad row refuses the whole manifest.
        return _refused_report(refusals)
    outdir.mkdir(parents=True, exist_ok=True)
    active = runner or SubprocessRunner()
    results = [
        run_row(row, nets=nets, admitted=admitted, runner=active, outdir=outdir, now=clock, which=which)
        for row in rows
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "checks_version": CHECKS_VERSION,
        "generated": _now_iso(),
        "confirmed_exploit": False,
        "refused": False,
        "budgets": BUDGETS,
        "limitations": {
            "tls": TLS_LIMITATION,
            "ssh": SSH_LIMITATION,
            "smb": SMB_LIMITATION,
        },
        "results": results,
    }
    text = json.dumps(report, indent=2)
    (outdir / "narrow-checks.json").write_text(text, encoding="utf-8")
    return report


def _refused_report(results: list[dict[str, Any]], error: str = "") -> dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "checks_version": CHECKS_VERSION,
        "generated": _now_iso(),
        "confirmed_exploit": False,
        "refused": True,
        "budgets": BUDGETS,
        "limitations": {"tls": TLS_LIMITATION, "ssh": SSH_LIMITATION, "smb": SMB_LIMITATION},
        "results": results,
    }
    if error:
        report["error"] = error
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="narrow_checks.py",
        description=(
            "Run admitted TLS config, SSH algorithm, and SMB2 signing checks. "
            "IP and port must both be listed. Hostnames are refused. "
            "This does not run the all-phase recon workflow."
        ),
    )
    parser.add_argument("--manifest", required=True, help="Lines: tls|ssh|smb IP PORT")
    parser.add_argument(
        "--scope-check",
        required=True,
        help="Bare IPs and canonical CIDRs. A non-canonical CIDR such as 203.0.113.10/0 is rejected and is not widened.",
    )
    parser.add_argument("--admit", required=True, help="Exact ip:port lines. A bare IP is not enough.")
    parser.add_argument("-o", "--output", required=True, help="Output directory for narrow-checks.json and artifacts")
    parser.add_argument("--authorized", action="store_true", help="Confirm written authorization for every admitted socket")
    parser.add_argument("--version", action="version", version=f"narrow-checks {CHECKS_VERSION}")
    return parser


def confirm_authorized(flag: bool) -> bool:
    print(
        "narrow-checks is for authorized fixtures only. "
        "It connects to each admitted IP and port. It does not exploit."
    )
    if flag:
        print("Authorization recorded via --authorized.")
        return True
    if not sys.stdin.isatty():
        print("No TTY. Re-run with --authorized if you have written permission.", file=sys.stderr)
        return False
    try:
        answer = input("Type YES to continue: ").strip()
    except EOFError:
        return False
    return answer == "YES"


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not confirm_authorized(args.authorized):
        print("Aborted — authorization not confirmed.", file=sys.stderr)
        return 3
    manifest = Path(args.manifest)
    scope = Path(args.scope_check)
    admit = Path(args.admit)
    for path in (manifest, scope, admit):
        if not path.exists():
            print(f"missing file: {path}", file=sys.stderr)
            return 2
    rows = parse_manifest(manifest)
    outdir = Path(args.output).expanduser()
    report = run_manifest(rows, scope_file=scope, admit_file=admit, outdir=outdir)
    if report.get("refused"):
        if report.get("error"):
            print(f"refused: {report['error']}", file=sys.stderr)
        else:
            for row in report["results"]:
                print(
                    f"refused: {row.get('check_id')} {row.get('target')} {row['provenance']['error']}",
                    file=sys.stderr,
                )
        return 2
    counts: dict[str, int] = {}
    for row in report["results"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    # Exit 0 means the manifest was admitted. It is also the exit for a weakness.
    print(json.dumps({"output": str(outdir / "narrow-checks.json"), "counts": counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
