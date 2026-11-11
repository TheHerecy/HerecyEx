#!/usr/bin/env python3
"""Admitted TLS, SSH algorithm, and SMB2 signing checks.

This is not the all-phase recon workflow. It does not discover hosts, does not
follow redirects, and does not run nuclei, nikto, testssl, enum4linux, or smbmap.

A row runs only when the manifest names that check, that IP, and that port, the
IP is inside the explicit scope (or a fresh hostname authorization), and the
same IP:port is in --admit. Anything else is not_tested and no probe process
is started. A plain hostname never authorizes an address. See DNS_POLICY.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from xml.etree import ElementTree

import external_recon_workflow as hx

CHECKS_VERSION = "1.2.0"
SCHEMA_VERSION = "1"

# Canonical policy text copied into every report. README summarizes the same rules.
DNS_POLICY = (
    "A plain FQDN in the narrow scope is resolved and recorded. It does not authorize any address. "
    "An address is probed only when the manifest names that IP, --admit lists that IP:port, and the IP "
    "is inside an included bare IP or canonical CIDR and is not excluded. "
    "A leading '+' on an FQDN authorizes that name's current A and AAAA answers. A plain A or AAAA "
    "with no CNAME is authorized even when the address is shared infrastructure; prefer an explicit "
    "IP or CIDR for those names. A CNAME whose registrable domain differs is third-party, including "
    "CDNs and SaaS, and is flagged and not probed. "
    "A leading '++' is the explicit per-name override that authorizes the current answers even across "
    "a third-party CNAME. Exclusions still win. 0.0.0.0/0 and ::/0 are never accepted. "
    "Immediately before a probe that '+' or '++' authorized, the name is resolved again. If the address "
    "is no longer present, the lookup fails, or a '+' name has become a third-party CNAME, the row is "
    "error and no probe is started. "
    "A DNS change does not cancel an explicit IP or CIDR authorization; the new answers are only recorded. "
    "A resolver that cannot show the CNAME chain (the getaddrinfo fallback) cannot satisfy '+' or '++'; "
    "those names are flagged cname_chain_unknown. "
    "Registrable domain is the workflow eTLD+1 table (co.uk, com.au, co.jp, and the other two-part "
    "suffixes in that table), not the full Public Suffix List. A suffix that is not in the table uses "
    "the last two labels. "
    "--dry-run does not resolve and does not contact the network."
)

SCOPE_POLICY = (
    "Narrow scope accepts a bare IP, a canonical CIDR, an FQDN, '!' exclusions of those, "
    "'+FQDN' hostname authorization, and '++FQDN' third-party CNAME override. "
    "A domain suffix does not admit other names or any address. "
    "0.0.0.0/0 and ::/0 are refused outright, including as exclusions and with --narrow-allow-broad-cidr. "
    "Other CIDRs must already be the network address. The default prefix floor is /24 for IPv4 and /120 "
    "for IPv6. The default total is 1024 addresses. Duplicate included networks are de-duplicated, then "
    "their sizes are summed. Exclusions do not reduce that total. "
    "--narrow-allow-broad-cidr lifts only the prefix floor. The total cap still applies. "
    "Malformed lines fail closed before tools, the output directory, and network contact."
)

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
    "unreachable",
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


@dataclass
class NarrowLimits:
    """Caps for one narrow run. Defaults are the CLI defaults."""

    workers: int = 2
    rate_interval: float = 0.2
    connect_timeout: int = 10
    host_timeout: int = 0
    min_prefix_v4: int = 24
    min_prefix_v6: int = 120
    max_addresses: int = 1024
    allow_broad_cidr: bool = False

    def validate(self) -> None:
        if self.workers < 1:
            raise NarrowInputError("--narrow-workers must be an integer >= 1")
        if self.rate_interval < 0:
            raise NarrowInputError("--narrow-rate must be >= 0")
        if self.connect_timeout < 1:
            raise NarrowInputError("--narrow-connect-timeout must be an integer >= 1")
        if self.host_timeout < 0:
            raise NarrowInputError("--narrow-host-timeout must be >= 0 (0 keeps the per-check budget)")
        if self.min_prefix_v4 < 0 or self.min_prefix_v4 > 32:
            raise NarrowInputError("--narrow-min-prefix-v4 must be an integer 0-32")
        if self.min_prefix_v6 < 0 or self.min_prefix_v6 > 128:
            raise NarrowInputError("--narrow-min-prefix-v6 must be an integer 0-128")
        if self.max_addresses < 1:
            raise NarrowInputError("--narrow-max-addresses must be an integer >= 1")


@dataclass(frozen=True)
class ScopeName:
    name: str
    mode: str  # record, authorize, authorize-third-party, exclude


@dataclass
class NarrowScope:
    networks: list = field(default_factory=list)
    excluded_nets: list = field(default_factory=list)
    names: list = field(default_factory=list)


_FQDN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_UNREACHABLE = re.compile(
    r"(connection refused|no route to host|network is unreachable|host(?: is)? unreachable|"
    r"could not connect|connection timed out|connection reset by peer|timed out connecting|"
    r"no address associated|name or service not known)",
    re.IGNORECASE,
)


def _scope_error(errors: list[str]) -> None:
    noncanon = any("must be canonical" in item for item in errors)
    prefix = (
        "scope file rejected; non-canonical CIDRs are not widened. "
        if noncanon
        else "scope file rejected. "
    )
    raise NarrowInputError(prefix + "; ".join(errors))


def _is_fqdn(value: str) -> bool:
    return bool(_FQDN.match(value))


def _looks_like_ip_token(value: str) -> bool:
    if ":" in value:
        return True
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _prefix_floor(net: ipaddress._BaseNetwork, limits: NarrowLimits) -> int:
    return limits.min_prefix_v4 if net.version == 4 else limits.min_prefix_v6


def parse_narrow_scope(
    path: Path,
    limits: Optional[NarrowLimits] = None,
) -> NarrowScope:
    """Parse a narrow scope file. Fail closed on malformed, forbidden, or over-broad lines.

    Prefix floors and the address cap always apply. There is no uncapped entry point.
    ``/0`` is refused even when the prefix floor is lifted.
    """
    limits = limits or NarrowLimits()
    limits.validate()
    includes: list = []
    excludes: list = []
    names: list[ScopeName] = []
    seen_nets: set = set()
    seen_names: set[str] = set()
    errors: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        mode = "include"
        body = line
        if line.startswith("++"):
            mode = "authorize-third-party"
            body = line[2:].strip()
        elif line.startswith("+"):
            mode = "authorize"
            body = line[1:].strip()
        elif line.startswith("!"):
            mode = "exclude"
            body = line[1:].strip()
        if not body:
            errors.append(f"line {lineno}: malformed scope entry {line!r}")
            continue
        body = body.rstrip(".")
        slash = "/" in body
        if mode in {"authorize", "authorize-third-party"} and (slash or _looks_like_ip_token(body)):
            errors.append(f"line {lineno}: hostname authorization applies to an FQDN, not {line!r}")
            continue
        # Numeric addresses also match the FQDN grammar, so IP tokens are parsed first.
        if slash or _looks_like_ip_token(body):
            if slash:
                try:
                    net = ipaddress.ip_network(body, strict=True)
                except ValueError:
                    errors.append(
                        f"line {lineno}: scope CIDR must be canonical (network address and prefix), not {line!r}"
                    )
                    continue
            else:
                try:
                    net = ipaddress.ip_network(ipaddress.ip_address(body))
                except ValueError:
                    errors.append(f"line {lineno}: malformed scope entry {line!r}")
                    continue
            if net.prefixlen == 0:
                errors.append(f"line {lineno}: prefix /0 is refused outright ({line!r})")
                continue
            if not limits.allow_broad_cidr and net.prefixlen < _prefix_floor(net, limits):
                floor = _prefix_floor(net, limits)
                errors.append(
                    f"line {lineno}: CIDR {line!r} is broader than the /{floor} prefix floor; "
                    "pass --narrow-allow-broad-cidr to override the floor "
                    "(the address cap and /0 refusal still apply)"
                )
                continue
            if net in seen_nets and mode == "include":
                continue
            if mode == "exclude":
                excludes.append(net)
            else:
                seen_nets.add(net)
                includes.append(net)
            continue
        if not _is_fqdn(body):
            errors.append(f"line {lineno}: malformed scope entry {line!r}")
            continue
        fqdn = body.lower()
        if fqdn in seen_names:
            errors.append(f"line {lineno}: duplicate scope hostname {fqdn!r}")
            continue
        seen_names.add(fqdn)
        name_mode = {
            "include": "record",
            "exclude": "exclude",
            "authorize": "authorize",
            "authorize-third-party": "authorize-third-party",
        }[mode]
        names.append(ScopeName(fqdn, name_mode))
    if errors:
        _scope_error(errors)
    total = 0
    for net in includes:
        total += int(net.num_addresses)
        if total > limits.max_addresses:
            raise NarrowInputError(
                "scope file rejected. "
                f"included networks sum to at least {total} addresses, over "
                f"--narrow-max-addresses {limits.max_addresses}"
            )
    return NarrowScope(networks=includes, excluded_nets=excludes, names=names)


def load_narrow_scope(path: Path, limits: Optional[NarrowLimits] = None) -> list:
    """Included networks from a narrow scope file, with the same caps as a run.

    A bare IP is that host (/32 or /128). A CIDR is accepted only when
    ``ipaddress.ip_network(line, strict=True)`` accepts it, so the written
    address is already the network address. ``203.0.113.10/0`` and
    ``203.0.113.10/24`` are rejected. They are not rewritten to
    ``0.0.0.0/0`` or ``203.0.113.0/24``. ``0.0.0.0/0`` and ``::/0`` are refused.
    The default prefix floor and address cap apply. Pass ``limits`` only to use
    the same explicit override a run would use (``--narrow-allow-broad-cidr``
    still cannot admit ``/0``, and the address cap still applies).

    The broad recon loader still uses strict=False. A domain suffix is not a
    network and does not admit an address. Valid FQDNs are kept by the parser
    and are not part of this network list.
    """
    return parse_narrow_scope(path, limits).networks


def _unique_ips(values: Iterable[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for value in values:
        try:
            text = str(ipaddress.ip_address(str(value).split("%", 1)[0]))
        except ValueError:
            continue
        if text not in seen:
            seen.add(text)
            found.append(text)
    return found


def registrable_domain(name: str) -> str:
    """eTLD+1 from the workflow suffix table, including co.uk and com.au.

    This is not the full Public Suffix List. A suffix absent from that table
    falls back to the last two labels.
    """
    return hx.registrable_domain(name)


def cname_is_third_party(query: str, cnames: Iterable[str]) -> bool:
    home = registrable_domain(query)
    return any(registrable_domain(target) != home for target in cnames if target)


def _addr_in(addr: ipaddress._BaseAddress, nets: list) -> bool:
    return any(addr in net for net in nets)


def expand_scope_targets(scope: NarrowScope) -> list[str]:
    """In-scope addresses after exclusions. Caller has already enforced the cap."""
    found: set = set()
    for net in scope.networks:
        for addr in net:
            if _addr_in(addr, scope.excluded_nets):
                continue
            found.add(addr)
    return [str(addr) for addr in sorted(found, key=lambda item: (item.version, item))]


def _call_resolver(resolver: Callable[[str], dict[str, Any]], name: str) -> dict[str, Any]:
    try:
        raw = resolver(name) or {}
    except Exception as exc:
        raw = {"error": f"{type(exc).__name__}: {exc}"}
    a = _unique_ips(raw.get("a") or [])
    aaaa = _unique_ips(raw.get("aaaa") or [])
    cnames = [str(item).rstrip(".").lower() for item in (raw.get("cnames") or []) if str(item).strip()]
    return {
        "name": name,
        "queried_at": str(raw.get("queried_at") or _now_iso()),
        "a": a,
        "aaaa": aaaa,
        "cnames": cnames,
        "cname_unknown": bool(raw.get("cname_unknown")),
        "error": str(raw.get("error") or ""),
    }


def classify_resolution(entry: ScopeName, raw: dict[str, Any], scope: NarrowScope) -> dict[str, Any]:
    """Apply DNS_POLICY. A plain name never sets authorizes."""
    item = dict(raw)
    item["name"] = entry.name
    item["mode"] = entry.mode
    item["authorizes"] = False
    item["outside"] = []
    if entry.mode == "exclude":
        item["flagged"] = "excluded"
        return item
    if item.get("error"):
        item["flagged"] = "resolution_error"
        return item
    third = cname_is_third_party(entry.name, item.get("cnames") or [])
    if item.get("cname_unknown") and entry.mode in {"authorize", "authorize-third-party"}:
        item["flagged"] = "cname_chain_unknown"
        return item
    if third and entry.mode != "authorize-third-party":
        item["flagged"] = "third_party_cname"
        addresses = []
        for ip in list(item.get("a") or []) + list(item.get("aaaa") or []):
            addr = ipaddress.ip_address(ip)
            if not _addr_in(addr, scope.networks) or _addr_in(addr, scope.excluded_nets):
                addresses.append(ip)
        item["outside"] = addresses
        return item
    addresses = list(item.get("a") or []) + list(item.get("aaaa") or [])
    if not addresses:
        item["flagged"] = "no_records"
        return item
    outside = []
    usable = []
    for ip in addresses:
        addr = ipaddress.ip_address(ip)
        if _addr_in(addr, scope.excluded_nets) or not _addr_in(addr, scope.networks):
            outside.append(ip)
        else:
            usable.append(ip)
    item["outside"] = outside
    if entry.mode == "record":
        item["flagged"] = "outside_explicit_scope" if outside else ""
        return item
    if not usable and outside and all(_addr_in(ipaddress.ip_address(ip), scope.excluded_nets) for ip in outside):
        item["flagged"] = "excluded"
        return item
    item["authorizes"] = True
    item["flagged"] = "third_party_override" if third else ""
    return item


def resolve_scope_names(
    scope: NarrowScope,
    resolver: Callable[[str], dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for entry in scope.names:
        if entry.mode == "exclude":
            results.append({
                "name": entry.name,
                "mode": entry.mode,
                "queried_at": "",
                "a": [],
                "aaaa": [],
                "cnames": [],
                "cname_unknown": False,
                "error": "",
                "authorizes": False,
                "outside": [],
                "flagged": "excluded",
            })
            continue
        raw = _call_resolver(resolver, entry.name)
        results.append(classify_resolution(entry, raw, scope))
    return results


def _name_for(item: dict[str, Any]) -> ScopeName:
    return ScopeName(str(item["name"]), str(item.get("mode") or "record"))


def address_authorized(ip: str, scope: NarrowScope, resolutions: Optional[list[dict[str, Any]]]) -> bool:
    addr = ipaddress.ip_address(ip)
    if _addr_in(addr, scope.excluded_nets):
        return False
    if _addr_in(addr, scope.networks):
        return True
    wanted = str(addr)
    for item in resolutions or []:
        if not item.get("authorizes"):
            continue
        if wanted in set(item.get("a") or []) or wanted in set(item.get("aaaa") or []):
            return True
    return False


def _resolve_with_query(name: str, query: Callable[[str, str], list[str]]) -> dict[str, Any]:
    """Walk CNAMEs, then collect A and AAAA. ``query`` raises LookupError on NXDOMAIN."""
    stamp = _now_iso()
    cnames: list[str] = []
    seen = {name.rstrip(".").lower()}
    current = name
    error = ""
    for _hop in range(8):
        try:
            answers = query(current, "CNAME")
        except LookupError as exc:
            error = str(exc) or "nxdomain"
            break
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            break
        if not answers:
            break
        target = str(answers[0]).rstrip(".").lower()
        if not target or target in seen:
            break
        cnames.append(target)
        seen.add(target)
        current = target
    a: list[str] = []
    aaaa: list[str] = []
    if not error:
        for rtype, bucket in (("A", a), ("AAAA", aaaa)):
            try:
                bucket.extend(query(name, rtype))
            except LookupError as exc:
                if not a and not aaaa and rtype == "AAAA":
                    error = str(exc) or "nxdomain"
            except Exception as exc:
                if not error:
                    error = f"{rtype}:{type(exc).__name__}: {exc}"
    return {
        "a": _unique_ips(a),
        "aaaa": _unique_ips(aaaa),
        "cnames": cnames,
        "cname_unknown": False,
        "error": "" if (a or aaaa) else error,
        "queried_at": stamp,
    }


def _resolve_getaddrinfo(name: str, getaddrinfo: Optional[Callable[..., Any]] = None) -> dict[str, Any]:
    lookup = getaddrinfo or socket.getaddrinfo
    stamp = _now_iso()
    try:
        infos = lookup(name, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return {
            "a": [],
            "aaaa": [],
            "cnames": [],
            "cname_unknown": True,
            "error": str(exc),
            "queried_at": stamp,
        }
    a: list[str] = []
    aaaa: list[str] = []
    for family, _socktype, _proto, _canon, sockaddr in infos:
        text = str(sockaddr[0]).split("%", 1)[0]
        if family == socket.AF_INET:
            a.append(text)
        elif family == socket.AF_INET6:
            aaaa.append(text)
    return {
        "a": _unique_ips(a),
        "aaaa": _unique_ips(aaaa),
        "cnames": [],
        "cname_unknown": True,
        "error": "",
        "queried_at": stamp,
    }


def _dnspython_query(name: str, rtype: str) -> list[str]:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answers = resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN as exc:
        raise LookupError("nxdomain") from exc
    except dns.resolver.NoAnswer:
        return []
    except dns.exception.DNSException as exc:
        raise RuntimeError(str(exc)) from exc
    values = []
    for rr in answers:
        text = str(getattr(rr, "target", rr)).rstrip(".")
        values.append(text)
    return values


def default_resolver(name: str) -> dict[str, Any]:
    """dnspython when it is installed, otherwise getaddrinfo (no CNAME chain)."""
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return _resolve_getaddrinfo(name)
    return _resolve_with_query(name, _dnspython_query)


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


def admission_block(
    host: str,
    port: Optional[int],
    nets: list,
    admitted: set[tuple[str, int]],
    scope: Optional[NarrowScope] = None,
    resolutions: Optional[list[dict[str, Any]]] = None,
) -> Optional[str]:
    """Return a reason to refuse, or None if this exact IP and port may be probed."""
    if port is None or not isinstance(port, int) or port < 1 or port > 65535:
        return "port is missing or not an integer 1-65535"
    if not hx.is_ip(host):
        return "hostname and non-IP targets are not admitted"
    ip = str(ipaddress.ip_address(host))
    if scope is not None:
        if not address_authorized(ip, scope, resolutions):
            return "IP is outside --scope-check"
    elif not nets or not hx.in_scope(ip, nets, []):
        return "IP is outside --scope-check"
    if (ip, port) not in admitted:
        return "IP:port is not in --admit (default deny)"
    return None


def tls_argv(binary: str, ip: str, port: int, xml_path: Path, connect_timeout: Optional[int] = None) -> list[str]:
    budget = BUDGETS["tls"]
    connect = budget["connect_timeout"] if connect_timeout is None else connect_timeout
    socket_timeout = budget["socket_timeout"]
    if connect_timeout is not None:
        socket_timeout = min(socket_timeout, connect)
    # Config handshakes only. Heartbleed, CRIME, renegotiation, and fallback checks are off.
    # No --sni-name, no --targets, no --pk, no STARTTLS, no --bugs.
    # testssl is intentionally not used: this argv is the pinned sslscan contract.
    return [
        binary,
        "--no-colour",
        "--no-heartbleed",
        "--no-compression",
        "--no-renegotiation",
        "--no-fallback",
        "--no-groups",
        "--show-certificate",
        f"--connect-timeout={connect}",
        f"--timeout={socket_timeout}",
        f"--xml={xml_path}",
        f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}",
    ]


def ssh_argv(binary: str, ip: str, port: int, connect_timeout: Optional[int] = None) -> list[str]:
    # Algorithm audit only. No client listener, no DHEat, no GEX sweep, no target file.
    timeout = BUDGETS["ssh"]["tool_timeout"] if connect_timeout is None else connect_timeout
    return [
        binary,
        "-n",
        "-p", str(port),
        "-t", str(timeout),
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
    dns_recheck: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(status)
    provenance: dict[str, Any] = {
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
    }
    if dns_recheck:
        provenance["dns_recheck"] = dns_recheck
    return {
        "schema_version": SCHEMA_VERSION,
        "checks_version": CHECKS_VERSION,
        "check_id": check,
        "status": status,
        "confirmed_exploit": False,
        "target": {"ip": ip, "port": port, "transport": "tcp"},
        "observations": observations or [],
        "provenance": provenance,
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
    order = ["error", "unreachable", "not_tested", "observed_weakness", "lead", "observed_no_weakness"]
    present = set(statuses)
    for item in order:
        if item in present:
            return item
    return "error"


def _weak_signature_severity(algorithm: str) -> Optional[str]:
    text = algorithm.lower().replace(" ", "")
    if not text:
        return None
    if "md5" in text:
        return "high"
    if re.search(r"sha-?1(?!\d)", text):
        return "medium"
    return None


def _weak_key(kind: str, bits: int) -> bool:
    if bits <= 0:
        return False
    name = kind.lower()
    if "ec" in name or "ecdsa" in name:
        return bits < 256
    return bits < 2048


def _tls_cert_findings(root: ElementTree.Element) -> list[dict[str, Any]]:
    """Certificate problems present in the XML. Missing elements are not a pass or a fail."""
    findings: list[dict[str, Any]] = []
    for node in root.iter("self-signed"):
        if (node.text or "").strip().lower() in {"true", "yes", "1"}:
            findings.append({
                "id": "tls-cert-self-signed",
                "status": "observed_weakness",
                "severity": "medium",
                "evidence": "self-signed true",
                "remediation": (
                    "Replace the self-signed certificate with one issued by a CA "
                    "this service is supposed to present."
                ),
            })
            break
    for node in root.iter("signature-algorithm"):
        algorithm = (node.text or "").strip()
        severity = _weak_signature_severity(algorithm)
        if not severity:
            continue
        findings.append({
            "id": "tls-cert-signature",
            "status": "observed_weakness",
            "severity": severity,
            "evidence": algorithm,
            "remediation": (
                "Reissue the certificate with a SHA-256 or stronger signature. "
                "MD5 and SHA-1 signatures are not acceptable."
            ),
        })
        break
    weak_keys = []
    for node in list(root.iter("pk")) + list(root.iter("pk-bits")):
        bits_text = (node.get("bits") or node.text or "").strip()
        try:
            bits = int(bits_text)
        except ValueError:
            continue
        kind = node.get("type") or node.get("algorithm") or ""
        if _weak_key(kind, bits):
            weak_keys.append(f"{kind or 'key'} {bits}")
    if weak_keys:
        findings.append({
            "id": "tls-cert-key",
            "status": "observed_weakness",
            "severity": "high",
            "evidence": "; ".join(weak_keys[:4]),
            "remediation": (
                "Replace the certificate key. RSA and DSA keys shorter than 2048 bits, "
                "and elliptic-curve keys shorter than 256 bits, are not acceptable."
            ),
        })
    return findings


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
            (ptype == "tls" and version in {"1.0", "1.1"})
            or (ptype == "ssl" and version in {"2", "3"})
        )
        if enabled == "1" and weak_version:
            if version == "1.0":
                proto_id = "tls-1.0"
            elif version == "1.1":
                proto_id = "tls-1.1"
            else:
                proto_id = f"tls-{ptype}{version}"
            observations.append({
                "id": proto_id,
                "status": "observed_weakness",
                "severity": "high",
                "evidence": line,
                "remediation": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 on this listener.",
            })

    weak_ciphers = []
    triple_des = []
    for cipher in ciphers:
        status = (cipher.get("status") or "").lower()
        name = cipher.get("cipher") or ""
        if status not in {"accepted", "preferred"}:
            continue
        evidence = f'{status} {cipher.get("sslversion") or ""} {name}'.strip()
        if WEAK_CIPHER.search(name):
            weak_ciphers.append(evidence)
        elif re.search(r"DES-CBC3|3DES", name, re.I):
            triple_des.append(evidence)
    if weak_ciphers:
        observations.append({
            "id": "tls-cipher",
            "status": "observed_weakness",
            "severity": "high",
            "evidence": "; ".join(weak_ciphers[:8]),
            "remediation": "Disable NULL, anonymous, export, RC4, and single-DES cipher suites.",
        })
        snippet_lines.extend(weak_ciphers[:8])
    if triple_des:
        observations.append({
            "id": "tls-3des",
            "status": "observed_weakness",
            "severity": "medium",
            "evidence": "; ".join(triple_des[:8]),
            "remediation": (
                "Disable 3DES cipher suites. 3DES is vulnerable to SWEET32 (CVE-2016-2183). "
                "Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305."
            ),
        })
        snippet_lines.extend(triple_des[:8])

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
            "severity": "medium",
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
    observations.extend(_tls_cert_findings(root))

    if not any(item["id"] == "tls-cipher" for item in observations):
        observations.append({
            "id": "tls-cipher",
            "status": "observed_no_weakness",
            "evidence": f"{len(ciphers)} cipher element(s), no NULL/anonymous/export/RC4/single-DES accepted",
            "remediation": "",
        })
    protocol_weak = {"tls-1.0", "tls-1.1", "tls-ssl2", "tls-ssl3"}
    if not any(item["id"] in protocol_weak and item["status"] == "observed_weakness" for item in observations):
        if not any(item["status"] == "error" and str(item["id"]).startswith("tls-protocol") for item in observations):
            observations.append({
                "id": "tls-protocol",
                "status": "observed_no_weakness",
                "evidence": "SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are not enabled in the XML",
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


_SSH_SECTION = re.compile(r"\((kex|mac|enc|key)\)")


def _ssh_cipher_remediation(lines: list[str], warned: bool) -> str:
    blob = " ".join(lines).lower()
    if warned and "[fail]" not in blob:
        return (
            "CBC-mode SSH ciphers were marked [warn], not [fail]. "
            "Prefer AEAD ciphers (chacha20-poly1305 or AES-GCM) when the approved baseline disallows CBC."
        )
    names = []
    if "3des" in blob:
        names.append("3DES-CBC")
    if "arcfour" in blob or "rc4" in blob:
        names.append("arcfour (RC4)")
    if "cbc" in blob:
        names.append("CBC-mode ciphers")
    listed = ", ".join(dict.fromkeys(names)) if names else "the ciphers marked [fail]"
    return (
        f"Disable SSH ciphers marked [fail] ({listed}). "
        "Prefer AEAD ciphers such as chacha20-poly1305 or AES-GCM."
    )


def parse_ssh_audit(text: str, returncode: int, timed_out: bool) -> tuple[str, list[dict[str, Any]], str, str]:
    if timed_out:
        return "error", [], "", "ssh-audit timed out"
    if not text.strip():
        return "error" if returncode not in {None, 127} else "error", [], "", "ssh-audit produced no output"
    if _UNREACHABLE.search(text) and "(kex)" not in text and "(mac)" not in text and "[fail]" not in text:
        evidence = next((raw.strip() for raw in text.splitlines() if _UNREACHABLE.search(raw)), text.strip())
        return "unreachable", [{
            "id": "ssh-reachability",
            "status": "unreachable",
            "severity": "info",
            "evidence": evidence[:400],
            "remediation": "Confirm this in-scope listener is reachable. Unreachable is not a negative crypto result.",
        }], evidence[:400], "host unreachable, filtered, or connection failed"
    fails = {"kex": [], "mac": [], "enc": [], "key": []}
    warns = {"kex": [], "mac": [], "enc": [], "key": []}
    ambiguous = []
    counts = {"kex": 0, "mac": 0, "enc": 0, "key": 0}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _SSH_SECTION.search(line)
        if match:
            current = match.group(1)
            counts[current] += 1
        elif current is None or ("[fail]" not in line and "[warn]" not in line):
            continue
        if "[fail]" not in line and "[warn]" not in line:
            continue
        note = line.split("[fail]", 1)[-1] if "[fail]" in line else line.split("[warn]", 1)[-1]
        if re.search(r"\bnot\b", note, re.I):
            ambiguous.append(line)
            continue
        bucket = fails if "[fail]" in line else warns
        bucket[current].append(line)
    flat_fails = [line for kind in ("kex", "mac", "enc", "key") for line in fails[kind]]
    flat_warns = [line for kind in ("kex", "mac", "enc", "key") for line in warns[kind]]
    if ambiguous and not flat_fails:
        return "error", [{
            "id": "ssh-ambiguous",
            "status": "error",
            "evidence": ambiguous[0][:400],
            "remediation": "",
        }], ambiguous[0][:400], "a [fail] or [warn] note contains 'not' and was not accepted as a weakness"
    if counts["kex"] < 1 or counts["mac"] < 1:
        return "error", [], "", "ssh-audit output has no complete (kex) and (mac) algorithm lines"
    observations = []
    if fails["kex"] or fails["mac"]:
        observations.append({
            "id": "ssh-algorithm",
            "status": "observed_weakness",
            "severity": "high",
            "evidence": "\n".join((fails["kex"] + fails["mac"])[:12]),
            "remediation": "Remove the listed SSH key-exchange and MAC algorithms.",
        })
    if fails["enc"]:
        observations.append({
            "id": "ssh-cipher",
            "status": "observed_weakness",
            "severity": "high",
            "evidence": "\n".join(fails["enc"][:12]),
            "remediation": _ssh_cipher_remediation(fails["enc"], warned=False),
        })
    if fails["key"]:
        observations.append({
            "id": "ssh-hostkey",
            "status": "observed_weakness",
            "severity": "high",
            "evidence": "\n".join(fails["key"][:12]),
            "remediation": (
                "Disable SSH host-key algorithms marked [fail], including ssh-dss and SHA-1 ssh-rsa. "
                "Use ssh-ed25519 or rsa-sha2-256/512."
            ),
        })
    if flat_fails:
        status = "observed_weakness"
    elif flat_warns:
        if warns["kex"] or warns["mac"]:
            observations.append({
                "id": "ssh-algorithm-warn",
                "status": "lead",
                "severity": "low",
                "evidence": "\n".join((warns["kex"] + warns["mac"])[:12]),
                "remediation": "Review the warned SSH algorithms against the approved baseline.",
            })
        if warns["enc"]:
            observations.append({
                "id": "ssh-cipher-warn",
                "status": "lead",
                "severity": "medium",
                "evidence": "\n".join(warns["enc"][:12]),
                "remediation": _ssh_cipher_remediation(warns["enc"], warned=True),
            })
        if warns["key"]:
            observations.append({
                "id": "ssh-hostkey-warn",
                "status": "lead",
                "severity": "medium",
                "evidence": "\n".join(warns["key"][:12]),
                "remediation": "Review the warned SSH host-key algorithms against the approved baseline.",
            })
        status = "lead"
    elif returncode not in {0, None}:
        return "error", [], "", f"ssh-audit exit {returncode} without a [fail] line is not a negative result"
    else:
        evidence = f"{counts['kex']} kex line(s), {counts['mac']} mac line(s), no [fail] or [warn]"
        if counts["enc"] and counts["key"]:
            evidence += f"; {counts['enc']} enc line(s), {counts['key']} key line(s)"
        else:
            evidence += "; cipher and host-key coverage is not claimed when those sections are absent"
        observations.append({
            "id": "ssh-algorithm",
            "status": "observed_no_weakness",
            "evidence": evidence,
            "remediation": "",
        })
        status = "observed_no_weakness"
    snippet = "\n".join((flat_fails or flat_warns)[:12])
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
        severity = "high" if "disabled" in weak[0].lower() else "medium"
        return "observed_weakness", [{
            "id": "smb-signing",
            "status": "observed_weakness",
            "severity": severity,
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
    "algorithm lists; that is not a user login. [fail] on a (kex), (mac), (enc), or (key) line "
    "is a weakness. [warn] stays a lead, including CBC ciphers when ssh-audit marks them [warn]. "
    "3DES-CBC and arcfour are weaknesses only when the line is [fail]. "
    "A negative result that has no (enc) or (key) section does not cover ciphers or host keys. "
    "A note containing the word 'not' is rejected. Both a (kex) line and a (mac) line are still "
    "required before any algorithm tag is accepted."
)

TLS_LIMITATION = (
    "sslscan 2.1.5 flags used: --no-colour --no-heartbleed --no-compression --no-renegotiation "
    "--no-fallback --no-groups --show-certificate --connect-timeout=10 --timeout=5 --xml=FILE IP:PORT. "
    "Those --no-* switches are present in the rbsec sslscan 2.1.5 source. testssl is not invoked. "
    "No --sni-name is set. sslscan XML is the TLS evidence. "
    "TLS 1.0, TLS 1.1, SSLv2, and SSLv3 enabled=1 in XML are weaknesses. "
    "Accepted NULL, anonymous, export, RC4, and single-DES suites are weaknesses. "
    "Accepted 3DES (DES-CBC3) is a medium finding (SWEET32). AES-CBC is not classified from the cipher name. "
    "Certificate expiry uses not-valid-after against the checker clock. A missing or unparsed date is error. "
    "Self-signed, MD5 or SHA-1 signatures, and short keys are weaknesses only when those XML elements are present. "
    "Their absence is not a negative result. "
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
    dns_recheck: Optional[list[dict[str, Any]]] = None,
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
    if status in {"observed_weakness", "lead", "unreachable"}:
        texts = []
        for item in observations:
            text = item.get("remediation") or ""
            if item.get("status") == status and text and text not in texts:
                texts.append(text)
        if texts:
            remediation = " ".join(texts)
    else:
        remediation = ""
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
        dns_recheck=dns_recheck,
    )


def _process_timeout(check: str, limits: NarrowLimits) -> int:
    if limits.host_timeout > 0:
        return limits.host_timeout
    return int(BUDGETS[check]["process_timeout"])


def _version_timeout(limits: NarrowLimits) -> int:
    if 0 < limits.host_timeout < 10:
        return limits.host_timeout
    return 10


def _note_probe(counter: Optional[list[int]], lock: Optional[threading.Lock]) -> None:
    if counter is None:
        return
    if lock is None:
        counter[0] += 1
        return
    with lock:
        counter[0] += 1


def _dns_recheck(
    ip: str,
    scope: NarrowScope,
    resolutions: list[dict[str, Any]],
    resolver: Callable[[str], dict[str, Any]],
) -> tuple[Optional[str], list[dict[str, Any]]]:
    """Re-resolve names that currently point at ip. Block only '+'/'++' authorization."""
    addr = ipaddress.ip_address(ip)
    explicit = _addr_in(addr, scope.networks) and not _addr_in(addr, scope.excluded_nets)
    wanted = str(addr)
    records = []
    block = None
    for item in resolutions:
        answers = set(item.get("a") or []) | set(item.get("aaaa") or [])
        if wanted not in answers:
            continue
        fresh = classify_resolution(_name_for(item), _call_resolver(resolver, str(item["name"])), scope)
        fresh["previous_queried_at"] = item.get("queried_at") or ""
        still = wanted in set(fresh.get("a") or []) or wanted in set(fresh.get("aaaa") or [])
        fresh["still_present"] = still
        records.append(fresh)
        depended = (not explicit) and bool(item.get("authorizes"))
        if depended and (fresh.get("error") or not still or not fresh.get("authorizes")):
            block = "dns_changed: resolved address changed before the probe"
    return block, records


def _apply_unreachable(
    status: str,
    observations: list[dict[str, Any]],
    err: str,
    blob: str,
    timed_out: bool,
) -> tuple[str, list[dict[str, Any]], str]:
    if timed_out or status != "error" or not _UNREACHABLE.search(blob or ""):
        return status, observations, err
    evidence = next((line.strip() for line in blob.splitlines() if line.strip() and _UNREACHABLE.search(line)), "unreachable")
    observations = list(observations) + [{
        "id": "reachability",
        "status": "unreachable",
        "severity": "info",
        "evidence": evidence[:400],
        "remediation": "Confirm this in-scope listener is reachable. Unreachable is not a negative crypto result.",
    }]
    return "unreachable", observations, "host unreachable, filtered, or connection failed"


class _RateGate:
    """One start reservation per wait(). The sleep loop never takes a work item."""

    def __init__(self, interval: float, sleep: Callable[[float], None], clock: Callable[[], float]) -> None:
        self.interval = interval
        self.sleep = sleep
        self.clock = clock
        self.lock = threading.Lock()
        self.next_ok: Optional[float] = None

    def wait(self, stop_event: threading.Event) -> None:
        if self.interval <= 0 or stop_event.is_set():
            return
        with self.lock:
            now = self.clock()
            if self.next_ok is None:
                self.next_ok = now
            delay = self.next_ok - now
            if delay < 0:
                delay = 0
                self.next_ok = now
            self.next_ok += self.interval
        if delay <= 0:
            return
        # One sleep for the reserved gap. This loop only waits; it does not poll for work.
        remaining = delay
        while remaining > 0:
            if stop_event.is_set():
                return
            step = remaining if remaining < 0.05 else 0.05
            self.sleep(step)
            remaining -= step


def _install_stop(stop_event: threading.Event) -> dict[int, Any]:
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[sig] = signal.signal(sig, handler)
        except Exception:
            continue
    return previous


def _restore_stop(previous: dict[int, Any]) -> None:
    for sig, handler in previous.items():
        try:
            signal.signal(sig, handler)
        except Exception:
            continue


def _limits_payload(limits: NarrowLimits) -> dict[str, Any]:
    return {
        "workers": limits.workers,
        "rate_interval": limits.rate_interval,
        "connect_timeout": limits.connect_timeout,
        "host_timeout": limits.host_timeout,
        "min_prefix_v4": limits.min_prefix_v4,
        "min_prefix_v6": limits.min_prefix_v6,
        "max_addresses": limits.max_addresses,
        "allow_broad_cidr": limits.allow_broad_cidr,
        "effective_process_timeout": {
            "tls": _process_timeout("tls", limits),
            "ssh": _process_timeout("ssh", limits),
            "smb": _process_timeout("smb", limits),
        },
    }


def run_row(
    row: dict[str, Any],
    *,
    nets: list,
    admitted: set[tuple[str, int]],
    runner: Any,
    outdir: Path,
    now: datetime,
    which=shutil.which,
    scope: Optional[NarrowScope] = None,
    resolutions: Optional[list[dict[str, Any]]] = None,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    limits: Optional[NarrowLimits] = None,
    probe_counter: Optional[list[int]] = None,
    probe_lock: Optional[threading.Lock] = None,
) -> dict[str, Any]:
    host = str(row.get("host") or "")
    port = row.get("port")
    check = str(row.get("check") or "")
    if row.get("error"):
        return _result(check or "unknown", host, port if isinstance(port, int) else None, "not_tested", error=row["error"])
    active_limits = limits or NarrowLimits()
    reason = admission_block(
        host, port if isinstance(port, int) else None, nets, admitted, scope, resolutions,
    )
    if reason:
        return _result(check or "unknown", host, port if isinstance(port, int) else None, "not_tested", error=reason)
    if check not in {"tls", "ssh", "smb"}:
        return _result(check or "unknown", host, port, "not_tested", error=f"unsupported check {check}")
    ip = str(ipaddress.ip_address(host))
    port_i = int(port)
    dns_recheck: list[dict[str, Any]] = []
    if scope is not None and resolutions and resolver is not None:
        block, dns_recheck = _dns_recheck(ip, scope, resolutions, resolver)
        if block:
            return _result(
                check, ip, port_i, "error",
                error=block,
                dns_recheck=dns_recheck,
                limitations={"tls": TLS_LIMITATION, "ssh": SSH_LIMITATION, "smb": SMB_LIMITATION}[check],
            )
    binary_name = {"tls": "sslscan", "ssh": "ssh-audit", "smb": "nmap"}[check]
    binary = which(binary_name)
    if not binary:
        missed = _tool_missing(check, None, ip, port_i)
        if dns_recheck:
            missed["provenance"]["dns_recheck"] = dns_recheck
        return missed
    art = outdir / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    safe_ip = ip.replace(":", "_")
    version_run = runner.run(version_argv(check, binary), _version_timeout(active_limits))
    tool_version = redact((version_run.stdout or version_run.stderr or "").strip().splitlines()[0] if (version_run.stdout or version_run.stderr) else "")
    if version_run.timed_out:
        return _result(check, ip, port_i, "error", tool=binary_name, tool_version=tool_version, error="version command timed out", timed_out=True, argv=version_run.argv, exit_code=version_run.returncode, started=version_run.started, finished=version_run.finished, dns_recheck=dns_recheck)
    budget = _process_timeout(check, active_limits)
    if check == "tls":
        xml_path = art / f"tls-{safe_ip}-{port_i}.xml"
        argv = tls_argv(binary, ip, port_i, xml_path, active_limits.connect_timeout)
        _note_probe(probe_counter, probe_lock)
        completed = runner.run(argv, budget)
        if xml_path.exists():
            xml_text = redact(xml_path.read_text(encoding="utf-8", errors="replace"))
        else:
            xml_text = redact(completed.stdout)
        status, observations, snippet, err = parse_tls_output(xml_text, now)
        if completed.timed_out:
            status, err = "error", "sslscan timed out"
        status, observations, err = _apply_unreachable(
            status, observations, err, "\n".join([xml_text, completed.stdout, completed.stderr]), completed.timed_out,
        )
        completed = Completed(
            completed.argv, completed.returncode, xml_text, completed.stderr,
            completed.timed_out, completed.started, completed.finished,
        )
        return _finish_from_parse(
            check, ip, port_i, status, observations, snippet, err, completed,
            "sslscan", tool_version or "unknown", art / f"tls-{safe_ip}-{port_i}.txt",
            TLS_LIMITATION, "", dns_recheck,
        )
    if check == "ssh":
        argv = ssh_argv(binary, ip, port_i, active_limits.connect_timeout)
        _note_probe(probe_counter, probe_lock)
        completed = runner.run(argv, budget)
        status, observations, snippet, err = parse_ssh_audit(redact(completed.stdout), completed.returncode, completed.timed_out)
        status, observations, err = _apply_unreachable(
            status, observations, err, "\n".join([completed.stdout, completed.stderr]), completed.timed_out,
        )
        return _finish_from_parse(
            check, ip, port_i, status, observations, snippet, err, completed,
            "ssh-audit", tool_version or "unknown", art / f"ssh-{safe_ip}-{port_i}.txt",
            SSH_LIMITATION, "", dns_recheck,
        )
    normal = art / f"smb-{safe_ip}-{port_i}.nmap"
    argv = smb_argv(binary, ip, port_i, normal)
    _note_probe(probe_counter, probe_lock)
    completed = runner.run(argv, budget)
    text = redact(completed.stdout)
    if normal.exists():
        file_text = redact(normal.read_text(encoding="utf-8", errors="replace"))
        if len(file_text) > len(text):
            text = file_text
    status, observations, snippet, err = parse_smb2_signing(text, completed.returncode, completed.timed_out)
    status, observations, err = _apply_unreachable(
        status, observations, err, "\n".join([text, completed.stderr]), completed.timed_out,
    )
    finished = _finish_from_parse(
        check, ip, port_i, status, observations, snippet, err,
        Completed(completed.argv, completed.returncode, text, completed.stderr, completed.timed_out, completed.started, completed.finished),
        "nmap", tool_version or "unknown", art / f"smb-{safe_ip}-{port_i}.txt",
        SMB_LIMITATION, "", dns_recheck,
    )
    return finished


def refusal_reason(
    row: dict[str, Any],
    nets: list,
    admitted: set[tuple[str, int]],
    scope: Optional[NarrowScope] = None,
    resolutions: Optional[list[dict[str, Any]]] = None,
) -> Optional[str]:
    """None when this row may be probed. Any other string is a hard refusal."""
    if row.get("error"):
        return str(row["error"])
    host = str(row.get("host") or "")
    port = row.get("port")
    check = str(row.get("check") or "")
    reason = admission_block(host, port if isinstance(port, int) else None, nets, admitted, scope, resolutions)
    if reason:
        return reason
    if check not in {"tls", "ssh", "smb"}:
        return f"unsupported check {check}"
    return None


def _row_identity(row: dict[str, Any]) -> tuple[str, str, Optional[int]]:
    host = str(row.get("host") or "")
    port = row.get("port") if isinstance(row.get("port"), int) else None
    if hx.is_ip(host):
        host = str(ipaddress.ip_address(host))
    return str(row.get("check") or ""), host, port


def _result_for_row(row: dict[str, Any], status: str, error: str) -> dict[str, Any]:
    host = str(row.get("host") or "")
    port = row.get("port") if isinstance(row.get("port"), int) else None
    return _result(str(row.get("check") or "unknown"), host, port, status, error=error)


def _has_authorizing_names(scope: NarrowScope) -> bool:
    return any(entry.mode in {"authorize", "authorize-third-party"} for entry in scope.names)


def _needs_resolution(scope: NarrowScope) -> bool:
    return any(entry.mode != "exclude" for entry in scope.names)


def _run_bounded(
    rows: list[dict[str, Any]],
    *,
    scope: NarrowScope,
    admitted: set[tuple[str, int]],
    resolutions: list[dict[str, Any]],
    resolver: Callable[[str], dict[str, Any]],
    runner: Any,
    outdir: Path,
    now: datetime,
    which: Callable[[str], Optional[str]],
    limits: NarrowLimits,
    stop_event: threading.Event,
    sleeper: Callable[[float], None],
    clock: Callable[[], float],
) -> tuple[list[dict[str, Any]], int]:
    """At most ``workers`` rows are in flight. Stop prevents any further take()."""
    results: list[Optional[dict[str, Any]]] = [None] * len(rows)
    index = 0
    index_lock = threading.Lock()
    probe_lock = threading.Lock()
    probe_counter = [0]
    gate = _RateGate(limits.rate_interval, sleeper, clock)

    def take() -> Optional[int]:
        nonlocal index
        with index_lock:
            if stop_event.is_set() or index >= len(rows):
                return None
            current = index
            index += 1
            return current

    def worker() -> None:
        while True:
            # Take first so an idle poll does not reserve a rate slot.
            current = take()
            if current is None:
                return
            gate.wait(stop_event)
            if stop_event.is_set():
                results[current] = _result_for_row(rows[current], "not_tested", "interrupted before probe")
                return
            try:
                results[current] = run_row(
                    rows[current],
                    nets=scope.networks,
                    admitted=admitted,
                    runner=runner,
                    outdir=outdir,
                    now=now,
                    which=which,
                    scope=scope,
                    resolutions=resolutions,
                    resolver=resolver,
                    limits=limits,
                    probe_counter=probe_counter,
                    probe_lock=probe_lock,
                )
            except Exception as exc:
                results[current] = _result_for_row(rows[current], "error", f"check failed: {type(exc).__name__}: {exc}")

    threads = []
    count = min(limits.workers, len(rows))
    for _ in range(count):
        thread = threading.Thread(target=worker, name="narrow-check")
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    finished: list[dict[str, Any]] = []
    for position, row in enumerate(rows):
        if results[position] is None:
            finished.append(_result_for_row(row, "not_tested", "interrupted before probe"))
        else:
            finished.append(results[position])
    return finished, probe_counter[0]


def _row_excluded(row: dict[str, Any], scope: NarrowScope) -> bool:
    host = str(row.get("host") or "")
    if not hx.is_ip(host):
        return False
    return _addr_in(ipaddress.ip_address(host), scope.excluded_nets)


def _annotate(report: dict[str, Any], scope: NarrowScope, limits: NarrowLimits, resolutions: list[dict[str, Any]]) -> dict[str, Any]:
    report["limits"] = _limits_payload(limits)
    report["scope_policy"] = SCOPE_POLICY
    report["dns_policy"] = DNS_POLICY
    report["dns"] = {"policy": DNS_POLICY, "resolutions": resolutions}
    report["hostnames"] = [
        {"name": entry.name, "mode": entry.mode, "resolved": bool(resolutions)}
        for entry in scope.names
    ]
    return report


def _dry_run_report(
    scope: NarrowScope,
    hard: list[dict[str, Any]],
    pending: list[dict[str, Any]],
    limits: NarrowLimits,
) -> dict[str, Any]:
    targets = expand_scope_targets(scope)
    pending_results = [
        _result_for_row(row, "not_tested", "hostname authorization is not proven offline")
        for row in pending
    ]
    results = hard + pending_results
    if results:
        report = _refused_report(results)
    else:
        report = _refused_report([])
        report["refused"] = False
        report.pop("error", None)
    report["dry_run"] = True
    report["expanded_count"] = len(targets)
    report["targets"] = targets
    return _annotate(report, scope, limits, [])


def run_manifest(
    rows: list[dict[str, Any]],
    *,
    scope_file: Path,
    admit_file: Path,
    outdir: Path,
    runner: Any = None,
    now: Optional[datetime] = None,
    which=shutil.which,
    limits: Optional[NarrowLimits] = None,
    resolver: Optional[Callable[[str], dict[str, Any]]] = None,
    sleeper: Optional[Callable[[float], None]] = None,
    clock: Optional[Callable[[], float]] = None,
    stop_event: Optional[threading.Event] = None,
    install_signals: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    active_limits = limits or NarrowLimits()
    try:
        active_limits.validate()
        scope = parse_narrow_scope(scope_file, active_limits)
        admitted = parse_admit(admit_file)
    except NarrowInputError as exc:
        # No output directory and no tool. Bad admit used to raise SystemExit.
        return _refused_report([
            _result("unknown", "", None, "not_tested", error=exc.message),
        ], error=exc.message)
    clock_now = now or datetime.now(timezone.utc)
    if clock_now.tzinfo is None:
        clock_now = clock_now.replace(tzinfo=timezone.utc)
    hard: list[dict[str, Any]] = []
    pending: list[dict[str, Any]] = []
    seen: set[tuple[str, str, Optional[int]]] = set()
    if not rows:
        hard.append(_result("unknown", "", None, "not_tested", error="manifest has no checks"))
    for row in rows:
        if row.get("error"):
            hard.append(_result_for_row(row, "not_tested", str(row["error"])))
            continue
        ident = _row_identity(row)
        if ident in seen:
            hard.append(_result_for_row(row, "not_tested", "duplicate manifest row"))
            continue
        seen.add(ident)
        reason = refusal_reason(row, scope.networks, admitted, scope, None)
        if reason is None:
            continue
        if (
            reason == "IP is outside --scope-check"
            and _has_authorizing_names(scope)
            and not _row_excluded(row, scope)
        ):
            pending.append(row)
            continue
        hard.append(_result_for_row(row, "not_tested", reason))
    if dry_run:
        # No resolver, no runner, no output directory.
        return _dry_run_report(scope, hard, pending, active_limits)
    if hard:
        # One bad row refuses the whole manifest before DNS, tools, or the output directory.
        return _refused_report(hard)
    stop = stop_event or threading.Event()
    previous = _install_stop(stop) if install_signals else None
    try:
        resolutions: list[dict[str, Any]] = []
        active_resolver = resolver or default_resolver
        if _needs_resolution(scope) and not stop.is_set():
            resolutions = resolve_scope_names(scope, active_resolver)
        if pending:
            still = []
            for row in pending:
                reason = refusal_reason(row, scope.networks, admitted, scope, resolutions)
                if reason:
                    still.append(_result_for_row(row, "not_tested", reason))
            if still:
                refused = _refused_report(still)
                return _annotate(refused, scope, active_limits, resolutions)
        if stop.is_set():
            outdir.mkdir(parents=True, exist_ok=True)
            results = [_result_for_row(row, "not_tested", "interrupted before probe") for row in rows]
            report = _success_report(results, active_limits, scope, resolutions, probes=0, interrupted=True, workers=0)
            (outdir / "narrow-checks.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            return report
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "artifacts").mkdir(parents=True, exist_ok=True)
        results, probes = _run_bounded(
            rows,
            scope=scope,
            admitted=admitted,
            resolutions=resolutions,
            resolver=active_resolver,
            runner=runner or SubprocessRunner(),
            outdir=outdir,
            now=clock_now,
            which=which,
            limits=active_limits,
            stop_event=stop,
            sleeper=sleeper or time.sleep,
            clock=clock or time.monotonic,
        )
        report = _success_report(
            results,
            active_limits,
            scope,
            resolutions,
            probes=probes,
            interrupted=stop.is_set(),
            workers=min(active_limits.workers, len(rows)),
        )
        (outdir / "narrow-checks.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        if previous:
            _restore_stop(previous)


def _success_report(
    results: list[dict[str, Any]],
    limits: NarrowLimits,
    scope: NarrowScope,
    resolutions: list[dict[str, Any]],
    *,
    probes: int,
    interrupted: bool,
    workers: int,
) -> dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "checks_version": CHECKS_VERSION,
        "generated": _now_iso(),
        "confirmed_exploit": False,
        "refused": False,
        "interrupted": interrupted,
        "budgets": BUDGETS,
        "probe_accounting": {
            "rows": len(results),
            "probes_started": probes,
            "workers": workers,
            # One probe per manifest row that starts. Two rows for one IP are two probes.
            "per_row_probe_cap": 1,
        },
        "limitations": {
            "tls": TLS_LIMITATION,
            "ssh": SSH_LIMITATION,
            "smb": SMB_LIMITATION,
        },
        "results": results,
    }
    return _annotate(report, scope, limits, resolutions)


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
            "Manifest targets are IPs. A plain scope hostname does not authorize addresses. "
            "This does not run the all-phase recon workflow."
        ),
    )
    parser.add_argument("--manifest", required=True, help="Lines: tls|ssh|smb IP PORT")
    parser.add_argument(
        "--scope-check",
        required=True,
        help=(
            "Bare IPs, canonical CIDRs, FQDNs, !exclusions, +FQDN, and ++FQDN. "
            "A non-canonical CIDR such as 203.0.113.10/0 is rejected and is not widened. "
            "0.0.0.0/0 and ::/0 are refused."
        ),
    )
    parser.add_argument("--admit", required=True, help="Exact ip:port lines. A bare IP is not enough.")
    parser.add_argument("-o", "--output", required=True, help="Output directory for narrow-checks.json and artifacts")
    parser.add_argument("--authorized", action="store_true", help="Confirm written authorization for every admitted socket")
    _add_narrow_limit_args(parser)
    parser.add_argument("--version", action="version", version=f"narrow-checks {CHECKS_VERSION}")
    return parser


def _add_narrow_limit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dry-run", action="store_true", help="Print the expanded scope and exit. No DNS, no probes, no output directory.")
    parser.add_argument("--narrow-workers", type=int, default=2, help="Max concurrent host checks (default: 2).")
    parser.add_argument("--narrow-rate", type=float, default=0.2, help="Seconds between host-check starts (default: 0.2).")
    parser.add_argument("--narrow-connect-timeout", type=int, default=10, help="Per-host connect timeout in seconds (default: 10).")
    parser.add_argument("--narrow-host-timeout", type=int, default=0, help="Overall process timeout in seconds. 0 keeps ssh 30 / tls 90 / smb 45.")
    parser.add_argument("--narrow-min-prefix-v4", type=int, default=24, help="Reject IPv4 CIDRs broader than this prefix (default: 24).")
    parser.add_argument("--narrow-min-prefix-v6", type=int, default=120, help="Reject IPv6 CIDRs broader than this prefix (default: 120).")
    parser.add_argument("--narrow-max-addresses", type=int, default=1024, help="Refuse when included networks sum past this many addresses (default: 1024).")
    parser.add_argument("--narrow-allow-broad-cidr", action="store_true", help="Lift the prefix floor. Does not allow /0 and does not lift the address cap.")


def limits_from_args(args: argparse.Namespace) -> NarrowLimits:
    limits = NarrowLimits(
        workers=args.narrow_workers,
        rate_interval=args.narrow_rate,
        connect_timeout=args.narrow_connect_timeout,
        host_timeout=args.narrow_host_timeout,
        min_prefix_v4=args.narrow_min_prefix_v4,
        min_prefix_v6=args.narrow_min_prefix_v6,
        max_addresses=args.narrow_max_addresses,
        allow_broad_cidr=bool(args.narrow_allow_broad_cidr),
    )
    limits.validate()
    return limits


def emit_narrow_report(report: dict[str, Any], outdir: Path, *, include_mode: bool) -> int:
    """Print the operator summary. Exit 2 on refusal, 130 on interrupt, 0 otherwise."""
    if report.get("dry_run"):
        payload: dict[str, Any] = {
            "dry_run": True,
            "expanded_count": report.get("expanded_count", 0),
            "targets": report.get("targets", []),
            "hostnames": report.get("hostnames", []),
            "refused": bool(report.get("refused")),
            "confirmed_exploit": False,
        }
        if include_mode:
            payload["mode"] = "narrow-checks"
        print(json.dumps(payload))
        if report.get("refused"):
            _print_refusals(report)
            return 2
        return 0
    if report.get("refused"):
        _print_refusals(report)
        return 2
    counts: dict[str, int] = {}
    for row in report["results"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    payload = {
        "output": str(outdir / "narrow-checks.json"),
        "counts": counts,
        "confirmed_exploit": False,
    }
    if include_mode:
        payload = {
            "mode": "narrow-checks",
            "output": payload["output"],
            "counts": counts,
            "confirmed_exploit": False,
        }
    if report.get("interrupted"):
        payload["interrupted"] = True
    print(json.dumps(payload))
    return 130 if report.get("interrupted") else 0


def _print_refusals(report: dict[str, Any]) -> None:
    if report.get("error"):
        print(f"refused: {report['error']}", file=sys.stderr)
        return
    for row in report.get("results") or []:
        target = row.get("target") or {}
        if "ip" in target:
            where = f"{target.get('ip')}:{target.get('port')}"
        else:
            where = str(target)
        print(
            f"refused: {row.get('check_id')} {where} {row['provenance']['error']}",
            file=sys.stderr,
        )


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
    try:
        limits = limits_from_args(args)
    except NarrowInputError as exc:
        print(f"refused: {exc.message}", file=sys.stderr)
        return 2
    report = run_manifest(
        rows,
        scope_file=scope,
        admit_file=admit,
        outdir=outdir,
        limits=limits,
        install_signals=True,
        dry_run=bool(args.dry_run),
    )
    # Exit 0 means the manifest was admitted or a dry-run found no hard refusal.
    # It is also the exit for a weakness. It is not acceptance.
    return emit_narrow_report(report, outdir, include_mode=False)


if __name__ == "__main__":
    sys.exit(main())
