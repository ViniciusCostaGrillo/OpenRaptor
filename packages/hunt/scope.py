"""Deterministic Scope Guard for Bug Bounty and Pentest targets."""

from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

_DISALLOWED_V4_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)

_DISALLOWED_V6_NETS = (
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)


class ScopeViolationError(Exception):
    """Raised when a target is out of scope or resolves to a disallowed IP."""


class ScopeConfig(BaseModel):
    """Authorized scope, rate limit, and custom Bug Bounty HTTP metadata."""

    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rate_limit_rps: float = 5.0
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    allow_private_ips: bool = False

    @classmethod
    def from_file(cls, path: Path) -> ScopeConfig:
        """Load scope configuration from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)

    @classmethod
    def from_target(cls, target: str) -> ScopeConfig:
        """Build a minimal single-target scope when no scope file is provided."""
        host = extract_host(target)
        return cls(in_scope=[host] if host else [target])


def extract_host(target: str) -> str:
    """Extract hostname or IP/CIDR from a URL or bare network target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower().rstrip(".")
    if raw.startswith("[") and "]" in raw:
        # [::1]:8080 or [::1]
        inner = raw[1 : raw.index("]")]
        return inner.lower()
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return raw
        except ValueError:
            raw = raw.split("/", 1)[0]
    if raw.count(":") == 1:
        host_part, _, port_part = raw.partition(":")
        if port_part.isdigit():
            return host_part.lower().rstrip(".")
    return raw.lower().rstrip(".")


def _extract_url_parts(target: str) -> tuple[str, str, str]:
    """Return (scheme, host, path) for a target or rule."""
    raw = target.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower().rstrip("."),
            parsed.path or "/",
        )
    return ("", extract_host(raw), "")


def _is_disallowed_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def _network_overlaps_disallowed(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if isinstance(net, ipaddress.IPv4Network):
        return any(net.overlaps(bad) for bad in _DISALLOWED_V4_NETS)
    return any(net.overlaps(bad) for bad in _DISALLOWED_V6_NETS)


def _path_matches(target_path: str, rule_path: str) -> bool:
    norm_rule = rule_path.rstrip("/") or "/"
    norm_target = target_path or "/"
    if norm_rule == "/":
        return True
    return norm_target == norm_rule or norm_target.startswith(norm_rule + "/")


def matches_rule(target: str, rule: str) -> bool:
    """Check whether a target (URL, host, IP, or CIDR) matches a scope rule."""
    t_scheme, t_host, t_path = _extract_url_parts(target)
    r_scheme, r_host, r_path = _extract_url_parts(rule)
    if not t_host or not r_host:
        return False

    # CIDR / IP rule
    try:
        rule_net = ipaddress.ip_network(r_host, strict=False)
        try:
            host_net = ipaddress.ip_network(t_host, strict=False)
            return host_net.subnet_of(rule_net)  # type: ignore[arg-type]
        except ValueError:
            return False
    except ValueError:
        pass

    # Host match (exact or *.domain wildcard)
    if r_host.startswith("*."):
        suffix = r_host[2:]
        host_ok = t_host.endswith(f".{suffix}") and len(t_host) > len(suffix) + 1
    else:
        host_ok = t_host == r_host

    if not host_ok:
        return False

    # Path-scoped URL rule (e.g. https://example.com/api)
    if r_scheme and r_path not in ("", "/"):
        if not t_scheme:
            return False
        return _path_matches(t_path, r_path)

    return True


def assert_in_scope(
    target: str,
    config: ScopeConfig,
    *,
    resolve_dns: bool = True,
) -> str:
    """Validate that target is in scope, not excluded, and not a private/disallowed IP.

    Returns the original target string if valid; raises ScopeViolationError otherwise.
    """
    host = extract_host(target)
    if not host:
        raise ScopeViolationError(f"Unable to extract host from target: {target!r}")

    for excluded in config.out_of_scope:
        if matches_rule(target, excluded):
            raise ScopeViolationError(
                f"Target {target!r} (host={host!r}) matched out_of_scope rule {excluded!r}"
            )

    if not any(matches_rule(target, allowed) for allowed in config.in_scope):
        raise ScopeViolationError(
            f"Target {target!r} (host={host!r}) is not in in_scope rules"
        )

    # Direct IP / CIDR check (including supernet overlap)
    try:
        net = ipaddress.ip_network(host, strict=False)
        if not config.allow_private_ips and _network_overlaps_disallowed(net):
            raise ScopeViolationError(
                f"Target {target!r} overlaps a disallowed private/loopback/reserved IP/CIDR"
            )
        return target
    except ValueError:
        pass

    # DNS resolution check to prevent SSRF / DNS rebinding into private IPs
    if resolve_dns and not config.allow_private_ips:
        try:
            addr_info = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise ScopeViolationError(
                f"DNS resolution failed for in-scope host {host!r}: {exc}"
            ) from exc

        for entry in addr_info:
            ip_str = str(entry[4][0]).split("%", 1)[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if _is_disallowed_ip(ip_obj):
                raise ScopeViolationError(
                    f"Target {target!r} resolved to disallowed IP {ip_str}"
                )

    return target
