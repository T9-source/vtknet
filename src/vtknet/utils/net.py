"""Target helpers: CIDR expansion, port-spec parsing, hostname resolution."""

from __future__ import annotations

import ipaddress
import socket


def expand_hosts(spec: str) -> list[str]:
    """Expand '10.0.0.0/24' (or a single IP/hostname) into a host list.

    CIDR expansion excludes network and broadcast addresses. /31 and /32
    keep their addresses. IPv6 is intentionally rejected until its phase.
    """
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        if net.version != 4:
            raise ValueError(f"IPv6 targets are planned for a later phase; got: {spec}")
        return [str(h) for h in net.hosts()]
    return [spec]


def parse_ports(spec: str) -> list[int]:
    """Parse '80', '80,443', '1-1024', '80,100-200,443' into a sorted unique list."""
    ports: set = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if not (0 <= lo <= 65535 and 0 <= hi <= 65535 and lo <= hi):
                raise ValueError(f"invalid port range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (0 <= p <= 65535):
                raise ValueError(f"invalid port: {part}")
            ports.add(p)
    if not ports:
        raise ValueError(f"empty port specification: {spec!r}")
    return sorted(ports)


def resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4 address; literal IPs pass through unchanged."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    return socket.gethostbyname(host)
