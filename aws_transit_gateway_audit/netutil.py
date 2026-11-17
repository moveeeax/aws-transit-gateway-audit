"""CIDR helpers. IPv4 and IPv6, no third-party dependency."""

from __future__ import annotations

import ipaddress

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_cidr(value: str) -> Network | None:
    """Return a network, or None when the string is not a usable CIDR."""
    if not value or not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def overlap(a: str, b: str) -> str | None:
    """Return the overlapping prefix of two CIDRs, or None.

    IP networks are aligned blocks, so when two of them overlap at all one
    always contains the other and the narrower prefix *is* the overlap.
    """
    net_a, net_b = parse_cidr(a), parse_cidr(b)
    if net_a is None or net_b is None:
        return None
    if net_a.version != net_b.version:
        return None
    if not net_a.overlaps(net_b):
        return None
    return str(net_a if net_a.prefixlen >= net_b.prefixlen else net_b)


def is_default_route(value: str) -> bool:
    net = parse_cidr(value)
    return net is not None and net.prefixlen == 0
