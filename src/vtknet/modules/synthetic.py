"""Synthetic attack-trace generator for IDS/rule testing (detection engineering).

Every scenario is seeded (``seed``) so the same call reproduces byte-identical
pcaps — reproducible test data for Suricata/Zeek/NIDS rules. All default
addresses come from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) so traces are unambiguous test traffic.
"""

from __future__ import annotations

import json
import logging
import random
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, Raw, rdpcap, wrpcap
from scapy.layers.inet import fragment
from scapy.packet import Packet

import vtknet

log = logging.getLogger("vtknet.synthetic")

TEST_NETS = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

_SCENARIOS: dict[str, tuple[Callable[[random.Random, dict[str, Any]], list[Packet]], str]] = {}


def _register(name: str, description: str) -> Callable:
    def deco(fn: Callable[[random.Random, dict[str, Any]], list[Packet]]) -> Callable:
        _SCENARIOS[name] = (fn, description)
        return fn

    return deco


def list_scenarios() -> list[str]:
    return sorted(_SCENARIOS)


@dataclass
class TraceMeta:
    name: str
    description: str
    params: dict[str, Any] = field(default_factory=dict)
    iocs: dict[str, Any] = field(default_factory=dict)
    count: int = 0


# -- helpers -----------------------------------------------------------


def _rand_doc_ip(rng: random.Random) -> str:
    a, b, c = rng.choice(TEST_NETS)
    return f"{a}.{b}.{c}.{rng.randint(1, 254)}"


def _rand_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


# -- scenarios ------------------------------------------------------------


@_register("tcp_scan", "Sequential SYN probes from one source across many ports (port-scan signature).")
def _tcp_scan(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    src_ip, src_mac = _rand_doc_ip(rng), _rand_mac(rng)
    ports = rng.sample(range(1, 10001), min(p["count"], 10000))
    return [
        Ether(src=src_mac, dst=BROADCAST_MAC)
        / IP(src=src_ip, dst=p["target"])
        / TCP(sport=rng.randint(1024, 65535), dport=port, flags="S")
        for port in ports
    ]


@_register("syn_flood", "High-rate SYNs from randomized sources (flood signature).")
def _syn_flood(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    ports = [80, 443, 8080]
    return [
        Ether(src=_rand_mac(rng), dst=BROADCAST_MAC)
        / IP(src=_rand_doc_ip(rng), dst=p["target"])
        / TCP(sport=rng.randint(1024, 65535), dport=rng.choice(ports), flags="S")
        for _ in range(p["count"])
    ]


@_register("stealth_scan", "NULL/FIN/XMAS probe rotation across ports (stealth-scan signatures).")
def _stealth_scan(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    flags_cycle = ["", "F", "FPU"]
    base, src_ip = rng.randint(20, 10000), _rand_doc_ip(rng)
    return [
        Ether(src=_rand_mac(rng), dst=BROADCAST_MAC)
        / IP(src=src_ip, dst=p["target"])
        / TCP(sport=rng.randint(1024, 65535), dport=base + i, flags=flags_cycle[i % 3])
        for i in range(p["count"])
    ]


@_register("dns_tunnel", "Long randomized TXT subdomain queries to one nameserver (DNS-tunneling signature).")
def _dns_tunnel(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    ns, domain, src_ip = p["target"], p["base_domain"], _rand_doc_ip(rng)
    alpha = "abcdefghijklmnopqrstuvwxyz234567"
    out: list[Packet] = []
    for _ in range(p["count"]):
        label = "".join(rng.choice(alpha) for _ in range(rng.randint(30, 60)))
        out.append(
            Ether(src=_rand_mac(rng), dst=BROADCAST_MAC)
            / IP(src=src_ip, dst=ns)
            / UDP(sport=rng.randint(1024, 65535), dport=53)
            / DNS(rd=1)
            / DNSQR(qname=f"{label}.{domain}", qtype="TXT")
        )
    return out


@_register("arp_spoof", "Gratuitous ARP announcements binding gateway IP to attacker MAC (ARP-poisoning signature).")
def _arp_spoof(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    victim_ip = p["target"]
    victim_mac = p.get("victim_mac", "aa:bb:cc:00:00:10")
    gateway_ip = p.get("gateway_ip", "192.0.2.1")
    attacker_mac = p.get("attacker_mac", "aa:bb:cc:00:00:99")
    return [
        Ether(dst=victim_mac, src=attacker_mac)
        / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwsrc=attacker_mac)
        for _ in range(p["count"])
    ]


@_register("frag_evasion", "One TCP stream shuffled into out-of-order IP fragments (reassembly-test signature).")
def _frag_evasion(rng: random.Random, p: dict[str, Any]) -> list[Packet]:
    target = p["target"]
    count = max(2, p["count"])  # fragments in the stream
    # size the payload so payload + TCP header splits into exactly `count` fragments
    payload = bytes(rng.getrandbits(8) for _ in range(512 * count - 20))
    base = (
        IP(dst=target)
        / TCP(sport=rng.randint(1024, 65535), dport=p.get("dport", 80), flags="PA")
        / Raw(payload)
    )
    frags = fragment(base, fragsize=512)
    order = list(range(len(frags)))
    rng.shuffle(order)  # out-of-order arrival: does the monitor reassemble?
    src_mac = _rand_mac(rng)
    return [Ether(src=src_mac, dst=BROADCAST_MAC) / frags[i] for i in order]


# -- public API -------------------------------------------------------------


def build_trace(
    name: str,
    *,
    seed: int = 1337,
    count: int = 50,
    target: str = "192.0.2.9",
    base_domain: str = "example.com",
    **extra: Any,
) -> tuple[list[Packet], TraceMeta]:
    """Build a scenario trace deterministically. Raises ValueError on unknown name."""
    if name not in _SCENARIOS:
        raise ValueError(
            f"unknown scenario: {name!r} (available: {', '.join(list_scenarios())})"
        )
    rng = random.Random(seed)
    params: dict[str, Any] = {
        "count": count,
        "target": target,
        "base_domain": base_domain,
        **extra,
    }
    pkts = _SCENARIOS[name][0](rng, params)
    iocs = {"target": target}
    if name == "dns_tunnel":
        iocs["queried_domain"] = base_domain
    if name == "frag_evasion":
        iocs["fragments"] = len(pkts)
    meta = TraceMeta(
        name=name,
        description=_SCENARIOS[name][1],
        params={**params, "seed": seed},
        iocs=iocs,
        count=len(pkts),
    )
    return pkts, meta


def write_trace(name: str, path: str, **kwargs: Any) -> TraceMeta:
    """Build the trace, write the pcap and a JSON metadata sidecar (<path>.json)."""
    pkts, meta = build_trace(name, **kwargs)
    out = Path(path).expanduser()
    if not out.parent.is_dir():
        # fail before touching the network-facing parts: a clean CLI error
        # beats scapy's traceback when the operator typos the output path
        raise FileNotFoundError(f"output directory does not exist: {out.parent}")
    wrpcap(str(out), pkts)
    sidecar = out.with_name(out.name + ".json")
    sidecar.write_text(
        json.dumps({"tool": "vtknet", "version": vtknet.__version__, **asdict(meta)}, indent=2),
        encoding="utf-8",
    )
    log.info("trace %s: %d packets -> %s (meta: %s)", name, meta.count, out, sidecar)
    return meta


def replay_trace(trace: str | list[Packet], iface: str, pps: float | None = None) -> int:
    """Replay a pcap file (or packet list) at wire speed via tcpreplay/sendpfast.

    Requires the ``tcpreplay`` binary and root on a real interface.
    Raises RuntimeError with a clear message on failure; returns packet count.
    """
    from scapy.sendrecv import sendpfast  # local: tcpreplay binary only needed here

    pkts = rdpcap(trace) if isinstance(trace, str) else trace
    try:
        sendpfast(pkts, pps=pps, iface=iface)
    except Exception as exc:
        raise RuntimeError(
            f"replay failed on {iface} (is tcpreplay installed and the interface up?): {exc}"
        ) from exc
    log.info("replayed %d packets on %s (pps=%s)", len(pkts), iface, pps)
    return len(pkts)
