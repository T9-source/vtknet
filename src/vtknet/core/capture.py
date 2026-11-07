"""Packet capture: live sniffing, offline pcap reading, and reply correlation.

``Capture`` wraps scapy's ``AsyncSniffer`` with a bounded ring buffer,
optional stop-timeout, and pcap I/O. Offline mode (``CaptureConfig.offline``)
reads a pcap file without root, which makes the whole capture pipeline
testable in CI.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from scapy.all import ARP, ICMP, IP, TCP, AsyncSniffer, rdpcap, wrpcap
from scapy.packet import Packet
from scapy.utils import PcapWriter
from typing_extensions import Self

from vtknet.core.models import utcnow

log = logging.getLogger("vtknet.capture")


@dataclass
class CaptureConfig:
    iface: str | None = None  # None -> scapy conf.iface (live mode only)
    filter_bpf: str | None = None  # BPF filter (needs libpcap on the system)
    promisc: bool = True
    max_packets: int = 10000  # ring buffer size; 0 = unbounded
    count: int = 0  # stop after N packets (0 = unlimited)
    timeout: float = 0.0  # stop after N seconds (0 = unlimited; live mode only)
    offline: str | None = None  # read from a pcap file instead of the wire
    stream_to: str | None = None  # stream every packet to this pcap as it arrives (never OOM)


class Capture:
    """Live or offline packet capture with a bounded in-memory buffer."""

    def __init__(self, cfg: CaptureConfig | None = None) -> None:
        self.cfg = cfg or CaptureConfig()
        maxlen = None if self.cfg.max_packets <= 0 else self.cfg.max_packets
        self._pkts: deque[Packet] = deque(maxlen=maxlen)
        self._sniffer: AsyncSniffer | None = None
        self._timer: threading.Timer | None = None
        self._writer: PcapWriter | None = (
            PcapWriter(self.cfg.stream_to, append=False, sync=True)
            if self.cfg.stream_to
            else None
        )
        self._received = 0
        self._started: str | None = None
        self._stopped: str | None = None

    # -- lifecycle -------------------------------------------------------

    def start(self) -> Capture:
        """Start the capture. Raises RuntimeError if already running."""
        if self._sniffer is not None:
            raise RuntimeError("capture already started")
        kwargs: dict = {"prn": self._on_packet, "store": False, "count": self.cfg.count}
        if self.cfg.offline:
            kwargs["offline"] = self.cfg.offline
        else:
            kwargs["iface"] = self.cfg.iface
            kwargs["promisc"] = self.cfg.promisc
        if self.cfg.filter_bpf:
            kwargs["filter"] = self.cfg.filter_bpf
        self._started = utcnow()
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()
        if self.cfg.timeout > 0 and not self.cfg.offline:
            self._timer = threading.Timer(self.cfg.timeout, self.stop)
            self._timer.daemon = True
            self._timer.start()
        return self

    def wait(self, timeout: float = 15.0) -> bool:
        """Block until the capture finishes (count reached / file done) or timeout.

        Returns True if the capture finished on its own, False if the
        deadline hit first (capture keeps running; call stop() yourself).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.cfg.count and len(self._pkts) >= self.cfg.count:
                return True
            if self._sniffer is not None and not self._sniffer.running:
                return True
            time.sleep(0.05)
        return False

    def stop(self) -> list[Packet]:
        """Stop the capture (and close any stream writer), return the buffered packets."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:  # noqa: BLE001 — scapy raises varied types when
                log.debug("sniffer already stopped: %s", exc)  # count was reached
            self._sniffer = None
        if self._writer is not None:
            self._writer.close()
            self._writer = None
            log.info("stream pcap closed: %s", self.cfg.stream_to)
        self._stopped = utcnow()
        return list(self._pkts)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- data access -----------------------------------------------------

    def _on_packet(self, pkt: Packet) -> None:
        self._received += 1
        self._pkts.append(pkt)
        if self._writer is not None:
            self._writer.write(pkt)

    def packets(self) -> list[Packet]:
        """Snapshot of the buffered packets."""
        return list(self._pkts)

    def stats(self) -> dict:
        return {
            "received": self._received,
            "kept": len(self._pkts),
            "started": self._started,
            "stopped": self._stopped,
        }

    def write_pcap(self, path: str) -> None:
        wrpcap(path, self._pkts)
        log.info("pcap written to %s (%d packets)", path, len(self._pkts))


# -- pcap I/O ----------------------------------------------------------


def load_pcap(path: str) -> list[Packet]:
    """Read a pcap file into memory (use iter_pcap for large files)."""
    return rdpcap(path)


def iter_pcap(path: str) -> Iterable[Packet]:
    """Stream packets from a pcap file one at a time (low memory footprint)."""
    from scapy.utils import PcapReader  # local import: generator-scoped file handle

    with PcapReader(path) as reader:
        yield from reader


# -- correlation -------------------------------------------------------


def match_replies(
    sent: list[Packet], seen: Iterable[Packet]
) -> list[tuple[Packet, Packet]]:
    """Match probe packets to their replies among captured packets.

    Supported probes: TCP (4-tuple), ICMP echo (id + endpoints), ARP
    (requester IP). Each reply is matched to at most one probe.
    """
    tcp_idx: dict[tuple, Packet] = {}
    icmp_idx: dict[tuple, Packet] = {}
    arp_idx: dict[str, Packet] = {}
    for rep in seen:
        if rep.haslayer(TCP) and rep.haslayer(IP):
            key = (rep[IP].src, rep[IP].dst, rep[TCP].sport, rep[TCP].dport)
            tcp_idx.setdefault(key, rep)
        elif rep.haslayer(ICMP) and rep.haslayer(IP):
            key = (rep[IP].src, rep[IP].dst, rep[ICMP].id)
            icmp_idx.setdefault(key, rep)
        elif rep.haslayer(ARP):
            arp_idx.setdefault(rep[ARP].psrc, rep)

    matches: list[tuple[Packet, Packet]] = []
    for probe in sent:
        rep = None
        if probe.haslayer(TCP) and probe.haslayer(IP):
            key = (probe[IP].dst, probe[IP].src, probe[TCP].dport, probe[TCP].sport)
            rep = tcp_idx.get(key)
        elif probe.haslayer(ICMP) and probe.haslayer(IP):
            rep = icmp_idx.get((probe[IP].dst, probe[IP].src, probe[ICMP].id))
        elif probe.haslayer(ARP):
            rep = arp_idx.get(probe[ARP].pdst)
        if rep is not None:
            matches.append((probe, rep))
    return matches
