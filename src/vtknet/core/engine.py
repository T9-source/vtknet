"""Unified send/receive engine on top of scapy.

All modules go through ``Engine`` so pacing (rate + jitter), timeouts,
retries, interface selection and dry-run behave identically everywhere.
"""

from __future__ import annotations

import logging
import random
from collections.abc import Iterator
from dataclasses import dataclass

from scapy.all import send, sendp, sr, sr1, srp, srp1
from scapy.packet import Packet

log = logging.getLogger("vtknet.engine")


@dataclass
class EngineConfig:
    iface: str | None = None  # None -> scapy conf.iface
    timeout: float = 2.0  # seconds waiting for replies
    retry: int = 1  # retransmission rounds for unanswered packets
    rate: float = 100.0  # packets per second; 0 disables pacing
    jitter: float = 0.0  # extra random delay per batch, seconds
    batch_size: int = 64  # packets per sr() call when pacing
    dry_run: bool = False  # build packets, send nothing


class Engine:
    """Send/receive with uniform behaviour. ``l2=True`` switches to srp (ARP, 802.11)."""

    def __init__(self, cfg: EngineConfig | None = None) -> None:
        self.cfg = cfg or EngineConfig()

    # -- pacing ----------------------------------------------------------

    def _inter(self) -> float:
        """Per-batch inter-packet delay: 1/rate plus uniform jitter."""
        base = 0.0 if self.cfg.rate <= 0 else 1.0 / self.cfg.rate
        if self.cfg.jitter > 0 and base > 0:
            base += random.uniform(0.0, self.cfg.jitter)
        return base

    def _chunks(self, pkts: list[Packet]) -> Iterator[list[Packet]]:
        """Split probes into batches; pacing varies per batch, not metronomic."""
        size = max(1, self.cfg.batch_size)
        for i in range(0, len(pkts), size):
            yield pkts[i : i + size]

    # -- sending ---------------------------------------------------------

    def send_recv(
        self, pkts: list[Packet], l2: bool = False, multi: bool = False
    ) -> tuple[list[tuple[Packet, Packet]], list[Packet]]:
        """Send a list of packets and collect replies.

        Returns ``(answered, unanswered)``: answered is a list of
        ``(sent, reply)`` pairs; unanswered are probes that timed out
        (including after ``retry`` rounds). ``multi=True`` collects every
        reply per probe (DHCP offers, multiple responders) instead of the
        first one.
        """
        if self.cfg.dry_run:
            return self._dry_run(pkts)
        sr_fn = srp if l2 else sr
        answered: list[tuple[Packet, Packet]] = []
        unanswered: list[Packet] = []
        for chunk in self._chunks(pkts):
            ans, unans = sr_fn(
                chunk,
                iface=self.cfg.iface,
                timeout=self.cfg.timeout,
                retry=self.cfg.retry,
                inter=self._inter(),
                verbose=0,
                multi=multi,
            )
            answered.extend(ans)
            unanswered.extend(unans)
        log.debug(
            "sent=%d answered=%d unanswered=%d", len(pkts), len(answered), len(unanswered)
        )
        return answered, unanswered

    def send1(self, pkt: Packet, l2: bool = False) -> Packet | None:
        """Send one packet, return the first reply (or None on timeout)."""
        if self.cfg.dry_run:
            log.info("dry-run: %s", pkt.summary())
            return None
        fn = srp1 if l2 else sr1
        return fn(
            pkt,
            iface=self.cfg.iface,
            timeout=self.cfg.timeout,
            retry=self.cfg.retry,
            verbose=0,
        )

    def send(self, pkts: Packet | list[Packet], l2: bool = False) -> None:
        """Fire-and-forget send (no reply collection). Honors dry-run."""
        if self.cfg.dry_run:
            single = isinstance(pkts, Packet)
            for p in [pkts] if single else pkts:
                log.info("dry-run: %s", p.summary())
            return
        fn = sendp if l2 else send
        fn(pkts, iface=self.cfg.iface, inter=self._inter(), verbose=0)

    # -- internals -------------------------------------------------------

    def _dry_run(
        self, pkts: list[Packet]
    ) -> tuple[list[tuple[Packet, Packet]], list[Packet]]:
        """Log what would be sent; return probes as unanswered. No traffic, ever."""
        log.info("dry-run: %d packet(s) would be sent, no traffic generated", len(pkts))
        for p in pkts[:10]:
            log.info("dry-run: %s", p.summary())
        if len(pkts) > 10:
            log.info("dry-run: ... and %d more", len(pkts) - 10)
        return [], list(pkts)
