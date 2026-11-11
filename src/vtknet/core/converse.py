"""Bounded I/O over scapy ``TCP_client`` links.

scapy automaton supersockets block in ``recv()`` until data or FIN — a
server that accepts the connection and then stays silent would hang a
probe forever. ``link_recv_bounded`` enforces the deadline from the
caller's side: the read runs on a helper thread, and if the deadline
passes the link is closed underneath the reader, which unblocks it
(automaton stop + socket close).
"""

from __future__ import annotations

import logging
import threading

log = logging.getLogger("vtknet.converse")


def link_recv_bounded(link: object, timeout: float) -> bytes:
    """Read once from a scapy conversation link within ``timeout`` seconds.

    Returns the received bytes, or ``b""`` on timeout/error — callers
    treat ``b""`` as "no data", never as a crash. Closing the link from
    this side is what unblocks a stuck reader; never leave a
    conversation open past its budget.
    """
    if timeout <= 0:
        timeout = 0.1  # a zero budget is a polite no-wait read, not a hang
    result: list[bytes] = []
    done = threading.Event()

    def _read() -> None:
        try:
            chunk = link.recv()  # type: ignore[attr-defined]
            result.append(bytes(chunk) if chunk else b"")
        except Exception as exc:  # noqa: BLE001 — any failure is simply "no data"
            log.debug("bounded link recv: %s", exc)
            result.append(b"")
        finally:
            done.set()

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    if not done.wait(timeout):
        try:
            link.close()  # type: ignore[attr-defined]  # forces the blocked recv out
        except Exception as exc:  # noqa: BLE001 — double-close must not crash us
            log.debug("bounded link close: %s", exc)
        done.wait(timeout)  # brief grace for the reader to notice and exit
        return b""
    return result[0] if result else b""
