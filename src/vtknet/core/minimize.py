"""Delta minimization — shrink a crashing mutant to its minimal form.

``vtk fuzz --minimize``: when the fuzzer records a crash (host stopped
answering after mutant #N), the offending packet is re-derived from the
same seed and then delta-debugged field-by-field: each header field is
reset to its benign base value and the *reduced* packet is re-fired at
the target; if the target still stops answering, the field stays reduced.
The result is the smallest packet we could reach that still kills the
target — a vendor-ready bug report in one artifact.

Termination: every field is visited once (O(fields) re-fires), a bounded
recheck per step, and the loop always ends with the last-known-crashing
packet as the answer. Reproducibility: the whole procedure is a pure
function of (seed, target, base) given the same network behavior.
"""

from __future__ import annotations

import logging

from scapy.packet import Packet

from vtknet.modules import fuzz as fuzzmod

log = logging.getLogger("vtknet.minimize")


def _field_instances(pkt: Packet) -> list[tuple[Packet, str, object]]:
    """(layer-instance, field-name, current-value) for header fields."""
    out: list[tuple[Packet, str, object]] = []
    for layer in pkt.layers():
        inst = pkt.getlayer(layer)
        for f in inst.fields_desc:
            name = f.name
            if name.endswith("chksum") or name == "options":
                continue
            try:
                out.append((inst, name, inst.getfieldval(name)))
            except Exception as exc:  # noqa: BLE001 — a hostile field is simply skipped
                log.debug("field %s unreadable: %s", name, exc)
                continue
    return out


def minimize_crash(
    crashing: Packet,
    base: Packet,
    refire,  # Callable[[Packet], bool] — True = target still crashes
    max_steps: int = 64,
) -> dict:
    """Greedy ddmin over packet fields; ``refire`` decides crash reproduction.

    Returns {packet, removed: [field...], steps, minimal: bool}. The
    returned packet is the smallest observed crashing variant.
    """
    current = crashing.copy()
    removed: list[str] = []
    steps = 0
    candidates = _field_instances(crashing)
    # align candidates to the *crashing* packet's values (base supplies benign values)
    base_map = {}
    for layer, name, val in _field_instances(base):
        base_map[(id(layer.__class__), name)] = val

    for inst, name, _val in candidates:
        if steps >= max_steps:
            break
        benign = base_map.get((id(inst.__class__), name))
        if benign is None:
            continue
        original = inst.getfieldval(name)
        if original == benign:
            continue
        trial = current.copy()
        t_inst = trial.getlayer(inst.__class__)
        try:
            t_inst.setfieldval(name, benign)
        except Exception as exc:  # noqa: BLE001 — a rejecting field is not a minimizer failure
            log.debug("minimize: field %s rejected reset: %s", name, exc)
            continue
        steps += 1
        if refire(trial):
            # still crashing without this field's mutation → keep it reduced
            current = trial
            removed.append(name)
            log.debug("minimize: removed %s", name)

    return {
        "packet": current,
        "removed": removed,
        "steps": steps,
        "minimal": len(removed) > 0,
    }


def minimize_from_seed(
    engine,  # vtknet.core.engine.Engine
    dst: str,
    base: str,
    port: int | None,
    seed: int,
    crash_index: int,
    recheck_delay: float = 0.3,
) -> dict:
    """Rebuild the crashing mutant from (seed, index) and minimize it live."""
    base_pkt = fuzzmod._base_packet(dst, base, port, __import__("random").Random(seed))
    crashing = list(fuzzmod.fuzz_variants(base_pkt, crash_index + 1, seed))[crash_index]

    def refire(trial: Packet) -> bool:
        engine.send([trial])
        import time

        time.sleep(recheck_delay)
        return engine.send1(__import__("scapy.all", fromlist=["IP"]).IP(dst=dst) / __import__("scapy.all", fromlist=["ICMP"]).ICMP()) is None

    return minimize_crash(crashing, base_pkt, refire)
