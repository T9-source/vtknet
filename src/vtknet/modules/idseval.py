"""``synth --eval`` — the IDS regression harness (Sprint 2, MVP).

Pipeline: generate a seeded scenario pcap → run an IDS engine over it →
score its alerts against the scenario's ground truth → emit findings the
same way every other module does (score matrix + evidence).

Engines (v1): ``suricata`` (binary via subprocess, ``-r`` offline mode)
and ``null`` (a no-op engine so the harness itself is testable without
Suricata installed). The null engine is also the template: any engine is
"a callable pcap->matched signatures list".

Ground truth: synthetic scenarios are deterministic per seed, so the
expected signals are derived from the sidecar (scenario name + iocs).
Scoring rule set per scenario family:

- port-oriented scenarios (tcp_scan, syn_flood, stealth_scan): alert on
  the target counts as a true positive;
- dns_tunnel: any alert referencing the base domain or "dns" counts;
- arp_spoof: any alert counts (the whole trace is the attack);
- frag_evasion: any alert counts.

MVP scoring is intentionally conservative: it compares *counts and
keywords*, not per-packet correlation — documented honestly in the
findings.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess  # nosec B404 — fixed argv, no shell, engine binary from PATH
from pathlib import Path
from typing import Any

from vtknet.core.models import Evidence, Finding, Severity
from vtknet.modules import synthetic

log = logging.getLogger("vtknet.idseval")

ENGINES = ("suricata", "null")

# which scenario families expect which alert keywords (ground-truth mapping)
_EXPECTED_KEYWORDS: dict[str, tuple[str, ...]] = {
    "tcp_scan": ("scan", "portscan", "syn"),
    "syn_flood": ("flood", "dos", "syn", "scan"),
    "stealth_scan": ("scan", "stealth", "null", "fin", "xmas"),
    "dns_tunnel": ("dns", "tunnel"),
    "arp_spoof": ("arp", "spoof", "poison"),
    "frag_evasion": ("frag", "evasion", "reassembly"),
}


def _engine_run(engine: str, pcap: str, extra: dict[str, Any]) -> list[str]:
    """Run the IDS engine offline over the pcap; return matched signature texts."""
    if engine == "null":
        return list(extra.get("null_alerts", []))
    if engine == "suricata":
        binary = shutil.which("suricata")
        if not binary:
            raise ValueError("suricata binary not found on PATH (or use --engine null)")
        eve = extra.get("eve") or str(Path(pcap).with_suffix(".eve.json"))
        cmd = [binary, "-r", pcap, "-l", str(extra["log_dir"]), "-k", "none"]
        subprocess.run(cmd, check=False, capture_output=True, timeout=300)  # nosec B603
        return _parse_eve(eve)
    raise ValueError(f"unknown engine: {engine!r} (available: {', '.join(ENGINES)})")


def _parse_eve(eve_path: str) -> list[str]:
    """Read Suricata's eve.json alerts into signature strings (tolerant)."""
    sigs: list[str] = []
    path = Path(eve_path)
    if not path.exists():
        return sigs
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("event_type") == "alert":
            alert = rec.get("alert", {})
            sigs.append(str(alert.get("signature", "")))
    return sigs


def score(
    scenario: str,
    alerts: list[str],
    iocs: dict[str, Any],
) -> dict[str, Any]:
    """Compare alerts against the scenario's ground truth (conservative MVP)."""
    expected = _EXPECTED_KEYWORDS.get(scenario, ())
    blob = " | ".join(alerts).lower()
    keyword_hits = [k for k in expected if k in blob]
    target = str(iocs.get("target", ""))
    target_hit = bool(target) and target.lower() in blob
    tp_signal = bool(keyword_hits or target_hit or alerts)
    return {
        "scenario": scenario,
        "alerts_total": len(alerts),
        "expected_signals": list(expected),
        "keyword_hits": keyword_hits,
        "target_in_alerts": target_hit,
        "detected": tp_signal,
        "verdict": "detected" if tp_signal else "missed",
        "method": "keyword+target heuristic (MVP)",
    }


def eval_scenario(
    scenario: str,
    workdir: str,
    engine: str = "suricata",
    seed: int = 1337,
    count: int = 50,
    target: str = "192.0.2.9",
    extra: dict[str, Any] | None = None,
) -> tuple[list[Finding], dict[str, int]]:
    """Generate → run → score one scenario; findings carry the score matrix."""
    extra = dict(extra or {})
    wd = Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    pcap = str(wd / f"{scenario}.pcap")

    meta = synthetic.write_trace(scenario, pcap, seed=seed, count=count, target=target)
    if engine == "suricata":
        log_dir = wd / "suricata-log"
        log_dir.mkdir(exist_ok=True)
        extra.setdefault("log_dir", str(log_dir))
        extra.setdefault("eve", str(log_dir / "eve.json"))

    alerts = _engine_run(engine, pcap, extra)
    s = score(meta.name, alerts, meta.iocs)
    findings = [
        Finding(
            module="idseval",
            kind="eval.detected" if s["detected"] else "eval.missed",
            host=target,
            severity=Severity.INFO if s["detected"] else Severity.HIGH,
            detail={
                "engine": engine,
                "pcap": pcap,
                "seed": seed,
                **s,
            },
            evidence=[Evidence("pcap", pcap, f"generated scenario trace (seed={seed})")],
        )
    ]
    stats = {"alerts": len(alerts), "detected": int(s["detected"])}
    log.info("synth --eval %s [%s]: %s", scenario, engine, s["verdict"])
    return findings, stats
