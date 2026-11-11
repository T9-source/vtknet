"""Blindspots — every report declares the boundaries of its own knowledge.

A scan that gets no reply cannot distinguish "closed" from "filtered"; a
sweep without answers cannot distinguish "down" from "silent". Pretending
otherwise manufactures false confidence. ``blindspots_for`` appends
epistemic findings to a finished result: what was probed, what came back
unresolved, and why. The most honest report in the market.
"""

from __future__ import annotations

import logging

from vtknet.core.models import Finding, ScanResult, Severity

log = logging.getLogger("vtknet.blindspot")


def blindspots_for(result: ScanResult) -> list[Finding]:
    """Epistemic-boundary findings for one finished run (never fatal)."""
    out: list[Finding] = []
    stats = result.stats

    if result.command == "scan":
        filtered = int(stats.get("filtered", 0))
        if filtered:
            out.append(
                Finding(
                    module="blindspot",
                    kind="blindspot.unresolved-ports",
                    host=str(result.args.get("target", "-")),
                    severity=Severity.INFO,
                    detail={
                        "ports": filtered,
                        "note": "no reply — open vs closed is indistinguishable under filtering",
                    },
                )
            )
    elif result.command == "sweep":
        sent = int(stats.get("sent", 0))
        answered = int(stats.get("answered", 0))
        silent = sent - answered
        if silent > 0:
            out.append(
                Finding(
                    module="blindspot",
                    kind="blindspot.silent-hosts",
                    host=str(result.args.get("target", "-")),
                    severity=Severity.INFO,
                    detail={
                        "hosts": silent,
                        "note": "no ICMP reply — down or filtered, unknowable from here",
                    },
                )
            )
    elif result.command == "tls":
        unknown = sum(
            1 for f in result.findings if f.kind in ("tls.no-response", "tls.no-data")
        )
        if unknown:
            out.append(
                Finding(
                    module="blindspot",
                    kind="blindspot.cert-unknown",
                    host=str(result.args.get("target", "-")),
                    severity=Severity.INFO,
                    detail={
                        "targets": unknown,
                        "note": "no ServerHello — certificate health is unknown, not good",
                    },
                )
            )
    elif result.command == "banner":
        nodata = sum(1 for f in result.findings if f.kind == "banner.no-connection")
        if nodata:
            out.append(
                Finding(
                    module="blindspot",
                    kind="blindspot.port-state-unknown",
                    host=str(result.args.get("target", "-")),
                    severity=Severity.INFO,
                    detail={
                        "targets": nodata,
                        "note": "conversation could not open — port state stays unknown",
                    },
                )
            )
    if out:
        log.info("blindspots: %d epistemic finding(s) appended", len(out))
    return out
