"""Result rendering: human summary (stdout) and self-contained HTML reports."""

from __future__ import annotations

import html
import json
import logging
import uuid

import vtknet
from vtknet.core.kinds import get_kind
from vtknet.core.models import Finding, ScanResult, sha256_hex

log = logging.getLogger("vtknet.report")

_SEV_CLASS = {"info": "info", "low": "low", "medium": "medium", "high": "high"}


def print_summary(result: ScanResult) -> None:
    """Print a compact aligned summary to stdout."""
    print(f"== vtk {result.command} ==")
    for f in result.findings:
        where = f"{f.host}:{f.port}" if f.port is not None else f.host
        detail = " ".join(f"{k}={v}" for k, v in f.detail.items())
        print(f"  [{f.severity.value:<6}] {f.kind:<16} {where:<24} {detail}")
    print(
        f"  -- sent={result.stats.get('sent', 0)} answered={result.stats.get('answered', 0)} "
        f"findings={len(result.findings)} duration={result.duration_s}s"
    )


def render_html(result: ScanResult) -> str:
    """Render one run as a self-contained HTML report (inline CSS, no dependencies)."""
    rows: list[str] = []
    for f in result.findings:
        where = f"{html.escape(f.host)}" + (f":{f.port}" if f.port is not None else "")
        detail = html.escape(json.dumps(f.detail, ensure_ascii=False))
        evidence = ""
        if f.evidence:
            ev = f.evidence[0]
            data = ev.data if len(ev.data) <= 96 else ev.data[:96] + "…"
            evidence = f'<span class="ev">{html.escape(ev.kind)}</span> <code>{html.escape(data)}</code>'
        cls = _SEV_CLASS.get(f.severity.value, "info")
        rows.append(
            f"<tr><td><span class='badge {cls}'>{f.severity.value}</span></td>"
            f"<td>{html.escape(f.kind)}</td><td>{where}</td>"
            f"<td><code>{detail}</code></td><td>{evidence}</td></tr>"
        )
    stat_cells = " ".join(
        f"<div class='stat'><b>{k}</b>{v}</div>" for k, v in result.stats.items()
    )
    args_json = html.escape(json.dumps(result.args, ensure_ascii=False))
    body = (
        "".join(rows)
        if rows
        else "<tr><td colspan='5' class='empty'>no findings</td></tr>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>vtknet — {html.escape(result.command)}</title>
<style>
body{{font-family:ui-monospace,Menlo,Consolas,monospace;margin:2rem;background:#111;color:#ddd}}
h1{{font-size:1.3rem}} h1 small{{color:#888;font-weight:normal}}
table{{border-collapse:collapse;width:100%;margin-top:1rem}}
td,th{{border:1px solid #333;padding:.45rem .6rem;text-align:left;font-size:.85rem;vertical-align:top}}
th{{background:#1c1c1c;color:#999}}
code{{color:#9cdcfe;word-break:break-all}}
.badge{{padding:.1rem .5rem;border-radius:.6rem;font-size:.75rem;color:#111}}
.badge.info{{background:#8ab4f8}} .badge.low{{background:#ffd479}}
.badge.medium{{background:#ffb074}} .badge.high{{background:#ff7b72}}
.stats{{display:flex;gap:.8rem;flex-wrap:wrap;margin-top:.8rem}}
.stat{{background:#1c1c1c;padding:.4rem .8rem;border-radius:.4rem;font-size:.8rem}}
.stat b{{display:block;color:#999;font-weight:normal;font-size:.7rem}}
.ev{{color:#c586c0}}
.empty{{color:#888;text-align:center}}
footer{{margin-top:1.5rem;color:#666;font-size:.75rem}}
</style></head><body>
<h1>vtknet — {html.escape(result.command)} <small>{html.escape(result.started)}</small></h1>
<div class="stats"><div class="stat"><b>duration</b>{result.duration_s}s</div>
<div class="stat"><b>findings</b>{len(result.findings)}</div>{stat_cells}</div>
<table><tr><th>severity</th><th>kind</th><th>host</th><th>detail</th><th>evidence</th></tr>
{body}</table>
<footer>vtknet {vtknet.__version__} · args: {args_json}</footer>
</body></html>"""


# SARIF 2.1.0 mapping: finding severity -> SARIF level (Trivy convention).
_SARIF_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error"}
# CVSS-like buckets GitHub derives from rule.properties["security-severity"]
# (>9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low) — Trivy's numbers.
_SARIF_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.5", "low": "2.0", "info": "0.0"}

# detail keys excluded from the stable cross-run fingerprint — the history
# diff's volatility rule plus run-variant packet facts (TTLs, ephemeral ports)
_FINGERPRINT_VOLATILE = {
    "started",
    "ended",
    "duration_s",
    "elapsed_s",
    "received",
    "kept",
    "ttl",
    "sport",
    "flags",
    "banner",
    "length",
}


def finding_fingerprint(f: Finding) -> str:
    """Stable cross-run hash of a finding's identity — the dedup key.

    A per-run uuid would close and reopen GitHub alerts on every scan;
    this hash is identical for logically identical findings (kind + host +
    port + state + the stable slice of detail) and differs on real change.
    """
    stable_detail = {
        k: v for k, v in sorted(f.detail.items()) if k not in _FINGERPRINT_VOLATILE
    }
    basis = json.dumps(
        {"kind": f.kind, "host": f.host, "port": f.port, "state": f.state, "detail": stable_detail},
        sort_keys=True,
        ensure_ascii=False,
    )
    return sha256_hex(basis)


def _result_uri(f: Finding) -> str:
    """Deterministic URI-addressable artifact (SARIF §3.4.7: hosts ARE
    deterministic; the port lives in the URI authority, not in a region)."""
    if f.host in ("-", ""):
        return "vtknet://local"
    return f"tcp://{f.host}:{f.port}" if f.port is not None else f"tcp://{f.host}"


def render_sarif(result: ScanResult) -> str:
    """Render one run as a SARIF 2.1.0 log — lands directly in the GitHub
    Security tab via the upload-sarif action (and works with VS Code,
    Visual Studio and other SARIF consumers).

    GitHub-grade details: rule metadata (descriptions + help + the
    security-severity property) is generated from the kinds registry;
    results carry the stable ``primaryLocationLineHash`` fingerprint
    GitHub actually reads for alert dedup, a deterministic
    ``correlationGuid``, and the first evidence hash anchors the claim.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in result.findings:
        spec = get_kind(f.kind)
        meaning = spec.meaning if spec else f"vtknet finding kind: {f.kind}"
        default_sev = spec.severity if spec else f.severity.value
        if f.kind not in rules:
            rules[f.kind] = {
                "id": f.kind,
                "shortDescription": {"text": meaning[:1024]},
                "fullDescription": {"text": meaning},  # required by GitHub's importer
                "help": {"text": f"{meaning} (default severity: {default_sev})"},
                "helpUri": f"https://vtknet.readthedocs.io/kinds#{f.kind}",
                "properties": {"security-severity": _SARIF_SECURITY_SEVERITY.get(default_sev, "0.0")},
            }
        fp = finding_fingerprint(f)
        results.append(
            {
                "ruleId": f.kind,
                "level": _SARIF_LEVEL.get(f.severity.value, "note"),
                "message": {
                    "text": f"[{f.module}] {f.kind} on {f.host}"
                    + (f":{f.port}" if f.port is not None else "")
                    + (f" — {f.state}" if f.state else "")
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _result_uri(f)},
                            # GitHub wants all four region fields present
                            "region": {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": fp,  # the only key GitHub reads
                    "vtknetFindingHash/v1": fp,  # versioned key per SARIF §3.27.17
                },
                "correlationGuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f"vtknet:{fp}")),
                **(
                    {
                        "properties": {
                            "evidenceSha256": f.evidence[0].sha256,
                            "evidenceNote": f.evidence[0].note,
                        }
                    }
                    if f.evidence
                    else {}
                ),
            }
        )
    log_doc = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vtknet",
                        "informationUri": "https://github.com/vtknet/vtknet",
                        "rules": sorted(rules.values(), key=lambda r: r["id"]),
                    }
                },
                "originalUriBaseIds": {
                    "SRCROOT": {"description": {"text": "probed network hosts (not source files)"}}
                },
                "results": results,
            }
        ],
    }
    return json.dumps(log_doc, indent=2, ensure_ascii=False)


def write_sarif(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_sarif(result))
    log.info("SARIF report written to %s", path)


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
        log.info("HTML report written to %s", path)
