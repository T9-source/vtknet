"""Result rendering: human summary (stdout) and self-contained HTML reports."""

from __future__ import annotations

import html
import json
import logging

import vtknet
from vtknet.core.models import ScanResult

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


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
        log.info("HTML report written to %s", path)
