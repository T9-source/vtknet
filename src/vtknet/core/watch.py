"""``vtk watch`` — scheduled network-truth rounds with diffing (Sprint 3 MVP).

One watch profile = a probe plan (module + args) + a diff policy. Each
round runs the plan through the normal CLI machinery, stores the result
in the history DB (so all existing tooling works), and diffs it against
the previous round of the same profile; changes above the severity floor
become ``watch.change`` findings ready for a webhook.

v1 scope (honest): single process, one-shot ``--once`` or interval loop,
webhook = POST-JSON (Discord/Slack/Telegram-compatible gateways are all
just HTTP POST endpoints with different body shapes — v1 sends the raw
findings JSON; adapters come with the TUI sprint).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen  # stdlib only

from vtknet.core.models import Finding, Severity
from vtknet.core.store import History

log = logging.getLogger("vtknet.watch")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def default_profile() -> dict[str, Any]:
    """The v1 built-in profile: ICMP sweep + a few TCP ports, then diff."""
    return {
        "name": "default",
        "interval_s": 300,
        "min_severity": "low",
        "webhook": None,
        "rounds": [
            {"module": "sweep", "args": {"target": "192.168.1.0/24"}},
            {"module": "scan", "args": {"target": "192.168.1.1", "ports": "22,80,443"}},
        ],
    }


def round_argv(module: str, args: dict[str, Any]) -> list[str]:
    """Build the CLI argv for one probe round (pure, testable)."""
    argv = []
    for k, v in args.items():
        flag = "--" + k.replace("_", "-")
        if isinstance(v, bool):
            if v:
                argv.append(flag)
        else:
            argv += [flag, str(v)]
    return argv


def diff_rounds(history: History, prev_id: int, last_id: int, min_severity: str) -> list[Finding]:
    """Diff two runs and keep changes at/above the severity floor."""
    d = history.diff(prev_id, last_id)
    floor = SEVERITY_ORDER.get(min_severity, 1)
    out: list[Finding] = []
    for category in ("added", "removed", "changed"):
        for item in d[category]:
            kind = f"watch.{category}"
            sev = Severity.LOW if category != "changed" else Severity.MEDIUM
            if SEVERITY_ORDER.get(sev.value, 0) < floor:
                continue
            out.append(
                Finding(
                    module="watch",
                    kind=kind,
                    host=item["host"],
                    port=item["port"],
                    severity=sev,
                    detail={"kind": item["kind"], "round_b": last_id, "round_a": prev_id, **item},
                )
            )
    return out


def notify_webhook(url: str, payload: dict[str, Any], timeout: float = 10.0) -> bool:
    """POST the change findings to a webhook; failures log, never crash the loop."""
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=timeout) as resp:  # nosec B310 — operator-supplied https URL
            ok = 200 <= resp.status < 300
    except (URLError, TimeoutError, OSError) as exc:
        log.warning("webhook delivery failed: %s", exc)
        return False
    if not ok:
        log.warning("webhook returned %s", resp.status)
    return ok


def watch_once(profile: dict[str, Any], db_path: str) -> tuple[list[Finding], dict[str, int]]:
    """Run every round in the profile once; diff each against its previous round."""
    from vtknet import cli

    history = History(db_path)
    findings: list[Finding] = []
    stats: dict[str, int] = {"rounds": 0, "changes": 0}
    try:
        for rnd in profile.get("rounds", []):
            module, rargs = rnd["module"], dict(rnd.get("args", {}))
            # a watch round is identified by command+args so diffing keys right
            before = history.find_last_run(
                module, target=rargs.get("target") or rargs.get("name")
            )
            argv = round_argv(module, rargs)
            rc = cli.main(argv)
            stats["rounds"] += 1
            if rc != 0:
                log.warning("round %s exited %s — skipped", module, rc)
                continue
            after = history.find_last_run(
                module, target=rargs.get("target") or rargs.get("name")
            )
            if before is not None and after is not None and after != before:
                changes = diff_rounds(history, before, after, profile.get("min_severity", "low"))
                findings.extend(changes)
                stats["changes"] += len(changes)
        hook = profile.get("webhook")
        if hook and findings:
            notify_webhook(
                hook,
                {"profile": profile.get("name", "default"), "changes": [f.to_dict() for f in findings]},
            )
    finally:
        history.close()
    return findings, stats


def watch_loop(profile: dict[str, Any], db_path: str, once: bool = False) -> None:
    """The loop; Ctrl-C stops it cleanly."""
    interval = float(profile.get("interval_s", 300))
    while True:
        try:
            _, stats = watch_once(profile, db_path)
            log.info("watch round done: %s", stats)
        except Exception as exc:  # noqa: BLE001 — a failed round must not kill the daemon
            log.error("watch round failed: %s", exc)
        if once:
            return
        time.sleep(interval)


def load_profile(path: str | None) -> dict[str, Any]:
    """Load a profile JSON (or the built-in default when path is None)."""
    if not path:
        return default_profile()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rounds" not in data:
        raise ValueError(f"watch profile needs a 'rounds' list: {path}")
    return data
