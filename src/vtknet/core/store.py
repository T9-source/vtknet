"""SQLite-backed run history — the temporal memory of the toolkit.

Every network-truth run auto-persists (findings + evidence); ``diff`` compares
two runs by finding identity (module|kind|host|port) and ignores volatile
detail keys (timestamps, capture counters) so a re-run of the same scan
against the same target yields a clean, empty diff.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from vtknet.core.models import Finding, ScanResult

log = logging.getLogger("vtknet.store")

DEFAULT_DB = str(Path.home() / ".vtknet" / "history.db")

# detail keys excluded from change detection — they vary on every run by design
VOLATILE_DETAIL_KEYS = {"started", "ended", "duration_s", "elapsed_s", "received", "kept"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT NOT NULL,
    command TEXT NOT NULL,
    args_json TEXT NOT NULL,
    duration_s REAL NOT NULL,
    stats_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    module TEXT NOT NULL,
    kind TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER,
    state TEXT,
    severity TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    uid TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_uid ON findings(uid);
"""


def finding_uid(f: Finding) -> str:
    """Stable identity used for cross-run diffing."""
    return f"{f.module}|{f.kind}|{f.host}|{f.port if f.port is not None else ''}"


def _stable_detail(detail: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in detail.items() if k not in VOLATILE_DETAIL_KEYS}


class History:
    """Append-only run store. One process, one connection — CLI scale."""

    def __init__(self, path: str = DEFAULT_DB) -> None:
        self.path = path
        parent = Path(path).parent
        parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.executescript(_SCHEMA)

    # -- writes ------------------------------------------------------------

    def save_result(self, result: ScanResult) -> int:
        """Persist one run + its findings; returns the run id."""
        cur = self._conn.execute(
            "INSERT INTO runs (started, finished, command, args_json, duration_s, stats_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                result.started,
                result.finished,
                result.command,
                json.dumps(result.args, ensure_ascii=False),
                result.duration_s,
                json.dumps(result.stats),
            ),
        )
        run_id = int(cur.lastrowid)
        self._conn.executemany(
            "INSERT INTO findings (run_id, ts, module, kind, host, port, state, severity, "
            "detail_json, evidence_json, uid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    run_id,
                    f.timestamp,
                    f.module,
                    f.kind,
                    f.host,
                    f.port,
                    f.state,
                    f.severity.value,
                    json.dumps(f.detail, ensure_ascii=False),
                    json.dumps([e.to_dict() for e in f.evidence]),
                    finding_uid(f),
                )
                for f in result.findings
            ],
        )
        self._conn.commit()
        log.info("run #%d saved to history (%d findings)", run_id, len(result.findings))
        return run_id

    # -- reads ---------------------------------------------------------------

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT id, started, command, duration_s, stats_json, "
            "(SELECT COUNT(*) FROM findings WHERE run_id = runs.id) "
            "FROM runs ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r[0],
                "started": r[1],
                "command": r[2],
                "duration_s": r[3],
                "stats": json.loads(r[4]),
                "findings": r[5],
            }
            for r in rows
        ]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT id, started, finished, command, args_json, duration_s, stats_json "
            "FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        frs = self._conn.execute(
            "SELECT ts, module, kind, host, port, state, severity, detail_json, "
            "evidence_json, uid FROM findings WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        return {
            "id": row[0],
            "started": row[1],
            "finished": row[2],
            "command": row[3],
            "args": json.loads(row[4]),
            "duration_s": row[5],
            "stats": json.loads(row[6]),
            "findings": [
                {
                    "ts": f[0],
                    "module": f[1],
                    "kind": f[2],
                    "host": f[3],
                    "port": f[4],
                    "state": f[5],
                    "severity": f[6],
                    "detail": json.loads(f[7]),
                    "evidence": json.loads(f[8]),
                    "uid": f[9],
                }
                for f in frs
            ],
        }

    # -- diffing -------------------------------------------------------------

    def diff(self, run_a: int, run_b: int) -> dict[str, Any]:
        """Added / removed / changed findings between two runs (a -> b)."""
        a, b = self.get_run(run_a), self.get_run(run_b)
        if a is None or b is None:
            known = [r["id"] for r in self.list_runs(1000)]
            raise ValueError(f"unknown run id (history has: {known})")

        def index(run: dict[str, Any]) -> dict[tuple, Any]:
            out: dict[tuple, Any] = {}
            for f in run["findings"]:
                key = (f["kind"], f["host"], f["port"])
                out[key] = (f["state"], f["severity"], _stable_detail(f["detail"]))
            return out

        ia, ib = index(a), index(b)
        added = [k for k in ib if k not in ia]
        removed = [k for k in ia if k not in ib]
        changed = [k for k in ib if k in ia and ia[k] != ib[k]]
        return {
            "run_a": run_a,
            "run_b": run_b,
            "added": [{"kind": k[0], "host": k[1], "port": k[2], "detail": ib[k][2]} for k in added],
            "removed": [
                {"kind": k[0], "host": k[1], "port": k[2], "detail": ia[k][2]} for k in removed
            ],
            "changed": [
                {"kind": k[0], "host": k[1], "port": k[2], "before": ia[k][2], "after": ib[k][2]}
                for k in changed
            ],
        }

    def close(self) -> None:
        self._conn.close()
