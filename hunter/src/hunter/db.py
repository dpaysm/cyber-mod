"""SQLite layer — all requests, tests, results and notes live here (audit trail).

The TUI (reader) and the mitmproxy addon (writer) share the same file;
safe with WAL mode + locking.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

READ_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

MAX_BODY_CHARS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen     REAL    NOT NULL,
    last_seen      REAL    NOT NULL,
    host           TEXT    NOT NULL,
    method         TEXT    NOT NULL,
    url            TEXT    NOT NULL,
    path_raw       TEXT    NOT NULL,
    path_template  TEXT    NOT NULL,
    query_keys     TEXT    NOT NULL DEFAULT '',
    dedupe_key     TEXT    NOT NULL,
    req_headers    TEXT    NOT NULL DEFAULT '{}',
    req_body       TEXT    NOT NULL DEFAULT '',
    status         INTEGER,
    resp_headers   TEXT,
    resp_body      TEXT,
    count          INTEGER NOT NULL DEFAULT 1,
    suspicion      INTEGER NOT NULL DEFAULT 0,   -- filled by AI in STAGE 2
    notes          TEXT    NOT NULL DEFAULT '',  -- STAGE 5
    finding_status TEXT    NOT NULL DEFAULT ''   -- '', CONFIRMED, SUSPECT, REFUTED
);
CREATE INDEX IF NOT EXISTS idx_requests_dedupe ON requests(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_requests_id ON requests(id);

CREATE TABLE IF NOT EXISTS test_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    request_id  INTEGER NOT NULL,
    script      TEXT    NOT NULL,
    run_dir     TEXT    NOT NULL,
    verdict     TEXT    NOT NULL DEFAULT '',   -- AI verdict (no control/present/unclear)
    total_req   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_test_runs_request ON test_runs(request_id);

CREATE TABLE IF NOT EXISTS pipeline_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    stage      TEXT    NOT NULL,   -- triage / flag / escalation / k3 / error
    request_id INTEGER,
    model      TEXT    NOT NULL DEFAULT '',
    text       TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL    NOT NULL,
    request_id    INTEGER,
    host          TEXT    NOT NULL,
    path_template TEXT    NOT NULL,
    title         TEXT    NOT NULL,
    severity      TEXT    NOT NULL DEFAULT 'orta',
    status        TEXT    NOT NULL DEFAULT 'SUSPECT',  -- CONFIRMED / SUSPECT / REFUTED
    notes         TEXT    NOT NULL DEFAULT '',
    run_id        INTEGER
);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    # we patch the schema with ALTER; no alembic or anything, please
    def _migrate(self) -> None:
        """Add new columns to old databases (ALTER TABLE is not idempotent)."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(requests)")}
        if "triaged" not in cols:
            self._conn.execute(
                "ALTER TABLE requests ADD COLUMN triaged INTEGER NOT NULL DEFAULT 0"
            )
        if "triage_note" not in cols:
            self._conn.execute(
                "ALTER TABLE requests ADD COLUMN triage_note TEXT NOT NULL DEFAULT ''"
            )

    # ------------------------------------------------------------------ yazma

    def record_exchange(
        self,
        *,
        method: str,
        host: str,
        url: str,
        path_raw: str,
        path_template: str,
        query_keys: str,
        dedupe_key: str,
        req_headers: str,
        req_body: str,
        status: int | None,
        resp_headers: str | None,
        resp_body: str | None,
    ) -> tuple[int, bool]:
        """Record the exchange. Returns: (row_id, is_new_row).

        For read methods (GET/HEAD/OPTIONS) with the same dedupe key no new
        row is created; the row's counter increments and the last-seen
        response is updated. Write methods (POST/PUT/PATCH/DELETE) always
        create a new row.
        """
        now = time.time()
        method = method.upper()
        with self._lock:
            if method in READ_METHODS:
                row = self._conn.execute(
                    "SELECT id FROM requests WHERE dedupe_key = ?", (dedupe_key,)
                ).fetchone()
                if row is not None:
                    self._conn.execute(
                        """UPDATE requests
                           SET count = count + 1, last_seen = ?, url = ?, path_raw = ?,
                               req_headers = ?, req_body = ?, status = ?,
                               resp_headers = ?, resp_body = ?
                           WHERE id = ?""",
                        (now, url, path_raw, req_headers, req_body, status,
                         resp_headers, resp_body, row["id"]),
                    )
                    self._conn.commit()
                    return row["id"], False

            cur = self._conn.execute(
                """INSERT INTO requests
                   (first_seen, last_seen, host, method, url, path_raw,
                    path_template, query_keys, dedupe_key, req_headers, req_body,
                    status, resp_headers, resp_body, count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (now, now, host, method, url, path_raw, path_template, query_keys,
                 dedupe_key, req_headers, req_body, status, resp_headers, resp_body),
            )
            self._conn.commit()
            return int(cur.lastrowid), True

    # ------------------------------------------------------------------ okuma

    def list_requests(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT id, host, method, path_template, query_keys, status, "
                "count, suspicion, finding_status FROM requests ORDER BY id"
            ).fetchall()

    def get_request(self, request_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM requests WHERE id = ?", (request_id,)
            ).fetchone()

    def stats(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(count), 0) AS hits FROM requests"
            ).fetchone()
            return {"rows": int(row["n"]), "hits": int(row["hits"])}

    # ------------------------------------------------------------- STAGE 2+

    def update_suspicion(self, request_id: int, score: int) -> None:
        score = max(0, min(9, int(score)))
        with self._lock:
            self._conn.execute(
                "UPDATE requests SET suspicion = ? WHERE id = ?", (score, request_id)
            )
            self._conn.commit()

    # ------------------------------------------------------------- STAGE 3+

    def add_test_run(
        self, request_id: int, script: str, run_dir: str, total_req: int = 1
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO test_runs (ts, request_id, script, run_dir, total_req) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), request_id, script, run_dir, total_req),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def last_test_run(self, request_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM test_runs WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                (request_id,),
            ).fetchone()

    def update_test_run_verdict(self, run_id: int, verdict: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE test_runs SET verdict = ? WHERE id = ?", (verdict, run_id)
            )
            self._conn.commit()

    def get_test_run(self, run_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM test_runs WHERE id = ?", (run_id,)
            ).fetchone()

    # ------------------------------------------------------------- STAGE 4/5

    def update_notes(self, request_id: int, note: str) -> None:
        """Append the note to the existing notes (audit trail is never
        deleted)."""
        stamp = time.strftime("%Y-%m-%d %H:%M")
        with self._lock:
            row = self._conn.execute(
                "SELECT notes FROM requests WHERE id = ?", (request_id,)
            ).fetchone()
            existing = row["notes"] if row else ""
            combined = f"{existing}\n[{stamp}] {note}".strip() if existing else f"[{stamp}] {note}"
            self._conn.execute(
                "UPDATE requests SET notes = ? WHERE id = ?", (combined, request_id)
            )
            self._conn.commit()

    def add_finding(
        self,
        *,
        request_id: int | None,
        host: str,
        path_template: str,
        title: str,
        severity: str,
        status: str,
        notes: str,
        run_id: int | None,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings "
                "(ts, request_id, host, path_template, title, severity, status, notes, run_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), request_id, host.lower(), path_template, title, severity, status,
                 notes, run_id),
            )
            fid = int(cur.lastrowid)
            if request_id is not None:
                self._conn.execute(
                    "UPDATE requests SET finding_status = ? WHERE id = ?",
                    (status, request_id),
                )
            self._conn.commit()
            return fid

    def list_findings(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM findings ORDER BY id").fetchall()

    def has_confirmed_finding_for(self, host: str, path_template: str) -> bool:
        """Minimum-PoC lock: is there a CONFIRMED finding on this surface?
        (accepts the old Turkish token too)"""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM findings WHERE host = ? AND path_template = ? "
                "AND status IN ('CONFIRMED', 'DOĞRULANDI') LIMIT 1",
                (host.lower(), path_template),
            ).fetchone()
            return row is not None

    # ------------------------------------------------------------- triage line

    def untriaged_requests(self, limit: int) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM requests WHERE triaged = 0 ORDER BY id LIMIT ?",
                (limit,),
            ).fetchall()

    def mark_triaged(self, request_id: int, note: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE requests SET triaged = 1, triage_note = ? WHERE id = ?",
                (note, request_id),
            )
            self._conn.commit()

    def add_pipeline_event(
        self, stage: str, request_id: int | None, model: str, text: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO pipeline_events (ts, stage, request_id, model, text) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), stage, request_id, model, text),
            )
            self._conn.commit()

    def list_pipeline_events(self, limit: int = 100) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM (SELECT * FROM pipeline_events ORDER BY id DESC LIMIT ?) "
                "ORDER BY id",
                (limit,),
            ).fetchall()

    def clear_session_data(self, *, everything: bool = False) -> dict[str, int]:
        """Clear session records: requests + pipeline events.

        With everything=True, findings and test runs are deleted too.
        Returns the numbers of deleted rows.
        """
        tables = ["requests", "pipeline_events"]
        if everything:
            tables += ["findings", "test_runs"]
        counts: dict[str, int] = {}
        with self._lock:
            for t in tables:
                cur = self._conn.execute(f"DELETE FROM {t}")
                counts[t] = cur.rowcount
            self._conn.commit()
        return counts

    def close(self) -> None:
        with self._lock:
            self._conn.close()
