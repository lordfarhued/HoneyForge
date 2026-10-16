from __future__ import annotations

import json
import sqlite3
from pathlib import Path


class DurableQueue:
    def __init__(self, path: str, max_events: int = 10_000):
        if not 1 <= max_events <= 1_000_000:
            raise ValueError("max_events must be between 1 and 1000000")
        self.max_events = max_events
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS event_queue (
                event_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS configurations (
                instance_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS processed_jobs (
                job_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                result_json TEXT NOT NULL,
                processed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS engine_state (
                instance_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        self.connection.commit()

    def enqueue(self, event: dict) -> bool:
        event_id = event["external_id"]
        if self.connection.execute(
            "SELECT 1 FROM event_queue WHERE event_id = ?", (event_id,)
        ).fetchone():
            return True
        if self.depth() >= self.max_events:
            return False
        cursor = self.connection.execute(
            "INSERT OR IGNORE INTO event_queue(event_id, payload_json) VALUES (?, ?)",
            (event_id, json.dumps(event, separators=(",", ":"), ensure_ascii=False)),
        )
        self.connection.commit()
        return cursor.rowcount > 0

    def pending(self, limit: int) -> list[dict]:
        rows = self.connection.execute(
            "SELECT payload_json FROM event_queue ORDER BY rowid LIMIT ?", (limit,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        self.connection.executemany("DELETE FROM event_queue WHERE event_id = ?", [(value,) for value in event_ids])
        self.connection.commit()

    def depth(self) -> int:
        return int(self.connection.execute("SELECT count(*) FROM event_queue").fetchone()[0])

    def store_configuration(self, instance_id: str, version: int, payload: dict) -> bool:
        current = self.connection.execute(
            "SELECT version FROM configurations WHERE instance_id = ?", (instance_id,)
        ).fetchone()
        changed = current is None or int(current[0]) != version
        if changed:
            self.connection.execute(
                """INSERT INTO configurations(instance_id, version, payload_json) VALUES (?, ?, ?)
                   ON CONFLICT(instance_id) DO UPDATE SET version=excluded.version,
                   payload_json=excluded.payload_json, updated_at=CURRENT_TIMESTAMP""",
                (instance_id, version, json.dumps(payload, separators=(",", ":"), ensure_ascii=False)),
            )
            self.connection.commit()
        return changed

    def configurations(self) -> list[dict]:
        rows = self.connection.execute(
            "SELECT payload_json FROM configurations ORDER BY instance_id"
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def configuration(self, instance_id: str) -> dict | None:
        row = self.connection.execute(
            "SELECT payload_json FROM configurations WHERE instance_id = ?", (instance_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def remove_stale_configurations(self, active_instance_ids: set[str]) -> None:
        current = {
            row[0] for row in self.connection.execute("SELECT instance_id FROM configurations").fetchall()
        }
        stale = current - active_instance_ids
        if not stale:
            return
        self.connection.executemany(
            "DELETE FROM configurations WHERE instance_id = ?", [(value,) for value in stale]
        )
        self.connection.executemany(
            "DELETE FROM engine_state WHERE instance_id = ?", [(value,) for value in stale]
        )
        self.connection.commit()

    def engine_enabled(self, instance_id: str) -> bool:
        row = self.connection.execute(
            "SELECT enabled FROM engine_state WHERE instance_id = ?", (instance_id,)
        ).fetchone()
        return bool(row[0]) if row else False

    def set_engine_enabled(self, instance_id: str, enabled: bool) -> None:
        self.connection.execute(
            """INSERT INTO engine_state(instance_id, enabled) VALUES (?, ?)
               ON CONFLICT(instance_id) DO UPDATE SET enabled=excluded.enabled,
               updated_at=CURRENT_TIMESTAMP""",
            (instance_id, int(enabled)),
        )
        self.connection.commit()

    def get_job_result(self, job_id: str) -> tuple[str, dict] | None:
        row = self.connection.execute(
            "SELECT state, result_json FROM processed_jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def store_job_result(self, job_id: str, state: str, result: dict) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO processed_jobs(job_id, state, result_json) VALUES (?, ?, ?)",
            (job_id, state, json.dumps(result, separators=(",", ":"), ensure_ascii=False)),
        )
        self.connection.commit()
