# AEGIS Webhook Common — Idempotency Store
# SQLite claim-by-event-id (INSERT OR IGNORE): atomic, durable, stdlib-only.
# All IP belongs to JDB Sales.
import logging
import os
import sqlite3
import threading
from pathlib import Path

logger = logging.getLogger("aegis-webhook-common")

_CLAIM_TABLE = """
CREATE TABLE IF NOT EXISTS processed_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT,
    processed_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

_lock = threading.Lock()


def _db_path() -> Path:
    # /opt/aegis/data is the app's writable dir (owned aegis:aegis). /opt/aegis
    # itself is root-owned — do NOT create the db there or claims fail silently.
    return Path(os.environ.get("AEGIS_PROCESSED_DB", "/opt/aegis/data/processed_events.db"))


def init_store() -> Path:
    """Create the store + table if missing. Returns the db path. Never fails the caller."""
    path = _db_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as con:
            con.execute(_CLAIM_TABLE)
            con.commit()
    except Exception as exc:
        logger.error("webhook idempotency store init failed (%s): %s", path, exc)
    return path


def claim(event_id: str, kind: str | None = None) -> bool:
    """
    Atomically claim an event for side-effect processing.
    Returns True if THIS caller gets the claim (first delivery),
    False if it was already processed (duplicate retry/redelivery).
    Safe under concurrency (single-writer lock + SQLite serialized writes).
    """
    if not event_id:
        return True  # no id -> cannot dedupe, behave permissively
    with _lock:
        try:
            with sqlite3.connect(_db_path(), timeout=10) as con:
                cur = con.execute(
                    "INSERT OR IGNORE INTO processed_events (event_id, kind) VALUES (?, ?)",
                    (event_id, kind),
                )
                con.commit()
                return cur.rowcount == 1
        except Exception as exc:
            logger.error("idempotency claim failed for %s: %s", event_id, exc)
            return True  # store down -> process anyway (at-least-once safety)


def is_processed(event_id: str) -> bool:
    """Read-only duplicate check (for reporting/tests)."""
    try:
        with sqlite3.connect(_db_path(), timeout=10) as con:
            cur = con.execute("SELECT 1 FROM processed_events WHERE event_id = ?", (event_id,))
            return cur.fetchone() is not None
    except Exception:
        return False


# Auto-create the store's table at import time so the first webhook never races
# a missing-table 'process anyway' fallback.
init_store()


def count_processed(kind: str | None = None) -> int:
    """Count claimed events (for tests + monitoring)."""
    try:
        with sqlite3.connect(_db_path(), timeout=10) as con:
            if kind:
                cur = con.execute("SELECT COUNT(*) FROM processed_events WHERE kind = ?", (kind,))
            else:
                cur = con.execute("SELECT COUNT(*) FROM processed_events")
            return int(cur.fetchone()[0])
    except Exception:
        return 0