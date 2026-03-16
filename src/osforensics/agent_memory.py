"""Evidence store and episodic memory for the investigation agent.

All data is persisted to SQLite at ~/.osforensics/agent_memory.db so
investigation history survives server restarts.

Tables
------
sessions   – one row per investigation session
episodes   – ordered ReAct steps (thought → action → observation)
evidence   – structured artifacts extracted by tools
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path.home() / ".osforensics" / "agent_memory.db"

# ── Connection ─────────────────────────────────────────────────────────────────

_conn: Optional[sqlite3.Connection] = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _init(_conn)
    return _conn


def _init(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id         TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            query      TEXT,
            status     TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS episodes (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL,
            step        INTEGER NOT NULL,
            timestamp   REAL NOT NULL,
            thought     TEXT,
            action      TEXT,
            args        TEXT,
            observation TEXT
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            item_type   TEXT NOT NULL,
            source      TEXT,
            data        TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ep_session ON episodes(session_id);
        CREATE INDEX IF NOT EXISTS idx_ev_session ON evidence(session_id);
    """)
    conn.commit()


def _uid() -> str:
    return uuid.uuid4().hex[:10]


# ── Public API ─────────────────────────────────────────────────────────────────

def create_session(query: str = "") -> str:
    """Create a new investigation session and return its ID."""
    sid = _uid()
    _db().execute(
        "INSERT INTO sessions (id, created_at, query) VALUES (?, ?, ?)",
        (sid, time.time(), query),
    )
    _db().commit()
    return sid


def add_episode(
    session_id: str,
    step: int,
    thought: str,
    action: str,
    args: Dict[str, Any],
    observation: Dict[str, Any],
) -> str:
    """Append a ReAct step to the episode log."""
    eid = _uid()
    _db().execute(
        "INSERT INTO episodes "
        "  (id, session_id, step, timestamp, thought, action, args, observation) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            eid, session_id, step, time.time(),
            thought, action,
            json.dumps(args, default=str),
            json.dumps(observation, default=str),
        ),
    )
    _db().commit()
    return eid


def store_evidence(
    session_id: str,
    item_type: str,
    data: Dict[str, Any],
    source: str = "",
) -> str:
    """Store a structured evidence artifact."""
    eid = _uid()
    _db().execute(
        "INSERT INTO evidence (id, session_id, timestamp, item_type, source, data) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (eid, session_id, time.time(), item_type, source, json.dumps(data, default=str)),
    )
    _db().commit()
    return eid


def get_episodes(session_id: str) -> List[Dict]:
    """Return all ReAct steps for a session, ordered by step number."""
    rows = _db().execute(
        "SELECT * FROM episodes WHERE session_id = ? ORDER BY step",
        (session_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["args"]        = json.loads(d["args"]        or "{}")
        d["observation"] = json.loads(d["observation"] or "{}")
        result.append(d)
    return result


def get_evidence(session_id: str, item_type: Optional[str] = None) -> List[Dict]:
    """Return all evidence items for a session, optionally filtered by type."""
    q = "SELECT * FROM evidence WHERE session_id = ?"
    params: list = [session_id]
    if item_type:
        q += " AND item_type = ?"
        params.append(item_type)
    rows = _db().execute(q + " ORDER BY timestamp", params).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["data"] = json.loads(d["data"])
        result.append(d)
    return result


def get_sessions(limit: int = 20) -> List[Dict]:
    """Return the most recent sessions."""
    rows = _db().execute(
        "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def clear_session(session_id: str) -> None:
    """Delete all episodes and evidence for a session."""
    db = _db()
    db.execute("DELETE FROM episodes WHERE session_id = ?", (session_id,))
    db.execute("DELETE FROM evidence  WHERE session_id = ?", (session_id,))
    db.execute("UPDATE sessions SET status = 'cleared' WHERE id = ?", (session_id,))
    db.commit()
