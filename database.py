"""
SQLite persistence layer for scan history (Channel: History & Reports).
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager


# Vercel serverless environment has a writable /tmp directory.
# Locally, keep the database in the project folder.
if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/sentrylink.db"
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, "sentrylink.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submitted_url TEXT NOT NULL,
    final_url TEXT,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    classification TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(SCHEMA)
        conn.commit()


def save_scan(result: dict) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO scans
            (submitted_url, final_url, score, grade, classification, result_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result["submitted_url"],
                result.get("final_url"),
                result["score"],
                result["grade"],
                result["classification"],
                json.dumps(result),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        conn.commit()
        return cur.lastrowid


def list_scans(limit: int = 50):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT id, submitted_url, final_url, score, grade,
            classification, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?""",
            (limit,),
        ).fetchall()

        return [dict(r) for r in rows]


def get_scan(scan_id: int):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

        if not row:
            return None

        data = dict(row)
        data["result"] = json.loads(data.pop("result_json"))

        return data


def delete_scan(scan_id: int) -> bool:
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM scans WHERE id = ?",
            (scan_id,)
        )

        conn.commit()
        return cur.rowcount > 0


def clear_history() -> int:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM scans")
        conn.commit()
        return cur.rowcount
