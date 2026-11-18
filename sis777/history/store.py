"""Inspection history (SQLite) — <system name>\\data\\history.db on the USB."""
from __future__ import annotations

import datetime as dt
import json
import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, started TEXT, finished TEXT, type TEXT,
    computer TEXT, mac TEXT, os TEXT, score INTEGER, counts TEXT, completed INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS results(run_id INTEGER, phase TEXT, code TEXT, status TEXT, mark TEXT,
    current TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS answers(run_id INTEGER, popup TEXT, question TEXT, answer TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS actions(run_id INTEGER, code TEXT, action TEXT, detail TEXT, at TEXT);
"""


def now() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class History:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.run_id: int | None = None

    def last_run_days_ago(self) -> int | None:
        q = "SELECT started FROM runs WHERE completed=1"
        args: tuple = ()
        if self.run_id:
            q += " AND id<>?"
            args = (self.run_id,)
        row = self.db.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        if not row:
            return None
        return (dt.date.today() - dt.date.fromisoformat(row[0][:10])).days

    def start(self, typ: str, computer: str, mac: str, os_label: str) -> int:
        cur = self.db.execute("INSERT INTO runs(started,type,computer,mac,os) VALUES(?,?,?,?,?)",
                              (now(), typ, computer, mac, os_label))
        self.db.commit()
        self.run_id = cur.lastrowid
        return self.run_id

    def save_results(self, phase: str, results) -> None:
        self.db.executemany("INSERT INTO results VALUES(?,?,?,?,?,?,?)",
                            [(self.run_id, phase, r.code, r.status.value, r.mark, r.current, r.note) for r in results])
        self.db.commit()

    def answer(self, popup: str, question: str, answer) -> None:
        self.db.execute("INSERT INTO answers VALUES(?,?,?,?,?)",
                        (self.run_id, popup, question, json.dumps(answer, ensure_ascii=False, default=str), now()))
        self.db.commit()

    def action(self, code: str, action: str, detail: str) -> None:
        self.db.execute("INSERT INTO actions VALUES(?,?,?,?,?)", (self.run_id, code, action, detail, now()))
        self.db.commit()

    def finish(self, score: int | None, counts: dict) -> None:
        self.db.execute("UPDATE runs SET finished=?, score=?, counts=?, completed=1 WHERE id=?",
                        (now(), score, json.dumps(counts, ensure_ascii=False), self.run_id))
        self.db.commit()

    def runs(self, limit: int = 50) -> list[tuple]:
        return self.db.execute("SELECT id, started, type, score, counts, completed FROM runs ORDER BY id DESC LIMIT ?",
                               (limit,)).fetchall()

    def close(self) -> None:
        self.db.close()
