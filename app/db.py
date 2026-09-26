# ShadowTrap - SQLite storage layer
import os
import sqlite3

DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shadowtrap.db")
DB = os.path.abspath(os.environ.get("SHADOWTRAP_DB") or DEFAULT_DB)


def get_conn():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, ip TEXT, sid TEXT, method TEXT, path TEXT,
        event_type TEXT, detail TEXT, ua TEXT);
    CREATE TABLE IF NOT EXISTS sequences(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, sid TEXT, start_ts TEXT, end_ts TEXT,
        stage_json TEXT, confidence TEXT, reasons_json TEXT,
        n_events INTEGER);
    """)
    conn.commit()
    conn.close()
