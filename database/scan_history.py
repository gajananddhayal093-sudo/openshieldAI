import sqlite3
from datetime import datetime


DB_FILE = "database/openshield.db"


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        scan_type TEXT,
        risk TEXT,
        score INTEGER,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


def save_scan(target, scan_type, risk, score):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans
    (target, scan_type, risk, score, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        target,
        scan_type,
        risk,
        score,
        datetime.utcnow().isoformat()
    ))

    conn.commit()
    conn.close()


def get_history(limit=10):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, target, scan_type, risk, score, created_at
    FROM scans
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    return rows
