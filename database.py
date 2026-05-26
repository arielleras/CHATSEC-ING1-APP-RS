import sqlite3
import datetime
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

DB_NAME = os.getenv("DB_NAME", "chatsec.db")
DB_PATH = str(Path(__file__).parent / DB_NAME)


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    print(f"[DB] Base utilisée : {Path(DB_PATH).resolve()}")

    with get_connection() as conn:
        c = conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            mfa_secret TEXT,
            created_at TEXT NOT NULL
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS pending_signups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            mfa_secret TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            event TEXT NOT NULL,
            details TEXT
        )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS active_sessions (
                username   TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                started_at TEXT NOT NULL
            )
        """)
        c.execute("DELETE FROM active_sessions")

        conn.commit()

    print("[DB] Base de données initialisée.")


def log_event(level: str, event: str, details: str = ""):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO logs (timestamp, level, event, details) VALUES (?, ?, ?, ?)",
            (timestamp, level, event, details)
        )
        conn.commit()

    print(f"[{level}] {timestamp} | {event} | {details}")


def create_user(username: str, password_hash: str) -> bool:
    try:
        created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        with get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, created_at)
            )
            conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False


def create_user_with_mfa(username: str, password_hash: str, mfa_secret: str) -> bool:
    try:
        created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        with get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password_hash, mfa_secret, created_at) VALUES (?, ?, ?, ?)",
                (username, password_hash, mfa_secret, created_at)
            )
            conn.commit()
        return True

    except sqlite3.IntegrityError:
        return False


def get_user(username: str) -> dict | None:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        return dict(row) if row else None


def update_public_key(username: str, public_key_pem: str):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE users SET public_key = ? WHERE username = ?",
            (public_key_pem, username)
        )
        conn.commit()


def update_mfa_secret(username: str, secret: str):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE users SET mfa_secret = ? WHERE username = ?",
            (secret, username)
        )
        conn.commit()


def get_all_usernames() -> list[str]:
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        rows = c.fetchall()

    return [r[0] for r in rows]


def create_session(username: str, session_id: str) -> bool:
    """
    Crée une session pour `username`. Si une session existe déjà,
    retourne False (connexion refusée — déjà connecté).
    """
    try:
        started_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        with get_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO active_sessions (username, session_id, started_at) VALUES (?, ?, ?)",
                (username, session_id, started_at)
            )
        return True
    except sqlite3.IntegrityError:
        return False  # username déjà présent → déjà connecté


def delete_session(username: str):
    """Supprime la session à la déconnexion."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM active_sessions WHERE username = ?", (username,))


def get_session(username: str) -> dict | None:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM active_sessions WHERE username = ?", (username,))
        row = c.fetchone()
    return dict(row) if row else None

def username_exists_anywhere(username: str) -> bool:
    with get_connection() as conn:
        c = conn.cursor()

        c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if c.fetchone():
            return True

        c.execute("SELECT 1 FROM pending_signups WHERE username = ?", (username,))
        if c.fetchone():
            return True

        return False


def upsert_pending_signup(username: str, password_hash: str, mfa_secret: str):
    created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM pending_signups WHERE username = ?", (username,))
        c.execute(
            "INSERT INTO pending_signups (username, password_hash, mfa_secret, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, mfa_secret, created_at)
        )
        conn.commit()


def get_pending_signup(username: str) -> dict | None:
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM pending_signups WHERE username = ?", (username,))
        row = c.fetchone()
        return dict(row) if row else None


def delete_pending_signup(username: str):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM pending_signups WHERE username = ?", (username,))
        conn.commit()