import sqlite3
import datetime

DB_PATH = "chatsec.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    with get_connection() as conn:
        c = conn.cursor()

        c.execute("PRAGMA journal_mode=WAL")

        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                public_key    TEXT,
                mfa_secret    TEXT,
                created_at    TEXT    NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT    NOT NULL,
                level      TEXT    NOT NULL,
                event      TEXT    NOT NULL,
                details    TEXT
            )
        """)

    print("[DB] Base de données initialisée.")


def log_event(level: str, event: str, details: str = ""):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO logs (timestamp, level, event, details) VALUES (?, ?, ?, ?)",
            (timestamp, level, event, details)
        )

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


def update_mfa_secret(username: str, secret: str):
    with get_connection() as conn:
        c = conn.cursor()
        c.execute(
            "UPDATE users SET mfa_secret = ? WHERE username = ?",
            (secret, username)
        )


def get_all_usernames() -> list[str]:
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT username FROM users")
        rows = c.fetchall()

    return [r[0] for r in rows]