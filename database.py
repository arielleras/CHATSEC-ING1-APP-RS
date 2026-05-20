"""
database.py
-----------
Initialise la base SQLite et fournit les fonctions
d'accès pour les utilisateurs et les logs.

Tables :
  - users  : stocke les comptes (username, hash bcrypt, clé publique RSA, secret MFA)
  - logs   : enregistre tous les événements serveur
"""

import sqlite3
import datetime

DB_PATH = "chatsec.db"

# ── Initialisation ────────────────────────────────────────────────

def init_db():
    """Crée les tables si elles n'existent pas encore."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Table utilisateurs
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

    # Table logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT    NOT NULL,
            level      TEXT    NOT NULL,
            event      TEXT    NOT NULL,
            details    TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Base de données initialisée.")

# ── Logs ──────────────────────────────────────────────────────────

def log_event(level: str, event: str, details: str = ""):
    """
    Enregistre un événement dans la table logs.

    level   : INFO | WARNING | ERROR
    event   : description courte (ex: 'CONNEXION', 'ECHEC_LOGIN')
    details : informations complémentaires (optionnel)
    """
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO logs (timestamp, level, event, details) VALUES (?, ?, ?, ?)",
        (timestamp, level, event, details)
    )
    conn.commit()
    conn.close()
    # Affiche aussi dans le terminal pour le débogage
    print(f"[{level}] {timestamp} | {event} | {details}")

# ── Utilisateurs ──────────────────────────────────────────────────

def create_user(username: str, password_hash: str) -> bool:
    """
    Crée un utilisateur. Retourne True si succès, False si username déjà pris.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, created_at)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        # Username déjà existant (contrainte UNIQUE)
        return False

def get_user(username: str) -> dict | None:
    """
    Récupère un utilisateur par son username.
    Retourne un dict ou None si introuvable.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # permet d'accéder par nom de colonne
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def update_public_key(username: str, public_key_pem: str):
    """Stocke ou met à jour la clé publique RSA d'un utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET public_key = ? WHERE username = ?",
        (public_key_pem, username)
    )
    conn.commit()
    conn.close()

def update_mfa_secret(username: str, secret: str):
    """Stocke le secret TOTP d'un utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE users SET mfa_secret = ? WHERE username = ?",
        (secret, username)
    )
    conn.commit()
    conn.close()

def get_all_usernames() -> list[str]:
    """Retourne la liste de tous les usernames enregistrés."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username FROM users")
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]
