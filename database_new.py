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
def create_public_keys_table(self):

    cursor = self.conn.cursor()

    cursor.execute('''

        CREATE TABLE IF NOT EXISTS user_public_keys (

            username TEXT PRIMARY KEY,

            public_key_pem TEXT NOT NULL,

            algorithm TEXT DEFAULT 'RSA-2048',

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )

    ''')

    self.conn.commit()


import sqlite3
from datetime import datetime


class Database:
    """Version augmentée avec support des clés publiques RSA."""

    def __init__(self, db_name='chatsec.db'):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name, check_same_thread=False)

        # Créer les tables
        self.create_users_table()
        self.create_public_keys_table()  # NOUVEAU

    def create_public_keys_table(self):
        """
        Crée la table pour stocker les clés publiques RSA.

        Schema:
        -------
        - username: Clé primaire, lien vers les utilisateurs
        - public_key_pem: La clé publique en format PEM/base64
        - algorithm: L'algorithme utilisé (ex: RSA-2048)
        - created_at: Date de création
        - updated_at: Dernière mise à jour
        """
        cursor = self.conn.cursor()
        cursor.execute('''
              CREATE TABLE IF NOT EXISTS user_public_keys (
                  username TEXT PRIMARY KEY,
                  public_key_pem TEXT NOT NULL,
                  algorithm TEXT DEFAULT 'RSA-2048',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (username) REFERENCES users(username)
              )
          ''')
        self.conn.commit()
        print("[DB] Table user_public_keys créée/vérifiée")

        # =========================================================================
        # OPÉRATIONS CRUD : Clés publiques
        # =========================================================================

    def save_user_public_key(self, username, public_key_pem, algorithm='RSA-2048'):
        """
        Sauvegarde ou met à jour la clé publique d'un utilisateur.

        Args:
            username (str): Nom d'utilisateur
            public_key_pem (str): Clé publique en format PEM
            algorithm (str): Algorithme (par défaut RSA-2048)
        """
        cursor = self.conn.cursor()
        cursor.execute('''
              INSERT OR REPLACE INTO user_public_keys 
              (username, public_key_pem, algorithm, updated_at)
              VALUES (?, ?, ?, ?)
          ''', (username, public_key_pem, algorithm, datetime.now()))
        self.conn.commit()

    def get_user_public_key(self, username):
        """
        Récupère la clé publique d'un utilisateur.

        Args:
            username (str): Nom d'utilisateur

        Returns:
            str: Clé publique en PEM, ou None si non trouvée
        """
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT public_key_pem FROM user_public_keys WHERE username = ?',
            (username,)
        )
        result = cursor.fetchone()
        return result[0] if result else None

    def get_all_public_keys(self):
        """
        Récupère TOUTES les clés publiques.

        Utilisé au démarrage du serveur pour charger en mémoire.

        Returns:
            list: [(username, public_key_pem), ...]
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT username, public_key_pem FROM user_public_keys')
        return cursor.fetchall()

    def delete_user_public_key(self, username):
        """
        Supprime la clé publique d'un utilisateur.

        Args:
            username (str): Nom d'utilisateur
        """
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM user_public_keys WHERE username = ?', (username,))
        self.conn.commit()

    def get_public_key_info(self, username):
        """
        Récupère les infos complètes de la clé publique.

        Returns:
            dict: {
                'username': str,
                'algorithm': str,
                'created_at': str,
                'updated_at': str
            }
        """
        cursor = self.conn.cursor()
        cursor.execute('''
              SELECT username, algorithm, created_at, updated_at 
              FROM user_public_keys WHERE username = ?
          ''', (username,))
        result = cursor.fetchone()

        if result:
            return {
                'username': result[0],
                'algorithm': result[1],
                'created_at': result[2],
                'updated_at': result[3]
            }
        return None

        # =========================================================================
        # UTILITAIRES
        # =========================================================================

    def count_public_keys(self):
        """Retourne le nombre de clés publiques stockées."""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM user_public_keys')
        return cursor.fetchone()[0]

    def list_all_users_with_keys(self):
        """Liste tous les utilisateurs avec une clé publique."""
        cursor = self.conn.cursor()
        cursor.execute('''
              SELECT u.username, pk.algorithm, pk.updated_at
              FROM users u
              LEFT JOIN user_public_keys pk ON u.username = pk.username
          ''')
        return cursor.fetchall()

    def export_public_keys_backup(self, filepath='public_keys_backup.json'):
        """
        Exporte tous les clés publiques dans un fichier JSON.
        Utile pour sauvegarde ou migration.

        Args:
            filepath (str): Chemin du fichier de destination
        """
        import json

        keys = {}
        for username, public_key_pem in self.get_all_public_keys():
            keys[username] = public_key_pem

        with open(filepath, 'w') as f:
            json.dump(keys, f, indent=2)

        print(f"[DB] Clés exportées dans {filepath}")

    def import_public_keys_backup(self, filepath):
        """
        Importe les clés publiques depuis un fichier JSON.

        Args:
            filepath (str): Chemin du fichier JSON
        """
        import json

        with open(filepath, 'r') as f:
            keys = json.load(f)

        for username, public_key_pem in keys.items():
            self.save_user_public_key(username, public_key_pem)

        print(f"[DB] {len(keys)} clés importées depuis {filepath}")

    def close(self):
        """Ferme la connexion à la base de données."""
        self.conn.close()
