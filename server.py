"""
server.py
---------
Serveur TCP + TLS de CHATSEC.

Rôle :
  - Écoute les connexions sur le port 5555
  - Enveloppe chaque connexion avec TLS (certificat auto-signé)
  - Gère chaque client dans un thread séparé
  - Route les messages chiffrés entre clients (sans jamais les déchiffrer)
  - Logue tous les événements dans SQLite via database.py

Lancement :
  python server.py

Prérequis :
  1. Avoir lancé generate_cert.py (produit server.crt + server.key)
  2. Avoir installé les dépendances (pip install -r requirements.txt)
"""

import socket
import ssl
import threading
import json
import pyotp
import uuid
from pathlib import Path

from database import (
    init_db, log_event, get_user, update_public_key,
    get_all_usernames, update_mfa_secret,
    create_session, delete_session
)

# ── Configuration ─────────────────────────────────────────────────

HOST = "0.0.0.0"   # écoute sur toutes les interfaces réseau
PORT = 5555
CERT_FILE = str(Path(__file__).parent / "server.crt")
KEY_FILE  = str(Path(__file__).parent / "server.key")

# Dictionnaire des clients connectés : { username: ssl_socket }
# Partagé entre tous les threads → protégé par un verrou
connected_clients: dict[str, ssl.SSLSocket] = {}
clients_lock = threading.Lock()

# ── Envoi d'un message JSON ───────────────────────────────────────

def send_json(sock: ssl.SSLSocket, data: dict):
    """
    Sérialise un dict en JSON et l'envoie sur le socket.
    On préfixe avec la taille du message (4 octets) pour savoir
    où s'arrête chaque message (framing).
    """
    raw = json.dumps(data).encode("utf-8")
    # Préfixe : taille sur 4 octets, big-endian
    size = len(raw).to_bytes(4, byteorder="big")
    sock.sendall(size + raw)

def recv_json(sock: ssl.SSLSocket) -> dict | None:
    """
    Lit exactement un message JSON depuis le socket.
    Retourne None si la connexion est fermée.
    """
    try:
        # 1. Lire les 4 premiers octets = taille du message
        raw_size = _recv_exact(sock, 4)
        if raw_size is None:
            return None
        size = int.from_bytes(raw_size, byteorder="big")

        # 2. Lire exactement 'size' octets = le message
        raw = _recv_exact(sock, size)
        if raw is None:
            return None

        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes | None:
    """Lit exactement n octets depuis le socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ── Gestion d'un client ───────────────────────────────────────────

def handle_client(conn: ssl.SSLSocket, addr: tuple):
    """
    Fonction exécutée dans un thread pour chaque client connecté.
    Gère toute la session : login, échange de messages, déconnexion.
    """
    username = None
    log_event("INFO", "CONNEXION_ENTREE", f"addr={addr}")

    try:
        while True:
            msg = recv_json(conn)

            # Connexion fermée côté client
            if msg is None:
                break

            action = msg.get("action")

            # ── Inscription ───────────────────────────────────────
            if action == "SIGNUP":
                _handle_signup(conn, msg)

            # ── Connexion ─────────────────────────────────────────
            elif action == "LOGIN":
                username = _handle_login(conn, msg, addr)

            # ── Dépôt de clé publique RSA ─────────────────────────
            elif action == "UPLOAD_KEY":
                _handle_upload_key(conn, msg, username)

            # ── Demande de clé publique d'un autre user ───────────
            elif action == "GET_KEY":
                _handle_get_key(conn, msg)

            # ── Envoi d'un message chiffré à un autre user ────────
            elif action == "MESSAGE":
                _handle_message(conn, msg, username)

            # ── Liste des utilisateurs connectés ──────────────────
            elif action == "LIST_USERS":
                _handle_list_users(conn, username)

            # ── Action inconnue ───────────────────────────────────
            else:
                send_json(conn, {"status": "ERROR", "message": "Action inconnue"})
                log_event("WARNING", "ACTION_INCONNUE", f"action={action}, user={username}")

    except Exception as e:
        log_event("ERROR", "ERREUR_CLIENT", f"user={username}, err={e}")

    finally:
        # Chercher le username par socket si non défini
        if not username:
            with clients_lock:
                for u, s in list(connected_clients.items()):
                    if s is conn:
                        username = u
                        break

        if username:
            with clients_lock:
                connected_clients.pop(username, None)
            delete_session(username)
            log_event("INFO", "DECONNEXION", f"user={username}, addr={addr}")
            _broadcast_user_list()
        conn.close()

# ── Handlers des actions ──────────────────────────────────────────

def _handle_signup(conn, msg):
    """Inscription d'un nouvel utilisateur."""
    import bcrypt
    from database import create_user

    username = msg.get("username", "").strip()
    password = msg.get("password", "")

    if not username or not password:
        send_json(conn, {"status": "ERROR", "message": "Username ou mot de passe vide"})
        return

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    if create_user(username, password_hash):
        mfa_secret = pyotp.random_base32()

        update_mfa_secret(username, mfa_secret)

        mfa_uri = pyotp.TOTP(mfa_secret).provisioning_uri(
            name=username,
            issuer_name="CHATSEC"
        )

        send_json(conn, {
            "status": "OK",
            "message": "Compte créé. Scannez le QR code MFA.",
            "mfa_uri": mfa_uri
        })

        log_event("INFO", "SIGNUP_OK", f"user={username}")
    else:
        send_json(conn, {"status": "ERROR", "message": "Username déjà pris"})
        log_event("WARNING", "SIGNUP_ECHEC", f"user={username} déjà existant")


def _handle_login(conn, msg, addr) -> str | None:
    import bcrypt

    username = msg.get("username", "").strip()
    password = msg.get("password", "")
    otp = msg.get("otp", "").strip()

    user = get_user(username)

    mfa_secret = user.get("mfa_secret")

    if not mfa_secret:
        send_json(conn, {"status": "ERROR", "message": "MFA non configuré"})
        return None

    if not otp or not pyotp.TOTP(mfa_secret).verify(otp, valid_window=1):
        send_json(conn, {"status": "ERROR", "message": "Code MFA incorrect"})
        log_event("WARNING", "MFA_ECHEC", f"user={username}, addr={addr}")
        return None

    """Génère un identifiant unique de session"""
    session_id = str(uuid.uuid4())
    if not create_session(username, session_id):
        send_json(conn, {
            "status": "ERROR",
            "message": "Cet utilisateur est déjà connecté sur un autre appareil."
        })
        log_event("WARNING", "LOGIN_DOUBLE_SESSION", f"user={username}, addr={addr}")
        return None, None


    with clients_lock:
        connected_clients[username] = conn

    send_json(conn, {"status": "OK", "message": "Connecté"})
    log_event("INFO", "LOGIN_OK", f"user={username}, addr={addr}")
    _broadcast_user_list()

    return username


def _handle_upload_key(conn, msg, username):
    """Le client dépose sa clé publique RSA sur le serveur."""
    if not username:
        send_json(conn, {"status": "ERROR", "message": "Non authentifié"})
        return

    public_key = msg.get("public_key", "")
    if not public_key:
        send_json(conn, {"status": "ERROR", "message": "Clé manquante"})
        return

    update_public_key(username, public_key)
    send_json(conn, {"status": "OK", "message": "Clé publique enregistrée"})
    log_event("INFO", "UPLOAD_KEY", f"user={username}")


def _handle_get_key(conn, msg):
    """Retourne la clé publique RSA d'un utilisateur donné."""
    target = msg.get("target", "")
    user = get_user(target)

    if user and user.get("public_key"):
        send_json(conn, {"status": "OK", "public_key": user["public_key"]})
    else:
        send_json(conn, {"status": "ERROR", "message": f"Clé introuvable pour {target}"})


def _handle_message(conn, msg, username):
    """
    Route un message chiffré vers son destinataire.
    Le serveur NE DÉCHIFFRE PAS le contenu — il fait suivre tel quel.
    """
    if not username:
        send_json(conn, {"status": "ERROR", "message": "Non authentifié"})
        return

    target   = msg.get("to", "")
    content  = msg.get("content", "")  # contenu RSA-OAEP chiffré en base64

    with clients_lock:
        target_conn = connected_clients.get(target)

    if target_conn:
        # Transmettre le message au destinataire
        send_json(target_conn, {
            "action":  "MESSAGE",
            "from":    username,
            "content": content   # chiffré, le serveur ne voit rien
        })
        send_json(conn, {"status": "OK"})
        log_event("INFO", "MESSAGE_ROUTE", f"from={username}, to={target}")
    else:
        send_json(conn, {"status": "ERROR", "message": f"{target} n'est pas connecté"})
        log_event("WARNING", "MESSAGE_ECHEC", f"from={username}, to={target} introuvable")


def _handle_list_users(conn, username):
    """Envoie la liste des utilisateurs actuellement connectés."""
    with clients_lock:
        users = [u for u in connected_clients.keys() if u != username]
    send_json(conn, {"status": "OK", "users": users})


def _broadcast_user_list():
    """Envoie la liste des connectés à TOUS les clients (mise à jour en temps réel)."""
    with clients_lock:
        all_users = list(connected_clients.keys())
        snapshot  = dict(connected_clients)

    for uname, sock in snapshot.items():
        others = [u for u in all_users if u != uname]
        try:
            send_json(sock, {"action": "USER_LIST", "users": others})
        except Exception:
            pass  # client déconnecté entre temps, ignoré

# ── Démarrage du serveur ──────────────────────────────────────────

def start_server():
    init_db()
    log_event("INFO", "DEMARRAGE", f"Serveur CHATSEC sur {HOST}:{PORT}")

    # Contexte TLS : charge le certificat et la clé
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Socket TCP brut
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    raw_sock.listen(10)

    print(f"[CHATSEC] Serveur en écoute sur {HOST}:{PORT} (TLS)")

    # Envelopper le socket d'écoute avec TLS
    tls_sock = context.wrap_socket(raw_sock, server_side=True)

    try:
        while True:
            # Accepter une nouvelle connexion TLS
            try:
                conn, addr = tls_sock.accept()
            except ssl.SSLError as e:
                log_event("WARNING", "TLS_HANDSHAKE_ECHEC", str(e))
                continue
            except OSError as e:
                log_event("ERROR", "ACCEPT_ECHEC", str(e))
                continue
            log_event("INFO", "NOUVELLE_CONNEXION", f"addr={addr}")

            # Lancer un thread dédié pour ce client
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

    except KeyboardInterrupt:
        log_event("INFO", "ARRET", "Serveur arrêté manuellement")
        print("\n[CHATSEC] Serveur arrêté.")
    finally:
        tls_sock.close()

if __name__ == "__main__":
    start_server()
