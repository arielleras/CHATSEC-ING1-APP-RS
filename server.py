"""
server.py
---------
Serveur TCP + TLS de CHATSEC.
"""

import socket
import ssl
import threading
import json
import time
import pyotp
from pathlib import Path

from database import (
    init_db,
    log_event,
    get_user,
    update_public_key,
    update_mfa_secret,
)

HOST = "0.0.0.0"
PORT = 5555
CERT_FILE = str(Path(__file__).parent / "server.crt")
KEY_FILE = str(Path(__file__).parent / "server.key")

connected_clients: dict[str, ssl.SSLSocket] = {}
clients_lock = threading.Lock()

MAX_LOGIN_ATTEMPTS = 5
LOCK_TIME_SECONDS = 60

AUTH_STATE = {
    "attempt_counts": {},
    "blocked_until": {},
    "lock": threading.Lock(),
}


def send_json(sock: ssl.SSLSocket, data: dict):
    raw = json.dumps(data).encode("utf-8")
    size = len(raw).to_bytes(4, byteorder="big")
    sock.sendall(size + raw)


def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_json(sock: ssl.SSLSocket) -> dict | None:
    try:
        raw_size = _recv_exact(sock, 4)
        if raw_size is None:
            return None

        size = int.from_bytes(raw_size, byteorder="big")
        raw = _recv_exact(sock, size)
        if raw is None:
            return None

        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _get_attempt_count(username: str) -> int:
    with AUTH_STATE["lock"]:
        return AUTH_STATE["attempt_counts"].get(username, 0)


def _is_blocked(username: str) -> int:
    now = time.time()

    with AUTH_STATE["lock"]:
        blocked_until = AUTH_STATE["blocked_until"].get(username, 0)

        if blocked_until > now:
            return max(1, int(blocked_until - now))

        if username in AUTH_STATE["blocked_until"]:
            AUTH_STATE["blocked_until"].pop(username, None)
            AUTH_STATE["attempt_counts"][username] = 0

    return 0


def _register_failed_attempt(username: str) -> bool:
    with AUTH_STATE["lock"]:
        current = AUTH_STATE["attempt_counts"].get(username, 0) + 1
        AUTH_STATE["attempt_counts"][username] = current

        print(f"[DEBUG] tentative échouée pour {username}: {current}/{MAX_LOGIN_ATTEMPTS}")
        print(f"[DEBUG] id(attempt_counts) = {id(AUTH_STATE['attempt_counts'])}")
        print(f"[DEBUG] état attempt_counts = {AUTH_STATE['attempt_counts']}")
        print(f"[DEBUG] état blocked_until = {AUTH_STATE['blocked_until']}")

        if current >= MAX_LOGIN_ATTEMPTS:
            AUTH_STATE["blocked_until"][username] = time.time() + LOCK_TIME_SECONDS
            print(f"[DEBUG] compte bloqué pour {username} pendant {LOCK_TIME_SECONDS} secondes")
            print(f"[DEBUG] état blocked_until = {AUTH_STATE['blocked_until']}")
            return True

        return False


def _reset_attempts(username: str):
    with AUTH_STATE["lock"]:
        AUTH_STATE["attempt_counts"][username] = 0
        AUTH_STATE["blocked_until"].pop(username, None)

    print(f"[DEBUG] compteur réinitialisé pour {username}")
    print(f"[DEBUG] état attempt_counts = {AUTH_STATE['attempt_counts']}")
    print(f"[DEBUG] état blocked_until = {AUTH_STATE['blocked_until']}")


def handle_client(conn: ssl.SSLSocket, addr: tuple):
    username = None
    log_event("INFO", "CONNEXION_ENTREE", f"addr={addr}")

    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            action = msg.get("action")

            if action == "SIGNUP":
                _handle_signup(conn, msg)

            elif action == "LOGIN":
                username = _handle_login(conn, msg, addr)

            elif action == "UPLOAD_KEY":
                _handle_upload_key(conn, msg, username)

            elif action == "GET_KEY":
                _handle_get_key(conn, msg)

            elif action == "MESSAGE":
                _handle_message(conn, msg, username)

            elif action == "LIST_USERS":
                _handle_list_users(conn, username)

            else:
                send_json(conn, {"status": "ERROR", "message": "Action inconnue"})
                log_event("WARNING", "ACTION_INCONNUE", f"action={action}, user={username}")

    except Exception as e:
        print(f"[DEBUG] erreur client: {e}")
        log_event("ERROR", "ERREUR_CLIENT", f"user={username}, err={e}")

    finally:
        if username:
            with clients_lock:
                connected_clients.pop(username, None)
            log_event("INFO", "DECONNEXION", f"user={username}, addr={addr}")
            _broadcast_user_list()

        conn.close()


def _handle_signup(conn, msg):
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

    print(f"[DEBUG] tentative de connexion pour {username}")

    blocked_seconds = _is_blocked(username)
    if blocked_seconds > 0:
        print(f"[DEBUG] {username} est encore bloqué pendant {blocked_seconds} secondes")
        send_json(conn, {
            "status": "ERROR",
            "message": f"Compte bloqué pendant 1 minute. Réessaie dans {blocked_seconds} secondes."
        })
        log_event("WARNING", "LOGIN_BLOQUE", f"user={username}, addr={addr}, remaining={blocked_seconds}s")
        return None

    user = get_user(username)

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        is_blocked = _register_failed_attempt(username)

        if is_blocked:
            send_json(conn, {"status": "ERROR", "message": "Compte bloqué pendant 1 minute."})
            log_event("WARNING", "LOGIN_BLOQUE", f"user={username}, addr={addr}")
            return None

        remaining = MAX_LOGIN_ATTEMPTS - _get_attempt_count(username)
        log_event("WARNING", "LOGIN_ECHEC", f"user={username}, addr={addr}")
        return None

    mfa_secret = user.get("mfa_secret")

    if not mfa_secret:
        send_json(conn, {"status": "ERROR", "message": "MFA non configuré"})
        return None

    if not otp or not pyotp.TOTP(mfa_secret).verify(otp, valid_window=1):
        is_blocked = _register_failed_attempt(username)

        if is_blocked:
            send_json(conn, {"status": "ERROR", "message": "Compte bloqué pendant 1 minute."})
            log_event("WARNING", "MFA_BLOQUE", f"user={username}, addr={addr}")
            return None

        remaining = MAX_LOGIN_ATTEMPTS - _get_attempt_count(username)
        log_event("WARNING", "MFA_ECHEC", f"user={username}, addr={addr}")
        return None

    _reset_attempts(username)

    with clients_lock:
        connected_clients[username] = conn

    send_json(conn, {"status": "OK", "message": "Connecté"})
    log_event("INFO", "LOGIN_OK", f"user={username}, addr={addr}")
    print(f"[DEBUG] connexion réussie pour {username}")
    _broadcast_user_list()

    return username


def _handle_upload_key(conn, msg, username):
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
    target = msg.get("target", "")
    user = get_user(target)

    if user and user.get("public_key"):
        send_json(conn, {"status": "OK", "public_key": user["public_key"]})
    else:
        send_json(conn, {"status": "ERROR", "message": f"Clé introuvable pour {target}"})


def _handle_message(conn, msg, username):
    if not username:
        send_json(conn, {"status": "ERROR", "message": "Non authentifié"})
        return

    target = msg.get("to", "")
    content = msg.get("content", "")

    with clients_lock:
        target_conn = connected_clients.get(target)

    if target_conn:
        send_json(target_conn, {
            "action": "MESSAGE",
            "from": username,
            "content": content
        })
        send_json(conn, {"status": "OK"})
        log_event("INFO", "MESSAGE_ROUTE", f"from={username}, to={target}")
    else:
        send_json(conn, {"status": "ERROR", "message": f"{target} n'est pas connecté"})
        log_event("WARNING", "MESSAGE_ECHEC", f"from={username}, to={target} introuvable")


def _handle_list_users(conn, username):
    with clients_lock:
        users = [u for u in connected_clients.keys() if u != username]
    send_json(conn, {"status": "OK", "users": users})


def _broadcast_user_list():
    with clients_lock:
        all_users = list(connected_clients.keys())
        snapshot = dict(connected_clients)

    for uname, sock in snapshot.items():
        others = [u for u in all_users if u != uname]
        try:
            send_json(sock, {"action": "USER_LIST", "users": others})
        except Exception:
            pass


def start_server():
    init_db()
    log_event("INFO", "DEMARRAGE", f"Serveur CHATSEC sur {HOST}:{PORT}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((HOST, PORT))
    raw_sock.listen(10)

    print("### BON SERVER CHARGÉ ###")
    print(f"[CHATSEC] Serveur en écoute sur {HOST}:{PORT} (TLS)")
    print("[DEBUG] timeout actif : 5 tentatives -> blocage 1 minute")

    tls_listener = context.wrap_socket(raw_sock, server_side=True)

    try:
        while True:
            try:
                conn, addr = tls_listener.accept()
            except ssl.SSLError as e:
                log_event("WARNING", "TLS_HANDSHAKE_ECHEC", str(e))
                continue
            except OSError as e:
                log_event("ERROR", "ACCEPT_ECHEC", str(e))
                continue

            log_event("INFO", "NOUVELLE_CONNEXION", f"addr={addr}")
            print(f"[DEBUG] nouvelle connexion depuis {addr}")

            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

    except KeyboardInterrupt:
        log_event("INFO", "ARRET", "Serveur arrêté manuellement")
        print("\n[CHATSEC] Serveur arrêté.")
    finally:
        tls_listener.close()


if __name__ == "__main__":
    start_server()