import socket
import ssl
import threading
import time
import json
import uuid
from pathlib import Path

import bcrypt
import pyotp

from database import (
    init_db,
    log_event,
    get_user,
    update_public_key,
    username_exists_anywhere,
    upsert_pending_signup,
    get_pending_signup,
    delete_pending_signup,
    create_user_with_mfa,
    create_session,
    delete_session,
)

from logger_config import setup_logger

logger = setup_logger()

from dotenv import load_dotenv
import os

load_dotenv()

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 5555))

CERT_FILE = str(Path(__file__).parent / os.getenv("CERT_FILE", "server.crt"))
KEY_FILE = str(Path(__file__).parent / os.getenv("KEY_FILE", "server.key"))

DB_NAME = os.getenv("DB_NAME", "chatsec.db")

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
LOCK_TIME_SECONDS = int(os.getenv("LOCK_TIME_SECONDS", 60))

connected_clients: dict[str, ssl.SSLSocket] = {}
clients_lock = threading.Lock()

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
        with AUTH_STATE["lock"]:
            AUTH_STATE["blocked_until"].pop(username, None)
            AUTH_STATE["attempt_counts"][username] = 0

    return 0


def _register_failed_attempt(username: str) -> bool:
    with AUTH_STATE["lock"]:
        current = AUTH_STATE["attempt_counts"].get(username, 0) + 1
        AUTH_STATE["attempt_counts"][username] = current

        if current >= MAX_LOGIN_ATTEMPTS:
            AUTH_STATE["blocked_until"][username] = time.time() + LOCK_TIME_SECONDS
            return True

    return False


def _reset_attempts(username: str):
    with AUTH_STATE["lock"]:
        AUTH_STATE["attempt_counts"][username] = 0
        AUTH_STATE["blocked_until"].pop(username, None)


def handle_client(conn: ssl.SSLSocket, addr: tuple):
    username = None
    log_event("INFO", "CONNEXION_ENTREE", f"addr={addr}")
    logger.info(f"CONNEXION_ENTREE | addr={addr}")

    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            action = msg.get("action")

            if action == "CHECK_USERNAME":
                _handle_check_username(conn, msg)

            elif action == "SIGNUP_PREPARE":
                _handle_signup_prepare(conn, msg)

            elif action == "SIGNUP_CONFIRM":
                _handle_signup_confirm(conn, msg)

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
        log_event("ERROR", "ERREUR_CLIENT", f"user={username}, err={e}")
        logger.error(f"ERREUR_CLIENT | user={username}, err={e}")

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
            logger.info(f"DECONNEXION | user={username}, addr={addr}")

            _broadcast_user_list()
        conn.close()


def _handle_check_username(conn, msg):
    username = msg.get("username", "").strip()
    exists = username_exists_anywhere(username)

    logger.info(f"CHECK_USERNAME | username={username} exists={exists}")

    if len(username) < 2:
        send_json(conn, {"status": "ERROR", "message": "Nom d'utilisateur trop court."})
        return

    if exists:
        send_json(conn, {"status": "ERROR", "message": "Nom d'utilisateur déjà pris."})
        return

    send_json(conn, {"status": "OK", "message": "Nom d'utilisateur disponible."})


def _handle_signup_prepare(conn, msg):
    username = msg.get("username", "").strip()
    password = msg.get("password", "")

    if not username or not password:
        send_json(conn, {"status": "ERROR", "message": "Username ou mot de passe vide"})
        return

    if len(username) < 2:
        send_json(conn, {"status": "ERROR", "message": "Nom d'utilisateur trop court."})
        return

    if username_exists_anywhere(username):
        send_json(conn, {"status": "ERROR", "message": "Nom d'utilisateur déjà pris."})
        return

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    mfa_secret = pyotp.random_base32()

    upsert_pending_signup(username, password_hash, mfa_secret)

    mfa_uri = pyotp.TOTP(mfa_secret).provisioning_uri(
        name=username,
        issuer_name="CHATSEC"
    )

    send_json(conn, {
        "status": "OK",
        "message": "QR code MFA prêt.",
        "mfa_uri": mfa_uri
    })
    log_event("INFO", "SIGNUP_PREPARE_OK", f"user={username}")
    logger.info(f"SIGNUP_PREPARE_OK | user={username}")


def _handle_signup_confirm(conn, msg):
    username = msg.get("username", "").strip()
    otp = msg.get("otp", "").strip()

    if not username or not otp:
        send_json(conn, {"status": "ERROR", "message": "Username ou code MFA vide"})
        return

    pending = get_pending_signup(username)
    if not pending:
        send_json(conn, {"status": "ERROR", "message": "Aucune inscription en attente."})
        return

    mfa_secret = pending["mfa_secret"]

    if not pyotp.TOTP(mfa_secret).verify(otp, valid_window=1):
        send_json(conn, {"status": "ERROR", "message": "Code MFA invalide."})
        log_event("WARNING", "SIGNUP_CONFIRM_ECHEC", f"user={username}")
        return

    if get_user(username) is not None:
        delete_pending_signup(username)
        send_json(conn, {"status": "ERROR", "message": "Nom d'utilisateur déjà pris."})
        return

    ok = create_user_with_mfa(username, pending["password_hash"], mfa_secret)
    if not ok:
        send_json(conn, {"status": "ERROR", "message": "Impossible de créer le compte."})
        return

    delete_pending_signup(username)

    send_json(conn, {
        "status": "OK",
        "message": "Compte créé avec succès."
    })
    log_event("INFO", "SIGNUP_CONFIRM_OK", f"user={username}")
    logger.info(f"SIGNUP_CONFIRM_OK | user={username}")


def _handle_login(conn, msg, addr) -> str | None:
    username = msg.get("username", "").strip()
    password = msg.get("password", "")
    otp = msg.get("otp", "").strip()

    blocked_seconds = _is_blocked(username)
    if blocked_seconds > 0:
        send_json(conn, {
            "status": "ERROR",
            "message": f"Compte bloqué pendant 1 minute. Réessaie dans {blocked_seconds} secondes."
        })
        log_event("WARNING", "LOGIN_BLOQUE", f"user={username}, addr={addr}, remaining={blocked_seconds}s")
        return None

    user = get_user(username)

    # Vérification mot de passe bcrypt
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        is_blocked = _register_failed_attempt(username)

        if is_blocked:
            send_json(conn, {"status": "ERROR", "message": "Compte bloqué pendant 1 minute."})
            log_event("WARNING", "LOGIN_BLOQUE", f"user={username}, addr={addr}")
            logger.warning(f"LOGIN_BLOQUE | user={username}, addr={addr}")
            return None

        remaining = MAX_LOGIN_ATTEMPTS - _get_attempt_count(username)
        send_json(conn, {
            "status": "ERROR",
            "message": f"Identifiants incorrects. Il reste {remaining} tentative(s)."
        })
        log_event("WARNING", "LOGIN_ECHEC", f"user={username}, addr={addr}")
        logger.warning(f"LOGIN_ECHEC | user={username}, addr={addr}")
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
        send_json(conn, {
            "status": "ERROR",
            "message": f"Code MFA incorrect. Il reste {remaining} tentative(s)."
        })
        log_event("WARNING", "MFA_ECHEC", f"user={username}, addr={addr}")
        return None

    session_id = str(uuid.uuid4())
    if not create_session(username, session_id):
        send_json(conn, {
            "status": "ERROR",
            "message": "Cet utilisateur est déjà connecté sur un autre appareil."
        })
        log_event("WARNING", "LOGIN_DOUBLE_SESSION", f"user={username}, addr={addr}")
        return None

    _reset_attempts(username)

    with clients_lock:
        connected_clients[username] = conn

    send_json(conn, {"status": "OK", "message": "Connecté"})
    log_event("INFO", "LOGIN_OK", f"user={username}, addr={addr}")
    logger.info(f"LOGIN_OK | user={username}, addr={addr}")
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
    signature = msg.get("signature", "")  # ← ajoute ça

    with clients_lock:
        target_conn = connected_clients.get(target)

    if target_conn:
        send_json(target_conn, {
            "action": "MESSAGE",
            "from": username,
            "content": content,
            "signature": signature
        })
        send_json(conn, {"status": "OK"})
        log_event("INFO", "MESSAGE_ROUTE", f"from={username}, to={target}")
        logger.info(f"MESSAGE_ROUTE | from={username}, to={target}")
    else:
        send_json(conn, {"status": "ERROR", "message": f"{target} n'est pas connecté"})
        log_event("WARNING", "MESSAGE_ECHEC", f"from={username}, to={target} introuvable")
        logger.warning(f"MESSAGE_ECHEC | from={username}, to={target}")

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

    logger.info(f"SERVEUR_ECOUTE | {HOST}:{PORT} TLS actif")

    tls_listener = context.wrap_socket(raw_sock, server_side=True)

    try:
        while True:
            try:
                conn, addr = tls_listener.accept()
            except ssl.SSLError as e:
                log_event("WARNING", "TLS_HANDSHAKE_ECHEC", str(e))
                logger.warning(f"TLS_HANDSHAKE_ECHEC | {e}")
                continue
            except OSError as e:
                log_event("ERROR", "ACCEPT_ECHEC", str(e))
                logger.error(f"ACCEPT_ECHEC | {e}")
                continue

            log_event("INFO", "NOUVELLE_CONNEXION", f"addr={addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

    except KeyboardInterrupt:
        log_event("INFO", "ARRET", "Serveur arrêté manuellement")
        logger.info("SERVEUR_ARRETE")
    finally:
        tls_listener.close()


if __name__ == "__main__":
    start_server()