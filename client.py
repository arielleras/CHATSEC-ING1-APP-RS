"""
client.py
---------
Client TCP + TLS de CHATSEC.
"""

import socket
import ssl
import json
import threading
import os
import base64
import queue

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ── Configuration ─────────────────────────────────────────────────

SERVER_HOST      = "127.0.0.1"
SERVER_PORT      = 5555
PRIVATE_KEY_FILE = "my_private.pem"
PUBLIC_KEY_FILE  = "my_public.pem"

# ── Clés RSA ──────────────────────────────────────────────────────

def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = RSA.import_key(f.read())
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = RSA.import_key(f.read())
        print("[CLE] Clés RSA chargées depuis le disque.")
    else:
        print("[CLE] Génération d'une nouvelle paire de clés RSA-2048...")
        private_key = RSA.generate(2048)
        public_key  = private_key.publickey()
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.export_key())
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.export_key())
        print("[CLE] Clés RSA générées et sauvegardées.")
    return private_key, public_key

# ── Chiffrement / Déchiffrement ───────────────────────────────────

def encrypt_message(message: str, recipient_public_key_pem: str) -> str:
    recipient_key = RSA.import_key(recipient_public_key_pem.encode())
    cipher = PKCS1_OAEP.new(recipient_key)
    encrypted = cipher.encrypt(message.encode("utf-8"))
    return base64.b64encode(encrypted).decode("utf-8")

def decrypt_message(encrypted_b64: str, private_key) -> str:
    encrypted = base64.b64decode(encrypted_b64.encode("utf-8"))
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted).decode("utf-8")

# ── Framing JSON ──────────────────────────────────────────────────

def send_json(sock, data: dict):
    raw  = json.dumps(data).encode("utf-8")
    size = len(raw).to_bytes(4, byteorder="big")
    sock.sendall(size + raw)

def recv_json(sock) -> dict | None:
    try:
        raw_size = _recv_exact(sock, 4)
        if raw_size is None:
            return None
        size = int.from_bytes(raw_size, byteorder="big")
        raw  = _recv_exact(sock, size)
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def _recv_exact(sock, n: int) -> bytes | None:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# ── Classe Client ─────────────────────────────────────────────────

class ChatClient:

    def __init__(self):
        self.sock         = None
        self.username     = None
        self.private_key  = None
        self.public_key   = None
        self.running      = False
        self.on_message   = None
        self.on_user_list = None

        # File d'attente pour les réponses aux requêtes
        # (sépare les réponses serveur des messages entrants)
        self._response_queue = queue.Queue()

    # ── Connexion ─────────────────────────────────────────────────

    def connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE
        raw_sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock  = context.wrap_socket(raw_sock, server_hostname=SERVER_HOST)
        self.sock.connect((SERVER_HOST, SERVER_PORT))
        print(f"[TLS] Connecté au serveur {SERVER_HOST}:{SERVER_PORT}")

    def disconnect(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    # ── Thread de réception ───────────────────────────────────────

    def _receive_loop(self):
        """
        Thread unique qui lit TOUS les messages entrants et les trie :
        - Messages et USER_LIST → callbacks
        - Réponses serveur (status OK/ERROR) → file d'attente
        """
        while self.running:
            try:
                msg = recv_json(self.sock)
                if msg is None:
                    print("[INFO] Connexion au serveur perdue.")
                    self.running = False
                    break

                action = msg.get("action")

                if action == "MESSAGE":
                    # Message chiffré d'un autre utilisateur
                    sender    = msg.get("from", "?")
                    encrypted = msg.get("content", "")
                    try:
                        plaintext = decrypt_message(encrypted, self.private_key)
                    except Exception:
                        plaintext = "[Message illisible]"
                    if self.on_message:
                        self.on_message(sender, plaintext)
                    else:
                        print(f"\n[MESSAGE] {sender} : {plaintext}")

                elif action == "USER_LIST":
                    # Broadcast liste utilisateurs
                    users = msg.get("users", [])
                    if self.on_user_list:
                        self.on_user_list(users)
                    else:
                        print(f"[CONNECTÉS] {users}")

                else:
                    # Réponse à une requête → file d'attente
                    self._response_queue.put(msg)

            except Exception as e:
                if self.running:
                    print(f"[ERREUR] Réception : {e}")
                break

    def _send_request(self, data: dict, timeout: float = 5.0) -> dict | None:
        """
        Envoie une requête et attend la réponse via la file d'attente.
        Le thread de réception place la réponse dans la queue.
        """
        send_json(self.sock, data)
        try:
            return self._response_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ── Authentification ──────────────────────────────────────────

    def signup(self, username: str, password: str) -> tuple[bool, str]:
        send_json(self.sock, {
            "action":   "SIGNUP",
            "username": username,
            "password": password
        })
        resp = recv_json(self.sock)
        if resp and resp.get("status") == "OK":
            return True, resp.get("message", "Compte créé")
        return False, resp.get("message", "Erreur") if resp else "Pas de réponse"

    def login(self, username: str, password: str) -> tuple[bool, str]:
        # Démarrer le thread AVANT le login
        # pour qu'il gère le USER_LIST broadcast qui suit immédiatement
        self.running = True
        t = threading.Thread(target=self._receive_loop, daemon=True)
        t.start()

        resp = self._send_request({
            "action":   "LOGIN",
            "username": username,
            "password": password
        })

        if resp and resp.get("status") == "OK":
            self.username = username
            self.private_key, self.public_key = load_or_generate_keys()
            self._upload_public_key()
            return True, "Connecté"

        self.running = False
        return False, resp.get("message", "Erreur") if resp else "Pas de réponse"

    def _upload_public_key(self):
        pub_pem = self.public_key.export_key().decode("utf-8")
        resp = self._send_request({
            "action":     "UPLOAD_KEY",
            "public_key": pub_pem
        })
        if resp and resp.get("status") == "OK":
            print("[CLE] Clé publique déposée sur le serveur.")
        else:
            print("[ERREUR] Impossible de déposer la clé publique.")

    # ── Envoi de messages ─────────────────────────────────────────

    def send_message(self, to: str, message: str) -> tuple[bool, str]:
        recipient_key = self._get_public_key(to)
        if not recipient_key:
            return False, f"Impossible de récupérer la clé de {to}"
        try:
            encrypted = encrypt_message(message, recipient_key)
        except Exception as e:
            return False, f"Erreur chiffrement : {e}"
        resp = self._send_request({
            "action":  "MESSAGE",
            "to":      to,
            "content": encrypted
        })
        if resp and resp.get("status") == "OK":
            return True, "Message envoyé"
        return False, resp.get("message", "Erreur") if resp else "Pas de réponse"

    def _get_public_key(self, username: str) -> str | None:
        resp = self._send_request({
            "action": "GET_KEY",
            "target": username
        })
        if resp and resp.get("status") == "OK":
            return resp.get("public_key")
        return None

    def get_connected_users(self) -> list[str]:
        resp = self._send_request({"action": "LIST_USERS"})
        if resp and resp.get("status") == "OK":
            return resp.get("users", [])
        return []


# ── Test terminal ─────────────────────────────────────────────────

if __name__ == "__main__":
    import getpass

    client = ChatClient()
    try:
        client.connect()
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter : {e}")
        exit(1)

    print("\n=== CHATSEC — Mode Terminal ===")
    print("1. Créer un compte")
    print("2. Se connecter")
    choix    = input("Choix : ").strip()
    username = input("Username : ").strip()
    password = getpass.getpass("Mot de passe : ")

    if choix == "1":
        ok, msg = client.signup(username, password)
        print(f"[SIGNUP] {msg}")
        if not ok:
            client.disconnect()
            exit(1)
        ok, msg = client.login(username, password)
    else:
        ok, msg = client.login(username, password)

    print(f"[LOGIN] {msg}")
    if not ok:
        client.disconnect()
        exit(1)

    print(f"\n[OK] Connecté en tant que {username}")
    print("Commandes : 'users' | 'quit' | @username message\n")

    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip().lower() == "quit":
            break
        elif line.strip().lower() == "users":
            print(f"[CONNECTÉS] {client.get_connected_users()}")
        elif line.startswith("@"):
            parts = line[1:].split(" ", 1)
            if len(parts) == 2:
                to, message = parts
                ok, msg = client.send_message(to, message)
                print(f"[ENVOI → {to}] {msg}")
            else:
                print("Format : @username message")
        else:
            print("Format : @username message")

    client.disconnect()