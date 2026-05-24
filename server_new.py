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
import json
from rsa_signature import RSASignatureManager
import socket
import ssl
import threading
import json
import pyotp
from pathlib import Path

from database import init_db, log_event, get_user, update_public_key, get_all_usernames, update_mfa_secret

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
        # Nettoyage : retirer le client de la liste des connectés
        if username:
            with clients_lock:
                connected_clients.pop(username, None)
            log_event("INFO", "DECONNEXION", f"user={username}, addr={addr}")
            _broadcast_user_list()  # mettre à jour la liste chez tous
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

    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        send_json(conn, {"status": "ERROR", "message": "Identifiants incorrects"})
        log_event("WARNING", "LOGIN_ECHEC", f"user={username}, addr={addr}")
        return None

    mfa_secret = user.get("mfa_secret")

    if not mfa_secret:
        send_json(conn, {"status": "ERROR", "message": "MFA non configuré"})
        return None

    if not otp or not pyotp.TOTP(mfa_secret).verify(otp, valid_window=1):
        send_json(conn, {"status": "ERROR", "message": "Code MFA incorrect"})
        log_event("WARNING", "MFA_ECHEC", f"user={username}, addr={addr}")
        return None

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

    def __init__(self, host='127.0.0.1', port=5555):
        # ... code existant ...
        self.host = host
        self.port = port
        self.clients = {}  # username -> socket

        # ========== NOUVEAU : RSA ==========
        self.user_public_keys = {}  # username -> public_key_pem
        self.rsa_validator = RSASignatureManager()
        # ====================================

        self.db = Database()
        self.db.create_users_table()
        self.db.create_public_keys_table()  # NOUVEAU

        # Charger les clés publiques depuis la DB
        self._load_public_keys_from_db()

    # =========================================================================
    # MÉTHODE 1 : Charger les clés publiques depuis la DB
    # =========================================================================

    def _load_public_keys_from_db(self):
        """
        Au démarrage du serveur, charger toutes les clés publiques
        depuis la base de données en mémoire.
        """
        public_keys = self.db.get_all_public_keys()

        for username, public_key_pem in public_keys:
            self.user_public_keys[username] = public_key_pem
            print(f"[RSA] Clé publique chargée pour {username}")

    # =========================================================================
    # MÉTHODE 2 : Enregistrer la clé publique d'un client
    # =========================================================================

    def _register_public_key(self, username, public_key_pem):
        """
        Enregistre et sauvegarde la clé publique d'un client.

        Étapes:
        1. Valider que c'est une clé RSA valide
        2. Sauvegarder en mémoire
        3. Sauvegarder en base de données
        4. Notifier les autres clients

        Args:
            username (str): Nom de l'utilisateur
            public_key_pem (str): Clé publique en format base64/PEM
        """
        try:
            # Valider la clé
            public_key = self.rsa_validator.pem_string_to_public_key(public_key_pem)

            # Stocker en mémoire
            self.user_public_keys[username] = public_key_pem

            # Sauvegarder en DB
            self.db.save_user_public_key(username, public_key_pem)

            print(f"[RSA] ✓ Clé publique enregistrée pour {username}")

            # Notifier les autres clients
            self._broadcast_public_key(username, public_key_pem)

        except Exception as e:
            print(f"[RSA] ✗ Erreur lors de l'enregistrement: {e}")

    # =========================================================================
    # MÉTHODE 3 : Envoyer la clé publique à tous les clients
    # =========================================================================

    def _broadcast_public_key(self, username, public_key_pem):
        """
        Envoie la clé publique d'un utilisateur à tous les autres clients.

        Cela permet à tous les clients de vérifier les signatures
        de cet utilisateur.

        Args:
            username (str): Utilisateur dont on partage la clé
            public_key_pem (str): Clé à partager
        """
        notification = {
            'type': 'public_key',
            'username': username,
            'public_key': public_key_pem
        }

        message = json.dumps(notification)

        # Envoyer à tous les clients connectés
        for client_username, client_socket in self.clients.items():
            if client_username != username:  # Pas à l'expéditeur
                try:
                    self._send_to_client(client_socket, message)
                except Exception as e:
                    print(f"[ERREUR] Impossible d'envoyer à {client_username}: {e}")

    # =========================================================================
    # MÉTHODE 4 : Relayer un message privé SIGNÉ et CHIFFRÉ
    # =========================================================================

    def _relay_signed_private_message(self, packet):
        """
        Relaye un message privé signé et chiffré.

        Important: Le serveur NE DÉCHIFFRE PAS le contenu.
        Il se contente de le relayer.

        Le destinataire vérifiera la signature lui-même.

        Args:
            packet (dict): Paquet contenant:
                - sender: Expéditeur
                - recipient: Destinataire
                - encrypted_content: Contenu chiffré
                - signature: Signature du contenu original
                - algorithm: Algorithme utilisé
        """
        recipient = packet.get('recipient')
        sender = packet.get('sender')

        if recipient not in self.clients:
            print(f"[INFO] Destinataire {recipient} non connecté")
            # Optionnel: Sauvegarder en base pour livraison ultérieure
            return

        try:
            recipient_socket = self.clients[recipient]
            message = json.dumps(packet)
            self._send_to_client(recipient_socket, message)

            print(f"[✓] Message signé relayé: {sender} → {recipient}")

        except Exception as e:
            print(f"[ERREUR] Impossible de relayer le message: {e}")

    # =========================================================================
    # MÉTHODE 5 : Valider et relayer un message PUBLIC SIGNÉ (optionnel)
    # =========================================================================

    def _broadcast_signed_public_message(self, packet):
        """
        Diffuse un message public signé à tous les clients.

        Optionnel: Le serveur peut valider la signature avant de relayer.

        Args:
            packet (dict): Paquet contenant:
                - sender: Expéditeur
                - content: Contenu
                - signature: Signature
                - algorithm: Algorithme
        """
        sender = packet.get('sender')
        signature = packet.get('signature')
        content = packet.get('content')

        # Optionnel: Valider la signature côté serveur
        is_signature_valid = self._validate_message_signature(
            sender,
            content,
            signature
        )

        if not is_signature_valid:
            print(f"[AVERTISSEMENT] Signature invalide du message de {sender}")
            # Optionnel: rejeter ou marquer comme invalide

        message = json.dumps(packet)

        # Diffuser à tous les clients
        for client_socket in self.clients.values():
            try:
                self._send_to_client(client_socket, message)
            except Exception as e:
                print(f"[ERREUR] Lors du broadcast: {e}")

        print(f"[✓] Message public diffusé de {sender}")

    # =========================================================================
    # MÉTHODE 6 : Valider une signature (côté serveur)
    # =========================================================================

    def _validate_message_signature(self, sender, content, signature):
        """
        Valide la signature d'un message côté serveur.

        C'est optionnel : le client va aussi valider.
        Mais le serveur peut rejeter les messages avec mauvaises signatures.

        Args:
            sender (str): Expéditeur
            content (str): Contenu original
            signature (str): Signature en base64

        Returns:
            bool: True si signature valide
        """
        if sender not in self.user_public_keys:
            print(f"[INFO] Clé publique de {sender} non disponible")
            return False

        try:
            public_key_pem = self.user_public_keys[sender]
            public_key = self.rsa_validator.pem_string_to_public_key(
                public_key_pem
            )

            is_valid = self.rsa_validator.verify_signature(
                content,
                signature,
                public_key
            )

            return is_valid

        except Exception as e:
            print(f"[ERREUR] Lors de la validation: {e}")
            return False

    # =========================================================================
    # MÉTHODE 7 : Handler principal pour les messages reçus
    # =========================================================================

    def handle_client_message(self, client_username, data):
        """
        Point d'entrée pour traiter les messages d'un client.

        Délègue selon le type de message.

        Args:
            client_username (str): Client qui envoie
            data (str): JSON du message
        """
        try:
            packet = json.loads(data)
            msg_type = packet.get('type')

            if msg_type == 'register_public_key':
                # Nouveau: Client partage sa clé publique
                self._register_public_key(
                    packet['username'],
                    packet['public_key']
                )

            elif msg_type == 'private_message':
                # Message privé signé et chiffré
                self._relay_signed_private_message(packet)

            elif msg_type == 'public_message':
                # Message public signé
                self._broadcast_signed_public_message(packet)

            elif msg_type == 'list_users':
                # Demande de liste des utilisateurs (code existant)
                self._send_user_list(client_username)

            else:
                print(f"[INFO] Type de message inconnu: {msg_type}")

        except json.JSONDecodeError as e:
            print(f"[ERREUR] Impossible de parser le message: {e}")
        except Exception as e:
            print(f"[ERREUR] Lors du traitement du message: {e}")

    def print_rsa_status(self):
        """Affiche l'état des clés publiques du serveur (DEBUG)."""
        print("\n" + "=" * 60)
        print("RSA Status du Serveur")
        print("=" * 60)
        print(f"Clés publiques en cache: {list(self.user_public_keys.keys())}")
        print(f"Clients connectés: {list(self.clients.keys())}")
        print("=" * 60 + "\n")
        
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
