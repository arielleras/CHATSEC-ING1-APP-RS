"""
client.py
---------
Client TCP + TLS de CHATSEC.
"""
from rsa_signature import RSASignatureManager
import os
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



class ChatSecClient:
    """Version augmentée avec support RSA."""

    def __init__(self, username, server_address=('127.0.0.1', 5555)):
        # ... code existant ...
        self.username = username
        self.server_address = server_address

        # ========== NOUVEAU : RSA ==========
        self.rsa_manager = RSASignatureManager(key_size=2048)
        self.user_public_keys = {}  # Cache: username -> public_key object

        # Chemins des clés
        self.private_key_path = f'keys/{username}_private.pem'
        self.public_key_path = f'keys/{username}_public.pem'

        # Initialiser les clés RSA
        self._initialize_rsa_keys()
        # ====================================

        self.socket = None
        # ... resto du code existant ...

    # =========================================================================
    # MÉTHODE 1 : Initialiser les clés RSA
    # =========================================================================

    def _initialize_rsa_keys(self):
        """
        Initialise les clés RSA pour cet utilisateur.

        Logique:
        - Si les clés existent: les charger
        - Sinon: les générer et les sauvegarder
        """
        # Créer le dossier 'keys' s'il n'existe pas
        os.makedirs('keys', exist_ok=True)

        if os.path.exists(self.private_key_path):
            # Les clés existent déjà
            print(f"[RSA] Chargement des clés pour {self.username}...")
            try:
                self.rsa_manager.load_private_key(self.private_key_path)
                print(f"[RSA] ✓ Clés chargées avec succès")
            except Exception as e:
                print(f"[RSA] ✗ Erreur lors du chargement: {e}")
                # Régénérer les clés en cas d'erreur
                self._generate_new_rsa_keys()
        else:
            # Les clés n'existent pas: les générer
            self._generate_new_rsa_keys()

    def _generate_new_rsa_keys(self):
        """Génère une nouvelle paire de clés RSA."""
        print(f"[RSA] Génération de nouvelles clés pour {self.username}...")

        self.rsa_manager.generate_keypair()
        self.rsa_manager.save_private_key(self.private_key_path)
        self.rsa_manager.save_public_key(self.public_key_path)

        print(f"[RSA] ✓ Clés créées et sauvegardées dans keys/")

    # =========================================================================
    # MÉTHODE 2 : Envoyer la clé publique au serveur
    # =========================================================================

    def register_public_key(self):
        """
        Envoie la clé publique au serveur après authentification.

        Cette clé est stockée sur le serveur et distribuée aux autres clients
        pour qu'ils puissent vérifier les signatures de ce client.
        """
        public_key_pem = self.rsa_manager.public_key_to_pem_string()

        message = {
            'type': 'register_public_key',
            'username': self.username,
            'public_key': public_key_pem
        }

        self.send_to_server(json.dumps(message))
        print(f"[RSA] ✓ Clé publique envoyée au serveur")

    # =========================================================================
    # MÉTHODE 3 : Mettre en cache les clés publiques distantes
    # =========================================================================

    def cache_remote_public_key(self, username, public_key_pem):
        """
        Met en cache la clé publique d'un autre utilisateur.

        Args:
            username (str): Nom de l'utilisateur
            public_key_pem (str): Clé publique en format base64/PEM
        """
        try:
            public_key = self.rsa_manager.pem_string_to_public_key(public_key_pem)
            self.user_public_keys[username] = public_key
            print(f"[RSA] ✓ Clé publique de {username} mise en cache")
        except Exception as e:
            print(f"[RSA] ✗ Erreur lors du cache de la clé: {e}")

    # =========================================================================
    # MÉTHODE 4 : Envoyer un message privé SIGNÉ et CHIFFRÉ
    # =========================================================================

    def send_private_message(self, recipient, content):
        """
        Envoie un message privé signé et chiffré.

        Processus:
        1. Vérifier qu'on a la clé publique du destinataire
        2. Créer un paquet: signature + contenu chiffré
        3. Envoyer au serveur

        Args:
            recipient (str): Nom du destinataire
            content (str): Contenu du message
        """
        # Vérifier qu'on a la clé du destinataire
        if recipient not in self.user_public_keys:
            print(f"[ERREUR] Clé publique de '{recipient}' non disponible")
            print(f"[INFO] Utilisateurs connues: {list(self.user_public_keys.keys())}")
            return False

        try:
            recipient_public_key = self.user_public_keys[recipient]

            # Créer le paquet signé et chiffré
            packet = self.rsa_manager.create_signed_message_packet(
                content=content,
                sender_name=self.username,
                recipient_name=recipient,
                recipient_public_key=recipient_public_key
            )

            # Préparer le message pour le serveur
            message_data = {
                'type': 'private_message',
                'sender': self.username,
                'recipient': recipient,
                'encrypted_content': packet['encrypted_content'],
                'signature': packet['signature'],
                'algorithm': packet['algorithm']
            }

            # Envoyer
            self.send_to_server(json.dumps(message_data))
            print(f"[✓] Message signé et chiffré envoyé à {recipient}")
            return True

        except Exception as e:
            print(f"[ERREUR] Impossible d'envoyer le message: {e}")
            return False

    # =========================================================================
    # MÉTHODE 5 : Envoyer un message PUBLIC SIGNÉ (optionnel)
    # =========================================================================

    def send_public_message(self, content):
        """
        Envoie un message public avec signature.

        Optionnel mais recommandé pour la traçabilité.

        Args:
            content (str): Contenu du message
        """
        try:
            signature = self.rsa_manager.sign_message(content)

            message_data = {
                'type': 'public_message',
                'sender': self.username,
                'content': content,
                'signature': signature,
                'algorithm': 'RSA-2048-SHA256'
            }

            self.send_to_server(json.dumps(message_data))
            print(f"[✓] Message public signé envoyé")
            return True

        except Exception as e:
            print(f"[ERREUR] Impossible d'envoyer le message public: {e}")
            return False

    # =========================================================================
    # MÉTHODE 6 : Recevoir et vérifier un message privé
    # =========================================================================

    def receive_private_message(self, packet):
        """
        Reçoit et vérifie un message privé signé et chiffré.

        Processus:
        1. Récupérer la clé publique de l'expéditeur
        2. Vérifier la signature ET déchiffrer
        3. Retourner le contenu authentifié

        Args:
            packet (dict): Paquet reçu du serveur

        Returns:
            dict: {
                'valid': bool,
                'content': str or None,
                'sender': str,
                'error': str or None
            }
        """
        sender = packet.get('sender')

        # Vérifier qu'on a la clé du sender
        if sender not in self.user_public_keys:
            print(f"[AVERTISSEMENT] Clé publique de '{sender}' non disponible")
            return {
                'valid': False,
                'content': None,
                'sender': sender,
                'error': 'Clé publique non disponible'
            }

        try:
            sender_public_key = self.user_public_keys[sender]

            # Vérifier et déchiffrer
            result = self.rsa_manager.verify_and_decrypt_message(
                packet,
                sender_public_key
            )

            result['sender'] = sender  # Ajouter le sender pour l'affichage
            return result

        except Exception as e:
            return {
                'valid': False,
                'content': None,
                'sender': sender,
                'error': f'Erreur: {str(e)}'
            }

    # =========================================================================
    # MÉTHODE 7 : Recevoir et vérifier un message PUBLIC
    # =========================================================================

    def receive_public_message(self, packet):
        """
        Reçoit et vérifie un message public signé.

        Args:
            packet (dict): Paquet reçu du serveur

        Returns:
            dict: {
                'valid': bool,
                'content': str,
                'sender': str,
                'signature_status': str  # "✓ Valide" ou "✗ Invalide"
            }
        """
        sender = packet.get('sender')
        signature = packet.get('signature')
        content = packet.get('content')

        # Vérifier qu'on a la clé publique
        if sender not in self.user_public_keys:
            return {
                'valid': False,
                'content': content,
                'sender': sender,
                'signature_status': '❓ Clé non disponible'
            }

        try:
            # Vérifier la signature
            is_valid = self.rsa_manager.verify_signature(
                content,
                signature,
                self.user_public_keys[sender]
            )

            status = '🔒 ✓ Valide' if is_valid else '🔓 ✗ Invalide'

            return {
                'valid': is_valid,
                'content': content,
                'sender': sender,
                'signature_status': status
            }

        except Exception as e:
            return {
                'valid': False,
                'content': content,
                'sender': sender,
                'signature_status': f'❌ Erreur: {str(e)}'
            }

    # =========================================================================
    # MÉTHODE 8 : Handler pour les messages reçus
    # =========================================================================

    def handle_received_message(self, data):
        """
        Point d'entrée pour traiter les messages reçus.
        Délègue selon le type de message.

        Args:
            data (str): JSON du message
        """
        try:
            packet = json.loads(data)
            msg_type = packet.get('type')

            if msg_type == 'private_message':
                result = self.receive_private_message(packet)
                self._on_private_message_received(result)

            elif msg_type == 'public_message':
                result = self.receive_public_message(packet)
                self._on_public_message_received(result)

            elif msg_type == 'public_key':
                # Autre client a partagé sa clé publique
                self.cache_remote_public_key(
                    packet.get('username'),
                    packet.get('public_key')
                )

            else:
                # Message de type inconnu
                print(f"[INFO] Message type inconnu: {msg_type}")

        except json.JSONDecodeError as e:
            print(f"[ERREUR] Impossible de parser le message: {e}")